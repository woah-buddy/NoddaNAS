// Browser implementation of NoddaNAS end-to-end encryption (docs/E2EE.md v1),
// using only the WebCrypto API: X25519, Ed25519, HKDF/PBKDF2/HMAC-SHA-256 and
// AES-256-GCM. The Go implementation (internal/e2ee) follows the same spec;
// interoperability tests check that each reads what the other writes.

const L = 'noddanas/e2ee/v1/';
const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });
const subtle = crypto.subtle;

export const CHUNK = 64 * 1024;
export const PBKDF2_ITERATIONS = 600000;
export const MIN_PASSPHRASE = 12;
const MAGIC = 'NDNSE2E1';
const ALG = 'X25519+HKDF-SHA256+AES-256-GCM/STREAM-64K';
const TAG = 16;
const TRAILER = 4 + 64;

export class E2EEError extends Error {}
const authFail = () => new E2EEError('authentication failed: the data was modified or does not belong to these keys');

// ---- bytes ------------------------------------------------------------------------------
export function b64u(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64u(s) {
  if (typeof s !== 'string' || /[^A-Za-z0-9_-]/.test(s)) throw new E2EEError('malformed base64');
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
export const random = (n) => crypto.getRandomValues(new Uint8Array(n));
export const newId = () => hex(random(16));
const utf8 = (s) => te.encode(s);
const NUL = new Uint8Array([0]);
function label(name, ...parts) {
  const chunks = [utf8(L + name)];
  for (const p of parts) chunks.push(NUL, typeof p === 'string' ? utf8(p) : p);
  return concat(...chunks);
}
const sha256 = async (b) => new Uint8Array(await subtle.digest('SHA-256', b));
function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// ---- primitives -----------------------------------------------------------------------------
export async function hkdf(ikm, salt, info) {
  const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt || new Uint8Array(), info: utf8(L + info) }, k, 256));
}
const aesKey = (raw, use) => subtle.importKey('raw', raw, 'AES-GCM', false, [use]);
async function gcmSeal(key, pt, aad) {
  const iv = random(12);
  const params = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = aad;
  return concat(iv, new Uint8Array(await subtle.encrypt(params, await aesKey(key, 'encrypt'), pt)));
}
async function gcmOpen(key, data, aad) {
  if (data.length < 28) throw authFail();
  const params = { name: 'AES-GCM', iv: data.subarray(0, 12) };
  if (aad) params.additionalData = aad;
  try {
    return new Uint8Array(await subtle.decrypt(params, await aesKey(key, 'decrypt'), data.subarray(12)));
  } catch {
    throw authFail();
  }
}
async function hmac(key, msg) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, msg));
}

// WebCrypto imports raw private scalars only via PKCS#8 (RFC 8410 prefixes).
const PKCS8_X25519 = Uint8Array.from([0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x6e, 4, 0x22, 4, 0x20]);
const PKCS8_ED25519 = Uint8Array.from([0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20]);

// Returns a non-extractable private key plus the raw public key.
async function importPrivate(raw, alg, usage) {
  const prefix = alg === 'X25519' ? PKCS8_X25519 : PKCS8_ED25519;
  const tmp = await subtle.importKey('pkcs8', concat(prefix, raw), { name: alg }, true, usage);
  const pub = unb64u((await subtle.exportKey('jwk', tmp)).x);
  return { priv: await subtle.importKey('pkcs8', concat(prefix, raw), { name: alg }, false, usage), pub };
}
const x25519 = (d) => importPrivate(d, 'X25519', ['deriveBits']);
const ed25519 = (seed) => importPrivate(seed, 'Ed25519', ['sign']);
const sign = async (priv, msg) => new Uint8Array(await subtle.sign('Ed25519', priv, msg));
async function verify(pub, msg, sig) {
  if (!pub || pub.length !== 32 || !sig || sig.length !== 64) return false;
  return subtle.verify('Ed25519', await subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']), sig, msg);
}
async function mustVerify(pub, msg, sig) { if (!(await verify(pub, msg, sig))) throw authFail(); }

// seal: anonymous public-key encryption to an X25519 key (spec §2).
export async function seal(recipientPub, pt, ctx) {
  const eph = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const ephPub = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const rk = await subtle.importKey('raw', recipientPub, { name: 'X25519' }, false, []);
  const ss = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: rk }, eph.privateKey, 256));
  return concat(ephPub, await gcmSeal(await hkdf(ss, concat(ephPub, recipientPub), 'seal'), pt, ctx));
}
async function unseal(key, sealed, ctx) {
  if (sealed.length < 32 + 28) throw authFail();
  let ss;
  try {
    const ek = await subtle.importKey('raw', sealed.subarray(0, 32), { name: 'X25519' }, false, []);
    ss = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: ek }, key.priv, 256));
  } catch {
    throw authFail();
  }
  return gcmOpen(await hkdf(ss, concat(sealed.subarray(0, 32), key.pub), 'seal'), sealed.subarray(32), ctx);
}

export async function fingerprint(encPub, sigPub) {
  return hex(await sha256(concat(label('fingerprint'), NUL, encPub, sigPub))).slice(0, 40);
}
export const formatFingerprint = (fp) => fp.match(/.{1,4}/g).join(' ');

function pad32(b) {
  const out = new Uint8Array(Math.max(32, Math.ceil(b.length / 32) * 32));
  out.set(b);
  return out;
}
function unpad(b) {
  let n = b.length;
  while (n > 0 && b[n - 1] === 0) n--;
  return b.subarray(0, n);
}
const nfc = (s) => s.normalize('NFC');

// ---- recovery codes (Crockford base32, 20 bytes) ----------------------------------------------
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export function formatRecoveryCode(bytes) {
  let bits = 0n, n = 0, out = '', chars = 0;
  for (const c of bytes) {
    bits = (bits << 8n) | BigInt(c);
    n += 8;
    while (n >= 5) {
      n -= 5;
      if (chars > 0 && chars % 4 === 0) out += '-';
      out += CROCKFORD[Number((bits >> BigInt(n)) & 31n)];
      chars++;
    }
  }
  return out;
}
export function parseRecoveryCode(s) {
  let bits = 0n, n = 0, count = 0;
  const out = [];
  for (let ch of s.toUpperCase()) {
    if (ch === '-' || ch === ' ') continue;
    if (ch === 'O') ch = '0';
    if (ch === 'I' || ch === 'L') ch = '1';
    const v = CROCKFORD.indexOf(ch);
    if (v < 0) throw new E2EEError('invalid character in recovery code');
    count++;
    bits = (bits << 5n) | BigInt(v);
    n += 5;
    if (n >= 8) { n -= 8; out.push(Number((bits >> BigInt(n)) & 255n)); }
  }
  if (count !== 32 || out.length !== 20) throw new E2EEError('a recovery code has 32 characters');
  return new Uint8Array(out);
}

// ---- accounts (spec §1) -------------------------------------------------------------------------
const pubkeysMsg = (userId, enc, sig) => concat(label('pubkeys', userId), NUL, enc, sig);

export class Account {
  constructor(userId, mk, enc, sig) { Object.assign(this, { userId, mk, enc, sig }); }
  fingerprint() { return fingerprint(this.enc.pub, this.sig.pub); }
  async publicUser() { return { id: this.userId, enc: this.enc.pub, sig: this.sig.pub, fp: await this.fingerprint() }; }
  async personalSpace(spaceId) { return Space.open(spaceId, await hkdf(this.mk, null, 'space-secret/personal')); }
}

async function passphraseUnlocker(userId, passphrase, mk) {
  const salt = random(16);
  const k = await passphraseKey(passphrase, salt, PBKDF2_ITERATIONS);
  return { type: 'passphrase', kdf: 'pbkdf2-sha256', iter: PBKDF2_ITERATIONS, salt: b64u(salt),
    mk: b64u(await gcmSeal(k, mk, label('unlock/passphrase', userId))) };
}
async function passphraseKey(passphrase, salt, iter) {
  const k = await subtle.importKey('raw', utf8(nfc(passphrase)), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, k, 256));
}

// newAccount creates keys and returns { account, bundle, recoveryCode }.
export async function newAccount(userId, passphrase) {
  if ([...passphrase].length < MIN_PASSPHRASE) throw new E2EEError(`passphrase must be at least ${MIN_PASSPHRASE} characters`);
  const mk = random(32), encD = random(32), seed = random(32), code = random(20);
  const enc = await x25519(encD), sig = await ed25519(seed);
  const priv = utf8(JSON.stringify({ enc: b64u(encD), sig: b64u(seed) }));
  const rsalt = random(16);
  const bundle = {
    v: 1, userId, pub: { enc: b64u(enc.pub), sig: b64u(sig.pub) },
    selfSig: b64u(await sign(sig.priv, pubkeysMsg(userId, enc.pub, sig.pub))),
    private: b64u(await gcmSeal(await hkdf(mk, null, 'mk/private-keys'), priv, label('private-keys', userId))),
    unlock: [
      await passphraseUnlocker(userId, passphrase, mk),
      { type: 'recovery', salt: b64u(rsalt), mk: b64u(await gcmSeal(await hkdf(code, rsalt, 'unlock/recovery'), mk, label('unlock/recovery', userId))) },
    ],
  };
  encD.fill(0); seed.fill(0);
  return { account: new Account(userId, mk, enc, sig), bundle, recoveryCode: formatRecoveryCode(code) };
}

async function openBundle(b, mk) {
  const pt = await gcmOpen(await hkdf(mk, null, 'mk/private-keys'), unb64u(b.private), label('private-keys', b.userId));
  const keys = JSON.parse(td.decode(pt));
  const enc = await x25519(unb64u(keys.enc)), sig = await ed25519(unb64u(keys.sig));
  // The private keys must match the published ones, or the bundle was tampered with.
  if (b64u(enc.pub) !== b.pub.enc || b64u(sig.pub) !== b.pub.sig) throw authFail();
  return new Account(b.userId, mk, enc, sig);
}

export async function unlock(bundle, passphrase) {
  for (const u of bundle.unlock) {
    if (u.type !== 'passphrase' || u.kdf !== 'pbkdf2-sha256') continue;
    if (!(u.iter >= 100000 && u.iter <= 10000000)) throw new E2EEError('unsupported passphrase parameters');
    const k = await passphraseKey(passphrase, unb64u(u.salt), u.iter);
    try {
      return await openBundle(bundle, await gcmOpen(k, unb64u(u.mk), label('unlock/passphrase', bundle.userId)));
    } catch { /* try the next unlocker */ }
  }
  throw new E2EEError('wrong passphrase');
}

export async function unlockWithRecoveryCode(bundle, code) {
  const raw = parseRecoveryCode(code);
  for (const u of bundle.unlock) {
    if (u.type !== 'recovery') continue;
    try {
      const k = await hkdf(raw, unb64u(u.salt), 'unlock/recovery');
      return await openBundle(bundle, await gcmOpen(k, unb64u(u.mk), label('unlock/recovery', bundle.userId)));
    } catch { /* next */ }
  }
  throw new E2EEError('wrong recovery code');
}

// changePassphrase returns a new bundle with only the passphrase unlocker replaced.
export async function changePassphrase(account, bundle, passphrase) {
  if ([...passphrase].length < MIN_PASSPHRASE) throw new E2EEError(`passphrase must be at least ${MIN_PASSPHRASE} characters`);
  return { ...bundle, unlock: [await passphraseUnlocker(account.userId, passphrase, account.mk), ...bundle.unlock.filter((u) => u.type !== 'passphrase')] };
}

// verifyUser checks a directory entry's self-signature and returns usable keys.
export async function verifyUser(id, keys) {
  if (!keys) throw new E2EEError('that user has not set up encryption');
  const enc = unb64u(keys.enc), sig = unb64u(keys.sig);
  await mustVerify(sig, pubkeysMsg(id, enc, sig), unb64u(keys.selfSig));
  return { id, enc, sig, fp: await fingerprint(enc, sig) };
}

// ---- spaces (spec §3) ----------------------------------------------------------------------------
export class Space {
  static async open(id, secret) {
    const s = new Space();
    s.id = id;
    s.secret = secret;
    s.key = await x25519(await hkdf(secret, null, 'space-x25519'));
    return s;
  }
  static async newTeam(id) { return Space.open(id, random(32)); }
  get publicKey() { return this.key.pub; }
  async wrapRoot(rootId, nk) { return b64u(await gcmSeal(await hkdf(this.secret, null, 'space-root'), nk.raw, label('space-root', this.id, rootId))); }
  async unwrapRoot(rootId, wrapped) {
    return NodeKey.from(await gcmOpen(await hkdf(this.secret, null, 'space-root'), unb64u(wrapped), label('space-root', this.id, rootId)));
  }
  async encryptName(name) { return b64u(await gcmSeal(await hkdf(this.secret, null, 'space-name'), pad32(utf8(nfc(name))), label('space-name', this.id))); }
  async decryptName(enc) { return td.decode(unpad(await gcmOpen(await hkdf(this.secret, null, 'space-name'), unb64u(enc), label('space-name', this.id)))); }
  async grant(granter, member) {
    const g = await seal(member.enc, this.secret, label('space-grant', this.id, member.id));
    return { grant: b64u(g), grantSig: b64u(await sign(granter.sig.priv, concat(label('space-grant-sig', this.id, member.id), NUL, await sha256(g)))) };
  }
  static async openGrant(me, granter, spaceId, grant, grantSig) {
    const g = unb64u(grant);
    await mustVerify(granter.sig, concat(label('space-grant-sig', spaceId, me.userId), NUL, await sha256(g)), unb64u(grantSig));
    const secret = await unseal(me.enc, g, label('space-grant', spaceId, me.userId));
    if (secret.length !== 32) throw authFail();
    return Space.open(spaceId, secret);
  }
}
const spaceKeyMsg = (spaceId, pub) => concat(label('space-key', spaceId), NUL, pub);
export async function signSpaceKey(account, spaceId, pub) { return b64u(await sign(account.sig.priv, spaceKeyMsg(spaceId, pub))); }
export async function verifySpaceKey(creator, spaceId, pubB64, sigB64) {
  const pub = unb64u(pubB64);
  await mustVerify(creator.sig, spaceKeyMsg(spaceId, pub), unb64u(sigB64));
  return pub;
}

// ---- node keys (spec §4) -------------------------------------------------------------------------
export class NodeKey {
  static async from(raw) {
    if (raw.length !== 32) throw authFail();
    const k = new NodeKey();
    k.raw = raw;
    [k.wrap, k.name, k.hash] = await Promise.all([hkdf(raw, null, 'node/wrap'), hkdf(raw, null, 'node/name'), hkdf(raw, null, 'node/hash')]);
    return k;
  }
  static fresh() { return NodeKey.from(random(32)); }
  async wrapChild(childId, child) { return b64u(await gcmSeal(this.wrap, child.raw, label('node-key', childId))); }
  async unwrapChild(childId, wrapped) { return NodeKey.from(await gcmOpen(this.wrap, unb64u(wrapped), label('node-key', childId))); }
  async encryptName(childId, name) { return b64u(await gcmSeal(this.name, pad32(utf8(nfc(name))), label('node-name', childId))); }
  async decryptName(childId, enc) { return td.decode(unpad(await gcmOpen(this.name, unb64u(enc), label('node-name', childId)))); }
  async nameHash(name) { return hex(await hmac(this.hash, utf8(nfc(name).toLowerCase()))); }
  async entry(childId, name, child) {
    return { nameEnc: await this.encryptName(childId, name), nameHash: await this.nameHash(name), wrappedKey: await this.wrapChild(childId, child) };
  }
}

// validateName mirrors the server's former rules; clients enforce them now.
export function validateName(name) {
  const n = nfc(name);
  if (!n || utf8(n).length > 255) return 'Names must be 1-255 bytes.';
  if (/^\.+$/.test(n)) return 'Names cannot consist only of dots.';
  if (n.trim() !== n) return 'Names cannot start or end with spaces.';
  if (/[\/\\\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/.test(n)) return 'Names cannot contain /, \\, control or bidirectional characters.';
  return '';
}

// ---- grants: shares, links, trash (spec §6-7) --------------------------------------------------
async function keyAndName(nk, name, kind) {
  const o = { nk: b64u(nk.raw), name: nfc(name) };
  if (kind) o.kind = kind;
  return utf8(JSON.stringify(o));
}
async function parseKeyAndName(pt) {
  const o = JSON.parse(td.decode(pt));
  return { nk: await NodeKey.from(unb64u(o.nk)), name: o.name, kind: o.kind };
}
const shareSigMsg = async (shareId, nodeId, recipientId, perm, sealed) =>
  concat(label('share-sig', shareId, nodeId, recipientId, perm), NUL, await sha256(sealed));

export async function shareNode(sharer, recipient, shareId, nodeId, perm, name, nk) {
  const s = await seal(recipient.enc, await keyAndName(nk, name), label('share', shareId, nodeId, recipient.id));
  return { sealedKey: b64u(s), sig: b64u(await sign(sharer.sig.priv, await shareSigMsg(shareId, nodeId, recipient.id, perm, s))) };
}
export async function openShare(me, sharer, share) {
  const sealed = unb64u(share.sealedKey);
  await mustVerify(sharer.sig, await shareSigMsg(share.id, share.nodeId, me.userId, share.permission, sealed), unb64u(share.sig));
  return parseKeyAndName(await unseal(me.enc, sealed, label('share', share.id, share.nodeId, me.userId)));
}
export async function linkKey(secret, shareId, nodeId, name, nk) {
  return b64u(await gcmSeal(await hkdf(secret, null, 'link'), await keyAndName(nk, name), label('link', shareId, nodeId)));
}
export async function openLinkKey(secret, shareId, nodeId, lk) {
  return parseKeyAndName(await gcmOpen(await hkdf(secret, null, 'link'), unb64u(lk), label('link', shareId, nodeId)));
}
export async function trashKey(trasher, spacePub, nodeId, name, kind, nk) {
  const s = await seal(spacePub, await keyAndName(nk, name, kind), label('trash', nodeId));
  return { restoreKey: b64u(s), restoreSig: b64u(await sign(trasher.sig.priv, concat(label('trash-sig', nodeId), NUL, await sha256(s)))) };
}
export async function openTrashKey(space, trasher, node) {
  const s = unb64u(node.restoreKey);
  await mustVerify(trasher.sig, concat(label('trash-sig', node.id), NUL, await sha256(s)), unb64u(node.restoreSig));
  return parseKeyAndName(await unseal(space.key, s, label('trash', node.id)));
}

// ---- file containers (spec §5) --------------------------------------------------------------------
const chunkCount = (size) => (size === 0 ? 1 : Math.ceil(size / CHUNK));
function chunkNonce(i, last) {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setBigUint64(3, BigInt(i));
  n[11] = last ? 1 : 0;
  return n;
}
async function fileKeys(nk, salt) {
  const [content, meta, commit] = await Promise.all([hkdf(nk.raw, salt, 'file/content'), hkdf(nk.raw, salt, 'file/meta'), hkdf(nk.raw, salt, 'file/commit')]);
  return { content, meta, commit };
}

// encryptFile turns a Blob/File into a container Blob. onProgress(fraction).
export async function encryptFile(blob, { nk, spaceId, spacePub, meta, signer }, onProgress) {
  const size = blob.size, n = chunkCount(size), salt = random(32);
  const fk = await fileKeys(nk, salt);
  const header = {
    v: 1, alg: ALG, size, salt: b64u(salt), commit: b64u(fk.commit),
    owner: { space: spaceId, key: b64u(await seal(spacePub, nk.raw, label('file-owner', spaceId))) },
    meta: b64u(await gcmSeal(fk.meta, utf8(JSON.stringify(meta)), label('file/meta'))),
    signer: { user: signer.userId, fp: await signer.fingerprint() },
  };
  const hdr = utf8(JSON.stringify(header));
  const prefix = new Uint8Array(12 + hdr.length);
  prefix.set(utf8(MAGIC));
  new DataView(prefix.buffer).setUint32(8, hdr.length);
  prefix.set(hdr, 12);
  const key = await aesKey(fk.content, 'encrypt');
  const parts = [prefix], hashes = new Uint8Array(32 * n);
  for (let i = 0; i < n; i++) {
    const pt = new Uint8Array(await blob.slice(i * CHUNK, Math.min(size, (i + 1) * CHUNK)).arrayBuffer());
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: chunkNonce(i, i === n - 1) }, key, pt));
    hashes.set(await sha256(ct), 32 * i);
    parts.push(ct);
    if (onProgress) onProgress((i + 1) / n);
  }
  const msg = concat(label('container'), NUL, await sha256(prefix), await sha256(hashes));
  parts.push(utf8('SIG1'), await sign(signer.sig.priv, msg));
  return new Blob(parts, { type: 'application/octet-stream' });
}

// parseContainer reads the prefix of a container held in a Blob.
export async function parseContainer(blob) {
  const head = new Uint8Array(await blob.slice(0, 12).arrayBuffer());
  if (head.length < 12 || td.decode(head.subarray(0, 8)) !== MAGIC) throw new E2EEError('not a NoddaNAS encrypted file');
  const hl = new DataView(head.buffer).getUint32(8);
  if (hl === 0 || hl > 65536) throw new E2EEError('malformed container');
  const prefix = new Uint8Array(await blob.slice(0, 12 + hl).arrayBuffer());
  const h = JSON.parse(td.decode(prefix.subarray(12)));
  if (h.v !== 1 || h.alg !== ALG || !Number.isSafeInteger(h.size) || h.size < 0) throw new E2EEError('unsupported container');
  const total = 12 + hl + h.size + TAG * chunkCount(h.size) + TRAILER;
  if (blob.size !== total) throw new E2EEError('container is truncated or has trailing data');
  return { header: h, prefix, bodyOffset: 12 + hl };
}

// ownerNodeKey recovers the file key from the owner seal (independent restore).
export async function ownerNodeKey(c, space) {
  if (space.id !== c.header.owner.space) throw new E2EEError('this backup belongs to a different space');
  return NodeKey.from(await unseal(space.key, unb64u(c.header.owner.key), label('file-owner', space.id)));
}

// decryptFile decrypts and fully verifies a container. signerFor(userId)
// returns the signer's verified public user. Returns { blob, meta, signer }.
export async function decryptFile(blob, nk, signerFor, onProgress) {
  const c = await parseContainer(blob);
  const h = c.header, salt = unb64u(h.salt);
  const fk = await fileKeys(nk, salt);
  if (!ctEqual(fk.commit, unb64u(h.commit))) throw authFail(); // key commitment
  const meta = JSON.parse(td.decode(await gcmOpen(fk.meta, unb64u(h.meta), label('file/meta'))));
  const signer = await signerFor(h.signer.user);
  if (signer.fp !== h.signer.fp) throw new E2EEError('the file claims a signer key that does not match the directory');
  const key = await aesKey(fk.content, 'decrypt');
  const n = chunkCount(h.size), parts = [], hashes = new Uint8Array(32 * n);
  let off = c.bodyOffset;
  for (let i = 0; i < n; i++) {
    const plain = Math.min(CHUNK, h.size - i * CHUNK);
    const ct = new Uint8Array(await blob.slice(off, off + plain + TAG).arrayBuffer());
    off += plain + TAG;
    hashes.set(await sha256(ct), 32 * i);
    try {
      parts.push(new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: chunkNonce(i, i === n - 1) }, key, ct)));
    } catch {
      throw authFail();
    }
    if (onProgress) onProgress((i + 1) / n);
  }
  const trailer = new Uint8Array(await blob.slice(off, off + TRAILER).arrayBuffer());
  if (td.decode(trailer.subarray(0, 4)) !== 'SIG1') throw authFail();
  await mustVerify(signer.sig, concat(label('container'), NUL, await sha256(c.prefix), await sha256(hashes)), trailer.subarray(4));
  return { blob: new Blob(parts, { type: 'application/octet-stream' }), meta, signer };
}
