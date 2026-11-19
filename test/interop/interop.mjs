// Browser <-> Go interoperability driver for docs/E2EE.md.
// Usage: node interop.mjs <base-url>
// Loads <base-url>/e2ee.js in headless Chromium, checks every Go-produced
// vector from <base-url>/vectors.json, then produces browser vectors for the
// Go side to verify. Prints one JSON object on stdout.
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');

const base = process.argv[2];
const browser = await chromium.launch();
const page = await browser.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(String(e)));
await page.goto(base + '/index.html');

const result = await page.evaluate(async () => {
  const E = await import('/e2ee.js');
  const v = await (await fetch('/vectors.json')).json();
  const out = { checks: {} };
  const check = async (name, fn) => {
    try { out.checks[name] = (await fn()) === true ? 'ok' : 'false'; } catch (e) { out.checks[name] = 'error: ' + e.message; }
  };

  // ---- read what Go wrote ----
  let goAcct;
  await check('unlock-passphrase', async () => { goAcct = await E.unlock(v.bundle, v.passphrase); return goAcct.userId === v.bundle.userId; });
  await check('unlock-recovery', async () => (await E.unlockWithRecoveryCode(v.bundle, v.recoveryCode.toLowerCase())).userId === v.bundle.userId);
  await check('wrong-passphrase-rejected', async () => { try { await E.unlock(v.bundle, 'definitely wrong!!'); return false; } catch { return true; } });
  await check('fingerprint', async () => (await goAcct.fingerprint()) === v.fingerprint);
  const space = await goAcct.personalSpace(v.spaceId);
  await check('space-public-key', async () => E.b64u(space.publicKey) === v.spacePub);
  let root;
  await check('unwrap-root', async () => { root = await space.unwrapRoot(v.rootId, v.rootKey); return E.b64u(root.raw) === v.rootRaw; });
  let child;
  await check('unwrap-child', async () => { child = await root.unwrapChild(v.childId, v.childWrapped); return E.b64u(child.raw) === v.childRaw; });
  await check('decrypt-name', async () => (await root.decryptName(v.childId, v.childNameEnc)) === v.childName);
  const hk = await E.NodeKey.from(E.unb64u(v.hashKeyRaw));
  out.nameHashes = {};
  for (const n of v.hashNames) out.nameHashes[n] = await hk.nameHash(n);
  await check('container', async () => {
    const blob = new Blob([E.unb64u(v.container)]);
    const goUser = await E.verifyUser(v.bundle.userId, { enc: v.bundle.pub.enc, sig: v.bundle.pub.sig, selfSig: v.bundle.selfSig });
    const res = await E.decryptFile(blob, child, async () => goUser);
    return (await res.blob.text()) === v.plaintext && res.meta.name === v.childName;
  });
  await check('container-owner-seal', async () => {
    const c = await E.parseContainer(new Blob([E.unb64u(v.container)]));
    return E.b64u((await E.ownerNodeKey(c, space)).raw) === v.childRaw;
  });
  await check('tampered-container-rejected', async () => {
    const bad = E.unb64u(v.container);
    bad[bad.length - 100] ^= 1;
    const goUser = await E.verifyUser(v.bundle.userId, { enc: v.bundle.pub.enc, sig: v.bundle.pub.sig, selfSig: v.bundle.selfSig });
    try { await E.decryptFile(new Blob([bad]), child, async () => goUser); return false; } catch { return true; }
  });
  await check('recovery-code-format', async () => E.formatRecoveryCode(E.parseRecoveryCode(v.recoveryCode)) === v.recoveryCode);
  await check('open-contacts', async () => {
    const c = await E.openContacts(goAcct, v.contacts);
    return c.contacts[v.contactId].fp === v.contactFp && c.contacts[v.contactId].name === 'Bob \u2713';
  });
  await check('tampered-contacts-rejected', async () => {
    const bad = E.unb64u(v.contacts);
    bad[bad.length - 5] ^= 1;
    try { await E.openContacts(goAcct, E.b64u(bad)); return false; } catch { return true; }
  });
  await check('classify-contacts', async () => {
    const A = '1'.repeat(32), B = '2'.repeat(32);
    const cl = { v: 1, contacts: { [A]: { fp: 'a'.repeat(40), name: 'Alice Smith', email: 'alice@example.com', verifiedAt: 1 } } };
    const lv = (u) => E.classifyContact(cl, u).level;
    return lv({ id: A, fp: 'a'.repeat(40), name: 'Alice Smith' }) === 'verified'
      && lv({ id: A, fp: 'b'.repeat(40), name: 'Alice Smith' }) === 'changed'
      && lv({ id: B, fp: 'c'.repeat(40), name: 'alice  smith' }) === 'lookalike'
      && lv({ id: B, fp: 'c'.repeat(40), name: '\u0410l\u0456ce Sm1th' }) === 'lookalike'
      && lv({ id: B, fp: 'c'.repeat(40), name: 'Al\u200bice Smith' }) === 'lookalike'
      && lv({ id: B, fp: 'c'.repeat(40), name: 'Someone', email: 'ALICE@example.com' }) === 'lookalike'
      && lv({ id: B, fp: 'c'.repeat(40), name: 'Alicia Smith' }) === 'unverified';
  });

  // ---- write for Go to read ----
  const jsUserId = 'ab'.repeat(16);
  const { account, bundle, recoveryCode } = await E.newAccount(jsUserId, 'browser passphrase 123');
  const jsSpace = await account.personalSpace(v.jsSpaceId);
  const jsRoot = await E.NodeKey.fresh();
  const jsChild = await E.NodeKey.fresh();
  const plaintext = 'hello from the browser ✓ ' + 'x'.repeat(70000);
  const container = await E.encryptFile(new Blob([plaintext]), {
    nk: jsChild, spaceId: v.jsSpaceId, spacePub: jsSpace.publicKey,
    meta: { name: 'browser.txt', type: 'text/plain', mtime: 1 }, signer: account,
  });
  const goPub = await E.verifyUser(v.bundle.userId, { enc: v.bundle.pub.enc, sig: v.bundle.pub.sig, selfSig: v.bundle.selfSig });
  const team = await E.Space.newTeam(v.teamId);
  const linkSecret = E.random(32);
  await check('contacts-bound-to-owner', async () => { try { await E.openContacts(account, v.contacts); return false; } catch { return true; } });
  out.js = {
    bundle, recoveryCode, passphrase: 'browser passphrase 123', spaceId: v.jsSpaceId,
    spacePub: E.b64u(jsSpace.publicKey), spaceKeySig: await E.signSpaceKey(account, v.jsSpaceId, jsSpace.publicKey),
    rootId: v.rootId, rootKey: await jsSpace.wrapRoot(v.rootId, jsRoot), rootRaw: E.b64u(jsRoot.raw),
    childId: v.childId, childRaw: E.b64u(jsChild.raw), entry: await jsRoot.entry(v.childId, 'Ünïcode name.txt', jsChild),
    container: E.b64u(new Uint8Array(await container.arrayBuffer())), plaintext,
    share: await E.shareNode(account, goPub, v.shareId, v.childId, 'write', 'Shared folder', jsChild),
    teamSecret: E.b64u(team.secret), teamGrant: await team.grant(account, goPub), teamName: await team.encryptName('Team ✓'),
    linkSecret: E.b64u(linkSecret), linkKey: await E.linkKey(linkSecret, v.shareId, v.childId, 'Linked', jsChild),
    trash: await E.trashKey(account, E.unb64u(v.spacePub), v.childId, 'trashed.txt', 'file', jsChild),
    contacts: await E.sealContacts(account, { v: 1, contacts: { ['d'.repeat(32)]: { fp: 'e'.repeat(40), name: 'From the browser \u2713', verifiedAt: 2 } } }),
  };
  return out;
});
result.pageErrors = errors;
console.log(JSON.stringify(result));
await browser.close();
