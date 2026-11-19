# End-to-end encryption specification (v1)

This is the normative description of NoddaNAS's end-to-end encryption. Two independent
implementations follow it: the browser client (`web/static/e2ee.js`, WebCrypto) and the Go
client library (`internal/e2ee`, used by the `noddanas-cli` tool and the test suite). The
interoperability tests check that each can read what the other wrote.

## Goals

1. **The server never sees plaintext** file contents, file or folder names, team names, or any
   key that could decrypt them.
2. **Every stored file is independently backup-able and restorable while still encrypted.**
   A single file container, plus the owner's key backup and passphrase (or recovery code), is
   enough to decrypt it, with no server and no database.
3. Sharing with users, team folders and public links work without the server ever holding a key.
4. Integrity: the server cannot swap, truncate, reorder or substitute content or keys without
   clients noticing, assuming public keys are authentic (see "Trust in the key directory").

## Notation

- `b64u(x)`: base64url without padding. `hex(x)`: lowercase hex. `||`: concatenation.
- `HKDF(ikm, salt, info)`: HKDF-SHA256 producing 32 bytes. Empty salt when omitted.
- `GCM(k, pt, aad)`: AES-256-GCM with a fresh random 96-bit nonce; output `nonce || ct || tag`.
- Every label below is ASCII and begins with `noddanas/e2ee/v1/`, abbreviated `L/`. Labels joined
  with IDs use a single NUL byte `\0` as separator. IDs are 32 lowercase hex characters.

## 1. Account keys

Each user has:

| Key | Type | Purpose |
|---|---|---|
| `MK` | 32 random bytes | Account master key: encrypts the private keys, derives the personal space secret |
| `enc` | X25519 key pair | Receives keys sealed to the user (shares, team grants) |
| `sig` | Ed25519 key pair | Signs everything the user grants or uploads |

**Fingerprint:** `hex(SHA-256("L/fingerprint" \0 || encPub || sigPub))[:40]`, shown in groups of four.

**Self-signature:** `Ed25519(sigPriv, "L/pubkeys" \0 || userId || \0 || encPub || sigPub)`.

**Private keys:** `GCM(HKDF(MK, info="L/mk/private-keys"), JSON{"enc": b64u(x25519 private 32B),
"sig": b64u(ed25519 seed 32B)}, aad = "L/private-keys" \0 || userId)`.

**Unlockers** wrap `MK`. A bundle always has both:

- *Passphrase:* `K = PBKDF2-SHA256(UTF-8(NFC(passphrase)), salt16, iter=600000, 32B)`,
  `GCM(K, MK, aad = "L/unlock/passphrase" \0 || userId)`. Minimum 12 characters (client-enforced).
- *Recovery code:* 20 random bytes shown once as 32 Crockford-base32 characters in groups of
  four (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`; on input, `O`→`0`, `I`/`L`→`1`, dashes and spaces are
  ignored). `K = HKDF(code bytes, salt16, info="L/unlock/recovery")`,
  `GCM(K, MK, aad = "L/unlock/recovery" \0 || userId)`.

**Key bundle** (stored by the server, which can read only the public parts; also the user's key
backup file):

```json
{"v":1, "userId":"…", "pub":{"enc":"b64u","sig":"b64u"}, "selfSig":"b64u", "private":"b64u",
 "unlock":[{"type":"passphrase","kdf":"pbkdf2-sha256","iter":600000,"salt":"b64u","mk":"b64u"},
           {"type":"recovery","salt":"b64u","mk":"b64u"}]}
```

The server stores the bundle opaquely and refuses to change `pub` once set, so a stolen session
cannot silently swap a user's keys. Changing the passphrase replaces only the passphrase unlocker.

## 2. Sealing to a public key

`Seal(recipientPub, pt, ctx)`:

1. Generate an ephemeral X25519 key pair; `ss = X25519(ephPriv, recipientPub)` (all-zero rejected).
2. `k = HKDF(ss, salt = ephPub || recipientPub, info = "L/seal")`.
3. Output `ephPub(32) || GCM(k, pt, aad = ctx)`.

Sealing is anonymous (anyone can seal to a public key), so every seal that grants access is
accompanied by an Ed25519 signature from the granter, verified by the recipient.

## 3. Spaces

A *space* is an independently owned tree with its own quota: each user's personal space, and
team folders. Each space has a 32-byte **space secret** `SS`:

- personal space: `SS = HKDF(MK, info = "L/space-secret/personal")`;
- team space: 32 random bytes, granted to members.

From `SS`:

- **Space key pair** (X25519): private key = `HKDF(SS, info = "L/space-x25519")` (clamped per
  RFC 7748 by the X25519 implementation). The public key is published on the space with
  `spaceSig = Ed25519(creatorSigPriv, "L/space-key" \0 || spaceId || \0 || spacePub)`.
- **Root node key**: `rootKey = GCM(HKDF(SS, info="L/space-root"), NK_root,
  aad = "L/space-root" \0 || spaceId || \0 || rootNodeId)`.
- **Team name**: `GCM(HKDF(SS, info="L/space-name"), pad32(name), aad = "L/space-name" \0 || spaceId)`.
- **Member grant** (team spaces): `grant = Seal(memberEncPub, SS, ctx = "L/space-grant" \0 ||
  spaceId || \0 || memberId)`, `grantSig = Ed25519(granterSigPriv, "L/space-grant-sig" \0 ||
  spaceId || \0 || memberId || \0 || SHA-256(grant))`.

### Granting the key

The server decides who is a *member* (direct memberships, identity-provider group mappings), but
only a manager's client can create a grant. The member list is the server's claim, and whoever
controls the server could add to it, so **clients never grant automatically**. A manager's client
lists members who have access but no grant ("waiting for the team key"), with each person's name
and email as the server reports them, how the server says they joined, their key fingerprint and
their verification status (§8). It grants only after the manager confirms each person, or
confirms a bulk grant that lists everyone it covers. A bulk grant always leaves out people
flagged "key changed" or "look-alike". A key is never granted to a "key changed" user. The Go
client's `GrantPending` requires an approval callback that is shown each fingerprint.

## 4. Node keys

Every file and folder has a random 32-byte node key `NK`. Subkeys:

| Key | Derivation | Use |
|---|---|---|
| wrap | `HKDF(NK, info="L/node/wrap")` | wraps children's node keys |
| name | `HKDF(NK, info="L/node/name")` | encrypts children's names |
| hash | `HKDF(NK, info="L/node/hash")` | HMAC key for children's name hashes |

For a child `c` of folder `p` (node IDs are generated by the client):

- `wrappedKey = GCM(wrap_p, NK_c, aad = "L/node-key" \0 || c)`
- `nameEnc = GCM(name_p, pad32(UTF-8(NFC(name))), aad = "L/node-name" \0 || c)`, where `pad32`
  appends zero bytes up to a multiple of 32 (minimum 32); names never contain NUL.
- `nameHash = hex(HMAC-SHA256(hash_p, UTF-8(lower(NFC(name)))))`, `lower` being Unicode default
  full lowercasing (`String.prototype.toLowerCase`; Go `cases.Lower(language.Und)`). The server
  enforces uniqueness of `nameHash` per folder, so duplicate names (case-insensitively) are
  rejected without the server learning any name.

Binding the node ID into every AAD means the server cannot move a key or name from one node to
another. Moving a node re-wraps its key and re-encrypts its name under the new parent; its
descendants are untouched.

## 5. File containers

Each stored file version is one self-contained container (`.ndne` when exported):

```
offset   size  field
0        8     magic "NDNSE2E1"
8        4     H = header length, uint32 big-endian, 1..65536
12       H     header: UTF-8 JSON object
12+H     B     body: n chunks; B = size + 16·n, n = max(1, ceil(size / 65536))
12+H+B   4     "SIG1"
16+H+B   64    Ed25519 signature
```

Header fields:

| Field | Value |
|---|---|
| `v` | `1` |
| `alg` | `"X25519+HKDF-SHA256+AES-256-GCM/STREAM-64K"` |
| `size` | plaintext size in bytes |
| `salt` | `b64u(32 random bytes)`, fresh for every container |
| `commit` | `b64u(HKDF(NK, salt, info="L/file/commit"))`: key commitment |
| `owner` | `{"space": spaceId, "key": b64u(Seal(spacePub, NK, ctx = "L/file-owner" \0 || spaceId))}` |
| `meta` | `b64u(GCM(HKDF(NK, salt, info="L/file/meta"), JSON{"name","type","mtime"}, aad="L/file/meta"))` |
| `signer` | `{"user": userId, "fp": fingerprint}` |

Body: the STREAM construction. Chunk `i` (64 KiB of plaintext, the last possibly shorter or
empty) is `AES-256-GCM(HKDF(NK, salt, info="L/file/content"), nonce_i, chunk)` without AAD, where
`nonce_i = 0x000000 || uint64_be(i) || last`, `last` being `0x01` for the final chunk only. The
index prevents reordering, the final flag prevents truncation, and the per-container salt makes
every version's content key unique even though versions share `NK`.

Signature: `Ed25519(signerSigPriv, "L/container" \0 || SHA-256(bytes[0, 12+H)) || BH)` where
`BH = SHA-256(SHA-256(chunk_0) || … || SHA-256(chunk_{n-1}))` over the encrypted chunks.

Why each part exists:

- `owner.key` makes the container **independently restorable**: whoever holds the space secret
  (the owner, via passphrase or recovery code, or any team member) can open it with no other
  data. Restoring a backup into a folder re-wraps `NK` under that folder; the container bytes
  are stored unchanged and stay encrypted.
- `commit` makes the container **key-committing** (AES-GCM alone is not): a container fetched
  through the folder hierarchy is accepted only if it commits to the `NK` the hierarchy gave.
- The signature makes the container **attributable**, which matters for backups: anyone can seal
  a key to a public key, so an unsigned container from a backup could have been planted.

The server parses only `v`, `alg`, `size` and `owner.space`, checks the total length, and stores
the bytes as they are.

## 6. Shares and links

- **User share:** client-chosen `shareId`; `sealedKey = Seal(recipientEncPub, JSON{"nk","name"},
  ctx = "L/share" \0 || shareId || \0 || nodeId || \0 || recipientId)`;
  `sig = Ed25519(sharerSigPriv, "L/share-sig" \0 || shareId || \0 || nodeId || \0 || recipientId
  || \0 || permission || \0 || SHA-256(sealedKey))`.
- **Public link:** a 32-byte link secret `LS` lives only in the URL fragment
  (`/s#<token>.<b64u(LS)>`), which browsers never send to servers. The server stores
  `linkKey = GCM(HKDF(LS, info="L/link"), JSON{"nk","name"}, aad = "L/link" \0 || shareId || \0 ||
  nodeId)`. The `token` (server-side, hashed) gates access, rate limiting and expiry; `LS`
  decrypts.

## 7. Trash

Trashing a node attaches `restoreKey = Seal(spacePub, JSON{"nk","name","kind"}, ctx = "L/trash" \0
|| nodeId)` and `restoreSig = Ed25519(trasherSigPriv, "L/trash-sig" \0 || nodeId || \0 ||
SHA-256(restoreKey))`. This lets the space owner restore the item (and see its name) even if
its original folder has since been purged.

## 8. Verified contacts

Users compare key fingerprints out of band (in person or on a call) and mark the other person
verified. The list of verified people is sealed so that the server stores it but cannot read,
forge or swap it:

- `K_contacts = HKDF(MK, info = "L/mk/contacts")`;
- `contacts = GCM(K_contacts, JSON, aad = "L/contacts" \0 || userId)`, base64url, at most 46 KiB
  (about 300 people);
- `JSON = {"v":1,"contacts":{"<userId>":{"fp","name","email"?,"verifiedAt"}}}`: the fingerprint,
  name and email as shown when verified, and the time in Unix milliseconds.

The server keeps one sealed list per user with a revision number. A save must name the
revision it replaces, so two devices cannot silently overwrite each other: on a conflict the
client re-applies its change to the newer list. The server can withhold the list or serve an
older copy. That leaves people "not verified" (or brings back a verification the user had
removed), but it can never make an unverified person appear verified.

Clients classify every person they show:

| Level | Condition | Client behaviour |
|---|---|---|
| verified | The user ID is in the list, and its current fingerprint matches | ✔ badge |
| changed | The user ID is in the list, but the fingerprint differs | Red warning; refuse to share with them or grant them a team key. Published keys never change, so this means tampering. |
| look-alike | A different user ID whose name or email matches a verified contact's after folding case, accents, spacing, punctuation, invisible characters and common homoglyphs (Cyrillic and Greek look-alikes; `0`→`o`; `1`, `i` and `l` as one class) | Red "possible impersonation" warning; extra confirmation before sharing or granting |
| unverified | Anything else | Neutral badge with a "Verify…" action |

Name matching only produces warnings; it never grants anything. Only the fingerprint
comparison establishes identity.

## Trust in the key directory

Clients fetch other users' public keys from the server. A malicious server could substitute its
own keys, or create a look-alike account, when Alice shares with Bob (a machine-in-the-middle on
key distribution), the same limitation every E2EE system without key transparency has. Verified
contacts (§8) turn a one-time out-of-band fingerprint comparison into lasting protection. After
Bob verifies Alice, substituted keys show "key changed" and look-alike accounts show
"possible impersonation", wherever Alice appears. Fingerprints are shown in Settings, in the
verification dialog, and in every share and grant confirmation. All other server misbehaviour
(swapping keys, names or content between nodes; truncating or reordering content; forging
grants) is detected by the AADs, commitments and signatures above.

## What the server can still see

Tree shape, node and space IDs, which user created what, sizes (to within chunk and padding
granularity), timestamps, sharing relationships, team memberships, and access patterns. It can
also delete or withhold data (availability is not protected by cryptography).
