# End-to-end encryption specification (v1)

This is the normative description of FrontDir's end-to-end encryption. Two independent
implementations follow it: the browser client (`web/static/e2ee.js`, WebCrypto) and the Go
client library (`internal/e2ee`, used by the `frontdir-cli` tool and the test suite). The
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
- **Why "noddanas"?** FrontDir was called NoddaNAS when this format was defined. Labels, the
  container magic `NDNSE2E1`, and the server's token-hash labels (`noddanas/session/v1` and
  similar) are inputs to key derivation, authenticated data and hashes, so changing them would
  make every existing file, backup, link and session unreadable or invalid. They are fixed
  identifiers of format v1, not branding, and stay as they are. Names that are only read by a
  parser did change, and the old ones are still accepted: backups use `.fdenc` (`.ndne` before),
  mirror metadata `_frontdir-space.json` / `_frontdir-folder.json` and format tags such as
  `frontdir-keys/v1` (`noddanas-...` before), and app passwords start with `fd_` (`ndn_` before).

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

Each stored file version is one self-contained container (`.fdenc` when exported):

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

**Readers that cannot hold a whole file** (streaming browser downloads, the local WebDAV drive)
release plaintext chunk by chunk. They follow one rule: a chunk is released only after AES-GCM
authenticated it (so nobody without `NK`, the server included, can alter, reorder, drop, swap or
truncate anything unnoticed), and when chunks are read in order, the final chunk is released only
after the signature over all of them verifies. If it does not, the transfer is aborted (the
browser discards the partial download; a copy from the drive fails), so a forged file never
arrives whole. Ranged reads that skip chunks cannot check the signature and are authenticated by
AES-GCM alone; what they lack is attribution (proof of which key holder wrote the file), not
integrity. Small downloads in the browser, `frontdir-cli get` and restores still verify
everything before releasing anything.

Why each part exists:

- `owner.key` makes the container **independently restorable**: whoever holds the space secret
  (the owner, via passphrase or recovery code, or any team member) can open it with no other
  data. Restoring a backup into a folder re-wraps `NK` under that folder; the container bytes
  are stored unchanged and stay encrypted.
- `commit` makes the container **key-committing** (AES-GCM alone is not): a container fetched
  through the folder hierarchy is accepted only if it commits to the `NK` the hierarchy gave.
- The signature makes the container **attributable**, which matters for backups: anyone can seal
  a key to a public key, so an unsigned container from a backup could have been planted.

The server parses only `v`, `alg`, `size`, `owner.space` and `signer.user` (which must be a
well-formed user ID), checks the total length, and stores the bytes as they are. While they
stream in it also computes the values §5b needs.

## 5a. Thumbnails

A thumbnail is a small encrypted record attached to **one version** of a file, stored beside its
container rather than inside it. That way a thumbnail can be added to an existing file without
rewriting the file or touching its author's signature (which covers the whole header).

```
tk  = HKDF(NK, salt, info="L/file/thumb")        salt: that version's container salt
ct  = GCM(tk, JSON{"type", "w", "h", "data"}, aad = "L/file/thumb" \0 nodeId)
sig = Ed25519(makerSigPriv, "L/thumb-sig" \0 nodeId \0 || salt || SHA-256(ct))
```

`type` is `image/webp` or `image/jpeg`, `w` and `h` are at most 512, and `data` is `b64u` of at
most 24 KiB of image bytes. The server stores `{enc: b64u(ct), sig, maker}` per version and per
maker, and parses none of it.

- Only key holders can make a thumbnail (`tk` needs `NK`), the salt ties it to exactly one
  version (another version's key differs), and the AAD ties it to the node.
- Before deriving `tk`, readers check the header's key commitment against `NK`, so the header
  that supplies the salt and the author belongs to this node.
- **Display rule:** a thumbnail is shown only if its maker is the version's **verified** author
  (§5b: the signature over the header and body hash checks out for them) or the viewer. If the
  author cannot be verified, viewers see only their own thumbnails. A collaborator with write
  access can attach a thumbnail to someone else's file, but only they will ever see it. Records
  are stored per maker, so nobody can overwrite the author's thumbnail.
- Thumbnails are generated on the uploader's device from the plaintext, re-encoded, so photo
  metadata (EXIF, GPS) is not carried over. Clients render them only as `<img>` images of the two
  allowed types, never as SVG or a document.

## 5b. Version attribution

Every version shows who wrote it, checked without downloading the file. The container signature
(§5) covers `SHA-256(prefix) || BH`. Computing `BH` normally takes the whole body, but `BH` is not
secret: it is a hash of ciphertext. The server computes it once, as an upload streams in (chunk
boundaries follow from the header's `size`), and stores beside each version:

| Stored | Value |
|---|---|
| `prefix` | bytes `[0, 12+H)` of the container |
| `bodyHash` | `BH` |
| `trailer` | the last 68 bytes: `"SIG1"` and the signature |

A client verifies a version's author by:

1. parsing `prefix`, which must be exactly `12+H` bytes;
2. checking the key commitment against the `NK` the folder hierarchy gave, so the header is one
   that this node's key made;
3. looking up the user the header names and checking their key fingerprint matches;
4. verifying the trailer's signature with that user's key over
   `"L/container" \0 || SHA-256(prefix) || bodyHash`.

**Why the server cannot misattribute a version.** Only the author's key makes that signature, and
a header belongs to exactly one container (it carries a fresh random salt). So the only
`bodyHash` that verifies with a given header is the one its author computed. A server that alters
the prefix, `bodyHash` or trailer, or pairs one version's header with another's, makes the check
fail; it cannot make it name someone else. Clients show such a version as unverifiable.

What a passing check does not prove: that the stored body still matches `BH`. Reading the file
proves that (§5), as before. Attribution answers "who wrote this version", not "is the copy on
the server intact".

**Restores.** Restoring a version stores its container unchanged as a new version, so it keeps
its author. Who restored it comes from the restorer's signed version record (§5c). Clients show
both ("You · restored by Bob").

**Older versions.** Versions stored before the server recorded these values have none at first.
The server's maintenance worker computes them from the stored ciphertext, a few per run; until
then clients show the author as not checked yet. A container that is missing or damaged gets an
empty record and stays unverifiable.

## 5c. Signed version history

§5b proves who *wrote* each version. Everything else about a file's history (when each version
was saved, who stored it, and their order) would otherwise be the server's word. So whoever stores
a version also signs a small **version record** about it, and each record names the one before
it. That forms a hash chain, as commits do in git.

```
record = JSON{"v":1, "node", "seq", "prev", "container", "kind", "at", "by", "fp"}
sig    = Ed25519(by's key, "L/version-record" \0 || record bytes)
```

| Field | Value |
|---|---|
| `node` | the file's node ID |
| `seq` | position in the file's history: 1 for the first recorded version, then +1 each time |
| `prev` | `b64u(SHA-256(previous record's bytes))`; `""` exactly when `seq` is 1 |
| `container` | `b64u(SHA-256(prefix))`: which container this version is. The prefix holds a fresh salt, and the author's signature ties it to the body |
| `kind` | `"save"` (the signer encrypted this container, so `by` and `fp` must equal the header's `signer`) or `"restore"` (the signer stored an existing container again, from the history or a backup) |
| `at` | the signer's clock, Unix milliseconds |
| `by`, `fp` | the signer's user ID and key fingerprint |

The record must be in canonical form: these keys in this order, no spaces, integers as plain
digits. Go and the browser produce identical bytes, and readers refuse any other encoding, so the
two can never interpret the same bytes differently. At most 1 KiB.

**Uploading.** Before saving a new version, a client fetches the file's history, checks it (below),
and signs the record that follows the current one. The record travels with the upload. The server
stores only versions whose record is well-formed, signed by the uploader, about this file and this
container, and directly follows the current version. A unique (file, `seq`) index makes racing
uploads for the same position fail cleanly. A restore through the server needs a `restore` record
naming the restored container. Versions stored before records existed have none; new versions
always do.

**Checking a history** (`verifyHistory` / `VerifyHistory`), versions newest first:

1. Each record parses, is about this node, verifies under the key of the user it names (with the
   fingerprint it names), names this version's container, and for a `save` was signed by the
   container's author.
2. Recorded versions come first. A version without a record may only be older than every recorded
   one (versions from before records existed).
3. Each record follows the next older one: `seq` one higher, and `prev` equal to that record's hash.
4. The oldest record either has `seq` 1, or is the oldest version listed (older versions were
   deleted under the version limit, oldest first).

The server can no longer reorder versions, slip one in, drop one from the middle, change who
stored one or when, or present a restore as a save. Each of these breaks a signature or a link,
and the client reports the history as tampered with.

**Remembering (rollback and fork detection).** A chain doesn't stop the server cutting the newest
versions off the end: what's left is still a valid chain. So each client remembers, per file, the
newest record it has verified (`seq` and hash), on the device:

- **Gone back in time:** the history now ends before the remembered `seq`, or the file has no
  signed history any more.
- **Forked:** the version at the remembered `seq` has a different hash, or (when only the current
  record is known) the next version doesn't name the remembered one as `prev`.
- Otherwise the newer head is remembered. If the remembered version is older than every version
  still kept, ancestry can't be checked, and the history is accepted.

Clients check on every download of the current version (the server sends its record in
`X-FrontDir-Record` headers). If the current version is more than one ahead of what was
remembered, they check the whole chain in between. Clients also check before every save and
restore, and refuse to build on a history that fails. A rolled-back or forked file is not
downloaded or saved over until the user accepts the history as shown, for example after the
server was restored from a backup (Versions → Accept, or `frontdir-cli accept`). Acceptance
requires the history to be internally sound.

The memory stays on the device on purpose: kept on the server, it could be rolled back along with
everything else. Browsers keep it in local storage (the most recent 20,000 files per user), and
`frontdir-cli` and the drive keep it in a file (`FRONTDIR_STATE_DIR`).

**Limits.** These follow from having one untrusted server and no other channel between users:

- A client that has never seen a file's newer history can't tell it is missing. Each person
  catches rollbacks of what *they* have seen, including what they saved themselves.
- The server can show different people different histories (a fork). Each history must stay
  consistent from then on, and the split shows as soon as a client is shown a version that the
  other history produced. This is the best a single untrusted server allows ("fork consistency",
  Mazières and Shasha, PODC 2002).
- Clearing site data, or a new device, starts the memory afresh.
- This covers each file's versions, not the folder tree: the server can still hide a file,
  undo a rename or bring back a deleted file. That would need a signed log of every change per
  space.

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
granularity), timestamps, sharing relationships, team memberships, and access patterns. It also
sees which file versions have a thumbnail (a hint that they are images or videos) and the
thumbnail's size, but not the thumbnail. It can
also delete or withhold data (availability is not protected by cryptography).
