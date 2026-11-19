# Architecture

NoddaNAS is a single stateless Go binary in front of two stateful stores: PostgreSQL for
metadata and a filesystem for encrypted file content. Everything else (identity, TLS) is
delegated to dedicated components that already do those jobs well.

```
                 ┌──────────────────────────┐
  browser ──────▶│ reverse proxy (TLS)      │   Caddy / ingress controller
  WebDAV  ──────▶│                          │
  scripts ──────▶└────────────┬─────────────┘
                              │ HTTP
            ┌─────────────────▼──────────────────┐        ┌──────────────────┐
            │ noddanas (1..N replicas)           │◀──────▶│ OIDC provider    │
            │                                    │ OIDC   │ (MFA, passkeys,  │
            │  httpapi  ─ JSON API, WebDAV, UI   │        │  lockout, users) │
            │     │       public links           │        └──────────────────┘
            │  auth     ─ sessions, app passwords│
            │     │                              │
            │  service  ─ use cases +            │
            │             THE authorization point│
            │     │                   │          │
            │  store (SQL)        blobcrypt      │
            │     │                   │          │
            └─────┼───────────────────┼──────────┘
                  │                   │ ciphertext only, random names
         ┌────────▼───────┐   ┌───────▼───────────────┐
         │ PostgreSQL     │   │ filesystem volume      │
         │ tree, versions,│   │ (disk, NAS, NFS, PVC)  │
         │ wrapped keys,  │   └────────────────────────┘
         │ shares, quota  │
         └────────────────┘
```

## Layers and the dependency rule

Dependencies point inward only:

| Layer | Knows about | Never knows about |
|---|---|---|
| `domain` | nothing | everything else |
| `validate`, `secure`, `blobcrypt` | `domain` | HTTP, SQL |
| `service` | the above + its own interfaces (`Store`, `BlobStore`, `Keyring`) | HTTP, SQL, OIDC |
| `auth` | `service` | SQL details |
| `httpapi` | `service`, `auth` | SQL, files on disk |
| `store/postgres`, `blob/fsblob` | `domain`, the interfaces they implement | HTTP |

The point of this rule is that **authorization lives in exactly one layer**. `httpapi` cannot
reach the database, so it cannot "forget" a permission check: the only way to get a node is to
ask the service, and the service always authorizes first. Swapping PostgreSQL or the blob backend
cannot weaken a security rule, because adapters only persist what they are told.

## Authorization model

Implemented in `internal/service/access.go`.

1. Load the node's ancestor chain (node, parent, ..., root) in **one** recursive SQL query.
2. Check invariants on the chain: it reaches a root, it is no deeper than `MaxDepth` (fail
   closed), every node has the same owner, nothing in it is trashed.
3. Compute the caller's permission at every level of the chain:
   owner → `owner`; otherwise the strongest user-share grant at that level or above.
4. A caller with no permission gets **404 Not Found**. A caller who can see the node but lacks a
   stronger permission gets 403. This avoids an existence oracle.
5. Read-only credentials are capped to `read` regardless of ownership.

Structural changes (rename, move, delete) require **write on the parent**, the same rule POSIX
directories use. That one rule produces the expected sharing behaviour without special cases: if
Alice shares `Photos` with Bob read-write, Bob can manage what is *inside* `Photos` but cannot
rename or delete `Photos` itself, because he has no access to Alice's root folder.

Moves are refused when they would create a cycle or cross owners (content and quota belong to
the owner; cross-owner moves would silently transfer both).

## Data model

```
users     (id, issuer, subject, email?, root_id, quota_bytes, used_bytes)
nodes     (id, owner_id, parent_id?, name, name_key, kind, size, sha256, version_id,
           revision, trashed_at?, purging, purge_lease?)
versions  (id, node_id, owner_id, blob_key, wrapped_key, size, sha256, created_*)
shares    (id, kind, node_id, owner_id, permission, recipient_id? | token_hash, password_hash,
           expires_at, max_downloads, downloads, failed_attempts, locked_until)
sessions, app_passwords, login_requests   (secrets stored only as SHA-256 hashes)
```

Notable constraints (`internal/store/postgres/migrations/0001_init.sql`):

- `UNIQUE (parent_id, name_key) WHERE trashed_at IS NULL`: one live item per (case-folded) name
  per folder; trashed items free their name.
- `CHECK (kind = 'user' OR permission = 'read')`: a public link cannot grant write, even if a
  future bug tries to create one.
- `versions.node_id ... ON DELETE RESTRICT`: a node cannot be deleted while it still has stored
  content, so quota accounting cannot silently drift.
- Quota is charged with `UPDATE users SET used = used + $n WHERE used + $n <= quota`: the check
  and the increment are one atomic statement, so concurrent uploads cannot overshoot. The test
  suite proves this with 20 concurrent uploads against a quota that fits 10.
- Every write that depends on state uses a revision or state condition in the same statement
  (optimistic concurrency: a stale client gets 412, never a lost update).

## Encryption at rest

Implemented in `internal/blobcrypt`.

**Envelope encryption.** A small keyring file holds one or more 256-bit key-encryption keys
(KEKs); the first is primary. Each stored version gets its own random 256-bit data key (DEK).
The DEK encrypts the content; the KEK encrypts the DEK; the wrapped DEK is stored in the
`versions` row. The wrapping is AES-256-GCM with the blob's key as authenticated data, so a
wrapped DEK copied to a different row will not unwrap.

**Content format (STREAM construction).** Content is split into 64 KiB chunks, each sealed with
AES-256-GCM. The nonce is the chunk index plus a flag marking the final chunk. This is the same
construction used by `age` and Google Tink, and it gives:

- confidentiality and integrity per chunk;
- protection against reordering (the index is in the nonce) and truncation (the final flag);
- random access, which makes HTTP Range requests (video seeking, resumed downloads) possible
  without decrypting from the start.

**Why bother when disks can be encrypted?** Disk encryption protects a powered-off disk. It does
nothing for a running server's NFS export, a backup copied elsewhere, a snapshot, or a storage
volume attached to the wrong machine. Application-level encryption keeps the storage tier
untrusted, which is also what makes a future S3-compatible backend safe to point at a third party.

**Crypto-shredding.** The DEK exists only in the `versions` row. Deleting the row makes the blob
permanently unreadable, even if a storage snapshot or backup still contains it.

**Key rotation.** Add a new key as the first line of the keyring and restart: new content uses it,
old content still decrypts with the old key. Old DEKs can later be re-wrapped (roadmap: a
`rewrap` command); blobs never need re-encrypting.

## Uploads and downloads

Uploads stream through the server: body → size limiter → SHA-256 hasher → encryptor → blob
store. Nothing is buffered whole, so memory use is constant regardless of file size. Then:

1. if the client declared a size or SHA-256, they must match exactly or the upload is discarded;
2. the caller is **re-authorized** (an upload can take minutes; access may have been revoked);
3. the node, version and quota charge commit in one transaction;
4. if anything fails, the blob is deleted. If the process dies before then, the orphaned blob's
   key was never stored, so it is unreadable garbage (a GC is on the roadmap).

Downloads decrypt on the fly through an `io.ReadSeeker`, handed to `http.ServeContent`, which
implements Range, If-Range and ETag (the content's SHA-256) correctly.

## Background work

Trash expiry and permanent deletion run inside each replica (`NODDANAS_WORKER=true`). Work is
claimed with `SELECT ... FOR UPDATE SKIP LOCKED` plus a lease, so the `nodes` table doubles as a
queue: any number of replicas cooperate without double-processing, and no message broker is
needed. Purging deletes blobs first and rows second, so a crash at any point leaves work that is
found and retried; each step is idempotent and quota is refunded exactly once.

## Scaling

- **Stateless replicas.** Sessions, locks on work items and all state live in PostgreSQL, so you
  can run several `noddanas` replicas behind a load balancer.
- **Shared storage.** Multiple replicas need a shared filesystem (NFS, CephFS, a ReadWriteMany
  volume). An S3-compatible backend is on the roadmap.
- **Rate limits** are per replica (in-memory). Put a global limiter in your proxy if needed.
- **WebDAV locks** are in-memory per replica. With several replicas, use sticky sessions for
  `/dav/`, or run WebDAV on one replica.
- **Database.** Hot paths are indexed single-row lookups plus one recursive query per
  authorization (depth ≤ 64). PostgreSQL replicas, connection pooling (PgBouncer) and partitioning
  are available if you ever outgrow one instance.

## Web client

`web/static` is plain HTML/CSS/ES modules embedded into the binary at build time: no build
step, no npm dependency tree to audit, and no separate asset server. It is written only against
DOM APIs (`textContent`, `createElement`) so it can run under a CSP that enforces Trusted Types
with no policies: the browser refuses every string-to-HTML sink outright.

Public links carry their token in the URL fragment (`/s#token`). Browsers never send fragments
to servers, so tokens do not appear in access logs, proxies or `Referer` headers; the client
sends the token in POST bodies only.
