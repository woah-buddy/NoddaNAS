# Architecture

FrontDir is a single stateless Go server in front of PostgreSQL (metadata) and a filesystem
volume (encrypted containers), with all content cryptography done in clients: the browser
(`web/static/e2ee.js`) and the Go CLI (`internal/e2ee`, `internal/client`). Identity is
delegated to an OIDC or SAML provider.

```
 browser (WebCrypto) ─┐                          ┌──────────────────────┐
 frontdir-cli (Go)  ──┼── HTTPS ── reverse proxy │ OIDC and/or SAML IdP │
 rclone (WebDAV, ro) ─┘               │          └──────────┬───────────┘
                                      ▼                     │ sign-in only
                     ┌────────────────────────────────────┐ │
                     │ frontdir (1..N stateless replicas) │◀┘
                     │  httpapi   JSON API, WebDAV, UI     │
                     │  auth      sessions, app passwords  │
                     │  service   THE authorization point  │
                     │            quota, structure checks  │
                     └───────┬──────────────────┬──────────┘
                             │ SQL              │ opaque containers, random names
                    ┌────────▼───────┐  ┌───────▼────────────────┐
                    │ PostgreSQL     │  │ filesystem volume       │
                    │ tree shape,    │  │ (disk, NAS, NFS, PVC)   │
                    │ encrypted      │  └─────────────────────────┘
                    │ names, wrapped │
                    │ keys, grants   │
                    └────────────────┘
```

## Two independent layers of protection

1. **Authorization (server).** Who may fetch, write, list or delete which ciphertext. Enforced in
   one place, `internal/service/access.go`, for every interface.
2. **Cryptography (clients).** Who can *read* anything. Even an attacker who bypasses the server
   entirely (stolen disk, database dump, malicious administrator) holds only ciphertext and keys
   wrapped for someone else.

Neither layer trusts the other. A client verifies every key it receives (signatures, AEAD
bindings, key commitments); the server authorizes every request regardless of what the client
could decrypt.

## Spaces

A *space* is an independently owned tree with its own quota and its own key material:

- **Personal space**: one per user, created at first sign-in. Its secret is derived from the
  user's master key, so nothing about it needs to be shared.
- **Team folder** (team space): owned by no single user. Membership is the union of
  - **direct members**, added by a manager with a role (`read`, `write`, `manage`); any user may
    create a team folder (configurable), becoming its first manager; and
  - **group members**, from identity-provider groups that an **administrator** has mapped to the
    folder with a role. Groups are refreshed from the IdP at every sign-in.

Because the server cannot read the team key, joining has two halves: the server records the
membership (access is authorized immediately), and a manager's client *grants* the member the
team secret (sealed to their public key and signed). The web app does this automatically when a
manager opens the team page; `frontdir-cli` and the API expose it too. A team must always keep a
manager who holds the key, or nobody could grant it again.

Leaving a group, being removed, or an administrator deleting a group mapping revokes access at
the server immediately and deletes the member's stored key grant.

## Authorization model

`authorize(principal, node, want)`:

1. Load the node's ancestor chain in one recursive query; check it reaches the space root, stays
   in one space, contains nothing trashed, and that the space is not being deleted.
2. Start from the caller's **space role** (personal owner → full control; team member → their
   effective role).
3. Overlay **user shares** on the chain: a share grants its permission on its node and everything
   below it.
4. Cap read-only credentials at `read`. Callers with no permission get **404**; callers who can see
   the node but lack a stronger permission get 403.

Structural changes (rename, move, delete) need **write on the parent folder**, as in POSIX, so a
user given write access to a shared folder can manage its contents but not delete or rename the
shared folder itself. Moves never cross spaces (that would silently move content and quota to
another owner; clients copy instead, which also re-encrypts for the new owner).

## What the server stores

| Data | Form |
|---|---|
| File content | Client-encrypted containers under random names |
| File/folder names | Client-encrypted (`name_enc`) plus a keyed hash (`name_hash`) for uniqueness |
| Node keys | Wrapped under the parent folder's key (`wrapped_key`) |
| Space keys | Space public key (signed by its creator), root key wrapped under the space secret, team secret sealed to each member (signed by the granter) |
| User keys | Public keys plus the encrypted key bundle |
| Shares | Node key sealed to the recipient and signed by the sharer; links: node key encrypted under a secret that exists only in the link's URL fragment |
| Trash | Node key and name sealed to the space, signed by whoever trashed it |
| Bearer secrets | Hashes only (sessions, app passwords, link tokens) |

Integrity rules are database constraints (`internal/store/postgres/migrations/0001_init.sql`):
unique live name hash per folder; links can only grant read; a node with stored versions cannot be
deleted; quota is charged by `UPDATE ... WHERE used + n <= quota` in the same transaction that
records the content.

## Uploads, downloads and versions

The client encrypts a file into a container (header, 64 KiB STREAM chunks, signature trailer) and
uploads it with its encrypted directory entry. The server, without any key:

1. authorizes write on the destination folder (or file, for a new version);
2. parses the container header to learn its declared plaintext size and owning space, and refuses
   containers sealed to a different space;
3. streams the body to storage while hashing it, requiring the exact length the header implies;
4. re-authorizes (an upload can take minutes), then commits node, version and quota atomically.

Downloads return the container unchanged; the client checks the key commitment, decrypts, and
verifies the uploader's signature before trusting the result. Restoring an old version copies that
version's container into a new version; history is never rewritten.

## Independent backup and restore

Each container carries the file's key sealed to its **owner space**, plus encrypted metadata
(name, type, modification time) and the uploader's signature. Therefore:

- **Single file.** Download it (`Backup` in the app, `frontdir-cli backup`, WebDAV). To restore,
  the owner's client opens the owner seal with the space keys, verifies the signature, and uploads
  the container byte-for-byte unchanged with a new encrypted directory entry.
- **Offline.** `frontdir-cli decrypt` needs only the container, the key backup (the encrypted key
  bundle plus team grants) and the passphrase or recovery code.
- **Whole trees.** The WebDAV view and `frontdir-cli backup` write ID-named containers plus
  encrypted folder records (`_frontdir-folder.json`) and the space record
  (`_frontdir-space.json`). `frontdir-cli decrypt-tree` rebuilds the full tree, with real names,
  entirely offline. The backup medium never sees a plaintext name.

The server no longer encrypts at rest itself: an extra server-side layer would tie each stored
blob to a server key and database row, which is exactly what independent restore must avoid.
Disk-level encryption (LUKS, encrypted ZFS) remains a good idea for metadata.

## Sign-in

- **OIDC**: authorization-code flow with PKCE, state bound to a single-use server-side request
  and a `__Host-` cookie, nonce checked, ID token verified (signature, issuer, audience, expiry).
- **SAML**: SP-initiated only; `crewjam/saml` validates signatures, audience, issuer, destination
  and validity; FrontDir adds a single-use request binding (the AuthnRequest ID is stored
  server-side and consumed on first use; the browser carries a `SameSite=None` `__Host-` cookie
  because the IdP returns with a cross-site POST), refuses the artifact binding, and treats
  emails as verified only when the operator says so.
- Both feed the same **policy** (allowed groups / email domains) and refresh the user's groups and
  administrator flag at every sign-in. Accounts are keyed by (issuer, subject), never by email.
- Administrative changes need a **recent sign-in**: `/auth/reauth` sends the person back to the
  IdP with a forced authentication (OIDC `prompt=login`/`max_age=0`, SAML `ForceAuthn`), checks
  `auth_time`/`AuthnInstant`, and starts a new session marked with that time.
- Every request to an identity provider goes through one hardened HTTP client
  (`auth.NewIdPClient`) that refuses link-local, metadata and loopback addresses and caps
  responses, because administrators can enter IdP URLs on the web.

Browsers then hold only an opaque, HttpOnly, `__Host-` session cookie. Non-browser clients use
app passwords. Key setup and app-password management require an interactive session, so a
leaked app password cannot replace keys or mint more credentials.

## Settings

Server-only settings (addresses, database, storage, TLS, proxies, keys) come from the
environment. Settings an app owner decides are listed in `config.Registry` and can come from the
environment or from the web admin area; `config.Merge` applies precedence (environment, then web,
then default; each sign-in method as a whole) and `config.Build` validates and derives the runtime
configuration, the same code for both sources. `internal/settings` stores web values as one
revisioned document in PostgreSQL (secrets AES-GCM-encrypted under a key from the environment),
checks changes (recent re-authentication, live identity-provider checks, lockout guards,
confirmation before stranding accounts), and swaps the result into the running service, the
sign-in manager and the theme atomically. Replicas notice a new revision within 15 seconds. With
no sign-in method at all, the server runs in setup mode until the one-time setup link (`frontdir
setup-link`) is used.

## Background work

Trash expiry, permanent deletion and team-folder deletion run in each replica, claiming work
with `FOR UPDATE SKIP LOCKED` plus a lease. Purges delete blobs before rows, so an interrupted
purge is simply resumed; quota is refunded exactly once per version.

## Scaling

Replicas are stateless (sessions and work queues live in PostgreSQL). Several replicas need shared
storage (NFS, CephFS, ReadWriteMany volumes). Rate limits and WebDAV locks are per replica.
Because clients do all cryptography, server CPU is spent on I/O and SQL only.

## Web client

`web/static` is plain ES modules embedded into the binary: no build step and no npm dependencies.
It uses only DOM APIs, so it can run under a CSP that enforces Trusted Types with a single, narrow
policy (below).
Keys are held in memory for the tab's lifetime (WebCrypto private keys are imported
non-extractable); reloading asks for the passphrase again.

Downloads under 64 MiB are decrypted in memory and verified completely before they are offered.
Larger ones stream to disk: the page fetches the container, decrypts it chunk by chunk
(`openContainerStream` in `e2ee.js`), and hands each chunk to a service worker (`/dl/sw.js`,
registered with scope `/dl/` so it sees no other request), which turns the stream into an
ordinary browser download. The worker fetches nothing and keeps nothing; the page holds the keys.
Registering it needs a Trusted Types script URL, so the CSP allows exactly one policy,
`frontdir-sw`, which can only produce that one constant URL.

Thumbnails ([E2EE.md §5a](E2EE.md#5a-thumbnails)) are made in the browser when an image or video
is uploaded (`createImageBitmap`, or a frame captured from a `<video>` loaded from the local file,
which is why the CSP allows `media-src blob:`), or later with **Make thumbnails** on a folder.
Each is a small record encrypted for one version and stored beside the container, so adding one
never rewrites a file. Folder listings carry a `hasThumbnail` hint; only rows on screen fetch
theirs, four at a time, and a preview is shown only if made by the version's author or by the
viewer.

## Local drive (`frontdir-cli mount`)

`internal/davgw` is a WebDAV server that runs on the user's computer with their unlocked keys and
serves their spaces decrypted: Home and each team folder. Reads use `client.RemoteFile`, which
fetches only the byte ranges asked for (pinned to one version) and decrypts them with random
access; writes are buffered (spilling to disk only under a throwaway key), then encrypted and
uploaded on close. It listens on loopback only, requires a random token in the path, refuses
requests from browsers, and keeps operating-system clutter (`.DS_Store`, `._*`, `Thumbs.db`,
Office lock files) in memory. See [MOUNT.md](MOUNT.md).

Both paths release plaintext before a whole file has been read, so they share one rule, from
`e2ee.Verifier`: every chunk released has passed AES-GCM; the last chunk is released only after the
author's signature over all chunks verifies; on failure the transfer is aborted.

Colors are CSS custom properties defined only in `/theme.css`, which `internal/theme` generates at
startup from validated tokens. It uses cascade layers (mode, then accent, then high contrast), so
precedence is explicit rather than a specificity contest. The page picks a mode and accent with
`data-theme` / `data-accent` attributes on `<html>`, set from an allowlisted `localStorage` value
by `theme-init.js` before first paint. See [THEMING.md](THEMING.md).
