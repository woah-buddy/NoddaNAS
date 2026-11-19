# Threat model

This document records what NoddaNAS protects, from whom, how, and what risk remains. It uses
STRIDE per trust boundary. Each mitigation points to code or tests so a claim can be checked.

## Assets

| Asset | Why it matters |
|---|---|
| File content and names | The reason the system exists; often personal or regulated data |
| Keyring (KEKs) | Unlocks every stored file |
| Session cookies, app passwords, link tokens | Bearer credentials: whoever holds one acts as its owner |
| Sharing graph and metadata | Reveals relationships, structure, activity |
| Availability and quota | Storage is finite and shared |

## Actors

- **Anonymous internet user**, possibly holding a leaked public link.
- **Authenticated user** trying to reach other users' data or exceed their rights.
- **Malicious recipient** of a share.
- **Hostile web page** visited by a signed-in user (CSRF, XSS, clickjacking, XS-leaks).
- **Compromised client device** holding an app password.
- **Storage-tier attacker**: obtains the data volume, a backup or a snapshot.
- **Database attacker**: obtains a database dump.
- **Network attacker** between client and proxy, or inside the container network.

Out of scope: a fully compromised NoddaNAS host or process (it holds the keyring in memory),
a malicious administrator, a compromised OIDC provider.

## Trust boundaries

1. Internet → reverse proxy (TLS termination)
2. Proxy → NoddaNAS (HTTP on a private network)
3. NoddaNAS → OIDC provider (HTTPS)
4. NoddaNAS → PostgreSQL
5. NoddaNAS → blob storage volume
6. NoddaNAS process → the web client running in users' browsers

## STRIDE analysis

### Spoofing

| Threat | Mitigation | Evidence |
|---|---|---|
| Forged sign-in / stolen authorization code | OIDC code flow with PKCE (S256), `state` bound to a browser cookie and a single-use server-side login record, `nonce` checked against the ID token; ID token signature, issuer, audience and expiry verified | `auth/oidc.go`; e2e "access policy and forged callbacks" |
| Anyone with an IdP account signs in (e.g. a public IdP) | Optional group / verified-email-domain allowlist; loud startup warning if neither is set | `auth/oidc.go checkPolicy`, `cmd/noddanas` |
| Account takeover via a re-used or unverified email | Accounts keyed by (issuer, subject); emails recorded only when verified and unclaimed, so nobody can register a victim's address to receive shares | `service/users.go`; `TestProvisioning` |
| Session fixation | A new random session token on every login; the old session is deleted | `auth.StartSession`, `handleCallback` |
| Guessing tokens or IDs | 256-bit tokens, 128-bit IDs from `crypto/rand`; all validated for shape before any lookup | `secure`, `validate.ID` |
| Brute-forcing link passwords | argon2id hashing; lockout after N failures (default 10 for 15 min); per-IP rate limit on public endpoints | `access.go authorizeLink`; `TestPublicLinks` |

### Tampering

| Threat | Mitigation | Evidence |
|---|---|---|
| Modifying stored blobs (storage attacker) | Per-chunk AES-GCM with index and final-chunk flag in the nonce: modification, truncation, reordering and blob swapping are detected | `blobcrypt`; `TestTamperingIsDetected`, `TestCorruptBlobIsDetected` |
| Moving a wrapped data key to another record | Key wrapping authenticates the blob key as associated data | `keyring.go`; `TestKeyringWrapAndRotate` |
| Truncated or altered uploads | Optional declared size and SHA-256 enforced; WebDAV uploads aborted unless the body ended cleanly | `service/content.go`, `httpapi/dav.go`; `TestUploadIntegrity` |
| Lost updates / races | Revision checks and quota limits evaluated in the same SQL statement as the write | `store/postgres`; `TestQuotaIsAtomic` |
| SQL injection | Parameterized queries only; IDs format-validated | `store/postgres` |
| CSRF | Go `http.CrossOriginProtection` (Sec-Fetch-Site / Origin), `SameSite=Lax` cookies, JSON-only APIs, Host validation | `httpapi/server.go`; e2e "CSRF and host checks" |

### Repudiation

| Threat | Mitigation |
|---|---|
| Denying an action | Structured JSON audit events (uploads, downloads, shares, logins, failures, purges) with user ID, object IDs and request ID. Logs record route patterns and IDs, never file names, tokens or passwords. Ship stdout to an append-only store for tamper resistance. |

### Information disclosure

| Threat | Mitigation | Evidence |
|---|---|---|
| Horizontal access (user A reads B's files) | Single authorization point; ownership checked on the whole ancestor chain; "not found" for invisible items | `access.go`; `TestTenantIsolation` |
| Share escalation (read → write, escaping the shared subtree) | Permissions computed per level; link access requires the shared node to be an ancestor; links are read-only by DB constraint | `TestReadShare`, `TestWriteShare`, `TestPublicLinks` |
| Stolen volume / backup / snapshot | Application-level encryption; random blob names reveal no structure or ownership | `TestContentIsEncryptedAtRest` |
| Stolen database dump | Contains only *wrapped* DEKs (useless without the keyring), hashes of all bearer secrets, argon2id for link passwords. **Does** reveal file names, sizes and the sharing graph (see residual risks) | schema |
| Stored XSS via uploaded HTML/SVG | Downloads forced to `attachment` + `octet-stream` + `nosniff` + `CSP: sandbox`; inline only for passive media; WebDAV GETs pinned to `octet-stream` | `handlers.go serveContent`, `dav.go`; e2e "upload and safe download", "webdav" |
| XSS in the web client | No HTML sinks; CSP `script-src 'self'` with Trusted Types enforced and no policies | `ui.go`, `app.js` |
| Token leakage via logs/Referer | Link tokens in URL fragments and POST bodies; `Referrer-Policy: no-referrer`; logs record route patterns | `handlers.go`, `middleware.go` |
| Clickjacking / XS-leaks | `frame-ancestors 'none'`, `X-Frame-Options`, COOP and CORP `same-origin` | `middleware.go` |
| Verbose errors | Only typed, client-safe messages reach clients; internal errors return a request ID | `respond.go writeError` |
| Plaintext DB traffic | Recommend `sslmode=verify-full` off-host; compose puts PostgreSQL on an internal network | README, compose |

### Denial of service

| Threat | Mitigation |
|---|---|
| Storage exhaustion | Per-user quotas enforced atomically, including versions; max file size; uploads cut off at remaining quota |
| Slowloris / stalled transfers | `ReadHeaderTimeout`, default read/write deadlines, idle-extending deadlines for streams |
| Large or deep requests | JSON bodies capped at 64 KiB, header cap, folder depth capped (64), listing pages capped |
| Credential stuffing / scanning | Per-IP rate limits on sign-in, public and failed-auth paths; IP taken from `X-Forwarded-For` only from trusted proxies |
| argon2 as a CPU/memory amplifier | Parameters bounded when parsing stored hashes; public endpoints rate limited |
| Link lockout abuse | Accepted: an attacker must already hold the 256-bit token to trigger lockout |

### Elevation of privilege

| Threat | Mitigation | Evidence |
|---|---|---|
| App password used to mint more credentials | Credential management requires an interactive session | e2e "app passwords are scoped" |
| Read-only credential writing | Principal capped at `read` inside authorization | `TestReadOnlyCredential` |
| Re-sharing by recipients | Only owners can share | `TestReadShare` |
| Container escape impact | Distroless, non-root, read-only root FS, all capabilities dropped, `no-new-privileges`, seccomp `RuntimeDefault` (k8s) | `Dockerfile`, `deploy/` |
| Supply chain | Few dependencies (Go stdlib, `x/` packages, pgx, go-oidc); `go mod verify`; govulncheck, gosec, staticcheck and Trivy in CI; GitHub Actions pinned to commit SHAs; Dependabot | `.github/` |

## Residual risks and accepted trade-offs

1. **Metadata is not encrypted.** File and folder names, sizes, timestamps and sharing
   relationships are plaintext in PostgreSQL so the server can list, search and enforce
   uniqueness. Protect database dumps accordingly (encrypted backups, `verify-full` TLS).
2. **The server can read content.** Encryption is server-side, protecting storage and backups,
   not against a compromised NoddaNAS process or administrator. End-to-end encryption would make
   sharing, previews and WebDAV much harder; it is a deliberate non-goal for now.
3. **User enumeration via sharing.** Sharing by email reveals whether that email has an account
   (same as Nextcloud's user search). Limited to authenticated users.
4. **Revocation latency for downloads in progress.** Revoking a share stops new requests
   immediately; a download already streaming continues to completion.
5. **Per-replica rate limits and WebDAV locks.** See ARCHITECTURE.md › Scaling.
6. **Trash ≠ immediate deletion.** Deleted items remain restorable for the retention period, and
   storage-level snapshots may retain ciphertext longer. Crypto-shredding makes such leftovers
   unreadable once the version row is purged.
7. **Keyring loss = data loss.** By design there is no recovery path without the keyring. Back it
   up separately from the data (see OPERATIONS.md).
