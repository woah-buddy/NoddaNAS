# NoddaNAS

Self-hosted file storage and sharing, a lean alternative to Nextcloud's file features, built
**secure-by-design first, functionality second**. It ships as a single container image and runs
anywhere containers run: a home server, a NAS, on-premises hardware, Kubernetes, or any cloud.
Nothing in it depends on a particular cloud provider.

- **Language:** Go (memory-safe, statically compiled, small dependency tree, excellent standard library)
- **Metadata:** PostgreSQL
- **File content:** any POSIX filesystem (local disk, NAS mount, NFS/CephFS, Kubernetes volume), encrypted by the application
- **Sign-in:** any OpenID Connect provider (Keycloak, Authentik, Zitadel, Pocket ID, Entra ID, Google, ...)
- **Clients:** built-in web UI, WebDAV (Finder, Windows Explorer, rclone, davfs2, mobile apps), JSON API

## Features

| | |
|---|---|
| Files & folders | Upload/download (streaming, any size up to the configured limit), folders, rename, move, HTTP Range (video seeking, resumable downloads) |
| Versions | Every upload keeps a version; list, download, and restore old versions (configurable count) |
| Trash | Soft delete with restore; automatic purge after a retention period (default 30 days) |
| Sharing with users | Read or read-write access to a folder or file and everything below it; revocable; recipients can leave |
| Public links | Read-only, always expiring, optional password with lockout, optional download limit |
| Quotas | Per-user quotas, enforced atomically (concurrent uploads cannot overshoot) |
| WebDAV | Mount as a network drive using an app password |
| App passwords | Revocable, optionally read-only credentials for sync/CLI/WebDAV clients |

Not included (yet): calendar/contacts, document editing, the Nextcloud sync-client protocol,
end-to-end (client-side) encryption. See [Roadmap](#roadmap).

## Security at a glance

The full reasoning lives in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The headline decisions:

- **One authorization decision point.** Every operation from every interface (web, API, WebDAV,
  public links) passes through a single function (`internal/service/access.go`). Callers who cannot
  see an item get "not found", never "forbidden", so IDs cannot be probed.
- **No passwords stored, no auth invented.** Sign-in is delegated to your OIDC provider (which
  handles MFA, passkeys, lockout). Browsers get only an opaque `HttpOnly`, `Secure`, `__Host-`
  session cookie; OAuth tokens never reach JavaScript.
- **Encryption at rest with crypto-shredding.** Each file version has its own random AES-256 key,
  itself encrypted under a key-encryption key you hold. The storage volume only ever sees
  ciphertext under random names. Deleting a version destroys its key, so backups and snapshots of
  the volume become unreadable for it too.
- **Integrity enforced by the database.** Name uniqueness, quota accounting, optimistic
  concurrency and "public links are read-only" are SQL constraints or single-statement conditions,
  not just application checks.
- **Safe content delivery.** Downloads are `attachment` with `nosniff` and a sandboxing CSP;
  only passive media (images/audio/video) may display inline. Uploaded HTML or SVG can never run
  on your origin.
- **Hardened web client.** Strict Content-Security-Policy with Trusted Types enforced and zero
  policies: the browser itself refuses `innerHTML`-style injection.
- **Defense in depth on HTTP:** CSRF protection (Go's `CrossOriginProtection`), Host-header
  validation (anti DNS-rebinding), per-IP rate limiting, strict JSON parsing, bounded request
  sizes and slowloris-resistant I/O deadlines.
- **Minimal container:** distroless image, no shell, non-root UID, read-only root filesystem, all
  capabilities dropped; secrets read from files, not environment variables.

## Quick start (Docker Compose)

Requirements: Docker with Compose, a DNS name pointing at the host, ports 80/443 reachable (or see
"LAN only" below), and an OIDC provider.

1. **Register NoddaNAS with your OIDC provider** as a *confidential* client using the
   authorization-code flow, with redirect URI `https://<your-host>/auth/callback` and scopes
   `openid email profile`. Put the users who may sign in into a group (e.g. `noddanas-users`) and
   make sure the provider includes a `groups` claim in the ID token.

2. **Configure and start:**

   ```sh
   cd deploy/compose
   cp .env.example .env            # set NODDANAS_HOST, OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_ALLOWED_GROUPS
   sudo ../../scripts/init-secrets.sh
   sudo sh -c 'printf %s "<client secret>" > secrets/oidc_client_secret'
   docker compose up -d --build
   ```

3. **Back up `deploy/compose/secrets/noddanas_keyring` somewhere separate from your data.**
   Without it, stored files cannot be decrypted. With it plus the data volume, they can. Treat it
   like the master key it is.

4. Open `https://<your-host>` and sign in.

**LAN only:** add `tls internal` to `deploy/compose/Caddyfile` to use Caddy's local CA, and install
that CA on your devices.

To set a user's quota: `docker compose exec noddanas /noddanas set-quota alice@example.com 100GiB`.

## Configuration

All settings are environment variables. Any secret may instead be given as a file path via the
same name with a `_FILE` suffix (preferred: files stay out of `docker inspect` and process lists).

| Variable | Default | Purpose |
|---|---|---|
| `NODDANAS_PUBLIC_URL` | *(required)* | External origin, e.g. `https://files.example.com`. Must be HTTPS (plain HTTP only for localhost). |
| `NODDANAS_DATABASE_URL` | *(required)* | PostgreSQL DSN. Use `sslmode=verify-full` when the database is not on a private network. |
| `NODDANAS_KEYRING_FILE` | `/run/secrets/noddanas_keyring` | Encryption keyring. Refused if world-readable. Generate with `noddanas keygen`. |
| `NODDANAS_OIDC_ISSUER` | *(required)* | OIDC issuer URL. |
| `NODDANAS_OIDC_CLIENT_ID` | *(required)* | OIDC client ID. |
| `NODDANAS_OIDC_CLIENT_SECRET` | | OIDC client secret. |
| `NODDANAS_OIDC_ALLOWED_GROUPS` | | Comma-separated; at least one must appear in the groups claim. **Set this or the next one.** |
| `NODDANAS_OIDC_ALLOWED_EMAIL_DOMAINS` | | Comma-separated; requires a verified email in one of these domains. |
| `NODDANAS_OIDC_GROUPS_CLAIM` | `groups` | Claim holding group names. |
| `NODDANAS_OIDC_SCOPES` | `openid,email,profile` | Requested scopes. |
| `NODDANAS_DATA_DIR` | `/data` | Where encrypted blobs are stored. |
| `NODDANAS_LISTEN` | `:8080` | Listen address. |
| `NODDANAS_TRUSTED_PROXIES` | | CIDRs whose `X-Forwarded-For` is trusted (your reverse proxy). |
| `NODDANAS_DEFAULT_QUOTA` | `10GiB` | Quota for new users. |
| `NODDANAS_MAX_FILE_SIZE` | `50GiB` | Largest single file. |
| `NODDANAS_MAX_VERSIONS` | `10` | Versions kept per file (all count towards quota). |
| `NODDANAS_TRASH_RETENTION` | `30d` | How long trashed items are kept. |
| `NODDANAS_LINK_DEFAULT_TTL` / `_MAX_TTL` | `30d` / `365d` | Public link lifetime default / maximum. |
| `NODDANAS_SESSION_IDLE` / `_MAX_AGE` | `12h` / `7d` | Browser session idle timeout / absolute lifetime. |
| `NODDANAS_WEBDAV` | `true` | Serve WebDAV at `/dav/`. |
| `NODDANAS_WORKER` | `true` | Run background maintenance (trash expiry, purging) in this replica. |
| `NODDANAS_AUTO_MIGRATE` | `true` | Apply database migrations at startup. |
| `NODDANAS_TLS_CERT_FILE` / `_KEY_FILE` | | Serve HTTPS directly instead of behind a proxy. |
| `NODDANAS_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |

## Using WebDAV

Create an app password under **Settings** in the web UI, then connect your client to
`https://<your-host>/dav/` with any username and the app password. Examples:

- **macOS Finder:** Go → Connect to Server → `https://<your-host>/dav/`
- **Windows:** Map network drive → `https://<your-host>/dav/`
- **rclone:** `rclone config` → type `webdav`, vendor `other`, URL as above
- **Linux:** `mount -t davfs https://<your-host>/dav/ /mnt/nas`

Deleting through WebDAV moves items to the trash, so a misbehaving client cannot destroy data.

## Commands

```
noddanas serve                 run the server (default)
noddanas migrate               apply database migrations and exit (e.g. as an init container)
noddanas keygen [id]           print a new keyring line
noddanas set-quota EMAIL SIZE  set a user's quota, e.g. 50GiB
noddanas healthcheck           probe the local server (used by the image's HEALTHCHECK)
noddanas version               print the version
```

## Development

```sh
export NODDANAS_TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/noddanas_test?sslmode=disable'
make test     # unit + integration tests against real PostgreSQL, with the race detector
make lint     # gofmt, go vet, staticcheck
make vuln     # govulncheck
make gosec    # static security analysis
make docker   # build the container image
```

Integration tests skip themselves when `NODDANAS_TEST_DATABASE_URL` is unset. The end-to-end test
(`internal/httpapi/e2e_test.go`) runs the whole server over TLS against an in-process fake OIDC
provider, and checks the security properties above (CSRF, host checks, headers, scoped
credentials, WebDAV content-type pinning) as well as functionality.

### Repository layout

```
cmd/noddanas/          the single binary: server + admin commands
internal/domain/       core types and client-safe errors (no dependencies)
internal/validate/     the only place untrusted strings become trusted values
internal/secure/       IDs, tokens, hashing, argon2id (stdlib / x/crypto only)
internal/blobcrypt/    envelope encryption: keyring + seekable STREAM/AES-GCM
internal/service/      use cases and the single authorization decision point
internal/auth/         OIDC sign-in, sessions, app passwords
internal/httpapi/      JSON API, WebDAV, public links, static UI, middleware
internal/store/        PostgreSQL adapter and migrations
internal/blob/         blob storage adapters (filesystem)
web/static/            the web client (no build step, no npm dependencies)
deploy/                Docker Compose and Kubernetes reference deployments
docs/                  architecture, threat model, operations, API
```

## Roadmap

- S3-compatible blob backend (interface already in place: `service.BlobStore`)
- KEK in an external KMS / HashiCorp Vault Transit (interface: `service.Keyring`), plus a re-wrap command for key rotation
- Shared WebDAV lock store for multi-replica deployments
- Orphaned-blob garbage collector (orphans are already unreadable; this reclaims space)
- Thumbnails/previews in an isolated worker; malware scanning hook
- Admin UI, audit log viewer, user-visible activity feed
- Nextcloud-compatible sync protocol or a native sync client
- Copy across owners, folder downloads as zip

## License

GPL-3.0. See [LICENSE](LICENSE).
