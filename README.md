# NoddaNAS

Self-hosted, **end-to-end encrypted** file storage and sharing: a lean alternative to Nextcloud's
file features, built **secure-by-design first, functionality second**. It ships as a single
container image and runs anywhere containers run (home server, NAS, on-premises, Kubernetes,
any cloud), with no cloud-provider dependencies.

- **End-to-end encryption.** Files, file and folder names, and team names are encrypted on your
  device (browser or CLI) before upload. The server stores and serves ciphertext only and never
  holds a key that could decrypt it.
- **Every file is independently backup-able and restorable, still encrypted.** Each stored file is
  a self-contained, signed container. One container plus your key backup and passphrase (or
  recovery code) is enough to decrypt or restore it: no server, no database.
- **Sign in with OIDC or SAML 2.0** (Keycloak, Authentik, Zitadel, Pocket ID, Entra ID, Okta,
  Shibboleth, Google, ...).
- **Team folders**: owned by no single user, with their own quota. Members are added directly by
  managers (any user can create one) and/or through identity-provider **groups mapped by
  administrators**.
- **Sharing**: with individual users (read or read-write), and public links (always expiring,
  optional password and download limit, decryption key carried in the link's `#fragment`).

**Stack:** Go, PostgreSQL (metadata), any POSIX filesystem volume (encrypted containers), WebCrypto
in the browser.

## Features

| | |
|---|---|
| Files & folders | Upload, download, folders, rename, move, versions (restore any), trash with automatic purge |
| Backups | Download any file as an encrypted `.ndne` container and restore it later, anywhere in the same space; `noddanas-cli backup`; read-only WebDAV for rclone/restic mirrors |
| Offline recovery | `noddanas-cli decrypt` / `decrypt-tree` turn containers or whole mirrors back into files with just your key backup |
| Personal spaces | Every user has one, with a per-user quota |
| Team folders | Direct members (read / write / manage), IdP group mappings (admin), separate quota, signed key grants |
| Sharing | Users (read/write, E2EE key sealed to the recipient and signed by you) and public links |
| Sign-in | OIDC (PKCE) and/or SAML (SP-initiated, signed assertions); allowlist by group or email domain |
| Clients | Web app (no build step, no npm dependencies) and `noddanas-cli` (Go) |
| Theming | Light, dark, high-contrast and system modes with accent colors per user; operator name, logo, palette and accents, all validated for safety and contrast ([THEMING.md](docs/THEMING.md)) |

Not included (yet): calendar/contacts, document editing, the Nextcloud sync protocol, a plaintext
WebDAV gateway (see [Roadmap](#roadmap)).

## How the encryption works (short version)

The full specification is [docs/E2EE.md](docs/E2EE.md); the reasoning is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

- When you set up encryption you choose a **passphrase** and receive a **recovery code**. Either
  unlocks your **account master key**, which unlocks your private keys (X25519 for receiving
  keys, Ed25519 for signing). These secrets never leave your device unencrypted.
- Every file and folder has its own random key, wrapped by its parent folder's key. Sharing a
  folder means sealing that folder's key to the recipient (and signing it); team folders work the
  same way with a team key granted to each member.
- Each file's content goes into a container that also seals the file's key to its **owner
  space** and is **signed by the uploader**. That is what makes a single file restorable without
  anything else, and what lets you detect a planted or altered backup.
- Names are encrypted too. Duplicate names are still detected (case-insensitively) through a keyed
  hash the server cannot reverse.

There is **no back door and no admin recovery**: if you lose both your passphrase and your
recovery code, your files cannot be decrypted by anyone.

## Quick start (Docker Compose)

Requirements: Docker with Compose, a DNS name pointing at the host, ports 80/443 reachable, and an
OIDC or SAML identity provider.

1. **Register NoddaNAS with your identity provider.**
   - *OIDC*: a confidential client using the authorization-code flow, redirect URI
     `https://<host>/auth/callback`, scopes `openid email profile`, with a `groups` claim.
   - *SAML*: start NoddaNAS once, then import `https://<host>/auth/saml/metadata` (ACS
     `https://<host>/auth/saml/acs`, NameID format *persistent*), and release email, display name
     and group attributes.
   Put the people who may sign in into a group (e.g. `noddanas-users`) and administrators into
   another (e.g. `noddanas-admins`).

2. **Configure and start:**

   ```sh
   cd deploy/compose
   cp .env.example .env            # host, OIDC and/or SAML, allowed groups, admin groups
   sudo ../../scripts/init-secrets.sh
   sudo sh -c 'printf %s "<oidc client secret>" > secrets/oidc_client_secret'   # if using OIDC
   docker compose up -d --build
   ```

3. Open `https://<host>`, sign in, choose an encryption passphrase, and **store the recovery code
   somewhere safe**. Then, under Settings, **download your key backup** and keep it with your
   backups (it is itself encrypted).

To change a user's quota: `docker compose exec noddanas /noddanas set-quota alice@example.com 100GiB`
(administrators can also set any space's quota through the API).

## Configuration

All settings are environment variables. Secrets may instead be given as a file path in the same
name with a `_FILE` suffix (preferred).

| Variable | Default | Purpose |
|---|---|---|
| `NODDANAS_PUBLIC_URL` | *(required)* | External origin, e.g. `https://files.example.com` (HTTPS; plain HTTP only for localhost) |
| `NODDANAS_DATABASE_URL` | *(required)* | PostgreSQL DSN; use `sslmode=verify-full` off-host |
| `NODDANAS_OIDC_ISSUER` / `_CLIENT_ID` / `_CLIENT_SECRET` | | OIDC sign-in (optional if SAML is set) |
| `NODDANAS_OIDC_GROUPS_CLAIM` / `_SCOPES` | `groups` / `openid,email,profile` | |
| `NODDANAS_SAML_IDP_METADATA_URL` or `_FILE` | | SAML sign-in (optional if OIDC is set); URL must be https |
| `NODDANAS_SAML_SP_KEY_FILE` / `_CERT_FILE` | | Optional SP key pair: signs AuthnRequests, decrypts encrypted assertions |
| `NODDANAS_SAML_ENTITY_ID` | metadata URL | |
| `NODDANAS_SAML_TRUST_EMAIL` | `false` | Treat asserted emails as verified (needed for sharing by email) |
| `NODDANAS_SAML_EMAIL_ATTRIBUTES` / `_NAME_` / `_GROUP_` | common names | Attribute names (comma-separated) |
| `NODDANAS_ALLOWED_GROUPS` | | Sign-in requires one of these groups. **Set this or the next.** |
| `NODDANAS_ALLOWED_EMAIL_DOMAINS` | | Sign-in requires a verified email in one of these domains |
| `NODDANAS_ADMIN_GROUPS` | | Members administer group mappings and quotas |
| `NODDANAS_TEAM_CREATION` | `true` | Whether any user may create team folders |
| `NODDANAS_BRAND_NAME` / `_LOGO_FILE` | `NoddaNAS` / | Instance name; PNG/JPEG logo (re-encoded) |
| `NODDANAS_THEME_FILE` | | Color tokens and accents; validated, contrast-checked ([THEMING.md](docs/THEMING.md)) |
| `NODDANAS_DEFAULT_QUOTA` / `_TEAM_QUOTA` | `10GiB` / `50GiB` | Quotas for new personal / team spaces |
| `NODDANAS_MAX_FILE_SIZE` | `50GiB` | Largest single (encrypted) file |
| `NODDANAS_MAX_VERSIONS` | `10` | Versions kept per file (all count towards quota) |
| `NODDANAS_TRASH_RETENTION` | `30d` | How long trashed items are kept |
| `NODDANAS_LINK_DEFAULT_TTL` / `_MAX_TTL` | `30d` / `365d` | Public link lifetime default / maximum |
| `NODDANAS_SESSION_IDLE` / `_MAX_AGE` | `12h` / `7d` | Browser session lifetimes |
| `NODDANAS_DATA_DIR` | `/data` | Where encrypted containers are stored |
| `NODDANAS_TRUSTED_PROXIES` | | CIDRs whose `X-Forwarded-For` is trusted |
| `NODDANAS_WEBDAV` / `_WORKER` / `_AUTO_MIGRATE` | `true` | Read-only WebDAV, background worker, startup migrations |
| `NODDANAS_LISTEN` / `_TLS_CERT_FILE` / `_TLS_KEY_FILE` / `_LOG_LEVEL` | `:8080` / / / `info` | |

## Backups and the CLI

Build the client with `make cli` and create an **app password** under Settings.

```sh
export NODDANAS_URL=https://files.example.com NODDANAS_TOKEN_FILE=~/.noddanas-token
noddanas-cli ls Documents
noddanas-cli put report.pdf Documents        # encrypts locally, then uploads
noddanas-cli get Documents/report.pdf        # downloads, decrypts and verifies the signature
noddanas-cli backup ./nas-backup             # whole personal space, still encrypted, ID-named
noddanas-cli export-keys ./nas-backup/keys.json

# Later, with no server at all:
noddanas-cli decrypt-tree ./nas-backup ./restored --keys ./nas-backup/keys.json --recovery
noddanas-cli decrypt ./somefile.ndne ./somefile --keys ./keys.json
```

Backups contain no plaintext names: files are stored by ID, and names live encrypted in
`_noddanas-folder.json`. The same layout is served read-only at `https://<host>/dav/`, so
`rclone sync`/`restic` can mirror it with an app password. In the web app, **Backup** saves one file
as `name.ndne` and **Restore backup…** puts it back (byte-for-byte unchanged).

## Security at a glance

- **End-to-end encryption** with standard primitives only (X25519, Ed25519, HKDF, PBKDF2, HMAC,
  AES-256-GCM in the STREAM construction), implemented independently in Go and in the browser's
  WebCrypto, with a test that checks both agree byte-for-byte in both directions.
- **One authorization decision point** on the server for every interface; callers who cannot see
  an item get "not found". Authorization and cryptography are separate, independent layers.
- **No passwords stored, no auth invented**: OIDC or SAML, with server-side sessions in
  `__Host-` cookies (no tokens in JavaScript), and revocable, optionally read-only app passwords.
- **SAML done conservatively**: SP-initiated only, signature required, each response bound to a
  single-use request from the same browser, HTTP-POST binding only. Tests forge, replay and send
  unsolicited assertions.
- **Integrity in the database**: name-hash uniqueness, atomic quota, optimistic concurrency and
  "links are read-only" are SQL constraints or single-statement conditions.
- **Hardened web client**: strict CSP with Trusted Types enforced and no policies, so the browser
  itself refuses HTML injection. Containers are always served as sandboxed `octet-stream`
  attachments.
- **Minimal container**: distroless, non-root, read-only root filesystem, no capabilities.

## Development

```sh
export NODDANAS_TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/noddanas_test?sslmode=disable'
make test           # unit + integration + HTTP end-to-end tests (real PostgreSQL, race detector)
make test-browser   # Go <-> browser E2EE interoperability (needs node + playwright)
make lint vuln gosec
make build cli docker
```

The HTTP end-to-end test runs the real server over TLS against an in-process OIDC provider and a
real SAML IdP (crewjam/saml), and exercises key setup, sharing, team folders with group mappings,
independent restore, public links, and decrypting a WebDAV mirror offline.

### Repository layout

```
cmd/noddanas/          server binary (+ migrate, set-quota, healthcheck)
cmd/noddanas-cli/      end-to-end encrypted command-line client
internal/e2ee/         E2EE implementation (Go) of docs/E2EE.md
internal/client/       Go API client doing all crypto locally; offline decryption
internal/domain/       core types and client-safe errors
internal/validate/     the only place untrusted strings become trusted values
internal/secure/       IDs, tokens, hashing, argon2id
internal/service/      use cases and the single authorization decision point
internal/auth/         OIDC, SAML, sessions, app passwords
internal/httpapi/      JSON API, read-only ciphertext WebDAV, public links, static UI
internal/theme/        theme validation, contrast checks, stylesheet generation, logo sanitizing
internal/store/        PostgreSQL adapter and migrations
internal/blob/         blob storage adapter (filesystem)
web/static/            web client; e2ee.js is the browser E2EE implementation
test/interop/          browser side of the Go <-> WebCrypto interoperability test
deploy/                Docker Compose and Kubernetes reference deployments
docs/                  E2EE spec, architecture, threat model, operations, API, theming
```

## Roadmap

- Local decrypting WebDAV gateway in `noddanas-cli` (mount plaintext in Finder/Explorer)
- Streaming decryption for very large browser downloads (service-worker stream)
- Key rotation for team folders when members leave (today: access revoked, old key not rotated)
- Key transparency / verified contacts to remove trust in the server's key directory
- Passkey (WebAuthn PRF) unlock as an alternative to the passphrase
- S3-compatible blob backend; shared WebDAV lock store; orphaned-blob garbage collector

## License

GPL-3.0. See [LICENSE](LICENSE).
