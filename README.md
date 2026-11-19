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
| Disaster recovery | Whole-server backups stay end-to-end encrypted; `noddanas verify-storage` proves a backup is complete and intact without keys; tested rebuild runbook ([DISASTER_RECOVERY.md](docs/DISASTER_RECOVERY.md)) |
| Offline recovery | `noddanas-cli decrypt` / `decrypt-tree` turn containers or whole mirrors back into files with just your key backup |
| Personal spaces | Every user has one, with a per-user quota |
| Team folders | Direct members (read / write / manage), IdP group mappings (admin), separate quota, signed key grants that a manager approves person by person (never automatic) |
| Sharing | Users (read/write, E2EE key sealed to the recipient and signed by you) and public links; one **Shared** page (with me / by me) |
| Verified people | Compare key fingerprints once, out of band; NoddaNAS then marks that person ✔ everywhere and warns about swapped keys and look-alike accounts (encrypted list the server cannot read or forge) |
| Kill switches | Revoke all of your own public links, or (administrators) every link on the server; shell commands for break-glass link revocation and user offboarding |
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

This is the short version. The [administrator guide](docs/ADMIN_GUIDE.md) covers installation
(Compose and Kubernetes), identity-provider setup, configuration, backups, upgrades, monitoring,
user offboarding and incident response step by step.

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
   cp .env.example .env            # set NODDANAS_HOST; the rest can wait for the web
   sudo ../../scripts/init-secrets.sh
   docker compose up -d --build
   docker compose exec noddanas /noddanas setup-link   # prints a one-time setup link
   ```

3. Open the setup link, enter your identity provider's details (they are tried before they are
   saved), and **sign in to finish**: you become the first administrator. Choose an encryption
   passphrase and **store the recovery code somewhere safe**. Then, under Settings, **download your
   key backup** and keep it with your backups (it is itself encrypted).

Prefer configuration as code? Put the sign-in method, allowed groups and administrator groups in
`.env` instead (and the OIDC client secret in `secrets/oidc_client_secret`); settings set there are
locked in the web admin area. Next steps: the
[administrator guide](docs/ADMIN_GUIDE.md#6-first-sign-in-and-day-one-tasks).

## Configuration

Settings are environment variables, validated at startup (NoddaNAS refuses to start with an
unsafe or incomplete configuration and lists every problem). The required ones are
`NODDANAS_PUBLIC_URL` and `NODDANAS_DATABASE_URL` (or `_FILE`). Everything an app owner decides
(sign-in method, who may sign in, administrators, quotas, link lifetimes, sessions, branding) can
also be changed by administrators in the web app's **Admin** area, validated by the same code. A
value set in the environment wins and is locked there. Changes on the web need a fresh
re-authentication at the identity provider ("confirm it's you"), are tried against the identity
provider before sign-in changes are saved, refuse anything that would lock out the person making
them, and are audited.

The complete reference, with defaults, is in the
[administrator guide](docs/ADMIN_GUIDE.md#7-configuration-reference).

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
docs/                  administrator guide, disaster recovery, E2EE spec, architecture, threat model, API, theming
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
