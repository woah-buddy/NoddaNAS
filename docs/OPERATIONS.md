# Operations

## What is (and is not) on the server

Files are end-to-end encrypted by clients. The server stores ciphertext, encrypted names, wrapped
keys and public keys. **There is no server-side key that can decrypt user data, and no
administrator recovery.** Losing both a passphrase and a recovery code loses that user's data.
Tell users this before they rely on the system.

## Backups

### Server-level (administrator)

| Part | How | Notes |
|---|---|---|
| Database | `pg_dump -Fc` (or your PostgreSQL tooling) | Holds the tree, encrypted names, wrapped keys, key bundles and memberships. Without it, files are still individually restorable by their owners (see below), but folder structure and sharing are lost. |
| Data volume | Any file-level backup or snapshot of `NODDANAS_DATA_DIR` | Already ciphertext. Take it *after* the database dump. |

Restore: restore both, start NoddaNAS. No key material is involved.

### User-level (independent of the server)

Every stored file is a self-contained encrypted container that its owner can restore or decrypt
with nothing but their own keys. Encourage users to:

1. keep their **recovery code** offline;
2. download their **key backup** (Settings → Download key backup, or `noddanas-cli export-keys`),
   which is itself encrypted and opens only with their passphrase or recovery code;
3. back up their files, still encrypted, with `noddanas-cli backup <dir>` or by mirroring
   `https://<host>/dav/` with rclone/restic (read-only app password).

`noddanas-cli decrypt-tree <dir> <out> --keys keys.json` turns such a backup back into plaintext
files with real names, with no server. A single `.ndne` file decrypts with `noddanas-cli decrypt`,
or restores into the app with **Restore backup…**.

## Upgrades

Migrations run at startup, serialized across replicas by an advisory lock. To control timing set
`NODDANAS_AUTO_MIGRATE=false` and run `noddanas migrate` as a pre-deploy job. Back up first.

## Identity providers

- **OIDC**: confidential client, redirect `https://<host>/auth/callback`, include a `groups` claim.
- **SAML**: import `https://<host>/auth/saml/metadata` into the IdP; ACS
  `https://<host>/auth/saml/acs`; NameID format *persistent* (an email-format NameID ties the
  account to a mutable address); release email, display name and groups. Set
  `NODDANAS_SAML_TRUST_EMAIL=true` only if the IdP guarantees verified emails. Optionally give
  NoddaNAS an SP key pair (`NODDANAS_SAML_SP_KEY_FILE`/`_CERT_FILE`) to sign requests and accept
  encrypted assertions.
- Both: restrict sign-in with `NODDANAS_ALLOWED_GROUPS` (or `_EMAIL_DOMAINS`), set
  `NODDANAS_ADMIN_GROUPS`, and require MFA or passkeys at the IdP.

## Administration

- **Quotas**: `noddanas set-quota alice@example.com 200GiB` (personal), or
  `PUT /api/v1/spaces/{id}/quota` as an administrator (any space).
- **Group folders**: an administrator creates a team folder (or uses an existing one they manage)
  and maps IdP groups to it with a role on the folder's Members page. New group members get access
  immediately and their key the next time a manager opens that page.
- **Removing access**: remove the user from the IdP group (takes effect at their next sign-in and
  for group-based team access immediately on the next sync), revoke their sessions and app
  passwords, and remove direct team memberships. Already-downloaded data cannot be recalled.

- **Branding**: set `NODDANAS_BRAND_NAME`, `NODDANAS_BRAND_LOGO_FILE` and `NODDANAS_THEME_FILE`
  (see [THEMING.md](THEMING.md)). Changes apply on restart. An invalid theme stops startup with a
  list of problems, so check the logs after changing it.

## Monitoring

- `GET /healthz` (liveness) and `GET /readyz` (database and storage reachable).
- JSON logs on stdout. Useful events: `login.failed` (with method and IP),
  `link.password_failed`, `keys.setup`, `team.key_grant`, `team.group_map`, `purge failed`, and
  any `status>=500` (match the client's `requestId`).

## Hardening checklist

- [ ] `NODDANAS_ALLOWED_GROUPS` or `_ALLOWED_EMAIL_DOMAINS` set; `NODDANAS_ADMIN_GROUPS` set
- [ ] MFA or passkeys required at the identity provider
- [ ] SAML: persistent NameIDs; `TRUST_EMAIL` only if the IdP verifies emails
- [ ] Users told about recovery codes and key backups
- [ ] `NODDANAS_TRUSTED_PROXIES` set to exactly your proxy's range
- [ ] Database not reachable from the internet; `sslmode=verify-full` if off-host
- [ ] Container images pinned by digest; Dependabot or Renovate enabled
- [ ] Logs shipped to an append-only store; alerts on `login.failed` and 5xx spikes
- [ ] Backups tested by restoring them (server-level and a user-level `decrypt-tree`)
