# Operations

## Backups

A complete backup has **three** parts. Store the keyring separately from the other two: anyone
holding all three can read everything.

| Part | How | Notes |
|---|---|---|
| Database | `pg_dump -Fc` (or your PostgreSQL backup tooling) | Contains names, structure, wrapped keys. Encrypt the dump. |
| Data volume | Any file-level backup or snapshot of `NODDANAS_DATA_DIR` | Already ciphertext. Take it *after* the database dump: blobs newer than the dump are harmless orphans, but a dump referencing blobs missing from the volume means data loss. |
| Keyring | Copy of the keyring file | Offline / password manager / HSM. Without it, nothing can be decrypted. |

Restore: restore the database, restore the volume, provide the keyring, start NoddaNAS.

## Key rotation

1. `noddanas keygen k2026b` and put the new line **first** in the keyring file; keep the old lines.
2. Restart NoddaNAS. New uploads use the new key; existing content still decrypts.
3. Old keys must stay in the keyring until every version wrapped under them has been re-wrapped
   (a `rewrap` command is on the roadmap) or has aged out.

If you suspect the keyring leaked, rotate immediately; until rewrapping exists, treat content
uploaded before the rotation as exposed to whoever holds the old key and the data volume.

## Upgrades

Migrations run automatically at startup (serialized across replicas by a PostgreSQL advisory
lock). To control timing, set `NODDANAS_AUTO_MIGRATE=false` and run `noddanas migrate` as a
pre-deploy job or Kubernetes init container. Take a database backup first.

## Monitoring

- `GET /healthz`: liveness (process up). `GET /readyz`: database and storage reachable.
- Logs are JSON on stdout. Useful queries:
  - `msg=audit event=login.failed`: sign-in failures (with client IP)
  - `msg=audit event=link.password_failed`: public-link password guessing
  - `msg=http status>=500`: server errors (match `request_id` to the client's error)
  - `msg="purge failed"`: background deletion problems

## Administration

```sh
noddanas set-quota alice@example.com 200GiB
```

Users are provisioned automatically on first sign-in with the default quota. To remove someone's
access, remove them from the allowed group at your OIDC provider; their existing browser sessions
expire within the idle timeout. Revoke their app passwords too (roadmap: admin UI).

## Hardening checklist

- [ ] `NODDANAS_OIDC_ALLOWED_GROUPS` or `_ALLOWED_EMAIL_DOMAINS` set
- [ ] MFA or passkeys required at the OIDC provider
- [ ] Keyring file mode `0400` (or `0440` with a dedicated group), backed up offline
- [ ] `NODDANAS_TRUSTED_PROXIES` set to exactly your proxy's address range
- [ ] Database not reachable from the internet; `sslmode=verify-full` if off-host
- [ ] Container images pinned by digest; Dependabot or Renovate enabled
- [ ] Logs shipped to an append-only store; alerts on `login.failed` and 5xx spikes
- [ ] Backups of database and volume tested by restoring them
