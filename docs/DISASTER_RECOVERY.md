# Disaster recovery

This document explains how a server administrator backs up an entire FrontDir server at the
operating-system level and rebuilds it on new hardware after the original is lost to a fire,
flood, theft, ransomware or a failed disk. Throughout, users' files stay end-to-end encrypted.
The administrator, the backup software, the off-site storage provider and anyone who steals a
backup can copy the files, but cannot read them. Only the users who own or share a file can.

It assumes the Docker Compose installation from the [administrator guide](ADMIN_GUIDE.md),
installed in `/opt/FrontDir`. On Kubernetes the same principles apply; see
[Kubernetes](#kubernetes) at the end.

**Contents**

1. [The short version](#1-the-short-version)
2. [Why the backups stay end-to-end encrypted](#2-why-the-backups-stay-end-to-end-encrypted)
3. [What a complete backup contains](#3-what-a-complete-backup-contains)
4. [Plan before you need it](#4-plan-before-you-need-it)
5. [Taking backups](#5-taking-backups)
6. [Checking backups without reading them](#6-checking-backups-without-reading-them)
7. [Restoring after losing the server](#7-restoring-after-losing-the-server)
8. [When something else changed too](#8-when-something-else-changed-too)
9. [Keeping the backups themselves safe](#9-keeping-the-backups-themselves-safe)
10. [How this is tested](#10-how-this-is-tested)

---

## 1. The short version

- **Back up** the database (as a `pg_dump`), the encrypted-files volume, and the
  `deploy/compose` directory, every day, to an encrypted repository **in another building**.
- **Keep the repository password somewhere a fire at the server cannot reach,** and not
  only on the server.
- **Restore** on any new Linux host: restore the files, `pg_restore` the database, copy the
  encrypted files back, start FrontDir, and run `frontdir verify-storage --hash`.
- **Before letting users in,** re-apply security decisions made after the backup was taken
  (`frontdir revoke-sessions --all`, plus any offboarding or link revocations since).
- **Users** sign in and unlock with their own passphrase or recovery code, exactly as before.
  Nobody else, including you, can open their files at any point in this process.
- **Practise it** every quarter on a scratch machine, using a canary account.

---

## 2. Why the backups stay end-to-end encrypted

FrontDir encrypts every file, file name and folder name in the user's browser or CLI before
upload, with keys derived from secrets only the user knows. The server stores, and therefore
every backup contains, only what the server has:

| In a full backup | Protected by | Who can read it |
|---|---|---|
| File contents (the data volume) | Per-file keys (AES-256-GCM) that never reach the server unwrapped | Only users with access to that file |
| File, folder and team-folder names (database) | The same per-node keys | Only users with access |
| Per-file and per-folder keys (database) | Each wrapped by its parent folder's key, up to a space key that is derived from, or sealed to, user keys | Only users with access |
| Each user's private keys, the "key bundle" (database) | Encrypted twice: under the user's passphrase (PBKDF2-SHA256, 600,000 iterations), and under their recovery code (160 random bits) | Only that user |
| Session tokens, app passwords, public-link tokens (database) | Stored only as hashes | Nobody. A backup yields no usable credential. |
| Public-link passwords (database) | Argon2id hashes | Nobody |
| The secret that decrypts a public link | **Never stored anywhere on the server.** It lives only in the link (after `#`), which browsers never send. | Only people who were given the link |
| Metadata: email addresses, display names, group names, IDs, file sizes, timestamps, who shares with whom, quotas | Not encrypted (the server needs it to work) | Anyone with the backup |
| Server and proxy logs | Metadata only (user IDs, IP addresses, URLs of API calls, event types, sizes); never names, contents or keys | Anyone with the logs |

**There is no server key to back up or lose.** FrontDir has no master key, keyring or escrow
key. Its own secrets (the database password, the OIDC client secret, an optional SAML key pair)
protect access to services, not files, and can be regenerated after a disaster without losing
anything.

**One honest caveat: the passphrase.** A stolen database backup contains each user's key
bundle, and an attacker can try to guess passphrases offline against it. FrontDir makes each
guess expensive: the server refuses any key bundle that does not use the full 600,000-iteration
work factor, and clients require passphrases of at least 12 characters. The recovery-code half of
the bundle cannot be guessed. Even so, the confidentiality of a stolen backup ultimately rests on
users' passphrases. That is why section 9 still asks you to encrypt the backups and restrict
access to them, as defence in depth and to protect the metadata.

---

## 3. What a complete backup contains

| Item | Where (Compose) | Needed to restore? | Notes |
|---|---|---|---|
| Database | `postgres` service; back up as a `pg_dump` file | **Required** | The folder tree, encrypted names and keys, key bundles, shares, team memberships, users |
| Encrypted files | Docker volume `frontdir_frontdir-data` | **Required** | Ciphertext containers, one per file version |
| Deployment configuration | `/opt/FrontDir/deploy/compose` (`.env`, `secrets/`, `branding/`, and `compose.yaml` / `Caddyfile` if you changed them) | **Required** | `secrets/` holds credentials, including `settings_key`; the backup repository is encrypted |
| FrontDir version | The git commit you run | **Required** | Restore the same version, then upgrade |
| SAML SP key pair, if you configured one | Wherever `FRONTDIR_SAML_SP_KEY_FILE` / `_CERT_FILE` point | Recommended | Otherwise generate a new pair and give the IdP the new certificate |
| TLS certificates | Docker volume `frontdir_caddy-data` | Optional | Caddy obtains new ones automatically |
| Logs | Docker's container logs, or your log system | Optional | Useful for audit and for step 8 of the restore |

Outside this server, but just as necessary:

- **The identity provider.** Accounts are tied to the IdP's issuer and each user's subject ID.
  If the IdP is lost and recreated with new IDs, users get new, empty accounts (see
  [§8](#8-when-something-else-changed-too)). Back it up as carefully as FrontDir.
- **DNS** for the hostname.
- **The backup repository's password and location** (see the next section).

---

## 4. Plan before you need it

**3-2-1.** Keep three copies of the data, on two kinds of storage, with one copy off-site. For
fire, the off-site copy is the one that matters. Make at least one copy append-only or immutable
(for example a restic REST server in `--append-only` mode, or object storage with object lock), so
ransomware on the server cannot delete it.

**Decide your recovery targets.**

- **RPO** (how much recent data you can afford to lose) is your backup interval. Daily is typical.
- **RTO** (how long the rebuild may take) is whatever your last practice run took.

**Prepare a disaster-recovery kit,** stored off-site and in a password manager, and known to
at least two people:

- the backup repository location and its access credentials;
- the repository password (without it, every off-site copy is useless);
- the canary account's passphrase ([§6](#6-checking-backups-without-reading-them));
- admin access to the IdP and to DNS;
- a printed or off-line copy of this document.

**Encourage user-level backups as well.** The [administrator guide](ADMIN_GUIDE.md#user-backups-each-user-independent-of-the-server)
describes them: users' own encrypted copies (`frontdir-cli backup`) and key backups. They cover
files saved after your last server backup, and they still work if the server is gone for good.

---

## 5. Taking backups

The examples use [restic](https://restic.net) because it encrypts, deduplicates and supports
many off-site targets (SFTP, S3-compatible storage, Backblaze B2, its own REST server). Borg and
other tools work the same way. The file containers are already ciphertext, so the backup tool's
encryption mainly protects the database dump (metadata and key bundles) and the configuration.

### One-time setup

As root on the FrontDir host:

```sh
apt install restic                           # or your distribution's equivalent
install -m 600 /dev/null /root/.frontdir-restic-password
openssl rand -base64 32 > /root/.frontdir-restic-password
# Put a copy of this password in your disaster-recovery kit NOW.
export RESTIC_REPOSITORY=sftp:backup@offsite.example.com:/srv/restic/frontdir
export RESTIC_PASSWORD_FILE=/root/.frontdir-restic-password
restic init
```

### Method A: online backup (recommended)

No downtime, and the database dump restores into any newer PostgreSQL version. Save this as
`/usr/local/sbin/frontdir-backup` (mode `0700`, owned by root):

```sh
#!/bin/sh
# FrontDir whole-system backup: database dump, encrypted files, configuration.
set -eu
export RESTIC_REPOSITORY=sftp:backup@offsite.example.com:/srv/restic/frontdir
export RESTIC_PASSWORD_FILE=/root/.frontdir-restic-password
APP=/opt/FrontDir
COMPOSE=$APP/deploy/compose
STAGE=/var/backups/frontdir
umask 077
mkdir -p "$STAGE"
cd "$COMPOSE"

# 1. Database first. pg_dump takes a consistent snapshot while FrontDir keeps running.
docker compose exec -T postgres pg_dump -U frontdir -d frontdir -Fc > "$STAGE/frontdir-db.dump.part"
mv "$STAGE/frontdir-db.dump.part" "$STAGE/frontdir-db.dump"
git -C "$APP" rev-parse HEAD > "$STAGE/frontdir-version"

# 2. Then the encrypted files and the configuration.
DATA=$(docker volume inspect -f '{{ .Mountpoint }}' frontdir_frontdir-data)
restic backup --tag frontdir "$STAGE" "$DATA" "$COMPOSE"

# 3. Retention. With an append-only repository, run this from a separate trusted machine instead.
restic forget --tag frontdir --keep-daily 14 --keep-weekly 8 --keep-monthly 12 --prune
```

The order matters. Taken first, the database dump only refers to files that are already on disk,
so the later file backup contains every file it mentions. The one exception is items purged from
the trash in the minutes between the two steps, which were being deleted anyway.

Run it daily and make failures visible, for example with cron:

```cron
17 2 * * * root /usr/local/sbin/frontdir-backup >>/var/log/frontdir-backup.log 2>&1 || logger -p user.err "frontdir backup FAILED"
```

### Method B: offline copy

This is the simplest way to get a perfectly consistent copy, at the cost of a few minutes of
downtime. It copies the raw volume directories while the services are stopped:

```sh
cd /opt/FrontDir/deploy/compose
docker compose stop frontdir postgres
restic backup --tag frontdir-cold \
  "$(docker volume inspect -f '{{ .Mountpoint }}' frontdir_postgres-data)" \
  "$(docker volume inspect -f '{{ .Mountpoint }}' frontdir_frontdir-data)" \
  /opt/FrontDir/deploy/compose
docker compose start postgres frontdir
```

A copied PostgreSQL data directory restores only into the **same PostgreSQL major version**,
so keep the `postgres` image tag unchanged until you have a newer backup.

### Method C: filesystem or VM snapshots

If `/var/lib/docker/volumes` is on ZFS, Btrfs or LVM, an atomic snapshot of that filesystem can be
backed up while everything runs. PostgreSQL recovers from it as it would after a power cut. Both
volumes must be in the same snapshot. Snapshots of a whole virtual machine work the same way when
they cover all of its disks at once. Treat snapshots as an addition to off-site file-level
backups, not a replacement: a snapshot on the same storage burns with it.

### Things not to do

- Do not copy the PostgreSQL volume directory while PostgreSQL is running (except from an atomic
  snapshot). The copy can be silently corrupt.
- Do not back up only the data volume. Without the database, the folder structure, names,
  sharing and team access are gone. Users who kept a key backup can still decrypt individual
  containers with `frontdir-cli decrypt`, because each container carries its own encrypted
  name, but that is salvage, not recovery.
- Do not keep the only copy of the repository password on the server.

---

## 6. Checking backups without reading them

You can prove that backups are complete and intact without ever being able to read them.

| Check | How often | Command or method |
|---|---|---|
| The backup job ran | Daily | Your alert from the cron line above; `restic snapshots --tag frontdir` |
| Repository integrity | Monthly | `restic check --read-data-subset=5%` (a different 5% each time) |
| Full restore drill | Quarterly | [§7](#7-restoring-after-losing-the-server) on a scratch machine, ending with the two checks below |

**`frontdir verify-storage --hash`** checks every file version the database knows about. It
confirms the encrypted container exists, has the recorded size, and has the recorded SHA-256 of
its ciphertext. It needs no keys and decrypts nothing. It exits non-zero if anything is missing
or corrupted, listing the affected items, and it also counts stored containers that nothing
refers to (harmless, but they use space). With `--hash` it reads every stored byte, which can take
hours on a large installation. Without `--hash` it checks only presence and size, which takes
seconds to minutes.

**A canary account** proves the last link in the chain, that a user can decrypt, without
touching anyone's real data:

1. Create a dedicated IdP user (for example `dr-canary`) in the allowed group.
2. Sign in as that user, choose a passphrase, and record it in the disaster-recovery kit.
3. Upload a small file, for example `canary.txt` containing a sentence you will recognize.
4. After every restore, sign in as the canary on the restored server and open `canary.txt`.

If that file opens, the database, the encrypted files, the key bundles and the IdP mapping all
survived the round trip.

---

## 7. Restoring after losing the server

You need: the disaster-recovery kit, a new Linux host (any architecture Docker supports), and
time. Allow a few hours for a first run; practice makes it faster.

**1. Prepare the host.** Install Docker Engine with the Compose plugin, `restic` and `git`.

**2. Restore the backup to a staging directory.**

```sh
export RESTIC_REPOSITORY=sftp:backup@offsite.example.com:/srv/restic/frontdir
export RESTIC_PASSWORD_FILE=/root/.frontdir-restic-password   # from the disaster-recovery kit
restic snapshots --tag frontdir                                # pick a snapshot, usually the latest
restic restore latest --tag frontdir --target /restore
```

Files appear under `/restore` with their original paths, owners and permissions.

**3. Put the same FrontDir version back, with its configuration.**

```sh
git clone https://github.com/woah-buddy/FrontDir.git /opt/FrontDir
git -C /opt/FrontDir checkout "$(cat /restore/var/backups/frontdir/frontdir-version)"
cp -a /restore/opt/FrontDir/deploy/compose/. /opt/FrontDir/deploy/compose/
cd /opt/FrontDir/deploy/compose
```

**4. Restore the database.**

```sh
docker compose up -d --wait postgres        # creates an empty database with the restored password
docker compose exec -T postgres pg_restore -U frontdir -d frontdir --no-owner \
  < /restore/var/backups/frontdir/frontdir-db.dump
```

**5. Restore the encrypted files.**

```sh
docker compose build frontdir
docker compose create frontdir               # creates the data volume without starting the service
DATA=$(docker volume inspect -f '{{ .Mountpoint }}' frontdir_frontdir-data)
OLD=$(find /restore/var/lib/docker/volumes -maxdepth 2 -path '*frontdir_frontdir-data/_data')
cp -a "$OLD"/. "$DATA"/
chown -R 65532:65532 "$DATA"
```

(After an [offline backup](#method-b-offline-copy), skip step 4. After `docker compose create`,
copy the restored PostgreSQL volume directory into the new `frontdir_postgres-data` volume in the
same way, `chown -R 70:70` it, and keep the same PostgreSQL image.)

**6. Start and verify, before anyone can reach it.** Keep DNS pointing elsewhere for now.

```sh
docker compose up -d --wait
docker compose exec frontdir /frontdir verify-storage --hash
```

`verify-storage` must end with `OK`. If it lists missing or corrupted files, try an older
snapshot, or accept the loss of those specific versions. The command names each one, so you can
tell the affected users.

**7. Re-apply what happened after the backup was taken.** A restore brings back the past. That
includes sessions that had ended, app passwords and public links that had been revoked, team
members who had been removed, and files that had been deleted (still end-to-end encrypted).
Before opening the doors:

```sh
docker compose exec frontdir /frontdir revoke-sessions --all     # everyone signs in again via the IdP
```

Then, from your logs or change records of the time since the backup:

- run `revoke-access --user …` again for everyone offboarded since;
- run `revoke-links --user …` again (or `revoke-links --all`) for any link revocation since;
- ask team-folder managers to remove members who had been removed since.

The audit events you ship to your log store (`operator.*`, `admin.links.revoke_all`,
`share.link.revoke_all`, `share.delete`, `team.member_remove`) are that change record. This is
one more reason to keep logs off the server.

**8. Point DNS at the new host.** With the same hostname, nothing changes for the IdP or for
users. Caddy obtains a certificate within a minute or two. (Or restore the `caddy-data` volume
the same way as the data volume to reuse the old certificates.)

**9. Run the canary check.** Sign in as the canary and open `canary.txt`.

**10. Tell users.** Say what happened, give the date and time of the restore point, and confirm
that their files are back and remained end-to-end encrypted throughout. They unlock exactly as
before, with their passphrase or recovery code. Anything they saved after the restore point needs
to be uploaded again. If they keep their own encrypted backups, **Restore backup…** (or
`frontdir-cli restore`) puts those files back as they were, because their space keys did not
change.

Finally, securely delete `/restore` and `/var/backups/frontdir` from the new host once you are
confident, or keep them as root-only files.

---

## 8. When something else changed too

| What changed | What to do |
|---|---|
| **Hostname** | Set `FRONTDIR_HOST` in `.env`. Update the OIDC redirect URI at the IdP. For SAML, the SP entity ID defaults to the metadata URL, so either set `FRONTDIR_SAML_ENTITY_ID` to the old value or update the IdP. Public links still work if people replace the host part of the URL. |
| **Identity provider rebuilt** | Accounts are matched by issuer and subject ID. Restore the IdP from its own backup so both stay the same. If they change, users get new, empty accounts and their encrypted files remain with the old ones. There is currently no tool to relink them. |
| **PostgreSQL major version** | A `pg_dump` restores into a newer version. An offline volume copy does not. |
| **Newer FrontDir** | Restore the backed-up version first, confirm it works, then upgrade normally (migrations only move forward). |
| **Settings key lost** (`secrets/settings_key`) | Only secrets saved in the web admin area (the OIDC client secret) depend on it, and FrontDir refuses to start with a message naming them. Create a new key (`scripts/init-secrets.sh` makes one if the file is missing), run `docker compose run --rm frontdir settings reset OIDC_CLIENT_SECRET`, start, and enter the client secret again (through a setup link if nobody can sign in without it). Settings themselves are in the database and come back with it. |
| **Database lost, files survived** | See "Things not to do" in [§5](#things-not-to-do): individual containers can be salvaged by their owners, but this is not a recovery path. |

---

## 9. Keeping the backups themselves safe

- **Encrypt them** (restic and Borg do by default). File contents are protected anyway, but the
  database dump holds metadata in the clear and the users' passphrase-protected key bundles.
- **Limit who can read them** to the people who hold the disaster-recovery kit. Two people is
  right for most organisations.
- **Make one copy append-only or immutable,** so an attacker on the server cannot destroy the
  backups too.
- **Retention.** Deleted files survive in backups until the snapshots that contain them expire.
  They are still end-to-end encrypted, but say how long you keep backups in your privacy notice,
  and expire them on schedule.
- **Off-site providers** see only the backup tool's encrypted data. Inside that, files are
  encrypted a second time end to end.

---

## 10. How this is tested

The repository's test suite rehearses this scenario on every change:

- **`TestDisasterRecovery`** (`internal/httpapi/dr_test.go`):
  1. Runs a realistic workload: personal files with versions, a trashed file, a team folder, a
     share, a password-protected public link, and an app password.
  2. Takes a full backup: every database row, every file in the data directory, and the
     server's logs.
  3. Scans every byte of the backup for any plaintext name, content, passphrase, recovery code,
     link secret, link password or app password, in raw, hex and base64 forms.
     `TestLeakScannerCatchesEncodedSecrets` proves the scan would catch a leak.
  4. Restores onto a brand-new server and checks that the users get everything back (current
     versions, trash, a team folder, a share) using only their own passphrase or recovery code,
     and that a wrong passphrase gets nothing.
  5. Checks that `verify-storage --hash` passes on the restored server, and that restored public
     links work again until revoked, which is why step 7 of the runbook exists.
- **`TestWeakKeyBundlesRefused`:** the server refuses key bundles below the PBKDF2 work factor,
  so no backup can contain one.
- **`TestVerifyStorage`:** a missing container, a truncated one and a single flipped bit are all
  detected.

---

## Kubernetes

The same rules apply, using your platform's tools:

- **Database:** use your operator's or provider's backups. CloudNativePG, for example, has
  scheduled base backups with WAL archiving to object storage, which also allows point-in-time
  recovery.
- **Data volume:** use CSI volume snapshots copied off-cluster, or a file-level backup tool such
  as Velero with restic or Kopia.
- **Configuration:** your manifests (kept in git) and the `frontdir-secrets` Secret (kept in a
  secret manager).
- **Run the operator commands** with `kubectl -n frontdir exec deploy/frontdir -- /frontdir …`
  (`verify-storage --hash`, `revoke-sessions --all`, and the rest).
