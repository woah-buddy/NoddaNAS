# Administrator guide

This guide covers installing, configuring and maintaining a FrontDir server. It is written for
the person who runs the server. End users need only the web app and, optionally, `frontdir-cli`.

Two deployment paths are documented: **Docker Compose** on a single host (recommended for most
installations) and **Kubernetes**. Both run the same container image.

**Contents**

1. [Before you start](#1-before-you-start)
2. [Prepare your identity provider](#2-prepare-your-identity-provider)
3. [Install with Docker Compose](#3-install-with-docker-compose)
4. [Install on Kubernetes](#4-install-on-kubernetes)
5. [Using your own reverse proxy or TLS](#5-using-your-own-reverse-proxy-or-tls)
6. [First sign-in and day-one tasks](#6-first-sign-in-and-day-one-tasks)
7. [Configuration reference](#7-configuration-reference)
8. [Routine maintenance](#8-routine-maintenance)
9. [Backups and restore](#9-backups-and-restore)
10. [Upgrades](#10-upgrades)
11. [Monitoring and logs](#11-monitoring-and-logs)
12. [Managing users](#12-managing-users)
13. [Incident response](#13-incident-response)
14. [Rotating secrets](#14-rotating-secrets)
15. [Troubleshooting](#15-troubleshooting)
16. [Decommissioning](#16-decommissioning)

Commands in this guide assume Compose and are run from `deploy/compose`. On Kubernetes, replace
`docker compose exec frontdir /frontdir …` with `kubectl -n frontdir exec deploy/frontdir -- /frontdir …`.

---

## 1. Before you start

### What you are responsible for (and what you are not)

FrontDir encrypts files end to end, so the server's job is narrower than in a traditional file server:

| As the administrator you can | You cannot (by design) |
|---|---|
| Control who may sign in (through your identity provider) | Read any user's files, file names or folder names |
| Set quotas, create team folders, map IdP groups to them | Recover a user's data if they lose both their passphrase and recovery code |
| End sessions, revoke app passwords and public links | Search, preview or virus-scan file contents on the server |
| Back up and restore the whole server | Reset a user's encryption keys while keeping their data |

What *is* visible to the server, and so to you and to anyone who steals a backup, is **metadata**:
email addresses, display names, group names, folder structure (as IDs), file sizes, timestamps
and who shares with whom. Protect the database and its backups accordingly. See
[THREAT_MODEL.md](THREAT_MODEL.md) for the full analysis.

> **Tell your users before they rely on the system:** their recovery code is the only way back
> into their files if they forget their passphrase. There is no administrator reset.

### Components

| Component | Provided by | Notes |
|---|---|---|
| FrontDir server | This repository (one static binary in a distroless image) | Stateless except for the data volume; runs as UID 65532 with a read-only root filesystem |
| PostgreSQL 16 or newer | Compose file (`postgres:18-alpine`), a managed service, or an operator such as CloudNativePG | Holds users, the folder tree, encrypted names, wrapped keys and shares |
| Storage for file containers | A local volume, or `ReadWriteMany` storage on Kubernetes for multiple replicas | Holds only ciphertext |
| HTTPS reverse proxy | Compose file (Caddy, automatic certificates) or your own | TLS is required (plain HTTP is accepted only for `localhost`) |
| Identity provider | Yours: any OIDC provider and/or SAML 2.0 IdP | FrontDir stores no passwords |

### Sizing

- **Storage:** plan for your users' quotas, not their current usage. Each stored version adds
  about 0.03% of encryption overhead plus a few kilobytes. Old versions (up to
  `FRONTDIR_MAX_VERSIONS` per file) and the trash (kept for `FRONTDIR_TRASH_RETENTION`) count
  towards quotas and use disk.
- **CPU and memory:** low, because encryption happens on users' devices. The reference Kubernetes
  manifest requests 100m CPU and 128 MiB of memory with a 512 MiB limit, which suits small teams.
  Large file transfers stream and do not need memory proportional to file size.
- **Database:** small, roughly proportional to the number of files and folders.

### Decide up front

Write these down before installing. Every one becomes a setting.

1. **Hostname**, e.g. `files.example.com`, with a DNS record pointing at the server.
2. **Sign-in method:** OIDC, SAML, or both.
3. **Who may sign in:** an IdP group (e.g. `frontdir-users`), a verified email domain, or both.
   Leaving both empty lets *anyone your IdP authenticates* in. That is only acceptable for an IdP
   that contains nobody else.
4. **Who administers FrontDir:** an IdP group (e.g. `frontdir-admins`).
5. **Quotas:** default personal quota (10 GiB) and default team folder quota (50 GiB).
6. **Whether every user may create team folders**, or only administrators.
7. **Where server backups go,** and who can read them (they contain metadata).

---

## 2. Prepare your identity provider

FrontDir never sees passwords. It accepts a sign-in only when your IdP vouches for the user, and it
reads three things from the IdP: a stable user identifier, a **verified** email address (optional
but recommended), and **group names**. Groups are refreshed every time a user signs in.

Require multi-factor authentication or passkeys for FrontDir at the IdP. The IdP is the front door.

### OIDC

Create a **confidential** client using the **authorization code** flow:

| Setting | Value |
|---|---|
| Redirect (callback) URI | `https://<host>/auth/callback` |
| Post-logout redirect URI | `https://<host>/` |
| Scopes | `openid email profile` (change with `FRONTDIR_OIDC_SCOPES`) |
| Groups | Include group names in a `groups` claim of the ID token (rename with `FRONTDIR_OIDC_GROUPS_CLAIM`) |

FrontDir uses PKCE, `state` and `nonce` on every sign-in. Note the **issuer URL**, **client ID**
and **client secret**.

Provider notes:

- **Keycloak:** Client authentication *on*, Standard flow *on*. Add a *Group Membership* mapper
  with token claim name `groups` and *Full group path* off, so groups arrive as `frontdir-users`
  rather than `/frontdir-users`. The issuer is `https://<keycloak>/realms/<realm>`.
- **Authentik:** an OAuth2/OpenID provider, confidential client type. The default `profile`
  scope mapping already includes `groups`.
- **Microsoft Entra ID:** the `groups` claim carries group **object IDs** (GUIDs) by default, so
  put those IDs in `FRONTDIR_ALLOWED_GROUPS` and `FRONTDIR_ADMIN_GROUPS`. Entra ID does not send
  `email_verified` by default, so emails will not be recorded (see below).

**Why "verified" matters:** FrontDir records an email only if the IdP says it is verified (OIDC
`email_verified`). Otherwise someone could claim another person's address and receive the shares
meant for them. Without verified emails, people cannot share with a user by email,
`FRONTDIR_ALLOWED_EMAIL_DOMAINS` admits no one, and operator commands must identify users by ID
instead of email (see [Managing users](#12-managing-users)).

### SAML 2.0

FrontDir is a SAML service provider (SP). It accepts only **SP-initiated** sign-in (IdP-initiated
responses are refused, which prevents login CSRF), requires signed assertions, and uses the
HTTP-POST binding.

Create an application at your IdP with:

| Setting | Value |
|---|---|
| SP entity ID (audience) | `https://<host>/auth/saml/metadata` (or your `FRONTDIR_SAML_ENTITY_ID`) |
| ACS URL (HTTP-POST) | `https://<host>/auth/saml/acs` |
| NameID format | **Persistent.** An email NameID ties the account to an address that can change or be reassigned. |
| Signing | Sign the assertion or response. |
| Attributes | Email, display name and groups (common names are recognized automatically; see [§7](#saml)) |

Then note the IdP's **metadata URL** (must be `https://`) or download its metadata XML file.
Once FrontDir is running, its SP metadata is published at `https://<host>/auth/saml/metadata`.
Some IdPs prefer to import that file.

If your IdP has a user dashboard (tiles), point the FrontDir tile at
`https://<host>/auth/saml/login`. That starts an SP-initiated sign-in, which works, whereas an
IdP-initiated tile does not.

SAML has no "email verified" attribute. Set `FRONTDIR_SAML_TRUST_EMAIL=true` only if your IdP
guarantees that the email it sends belongs to that user.

### Groups to create

| Group | Purpose | Setting |
|---|---|---|
| `frontdir-users` | Everyone allowed to sign in | `FRONTDIR_ALLOWED_GROUPS` |
| `frontdir-admins` | Administrators (also add them to the users group) | `FRONTDIR_ADMIN_GROUPS` |
| Any others, e.g. `engineering` | Mapped to team folders by an administrator | Set in the web app |

---

## 3. Install with Docker Compose

Requirements: a Linux host with Docker Engine and the Compose plugin, `git` and `openssl`; DNS for
your hostname pointing at the host; inbound TCP 80 and 443 (and UDP 443 for HTTP/3) open.
Caddy obtains a certificate automatically. For a host reachable only on your LAN, see the note in
`deploy/compose/Caddyfile`.

**Step 1: get the code.** Use a release tag, or a commit you have reviewed, rather than an
arbitrary branch head:

```sh
git clone https://github.com/woah-buddy/FrontDir.git
cd FrontDir
git checkout <tag-or-commit>
cd deploy/compose
```

**Step 2: configure.** Copy the example settings and edit them:

```sh
cp .env.example .env
chmod 600 .env
```

Set at least `FRONTDIR_HOST`. Then decide where the rest of the configuration lives
([§7](#the-web-admin-area-and-the-server-who-owns-which-setting)):

- **On the web (simplest).** Leave the sign-in section of `.env` commented out. After the stack
  is up, a one-time setup link (step 7) opens a page where you configure sign-in and become the
  first administrator. Quotas, link lifetimes, who may sign in and branding are then changed in
  the admin area.
- **In `.env` (configuration as code).** Set a sign-in method (`OIDC_ISSUER` + `OIDC_CLIENT_ID`,
  and/or `SAML_IDP_METADATA_URL`), `ALLOWED_GROUPS` and `ADMIN_GROUPS`. A setting set here wins
  and is shown locked in the admin area.

You can mix the two per setting (each sign-in method is configured entirely in one place). Every
setting in [§7](#7-configuration-reference) can go in `.env`, named without the `FRONTDIR_` prefix
(`FRONTDIR_TEAM_CREATION` becomes `TEAM_CREATION`). `.env.example` lists them all, with defaults.
If your IdP provides SAML metadata only as a file, or you use an SP key pair, put those files in
`deploy/compose/saml/` (see the README there).

**Step 3: create secrets.** The script generates a random database password and the database URL,
a settings key (which encrypts secrets saved in the admin area, such as the OIDC client secret),
creates an empty file for the OIDC client secret, and sets ownership so each container can read
only its own secrets. It never overwrites existing files.

```sh
sudo ../../scripts/init-secrets.sh
```

If you configure OIDC in `.env`, write the client secret into its file without leaving it in
your shell history (if you configure OIDC on the web, leave the file empty and enter the secret
there):

```sh
sudo sh -c 'read -r s && printf %s "$s" > secrets/oidc_client_secret'   # paste, then Enter
```

**Step 4 (optional): branding.** Put `theme.json` and/or `logo.png` into `./branding` and set
`BRAND_NAME`, `THEME_FILE` and `BRAND_LOGO_FILE` in `.env`. See [THEMING.md](THEMING.md).

**Step 5: start.**

```sh
docker compose up -d --build
```

**Step 6: verify.**

```sh
docker compose ps                                   # all three services "running"; frontdir "healthy"
docker compose logs frontdir | grep 'frontdir listening'
curl -fsS -o /dev/null -w '%{http_code}\n' https://<host>/readyz   # expect 204
```

If FrontDir exits immediately, `docker compose logs frontdir` lists **every** configuration
problem at once. Fix them all and run `docker compose up -d` again.

**Step 7: sign-in on the web (if you left it out of `.env`).** The log says FrontDir is not set
up yet. Create the one-time setup link:

```sh
docker compose exec frontdir /frontdir setup-link
```

It prints a link (`https://<host>/setup#…`) to your terminal only; it is never written to a log.
Treat it like a password. Open it, enter your identity provider's details (the page shows the
redirect URI or SAML metadata URL to register there), and save: FrontDir tries them against the
identity provider before saving, so a typo is caught now. Then choose **Sign in to finish**. You
sign in through your identity provider, become the first administrator, and the link stops
working. Unused, it expires after 24 hours; running the command again replaces it.

**Step 8: SAML only.** If your IdP needs the SP metadata file, download it now from
`https://<host>/auth/saml/metadata` and import it. (With SAML configured on the web, the IdP's
metadata must be saved first, so register FrontDir at the IdP with the metadata URL as soon as
it is saved, then sign in to finish.)

Continue with [§6 First sign-in](#6-first-sign-in-and-day-one-tasks).

### What the Compose setup does for you

- Every container drops all Linux capabilities (re-adding only the few PostgreSQL and Caddy
  need), runs with `no-new-privileges`, and FrontDir runs as a non-root user on a read-only root
  filesystem.
- PostgreSQL sits on an internal network with no route to the internet or the host. It is
  initialized with data checksums and SCRAM password authentication.
- Only Caddy's network (`172.30.0.0/24`) is trusted to set `X-Forwarded-For`, so client IPs in
  logs and rate limits are real.
- Caddy does not compress responses (to avoid BREACH-style attacks) and does not buffer large
  transfers.

---

## 4. Install on Kubernetes

The reference manifest is `deploy/kubernetes/frontdir.yaml`. It creates a namespace with the
*restricted* Pod Security level, a service account without API access, a non-root pod with a
read-only root filesystem, probes, and a default-deny NetworkPolicy.

**Step 1: build and publish the image.** No public image is published yet. Build from a reviewed
commit and push to a registry your cluster can pull from:

```sh
docker build --build-arg VERSION=$(git describe --tags --always) -t registry.example.com/frontdir:<version> .
docker push registry.example.com/frontdir:<version>
```

Then set `image:` in the manifest to that image, preferably **by digest**
(`registry.example.com/frontdir@sha256:…`).

**Step 2: PostgreSQL.** Use a managed service or an operator (for example CloudNativePG). Create
a database and a user owning it. Off-host connections should use `sslmode=verify-full`.

**Step 3: storage.** The manifest requests a 500 GiB `ReadWriteOnce` volume and runs one replica
with the `Recreate` strategy. To run more replicas, use `ReadWriteMany` storage (NFS, CephFS,
Longhorn RWX, …) and switch to `RollingUpdate`. Several replicas are safe: migrations and
background jobs coordinate through the database. Rate limits are counted per replica.

**Step 4: secrets.** Create them out of band; never commit them:

```sh
kubectl create namespace frontdir      # or apply the manifest's Namespace first
kubectl -n frontdir create secret generic frontdir-secrets \
  --from-literal=database_url='postgres://frontdir:<password>@<db-host>:5432/frontdir?sslmode=verify-full' \
  --from-literal=oidc_client_secret='<secret>'
```

For SAML with an SP key pair, add the key and certificate to the secret and set
`FRONTDIR_SAML_SP_KEY_FILE` and `FRONTDIR_SAML_SP_CERT_FILE` to their mounted paths.

**Step 5: configure.** Edit the ConfigMap in the manifest: `FRONTDIR_PUBLIC_URL`, the sign-in
settings, `FRONTDIR_ALLOWED_GROUPS`, `FRONTDIR_ADMIN_GROUPS`, and `FRONTDIR_TRUSTED_PROXIES` (the
pod CIDR of your ingress controller, so that only the ingress can set `X-Forwarded-For`).

**Step 6: ingress.** The manifest has no Ingress, because ingress controllers differ. Whatever
you use must terminate TLS, pass the original `Host` header, set `X-Forwarded-For`, allow large
request bodies, avoid buffering, and allow long transfers. For ingress-nginx:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: frontdir
  namespace: frontdir
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    nginx.ingress.kubernetes.io/proxy-request-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
spec:
  ingressClassName: nginx
  tls:
    - hosts: [files.example.com]
      secretName: frontdir-tls
  rules:
    - host: files.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {service: {name: frontdir, port: {name: http}}}
```

The NetworkPolicy allows ingress only from the namespace labelled
`kubernetes.io/metadata.name: ingress-nginx`. Adjust it for another controller.

**Step 7: apply and verify.**

```sh
kubectl apply -f deploy/kubernetes/frontdir.yaml
kubectl -n frontdir rollout status deploy/frontdir
kubectl -n frontdir logs deploy/frontdir | grep 'frontdir listening'
curl -fsS -o /dev/null -w '%{http_code}\n' https://<host>/readyz   # expect 204
```

To run migrations as a separate step (for example a pre-upgrade Job), set
`FRONTDIR_AUTO_MIGRATE=false` and run `/frontdir migrate` with the same configuration.

---

## 5. Using your own reverse proxy or TLS

Any reverse proxy works if it:

1. terminates TLS for the hostname in `FRONTDIR_PUBLIC_URL`;
2. forwards the **original `Host` header** (FrontDir answers `421 Misdirected Request` to any other host);
3. sets `X-Forwarded-For`, and FrontDir lists the proxy's address in `FRONTDIR_TRUSTED_PROXIES`;
4. allows request bodies as large as `FRONTDIR_MAX_FILE_SIZE` (or unlimited), streams without
   buffering, and allows transfers that last longer than a minute;
5. does **not** compress responses, and does not rewrite `Origin`, `Sec-Fetch-*` or cookies.

nginx example:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name files.example.com;
    ssl_certificate     /etc/ssl/files.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/files.example.com/privkey.pem;

    client_max_body_size 0;
    proxy_request_buffering off;
    proxy_buffering off;
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;
    gzip off;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

**Without a proxy,** FrontDir can terminate TLS itself: set `FRONTDIR_TLS_CERT_FILE` and
`FRONTDIR_TLS_KEY_FILE` (TLS 1.2 minimum) and usually `FRONTDIR_LISTEN=:8443`. Certificates are
read at startup, so restart FrontDir after renewing them.

---

## 6. First sign-in and day-one tasks

1. Open `https://<host>` and sign in with an account in the admin group (or finish the setup link,
   [§3](#3-install-with-docker-compose) step 7, which makes you an administrator). FrontDir creates
   accounts automatically on first sign-in. There is nothing to pre-provision.
2. Choose an **encryption passphrase** (at least 12 characters). It is separate from your IdP
   password and never leaves the browser.
3. **Store the recovery code** shown once (print it, or save it to a password manager).
4. Settings → **Download key backup**, and keep the file with your backups. It is itself encrypted
   and opens only with your passphrase or recovery code.
5. Check that the header shows "admin" next to your quota and that **Admin** appears in the menu.
   If not, your account's groups do not include one in the administrator groups (see
   [Troubleshooting](#15-troubleshooting)), or use a setup link to appoint yourself.
6. In **Admin**, review **Sign-in → Who can sign in** (restrict it to a group or email domain
   unless your identity provider admits only the right people), **Storage & sharing** and
   **Branding**. Changing anything asks you to **confirm it's you** first
   ([§7](#confirm-its-you)).
7. Create team folders (Team folders → **New team folder**) and, on each folder's **Members**
   page, map IdP groups under **Identity-provider groups**. Members of a mapped group get access
   immediately, but cannot open anything until a manager gives them the folder key: they appear
   under **Waiting for the team key** on the Members page, with their key fingerprint, and the
   manager approves each one (or everyone listed, after reviewing the list). Keys are never
   granted automatically, because the member list comes from the server, and anyone who
   controls the server could add a name to it.
8. Send users a short notice. For example:

   > Our new file storage is end-to-end encrypted: not even the administrators can read your
   > files. When you first sign in you will choose an encryption passphrase and receive a
   > recovery code. **Keep the recovery code safe.** If you forget your passphrase and lose the
   > code, your files cannot be recovered by anyone. Under Settings, download your key backup
   > and keep it with your own backups. Before sharing anything sensitive with a colleague,
   > verify them once: choose **Verify…** next to their name and compare the fingerprint with
   > them in person or on a call. From then on you will see ✔ next to them, and a warning if
   > anyone imitates them.

---

## 7. Configuration reference

Settings are environment variables, and most can also be changed by administrators in the web
admin area ([below](#the-web-admin-area-and-the-server-who-owns-which-setting)). FrontDir
validates the whole configuration at startup and **refuses to start** if anything is missing or
unsafe, listing every problem. Environment changes take effect when FrontDir restarts; changes
in the admin area take effect immediately, on every replica within 15 seconds.

**With Docker Compose,** put each setting in `deploy/compose/.env` without the `FRONTDIR_`
prefix: `FRONTDIR_TEAM_CREATION=false` becomes `TEAM_CREATION=false`. `.env.example` lists
every one, with its default. Then run `docker compose up -d` to apply the change. A few settings
are fixed by the Compose setup on purpose, and setting them in `.env` has no effect:

| Setting | Fixed to | Why |
|---|---|---|
| `FRONTDIR_PUBLIC_URL` | `https://` + `FRONTDIR_HOST` | One hostname drives FrontDir and Caddy |
| `FRONTDIR_DATABASE_URL_FILE`, `FRONTDIR_OIDC_CLIENT_SECRET_FILE`, `FRONTDIR_SETTINGS_KEY_FILE` | Docker secrets from `secrets/` | Keeps credentials out of the environment |
| `FRONTDIR_TRUSTED_PROXIES` | Caddy's network, `172.30.0.0/24` | Only the proxy may set `X-Forwarded-For` |
| `FRONTDIR_LISTEN`, `FRONTDIR_TLS_CERT_FILE`, `FRONTDIR_TLS_KEY_FILE` | Port 8080, no TLS | Caddy terminates TLS and proxies to FrontDir |
| `FRONTDIR_DATA_DIR` | `/data` | The `frontdir-data` volume is mounted there |

Settings that name a file point inside the container. Put SAML files (IdP metadata, the SP key
pair) in `deploy/compose/saml/`, which is mounted read-only at `/etc/frontdir/saml`, and branding
files in `deploy/compose/branding/`, mounted at `/etc/frontdir/branding`. The repository's tests
check that every setting FrontDir reads can be set this way and is documented here.

For values that are secrets, prefer the `_FILE` form: `FRONTDIR_DATABASE_URL_FILE`,
`FRONTDIR_OIDC_CLIENT_SECRET_FILE` and `FRONTDIR_SETTINGS_KEY_FILE` name a file whose contents are
the value. File-based secrets
stay out of `docker inspect`, process listings and crash dumps. Setting both forms is an error.

Sizes accept `B`, `KiB`, `MiB`, `GiB`, `TiB` (e.g. `50GiB`). Durations accept Go syntax (`12h`,
`90m`) or days (`30d`). Lists are comma-separated. Booleans are `true` or `false`; anything else is
an error rather than a silent default.

### The web admin area and the server: who owns which setting

Think of it like a building: the person who runs the server owns the foundations (where the
database is, the address and port, TLS, proxies, the data directory, the keys), and administrators
furnish the rooms (quotas, link lifetimes, who may sign in, which identity provider, branding).
So the **Core** settings below are server-only, and everything in the other tables can also be
changed under **Admin** in the web app:

| Admin tab | Settings |
|---|---|
| People | Per-person storage, appointing administrators, revoking a person's access |
| Storage & sharing | [Storage and limits](#storage-and-limits), [sharing and sessions](#sharing-and-sessions) |
| Sign-in | [OIDC](#oidc), [SAML](#saml), [access policy](#access-policy) (who may sign in, administrator groups) |
| Branding | [Name, theme and logo](#branding) |
| Emergency | Revoke every public link; sign everyone out |

**Precedence.** A non-empty environment variable wins and is shown **locked** in the admin area,
with the variable's name; otherwise the value saved in the admin area; otherwise the default.
With Compose, a commented-out or empty line in `.env` is "not set". `FRONTDIR_WEB_SETTINGS=false`
locks every setting (configuration as code only).

**Sign-in methods are either/or.** OIDC is configured entirely in the environment (when
`FRONTDIR_OIDC_ISSUER` is set) or entirely on the web, and the same for SAML (anchored by
`FRONTDIR_SAML_IDP_METADATA_URL` or `_FILE`). A stray OIDC or SAML variable without its anchor is a
startup error, so a deployment never runs on a mix nobody reviewed as a whole.

**One set of rules.** Values from the admin area are parsed and validated by exactly the same code
as environment variables. Sign-in changes are also tried against the identity provider before
they are saved (OIDC discovery and signing keys; SAML metadata), and the error says what failed,
never what the remote server answered.

#### Confirm it's you

Viewing the admin area needs administrator rights. **Changing** anything in it also needs a
recent sign-in: your identity provider is asked to authenticate you again (OIDC `prompt=login`
and `max_age=0`; SAML `ForceAuthn`), and FrontDir checks that it did (OIDC `auth_time`, SAML
`AuthnInstant`). It lasts 15 minutes. It is the same idea as `sudo` asking for your password
again: a session left open on an unattended computer can look but cannot change who may sign
in, who administers, or where sign-in goes. App passwords never qualify. Some identity providers
omit `auth_time`; FrontDir then relies on them honouring `prompt=login` and logs a warning.

#### Guard rails

- **No self-lockout.** A change to who may sign in that would exclude the administrator making it
  is refused, as is a change to the administrator groups that would remove their own rights.
  Nobody can change their own appointment.
- **Sign-in cannot be switched off from the web.** At least one method must stay on.
- **Replacing an identity provider asks for confirmation.** Accounts are tied to the issuer that
  created them. Switching or removing a provider leaves its accounts unable to sign in (their
  files stay, encrypted), and people get new, empty accounts through the new provider. FrontDir
  counts the affected accounts, including yours, and asks before saving. Nobody can take over an
  existing account by pointing FrontDir at another provider.
- **Two administrators at once.** Saves carry a revision; the second of two conflicting saves is
  refused rather than silently overwriting the first.
- **Secrets** (the OIDC client secret) are stored encrypted with AES-256-GCM under
  `FRONTDIR_SETTINGS_KEY`, never shown again, and logged only as "set". Without a settings key,
  the admin area cannot store secrets and says so.
- **Outbound requests** to identity providers never go to link-local or cloud metadata addresses
  (or loopback, except on a `localhost` deployment); responses are capped at 1 MiB. Private
  network addresses are allowed, so an IdP on the same Docker network works.
- Every change is audited as `settings.changed`, with the values of ordinary settings and
  "(set)" or "(changed)" for secrets, documents and logos.

#### From the server's shell

| Command | Use |
|---|---|
| `docker compose exec frontdir /frontdir settings show` | Every setting, its source (`server`, `web`, `default`) and value; secrets hidden |
| `docker compose exec frontdir /frontdir settings reset KEY…` | Clear settings saved on the web: a key (`OIDC_CLIENT_SECRET`), a group (`oidc`, `saml`, `access`, `branding`, `storage`, ...) or `all`. Running servers pick it up within 15 seconds. |
| `docker compose exec frontdir /frontdir setup-link` | A one-time link to configure sign-in and become an administrator. Also the way back in when no administrator can sign in: reset the broken sign-in settings, then create a link. |

Saved settings that no longer validate (for example after an upgrade tightened a rule) stop the
server from starting with the list of problems and these commands as the fix. They are never
skipped: skipping a broken "allowed groups" would open sign-in to everyone.

### Core

| Variable | Default | Meaning |
|---|---|---|
| `FRONTDIR_PUBLIC_URL` | *required* | The external origin, e.g. `https://files.example.com`. HTTPS is required except for `localhost`. Used for host checks, CSRF checks and IdP redirects. |
| `FRONTDIR_DATABASE_URL` or `FRONTDIR_DATABASE_URL_FILE` | *required* | PostgreSQL connection URL. Use `sslmode=verify-full` when the database is on another host. |
| `FRONTDIR_DATA_DIR` | `/data` | Where encrypted file containers are stored |
| `FRONTDIR_LISTEN` | `:8080` | Listen address |
| `FRONTDIR_TLS_CERT_FILE` and `FRONTDIR_TLS_KEY_FILE` | | Serve HTTPS directly (set both or neither) |
| `FRONTDIR_TRUSTED_PROXIES` | | IPs or CIDRs whose `X-Forwarded-For` header is believed. Set it to exactly your proxy's addresses. |
| `FRONTDIR_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `FRONTDIR_AUTO_MIGRATE` | `true` | Apply database migrations at startup |
| `FRONTDIR_WORKER` | `true` | Run background jobs (trash expiry, purging deleted data, cleaning up expired sessions) |
| `FRONTDIR_WEBDAV` | `true` | Serve the read-only, ciphertext-only WebDAV endpoint at `/dav/` for backups |
| `FRONTDIR_SETTINGS_KEY` or `FRONTDIR_SETTINGS_KEY_FILE` | | 32 random bytes, base64 or hex (`scripts/init-secrets.sh` creates one). Encrypts secrets saved in the admin area. Without it the admin area cannot store secrets. Back it up separately from the database. |
| `FRONTDIR_WEB_SETTINGS` | `true` | `false` makes every setting read-only in the admin area |

### OIDC

| Variable | Default | Meaning |
|---|---|---|
| `FRONTDIR_OIDC_ISSUER` | | Issuer URL. Setting it enables OIDC. |
| `FRONTDIR_OIDC_CLIENT_ID` | *required with OIDC* | |
| `FRONTDIR_OIDC_CLIENT_SECRET` or `FRONTDIR_OIDC_CLIENT_SECRET_FILE` | | Client secret |
| `FRONTDIR_OIDC_SCOPES` | `openid,email,profile` | |
| `FRONTDIR_OIDC_GROUPS_CLAIM` | `groups` | ID-token claim holding group names |

### SAML

| Variable | Default | Meaning |
|---|---|---|
| `FRONTDIR_SAML_IDP_METADATA_URL` or `FRONTDIR_SAML_IDP_METADATA_FILE` | | IdP metadata (URL must be `https://`). Setting one enables SAML. |
| `FRONTDIR_SAML_ENTITY_ID` | `https://<host>/auth/saml/metadata` | SP entity ID |
| `FRONTDIR_SAML_SP_KEY_FILE` and `FRONTDIR_SAML_SP_CERT_FILE` | | Optional SP key pair (PEM) used to sign requests and decrypt encrypted assertions (set both or neither) |
| `FRONTDIR_SAML_TRUST_EMAIL` | `false` | Treat asserted emails as verified |
| `FRONTDIR_SAML_EMAIL_ATTRIBUTES` | `email`, `mail`, and the standard OID and claim URIs | Attribute names to read the email from, in order |
| `FRONTDIR_SAML_NAME_ATTRIBUTES` | `displayName`, `name`, `cn`, and standard URIs | Display name attributes |
| `FRONTDIR_SAML_GROUP_ATTRIBUTES` | `groups`, `memberOf`, `eduPersonAffiliation`, and standard URIs | Group attributes |

With neither OIDC nor SAML configured (here or on the web), FrontDir starts in **setup mode**:
the sign-in page explains that the server is not set up, and `frontdir setup-link` creates the
link to set it up ([§3](#3-install-with-docker-compose) step 7).

### Access policy

| Variable | Default | Meaning |
|---|---|---|
| `FRONTDIR_ALLOWED_GROUPS` | | Sign-in requires membership in at least one of these groups |
| `FRONTDIR_ALLOWED_EMAIL_DOMAINS` | | Sign-in requires a **verified** email in one of these domains |
| `FRONTDIR_ADMIN_GROUPS` | | Members are FrontDir administrators (as are people appointed under Admin → People, and whoever completes a setup link) |
| `FRONTDIR_TEAM_CREATION` | `true` | Whether every user may create team folders (`false`: administrators only) |

If both allow-lists are set, a user must satisfy **both**. If neither is set, FrontDir logs a
warning at startup and admits every account the IdP authenticates. Group memberships are
refreshed at every sign-in; a change to the administrator groups applies to everyone at once,
based on the groups each person had at their last sign-in.

### Storage and limits

| Variable | Default | Meaning |
|---|---|---|
| `FRONTDIR_DEFAULT_QUOTA` | `10GiB` | Quota of each new personal space |
| `FRONTDIR_DEFAULT_TEAM_QUOTA` | `50GiB` | Quota of each new team folder |
| `FRONTDIR_MAX_FILE_SIZE` | `50GiB` | Largest single (encrypted) file (at least `1MiB`) |
| `FRONTDIR_MAX_VERSIONS` | `10` | Versions kept per file (1-1000). All count towards quota. |
| `FRONTDIR_TRASH_RETENTION` | `30d` | Trashed items are purged after this (at least `1h`) |

### Sharing and sessions

| Variable | Default | Meaning |
|---|---|---|
| `FRONTDIR_LINK_DEFAULT_TTL` | `30d` | Expiry of a public link when the user does not choose one (at least `1h`, at most the maximum). Every link expires. |
| `FRONTDIR_LINK_MAX_TTL` | `365d` | Longest expiry a user may choose |
| `FRONTDIR_SESSION_IDLE` | `12h` | Browser sessions end after this much inactivity (`5m` to `30d`, at most the maximum age) |
| `FRONTDIR_SESSION_MAX_AGE` | `7d` | Browser sessions end after this long regardless of activity (`15m` to `365d`). Shortening it applies to existing sessions too. |

### Branding

| Variable | Default | Meaning |
|---|---|---|
| `FRONTDIR_BRAND_NAME` | `FrontDir` | Name in the header, page title and sign-in page |
| `FRONTDIR_BRAND_LOGO_FILE` | | PNG or JPEG logo (re-encoded, so only pixels are served) |
| `FRONTDIR_THEME_FILE` | | Theme JSON. See [THEMING.md](THEMING.md). |

In the admin area, the theme is edited as JSON and the logo uploaded; both are validated the same
way (including contrast) before they are saved.

### Fixed limits

These are built in, not configurable:

- Sign-in attempts (including "confirm it's you"): 20 per minute per client IP.
- A recent sign-in for administrative changes lasts 15 minutes.
- A setup link works once and expires after 24 hours.
- Failed credential checks: 30 per minute per client IP.
- Anonymous public-link requests: 120 per minute per client IP.
- A password-protected link locks for 15 minutes after 10 wrong passwords.

Client IPs are only accurate when `FRONTDIR_TRUSTED_PROXIES` is set correctly. Otherwise every
user appears to come from the proxy and shares one rate-limit budget.

---

## 8. Routine maintenance

| How often | Task | Section |
|---|---|---|
| Daily (automate) | Server backup: database, then data volume | [§9](#9-backups-and-restore) |
| Daily (automate) | Alert on failed health checks, 5xx spikes, `login.failed` bursts | [§11](#11-monitoring-and-logs) |
| Weekly | Review audit events: `link.password_failed`, `admin.links.revoke_all`, `operator.*`, `team.group_map` | [§11](#11-monitoring-and-logs) |
| Monthly | Apply FrontDir and base-image updates | [§10](#10-upgrades) |
| Monthly | Check disk usage against the sum of quotas | [§11](#11-monitoring-and-logs) |
| Monthly | `restic check --read-data-subset=5%` (or your tool's equivalent) | [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md#6-checking-backups-without-reading-them) |
| Quarterly | Full restore drill on a scratch machine: `verify-storage --hash`, then open the canary file | [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md#7-restoring-after-losing-the-server) |
| Quarterly | Review who is in the admin and allowed groups at the IdP | [§12](#12-managing-users) |
| Yearly, or when staff leave | Rotate the database password, OIDC client secret and SAML SP key | [§14](#14-rotating-secrets) |

The background worker does the rest automatically: it expires trash, purges deleted files and
team folders, removes expired sessions and login requests, and, after an upgrade, works through
older file versions so the web app can show who saved each one (a few versions a minute, reading
encrypted files from storage; it decrypts nothing).

---

## 9. Backups and restore

There are two independent kinds of backup. Use both. For backing up the whole server at the
operating-system level and rebuilding it on new hardware (fire, theft, ransomware), follow
**[DISASTER_RECOVERY.md](DISASTER_RECOVERY.md)**. It covers off-site repositories, verifying
backups without being able to read them, and a step-by-step rebuild runbook. This section covers
the basic mechanics.

### Server backups (you)

| What | Why | Notes |
|---|---|---|
| PostgreSQL database | Users, folder tree, encrypted names, wrapped keys, shares, team memberships | Contains metadata in the clear. Encrypt and restrict the backups. |
| Data volume (`FRONTDIR_DATA_DIR`) | The encrypted file containers | Already ciphertext and does not compress, so skip compression. |
| `deploy/compose/.env`, `secrets/`, `branding/` | Your configuration, including `secrets/settings_key` | Small; keep them separate from the data backups. Settings changed in the admin area are in the database; the OIDC client secret among them is encrypted under the settings key, so a database backup alone does not reveal it, and is not enough to restore it either. |

Back up the **database first, then the data volume**. Every file the database dump refers to will
then be in the later volume backup. The only exception is items purged from the trash between the
two steps, which were being deleted anyway.

With Compose:

```sh
cd deploy/compose
stamp=$(date +%F)
docker compose exec -T postgres pg_dump -U frontdir -d frontdir -Fc > frontdir-db-$stamp.dump
docker run --rm -v frontdir_frontdir-data:/data:ro -v "$PWD":/backup alpine \
  tar -C /data -cf /backup/frontdir-data-$stamp.tar .
```

Then copy both files off the host (restic, borg, rclone or your backup system), encrypted at rest.

**Restore** (Compose). This replaces the current database and data:

```sh
cd deploy/compose
docker compose stop frontdir
docker compose exec -T postgres dropdb -U frontdir frontdir
docker compose exec -T postgres createdb -U frontdir frontdir
docker compose exec -T postgres pg_restore -U frontdir -d frontdir --no-owner < frontdir-db-<date>.dump
docker run --rm -v frontdir_frontdir-data:/data -v "$PWD":/backup:ro alpine \
  sh -c 'find /data -mindepth 1 -delete && tar -C /data -xpf /backup/frontdir-data-<date>.tar'
docker compose start frontdir
docker compose exec frontdir /frontdir verify-storage --hash    # every file present and intact
docker compose exec frontdir /frontdir revoke-sessions --all    # see "restores bring back the past"
```

No keys are involved: the server never had any. Users sign in and unlock their files with their
own passphrases as before.

**Restores bring back the past:** sessions, app passwords and links revoked after the backup was
taken, removed team members and deleted files all come back. After any restore, end all sessions
and re-apply later revocations (see [DISASTER_RECOVERY.md §7](DISASTER_RECOVERY.md#7-restoring-after-losing-the-server),
step 7).

On Kubernetes, use your database's backup tooling (for example CloudNativePG's scheduled
backups) and volume snapshots or a file-level backup of the data volume, in the same order.

### User backups (each user, independent of the server)

Every stored file is a self-contained encrypted container that its owner can restore or decrypt
with only their own keys, even if this server is gone. Encourage users to:

1. keep their **recovery code** offline;
2. download their **key backup** (Settings → Download key backup, or `frontdir-cli export-keys`);
3. back up their files, still encrypted, with `frontdir-cli backup <dir>`, or by mirroring
   `https://<host>/dav/` with rclone or restic using a read-only app password.

`frontdir-cli decrypt-tree <backup-dir> <out-dir> --keys keys.json` turns such a backup back into
plaintext files with their real names, with no server involved.

### Test your restores

A backup you have not restored is a hope, not a backup. Each quarter:

1. restore the server backup into a scratch environment (a second Compose project on another
   host or a VM);
2. sign in there as a test user and open a file;
3. separately, decrypt one of your own `frontdir-cli backup` folders offline with `decrypt-tree`.

---

## 10. Upgrades

1. Read the release notes for anything marked as requiring action.
2. **Take a server backup** ([§9](#9-backups-and-restore)). Database migrations only move forward,
   so restoring that backup is how you roll back.
3. Update and rebuild:

   ```sh
   cd FrontDir && git fetch --tags && git checkout <new-tag-or-commit>
   cd deploy/compose
   docker compose build --pull frontdir
   docker compose pull postgres caddy
   docker compose up -d
   ```

4. Watch the logs until you see `frontdir listening`, and check `https://<host>/readyz`.
   Migrations run automatically at startup. With several replicas, a database lock ensures only
   one applies them.
5. Ask users of `frontdir-cli` (and its drive) to update it too. Since the release that added
   signed version history, the server refuses new files and versions without a signed version
   record, so an older CLI can still read but no longer save. The web app updates itself.

### Upgrading from NoddaNAS

FrontDir was called NoddaNAS. Encrypted files, key bundles, backups, public links and app
passwords carry over unchanged: the cryptographic identifiers kept their old values
([E2EE.md](E2EE.md#notation)), and old backup files (`.ndne`) and app passwords (`ndn_...`) are
still accepted. What changed is every name you deploy with:

| Before | Now |
|---|---|
| `NODDANAS_*` environment variables | `FRONTDIR_*` (FrontDir **refuses to start** while any `NODDANAS_*` variable is set, so an old setting is never silently ignored) |
| `NODDANAS_HOST` in `deploy/compose/.env` | `FRONTDIR_HOST` (the other `.env` names have no prefix and are unchanged) |
| Compose project, service and volumes `noddanas`, `noddanas_noddanas-data`, `noddanas_postgres-data` | `frontdir`, `frontdir_frontdir-data`, `frontdir_postgres-data` |
| Database role and name `noddanas` (Compose) | `frontdir` |
| Binaries and commands `noddanas`, `noddanas-cli` | `frontdir`, `frontdir-cli` (in the container: `/frontdir`) |
| Kubernetes namespace and objects `noddanas` | `frontdir` |
| Session cookie names | Renamed: everyone signs in once more |

With Docker Compose, the new names mean new volumes, so move your data with the backup and restore
commands from [§9](#9-backups-and-restore) (the same commands CI tests, with the names adjusted):

```sh
cd deploy/compose
# 1. With the old version still checked out and running: back up.
docker compose exec -T postgres pg_dump -U noddanas -d noddanas -Fc > ~/noddanas-db.dump
docker run --rm -v noddanas_noddanas-data:/data:ro -v ~:/backup alpine tar -C /data -cf /backup/noddanas-data.tar .
docker compose down                         # keeps the old volumes until you remove them

# 2. Check out FrontDir. Keep secrets/settings_key and secrets/oidc_client_secret; let the
#    script create a new database password and URL for the new database role.
git checkout <frontdir-tag-or-commit>
sudo mkdir -p ~/noddanas-secrets && sudo mv secrets/postgres_password secrets/database_url ~/noddanas-secrets/
sed -i 's/^NODDANAS_HOST=/FRONTDIR_HOST=/' .env
sudo ../../scripts/init-secrets.sh

# 3. Restore into the new names and start.
docker compose up -d --wait postgres
docker compose exec -T postgres pg_restore -U frontdir -d frontdir --no-owner < ~/noddanas-db.dump
docker run --rm -v frontdir_frontdir-data:/data -v ~:/backup:ro alpine tar -C /data -xpf /backup/noddanas-data.tar
docker compose up -d --build
docker compose exec frontdir /frontdir verify-storage --hash
docker compose exec frontdir /frontdir revoke-sessions --all   # the restore brings back old sessions

# 4. Once everything works, remove the old volumes and copies.
docker volume rm noddanas_noddanas-data noddanas_postgres-data noddanas_caddy-data noddanas_caddy-config
```

Caddy obtains a new certificate for the new `caddy-data` volume on its own. If you set any
`NODDANAS_*` variables outside `.env` (for example in an override file), rename them too. On
Kubernetes, either keep your existing namespace and object names (edit `frontdir.yaml` before
applying it) and rename the `NODDANAS_*` keys in your ConfigMap and Deployment, or restore a backup
into the new `frontdir` namespace. Command-line users rename `NODDANAS_URL`, `NODDANAS_TOKEN` and
the other client variables to `FRONTDIR_...`; their existing app passwords keep working.

**PostgreSQL major versions** (for example 18 to 19) change the on-disk format. Upgrade with a
dump and restore ([§9](#9-backups-and-restore)) into a fresh volume, or with `pg_upgrade`. Do not
just change the image tag on an existing volume.

**Kubernetes:** change the image (by digest) and apply. Optionally run migrations first as a Job
with `/frontdir migrate`, and set `FRONTDIR_AUTO_MIGRATE=false` on the Deployment.

Pin base images by digest in production. Dependabot is configured in this repository to propose
updates.

---

## 11. Monitoring and logs

### Health endpoints

| Endpoint | Meaning | Use for |
|---|---|---|
| `GET /healthz` → 204 | The process is running | Liveness probes; container `HEALTHCHECK` (built into the image) |
| `GET /readyz` → 204 or 503 | The database and data directory are reachable | Readiness probes, uptime monitoring |

Both reveal nothing except the status code.

### Logs

FrontDir writes one JSON object per line to standard output (`docker compose logs frontdir`,
`kubectl logs`). Ship them to an append-only store.

- **Request logs** (`"msg":"http"`) have `request_id`, `method`, `route`, `status`, `bytes`,
  `ms`, `ip` and `user` (a user ID). Every API error response carries the same ID as `requestId`
  (and every response has an `X-Request-Id` header), so an error seen by a CLI or script can be
  matched to its log line.
- **Audit events** (`"msg":"audit"`) carry an `event` field:

| Area | Events |
|---|---|
| Sign-in | `login.success`, `login.failed` (with method, error and IP), `user.provisioned`, `sessions.revoke_all` |
| Keys | `keys.setup`, `keys.bundle_updated` |
| App passwords | `app_password.create`, `app_password.revoke` |
| Files | `file.upload`, `file.download`, `file.version_restore`, `folder.create`, `node.update`, `node.trash`, `node.restore`, `node.purge_requested`, `node.purged`, `trash.empty` |
| Sharing | `share.user.create`, `share.link.create`, `share.delete`, `link.download`, `link.password_failed`, `share.link.revoke_all` |
| File mailboxes | `mailbox.create`, `mailbox.close`, `mailbox.drop`, `mailbox.password_failed`, `mailbox.drop_file`, `mailbox.drop_discard`, `mailbox.expired` |
| Team folders | `team.create`, `team.delete`, `team.member_role`, `team.member_remove`, `team.key_grant`, `team.group_map`, `team.group_unmap`, `space.quota`, `space.purged` |
| Emergency and maintenance actions | `admin.links.revoke_all` (web), `operator.links.revoke_user`, `operator.links.revoke_all`, `operator.access.revoke`, `operator.sessions.revoke_all`, `operator.storage.verify` (server shell) |

Audit events never contain file names, file contents or keys. The server does not have them.

Example: all audit events for one user in the last day:

```sh
docker compose logs --since 24h frontdir | grep '"msg":"audit"' | grep '"user":"<user-id>"'
```

### Suggested alerts

- `/readyz` failing for more than two minutes.
- More than 1% of responses with `status` ≥ 500 over 10 minutes.
- A burst of `login.failed` from one IP, or `link.password_failed` on one share.
- Any `admin.links.revoke_all` or `operator.*` event. These should never be a surprise.
- Data volume above 80% full.

### Capacity

```sh
docker system df -v | grep frontdir_frontdir-data    # data volume size
```

Compare it with the sum of quotas you have granted. Quotas cap what users can store, but trash
and old versions use space until they expire.

---

## 12. Managing users

### Finding a user's ID

Operator commands accept either a verified email or the user's 32-character ID. IDs appear in
logs (`"user":…`), and Admin → **People** lists everyone with their sign-in method, role and storage. From the
shell you can list users from the database:

```sh
docker compose exec postgres psql -U frontdir -d frontdir -c \
  "SELECT id, display_name, email, is_admin, created_at FROM users ORDER BY display_name"
```

### Adding users and administrators

Add people to the allowed group at your IdP. Their account is created the first time they sign
in. To make someone an administrator, either add them to an administrator group (effective at
their next sign-in) or, once they have signed in, choose **Make administrator** next to them under
Admin → People (effective immediately). Removing an administrator group from the settings takes
effect immediately for everyone; removing a person from the group at the IdP takes effect at their
next sign-in, so also revoke their access (below) to make it immediate. Administrators cannot read
anyone's files: those stay end-to-end encrypted.

### Quotas

Under Admin → People, choose **Storage…** next to the person. Or from the shell:

```sh
docker compose exec frontdir /frontdir set-quota alice@example.com 100GiB   # personal space
```

Team folder quotas are set by an administrator through the API (`PUT /api/v1/spaces/{id}/quota`).
New spaces get the defaults from [§7](#storage-and-limits).

### A user forgot their passphrase

They choose **Forgot passphrase? Use recovery code** on the unlock screen and then set a new
passphrase. If they have lost both the passphrase and the recovery code, their encrypted files
cannot be recovered, by you or by anyone. There is currently no way to reset an account's keys
and start over with an empty space. Files they shared with others, or stored in team folders,
remain available to those people.

### Offboarding a user

Do these in order:

1. **Disable or remove the user at the IdP,** or remove them from the allowed groups. This stops
   new sign-ins. Do it first, or they could simply sign in again.
2. **Cut off existing access:** Admin → People → **Revoke access** (ends their sessions and deletes
   their app passwords), or from the shell, which also revokes their public links:

   ```sh
   docker compose exec frontdir /frontdir revoke-access --user alice@example.com   # or --user <id>
   ```

   This ends all of their browser sessions, deletes all of their app passwords (CLI and WebDAV
   clients), and revokes every public link they created. The command prints its audit record to
   your terminal (not to the server's log stream), so paste it into your ticket.
3. **Team folders:** a manager removes their direct memberships on each folder's Members page.
   Group-mapped access needs no action. Group memberships are refreshed only when someone signs
   in, so after step 1 they cannot sign in to use them, and after step 2 they have no credentials.

What stays: their personal space and the files in it. Nobody can read them, and there is no
command to delete a user yet. Files they put in team folders belong to those folders. Anything
they already downloaded cannot be recalled.

---

## 13. Incident response

The key fact for every scenario: someone holding only server access, a stolen session or a
stolen app password gets **ciphertext**. Plaintext needs the user's passphrase or recovery code,
which the server never stores. The exception is a compromised server delivering malicious
JavaScript to the web app. That is the main residual risk of browser-based end-to-end encryption.

### Public links leaked or misused

| Scope | Who | How |
|---|---|---|
| One link | The creator, or a manager of the folder | Shared → Shared by me → **Revoke**, or the item's Share dialog |
| All of one user's links | That user | Shared → Shared by me → **Revoke all my public links** |
| All of one user's links | Operator | `docker compose exec frontdir /frontdir revoke-links --user <email-or-id>` |
| Every link on the server | Administrator | Admin → Emergency → **Revoke all public links**, then type `REVOKE ALL` |
| Every link on the server | Operator | `docker compose exec frontdir /frontdir revoke-links --all` |

Revocation is immediate and permanent. The server deletes the link's token and its wrapped key,
so the secret in already-shared URLs no longer unlocks anything. People who need access again get
a new link. Sharing with specific people and team folders is unaffected.

Every one of these also **closes file mailboxes** (the same people's, or everyone's): their links
stop accepting files at once. Files already sent stay in the mailboxes' inboxes, to be filed or
discarded, until they expire with the trash retention period. One mailbox can be closed from
**Mailboxes** or the folder's **Mailbox…** dialog by anyone who can write to the folder.

The web switch for everyone requires an administrator with an interactive session and a recent
sign-in (an app password cannot use it). The shell commands work even if the web app is down or every
administrator account is compromised.

### A user account is compromised

1. Disable the account at the IdP, then run `revoke-access --user …` ([§12](#offboarding-a-user)).
2. Review that user's audit events ([§11](#logs)). Look especially at `share.link.create`,
   `share.user.create`, `app_password.create` and `file.download`.
3. List the shares they created, and revoke any that are unexpected:

   ```sh
   docker compose exec postgres psql -U frontdir -d frontdir -c \
     "SELECT id, kind, node_id, recipient_id, created_at FROM shares WHERE created_by = '<user-id>' ORDER BY created_at DESC"
   ```

4. If the attacker may also have the user's passphrase (for example malware on their device),
   treat their files as disclosed. When the user regains access, they should change their
   passphrase. Note that changing the passphrase does not change the underlying keys.

### An administrator account is compromised

As above, and also review `settings.changed`, `user.admin_granted`, `user.admin_removed`,
`user.quota`, `user.access_revoked`, `sessions.revoke_everyone`, `team.group_map`,
`team.group_unmap`, `space.quota`, `team.delete` and `admin.links.revoke_all` events, and undo
unexpected changes (`frontdir settings show` lists where every setting now comes from;
`frontdir settings reset` clears web settings). Check the admin group's membership at the IdP,
and the appointed administrators under Admin → People. Because changes need a recent sign-in at
the identity provider, look there too for the matching authentication.

### The server or its host is compromised

1. Take it offline. Preserve disks and logs for investigation.
2. Rebuild from a known-good image on a clean host, and restore the most recent backup taken
   before the compromise.
3. Rotate every secret ([§14](#14-rotating-secrets)).
4. End every session and app password:

   ```sh
   docker compose exec frontdir /frontdir revoke-sessions --all
   docker compose exec postgres psql -U frontdir -d frontdir -c "DELETE FROM app_passwords;"
   ```

5. Tell users what happened. If the attacker could have changed the JavaScript the server
   delivered, anyone who unlocked their keys in the browser during that window should treat
   their keys as exposed, and the files those keys open as potentially disclosed. FrontDir does
   not yet support replacing a user's keys, so use the time window and the audit logs to judge
   the extent, and handle highly sensitive data accordingly.

---

## 14. Rotating secrets

| Secret | Steps |
|---|---|
| Database password | `docker compose exec postgres psql -U frontdir -d frontdir -c "ALTER USER frontdir PASSWORD '<new>'"`, write the new password into `secrets/postgres_password` and update it inside `secrets/database_url`, then `docker compose up -d --force-recreate frontdir`. |
| OIDC client secret | Create a second secret at the IdP. Configured in `.env`: write it to `secrets/oidc_client_secret`, `docker compose up -d --force-recreate frontdir`. Configured on the web: enter it under Admin → Sign-in. Test a sign-in, then delete the old secret at the IdP. |
| Settings key | Only secrets saved in the admin area depend on it. Write a new key to `secrets/settings_key` (`openssl rand -base64 32`), run `docker compose run --rm frontdir settings reset OIDC_CLIENT_SECRET`, `docker compose up -d --force-recreate frontdir`, then enter the client secret again under Admin → Sign-in (sign in first with another method, or through a setup link). |
| SAML SP key pair | Generate a new key and certificate, give the IdP the new certificate (many IdPs accept two during a transition), switch FrontDir's `_KEY_FILE`/`_CERT_FILE` and restart, then remove the old certificate at the IdP. |
| TLS certificates | Caddy renews automatically. With `FRONTDIR_TLS_*`, replace the files and restart. |
| Users' app passwords | Users revoke and recreate them under Settings → App passwords. Operators can remove all of a user's with `revoke-access`. |

Secret files must stay readable only by the container that needs them. `init-secrets.sh` sets
mode `0400` and the right owner. Keep both if you replace a file by hand.

---

## 15. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| FrontDir exits at startup with `configuration:` and a list | Missing or invalid settings | Fix every listed item. The list is complete. |
| Startup fails with `theme:` | The theme file fails validation (often contrast) | The message names each failing color pair. See [THEMING.md](THEMING.md). |
| Startup fails with `settings saved in the web admin area are not valid` or `restore the settings key` | A saved web setting no longer validates, or the settings key changed | Fix it in the environment, or clear it: `docker compose run --rm frontdir settings reset KEY`. |
| The sign-in page says the server is not set up | No sign-in method is configured | Run `docker compose exec frontdir /frontdir setup-link` ([§3](#3-install-with-docker-compose) step 7). |
| Nobody can sign in after a sign-in change | The identity provider changed, or a client secret is wrong | `docker compose exec frontdir /frontdir settings reset oidc` (or `saml`), then `setup-link` to configure it again. |
| "Confirm it's you" sends you back with `?error=signin` | The identity provider reported an authentication older than the request | It did not ask for your password again. Check that it honours `prompt=login` (OIDC) or `ForceAuthn` (SAML). |
| A setting is greyed out in the admin area | It is set in the environment (the field names the variable), or `FRONTDIR_WEB_SETTINGS=false` | Change it there, or remove it from the environment to manage it on the web. |
| Every request returns `421 Misdirected Request` | The `Host` reaching FrontDir differs from `FRONTDIR_PUBLIC_URL` | Make the proxy forward the original `Host`; check the URL's hostname and port. |
| Actions fail with `cross-origin request blocked` | `FRONTDIR_PUBLIC_URL` differs from the address in the browser, or the proxy rewrites `Origin` | Use the exact public origin; stop the proxy from altering `Origin` and `Sec-Fetch-*`. |
| Sign-in returns to the start page with "not permitted" (`?error=not_allowed`) | The user is not in `FRONTDIR_ALLOWED_GROUPS`, or has no verified email in an allowed domain | Check the groups the IdP actually sends: the `login.failed` audit event shows the reason. With Entra ID, use group object IDs. |
| Sign-in fails (`?error=signin`) with SAML | Wrong ACS URL or entity ID, unsigned assertion, clock skew, or an IdP-initiated sign-in | Compare the IdP settings with [§2](#saml-20); make sure the server's clock is synchronized (NTP); start sign-in at FrontDir, not at the IdP. |
| Sign-in fails with OIDC | Wrong redirect URI, issuer or secret | The redirect URI must be exactly `https://<host>/auth/callback`. |
| Logged-in user has no "admin" | Their admin group is not in the token or assertion | Check the groups claim or attribute and the administrator groups, then sign out and in again. Or appoint them under Admin → People. |
| Cannot share with someone by email | Their email is not verified, or they have not set up encryption yet | See [§2](#2-prepare-your-identity-provider) on verified emails. The recipient must sign in once and create keys. |
| A team member sees "you have not been given this team folder's key yet" | No manager has approved them since they joined | A manager opens the folder's Members page and chooses **Give key** next to them under **Waiting for the team key**. |
| Someone is shown with "⚠ Key changed" or "⚠ Possible impersonation" | The account's keys differ from the ones the user verified, or a different account imitates a verified person's name or email | Treat it as a security incident: published keys never change, so this means tampering or impersonation. Check the audit log and the `users` table, and see [§13](#13-incident-response). |
| Large uploads fail or stall | The proxy limits body size, buffers, or times out | See [§5](#5-using-your-own-reverse-proxy-or-tls). |
| Many users get "rate limited" | `FRONTDIR_TRUSTED_PROXIES` is unset, so everyone shares the proxy's IP | Set it to the proxy's address or range. |
| `/readyz` returns 503 | The database is unreachable, or the data directory is not writable | Check `docker compose ps`, the database logs, and the volume mount and its ownership (UID 65532). |
| Disk filling faster than expected | Old versions and trash | Lower `FRONTDIR_MAX_VERSIONS` or `FRONTDIR_TRASH_RETENTION`; users can empty their trash. |

When a user reports an error, ask for the time and what they were doing, and search the request
logs for their user ID around that time. API and CLI users can give you the `requestId` from the
error response or the `X-Request-Id` header.

---

## 16. Decommissioning

1. Announce a date well in advance. Ask every user to download their key backup and run
   `frontdir-cli backup` (or copy what they need), and to check that `decrypt-tree` works on their
   backup.
2. Run `revoke-links --all` so no public link outlives the service.
3. Take a final server backup and keep it as long as your retention policy requires. It contains
   metadata in the clear, so protect it and delete it when that period ends.
4. Stop and remove the deployment. With Compose, `docker compose down` keeps the volumes, and
   `docker compose down -v` **destroys them permanently**.
5. Remove the application at your IdP and delete the DNS record.
