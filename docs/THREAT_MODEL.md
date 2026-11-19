# Threat model

What FrontDir protects, from whom, how, and what risk remains. STRIDE per trust boundary; each
mitigation points to code or tests so the claim can be checked.

## Assets

| Asset | Why it matters |
|---|---|
| File contents and names, team names | The reason the system exists |
| Users' passphrases, recovery codes, master keys, private keys | Unlock everything a user can read |
| Team secrets, node keys, link secrets | Unlock a space, a subtree, or a link |
| Session cookies, app passwords, link tokens | Bearer credentials for server access |
| Metadata (tree shape, sizes, timestamps, memberships) | Reveals structure and relationships |
| Server settings (who may sign in, which identity provider, administrators) | Decide who gets an account and who administers |
| The setup link and the settings key | Bootstrap administration; protect secrets saved on the web |
| Availability and quota | Storage is finite and shared |

## Actors

- **Anonymous internet user**, possibly holding a leaked public link.
- **Authenticated user** trying to exceed their rights.
- **Malicious share recipient or team member.**
- **Hostile web page** visited by a signed-in user (CSRF, XSS, clickjacking).
- **Compromised client device** holding an app password.
- **Storage / backup attacker**: obtains the volume, a snapshot or a backup.
- **Database attacker**: obtains a database dump.
- **Malicious or compromised server operator**: controls the FrontDir process and its data.
- **Malicious identity provider response** (forged, replayed or unsolicited assertions).

Out of scope: a compromised end-user device or browser (it sees plaintext by definition), and a
compromised identity provider (it can sign anyone in; it still cannot decrypt anything).

## The central claim

**A party that controls the server and all its storage cannot read file contents, file or folder
names, or team names**, provided users verify public-key fingerprints when it matters (see
"Trust in the key directory"). Everything below either supports that claim or covers what the
server is still responsible for (access control, integrity of structure, availability).

## STRIDE analysis

### Spoofing

| Threat | Mitigation | Evidence |
|---|---|---|
| Forged OIDC sign-in | PKCE (S256), state bound to a single-use server record and a `__Host-` cookie, nonce, ID-token signature/issuer/audience/expiry | `auth/oidc.go`; e2e test |
| Forged or tampered SAML assertion | XML signature required and verified (crewjam/saml); audience, issuer, destination, validity window | e2e: tampered NameID rejected |
| Replayed SAML response | Each response must answer an AuthnRequest whose ID is stored server-side and consumed once, from the same browser | e2e: replay rejected |
| Unsolicited (IdP-initiated) SAML, login CSRF | IdP-initiated SSO disabled; no binding cookie → rejected | e2e: unsolicited rejected |
| Anyone the IdP knows signs in | Group / verified-email-domain policy for both OIDC and SAML; startup warning if open | e2e: policy test |
| Stolen or unattended administrator session changes settings, appoints administrators or switches the identity provider | Every admin-area change needs a recent re-authentication at the IdP (OIDC `prompt=login` + `max_age=0` with `auth_time` checked; SAML `ForceAuthn` with `AuthnInstant` checked), valid 15 minutes; app passwords never qualify; settings set in the environment are locked; every change audited | `TestSetupLinkAndWebSettings` (stale `auth_time` refused), `TestUpdateRules` |
| Switching the IdP to take over existing accounts | Accounts are keyed by (issuer, subject): a new IdP only creates new, empty accounts; switching or removing a provider requires explicit confirmation naming how many accounts it strands | `TestSignInChangesAreCheckedAndConfirmed` |
| Guessing or intercepting the setup link | 256-bit token, stored as a hash, one at a time, 24-hour expiry, deleted in the same transaction that appoints the first administrator; printed to the operator's terminal only, never logged; carried in the URL fragment (never sent to servers or in `Referer`) and POST bodies | `TestSignInChangesAreCheckedAndConfirmed`, browser test (token not in log, removed from the address bar) |
| Capturing another user's shares via their email | Accounts keyed by (issuer, subject); emails recorded only if verified and unclaimed; SAML emails trusted only if configured | `service/users.go` |
| Forged key grant (anyone can seal to a public key) | Every share, team grant and trash seal is signed by its granter; clients verify | `e2ee` tests: forged grant/share rejected |
| Server inserts a team member to obtain the team key | Clients never grant keys automatically; a manager approves each pending member after seeing their fingerprint and verification status; the Go library requires an approval callback | Browser test: database-inserted member is not granted; `TestEndToEnd` (no blind or unapproved grants) |
| Server substitutes a user's keys, or creates a look-alike account ("Аlice", with a Cyrillic А) | Verified contacts sealed under the user's master key (E2EE §8); "key changed" blocks sharing and grants; look-alike names and emails (homoglyphs, invisible characters) are flagged | `TestContacts`, interop `classify-contacts`, browser test: impersonation and key swap flagged |
| Swapped public keys in a user's own bundle | Private keys must match the published keys on unlock; server refuses to change published keys | `TestBundleTamperingDetected`; `TestProvisioningAndKeys` |

### Tampering

| Threat | Mitigation | Evidence |
|---|---|---|
| Modified, truncated, reordered or swapped content | STREAM: per-chunk AES-GCM, chunk index and final flag in the nonce; signature over the header and a hash of all chunks | `TestContainerTampering` |
| Swapping containers between files | Key commitment in each header; containers fetched via the hierarchy must commit to the node's key | `Prefix.Keys` |
| Moving keys or names between nodes | Node IDs bound into every wrap and name AEAD | `TestNodeHierarchy` |
| Planted backup file | Restore verifies the uploader's signature and shows who signed | client `RestoreContainer`; web restore |
| Concurrency races, quota overshoot | Same-statement conditions in SQL | `TestQuotaIsAtomic` |
| SQL injection | Parameterized queries; IDs format-validated | `store/postgres` |
| Malicious or careless theme (CSS exfiltration, hidden warnings, fake UI, polyglot logo) | Themes are hex color tokens only, never CSS; stylesheet generated server-side; CSP unchanged; WCAG contrast enforced for every mode and accent; fail closed at startup and before a web save; logos re-encoded to PNG, SVG refused, pixel bound checked before decode; web editing needs a recent re-authentication and can be locked by configuration | `TestThemeRejected`, `TestCSSIsInert`, `TestSanitizeLogo`, `TestThemeEndpoints` |
| Stolen server backup (database dump, data volume, logs) | Contents, names and keys are end-to-end encrypted; tokens and link passwords are hashes; link secrets are never stored; the server refuses key bundles below the PBKDF2 work factor, so offline guessing stays expensive; backups should still be encrypted (metadata, key bundles) | `TestDisasterRecovery` (scans a full backup for plaintext in raw/hex/base64), `TestWeakKeyBundlesRefused` |
| A restore silently brings back revoked sessions, links or members | Runbook step: `revoke-sessions --all` and re-apply later revocations from the audit log | [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md) §7 |
| Backup incomplete or corrupted, discovered only when needed | `verify-storage --hash` checks presence, size and SHA-256 of every stored ciphertext without keys | `TestVerifyStorage` |
| Leaked or abused public links at scale | Per-user and instance-wide kill switches revoke links in one SQL statement; the global web switch needs an admin *session* (not an app password) and a typed confirmation; per-user and global revocation are separate store methods, so no input can widen one into the other; `frontdir revoke-links` works without the web UI | `TestSharedByMeAndLinkKillSwitches`, e2e |
| Departed or compromised user keeps access through existing sessions or app passwords | `frontdir revoke-access` ends sessions, deletes app passwords and revokes links; the IdP blocks new sign-ins | e2e "operator offboarding" |
| CSRF | Go `CrossOriginProtection`, `SameSite=Lax` sessions, Host validation; the SAML ACS is exempt because it is authenticated by signature plus single-use binding | e2e |
| Bad settings saved from the web (typos, contradictions, lockouts) | One validator for environment and web values; sign-in changes tried against the IdP before saving; changes refused that would exclude or demote the administrator making them or switch sign-in off; optimistic concurrency between administrators; saved settings that stop validating stop startup rather than being skipped (skipping "allowed groups" would fail open); `frontdir settings reset` and `setup-link` as break-glass | `TestBuildRejectsWithFieldErrors`, `TestUpdateRules`, `TestAdminGroupsApplyImmediatelyAndGuardSelf` |

### Repudiation

Containers, shares, grants and trash seals are signed by their author's Ed25519 key, so a client
can attribute content and grants cryptographically. The server additionally logs structured audit
events (identifiers only; never names, tokens or passwords).

### Information disclosure

| Threat | Mitigation | Evidence |
|---|---|---|
| Server operator / database dump reads files or names | End-to-end encryption; server holds only wrapped/sealed keys | `TestE2EEFileLifecycle`, e2e "server holds only ciphertext" |
| Stolen volume or backup | Containers are ciphertext under random names; backups are ID-named | `frontdir-cli backup` smoke test |
| Offline guessing of a passphrase from the stored bundle | PBKDF2-SHA256, 600k iterations; 12-character minimum; the recovery code has 160 bits | `e2ee/account.go` |
| Horizontal access | Single authorization point; whole-chain checks; 404 for invisible items | `TestTenantIsolation` |
| Link leaks to servers or logs | Link secret only in the URL fragment; token only in POST bodies; `Referrer-Policy: no-referrer` | e2e "public link" |
| Stored XSS via uploads | The server only serves opaque containers as sandboxed attachments; the browser decrypts into a download | `serveContainer` |
| XSS in the web client (would expose in-memory keys) | CSP `script-src 'self'`, Trusted Types enforced (one policy, `frontdir-sw`, that can only produce the download worker's constant URL), DOM-only rendering, private keys non-extractable | `ui.go`, `app.js`, `TestThemeEndpoints` |
| Decrypted downloads rendered as a page in the app's origin | The download worker's responses are `attachment`, `application/octet-stream`, `nosniff`, `sandbox` CSP and `no-store`; the worker's scope is `/dl/` only, it fetches nothing, and each download id is random, single use and short-lived | `web/static/dl/sw.js`, browser test |
| Streaming releases plaintext before the signature is checked | Each chunk is AES-GCM-authenticated before release; the last chunk is withheld until the signature verifies, and a failure aborts the download (the browser discards it) or fails the copy from the drive | `TestStreamingVerifier`, interop `container-stream-*`, `TestDecryptingGateway` |
| The local drive (`frontdir-cli mount`) exposes plaintext to other users of the computer, to web pages, or to the network | Loopback only, with no option otherwise; a random 256-bit token in every path; loopback `Host` required (DNS rebinding) and browser requests (`Origin`, `Sec-Fetch-Site`) refused; inert response headers; upload buffers that spill to disk are encrypted under a key held in memory | `TestDecryptingGateway`, `TestListenIsLoopbackOnly`, `TestSpoolSpillsEncrypted` |
| Clickjacking / XS-leaks | `frame-ancestors 'none'`, COOP/CORP | middleware |
| Server-side request forgery through IdP URLs entered on the web (reaching cloud metadata or internal services, reading their responses) | All IdP traffic uses one client that refuses link-local, metadata, unspecified, multicast and (except on localhost deployments) loopback addresses, checked before sending and again on the address actually dialled (DNS rebinding); 1 MiB response cap, 20 s timeout, at most three redirects and never https→http; errors describe the failure and never echo the response | `TestIdPClientRefusesInternalAddresses`, `TestIdPChecksNeverEchoTheRemote` |
| OIDC client secret in a database dump | Secrets saved on the web are AES-256-GCM encrypted under a key that lives only in the server's environment, bound to the setting name; never returned by the API or logged | `TestSecretBox`, `TestSignInChangesAreCheckedAndConfirmed` |

### Denial of service

Atomic quotas (counted on stored, encrypted bytes) and maximum file size; streaming uploads with
idle deadlines; bounded JSON and header sizes; folder depth limit; per-IP rate limits on sign-in,
public and failed-auth paths; bounded KDF parameters when parsing stored bundles and hashes.

### Elevation of privilege

| Threat | Mitigation | Evidence |
|---|---|---|
| Read-only credential writes | Capped at read in authorization | `TestReadOnlyAndCycles` |
| App password replaces keys or mints credentials | Key setup/changes and credential management require an interactive session | e2e "credential scoping" |
| Non-admin maps groups to team folders | Admin check on every mapping change | `TestTeamFolders`, e2e |
| An administrator entrenches themselves, or the last one locks everyone out | Nobody changes their own administrator appointment or demotes themselves through the administrator groups; removing a group applies to everyone at once | `TestAdminGroupsApplyImmediatelyAndGuardSelf` |
| Team left without a key holder | Last key-holding manager cannot leave or be demoted | `TestTeamFolders` |
| Container escape impact | Distroless, non-root, read-only FS, no capabilities, seccomp | `Dockerfile`, `deploy/` |
| Supply chain | Small dependency set; pinned CI actions; govulncheck, gosec, staticcheck, Trivy; Dependabot | `.github/` |

## Residual risks and accepted trade-offs

1. **Trust in the key directory.** Clients fetch other users' public keys from the server. A
   malicious server could substitute keys when you share with someone (as with any E2EE system
   lacking key transparency). Mitigation: compare fingerprints out of band (shown in Settings and
   when sharing). Roadmap: key transparency / pinned contacts.
2. **Malicious server serving malicious JavaScript.** Browser E2EE trusts the code the server sends.
   An operator who modifies `app.js` could exfiltrate keys from future sessions. The CLI does not
   have this weakness. Mitigations: the code is embedded in a reproducible binary, and CSP limits
   third-party injection, but this is inherent to web-delivered E2EE.
3. **Metadata.** Tree shape, sizes (to within padding and chunk granularity), timestamps, who
   uploaded what, sharing relationships and team memberships are visible to the server.
4. **Revocation is access control, not re-encryption.** Removing someone from a share or team stops
   them fetching ciphertext immediately, but keys they already received remain valid for content
   they could already read. Team key rotation on member removal is on the roadmap.
5. **No recovery without the user.** Losing both passphrase and recovery code loses the data, by
   design; administrators cannot help. Users should keep the recovery code and key backup safe.
6. **Group members wait for a key.** Members who join through IdP groups are authorized at once
   but can decrypt only after a manager's client grants the team key.
7. **Passphrase strength.** PBKDF2 (chosen because browsers implement it natively) is less
   memory-hard than Argon2id; long passphrases matter. Passkey-based unlock is on the roadmap.
8. **Public links can carry their key.** Whoever has the full link URL can decrypt the shared item
   until it expires or is revoked; link passwords add a server-enforced gate on top.
9. **Per-replica rate limits and WebDAV locks.** See ARCHITECTURE.md › Scaling.
8. **Administrators can redirect sign-in.** An administrator who passes "confirm it's you" can
   point FrontDir at another identity provider. That cannot take over existing accounts or
   decrypt anything, but people who then sign in through the new provider get new accounts, and
   its groups decide who administers from then on. Lock sign-in to the server's configuration
   (`FRONTDIR_OIDC_ISSUER` / `FRONTDIR_SAML_IDP_METADATA_URL`, or `FRONTDIR_WEB_SETTINGS=false`)
   where that is a concern; changes are audited either way.
9. **The database is trusted for settings.** Anyone who can write to the database can change
   settings directly, as they could change any other metadata. Settings are not signed; the
   end-to-end encryption, not the settings, protects file contents from such an attacker.
10. **Identity providers on private networks are reachable.** So that an IdP on the same Docker
   network works, administrators can make the server send GET requests to private addresses.
   The responses are never shown, only whether the check passed.
11. **The local drive holds unlocked keys and serves plaintext for as long as it runs.** Anyone who
   can act as the user on that computer can read what the drive shows (as they could read files
   the user had downloaded). Stop it (Ctrl+C) when it is not needed. The drive's address is a
   secret; `--url-file` keeps it in a file readable only by the user.
