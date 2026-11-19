# Security policy

FrontDir is built secure-by-design first; see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for
what it defends against and the risks it accepts.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability
reporting ("Report a vulnerability" under the repository's Security tab). Include steps to
reproduce, affected version or commit, and impact. You should receive an acknowledgement within
a few days.

## Supported versions

Only the latest release (or the `main` branch before the first release) receives security fixes.

## Design rules for contributors

Changes are reviewed against these rules; a pull request that breaks one needs a very good reason
and an update to the threat model.

1. All authorization goes through `internal/service/access.go`. Transports never touch storage.
2. Untrusted strings become trusted values only in `internal/validate`.
3. New API responses use explicit view structs; never encode a domain or storage struct directly.
4. Secrets (tokens, passwords, keys) are never logged and are stored only as hashes or wrapped.
5. Database rules that protect integrity are enforced in SQL (constraint or same-statement
   condition), not only in Go.
6. No new runtime dependency without a clear need; prefer the standard library and `golang.org/x`.
7. Every security property gets a test that would fail if it regressed.
8. The server never receives plaintext content, names or usable keys. Any change to what clients
   encrypt goes through [docs/E2EE.md](docs/E2EE.md) first, then into **both** implementations
   (`internal/e2ee` and `web/static/e2ee.js`), and the interoperability test must pass.
9. Every key a client accepts from the server is authenticated: by an AEAD binding to its node or
   space, a key commitment, or a signature from the user who granted it.
10. SAML changes keep: signatures required, SP-initiated only, single-use request binding,
    HTTP-POST binding only.
11. Theming stays data, not code: allowlisted tokens with strict value grammars, stylesheets
    generated server-side, no CSP exceptions, contrast checked, images re-encoded
    ([docs/THEMING.md](docs/THEMING.md)).
12. Bulk or destructive operations get one code path per scope (a user's links vs. every link):
    an empty or missing identifier must never widen the scope. Instance-wide actions require an
    administrator's interactive session, and each has a shell equivalent for break-glass use.
13. A known vulnerability is never silenced. If govulncheck reports one that does not affect us
    (for example a stale advisory record), add an entry to `.github/govulncheck-exceptions.json`
    naming the exact advisory and module, with the evidence and an expiry at most 90 days away.
    `tools/vulngate` enforces all of this and fails when an exception expires.
14. Clients never grant a key, or extend trust, because the server says so. Membership lists,
    names and emails are the server's claims: a key grant needs an explicit decision by a person
    who has been shown the recipient's fingerprint, and identity comes only from fingerprints the
    user verified (E2EE.md §3 and §8).
15. Settings have one validator (`config.Build`) for every source, environment or web. A setting
    an administrator can change on the web is listed in `config.Registry`; what only the server's
    operator should decide (addresses, storage, keys, TLS, proxies) stays out of it. Every change
    in the admin area needs `service.RequireFreshAdmin` (a recent re-authentication), and saved
    settings that stop validating stop startup instead of being skipped.
16. The server makes outbound requests only to identity providers, only through
    `auth.NewIdPClient`, and never shows what came back (only what failed).
