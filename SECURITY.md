# Security policy

NoddaNAS is built secure-by-design first; see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for
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
