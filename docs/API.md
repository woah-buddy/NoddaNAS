# HTTP API

JSON in, JSON out unless noted. Everything that would reveal content (names, keys, file bytes) is
client-encrypted per [E2EE.md](E2EE.md); the server treats those fields as opaque, validated only
for shape and size. `internal/client` is a complete reference client.

**Authentication.** Browsers use the session cookie from sign-in. Other clients use an app password:
`Authorization: Bearer fd_...` (or HTTP Basic, any username). *session* = interactive session only.

**Errors**

```json
{"error": {"code": "not_found", "message": "...", "detail": {}, "requestId": "4d65d1f784238af0"}}
```

| Code | Status | Meaning |
|---|---|---|
| `invalid` | 400 | Bad input (including a malformed container or opaque field) |
| `unauthorized` | 401 | Not signed in / bad credentials / link password needed |
| `forbidden` | 403 | You can see the item but lack the needed permission or role |
| `reauth_required` | 403 | An administrative change needs a recent sign-in: send the browser to `/auth/reauth` |
| `not_found` | 404 | Does not exist **or you cannot see it** |
| `conflict` | 409 | Name hash taken (`detail.existingId`, `detail.existingKind`) |
| `confirm_required` | 409 | Repeat the request with `detail.confirm` added to its `confirm` list, after showing `message` to the person |
| `gone` | 410 | Link expired or download limit reached |
| `precondition` | 412 | Revision mismatch, or a prerequisite (e.g. recipient has no keys) |
| `too_large` | 413 | Over the size limit |
| `rate_limited` | 429 | Slow down / link locked |
| `quota_exceeded` | 507 | Not enough quota in the space |

IDs (nodes, spaces, shares) are 32 lowercase hex characters; clients choose node, space and share
IDs because they are bound into the encryption.

## Sign-in

| Method & path | |
|---|---|
| `GET /api/v1/auth/methods` | `{"oidc": bool, "saml": bool, "setup": bool}`; `setup` is true when no method is configured yet |
| `GET /auth/login?return_to=/path` | OIDC sign-in |
| `GET /auth/saml/login?return_to=/path` | SAML sign-in (SP-initiated) |
| `POST /auth/saml/acs` | SAML assertion consumer (HTTP-POST binding) |
| `GET /auth/saml/metadata` | SP metadata for your IdP |
| `POST /auth/logout` | Ends the session; returns `{"logoutUrl"}` (OIDC RP-initiated logout) |
| `GET /auth/reauth?return_to=/path` | *session*. "Confirm it's you": sign in again at the IdP (forced), through the method the account uses; the new session counts as a recent sign-in for 15 minutes |

**First-time setup** with the link from `frontdir setup-link` (the token is the URL fragment; send
it only in request bodies):

| Method & path | |
|---|---|
| `POST /api/v1/setup/view` | `{"token"}` → the sign-in settings, as in `GET /api/v1/admin/settings` |
| `POST /api/v1/setup/save` | `{"token","revision","set","confirm"}`: change sign-in and access settings only |
| `POST /api/v1/setup/login` | `{"token","method":"oidc"\|"saml"}` → `{"redirect"}` and the sign-in cookie. Completing that sign-in makes the person an administrator and spends the token. |

## Account and keys

| Method & path | |
|---|---|
| `GET /api/v1/me` | User (incl. public keys, admin flag) and personal space |
| `GET /api/v1/keys` | Your encrypted key bundle `{"bundle": "<json>"}` |
| `POST /api/v1/keys` | *session*. First-time setup: `{"bundle", "personalSpace": {"publicKey","keySig","rootKey"}}` |
| `PUT /api/v1/keys` | *session*. Replace the bundle (e.g. new passphrase); public keys must be unchanged |
| `GET /api/v1/users/{id}/keys` | A user's public keys and display name |
| `GET /api/v1/users/lookup?email=` | Find a user by verified email |
| `GET /api/v1/contacts` | Your sealed verified-contacts list (E2EE §8): `{"contacts": "<base64url or empty>", "revision": n}` |
| `PUT /api/v1/contacts` | `{"contacts", "revision"}` replaces it if `revision` is still current, and returns `{"revision"}`; 412 if another device saved first. Not available to read-only credentials. |
| `GET/POST /api/v1/app-passwords`, `DELETE /api/v1/app-passwords/{id}` | *session* |
| `POST /api/v1/sessions/revoke-all` | *session* |

## Spaces and team folders

| Method & path | |
|---|---|
| `GET /api/v1/spaces` | Personal space and team folders, each with your `role` and `myGrant` |
| `POST /api/v1/spaces` | Create a team folder: `{"id","rootId","nameEnc","keys":{"publicKey","keySig","rootKey"},"grant","grantSig"}` |
| `GET / PATCH / DELETE /api/v1/spaces/{id}` | Get; rename `{"nameEnc"}` (manage); delete (manage, permanent) |
| `GET /api/v1/spaces/{id}/members` | Members with direct role, group roles, effective role, `hasGrant` |
| `PUT /api/v1/spaces/{id}/members/{user}` | (manage) `{"role"}` to add/change a direct member; `{"grant","grantSig"}` to grant the key |
| `DELETE /api/v1/spaces/{id}/members/{user}` | (manage, or yourself to leave) |
| `GET /api/v1/spaces/{id}/groups` | Group mappings |
| `PUT / DELETE /api/v1/spaces/{id}/groups/{group}` | (admin) `{"role"}` |
| `PUT /api/v1/spaces/{id}/quota` | (admin, recent sign-in) `{"bytes"}` |
| `GET /api/v1/admin/spaces` | (admin) all team folders |
| `GET / DELETE /api/v1/spaces/{id}/trash` | List (write) / empty (manage) |

## Files and folders

| Method & path | |
|---|---|
| `GET /api/v1/nodes/{id}` | Node, your permission, `canModify` |
| `GET /api/v1/nodes/{id}/path` | Key-derivation path: `space` (with `rootKey`/`myGrant` if you are a member), optional entry `share`, and `nodes` from the entry point down |
| `GET /api/v1/nodes/{id}/children?limit=&cursor=` | Children with `nameEnc`, `wrappedKey`; follow `nextCursor` |
| `POST /api/v1/nodes/{id}/folders` | `{"id","nameEnc","nameHash","wrappedKey"}` |
| `POST /api/v1/nodes/{id}/files` | Body: container. Header `X-FrontDir-Entry: {"id","nameEnc","nameHash","wrappedKey"}` |
| `PUT /api/v1/nodes/{id}/content?revision=` | New version; body: container (same node key) |
| `GET /api/v1/nodes/{id}/content?version=` | The container (Range supported) |
| `PATCH /api/v1/nodes/{id}` | Rename `{"nameEnc","nameHash"}`; move also `{"parentId","wrappedKey"}`; optional `revision` |
| `POST /api/v1/nodes/{id}/trash` | `{"restoreKey","restoreSig","revision"?}` |
| `GET /api/v1/nodes/{id}/versions`, `POST .../versions/{vid}/restore` | |
| `POST /api/v1/trash/{id}/restore` | `{"parentId","nameEnc","nameHash","wrappedKey"}` |
| `DELETE /api/v1/trash/{id}` | Delete permanently (manage; asynchronous) |

## Sharing

| Method & path | |
|---|---|
| `GET /api/v1/nodes/{id}/shares` | (full control) |
| `POST /api/v1/nodes/{id}/shares` | User: `{"type":"user","shareId","recipientId","permission","sealedKey","sig"}`. Link: `{"type":"link","shareId","linkKey","password"?,"expiresAt"?,"maxDownloads"?}` → `token`, `urlPrefix` (append `.` + base64url link secret) |
| `DELETE /api/v1/shares/{id}` | Revoke (owner/manager/creator) or leave (recipient) |
| `GET /api/v1/shared-with-me` | Shares made with you, with sealed keys |
| `GET /api/v1/shared-by-me` | Shares you created (`items[].share` with `status`: `active`, `expired`, `exhausted` or `locked`; `items[].node`, or null if you can no longer see the item), plus `truncated`. No key material. |
| `POST /api/v1/links/revoke-all` | Kill switch: revoke every public link you created → `{"revoked": n}` (not with read-only credentials) |
| `POST /api/v1/admin/links/revoke-all` | *session*, admin, recent sign-in. Revoke every public link on the server → `{"revoked": n}` |

## Public links (anonymous; token in the body, key never sent)

| Method & path | |
|---|---|
| `POST /api/v1/public/node` | `{"token","password"?,"nodeId"?,"cursor"?}` → `link` (with `linkKey`), `path`, `children` |
| `POST /api/v1/public/download` | Same body → the container |
| `POST /api/v1/public/signer` | `{"token","password"?,"userId"}` → that user's public keys (to verify signatures) |

## WebDAV (read-only ciphertext, for backups)

`/dav/` with an app password: `/dav/<spaceId>/` contains `_frontdir-space.json`,
`_frontdir-folder.json`, subfolders by ID and `<fileId>.fdenc` containers. Write methods return 405.

## Administration

All *session* and administrators only. Changes need a recent sign-in (`reauth_required` otherwise).

| Method & path | |
|---|---|
| `GET /api/v1/admin/session` | `{"recent": bool, "recentUntil", "window"}` |
| `GET /api/v1/admin/settings` | `{"revision","readOnly","canStoreSecrets","setupMode","groups":[{"id","label","fromServer"}],"fields":[{"key","group","kind","label","help","default","value","isSet","source","locked","env"}],"signIn":{"oidcRedirectUri","samlMetadataUrl","samlAcsUrl"}}`. Secrets and the logo have an empty `value`; `isSet` says whether one is set. `source` is `server`, `web` or `default`. |
| `PUT /api/v1/admin/settings` | `{"revision","set":{"KEY":"value"},"confirm":[]}`. An empty value returns a setting to its default (or clears a secret); keys left out are unchanged. The logo is base64 of a PNG or JPEG. Problems come back as `invalid` with `detail` mapping each key to a message; 412 if someone else saved first. Body limit 2 MiB. |
| `GET /api/v1/admin/users?q=` | Up to 200 accounts: `{"users":[{"id","displayName","email","signIn","admin","adminGranted","keysSetUp","quotaBytes","usedBytes","createdAt"}]}` |
| `PUT /api/v1/admin/users/{id}/admin` | `{"admin": bool}` appoints or removes an administrator (not yourself) |
| `PUT /api/v1/admin/users/{id}/quota` | `{"size": "20GiB"}` sets personal storage |
| `POST /api/v1/admin/users/{id}/revoke-access` | Ends the person's sessions and deletes their app passwords |
| `POST /api/v1/admin/sessions/revoke-all` | Signs everyone out, including you |
| `POST /api/v1/admin/links/revoke-all` | Revokes every public link |

## Theming (public)

| Method & path | |
|---|---|
| `GET /api/v1/branding` | `{"name","logo": bool,"defaultAccent","accents":[{"id","label"}]}` |
| `GET /theme.css` | Generated stylesheet (`ETag`, revalidated) |
| `GET /branding/logo` | Re-encoded PNG logo, or 404 |

## Health

`GET /healthz` (204) and `GET /readyz` (204 or 503).
