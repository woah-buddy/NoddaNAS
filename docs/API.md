# HTTP API

All endpoints are under the instance's public origin. JSON in, JSON out, unless noted.

**Authentication.** Browsers use the session cookie set by `/auth/login`. Scripts and other
clients use an app password: `Authorization: Bearer ndn_...` (or HTTP Basic with any username).
Endpoints marked *session* refuse app passwords.

**Errors** look like:

```json
{"error": {"code": "not_found", "message": "...", "detail": {}, "requestId": "4d65d1f784238af0"}}
```

| Code | Status | Meaning |
|---|---|---|
| `invalid` | 400 | Bad input |
| `unauthorized` | 401 | Not signed in, or bad credentials |
| `forbidden` | 403 | You can see the item but lack the needed permission |
| `not_found` | 404 | Does not exist **or you cannot see it** (indistinguishable by design) |
| `conflict` | 409 | Name already taken (`detail.existingId` when it is a file you can see) |
| `gone` | 410 | Link expired or download limit reached |
| `precondition` | 412 | Revision mismatch: someone else changed the item |
| `too_large` | 413 | Over the size limit |
| `rate_limited` | 429 | Slow down / link locked |
| `quota_exceeded` | 507 | Not enough quota |

Nodes carry a `revision`. Pass it back on changes (`revision` field or query parameter) to get
optimistic-concurrency protection; omit it to apply the change to whatever is current.

## Sign-in

| Method & path | Notes |
|---|---|
| `GET /auth/login?return_to=/path` | Starts OIDC sign-in. `return_to` must be a same-site path. |
| `GET /auth/callback` | OIDC redirect target. |
| `POST /auth/logout` | Ends the session. Returns `{"logoutUrl": "..."}` for IdP sign-out. |

## Account

| Method & path | Notes |
|---|---|
| `GET /api/v1/me` | Profile, root folder ID, quota, whether the credential is read-only |
| `GET /api/v1/app-passwords` | *session* |
| `POST /api/v1/app-passwords` | *session*. `{"name", "readOnly", "expiresInDays"}` → `{"appPassword", "token"}` (token shown once) |
| `DELETE /api/v1/app-passwords/{id}` | *session* |
| `POST /api/v1/sessions/revoke-all` | *session*. Signs out every browser session |

## Files and folders

| Method & path | Notes |
|---|---|
| `GET /api/v1/nodes/{id}` | Node plus your `permission` and `canModify` |
| `GET /api/v1/nodes/{id}/children?limit=&cursor=` | Folder listing; follow `nextCursor` |
| `POST /api/v1/nodes/{id}/folders` | `{"name"}` |
| `POST /api/v1/nodes/{id}/upload?name=&overwrite=true` | Raw body = file content. Optional headers: `Content-Length`, `X-Content-SHA256` (hex), `Content-Type` |
| `PUT /api/v1/nodes/{id}/content?revision=` | New version of an existing file; raw body |
| `GET /api/v1/nodes/{id}/content?version=&inline=1` | Download (Range supported). `inline=1` only affects images/audio/video |
| `PATCH /api/v1/nodes/{id}` | `{"name"?, "parentId"?, "revision"?}` rename and/or move |
| `DELETE /api/v1/nodes/{id}?revision=` | Move to trash |
| `GET /api/v1/nodes/{id}/versions` | Newest first |
| `POST /api/v1/nodes/{id}/versions/{versionId}/restore` | Stores the old content as a new version |

Example:

```sh
TOKEN=ndn_...
ROOT=$(curl -s -H "Authorization: Bearer $TOKEN" https://files.example.com/api/v1/me | jq -r .user.rootId)
curl -H "Authorization: Bearer $TOKEN" \
     -H "X-Content-SHA256: $(sha256sum report.pdf | cut -d' ' -f1)" \
     --data-binary @report.pdf \
     "https://files.example.com/api/v1/nodes/$ROOT/upload?name=report.pdf"
```

## Trash

| Method & path | Notes |
|---|---|
| `GET /api/v1/trash` | Your trashed items with `expiresAt` |
| `POST /api/v1/trash/{id}/restore` | Optional `{"name"}` to resolve a name clash |
| `DELETE /api/v1/trash/{id}` | Delete permanently (asynchronous, 202) |
| `DELETE /api/v1/trash` | Empty the trash |

## Sharing

| Method & path | Notes |
|---|---|
| `GET /api/v1/nodes/{id}/shares` | Owner only |
| `POST /api/v1/nodes/{id}/shares` | `{"type":"user","email","permission":"read"\|"write"}` or `{"type":"link","password"?,"expiresAt"?,"maxDownloads"?}`. Link responses include `token` and `url`, shown once |
| `DELETE /api/v1/shares/{id}` | Owner revokes, or recipient leaves |
| `GET /api/v1/shared-with-me` | |

## Public links (anonymous)

The token goes in the request body, never the URL.

| Method & path | Notes |
|---|---|
| `POST /api/v1/public/node` | `{"token","password"?,"nodeId"?,"cursor"?}` → node, plus children for folders |
| `POST /api/v1/public/download` | Form-encoded `token`, `password`, `nodeId` → file as attachment |

## WebDAV

`/dav/` with HTTP Basic auth (any username, app password). Supports `PROPFIND`, `GET`, `PUT`,
`MKCOL`, `MOVE`, `DELETE` (to trash), `LOCK`/`UNLOCK`.

## Health

`GET /healthz` (liveness, 204) and `GET /readyz` (dependencies, 204 or 503).
