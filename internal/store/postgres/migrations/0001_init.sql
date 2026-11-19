-- NoddaNAS schema v1.
--
-- Integrity rules live here as constraints, not only in application code, so
-- a bug in one code path cannot quietly break them:
--   * a live name is unique within a folder (case-insensitive name_key);
--   * public links can only ever grant read access;
--   * a node with stored versions cannot be deleted (quota stays accurate);
--   * bearer secrets are stored only as hashes.

CREATE TABLE users (
    id           text PRIMARY KEY,
    issuer       text NOT NULL,
    subject      text NOT NULL,
    email        text,
    display_name text NOT NULL DEFAULT '',
    root_id      text NOT NULL,
    quota_bytes  bigint NOT NULL CHECK (quota_bytes >= 0),
    used_bytes   bigint NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    created_at   timestamptz NOT NULL,
    UNIQUE (issuer, subject)
);
CREATE UNIQUE INDEX users_email_key ON users (email) WHERE email IS NOT NULL;

CREATE TABLE nodes (
    id           text PRIMARY KEY,
    owner_id     text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    parent_id    text REFERENCES nodes (id) ON DELETE CASCADE,
    name         text NOT NULL,
    name_key     text COLLATE "C" NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('file', 'folder')),
    size         bigint NOT NULL DEFAULT 0 CHECK (size >= 0),
    content_type text NOT NULL DEFAULT '',
    sha256       text NOT NULL DEFAULT '',
    version_id   text,
    created_at   timestamptz NOT NULL,
    modified_at  timestamptz NOT NULL,
    modified_by  text NOT NULL,
    revision     bigint NOT NULL DEFAULT 1,
    trashed_at   timestamptz,
    purging      boolean NOT NULL DEFAULT false,
    purge_lease  timestamptz,
    CHECK (parent_id IS NOT NULL OR kind = 'folder'),
    CHECK (parent_id IS NOT NULL OR trashed_at IS NULL),
    CHECK (NOT purging OR trashed_at IS NOT NULL)
);
CREATE UNIQUE INDEX nodes_live_name ON nodes (parent_id, name_key) WHERE trashed_at IS NULL;
CREATE INDEX nodes_trash ON nodes (owner_id, trashed_at) WHERE trashed_at IS NOT NULL;
CREATE INDEX nodes_purge ON nodes (purge_lease NULLS FIRST) WHERE purging;

CREATE TABLE versions (
    id          text PRIMARY KEY,
    node_id     text NOT NULL REFERENCES nodes (id) ON DELETE RESTRICT,
    owner_id    text NOT NULL,
    blob_key    text NOT NULL UNIQUE,
    wrapped_key text NOT NULL,
    size        bigint NOT NULL CHECK (size >= 0),
    sha256      text NOT NULL,
    created_at  timestamptz NOT NULL,
    created_by  text NOT NULL
);
CREATE INDEX versions_node ON versions (node_id, created_at DESC);

CREATE TABLE shares (
    id              text PRIMARY KEY,
    kind            text NOT NULL CHECK (kind IN ('user', 'link')),
    node_id         text NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    owner_id        text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_by      text NOT NULL,
    permission      text NOT NULL CHECK (permission IN ('read', 'write')),
    created_at      timestamptz NOT NULL,
    recipient_id    text REFERENCES users (id) ON DELETE CASCADE,
    token_hash      text UNIQUE,
    password_hash   text NOT NULL DEFAULT '',
    expires_at      timestamptz,
    max_downloads   bigint NOT NULL DEFAULT 0 CHECK (max_downloads >= 0),
    downloads       bigint NOT NULL DEFAULT 0,
    failed_attempts bigint NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    CHECK ((kind = 'user') = (recipient_id IS NOT NULL)),
    CHECK ((kind = 'link') = (token_hash IS NOT NULL)),
    CHECK (kind = 'user' OR permission = 'read'),
    CHECK (recipient_id IS NULL OR recipient_id <> owner_id),
    UNIQUE (node_id, recipient_id)
);
CREATE INDEX shares_node ON shares (node_id);
CREATE INDEX shares_recipient ON shares (recipient_id) WHERE recipient_id IS NOT NULL;

CREATE TABLE sessions (
    token_hash   text PRIMARY KEY,
    user_id      text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expiry ON sessions (expires_at);

CREATE TABLE app_passwords (
    id           text PRIMARY KEY,
    user_id      text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         text NOT NULL,
    token_hash   text NOT NULL UNIQUE,
    read_only    boolean NOT NULL,
    created_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    expires_at   timestamptz
);
CREATE INDEX app_passwords_user ON app_passwords (user_id);

CREATE TABLE login_requests (
    token_hash    text PRIMARY KEY,
    state         text NOT NULL,
    nonce         text NOT NULL,
    pkce_verifier text NOT NULL,
    return_to     text NOT NULL,
    expires_at    timestamptz NOT NULL
);
CREATE INDEX login_requests_expiry ON login_requests (expires_at);
