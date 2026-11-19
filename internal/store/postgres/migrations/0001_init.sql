-- FrontDir schema v1 (end-to-end encrypted).
--
-- The server stores no plaintext names and no usable keys: names are
-- client-encrypted (name_enc) with a client-computed keyed hash for
-- uniqueness (name_hash), and every key is wrapped, sealed or signed by
-- clients (see docs/E2EE.md). Integrity rules still live here as
-- constraints, so a bug in one code path cannot quietly break them:
--   * a live name hash is unique within a folder;
--   * public links can only ever grant read access;
--   * a node with stored versions cannot be deleted (quota stays accurate);
--   * bearer secrets are stored only as hashes.

CREATE TABLE users (
    id                text PRIMARY KEY,
    issuer            text NOT NULL,
    subject           text NOT NULL,
    email             text,
    display_name      text NOT NULL DEFAULT '',
    is_admin          boolean NOT NULL DEFAULT false,
    personal_space_id text NOT NULL,
    -- E2EE public keys (immutable once set) and the opaque key bundle.
    enc_pub           text,
    sig_pub           text,
    self_sig          text,
    key_bundle        text,
    created_at        timestamptz NOT NULL,
    UNIQUE (issuer, subject),
    CHECK ((enc_pub IS NULL) = (key_bundle IS NULL))
);
CREATE UNIQUE INDEX users_email_key ON users (email) WHERE email IS NOT NULL;

CREATE TABLE user_groups (
    user_id    text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    group_name text NOT NULL,
    PRIMARY KEY (user_id, group_name)
);
CREATE INDEX user_groups_group ON user_groups (group_name);

CREATE TABLE spaces (
    id            text PRIMARY KEY,
    kind          text NOT NULL CHECK (kind IN ('personal', 'team')),
    owner_user_id text REFERENCES users (id) ON DELETE CASCADE,
    root_id       text NOT NULL,
    name_enc      text NOT NULL DEFAULT '',
    public_key    text,
    key_sig       text,
    key_signer    text,
    root_key      text,
    quota_bytes   bigint NOT NULL CHECK (quota_bytes >= 0),
    used_bytes    bigint NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    created_at    timestamptz NOT NULL,
    created_by    text NOT NULL,
    deleted_at    timestamptz,
    delete_lease  timestamptz,
    CHECK ((kind = 'personal') = (owner_user_id IS NOT NULL)),
    CHECK ((public_key IS NULL) = (root_key IS NULL))
);
CREATE UNIQUE INDEX spaces_personal ON spaces (owner_user_id) WHERE kind = 'personal';
CREATE INDEX spaces_deleted ON spaces (delete_lease NULLS FIRST) WHERE deleted_at IS NOT NULL;

-- Direct members (role set) and holders of a key grant. Members who come
-- only through a group mapping get a row once a manager grants them the key.
CREATE TABLE space_members (
    space_id   text NOT NULL REFERENCES spaces (id) ON DELETE CASCADE,
    user_id    text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       text CHECK (role IN ('read', 'write', 'manage')),
    grant_key  text,
    grant_sig  text,
    granted_by text,
    added_at   timestamptz NOT NULL,
    PRIMARY KEY (space_id, user_id),
    CHECK ((grant_key IS NULL) = (grant_sig IS NULL))
);
CREATE INDEX space_members_user ON space_members (user_id);

-- Identity-provider group to team-space mappings (admin-managed).
CREATE TABLE space_groups (
    space_id   text NOT NULL REFERENCES spaces (id) ON DELETE CASCADE,
    group_name text NOT NULL,
    role       text NOT NULL CHECK (role IN ('read', 'write', 'manage')),
    PRIMARY KEY (space_id, group_name)
);
CREATE INDEX space_groups_group ON space_groups (group_name);

CREATE TABLE nodes (
    id          text PRIMARY KEY,
    space_id    text NOT NULL REFERENCES spaces (id) ON DELETE CASCADE,
    parent_id   text REFERENCES nodes (id) ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('file', 'folder')),
    name_enc    text NOT NULL,
    name_hash   text COLLATE "C" NOT NULL,
    wrapped_key text,
    size        bigint NOT NULL DEFAULT 0 CHECK (size >= 0),  -- stored (encrypted) bytes
    plain_size  bigint NOT NULL DEFAULT 0 CHECK (plain_size >= 0), -- from the container header
    sha256      text NOT NULL DEFAULT '',
    version_id  text,
    created_at  timestamptz NOT NULL,
    created_by  text NOT NULL,
    modified_at timestamptz NOT NULL,
    modified_by text NOT NULL,
    revision    bigint NOT NULL DEFAULT 1,
    trashed_at  timestamptz,
    trashed_by  text,
    restore_key text,
    restore_sig text,
    purging     boolean NOT NULL DEFAULT false,
    purge_lease timestamptz,
    CHECK (parent_id IS NOT NULL OR kind = 'folder'),
    CHECK (parent_id IS NOT NULL OR trashed_at IS NULL),
    CHECK ((parent_id IS NULL) = (wrapped_key IS NULL)),
    CHECK (NOT purging OR trashed_at IS NOT NULL),
    CHECK ((trashed_at IS NULL) = (restore_key IS NULL))
);
CREATE UNIQUE INDEX nodes_live_name ON nodes (parent_id, name_hash) WHERE trashed_at IS NULL;
CREATE INDEX nodes_trash ON nodes (space_id, trashed_at) WHERE trashed_at IS NOT NULL;
CREATE INDEX nodes_purge ON nodes (purge_lease NULLS FIRST) WHERE purging;
CREATE INDEX nodes_space ON nodes (space_id);

-- Each version is one self-contained, client-encrypted container.
CREATE TABLE versions (
    id         text PRIMARY KEY,
    node_id    text NOT NULL REFERENCES nodes (id) ON DELETE RESTRICT,
    space_id   text NOT NULL,
    blob_key   text NOT NULL UNIQUE,
    size       bigint NOT NULL CHECK (size >= 0),
    sha256     text NOT NULL,
    created_at timestamptz NOT NULL,
    created_by text NOT NULL
);
CREATE INDEX versions_node ON versions (node_id, created_at DESC);
CREATE INDEX versions_space ON versions (space_id);

CREATE TABLE shares (
    id              text PRIMARY KEY,
    kind            text NOT NULL CHECK (kind IN ('user', 'link')),
    node_id         text NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    space_id        text NOT NULL REFERENCES spaces (id) ON DELETE CASCADE,
    created_by      text NOT NULL,
    permission      text NOT NULL CHECK (permission IN ('read', 'write')),
    created_at      timestamptz NOT NULL,
    recipient_id    text REFERENCES users (id) ON DELETE CASCADE,
    sealed_key      text,
    share_sig       text,
    token_hash      text UNIQUE,
    link_key        text,
    password_hash   text NOT NULL DEFAULT '',
    expires_at      timestamptz,
    max_downloads   bigint NOT NULL DEFAULT 0 CHECK (max_downloads >= 0),
    downloads       bigint NOT NULL DEFAULT 0,
    failed_attempts bigint NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    CHECK ((kind = 'user') = (recipient_id IS NOT NULL AND sealed_key IS NOT NULL AND share_sig IS NOT NULL)),
    CHECK ((kind = 'link') = (token_hash IS NOT NULL AND link_key IS NOT NULL)),
    CHECK (kind = 'user' OR permission = 'read'),
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

-- In-flight sign-ins (OIDC state/nonce/PKCE, or a SAML AuthnRequest ID).
CREATE TABLE login_requests (
    token_hash    text PRIMARY KEY,
    kind          text NOT NULL CHECK (kind IN ('oidc', 'saml')),
    state         text NOT NULL,
    nonce         text NOT NULL,
    pkce_verifier text NOT NULL,
    return_to     text NOT NULL,
    expires_at    timestamptz NOT NULL
);
CREATE INDEX login_requests_expiry ON login_requests (expires_at);
