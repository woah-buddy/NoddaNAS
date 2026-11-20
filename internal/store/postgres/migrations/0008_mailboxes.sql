-- File mailboxes (docs/E2EE.md §6a): links anyone can drop files into, and
-- nobody can read through. The server holds the mailbox's private key only
-- wrapped under the target folder's key, and its description only under a
-- key derived from the public key, which the server never sees.
CREATE TABLE mailboxes (
    id              text PRIMARY KEY,
    node_id         text NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    space_id        text NOT NULL REFERENCES spaces (id) ON DELETE CASCADE,
    created_by      text NOT NULL REFERENCES users (id),
    created_at      timestamptz NOT NULL,
    token_hash      text NOT NULL UNIQUE,
    box_key         text NOT NULL CHECK (length(box_key) <= 256),
    info            text NOT NULL CHECK (length(info) <= 4096),
    password_hash   text NOT NULL DEFAULT '',
    expires_at      timestamptz NOT NULL,
    max_bytes       bigint NOT NULL CHECK (max_bytes > 0),
    max_files       bigint NOT NULL CHECK (max_files > 0),
    auto_file       boolean NOT NULL DEFAULT false,
    closed_at       timestamptz,
    used_bytes      bigint NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    used_files      bigint NOT NULL DEFAULT 0 CHECK (used_files >= 0),
    failed_attempts bigint NOT NULL DEFAULT 0,
    locked_until    timestamptz
);
CREATE INDEX mailboxes_node ON mailboxes (node_id);
CREATE INDEX mailboxes_creator ON mailboxes (created_by);

-- Drops not filed yet. Their blobs must be deleted before their rows, so a
-- mailbox (or its folder) cannot be removed while drops remain: purges
-- delete drops first.
CREATE TABLE mailbox_drops (
    id         text PRIMARY KEY,
    mailbox_id text NOT NULL REFERENCES mailboxes (id) ON DELETE RESTRICT,
    space_id   text NOT NULL REFERENCES spaces (id) ON DELETE RESTRICT,
    blob_key   text NOT NULL,
    size       bigint NOT NULL CHECK (size > 0),
    plain_size bigint NOT NULL CHECK (plain_size >= 0),
    header     bytea NOT NULL CHECK (length(header) <= 16384),
    body_hash  bytea NOT NULL CHECK (length(body_hash) = 32),
    sha256     text NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE INDEX mailbox_drops_mailbox ON mailbox_drops (mailbox_id, created_at);
