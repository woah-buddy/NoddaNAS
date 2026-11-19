-- Settings changed in the web admin area: one document, replaced as a whole
-- under optimistic concurrency (revision), so two administrators cannot
-- silently overwrite each other. Values are text; secrets are AES-GCM
-- ciphertext ("enc:v1:...") under the server's settings key, which is not
-- stored in the database.
CREATE TABLE settings (
    id         smallint PRIMARY KEY CHECK (id = 1),
    revision   bigint NOT NULL,
    doc        jsonb NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by text NOT NULL
);

-- The one-time setup link (`frontdir setup-link`). Only a hash is stored;
-- there is at most one, and it is deleted when someone signs in through it.
CREATE TABLE setup_token (
    id         smallint PRIMARY KEY CHECK (id = 1),
    token_hash text NOT NULL,
    expires_at timestamptz NOT NULL
);

-- When the person last re-authenticated at their IdP on request ("confirm
-- it's you"). Administrative changes require this to be recent.
ALTER TABLE sessions ADD COLUMN reauth_at timestamptz;
ALTER TABLE login_requests ADD COLUMN reauth boolean NOT NULL DEFAULT false;
ALTER TABLE login_requests ADD COLUMN setup_hash text;

-- Administrators appointed in FrontDir (by the setup link or another
-- administrator), in addition to members of the administrator groups.
-- is_admin stays the effective flag: admin_granted OR member of an
-- administrator group.
ALTER TABLE users ADD COLUMN admin_granted boolean NOT NULL DEFAULT false;
