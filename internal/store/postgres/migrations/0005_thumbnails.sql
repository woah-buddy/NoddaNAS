-- Thumbnails: small client-encrypted records attached to one version of a
-- file (docs/E2EE.md §5a). Opaque to the server. One per version and maker,
-- so nobody can overwrite the author's thumbnail; clients show only the
-- author's or their own. They disappear with their version.
CREATE TABLE thumbnails (
    version_id text NOT NULL REFERENCES versions (id) ON DELETE CASCADE,
    maker_id   text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    enc        text NOT NULL CHECK (length(enc) <= 49152),
    sig        text NOT NULL CHECK (length(sig) <= 128),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (version_id, maker_id)
);
