-- Signed version history (docs/E2EE.md §5c): the record that whoever stored
-- a version signed about it, and the version's place in the file's hash
-- chain. Clients verify all of it; the server keeps it consistent (one
-- version per position, each naming the one before). NULL for versions
-- stored before records existed.
ALTER TABLE versions
    ADD COLUMN record      bytea  CHECK (length(record) BETWEEN 1 AND 1024),
    ADD COLUMN record_sig  bytea  CHECK (length(record_sig) = 64),
    ADD COLUMN seq         bigint CHECK (seq >= 1),
    ADD COLUMN record_hash bytea  CHECK (length(record_hash) = 32),
    ADD CONSTRAINT versions_record_complete CHECK (
        (record IS NULL) = (record_sig IS NULL) AND (record IS NULL) = (seq IS NULL)
        AND (record IS NULL) = (record_hash IS NULL));

-- Two uploads racing for the same place in a file's chain cannot both
-- succeed.
CREATE UNIQUE INDEX versions_node_seq ON versions (node_id, seq) WHERE seq IS NOT NULL;
