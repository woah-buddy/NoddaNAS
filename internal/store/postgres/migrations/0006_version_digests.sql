-- Version attribution (docs/E2EE.md §5b): what a client needs to check who
-- signed a version without downloading it. All of it is copied or derived
-- from the stored ciphertext, and clients verify it, so it needs no more
-- protection than the ciphertext does.
--   signer_id  the user the container header names as signer (a claim, used
--              to pick which thumbnails to offer; clients verify it)
--   header     the container prefix: magic, length, header JSON
--   body_hash  SHA-256 over the SHA-256 of each encrypted chunk
--   trailer    "SIG1" and the Ed25519 signature
-- NULL: not computed yet (versions stored before this migration; the
-- maintenance worker fills them in). Empty: cannot be computed (the stored
-- container is missing or damaged).
ALTER TABLE versions
    ADD COLUMN signer_id text  CHECK (length(signer_id) <= 64),
    ADD COLUMN header    bytea CHECK (length(header) <= 65548),
    ADD COLUMN body_hash bytea CHECK (length(body_hash) IN (0, 32)),
    ADD COLUMN trailer   bytea CHECK (length(trailer) IN (0, 68));

CREATE INDEX versions_digest_pending ON versions (id) WHERE body_hash IS NULL;
