-- Each user's verified-contacts list, sealed by their own client under their
-- master key (docs/E2EE.md §8). Opaque to the server. contacts_rev provides
-- optimistic concurrency so two devices cannot silently overwrite each other.
ALTER TABLE users ADD COLUMN contacts_enc text;
ALTER TABLE users ADD COLUMN contacts_rev bigint NOT NULL DEFAULT 0;
