-- "Shared by me" lists, and per-user link revocation, look shares up by creator.
CREATE INDEX shares_created_by ON shares (created_by, created_at DESC);
