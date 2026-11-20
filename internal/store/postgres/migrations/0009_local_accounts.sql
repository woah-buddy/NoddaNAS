-- Local accounts: people who sign in with an email, a password and a
-- one-time code from an authenticator app (TOTP), instead of through an
-- identity provider. Their users rows have issuer 'local'.
CREATE TABLE local_logins (
    user_id         text PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    login           text NOT NULL UNIQUE CHECK (login = lower(login) AND length(login) <= 254),
    -- Argon2id. Empty: no usable password (invited, being reset, or disabled).
    password_hash   text NOT NULL DEFAULT '',
    -- The TOTP secret, encrypted with a key derived from the settings key.
    totp_secret     text NOT NULL DEFAULT '',
    -- The last time step a code was accepted for: each code works once.
    totp_last_step  bigint NOT NULL DEFAULT 0,
    failed_attempts int NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    created_at      timestamptz NOT NULL,
    created_by      text NOT NULL
);

-- Single-use recovery codes, hashed.
CREATE TABLE local_recovery_codes (
    user_id   text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash text NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);

-- Short-lived steps of sign-in and enrolment, keyed by the hash of a
-- random token:
--   invite, reset  link to set a password and an authenticator (days)
--   enroll         that password and a new TOTP secret, until the first
--                  code from the app confirms them (minutes)
--   mfa            a correct password, waiting for the one-time code (minutes)
CREATE TABLE local_tickets (
    token_hash       text PRIMARY KEY,
    user_id          text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind             text NOT NULL CHECK (kind IN ('invite', 'reset', 'enroll', 'mfa')),
    parent           text NOT NULL DEFAULT '',  -- enroll: the invite or reset it continues
    pending_password text NOT NULL DEFAULT '',
    pending_secret   text NOT NULL DEFAULT '',
    attempts         int NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL
);
CREATE INDEX local_tickets_user ON local_tickets (user_id);
CREATE INDEX local_tickets_expiry ON local_tickets (expires_at);
