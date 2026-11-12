-- Pending connect requests (Switch spec 7, Switch wire 7.4.7): a content-free request from
-- a sender identity to be invited, kept until it is answered by a list entry for the
-- sender (a contact, a conversation entry or a deny list entry) or declined. Only the
-- sender's Pubky ID and when it asked are kept; one row per sender. The policy's
-- `max_pending`, capped by `max_connect_pending`, bounds the rows in code, since the cap
-- is the identity's own setting.
CREATE TABLE connect_requests (
    account_id  TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    pubky       BYTEA   NOT NULL CHECK (octet_length(pubky) = 32),
    at_ms       BIGINT  NOT NULL CHECK (at_ms >= 0),
    PRIMARY KEY (account_id, pubky)
);

-- Read oldest first (`GET /connect`).
CREATE INDEX connect_requests_by_time ON connect_requests (account_id, at_ms, pubky);
