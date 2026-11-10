-- The enrollments an account answered, so the same enrollment again gets the same answer
-- (Switch wire 3.7): by the document hash of the signed enrollment, the key that answered it.
-- At most max_enrollments per account are kept; the oldest drops (Switch wire 9.1).
CREATE TABLE enrollment_answers (
    account_id       TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    enrollment_hash  BYTEA   NOT NULL CHECK (octet_length(enrollment_hash) = 32),
    -- The key store ID of the service key the answer named.
    service_key      TEXT    NOT NULL,
    -- When it was first answered, in service time; the order the oldest drops in.
    answered_at_ms   BIGINT  NOT NULL CHECK (answered_at_ms >= 0),
    PRIMARY KEY (account_id, enrollment_hash)
);
