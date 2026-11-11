-- The key store entries an erasure still owes deleting (Switch wire 7.4.16): the account's
-- service key with its mark, and a pending key of the next generation. Written in the same
-- transaction that deletes the account, so the deletion is owed durably the moment the
-- account is gone; the service deletes each key, records the erasure in the key store's
-- ledger (spec 6.5), then drops the row: at once, and again at start for any a failure or a
-- crash left. No foreign key: the account is gone by then.
CREATE TABLE erased_keys (
    key_id          TEXT    PRIMARY KEY,
    account_id      TEXT    NOT NULL,
    erased_at_ms    BIGINT  NOT NULL CHECK (erased_at_ms >= 0)
);
