-- Push deliveries (Switch spec 9 step 4, Switch wire 8.2): one webhook owed to one handle of
-- a registration for one `notify` entry, queued in the append's transaction and sent by a
-- background worker. A row holds what sending and retrying need and nothing of the message:
-- the webhook carries only the handle. Its body, `ts` and `nonce`, is made at each attempt,
-- since `ts` is the time it is sent and each nonce is fresh.
--
-- A row goes with its registration (the cascade, at a removal, a recovery in place and an
-- erasure), at a replacement and when its handle leaves the list (`store::push`), once
-- delivered, and after its last attempt: at most 3, within 1 minute of its entry.
CREATE TABLE push_deliveries (
    id               BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id       TEXT    NOT NULL,
    app_id           BYTEA   NOT NULL CHECK (octet_length(app_id) = 16),
    -- The push key the registration held when the row was queued: a row under another key
    -- is never sent.
    push_key_id      TEXT    NOT NULL,
    handle           TEXT    NOT NULL,
    -- The entry's service time.
    entry_at_ms      BIGINT  NOT NULL CHECK (entry_at_ms >= 0),
    attempts         INT     NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    -- When the row may next be claimed: due at its entry; each claim leases it until a
    -- retry would be due, so one instance sends it at a time.
    next_attempt_ms  BIGINT  NOT NULL CHECK (next_attempt_ms >= 0),
    FOREIGN KEY (account_id, app_id)
        REFERENCES push_registrations (account_id, app_id) ON DELETE CASCADE
);
CREATE INDEX push_deliveries_due ON push_deliveries (next_attempt_ms);
CREATE INDEX push_deliveries_by_app ON push_deliveries (account_id, app_id);
