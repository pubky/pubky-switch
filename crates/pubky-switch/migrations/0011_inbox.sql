-- The inbox (Switch wire 7.4.3, 9.1): entries, the conversation entries the service writes
-- when an invite code admits a sender, and the senders flagged for hitting the limits.

-- An inbox entry, from its acceptance until every current target's cursor has passed it.
CREATE TABLE inbox_entries (
    account_id      TEXT     NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    generation      BIGINT   NOT NULL CHECK (generation >= 0),
    seq             BIGINT   NOT NULL CHECK (seq > 0),
    entry_id        BYTEA    NOT NULL CHECK (octet_length(entry_id) = 16),
    -- The sender identity and app, and the certificate the feed shows with the entry.
    sender          BYTEA    NOT NULL CHECK (octet_length(sender) = 32),
    sender_app      BYTEA    NOT NULL CHECK (octet_length(sender_app) = 16),
    cert            BYTEA    NOT NULL,
    accepted_at_ms  BIGINT   NOT NULL CHECK (accepted_at_ms >= 0),
    -- The envelope as received, sealed: the service never holds the keys that open it.
    envelope        BYTEA    NOT NULL,
    -- BLAKE3 of the envelope: a retry by content is the same envelope from the same sender
    -- identity (7.4.3 check 1).
    envelope_hash   BYTEA    NOT NULL CHECK (octet_length(envelope_hash) = 32),
    -- The apps it was wrapped to.
    targets         BYTEA[]  NOT NULL,
    -- The invite code's context, as its writer wrote it, when a code admitted the sender.
    context         BYTEA,
    -- The answer the append got, which a retry by content gets again.
    answer          BYTEA    NOT NULL,
    -- What it counts against the inbox quota: its envelope's bytes and the entry overhead.
    quota_bytes     BIGINT   NOT NULL CHECK (quota_bytes > 0),
    PRIMARY KEY (account_id, generation, seq)
);
CREATE UNIQUE INDEX inbox_entries_by_content ON inbox_entries (account_id, sender, envelope_hash);
CREATE INDEX inbox_entries_by_sender ON inbox_entries (account_id, sender);

-- A conversation entry the service writes for a sender an invite code admitted names the
-- code and its context, and no app (Switch wire 7.4.6). An entry's last admitted append is
-- kept for pruning.
ALTER TABLE list_entries
    ALTER COLUMN written_by DROP NOT NULL,
    ADD COLUMN code_hash BYTEA CHECK (octet_length(code_hash) = 32),
    ADD COLUMN context BYTEA,
    ADD COLUMN last_used_ms BIGINT CHECK (last_used_ms >= 0),
    ADD CHECK (written_by IS NOT NULL OR (list = 'conversation' AND code_hash IS NOT NULL));

-- Each sender identity's hits against the append limits (Switch wire 9.4 Flags).
CREATE TABLE sender_flags (
    account_id  TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    pubky       BYTEA   NOT NULL CHECK (octet_length(pubky) = 32),
    hits        BIGINT  NOT NULL CHECK (hits > 0),
    PRIMARY KEY (account_id, pubky)
);
