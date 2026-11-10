-- What an account holds of its identity (Switch wire 3.3, 3.7), and its chain (6.6).

ALTER TABLE accounts
    -- The limits announced at the first enrollment, as the answer writes them; every later
    -- enrollment announces the same (Switch wire 3.7). Not null, from the update below.
    ADD COLUMN announced_limits BYTEA,
    -- The key store ID of the next generation's pending key, once an enrollment at the
    -- serving account asked for one (Switch wire 3.7).
    ADD COLUMN pending_key     TEXT,
    -- The newest identity.json the account holds, in its carrying form (Switch wire 2.2).
    ADD COLUMN identity_doc    BYTEA,
    -- The transition proof of the delivery that took it, in its carrying form; null for a
    -- version the account was enrolled with (Switch wire 7.4.2).
    ADD COLUMN identity_proof  BYTEA,
    ADD CHECK (identity_proof IS NULL OR identity_doc IS NOT NULL);

-- An account enrolled before this column existed was announced the limits the service ran
-- with, which this migration can't see: the service passes the limits in force when it
-- migrates, in the setting pubky_switch.announced_limits, and every such account inherits
-- them. A database holding accounts can only be migrated that way; without the setting the
-- update fails and nothing is applied.
UPDATE accounts
    SET announced_limits = convert_to(current_setting('pubky_switch.announced_limits'), 'UTF8')
    WHERE announced_limits IS NULL;
ALTER TABLE accounts ALTER COLUMN announced_limits SET NOT NULL;

-- App IDs the account keeps for good: revoked, departed, or named by an enrollment's
-- revoked_apps, so they are never current again (Switch wire 3.3, 3.7, 9.1).
CREATE TABLE kept_app_ids (
    account_id  TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    app_id      BYTEA   NOT NULL CHECK (octet_length(app_id) = 16),
    -- Why it is kept: 'revoked', 'departed' or 'enrolled'.
    reason      TEXT    NOT NULL CHECK (reason IN ('revoked', 'departed', 'enrolled')),
    -- The service time it was revoked, departed, or the enrollment that named it.
    at_ms       BIGINT  NOT NULL CHECK (at_ms >= 0),
    PRIMARY KEY (account_id, app_id)
);

-- The chain: one row per chain item of a generation (Switch wire 6.6). Inbox entries and
-- cursor moves take seqs too, so seqs have gaps.
CREATE TABLE chain_items (
    account_id   TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    generation   BIGINT  NOT NULL CHECK (generation >= 0),
    seq          BIGINT  NOT NULL CHECK (seq > 0),
    -- 'op', 'identity' or 'service'.
    item_type    TEXT    NOT NULL CHECK (item_type IN ('op', 'identity', 'service')),
    -- The signed document's bytes (Switch wire 2.2); null once the document is deleted
    -- and only its stub is kept (Switch wire 7.5).
    item_bytes   BYTEA,
    -- The chain envelope's exact JSON bytes; with chain_hash, the item's stub.
    envelope     BYTEA   NOT NULL,
    chain_hash   BYTEA   NOT NULL CHECK (octet_length(chain_hash) = 32),
    server_time_ms BIGINT NOT NULL CHECK (server_time_ms >= 0),
    PRIMARY KEY (account_id, generation, seq)
);
