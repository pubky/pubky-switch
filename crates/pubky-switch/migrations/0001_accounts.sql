-- One account per identity the service hosts (Switch spec 6.2).
--
-- The row holds the account's position: the last seq given out, the chain head and the
-- stamped service time. Every request to the account locks this row, so one account's
-- operations are serialized (Switch spec 6.5).
CREATE TABLE accounts (
    -- The identity's Pubky ID.
    id              TEXT     PRIMARY KEY,
    -- The identity's Ed25519 public key.
    identity_key    BYTEA    NOT NULL CHECK (octet_length(identity_key) = 32),
    -- The generation the account serves (Switch spec 12.6).
    generation      BIGINT   NOT NULL CHECK (generation >= 0),
    -- The ID of the generation's service key in the key store.
    service_key     TEXT     NOT NULL,
    -- The last seq given out in this generation, shared by inbox entries and chain items
    -- (Switch spec 6.3).
    last_seq        BIGINT   NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
    -- The newest chain item's seq and the chain hash there; both null before the first.
    chain_seq       BIGINT   CHECK (chain_seq > 0 AND chain_seq <= last_seq),
    chain_hash      BYTEA    CHECK (octet_length(chain_hash) = 32),
    -- The last service time the account stamped; it never goes back (Switch spec 10.1).
    stamped_time_ms BIGINT   NOT NULL DEFAULT 0 CHECK (stamped_time_ms >= 0),
    -- When the account was created, in service time.
    created_at_ms   BIGINT   NOT NULL CHECK (created_at_ms >= 0),
    CHECK ((chain_seq IS NULL) = (chain_hash IS NULL))
);
