-- Chain stub retention (Switch wire 7.4.4 "Checkpoints", 9.1): the account's latest
-- checkpoint and the newest chain stub it dropped, one row per account once it has either.
-- A recovery in place empties it with the rest of the generation's state (wire 3.3), and an
-- erasure with the account.
--
-- The checkpoint is the signed head's JSON (wire 6.7) and its `seq`; the newest dropped
-- stub its `seq` and chain hash, which an export's checkpoint signs (wire 10.2). Each pair is
-- all null or all set: a checkpoint comes before the first drop, and a drop never goes past
-- the checkpoint.
CREATE TABLE chain_retention (
    account_id          TEXT    PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    checkpoint          BYTEA,
    checkpoint_seq      BIGINT  CHECK (checkpoint_seq > 0),
    dropped_seq         BIGINT  CHECK (dropped_seq > 0),
    dropped_chain_hash  BYTEA   CHECK (octet_length(dropped_chain_hash) = 32),
    CHECK ((checkpoint IS NULL) = (checkpoint_seq IS NULL)),
    CHECK ((dropped_seq IS NULL) = (dropped_chain_hash IS NULL)),
    CHECK (dropped_seq IS NULL OR dropped_seq <= checkpoint_seq)
);

-- The batch a chain item falls in, by its last `seq`: a sweep that would cut inside a batch
-- finds it with one lookup and stops before its first item (wire 7.4.4).
CREATE INDEX batches_by_last_seq ON batches (account_id, generation, last_seq);
-- The batch records whose proofs are gone, by their last `seq`: the sweep deletes those whose
-- stubs are all dropped by a range scan that reads none whose proofs are still kept.
CREATE INDEX batches_spent ON batches (account_id, generation, last_seq) WHERE proofs IS NULL;
