-- Records taken from recovery uploads after a provider loss, and divergent uploads (Switch
-- wire 7.4.14, 7.4.9, 10.3; Switch spec 12.6 step 3).
--
-- 0016 is the lagging work's; 0017 and 0018 are the generation change's.

-- Where a record's current write came from:
-- - a write made here carries its transition proof. `upload_base` is the uploaded version
--   that the first write here built on, with its operation's hash, or null when the writes
--   here built on none; a later upload newer than it is divergent, and that operation again
--   changes nothing;
-- - a write taken from an upload carries no proof (the lost service's proofs date nothing
--   here). `upload_seq` is the `upload` transition that listed it, which the record view
--   shows as its `seq`. `version_exact` is false when no proof gave its version and it holds
--   the lower bound.
ALTER TABLE shared_records
    ADD COLUMN from_upload BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN upload_seq BIGINT CHECK (upload_seq > 0),
    ADD COLUMN version_exact BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN upload_base_generation BIGINT CHECK (upload_base_generation >= 0),
    ADD COLUMN upload_base_version BIGINT CHECK (upload_base_version > 0),
    ADD COLUMN upload_base_op_hash BYTEA CHECK (octet_length(upload_base_op_hash) = 32),
    ALTER COLUMN proof DROP NOT NULL,
    ADD CHECK (
        (from_upload AND proof IS NULL AND upload_seq IS NOT NULL
            AND upload_base_generation IS NULL AND upload_base_version IS NULL
            AND upload_base_op_hash IS NULL)
        OR (NOT from_upload AND proof IS NOT NULL AND upload_seq IS NULL AND version_exact
            AND (upload_base_generation IS NULL) = (upload_base_version IS NULL)
            AND (upload_base_generation IS NULL) = (upload_base_op_hash IS NULL))
    );

-- The uploads that conflict with a record, kept until a write here (Switch wire 9.1, at most
-- `max_divergent_uploads` per record), each at its place among them from 0, as an export's
-- `divergent` parts carry them.
CREATE TABLE divergent_uploads (
    account_id  TEXT      NOT NULL,
    key         BYTEA     NOT NULL CHECK (octet_length(key) = 32),
    position    SMALLINT  NOT NULL CHECK (position >= 0),
    -- The uploaded signed record.put, and hash() of its bytes, which recognizes it again.
    op          BYTEA     NOT NULL,
    op_hash     BYTEA     NOT NULL CHECK (octet_length(op_hash) = 32),
    PRIMARY KEY (account_id, key, position),
    UNIQUE (account_id, key, op_hash),
    FOREIGN KEY (account_id, key) REFERENCES shared_records (account_id, key) ON DELETE CASCADE
);
