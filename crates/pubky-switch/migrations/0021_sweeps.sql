-- The sweeps (Switch wire 9.1). The indexes come first, so the exclusive lock the column
-- takes on `accounts`, which every request waits for until the migration commits, isn't
-- held while they build.
--
-- The deleted keys written here, by the position of their delete: the sweep finds whether
-- there is one with a single lookup, and forgets them by a range scan up to the lowest
-- cursor they wait for (Switch spec 10.3). It holds deleted keys only, which leave it once
-- forgotten.
CREATE INDEX shared_records_deleted ON shared_records (account_id, generation, version)
    WHERE deleted AND NOT from_upload;
-- The batches that still keep their transition proofs, oldest first: the sweep drops those
-- past `batch_proofs_ms` by a range scan, not by reading every batch the account has had,
-- since batch records stay while their chain stubs do.
CREATE INDEX batches_with_proofs ON batches (account_id, at_ms, batch_id)
    WHERE proofs IS NOT NULL;
-- The service time of an account's last once-a-minute sweep: forgotten deleted keys, spent
-- invite codes and batch proofs past `batch_proofs_ms` go at most once a minute of service
-- time, at a request to the account. Kept with the account, so the minute holds across
-- instances and restarts; null before the first.
ALTER TABLE accounts ADD COLUMN swept_at_ms BIGINT CHECK (swept_at_ms >= 0);
