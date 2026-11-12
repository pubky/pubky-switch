-- The service time of an account's last once-a-minute sweep (Switch wire 9.1): forgotten
-- deleted keys, spent invite codes and batch proofs past `batch_proofs_ms` go at most once a
-- minute of service time, at a request to the account. Kept with the account, so the
-- minute holds across instances and restarts; null before the first.
ALTER TABLE accounts ADD COLUMN swept_at_ms BIGINT CHECK (swept_at_ms >= 0);
-- The deleted keys written here, by the position of their delete: the sweep's look for one
-- is a single probe, and its forgetting a range scan up to the lowest cursor it waits for
-- (Switch spec 10.3). Small: a deleted key's row stays only until it is forgotten.
CREATE INDEX shared_records_deleted ON shared_records (account_id, generation, version)
    WHERE deleted AND NOT from_upload;
