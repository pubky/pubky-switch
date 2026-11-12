-- The service time of an account's last once-a-minute sweep (Switch wire 9.1): spent invite
-- codes and batch proofs past `batch_proofs_ms` go at most once a minute of service time,
-- at a request to the account. Kept with the account, so the minute holds across instances
-- and restarts; null before the first.
ALTER TABLE accounts ADD COLUMN swept_at_ms BIGINT CHECK (swept_at_ms >= 0);
