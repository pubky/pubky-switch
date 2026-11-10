-- An enrollment answer may drop only while the service would build it again byte for byte
-- (Switch wire 3.7, 9.1): one naming the pending key, which every later enrollment at the
-- serving account gets too. Every other answer is kept as long as the account: the
-- creating enrollment's and every one given while the account was staged, which named the
-- account's key, where a rebuild at the serving account would name the pending key.
ALTER TABLE enrollment_answers ADD COLUMN rebuildable BOOLEAN NOT NULL DEFAULT false;

-- The answers kept so far that named the account's pending key.
UPDATE enrollment_answers e SET rebuildable = true
    FROM accounts a
    WHERE a.id = e.account_id AND a.pending_key IS NOT NULL AND e.service_key = a.pending_key;
