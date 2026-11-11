-- The seq of the key bundle part that completed an app's full-bundle request (Switch wire
-- 6.2): the request stays in force for dropping passed parts until the app's cursor has
-- passed it, so the app reads every part it asked for before any of them goes.
ALTER TABLE apps ADD COLUMN full_completed_seq BIGINT CHECK (full_completed_seq > 0);
