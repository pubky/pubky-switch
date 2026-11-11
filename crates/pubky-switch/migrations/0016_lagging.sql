-- Lagging apps, missed items and unreadable items (Switch wire 7.4.4, 7.5, 9.1).

-- An app marked lagging: entries no longer wait for it (7.4.4). Set at the requests that
-- bring the pressure, with trusted time; cleared at the app's feed read.
ALTER TABLE apps ADD COLUMN lagging BOOLEAN NOT NULL DEFAULT false;

-- The inbox holds three kinds of item, each at a seq of its own, as an export's `entry`
-- part does (10.3):
-- - `entry`: an envelope a sender appended, for its target apps;
-- - `unreadable`: an entry no current app can open after its targets departed, for every
--   current app. It keeps the entry's entry_id, sender and acceptance time, and its envelope
--   is gone; it counts entry_overhead_bytes against the inbox quota;
-- - `missed`: for its one target, a lagging app, how many entries targeting it the service
--   deleted before it read them, and the first and last of their acceptance times. It has no
--   sender and counts against nothing.
ALTER TABLE inbox_entries
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'entry'
        CHECK (kind IN ('entry', 'unreadable', 'missed')),
    ADD COLUMN missed_entries BIGINT CHECK (missed_entries > 0),
    ADD COLUMN missed_from_ms BIGINT CHECK (missed_from_ms >= 0),
    ADD COLUMN missed_until_ms BIGINT CHECK (missed_until_ms >= 0),
    ALTER COLUMN entry_id DROP NOT NULL,
    ALTER COLUMN sender DROP NOT NULL,
    ALTER COLUMN sender_app DROP NOT NULL,
    ALTER COLUMN cert DROP NOT NULL,
    ALTER COLUMN envelope_hash DROP NOT NULL,
    ALTER COLUMN answer DROP NOT NULL,
    DROP CONSTRAINT inbox_entries_quota_bytes_check,
    ADD CHECK (quota_bytes >= 0),
    ADD CHECK (
        (kind = 'missed'
            AND missed_entries IS NOT NULL AND missed_from_ms IS NOT NULL
            AND missed_until_ms IS NOT NULL AND quota_bytes = 0)
        OR (kind <> 'missed'
            AND missed_entries IS NULL AND missed_from_ms IS NULL AND missed_until_ms IS NULL
            AND entry_id IS NOT NULL AND sender IS NOT NULL AND sender_app IS NOT NULL
            AND cert IS NOT NULL AND envelope_hash IS NOT NULL AND answer IS NOT NULL
            AND quota_bytes > 0)
    );
