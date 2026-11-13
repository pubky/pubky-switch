-- A purged app's kids stay registered (Switch spec 3.6 "Kids are unique", wire 9.1): the
-- purge clears the app's receive key records and keeps each of its kids with its App ID, so
-- no app registers one of them again and an envelope wrapped to one is told the app isn't
-- current, as before the purge. A row with no record is such a kept kid. Metadata only: no
-- rewrite and no scan.
ALTER TABLE receive_keys ALTER COLUMN record DROP NOT NULL;
