-- The `app.put` and `cert.put` items of an app, by the App ID 0022 added (Switch wire 7.5),
-- so a change to the app's record or renewed certificate finds its earlier documents
-- without reading every item. A plain build, in its own transaction: it scans
-- `chain_items` once under a SHARE lock, so writes that chain an item wait and reads don't.
-- Until it is built, those lookups scan the account's items instead.
CREATE INDEX chain_items_by_doc_app ON chain_items (account_id, doc_app)
    WHERE doc_app IS NOT NULL;
