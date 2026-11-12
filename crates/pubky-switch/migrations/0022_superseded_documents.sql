-- A chain item's document goes once no app may read it in full (Switch wire 7.5): the
-- service deletes it, and an operation's transition proof with it, in the transaction that
-- supersedes it, leaving the stub.
--
-- The App ID an `app.put` or `cert.put` document concerns, so the documents of an app whose
-- record or renewed certificate changes are found without reading every item; null for
-- every other item, and once the document is deleted.
ALTER TABLE chain_items
    ADD COLUMN doc_app BYTEA CHECK (doc_app IS NULL OR octet_length(doc_app) = 16);
CREATE INDEX chain_items_by_doc_app ON chain_items (account_id, doc_app)
    WHERE doc_app IS NOT NULL;
-- The documents chained before this rule are checked at the account's requests, a bounded
-- number at a time, oldest first: those through `documents_checked_seq` are, up to
-- `documents_check_end`, the account's last seq now. An account created later has none.
ALTER TABLE accounts
    ADD COLUMN documents_checked_seq BIGINT NOT NULL DEFAULT 0
        CHECK (documents_checked_seq >= 0),
    ADD COLUMN documents_check_end BIGINT NOT NULL DEFAULT 0
        CHECK (documents_check_end >= 0);
UPDATE accounts SET documents_check_end = last_seq;
