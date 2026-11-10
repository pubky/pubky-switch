-- When a claim may be deleted (Switch wire 6.8, 7.3 step 4): a tombstone or a failed claim
-- whose attempts are all done or failed, from its pinned deadline plus the reconciliation
-- window, or, pinned to no deadline, max_claim_age_ms after its last entry. The service
-- writes these with the claim's state, from the core's rule, so step 4 deletes with an
-- indexed query; the age is applied when it deletes, so a raised max_claim_age_ms applies
-- to every claim.
ALTER TABLE claims
    -- The columns below hold the claim's state. Rows written before this migration hold
    -- false until the service fills them from the state, a few per request.
    ADD COLUMN delete_known BOOLEAN NOT NULL DEFAULT false,
    -- Pinned to a deadline: the deadline plus the reconciliation window. Null otherwise,
    -- or while the claim may not be deleted.
    ADD COLUMN delete_after_ms BIGINT CHECK (delete_after_ms >= 0),
    -- Pinned to no deadline: its last entry's time. Null otherwise, or while the claim may
    -- not be deleted.
    ADD COLUMN delete_after_entry_ms BIGINT CHECK (delete_after_entry_ms >= 0);
CREATE INDEX claims_due_at_deadline ON claims (account_id, delete_after_ms)
    WHERE delete_after_ms IS NOT NULL;
CREATE INDEX claims_due_after_entry ON claims (account_id, delete_after_entry_ms)
    WHERE delete_after_entry_ms IS NOT NULL;
CREATE INDEX claims_unknown_deletion ON claims (account_id) WHERE NOT delete_known;
