-- When a claim may be deleted (Switch wire 6.8, 7.3 step 4): a tombstone or a failed claim
-- whose attempts are all done or failed, from its pinned deadline plus the reconciliation
-- window, or for a claim pinned to no deadline from its last entry plus max_claim_age_ms.
-- Null while it may not. The service writes it with the claim's state, so step 4 deletes
-- with one indexed query.
ALTER TABLE claims ADD COLUMN deletable_at_ms BIGINT CHECK (deletable_at_ms >= 0);
CREATE INDEX claims_by_deletable ON claims (account_id, deletable_at_ms)
    WHERE deletable_at_ms IS NOT NULL;
