-- A provider loss at this service (Switch spec 12.6; Switch wire 3.3, 3.7, 7.4.2, 7.4.12).

-- The recovery the generation the account serves began with: the generation it declares
-- lost, and the `recovery` transition's service time. Both NULL for a generation that began
-- any other way. `GET /apps` reports it as `recovery` while the account serves the generation
-- after `recovery_from`.
ALTER TABLE accounts
    ADD COLUMN recovery_from BIGINT CHECK (recovery_from >= 1),
    ADD COLUMN recovery_declared_at_ms BIGINT CHECK (recovery_declared_at_ms >= 0),
    ADD CHECK ((recovery_from IS NULL) = (recovery_declared_at_ms IS NULL));

-- The enrollments the account answered with a key a generation change has since retired: by
-- their hash, with the generation of the key the answer named. The same enrollment again is
-- `409 conflict`, so its signer enrolls anew (Switch wire 3.7). Kept as the answers they
-- replace were: at most max_enrollments per account, the oldest dropping.
CREATE TABLE retired_enrollments (
    account_id       TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    enrollment_hash  BYTEA   NOT NULL CHECK (octet_length(enrollment_hash) = 32),
    generation       BIGINT  NOT NULL CHECK (generation >= 1),
    retired_order    BIGINT  GENERATED ALWAYS AS IDENTITY,
    PRIMARY KEY (account_id, enrollment_hash)
);

-- The `revoked_apps` of every enrollment answered with the pending key, held with that key:
-- they join the account's tombstones when the delivery naming it starts the new generation,
-- and count for nothing if none does (Switch wire 3.7).
CREATE TABLE pending_revoked_apps (
    account_id  TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    app_id      BYTEA   NOT NULL CHECK (octet_length(app_id) = 16),
    PRIMARY KEY (account_id, app_id)
);

-- Why a key is owed deleting: an erasure, whose deletion the key store's ledger records
-- (spec 6.5), or a generation change that retired it, at an account that lives on.
ALTER TABLE erased_keys
    ADD COLUMN reason TEXT NOT NULL DEFAULT 'erasure' CHECK (reason IN ('erasure', 'retired'));
