-- The signer hand-over the switch holds for the account (Switch wire 7.4.17, 3.12): at most
-- one, replaced by the next PUT /handover. The body is the PUT's, byte for byte, which GET
-- /handover answers. It is deleted when the account takes the next identity.json version,
-- and with the account (erasure, 7.4.16). It isn't exported and counts against no quota.
CREATE TABLE handovers (
    account_id      TEXT    PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    target_app_id   BYTEA   NOT NULL CHECK (octet_length(target_app_id) = 16),
    body            BYTEA   NOT NULL
);
