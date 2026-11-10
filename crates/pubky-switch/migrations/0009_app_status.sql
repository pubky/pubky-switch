-- What GET /apps reports of each app beyond its row (Switch wire 7.4.12).

-- The data epoch of the first identity.json that listed each app: where its keys_through
-- starts. Written when a document lists an app for the first time, at an enrollment that
-- carries one or at a delivery. An app listed before this table existed has no row, and
-- its keys_through is unknown (null) until a key bundle part from epoch 1 raises it.
CREATE TABLE app_listings (
    account_id      TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    app_id          BYTEA   NOT NULL CHECK (octet_length(app_id) = 16),
    listed_epoch    BIGINT  NOT NULL CHECK (listed_epoch >= 0),
    PRIMARY KEY (account_id, app_id)
);

-- The newest document's data_epoch when an app was revoked or departed. A departure's
-- rotation is done once a delivered identity.json lists it in removed with a higher
-- data_epoch than this. Null for App IDs kept before this column existed, and for those an
-- enrollment named.
ALTER TABLE kept_app_ids
    ADD COLUMN data_epoch BIGINT CHECK (data_epoch >= 0);
