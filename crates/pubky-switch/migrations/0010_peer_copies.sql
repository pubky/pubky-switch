-- Peers' identity.json copies (Switch wire 7.4.5, 9.1): what admission and the listing
-- checks of other identities' apps read.

-- The order in which copies were last delivered, across accounts: the least recently
-- delivered copy is the one that drops beyond max_peers.
CREATE SEQUENCE peer_delivery_order;

-- One copy per identity per account, the highest version taken, as its sender signed it.
CREATE TABLE peer_copies (
    account_id   TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    identity     BYTEA   NOT NULL CHECK (octet_length(identity) = 32),
    -- The signed document in its carrying form (Switch wire 2.2).
    doc          BYTEA   NOT NULL,
    version      BIGINT  NOT NULL CHECK (version >= 1),
    generation   BIGINT  NOT NULL CHECK (generation >= 1),
    -- The hash of the document's body bytes, which a delivery at the held version is
    -- compared by (Switch wire 3.3).
    body_hash    BYTEA   NOT NULL CHECK (octet_length(body_hash) = 32),
    delivered    BIGINT  NOT NULL DEFAULT nextval('peer_delivery_order'),
    PRIMARY KEY (account_id, identity)
);
CREATE INDEX peer_copies_by_delivery ON peer_copies (account_id, delivered);

-- What a dropped copy of an admitted identity leaves until a copy is held again (Switch
-- wire 7.4.5 Floors): its version, generation and body hash.
CREATE TABLE peer_floors (
    account_id   TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    identity     BYTEA   NOT NULL CHECK (octet_length(identity) = 32),
    version      BIGINT  NOT NULL CHECK (version >= 1),
    generation   BIGINT  NOT NULL CHECK (generation >= 1),
    body_hash    BYTEA   NOT NULL CHECK (octet_length(body_hash) = 32),
    PRIMARY KEY (account_id, identity)
);
