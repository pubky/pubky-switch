-- The state signed operations change (Switch wire 6.2, 6.8): apps, receive keys, key bundle
-- parts, shared records, claims, the lists, invite codes and batch records. Every row
-- belongs to one account and changes only in a request holding the account's lock.
--
-- Signed documents are kept in their carrying form (Switch wire 2.2), exactly as received,
-- so a retry, a read or an export shows the bytes the writer signed. Sealed values stay
-- sealed: the service never holds the keys that open them (Switch spec 1).

ALTER TABLE accounts
    -- The directory's versions (Switch wire 7.4.10): directory_version moves with every
    -- stored app record or receive key, apps_version when an app becomes reachable.
    ADD COLUMN directory_version BIGINT NOT NULL DEFAULT 0 CHECK (directory_version >= 0),
    ADD COLUMN apps_version      BIGINT NOT NULL DEFAULT 0 CHECK (apps_version >= 0);

-- One row per own app the account has seen in an app.put (Switch wire 6.2, 7.2).
CREATE TABLE apps (
    account_id      TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    app_id          BYTEA   NOT NULL CHECK (octet_length(app_id) = 16),
    -- The app record the newest app.put stored.
    record          BYTEA,
    -- When the service took it, in service time (Switch wire 7.4.12 record_at).
    record_at_ms    BIGINT  CHECK (record_at_ms >= 0),
    -- The renewed certificate a cert.put stored; at most one (Switch wire 3.8).
    renewed_cert    BYTEA,
    -- The current receive key record (Switch wire 3.4).
    receive_key     BYTEA,
    -- The app's cursor (Switch wire 6.2 cursor.set): a position in the account's sequence.
    cursor_generation BIGINT CHECK (cursor_generation >= 0),
    cursor_seq      BIGINT  CHECK (cursor_seq >= 0),
    -- The apps_version at which the app became reachable (Switch wire 7.4.10).
    reachable_since BIGINT  CHECK (reachable_since >= 0),
    -- When a full key bundle was requested for the app and not yet covered (Switch wire 6.2).
    full_requested_ms BIGINT CHECK (full_requested_ms >= 0),
    -- The service time of its last authenticated request (Switch wire 7.3 step 6).
    last_seen_ms    BIGINT  CHECK (last_seen_ms >= 0),
    PRIMARY KEY (account_id, app_id),
    CHECK ((cursor_generation IS NULL) = (cursor_seq IS NULL))
);

-- Every receive key record any app registered, current or retired: a kid is never registered
-- twice in an account (Switch spec 3.6).
CREATE TABLE receive_keys (
    account_id  TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    kid         BYTEA   NOT NULL CHECK (octet_length(kid) = 8),
    app_id      BYTEA   NOT NULL CHECK (octet_length(app_id) = 16),
    n           BIGINT  NOT NULL CHECK (n >= 0),
    record      BYTEA   NOT NULL,
    PRIMARY KEY (account_id, kid)
);
CREATE INDEX receive_keys_by_app ON receive_keys (account_id, app_id, n);

-- The key bundle parts stored for a target app (Switch wire 6.2): their epoch ranges never
-- overlap.
CREATE TABLE key_bundle_parts (
    account_id      TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    target_app_id   BYTEA   NOT NULL CHECK (octet_length(target_app_id) = 16),
    first_epoch     BIGINT  NOT NULL CHECK (first_epoch >= 1),
    last_epoch      BIGINT  NOT NULL CHECK (last_epoch >= first_epoch),
    -- The seq of the key_bundle.put that stored it (its proof's bundle_seq).
    seq             BIGINT  NOT NULL CHECK (seq > 0),
    -- The signed key_bundle.put.
    op              BYTEA   NOT NULL,
    PRIMARY KEY (account_id, target_app_id, first_epoch)
);

-- Shared records, by key (Switch spec 10.3): the newest write of each, deleted or not.
CREATE TABLE shared_records (
    account_id    TEXT     NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    key           BYTEA    NOT NULL CHECK (octet_length(key) = 32),
    collection    BYTEA    NOT NULL CHECK (octet_length(collection) = 32),
    read_scope    TEXT     NOT NULL,
    write_scopes  TEXT[]   NOT NULL,
    -- The record's version: the write's generation and seq.
    generation    BIGINT   NOT NULL CHECK (generation >= 0),
    version       BIGINT   NOT NULL CHECK (version > 0),
    deleted       BOOLEAN  NOT NULL,
    -- The bytes its value counts against the storage quota: its ct, 0 for a delete
    -- (Switch wire 9.1).
    value_bytes   BIGINT   NOT NULL CHECK (value_bytes >= 0),
    -- The writing app, and the certificate the service checked the write against.
    writer        BYTEA    NOT NULL CHECK (octet_length(writer) = 16),
    cert          BYTEA    NOT NULL,
    -- The signed record.put and its transition proof.
    op            BYTEA    NOT NULL,
    proof         BYTEA    NOT NULL,
    PRIMARY KEY (account_id, key),
    CHECK (NOT deleted OR value_bytes = 0)
);
CREATE INDEX shared_records_by_collection ON shared_records (account_id, collection, key);

-- Claims, by claim key (Switch wire 6.8). The claim's state is the service's own encoding;
-- creator, tombstone and open_owners repeat what the per-app limits count, so they are
-- counted without reading every claim.
CREATE TABLE claims (
    account_id   TEXT     NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    claim_key    BYTEA    NOT NULL CHECK (octet_length(claim_key) = 32),
    state        BYTEA    NOT NULL,
    creator      BYTEA    CHECK (octet_length(creator) = 16),
    tombstone    BOOLEAN  NOT NULL,
    -- The owner of each attempt open or unknown, once per attempt.
    open_owners  BYTEA[]  NOT NULL,
    PRIMARY KEY (account_id, claim_key)
);

-- A claim's entries, with their proofs, for GET /claims (Switch wire 7.4.8).
CREATE TABLE claim_entries (
    account_id  TEXT    NOT NULL,
    claim_key   BYTEA   NOT NULL,
    -- The claim's step before the entry, its expected_step.
    step        BIGINT  NOT NULL CHECK (step >= 0),
    seq         BIGINT  NOT NULL CHECK (seq > 0),
    op          BYTEA   NOT NULL,
    proof       BYTEA   NOT NULL,
    PRIMARY KEY (account_id, claim_key, step),
    FOREIGN KEY (account_id, claim_key) REFERENCES claims (account_id, claim_key)
        ON DELETE CASCADE
);

-- The contacts, conversation entries and deny list (Switch wire 6.2, 7.4.6).
CREATE TABLE list_entries (
    account_id  TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    list        TEXT    NOT NULL CHECK (list IN ('contact', 'conversation', 'deny')),
    pubky       BYTEA   NOT NULL CHECK (octet_length(pubky) = 32),
    -- The app that wrote it.
    written_by  BYTEA   NOT NULL CHECK (octet_length(written_by) = 16),
    at_ms       BIGINT  NOT NULL CHECK (at_ms >= 0),
    PRIMARY KEY (account_id, list, pubky)
);

-- Invite codes, by code hash (Switch spec 7, Switch wire 6.2).
CREATE TABLE invite_codes (
    account_id    TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    code_hash     BYTEA   NOT NULL CHECK (octet_length(code_hash) = 32),
    max_uses      BIGINT  NOT NULL CHECK (max_uses > 0),
    uses          BIGINT  NOT NULL DEFAULT 0 CHECK (uses >= 0 AND uses <= max_uses),
    -- The app that wrote it.
    writer        BYTEA   NOT NULL CHECK (octet_length(writer) = 16),
    expires_at_ms BIGINT  NOT NULL CHECK (expires_at_ms >= 0),
    -- The code's context as JSON, shown in the clear (Switch wire 7.4.6).
    context       BYTEA   NOT NULL,
    PRIMARY KEY (account_id, code_hash)
);

-- Batch records (Switch wire 6.4 step 5, 9.1): a batch's ID, its operation hash, and its
-- proofs while they are kept.
CREATE TABLE batches (
    account_id  TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    batch_id    BYTEA   NOT NULL CHECK (octet_length(batch_id) = 16),
    ops_hash    BYTEA   NOT NULL CHECK (octet_length(ops_hash) = 32),
    -- The transition proofs as a JSON array; null once dropped.
    proofs      BYTEA,
    at_ms       BIGINT  NOT NULL CHECK (at_ms >= 0),
    generation  BIGINT  NOT NULL CHECK (generation >= 0),
    first_seq   BIGINT  NOT NULL CHECK (first_seq > 0),
    last_seq    BIGINT  NOT NULL CHECK (last_seq >= first_seq),
    PRIMARY KEY (account_id, batch_id)
);

-- A key bundle part's chain item is shown in full only to its target app (Switch wire 7.5).
ALTER TABLE chain_items
    ADD COLUMN only_for BYTEA CHECK (octet_length(only_for) = 16);
