-- The service's schema. Every table with an account column belongs to one account, and its
-- rows change only in a request holding the account's lock (Switch spec 6.5).
--
-- Signed documents are kept in their carrying form (Switch wire 2.2), exactly as received,
-- so a retry, a read or an export shows the bytes the writer signed. Sealed values stay
-- sealed: the service never holds the keys that open them (Switch spec 1).

-- One account per identity the service hosts (Switch spec 6.2).
--
-- The row holds the account's position: the last seq given out, the chain head and the
-- stamped service time. Every request to the account locks this row, so one account's
-- operations are serialized (Switch spec 6.5).
CREATE TABLE accounts (
    -- The identity's Pubky ID.
    id              TEXT     PRIMARY KEY,
    -- The identity's Ed25519 public key.
    identity_key    BYTEA    NOT NULL CHECK (octet_length(identity_key) = 32),
    -- The generation the account serves (Switch spec 12.6).
    generation      BIGINT   NOT NULL CHECK (generation >= 0),
    -- The ID of the generation's service key in the key store.
    service_key     TEXT     NOT NULL,
    -- The last seq given out in this generation, shared by inbox entries and chain items
    -- (Switch spec 6.3).
    last_seq        BIGINT   NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
    -- The newest chain item's seq and the chain hash there; both null before the first.
    chain_seq       BIGINT   CHECK (chain_seq > 0 AND chain_seq <= last_seq),
    chain_hash      BYTEA    CHECK (octet_length(chain_hash) = 32),
    -- The last service time the account stamped; it never goes back (Switch spec 10.1).
    stamped_time_ms BIGINT   NOT NULL DEFAULT 0 CHECK (stamped_time_ms >= 0),
    -- When the account was created, in service time.
    created_at_ms   BIGINT   NOT NULL CHECK (created_at_ms >= 0),
    -- The limits announced at the first enrollment, as the answer writes them; every later
    -- enrollment announces the same (Switch wire 3.7).
    announced_limits BYTEA   NOT NULL,
    -- The key store ID of the next generation's pending key, once an enrollment at the
    -- serving account asked for one (Switch wire 3.7).
    pending_key     TEXT,
    -- The newest identity.json the account holds, in its carrying form (Switch wire 2.2).
    identity_doc    BYTEA,
    -- The transition proof of the delivery that took it, in its carrying form; null for a
    -- version the account was enrolled with (Switch wire 7.4.2).
    identity_proof  BYTEA,
    -- The directory's versions (Switch wire 7.4.10): directory_version moves with every
    -- stored app record or receive key, apps_version when an app becomes reachable.
    directory_version BIGINT NOT NULL DEFAULT 0 CHECK (directory_version >= 0),
    apps_version    BIGINT   NOT NULL DEFAULT 0 CHECK (apps_version >= 0),
    -- The recovery the generation the account serves began with (Switch spec 12.6; Switch
    -- wire 3.3, 3.7, 7.4.2, 7.4.12): the generation it declares lost, and the `recovery`
    -- transition's service time. Both null for a generation that began any other way.
    -- `GET /apps` reports it as `recovery` while the account serves the generation after
    -- `recovery_from`.
    recovery_from   BIGINT   CHECK (recovery_from >= 1),
    recovery_declared_at_ms BIGINT CHECK (recovery_declared_at_ms >= 0),
    -- Staged admission after a provider loss (Switch spec 12.6 step 2; Switch wire 7.4.14):
    -- set at the `recovery` transition when the recovery document lists an app, cleared for
    -- good at `POST /recovery/admission` or at the first qualifying upload. It counts only
    -- while the account serves the generation the recovery began (`recovery_from`).
    admission_staged BOOLEAN NOT NULL DEFAULT false,
    -- The service time of an account's last once-a-minute sweep (Switch wire 9.1): forgotten
    -- deleted keys, spent invite codes and batch proofs past `batch_proofs_ms` go at most
    -- once a minute of service time, at a request to the account. Kept with the account, so
    -- the minute holds across instances and restarts; null before the first.
    swept_at_ms     BIGINT   CHECK (swept_at_ms >= 0),
    CHECK ((chain_seq IS NULL) = (chain_hash IS NULL)),
    CHECK (identity_proof IS NULL OR identity_doc IS NOT NULL),
    CHECK ((recovery_from IS NULL) = (recovery_declared_at_ms IS NULL))
);

-- App IDs the account keeps for good: revoked, departed, or named by an enrollment's
-- revoked_apps, so they are never current again (Switch wire 3.3, 3.7, 9.1).
CREATE TABLE kept_app_ids (
    account_id  TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    app_id      BYTEA   NOT NULL CHECK (octet_length(app_id) = 16),
    -- Why it is kept: 'revoked', 'departed' or 'enrolled'.
    reason      TEXT    NOT NULL CHECK (reason IN ('revoked', 'departed', 'enrolled')),
    -- The service time it was revoked, departed, or the enrollment that named it.
    at_ms       BIGINT  NOT NULL CHECK (at_ms >= 0),
    -- The newest document's data_epoch when the app was revoked or departed; null for App
    -- IDs an enrollment named. A departure's rotation is done once a delivered identity.json
    -- lists it in removed with a higher data_epoch than this, and stays done whatever later
    -- documents hold: the service doesn't refuse a document that lowers data_epoch (Switch
    -- wire 3.3).
    data_epoch  BIGINT  CHECK (data_epoch >= 0),
    rotated     BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (account_id, app_id)
);

-- The chain: one row per chain item of a generation (Switch wire 6.6). Inbox entries and
-- cursor moves take seqs too, so seqs have gaps.
CREATE TABLE chain_items (
    account_id   TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    generation   BIGINT  NOT NULL CHECK (generation >= 0),
    seq          BIGINT  NOT NULL CHECK (seq > 0),
    -- 'op', 'identity' or 'service'.
    item_type    TEXT    NOT NULL CHECK (item_type IN ('op', 'identity', 'service')),
    -- The signed document's bytes (Switch wire 2.2); null once the document is deleted
    -- and only its stub is kept (Switch wire 7.5).
    item_bytes   BYTEA,
    -- The chain envelope's exact JSON bytes; with chain_hash, the item's stub.
    envelope     BYTEA   NOT NULL,
    chain_hash   BYTEA   NOT NULL CHECK (octet_length(chain_hash) = 32),
    server_time_ms BIGINT NOT NULL CHECK (server_time_ms >= 0),
    -- A key bundle part's chain item is shown in full only to its target app (Switch wire
    -- 7.5).
    only_for     BYTEA   CHECK (octet_length(only_for) = 16),
    -- A signed operation's transition proof, shown with its chain item while the item's
    -- document is kept (Switch wire 7.4.4, 7.5). A batch record keeps its proofs only for
    -- batch_proofs_ms (9.1), so the chain item keeps its own.
    proof        BYTEA,
    -- The App ID an `app.put` or `cert.put` document concerns, so the documents of an app
    -- whose record or renewed certificate changes are found without reading every item;
    -- null for every other item, and once the document is deleted (Switch wire 7.5).
    doc_app      BYTEA,
    PRIMARY KEY (account_id, generation, seq),
    CHECK (proof IS NULL OR item_type = 'op'),
    CONSTRAINT chain_items_doc_app_length CHECK (doc_app IS NULL OR octet_length(doc_app) = 16)
);
-- The `app.put` and `cert.put` items of an app, by `doc_app`: a change to the app's record
-- or renewed certificate finds its earlier documents without reading every item.
CREATE INDEX chain_items_by_doc_app ON chain_items (account_id, doc_app)
    WHERE doc_app IS NOT NULL;

-- The enrollments an account answered, so the same enrollment again gets the same answer
-- (Switch wire 3.7): by the document hash of the signed enrollment, the key that answered it.
-- At most max_enrollments per account are kept; the oldest drops (Switch wire 9.1), and the
-- answer to the enrollment that created the account is never dropped.
CREATE TABLE enrollment_answers (
    account_id       TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    enrollment_hash  BYTEA   NOT NULL CHECK (octet_length(enrollment_hash) = 32),
    -- The key store ID of the service key the answer named.
    service_key      TEXT    NOT NULL,
    -- When it was first answered, in service time.
    answered_at_ms   BIGINT  NOT NULL CHECK (answered_at_ms >= 0),
    -- The order answers were kept in; the oldest drops first.
    kept_order       BIGINT  GENERATED ALWAYS AS IDENTITY,
    -- The answer to the enrollment that created the account.
    creating         BOOLEAN NOT NULL,
    -- An answer may drop only while the service would build it again byte for byte (Switch
    -- wire 3.7, 9.1): one naming the pending key, which every later enrollment at the
    -- serving account gets too. Every other answer is kept as long as the account: the
    -- creating enrollment's and every one given while the account was staged, which named
    -- the account's key, where a rebuild at the serving account would name the pending key.
    rebuildable      BOOLEAN NOT NULL,
    PRIMARY KEY (account_id, enrollment_hash)
);
CREATE UNIQUE INDEX enrollment_answers_one_creating ON enrollment_answers (account_id)
    WHERE creating;

-- The state signed operations change (Switch wire 6.2, 6.8): apps, receive keys, key bundle
-- parts, shared records, claims, the lists, invite codes and batch records.

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
    -- The seq of the key bundle part that completed the app's full-bundle request (Switch
    -- wire 6.2): the request stays in force for dropping passed parts until the app's cursor
    -- has passed it, so the app reads every part it asked for before any of them goes.
    full_completed_seq BIGINT CHECK (full_completed_seq > 0),
    -- An app marked lagging: entries no longer wait for it (Switch wire 7.4.4). Set at the
    -- requests that bring the pressure, with trusted time; cleared at the app's feed read.
    lagging         BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (account_id, app_id),
    CHECK ((cursor_generation IS NULL) = (cursor_seq IS NULL))
);

-- Every receive key record any app registered, current or retired: a kid is never registered
-- twice in an account (Switch spec 3.6). A purged app's kids stay registered (Switch spec 3.6
-- "Kids are unique", wire 9.1): the purge clears the app's receive key records and keeps
-- each of its kids with its App ID, so no app registers one of them again and an envelope
-- wrapped to one is told the app isn't current. A row with no record is such a kept kid.
CREATE TABLE receive_keys (
    account_id  TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    kid         BYTEA   NOT NULL CHECK (octet_length(kid) = 8),
    app_id      BYTEA   NOT NULL CHECK (octet_length(app_id) = 16),
    n           BIGINT  NOT NULL CHECK (n >= 0),
    record      BYTEA,
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
    -- The signed record.put, and its transition proof for a write made here.
    op            BYTEA    NOT NULL,
    proof         BYTEA,
    -- GET /records lists a collection's records ordered by the base64url text of their
    -- keys, compared as ASCII (Switch wire 7.4.9). That isn't the order of the keys' bytes:
    -- the base64url alphabet runs A-Z, a-z, 0-9, '-', '_', and ASCII puts '-' and the digits
    -- first. So each record keeps its key's text, unpadded base64url (wire 1.2), in the "C"
    -- collation, which compares bytes, and a page reads its collection by that text from an
    -- index.
    key_text      TEXT     COLLATE "C" NOT NULL
        GENERATED ALWAYS AS (translate(rtrim(encode(key, 'base64'), '='), '+/', '-_')) STORED,
    -- Where the record's current write came from (Switch wire 7.4.14, 7.4.9, 10.3; Switch
    -- spec 12.6 step 3):
    -- - a write made here carries its transition proof. `upload_base` is the uploaded
    --   version that the first write here built on, with its operation's hash, or null when
    --   the writes here built on none; a later upload newer than it is divergent, and that
    --   operation again changes nothing;
    -- - a write taken from an upload carries no proof (the lost service's proofs date
    --   nothing here). `upload_seq` is the `upload` transition that listed it, which the
    --   record view shows as its `seq`. `version_exact` is false when no proof gave its
    --   version and it holds the lower bound.
    from_upload   BOOLEAN  NOT NULL DEFAULT false,
    upload_seq    BIGINT   CHECK (upload_seq > 0),
    version_exact BOOLEAN  NOT NULL DEFAULT true,
    upload_base_generation BIGINT CHECK (upload_base_generation >= 0),
    upload_base_version BIGINT CHECK (upload_base_version > 0),
    upload_base_op_hash BYTEA CHECK (octet_length(upload_base_op_hash) = 32),
    PRIMARY KEY (account_id, key),
    CHECK (NOT deleted OR value_bytes = 0),
    CHECK (
        (from_upload AND proof IS NULL AND upload_seq IS NOT NULL
            AND upload_base_generation IS NULL AND upload_base_version IS NULL
            AND upload_base_op_hash IS NULL)
        OR (NOT from_upload AND proof IS NOT NULL AND upload_seq IS NULL AND version_exact
            AND (upload_base_generation IS NULL) = (upload_base_version IS NULL)
            AND (upload_base_generation IS NULL) = (upload_base_op_hash IS NULL))
    )
);
-- A feed page reads the documents still current among the seqs it covers.
CREATE INDEX shared_records_by_version ON shared_records (account_id, generation, version);
-- A list leaves deleted records out and shows only those whose read_scope the reader holds:
-- the index holds the live records only, with their read_scope and key, so a page chooses
-- its keys from the index alone, passing over the records the reader can't read without
-- reading their rows, and then reads the rows it shows by key.
CREATE INDEX shared_records_by_key_text ON shared_records (account_id, collection, key_text)
    INCLUDE (read_scope, key) WHERE NOT deleted;
-- The deleted keys written here, by the position of their delete (Switch wire 9.1): the
-- sweep finds whether there is one with a single lookup, and forgets them by a range scan
-- up to the lowest cursor they wait for (Switch spec 10.3). It holds deleted keys only,
-- which leave it once forgotten.
CREATE INDEX shared_records_deleted ON shared_records (account_id, generation, version)
    WHERE deleted AND NOT from_upload;

-- The uploads that conflict with a record, kept until a write here (Switch wire 9.1, at most
-- `max_divergent_uploads` per record), each at its place among them from 0, as an export's
-- `divergent` parts carry them.
CREATE TABLE divergent_uploads (
    account_id  TEXT      NOT NULL,
    key         BYTEA     NOT NULL CHECK (octet_length(key) = 32),
    position    SMALLINT  NOT NULL CHECK (position >= 0),
    -- The uploaded signed record.put, and hash() of its bytes, which recognizes it again.
    op          BYTEA     NOT NULL,
    op_hash     BYTEA     NOT NULL CHECK (octet_length(op_hash) = 32),
    PRIMARY KEY (account_id, key, position),
    UNIQUE (account_id, key, op_hash),
    FOREIGN KEY (account_id, key) REFERENCES shared_records (account_id, key) ON DELETE CASCADE
);

-- Claims, by claim key (Switch wire 6.8). The claim's state is the service's own encoding;
-- creator, tombstone and open_owners repeat what the per-app limits count, so they are
-- counted without reading every claim.
--
-- When a claim may be deleted (Switch wire 6.8, 7.3 step 4): a tombstone or a failed claim
-- whose attempts are all done or failed, from its pinned deadline plus the reconciliation
-- window, or, pinned to no deadline, max_claim_age_ms after its last entry. The service
-- writes these with the claim's state, from the core's rule, so step 4 deletes with an
-- indexed query; the age is applied when it deletes, so a raised max_claim_age_ms applies
-- to every claim.
CREATE TABLE claims (
    account_id   TEXT     NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    claim_key    BYTEA    NOT NULL CHECK (octet_length(claim_key) = 32),
    state        BYTEA    NOT NULL,
    creator      BYTEA    CHECK (octet_length(creator) = 16),
    tombstone    BOOLEAN  NOT NULL,
    -- The owner of each attempt open or unknown, once per attempt.
    open_owners  BYTEA[]  NOT NULL,
    -- Pinned to a deadline: the deadline plus the reconciliation window. Null otherwise,
    -- or while the claim may not be deleted.
    delete_after_ms BIGINT CHECK (delete_after_ms >= 0),
    -- Pinned to no deadline: its last entry's time. Null otherwise, or while the claim may
    -- not be deleted.
    delete_after_entry_ms BIGINT CHECK (delete_after_entry_ms >= 0),
    PRIMARY KEY (account_id, claim_key)
);
CREATE INDEX claims_due_at_deadline ON claims (account_id, delete_after_ms)
    WHERE delete_after_ms IS NOT NULL;
CREATE INDEX claims_due_after_entry ON claims (account_id, delete_after_entry_ms)
    WHERE delete_after_entry_ms IS NOT NULL;

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
-- A feed page reads the documents still current among the seqs it covers.
CREATE INDEX claim_entries_by_seq ON claim_entries (account_id, seq);

-- The contacts, conversation entries and deny list (Switch wire 6.2, 7.4.6). A conversation
-- entry the service writes for a sender an invite code admitted names the code and its
-- context, and no app (Switch wire 7.4.6). An entry's last admitted append is kept for
-- pruning.
CREATE TABLE list_entries (
    account_id  TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    list        TEXT    NOT NULL CHECK (list IN ('contact', 'conversation', 'deny')),
    pubky       BYTEA   NOT NULL CHECK (octet_length(pubky) = 32),
    -- The app that wrote it.
    written_by  BYTEA   CHECK (octet_length(written_by) = 16),
    at_ms       BIGINT  NOT NULL CHECK (at_ms >= 0),
    code_hash   BYTEA   CHECK (octet_length(code_hash) = 32),
    context     BYTEA,
    last_used_ms BIGINT CHECK (last_used_ms >= 0),
    PRIMARY KEY (account_id, list, pubky),
    CHECK (written_by IS NOT NULL OR (list = 'conversation' AND code_hash IS NOT NULL))
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
    -- The code's context as JSON, as its writer wrote it, shown in the clear (Switch wire
    -- 7.4.6).
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
-- The batches that still keep their transition proofs, oldest first: the sweep drops those
-- past `batch_proofs_ms` by a range scan, not by reading every batch the account has had,
-- since batch records stay while their chain stubs do.
CREATE INDEX batches_with_proofs ON batches (account_id, at_ms, batch_id)
    WHERE proofs IS NOT NULL;
-- The batch a chain item falls in, by its last `seq`: a sweep that would cut inside a batch
-- finds it with one lookup and stops before its first item (Switch wire 7.4.4).
CREATE INDEX batches_by_last_seq ON batches (account_id, generation, last_seq);
-- The batch records whose proofs are gone, by their last `seq`: the sweep deletes those whose
-- stubs are all dropped by a range scan that reads none whose proofs are still kept.
CREATE INDEX batches_spent ON batches (account_id, generation, last_seq) WHERE proofs IS NULL;

-- What GET /apps reports of each app beyond its row (Switch wire 7.4.12): the data epoch of
-- the first identity.json that listed each app, where its keys_through starts. Written when
-- a document lists an app for the first time, at an enrollment that carries one or at a
-- delivery, and raised as the key bundle parts the app passed go; a later listing never
-- dates it again.
CREATE TABLE app_listings (
    account_id      TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    app_id          BYTEA   NOT NULL CHECK (octet_length(app_id) = 16),
    listed_epoch    BIGINT  NOT NULL CHECK (listed_epoch >= 0),
    PRIMARY KEY (account_id, app_id)
);

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
    -- The App IDs the copy lists in removed, so a removed app is answered like a stranger
    -- without the document being read (Switch wire 7.2): the same work whether or not a
    -- copy is held.
    removed      BYTEA[] NOT NULL DEFAULT '{}',
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

-- The inbox (Switch wire 7.4.3, 7.4.4, 7.5, 9.1). It holds three kinds of item, each at a seq
-- of its own, as an export's `entry` part does (10.3):
-- - `entry`: an envelope a sender appended, for its target apps, from its acceptance until
--   every current target's cursor has passed it;
-- - `unreadable`: an entry no current app can open after its targets departed, for every
--   current app. It keeps the entry's entry_id, sender and acceptance time, and its envelope
--   is gone; it counts entry_overhead_bytes against the inbox quota;
-- - `missed`: for its one target, a lagging app, how many entries targeting it the service
--   deleted before it read them, and the first and last of their acceptance times. It has no
--   sender and counts against nothing.
CREATE TABLE inbox_entries (
    account_id      TEXT     NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    generation      BIGINT   NOT NULL CHECK (generation >= 0),
    seq             BIGINT   NOT NULL CHECK (seq > 0),
    entry_id        BYTEA    CHECK (octet_length(entry_id) = 16),
    -- The sender identity and app, and the certificate the feed shows with the entry.
    sender          BYTEA    CHECK (octet_length(sender) = 32),
    sender_app      BYTEA    CHECK (octet_length(sender_app) = 16),
    cert            BYTEA,
    accepted_at_ms  BIGINT   NOT NULL CHECK (accepted_at_ms >= 0),
    -- The envelope as received, sealed: the service never holds the keys that open it.
    envelope        BYTEA    NOT NULL,
    -- BLAKE3 of the envelope: a retry by content is the same envelope from the same sender
    -- identity (7.4.3 check 1).
    envelope_hash   BYTEA    CHECK (octet_length(envelope_hash) = 32),
    -- The apps it was wrapped to.
    targets         BYTEA[]  NOT NULL,
    -- The invite code's context, as its writer wrote it, when a code admitted the sender.
    context         BYTEA,
    -- The answer the append got, which a retry by content gets again.
    answer          BYTEA,
    -- What it counts against the inbox quota: its envelope's bytes and the entry overhead.
    quota_bytes     BIGINT   NOT NULL CHECK (quota_bytes >= 0),
    kind            TEXT     NOT NULL DEFAULT 'entry'
        CHECK (kind IN ('entry', 'unreadable', 'missed')),
    missed_entries  BIGINT   CHECK (missed_entries > 0),
    missed_from_ms  BIGINT   CHECK (missed_from_ms >= 0),
    missed_until_ms BIGINT   CHECK (missed_until_ms >= 0),
    PRIMARY KEY (account_id, generation, seq),
    CHECK (
        (kind = 'missed'
            AND missed_entries IS NOT NULL AND missed_from_ms IS NOT NULL
            AND missed_until_ms IS NOT NULL AND quota_bytes = 0)
        OR (kind <> 'missed'
            AND missed_entries IS NULL AND missed_from_ms IS NULL AND missed_until_ms IS NULL
            AND entry_id IS NOT NULL AND sender IS NOT NULL AND sender_app IS NOT NULL
            AND cert IS NOT NULL AND envelope_hash IS NOT NULL AND answer IS NOT NULL
            AND quota_bytes > 0)
    )
);
-- Also serves each sender's usage of the inbox quota, by its prefix.
CREATE UNIQUE INDEX inbox_entries_by_content ON inbox_entries (account_id, sender, envelope_hash);

-- Each sender identity's hits against the append limits (Switch wire 9.4 Flags), at most
-- `max_flags` per account: the least frequent drop, of those the one hit longest ago.
CREATE TABLE sender_flags (
    account_id   TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    pubky        BYTEA   NOT NULL CHECK (octet_length(pubky) = 32),
    hits         BIGINT  NOT NULL CHECK (hits > 0),
    last_hit_ms  BIGINT  NOT NULL CHECK (last_hit_ms >= 0),
    PRIMARY KEY (account_id, pubky)
);

-- The signer hand-over the switch holds for the account (Switch wire 7.4.17, 3.12): at most
-- one, replaced by the next PUT /handover. The body is the PUT's, byte for byte, which GET
-- /handover answers. It is deleted when the account takes the next identity.json version,
-- and with the account (erasure, 7.4.16). It isn't exported and counts against no quota.
CREATE TABLE handovers (
    account_id      TEXT    PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    target_app_id   BYTEA   NOT NULL CHECK (octet_length(target_app_id) = 16),
    body            BYTEA   NOT NULL
);

-- The key store entries owed deleting (Switch wire 7.4.16): an erased account's service key
-- with its mark, and a pending key of the next generation. Written in the same transaction
-- that deletes the account, so the deletion is owed durably the moment the account is gone;
-- the service deletes each key, records the erasure in the key store's ledger (spec 6.5),
-- then drops the row: at once, and again at start for any a failure or a crash left. No
-- foreign key: the account is gone by then.
CREATE TABLE erased_keys (
    key_id          TEXT    PRIMARY KEY,
    account_id      TEXT    NOT NULL,
    erased_at_ms    BIGINT  NOT NULL CHECK (erased_at_ms >= 0),
    -- Why a key is owed deleting: an erasure, whose deletion the key store's ledger records
    -- (spec 6.5); a generation change that retired it, at an account that lives on; or a
    -- push key (Switch wire 8.1), one a start minted, owed until the committed registration
    -- names it, and one a replacement or a removal let go, owed until the key store deletes
    -- it, whose deletion records no erasure.
    reason          TEXT    NOT NULL DEFAULT 'erasure'
        CHECK (reason IN ('erasure', 'retired', 'push'))
);
-- Whether an identity's erased account still owes keys: read when a request finds no account
-- for the identity, so the operator's 404 waits until they are gone.
CREATE INDEX erased_keys_by_account ON erased_keys (account_id);

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

-- Pending connect requests (Switch spec 7, Switch wire 7.4.7): a content-free request from
-- a sender identity to be invited, kept until it is answered by a list entry for the
-- sender (a contact, a conversation entry or a deny list entry) or declined. Only the
-- sender's Pubky ID and when it asked are kept; one row per sender. The policy's
-- `max_pending`, capped by `max_connect_pending`, bounds the rows in code, since the cap
-- is the identity's own setting.
CREATE TABLE connect_requests (
    account_id  TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    pubky       BYTEA   NOT NULL CHECK (octet_length(pubky) = 32),
    at_ms       BIGINT  NOT NULL CHECK (at_ms >= 0),
    PRIMARY KEY (account_id, pubky)
);
-- Read oldest first (`GET /connect`).
CREATE INDEX connect_requests_by_time ON connect_requests (account_id, at_ms, pubky);

-- Push registrations (Switch spec 9, Switch wire 8.1): one per own app, while the app is
-- current. The push key's secret half lives in the key store, never here: a row names it by
-- its key store ID and keeps its public half, which the answers carry. The handles are the
-- relay's opaque ones, at most 8. Removed with the app's currency, at a recovery in place
-- and at an erasure; each time the push key is owed deleting first, in `erased_keys`, in the
-- same transaction. No foreign key to `apps`, whose cascade would take a registration with a
-- deleted app row, its key unowed: an app's registration goes when it stops being current,
-- before any purge of its row.
CREATE TABLE push_registrations (
    account_id   TEXT    NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    app_id       BYTEA   NOT NULL CHECK (octet_length(app_id) = 16),
    relay_url    TEXT    NOT NULL,
    push_key_id  TEXT    NOT NULL UNIQUE,
    push_public  BYTEA   NOT NULL CHECK (octet_length(push_public) = 32),
    handles      TEXT[]  NOT NULL CHECK (cardinality(handles) <= 8),
    set_at_ms    BIGINT  NOT NULL CHECK (set_at_ms >= 0),
    PRIMARY KEY (account_id, app_id)
);

-- Push deliveries (Switch spec 9 step 4, Switch wire 8.2): one webhook owed to one handle of
-- a registration for one `notify` entry, queued in the append's transaction and sent by a
-- background worker. A row holds what sending and retrying need and nothing of the message:
-- the webhook carries only the handle. Its body, `ts` and `nonce`, is made at each attempt,
-- since `ts` is the time it is sent and each nonce is fresh.
--
-- A row goes with its registration (the cascade, at a removal, a recovery in place and an
-- erasure), at a replacement and when its handle leaves the list (`store::push`), once
-- delivered, and after its last attempt: at most 3, within 1 minute of its entry.
CREATE TABLE push_deliveries (
    id               BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id       TEXT    NOT NULL,
    app_id           BYTEA   NOT NULL CHECK (octet_length(app_id) = 16),
    -- The push key the registration held when the row was queued: a row under another key
    -- is never sent.
    push_key_id      TEXT    NOT NULL,
    handle           TEXT    NOT NULL,
    -- The entry's service time.
    entry_at_ms      BIGINT  NOT NULL CHECK (entry_at_ms >= 0),
    attempts         INT     NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    -- When the row may next be claimed: due at its entry; each claim leases it until a
    -- retry would be due, so one instance sends it at a time.
    next_attempt_ms  BIGINT  NOT NULL CHECK (next_attempt_ms >= 0),
    FOREIGN KEY (account_id, app_id)
        REFERENCES push_registrations (account_id, app_id) ON DELETE CASCADE
);
CREATE INDEX push_deliveries_due ON push_deliveries (next_attempt_ms);
CREATE INDEX push_deliveries_by_app ON push_deliveries (account_id, app_id);

-- Chain stub retention (Switch wire 7.4.4 "Checkpoints", 9.1): the account's latest
-- checkpoint and the newest chain stub it dropped, one row per account once it has either.
-- A recovery in place empties it with the rest of the generation's state (wire 3.3), and an
-- erasure with the account.
--
-- The checkpoint is the signed head's JSON (wire 6.7) and its `seq`; the newest dropped
-- stub its `seq` and chain hash, which an export's checkpoint signs (wire 10.2). Each pair is
-- all null or all set: a checkpoint comes before the first drop, and a drop never goes past
-- the checkpoint.
CREATE TABLE chain_retention (
    account_id          TEXT    PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    checkpoint          BYTEA,
    checkpoint_seq      BIGINT  CHECK (checkpoint_seq > 0),
    dropped_seq         BIGINT  CHECK (dropped_seq > 0),
    dropped_chain_hash  BYTEA   CHECK (octet_length(dropped_chain_hash) = 32),
    CHECK ((checkpoint IS NULL) = (checkpoint_seq IS NULL)),
    CHECK ((dropped_seq IS NULL) = (dropped_chain_hash IS NULL)),
    CHECK (dropped_seq IS NULL OR dropped_seq <= checkpoint_seq)
);
