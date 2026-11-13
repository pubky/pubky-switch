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

-- A push key owed deleting: one a start minted, owed until the committed registration names
-- it, and one a replacement or a removal let go, owed until the key store deletes it. Its
-- deletion records no erasure.
ALTER TABLE erased_keys DROP CONSTRAINT erased_keys_reason_check;
ALTER TABLE erased_keys
    ADD CONSTRAINT erased_keys_reason_check CHECK (reason IN ('erasure', 'retired', 'push'));
