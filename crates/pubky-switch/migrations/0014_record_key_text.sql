-- GET /records lists a collection's records ordered by the base64url text of their keys,
-- compared as ASCII (Switch wire 7.4.9). That isn't the order of the keys' bytes: the
-- base64url alphabet runs A-Z, a-z, 0-9, '-', '_', and ASCII puts '-' and the digits first.
-- So each record keeps its key's text, unpadded base64url (wire 1.2), in the "C" collation,
-- which compares bytes, and a page reads its collection by that text from an index.
ALTER TABLE shared_records
    ADD COLUMN key_text TEXT COLLATE "C" NOT NULL
    GENERATED ALWAYS AS (translate(rtrim(encode(key, 'base64'), '='), '+/', '-_')) STORED;
CREATE INDEX shared_records_by_key_text ON shared_records (account_id, collection, key_text);
