-- What the feed reads (Switch wire 7.4.4, 7.5).

-- A signed operation's transition proof, shown with its chain item while the item's
-- document is kept. A batch record keeps its proofs only for batch_proofs_ms (9.1), so the
-- chain item keeps its own.
ALTER TABLE chain_items
    ADD COLUMN proof BYTEA,
    ADD CHECK (proof IS NULL OR item_type = 'op');

-- Operations chained before this column existed take their proof from their batch's
-- record while it keeps them: a batch's operations take consecutive seqs, in the order of
-- its proofs (6.4). The JSON is re-encoded, which a reader of a signed document's two
-- members doesn't notice: the signed bytes are inside them, unchanged.
UPDATE chain_items AS c
    SET proof = convert_to(
        ((convert_from(b.proofs, 'UTF8')::jsonb) -> ((c.seq - b.first_seq)::int))::text,
        'UTF8')
    FROM batches AS b
    WHERE c.item_type = 'op'
      AND c.item_bytes IS NOT NULL
      AND b.proofs IS NOT NULL
      AND b.account_id = c.account_id
      AND b.generation = c.generation
      AND c.seq BETWEEN b.first_seq AND b.last_seq;

-- A page reads the documents still current among the seqs it covers.
CREATE INDEX shared_records_by_version ON shared_records (account_id, generation, version);
CREATE INDEX claim_entries_by_seq ON claim_entries (account_id, seq);
