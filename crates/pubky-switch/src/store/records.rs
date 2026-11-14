//! The records a `GET /records` page lists (Switch wire 7.4.9), read from the request's
//! snapshot after the lock ([`SnapshotRead`]), so a page is the state at the request's
//! stamped service time however many reads it takes.

use sqlx::Row;

use super::{
    SnapshotRead, StoreError, StoredRecord, from_db,
    ops::{RECORD_COLUMNS, record_of},
    to_db,
};

impl SnapshotRead {
    /// Up to `limit` current records of `collection` that a holder of the scopes `held`
    /// may read, deleted ones left out, whose keys' base64url text comes after `after`
    /// (`""` for the first), ordered by that text compared as ASCII (wire 7.4.9).
    ///
    /// A record's `read_scope` is held by equal strings, or by its parent name when it is a
    /// sub-scope `name:<sub>`: the rule of [`pubky_switch_core::scopes::holds`] (wire 3.1),
    /// applied by the query so a page reads only what it may show. Every `read_scope` a
    /// record holds passed the scope rule at its write (6.2), so splitting at the first `:`
    /// gives the parent `holds` takes.
    pub async fn readable_records(
        &mut self,
        collection: &[u8; 32],
        held: &[String],
        after: &str,
        limit: u64,
    ) -> Result<Vec<StoredRecord>, StoreError> {
        let id = self.id.clone();
        // The page's keys come from the list's index alone (`shared_records_by_key_text`),
        // which passes over the records the reader can't read without reading their rows; then
        // the rows it shows are read by key, the account's only (another account can hold a
        // record at the same key), in the page's order. The index-only scan skips the rows only
        // where the visibility map marks them all-visible, which vacuuming keeps: on a
        // 10,000-record collection an empty page took 12.7 ms freshly loaded, 4.5
        // ms with 5% rewritten and 0.9 to 1.8 ms vacuumed. Either way a page's work is
        // bounded by the collection's live records, not by the page.
        let rows = sqlx::query(&format!(
            "WITH page AS (SELECT key, key_text FROM shared_records \
             WHERE account_id = $1 AND collection = $2 AND NOT deleted AND key_text > $3 \
             AND (read_scope = ANY($4) \
                  OR (strpos(read_scope, ':') > 0 AND split_part(read_scope, ':', 1) = ANY($4))) \
             ORDER BY key_text LIMIT $5) \
             SELECT {RECORD_COLUMNS} FROM page JOIN shared_records USING (key) \
             WHERE account_id = $1 ORDER BY page.key_text"
        ))
        .bind(id)
        .bind(collection.as_slice())
        .bind(after)
        .bind(held)
        .bind(to_db(limit, "a page's limit")?)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(StoreError::from_db)?;
        rows.iter().map(record_of).collect()
    }

    /// The last `seq` the account gave out, in this snapshot.
    pub async fn last_seq(&mut self) -> Result<u64, StoreError> {
        let id = self.id.clone();
        let row = sqlx::query("SELECT last_seq FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        from_db(row.try_get("last_seq")?, "last_seq")
    }
}
