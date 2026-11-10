//! The account's chain items (Switch wire 6.6). The chain head lives in the account row
//! ([`super::AccountHead::chain`]); this module keeps the items themselves.

use pubky_switch_core::chain::{ItemType, Stub};

use super::{AccountTxn, StoreError, identity::time_to_db, to_db};

/// A chain item to keep.
#[derive(Clone, Debug)]
pub struct NewChainItem<'a> {
    /// Its `seq`, which this request gave out.
    pub seq: u64,
    /// Its type.
    pub item_type: ItemType,
    /// The signed document's bytes.
    pub item_bytes: &'a [u8],
    /// Its stub.
    pub stub: &'a Stub,
    /// The service time it was chained at.
    pub server_time_ms: u64,
    /// The app it is shown in full to, for a key bundle part (Switch wire 7.5).
    pub only_for: Option<[u8; 16]>,
}

impl AccountTxn {
    /// Keep a chain item, and move the chain head to it. Its `seq` must be one this request
    /// gave out, after the current head.
    pub async fn append_chain_item(&mut self, item: &NewChainItem<'_>) -> Result<(), StoreError> {
        self.set_chain_head(item.seq, item.stub.chain_hash)?;
        let head = self.head().clone();
        sqlx::query(
            "INSERT INTO chain_items (account_id, generation, seq, item_type, item_bytes, \
             envelope, chain_hash, server_time_ms, only_for) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&head.id)
        .bind(to_db(head.generation, "generation")?)
        .bind(to_db(item.seq, "seq")?)
        .bind(item.item_type.as_str())
        .bind(item.item_bytes)
        .bind(item.stub.envelope.as_slice())
        .bind(item.stub.chain_hash.as_slice())
        .bind(time_to_db(item.server_time_ms)?)
        .bind(item.only_for.map(|app| app.to_vec()))
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }
}
