//! Chain stub retention (Switch wire 7.4.4 "Checkpoints", 9.1): the account's latest
//! checkpoint, the newest stub dropped, and the bounded reads and deletes a request's sweep
//! makes, under the account's lock and in the request's transaction. Each read is bounded by
//! the caller and goes by an index: the chain's primary key, `batches_by_last_seq` and
//! `batches_spent`.

use pubky_switch_core::chain::SignedHead;
use sqlx::Row;

use super::{AccountTxn, StoreError, from_db, to_db};

/// What the account keeps for chain stub retention.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainRetention {
    /// The latest checkpoint (wire 7.4.4), absent before the first.
    pub checkpoint: Option<SignedHead>,
    /// The newest stub dropped: its `seq` and chain hash (wire 9.1), absent before the
    /// first drop.
    pub dropped: Option<(u64, [u8; 32])>,
}

/// A kept chain stub as the sweep reads it: no document and no envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeptStub {
    /// Its `seq`.
    pub seq: u64,
    /// The service time it was chained at, its envelope's `server_time`.
    pub server_time_ms: u64,
    /// The chain hash there.
    pub chain_hash: [u8; 32],
}

fn hash32(bytes: &[u8], what: &'static str) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| StoreError::Corrupt(what))
}

/// The checkpoint as stored: the signed head's JSON (wire 6.7).
pub(super) fn decode_checkpoint(bytes: &[u8]) -> Result<SignedHead, StoreError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt("checkpoint"))?;
    SignedHead::from_value(&value).map_err(|_| StoreError::Corrupt("checkpoint"))
}

impl AccountTxn {
    /// The account's latest checkpoint and newest dropped stub.
    pub async fn chain_retention(&mut self) -> Result<ChainRetention, StoreError> {
        let id = self.head().id.clone();
        let Some(row) = sqlx::query(
            "SELECT checkpoint, dropped_seq, dropped_chain_hash FROM chain_retention \
             WHERE account_id = $1",
        )
        .bind(id)
        .fetch_optional(self.conn())
        .await
        .map_err(StoreError::from_db)?
        else {
            return Ok(ChainRetention::default());
        };
        let checkpoint: Option<Vec<u8>> = row.try_get("checkpoint")?;
        let dropped_seq: Option<i64> = row.try_get("dropped_seq")?;
        let dropped_hash: Option<Vec<u8>> = row.try_get("dropped_chain_hash")?;
        let dropped = match (dropped_seq, dropped_hash) {
            (Some(seq), Some(hash)) => Some((
                from_db(seq, "dropped_seq")?,
                hash32(&hash, "dropped_chain_hash")?,
            )),
            (None, None) => None,
            _ => return Err(StoreError::Corrupt("chain_retention")),
        };
        Ok(ChainRetention {
            checkpoint: checkpoint.as_deref().map(decode_checkpoint).transpose()?,
            dropped,
        })
    }

    /// At most `limit` of the kept chain stubs after `after`, in the generation served, the
    /// oldest first: a range scan of the chain's primary key that reads no document.
    pub async fn kept_stubs(
        &mut self,
        after: u64,
        limit: u64,
    ) -> Result<Vec<KeptStub>, StoreError> {
        let head = self.head().clone();
        let rows = sqlx::query(
            "SELECT seq, server_time_ms, chain_hash FROM chain_items \
             WHERE account_id = $1 AND generation = $2 AND seq > $3 ORDER BY seq LIMIT $4",
        )
        .bind(&head.id)
        .bind(to_db(head.generation, "generation")?)
        .bind(to_db(after, "seq")?)
        .bind(to_db(limit, "limit")?)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                let hash: Vec<u8> = row.try_get("chain_hash")?;
                Ok(KeptStub {
                    seq: from_db(row.try_get("seq")?, "seq")?,
                    server_time_ms: from_db(row.try_get("server_time_ms")?, "server_time_ms")?,
                    chain_hash: hash32(&hash, "chain_hash")?,
                })
            })
            .collect()
    }

    /// The first `seq` of the batch that `seq` lies inside of, before its last item, in the
    /// generation served: one row of `batches_by_last_seq`, since batches don't overlap.
    /// `None` when `seq` ends a batch or belongs to none.
    pub async fn batch_across(&mut self, seq: u64) -> Result<Option<u64>, StoreError> {
        let head = self.head().clone();
        let row = sqlx::query(
            "SELECT first_seq FROM batches WHERE account_id = $1 AND generation = $2 \
             AND last_seq > $3 ORDER BY last_seq LIMIT 1",
        )
        .bind(&head.id)
        .bind(to_db(head.generation, "generation")?)
        .bind(to_db(seq, "seq")?)
        .fetch_optional(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let first = from_db(row.try_get("first_seq")?, "first_seq")?;
        Ok((first <= seq).then_some(first))
    }

    /// How many chain items there are after `after` in the generation served, counting no
    /// further than `up_to`.
    pub async fn chain_items_after(&mut self, after: u64, up_to: u64) -> Result<u64, StoreError> {
        let head = self.head().clone();
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM (SELECT 1 FROM chain_items WHERE account_id = $1 \
             AND generation = $2 AND seq > $3 LIMIT $4) AS counted",
        )
        .bind(&head.id)
        .bind(to_db(head.generation, "generation")?)
        .bind(to_db(after, "seq")?)
        .bind(to_db(up_to, "limit")?)
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        from_db(count, "count")
    }

    /// Keep `checkpoint` as the latest one, in place of any earlier.
    pub async fn keep_checkpoint(&mut self, checkpoint: &SignedHead) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO chain_retention (account_id, checkpoint, checkpoint_seq) \
             VALUES ($1, $2, $3) ON CONFLICT (account_id) DO UPDATE \
             SET checkpoint = EXCLUDED.checkpoint, checkpoint_seq = EXCLUDED.checkpoint_seq",
        )
        .bind(id)
        .bind(checkpoint.to_json())
        .bind(to_db(checkpoint.seq, "seq")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// Drop the chain items after `after` through `through`, in the generation served, and
    /// keep `through` as the newest stub dropped. The caller read them with
    /// [`Self::kept_stubs`], so the rows deleted are those it read. The number dropped.
    pub async fn drop_stubs_through(
        &mut self,
        after: u64,
        through: &KeptStub,
    ) -> Result<u64, StoreError> {
        let head = self.head().clone();
        let dropped = sqlx::query(
            "DELETE FROM chain_items WHERE account_id = $1 AND generation = $2 \
             AND seq > $3 AND seq <= $4",
        )
        .bind(&head.id)
        .bind(to_db(head.generation, "generation")?)
        .bind(to_db(after, "seq")?)
        .bind(to_db(through.seq, "seq")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?
        .rows_affected();
        sqlx::query(
            "UPDATE chain_retention SET dropped_seq = $2, dropped_chain_hash = $3 \
             WHERE account_id = $1",
        )
        .bind(&head.id)
        .bind(to_db(through.seq, "seq")?)
        .bind(through.chain_hash.as_slice())
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(dropped)
    }

    /// Delete at most `bound` batch records of the generation served whose proofs are gone
    /// and whose chain items all lie at or before `through`, the newest stub dropped, so
    /// none of their stubs is kept (wire 6.4 step 5, 9.1): a range scan of `batches_spent`.
    /// The number deleted.
    pub async fn drop_spent_batches(
        &mut self,
        through: u64,
        bound: u64,
    ) -> Result<u64, StoreError> {
        let head = self.head().clone();
        let dropped = sqlx::query(
            "DELETE FROM batches WHERE account_id = $1 AND batch_id IN ( \
                 SELECT batch_id FROM batches WHERE account_id = $1 AND generation = $2 \
                 AND proofs IS NULL AND last_seq <= $3 ORDER BY last_seq LIMIT $4)",
        )
        .bind(&head.id)
        .bind(to_db(head.generation, "generation")?)
        .bind(to_db(through, "seq")?)
        .bind(to_db(bound, "bound")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?
        .rows_affected();
        Ok(dropped)
    }
}
