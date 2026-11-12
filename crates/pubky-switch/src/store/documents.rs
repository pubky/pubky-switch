//! Deleting chain item documents no app may read any more (Switch wire 7.5): a superseded
//! record write, key bundle part, app record or renewed certificate, the entries of a
//! compacted or deleted claim. Each shows as its stub to every app once it isn't current,
//! whoever reads and wherever its cursor stands, so nothing a reader can be shown goes with
//! it. Its stub, which the chain, the signed heads and a later export verify by, stays; so
//! do the transition proofs apps hold, which name the stub, the record's current proof
//! (`shared_records`), a claim entry's (`claim_entries`) and a batch's for its retries
//! (`batches`), none of which this reads.
//!
//! The write paths note the items they may have superseded ([`AccountTxn::note_superseded`],
//! [`AccountTxn::note_app_documents`]); the transaction deletes, before it commits, those
//! the feed's own rule ([`super::CurrentDocs::shows_in_full_to_some_app`]) finds no app may
//! read. Documents chained before this rule are checked at the account's requests, a
//! bounded number at a time ([`AccountTxn::check_old_documents`]).

use pubky_switch_core::{
    ops::{OpKind, SignedOp},
    sig::SignedDoc,
};
use sqlx::Row;

use super::{AccountTxn, FeedRow, StoreError, from_db, to_db};

/// The App ID an `app.put` or `cert.put` document concerns, from its signed bytes; `None`
/// for any other item.
pub(super) fn doc_app_of(op: &SignedDoc) -> Option<[u8; 16]> {
    let op = SignedOp::peek(op).ok()?;
    match &op.body().kind {
        OpKind::AppPut { .. } => op.body().app_id,
        OpKind::CertPut { target_app_id, .. } => Some(*target_app_id),
        _ => None,
    }
}

impl AccountTxn {
    /// Note chain items at `seqs` this transaction may have superseded.
    pub(super) fn note_superseded(&mut self, seqs: impl IntoIterator<Item = u64>) {
        self.superseded.extend(seqs);
    }

    /// Note that `app`'s record or renewed certificate may have changed, so its earlier
    /// `app.put` and `cert.put` documents may be superseded.
    pub(super) fn note_app_documents(&mut self, app: [u8; 16]) {
        self.documents_of_apps.insert(app);
    }

    /// The chain items of the generation served among `seqs`, with their documents.
    async fn chain_rows(&mut self, seqs: &[i64]) -> Result<Vec<FeedRow>, StoreError> {
        let head = self.head().clone();
        let rows = sqlx::query(
            "SELECT seq, item_type, item_bytes, envelope, chain_hash, proof, only_for \
             FROM chain_items WHERE account_id = $1 AND generation = $2 AND seq = ANY($3) \
             AND item_bytes IS NOT NULL ORDER BY seq",
        )
        .bind(&head.id)
        .bind(to_db(head.generation, "generation")?)
        .bind(seqs)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        rows.iter().map(super::feed::row_of).collect()
    }

    /// Of the items at `seqs`, delete the documents no app may read in full any more, and
    /// their proofs; the others stay. The rows read, to see what stayed.
    async fn drop_documents_at(&mut self, seqs: &[i64]) -> Result<Vec<FeedRow>, StoreError> {
        let rows = self.chain_rows(seqs).await?;
        if rows.is_empty() {
            return Ok(rows);
        }
        let head = self.head().clone();
        let generation = to_db(head.generation, "generation")?;
        let at: Vec<i64> = rows
            .iter()
            .map(|row| to_db(row.seq, "seq"))
            .collect::<Result<_, _>>()?;
        let current = super::feed::current_docs_at(self.conn(), &head.id, generation, &at).await?;
        let mut stale = Vec::new();
        for row in &rows {
            if !current.shows_in_full_to_some_app(row)? {
                stale.push(to_db(row.seq, "seq")?);
            }
        }
        if !stale.is_empty() {
            sqlx::query(
                "UPDATE chain_items SET item_bytes = NULL, proof = NULL, doc_app = NULL \
                 WHERE account_id = $1 AND generation = $2 AND seq = ANY($3)",
            )
            .bind(&head.id)
            .bind(generation)
            .bind(&stale)
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        }
        Ok(rows
            .into_iter()
            .filter(|row| to_db(row.seq, "seq").is_ok_and(|seq| !stale.contains(&seq)))
            .collect())
    }

    /// Delete, before the commit, the documents this transaction superseded (the module's
    /// doc).
    pub(super) async fn drop_stale_documents(&mut self) -> Result<(), StoreError> {
        let mut seqs: Vec<i64> = std::mem::take(&mut self.superseded)
            .into_iter()
            .map(|seq| to_db(seq, "seq"))
            .collect::<Result<_, _>>()?;
        let apps: Vec<Vec<u8>> = std::mem::take(&mut self.documents_of_apps)
            .into_iter()
            .map(|app| app.to_vec())
            .collect();
        if !apps.is_empty() {
            let head = self.head().clone();
            let of_apps: Vec<i64> = sqlx::query_scalar(
                "SELECT seq FROM chain_items WHERE account_id = $1 AND generation = $2 \
                 AND doc_app = ANY($3)",
            )
            .bind(&head.id)
            .bind(to_db(head.generation, "generation")?)
            .bind(&apps)
            .fetch_all(self.conn())
            .await
            .map_err(StoreError::from_db)?;
            seqs.extend(of_apps);
        }
        if seqs.is_empty() {
            return Ok(());
        }
        seqs.sort_unstable();
        seqs.dedup();
        self.drop_documents_at(&seqs).await?;
        Ok(())
    }

    /// Check at most `bound` of the documents chained before this rule, oldest first:
    /// delete those no app may read in full any more, and note which app each remaining
    /// `app.put` and `cert.put` concerns, so a later change finds it. One indexed read of
    /// the account's row once every one is checked. The number checked.
    pub async fn check_old_documents(&mut self, bound: u64) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT documents_checked_seq, documents_check_end FROM accounts WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let checked = from_db(
            row.try_get("documents_checked_seq")?,
            "documents_checked_seq",
        )?;
        let end = from_db(row.try_get("documents_check_end")?, "documents_check_end")?;
        if checked >= end || bound == 0 {
            return Ok(0);
        }
        let through = checked.saturating_add(bound).min(end);
        let seqs: Vec<i64> = (checked.saturating_add(1)..=through)
            .map(|seq| to_db(seq, "seq"))
            .collect::<Result<_, _>>()?;
        let kept = self.drop_documents_at(&seqs).await?;
        let head = self.head().clone();
        let generation = to_db(head.generation, "generation")?;
        for row in &kept {
            if let Some(app) = row.item.as_ref().and_then(doc_app_of) {
                sqlx::query(
                    "UPDATE chain_items SET doc_app = $4 \
                     WHERE account_id = $1 AND generation = $2 AND seq = $3",
                )
                .bind(&head.id)
                .bind(generation)
                .bind(to_db(row.seq, "seq")?)
                .bind(app.to_vec())
                .execute(self.conn())
                .await
                .map_err(StoreError::from_db)?;
            }
        }
        sqlx::query("UPDATE accounts SET documents_checked_seq = $2 WHERE id = $1")
            .bind(&id)
            .bind(to_db(through, "documents_checked_seq")?)
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        Ok(through - checked)
    }
}
