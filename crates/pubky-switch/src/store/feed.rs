//! What a feed page reads (Switch wire 7.4.4, 7.5): the account's sequence and the chain
//! items of one page, with which of their documents are still current, all from one
//! snapshot taken without the account's lock.
//!
//! A page is read after the request that asked for it committed, so a long-poll never holds
//! the lock while it waits. Everything a page shows comes from one `REPEATABLE READ`
//! snapshot: the head it carries, the items up to it and the state that decides whether an
//! item shows its document or only its stub. A page never mixes two states of the account.

use std::collections::{HashMap, HashSet};

use futures_util::TryStreamExt;
use pubky_switch_core::{
    chain::{ItemType, Stub},
    ops::Position,
    sig::SignedDoc,
};
use sqlx::Row;

use super::{StoreError, from_db, identity::decode_doc, to_db};

/// The account's sequence as one page reads it, and the documents current among the seqs
/// the page may cover.
#[derive(Clone, Debug, Default)]
pub struct FeedSnapshot {
    /// The generation the account serves.
    pub generation: u64,
    /// The last `seq` given out.
    pub last_seq: u64,
    /// The newest chain item's `seq` and chain hash; `None` before the first.
    pub chain: Option<(u64, [u8; 32])>,
    /// The `seq` the page starts after: the reader's `after`, or 0 for a position of
    /// another generation (Switch wire 7.4.4).
    pub start: u64,
    /// The last position the page examines, before it runs on to the end of a batch.
    pub window_end: u64,
    /// The documents still current among the seqs the page may cover.
    pub current: CurrentDocs,
}

/// Which chain items' documents are still current (Switch wire 7.5): superseded record
/// writes and key bundles, superseded app records, renewed certificates replaced or carried
/// by the app's record, and the entries of compacted claims show as stubs.
#[derive(Clone, Debug, Default)]
pub struct CurrentDocs {
    /// The `seq` of each record's current write, with the record's `read_scope`.
    pub records: HashMap<u64, String>,
    /// The `seq` of each stored key bundle part.
    pub bundles: HashSet<u64>,
    /// The `seq` of each entry of a live claim.
    pub claim_entries: HashSet<u64>,
    /// Each app's stored record and renewed certificate.
    pub apps: HashMap<[u8; 16], AppDocs>,
}

/// An app's current documents.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AppDocs {
    /// The app record the newest `app.put` stored.
    pub record: Option<SignedDoc>,
    /// The renewed certificate a `cert.put` stored.
    pub renewed_cert: Option<SignedDoc>,
}

/// One chain item as a page reads it.
#[derive(Clone, Debug)]
pub struct FeedRow {
    /// Its `seq`.
    pub seq: u64,
    /// Its type.
    pub item_type: ItemType,
    /// Its signed document; `None` once deleted, when only its stub is kept.
    pub item: Option<SignedDoc>,
    /// Its stub.
    pub stub: Stub,
    /// A signed operation's transition proof.
    pub proof: Option<SignedDoc>,
    /// The app it is shown in full to, for a key bundle part.
    pub only_for: Option<[u8; 16]>,
}

fn item_type(text: &str) -> Result<ItemType, StoreError> {
    match text {
        "op" => Ok(ItemType::Op),
        "identity" => Ok(ItemType::Identity),
        "service" => Ok(ItemType::Service),
        _ => Err(StoreError::Corrupt("a chain item's type")),
    }
}

fn hash32(bytes: &[u8], what: &'static str) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| StoreError::Corrupt(what))
}

/// A chain item's document from its signed document bytes, `lp(body, signature)`
/// (Switch wire 2.2), as the chain keeps it.
fn item_doc(bytes: &[u8]) -> Result<SignedDoc, StoreError> {
    match pubky_switch_core::enc::split_lp(bytes).as_deref() {
        Some([body, sig]) => {
            let sig = <[u8; 64]>::try_from(sig.as_slice())
                .map_err(|_| StoreError::Corrupt("a chain item's signature"))?;
            Ok(SignedDoc::from_parts(body, &sig))
        }
        _ => Err(StoreError::Corrupt("a chain item")),
    }
}

fn row_of(row: &sqlx::postgres::PgRow) -> Result<FeedRow, StoreError> {
    let item: Option<Vec<u8>> = row.try_get("item_bytes")?;
    let proof: Option<Vec<u8>> = row.try_get("proof")?;
    let chain_hash: Vec<u8> = row.try_get("chain_hash")?;
    let only_for: Option<Vec<u8>> = row.try_get("only_for")?;
    let item_type_text: String = row.try_get("item_type")?;
    Ok(FeedRow {
        seq: from_db(row.try_get("seq")?, "seq")?,
        item_type: item_type(&item_type_text)?,
        item: item.map(|bytes| item_doc(&bytes)).transpose()?,
        stub: Stub {
            envelope: row.try_get("envelope")?,
            chain_hash: hash32(&chain_hash, "a chain item's chain hash")?,
        },
        proof: proof
            .map(|bytes| decode_doc(&bytes, "a chain item's proof"))
            .transpose()?,
        only_for: only_for
            .map(|app| <[u8; 16]>::try_from(app.as_slice()))
            .transpose()
            .map_err(|_| StoreError::Corrupt("a chain item's only_for"))?,
    })
}

/// Read one page of account `id` from one snapshot: the sequence, then the chain items
/// after `after` up to `positions` positions on, and as many after those as finish a batch
/// (`batch_tail`), in `seq` order. `take` sees each item and answers whether the page
/// wants the next. `None` for an account that isn't there.
pub(super) async fn read_feed<F>(
    pool: &sqlx::PgPool,
    id: &str,
    after: Option<Position>,
    positions: u64,
    batch_tail: u64,
    mut take: F,
) -> Result<Option<FeedSnapshot>, StoreError>
where
    F: FnMut(&FeedSnapshot, FeedRow) -> bool,
{
    let mut tx = pool.begin().await.map_err(StoreError::from_db)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(StoreError::from_db)?;
    let Some(row) = sqlx::query(
        "SELECT generation, last_seq, chain_seq, chain_hash FROM accounts WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(StoreError::from_db)?
    else {
        return Ok(None);
    };
    let generation = from_db(row.try_get("generation")?, "generation")?;
    let last_seq = from_db(row.try_get("last_seq")?, "last_seq")?;
    let chain_seq: Option<i64> = row.try_get("chain_seq")?;
    let chain_hash: Option<Vec<u8>> = row.try_get("chain_hash")?;
    let chain = match (chain_seq, chain_hash) {
        (Some(seq), Some(hash)) => Some((from_db(seq, "chain_seq")?, hash32(&hash, "chain_hash")?)),
        (None, None) => None,
        _ => return Err(StoreError::Corrupt("chain head")),
    };
    // A position of another sequence reads from the start of this one (Switch wire 7.4.4).
    let start = after
        .filter(|position| position.generation == generation)
        .map_or(0, |position| position.seq);
    let window_end = start.saturating_add(positions).min(last_seq);
    let mut snapshot = FeedSnapshot {
        generation,
        last_seq,
        chain,
        start,
        window_end,
        current: CurrentDocs::default(),
    };
    if start >= last_seq {
        tx.rollback().await.map_err(StoreError::from_db)?;
        return Ok(Some(snapshot));
    }
    let low = to_db(start, "seq")?;
    let high = to_db(window_end.saturating_add(batch_tail), "seq")?;
    let db_generation = to_db(generation, "generation")?;
    snapshot.current = current_docs(&mut tx, id, db_generation, low, high).await?;

    let mut rows = sqlx::query(
        "SELECT seq, item_type, item_bytes, envelope, chain_hash, proof, only_for \
         FROM chain_items WHERE account_id = $1 AND generation = $2 AND seq > $3 AND seq <= $4 \
         ORDER BY seq",
    )
    .bind(id)
    .bind(db_generation)
    .bind(low)
    .bind(high)
    .fetch(&mut *tx);
    while let Some(row) = rows.try_next().await.map_err(StoreError::from_db)? {
        if !take(&snapshot, row_of(&row)?) {
            break;
        }
    }
    drop(rows);
    tx.rollback().await.map_err(StoreError::from_db)?;
    Ok(Some(snapshot))
}

/// The documents current among the seqs in (`low`, `high`].
async fn current_docs(
    tx: &mut sqlx::PgConnection,
    id: &str,
    generation: i64,
    low: i64,
    high: i64,
) -> Result<CurrentDocs, StoreError> {
    let mut current = CurrentDocs::default();
    for row in sqlx::query(
        "SELECT version, read_scope FROM shared_records \
         WHERE account_id = $1 AND generation = $2 AND version > $3 AND version <= $4",
    )
    .bind(id)
    .bind(generation)
    .bind(low)
    .bind(high)
    .fetch_all(&mut *tx)
    .await
    .map_err(StoreError::from_db)?
    {
        current.records.insert(
            from_db(row.try_get("version")?, "version")?,
            row.try_get("read_scope")?,
        );
    }
    // Key bundle parts and claim entries are kept for the generation the account serves.
    for row in sqlx::query(
        "SELECT seq FROM key_bundle_parts WHERE account_id = $1 AND seq > $2 AND seq <= $3",
    )
    .bind(id)
    .bind(low)
    .bind(high)
    .fetch_all(&mut *tx)
    .await
    .map_err(StoreError::from_db)?
    {
        current.bundles.insert(from_db(row.try_get("seq")?, "seq")?);
    }
    // A tombstone's entries are compacted away (Switch wire 6.8), whatever rows it keeps.
    for row in sqlx::query(
        "SELECT e.seq FROM claim_entries e JOIN claims c \
         ON c.account_id = e.account_id AND c.claim_key = e.claim_key \
         WHERE e.account_id = $1 AND e.seq > $2 AND e.seq <= $3 AND NOT c.tombstone",
    )
    .bind(id)
    .bind(low)
    .bind(high)
    .fetch_all(&mut *tx)
    .await
    .map_err(StoreError::from_db)?
    {
        current
            .claim_entries
            .insert(from_db(row.try_get("seq")?, "seq")?);
    }
    for row in sqlx::query("SELECT app_id, record, renewed_cert FROM apps WHERE account_id = $1")
        .bind(id)
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::from_db)?
    {
        let app_id: Vec<u8> = row.try_get("app_id")?;
        let record: Option<Vec<u8>> = row.try_get("record")?;
        let renewed: Option<Vec<u8>> = row.try_get("renewed_cert")?;
        current.apps.insert(
            <[u8; 16]>::try_from(app_id.as_slice()).map_err(|_| StoreError::Corrupt("app_id"))?,
            AppDocs {
                record: record
                    .map(|bytes| decode_doc(&bytes, "app record"))
                    .transpose()?,
                renewed_cert: renewed
                    .map(|bytes| decode_doc(&bytes, "renewed cert"))
                    .transpose()?,
            },
        );
    }
    Ok(current)
}
