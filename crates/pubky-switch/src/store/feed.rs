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
    chain::{ItemType, SignedHead, Stub},
    ops::Position,
    sig::SignedDoc,
};
use sqlx::Row;

use super::{StoreError, from_db, identity::decode_doc, to_db};

/// The account's sequence as one page reads it, what the reader's authentication reads,
/// and the documents current among the seqs the page may cover.
#[derive(Clone, Debug, Default)]
pub struct FeedSnapshot {
    /// The generation the account serves.
    pub generation: u64,
    /// The generation's service key, by its key store ID.
    pub service_key: String,
    /// The last service time the account stamped.
    pub stamped_time_ms: u64,
    /// The newest `identity.json` the account holds.
    pub identity_doc: Option<SignedDoc>,
    /// The reader's app row.
    pub reader: Option<super::StoredApp>,
    /// Whether the reader's App ID is kept for good: revoked, departed, or named by an
    /// enrollment.
    pub reader_kept: bool,
    /// The last `seq` given out.
    pub last_seq: u64,
    /// The newest chain item's `seq` and chain hash; `None` before the first.
    pub chain: Option<(u64, [u8; 32])>,
    /// The latest checkpoint, which every page carries (Switch wire 7.4.4); `None` before the
    /// first.
    pub checkpoint: Option<SignedHead>,
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

impl CurrentDocs {
    /// Whether chain item `row` shows its document in full to some current own app, by the
    /// documents current (Switch wire 7.5): the union, over every reader, of what
    /// `service::feed::shows` shows in full. An item it isn't for shows as a stub to every
    /// app, whoever reads and wherever its cursor stands, so its document may go
    /// (`AccountTxn::drop_stale_documents`).
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupt`] for a stored document that doesn't read.
    pub fn shows_in_full_to_some_app(&self, row: &FeedRow) -> Result<bool, StoreError> {
        use pubky_switch_core::ops::{OpKind, SignedOp};
        let Some(item) = &row.item else {
            return Ok(false);
        };
        if row.item_type != ItemType::Op {
            // Deliveries, service transitions and a conversation entry the service wrote
            // show in full to every app, or to every app holding `lists.read`.
            return Ok(true);
        }
        let op = SignedOp::peek(item).map_err(|_| StoreError::Corrupt("a signed operation"))?;
        let body = op.body();
        Ok(match &body.kind {
            OpKind::Claim(_) => self.claim_entries.contains(&row.seq),
            OpKind::RecordPut(_) => self.records.contains_key(&row.seq),
            OpKind::KeyBundlePut(_) => row.only_for.is_some() && self.bundles.contains(&row.seq),
            OpKind::AppPut { record } => body.app_id.is_some_and(|app| {
                self.apps
                    .get(&app)
                    .is_some_and(|docs| docs.record.as_ref() == Some(record))
            }),
            OpKind::CertPut {
                target_app_id,
                cert,
            } => self
                .apps
                .get(target_app_id)
                .is_some_and(|docs| docs.renewed_cert.as_ref() == Some(cert)),
            OpKind::AllowPut { .. }
            | OpKind::AllowDelete { .. }
            | OpKind::DenyPut { .. }
            | OpKind::DenyDelete { .. }
            | OpKind::InviteCodePut(_)
            | OpKind::InviteCodeDelete { .. }
            | OpKind::ReceiveKeyPut { .. } => true,
        })
    }
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
pub(super) fn item_doc(bytes: &[u8]) -> Result<SignedDoc, StoreError> {
    match pubky_switch_core::enc::split_lp(bytes).as_deref() {
        Some([body, sig]) => {
            let sig = <[u8; 64]>::try_from(sig.as_slice())
                .map_err(|_| StoreError::Corrupt("a chain item's signature"))?;
            Ok(SignedDoc::from_parts(body, &sig))
        }
        _ => Err(StoreError::Corrupt("a chain item")),
    }
}

pub(super) fn row_of(row: &sqlx::postgres::PgRow) -> Result<FeedRow, StoreError> {
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

/// What builds a page from a snapshot: it decides first, from what the reader's
/// authentication reads, whether to read any item, then sees the items in `seq` order.
pub trait PageReader {
    /// Whether the page reads items at all; `false` stops before the first.
    fn begin(&mut self, snapshot: &FeedSnapshot) -> bool;
    /// See the next item; whether the page wants the one after.
    fn take(&mut self, snapshot: &FeedSnapshot, row: FeedRow) -> bool;
    /// See the next inbox item; whether the page wants the item after it.
    fn take_entry(&mut self, snapshot: &FeedSnapshot, item: super::InboxItem) -> bool;
}

/// Read one page of account `id` for its app `reader` from one snapshot: the sequence and
/// what the reader's authentication reads, then, if `page` begins, the chain items after
/// `after` up to `positions` positions on, and as many after those as finish a batch
/// (`batch_tail`), in `seq` order. `None` for an account that isn't there.
#[allow(clippy::too_many_arguments)]
pub(super) async fn read_feed(
    pool: &sqlx::PgPool,
    id: &str,
    reader: &[u8; 16],
    after: Option<Position>,
    positions: u64,
    batch_tail: u64,
    page: &mut impl PageReader,
) -> Result<Option<FeedSnapshot>, StoreError> {
    let mut tx = pool.begin().await.map_err(StoreError::from_db)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(StoreError::from_db)?;
    let Some(row) = sqlx::query(
        "SELECT generation, last_seq, chain_seq, chain_hash, service_key, stamped_time_ms, \
         identity_doc, r.checkpoint FROM accounts \
         LEFT JOIN chain_retention r ON r.account_id = accounts.id WHERE id = $1",
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
    // One behind the oldest kept stub reads on from there: the stubs dropped show no more,
    // the inbox entries at those positions still do, and the page carries the checkpoint.
    let start = after
        .filter(|position| position.generation == generation)
        .map_or(0, |position| position.seq);
    let checkpoint: Option<Vec<u8>> = row.try_get("checkpoint")?;
    let checkpoint = checkpoint
        .as_deref()
        .map(super::retention::decode_checkpoint)
        .transpose()?;
    let window_end = start.saturating_add(positions).min(last_seq);
    let identity_doc: Option<Vec<u8>> = row.try_get("identity_doc")?;
    let reader_kept: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM kept_app_ids WHERE account_id = $1 AND app_id = $2)",
    )
    .bind(id)
    .bind(reader.as_slice())
    .fetch_one(&mut *tx)
    .await
    .map_err(StoreError::from_db)?;
    let mut snapshot = FeedSnapshot {
        generation,
        service_key: row.try_get("service_key")?,
        stamped_time_ms: from_db(row.try_get("stamped_time_ms")?, "stamped_time_ms")?,
        identity_doc: identity_doc
            .map(|bytes| decode_doc(&bytes, "identity_doc"))
            .transpose()?,
        reader: super::ops::app_row(&mut *tx, id, reader).await?,
        reader_kept,
        last_seq,
        chain,
        checkpoint,
        start,
        window_end,
        current: CurrentDocs::default(),
    };
    if !page.begin(&snapshot) || start >= last_seq {
        tx.rollback().await.map_err(StoreError::from_db)?;
        return Ok(Some(snapshot));
    }
    let low = to_db(start, "seq")?;
    let high = to_db(window_end.saturating_add(batch_tail), "seq")?;
    let db_generation = to_db(generation, "generation")?;
    snapshot.current = current_docs(&mut tx, id, db_generation, low, high).await?;

    // Chain items and inbox items, in one sequence by seq: only the entries wrapped to the
    // reader, so another app's envelopes are never read, the unreadable items every current
    // app reads, and the reader's own `missed` item (Switch wire 7.5). The reader's currency
    // is checked for the page as a whole.
    let mut rows = sqlx::query(
        "SELECT 'chain' AS kind, seq, item_type, item_bytes, envelope, chain_hash, proof, \
                only_for, NULL::BYTEA AS entry_id, NULL::BYTEA AS sender, NULL::BYTEA AS cert, \
                NULL::BIGINT AS accepted_at_ms, NULL::BYTEA[] AS targets, NULL::BYTEA AS context, \
                NULL::TEXT AS item_kind, NULL::BIGINT AS missed_entries, \
                NULL::BIGINT AS missed_from_ms, NULL::BIGINT AS missed_until_ms \
         FROM chain_items WHERE account_id = $1 AND generation = $2 AND seq > $3 AND seq <= $4 \
         UNION ALL \
         SELECT 'entry', seq, NULL, NULL, envelope, NULL, NULL, NULL, entry_id, sender, cert, \
                accepted_at_ms, targets, context, kind, missed_entries, missed_from_ms, \
                missed_until_ms \
         FROM inbox_entries WHERE account_id = $1 AND generation = $2 AND seq > $3 AND seq <= $4 \
         AND (kind = 'unreadable' OR $5 = ANY(targets)) \
         ORDER BY seq",
    )
    .bind(id)
    .bind(db_generation)
    .bind(low)
    .bind(high)
    .bind(reader.as_slice())
    .fetch(&mut *tx);
    while let Some(row) = rows.try_next().await.map_err(StoreError::from_db)? {
        let kind: String = row.try_get("kind")?;
        let wants = if kind == "entry" {
            page.take_entry(&snapshot, super::inbox::item_of(&row)?)
        } else {
            page.take(&snapshot, row_of(&row)?)
        };
        if !wants {
            break;
        }
    }
    drop(rows);
    tx.rollback().await.map_err(StoreError::from_db)?;
    Ok(Some(snapshot))
}

/// The documents current among `seqs` of `generation`: as [`current_docs`], for a set of
/// seqs rather than a window, so a few seqs far apart read no more than they need.
pub(super) async fn current_docs_at(
    tx: &mut sqlx::PgConnection,
    id: &str,
    generation: i64,
    seqs: &[i64],
) -> Result<CurrentDocs, StoreError> {
    let mut current = CurrentDocs::default();
    for row in sqlx::query(
        "SELECT version, read_scope FROM shared_records \
         WHERE account_id = $1 AND generation = $2 AND version = ANY($3)",
    )
    .bind(id)
    .bind(generation)
    .bind(seqs)
    .fetch_all(&mut *tx)
    .await
    .map_err(StoreError::from_db)?
    {
        current.records.insert(
            from_db(row.try_get("version")?, "version")?,
            row.try_get("read_scope")?,
        );
    }
    for row in
        sqlx::query("SELECT seq FROM key_bundle_parts WHERE account_id = $1 AND seq = ANY($2)")
            .bind(id)
            .bind(seqs)
            .fetch_all(&mut *tx)
            .await
            .map_err(StoreError::from_db)?
    {
        current.bundles.insert(from_db(row.try_get("seq")?, "seq")?);
    }
    for row in sqlx::query(
        "SELECT e.seq FROM claim_entries e JOIN claims c \
         ON c.account_id = e.account_id AND c.claim_key = e.claim_key \
         WHERE e.account_id = $1 AND e.seq = ANY($2) AND NOT c.tombstone",
    )
    .bind(id)
    .bind(seqs)
    .fetch_all(&mut *tx)
    .await
    .map_err(StoreError::from_db)?
    {
        current
            .claim_entries
            .insert(from_db(row.try_get("seq")?, "seq")?);
    }
    current.apps = app_docs(tx, id).await?;
    Ok(current)
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
    current.apps = app_docs(tx, id).await?;
    Ok(current)
}

/// Each app's stored record and renewed certificate.
async fn app_docs(
    tx: &mut sqlx::PgConnection,
    id: &str,
) -> Result<HashMap<[u8; 16], AppDocs>, StoreError> {
    let mut apps = HashMap::new();
    for row in sqlx::query("SELECT app_id, record, renewed_cert FROM apps WHERE account_id = $1")
        .bind(id)
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::from_db)?
    {
        let app_id: Vec<u8> = row.try_get("app_id")?;
        let record: Option<Vec<u8>> = row.try_get("record")?;
        let renewed: Option<Vec<u8>> = row.try_get("renewed_cert")?;
        apps.insert(
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
    Ok(apps)
}
