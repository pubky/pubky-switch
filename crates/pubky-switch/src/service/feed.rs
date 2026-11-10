//! `GET /v1/{id}/feed` (Switch wire 7.4.4): a page of the account's sequence, each chain
//! item shown in full to the apps that may read it and as a stub to the others (7.5).
//!
//! The request runs the processing order under the account's lock like any other, and its
//! page is read once the lock is gone, from one snapshot ([`crate::store::FeedSnapshot`]).
//! A long-poll waits there for the account's next change, holding no lock.

use std::{collections::BTreeMap, time::Duration};

use pubky_switch_core::{
    chain::{ChainEnvelope, ChainTip, ItemType, ServiceTransition, ZERO_HASH},
    ops::{MAX_BATCH_ENTRIES, OpKind, Position, SignedOp},
    records::AppCert,
    scopes::Permission,
};
use serde_json::{Value, json};

use super::{Answer, Service};
use crate::{
    http::error::{ApiError, ErrorCode},
    keys::{KeyId, Mark, ServiceSigner, sign_head},
    store::{CurrentDocs, FeedRow, FeedSnapshot, StoreError},
};

/// Positions one page examines at most, before it runs on to the end of a batch (Switch
/// wire 7.4.4).
pub(crate) const POSITIONS_PER_PAGE: u64 = 1000;
/// Items per page by default, and at most (Switch wire 7.4.4).
pub(crate) const DEFAULT_LIMIT: usize = 100;
pub(crate) const MAX_LIMIT: usize = 500;
/// The longest long-poll, in seconds (Switch wire 7.4.4).
pub(crate) const MAX_WAIT_SECONDS: u64 = 25;

/// A feed request's query (Switch wire 7.4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FeedQuery {
    /// The position the page starts after; `None` for the start.
    pub(crate) after: Option<Position>,
    /// Items per page, 1 to 500.
    pub(crate) limit: usize,
    /// Long-poll seconds, at most 25.
    pub(crate) wait: u64,
}

impl FeedQuery {
    /// Read the query. Parameters the feed doesn't define are ignored.
    ///
    /// # Errors
    ///
    /// `400` for a malformed `after`, or a `limit` or `wait` that isn't an integer in its
    /// range.
    pub(crate) fn parse(query: &BTreeMap<String, String>) -> Result<Self, ApiError> {
        let after = query
            .get("after")
            .map(|text| Position::parse(text))
            .transpose()
            .map_err(|_| ApiError::bad_request("7.4.4: after is a position <generation>:<seq>"))?;
        let number = |name: &str| -> Result<Option<u64>, ApiError> {
            query
                .get(name)
                .map(|text| {
                    if text.is_empty()
                        || text.len() > 16
                        || !text.bytes().all(|b| b.is_ascii_digit())
                    {
                        return Err(ApiError::bad_request(format!(
                            "7.4.4: {name} is a decimal integer"
                        )));
                    }
                    text.parse::<u64>().map_err(|_| {
                        ApiError::bad_request(format!("7.4.4: {name} is a decimal integer"))
                    })
                })
                .transpose()
        };
        let limit = match number("limit")? {
            None => DEFAULT_LIMIT,
            Some(n) => usize::try_from(n)
                .ok()
                .filter(|n| (1..=MAX_LIMIT).contains(n))
                .ok_or_else(|| ApiError::bad_request("7.4.4: limit is 1 to 500"))?,
        };
        let wait = match number("wait")? {
            None => 0,
            Some(n) if n <= MAX_WAIT_SECONDS => n,
            Some(_) => return Err(ApiError::bad_request("7.4.4: wait is at most 25")),
        };
        Ok(Self { after, limit, wait })
    }
}

/// A feed read taken under the lock, whose page is read after it.
#[derive(Debug)]
pub(super) struct FeedRead {
    account: String,
    identity_key: [u8; 32],
    service_key: KeyId,
    reader: AppCert,
    query: FeedQuery,
}

/// How an item shows to a reader (Switch wire 7.5).
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Shown {
    /// In full, with the conversation entry's context for a service-written one.
    Full { context: Option<Value> },
    /// Its stub only.
    Stub,
}

fn corrupt(what: &'static str) -> StoreError {
    StoreError::Corrupt(what)
}

/// How chain item `row` shows to `reader`, a current own app, by the documents still
/// current (Switch wire 7.5).
///
/// # Errors
///
/// A [`StoreError`] for a stored document that doesn't read.
pub(crate) fn shows(
    row: &FeedRow,
    reader: &AppCert,
    current: &CurrentDocs,
) -> Result<Shown, StoreError> {
    let full = Shown::Full { context: None };
    let shown_if = |shown: bool| if shown { full.clone() } else { Shown::Stub };
    let Some(item) = &row.item else {
        return Ok(Shown::Stub);
    };
    Ok(match row.item_type {
        ItemType::Identity => full,
        ItemType::Service => {
            let body = item
                .body_bytes()
                .map_err(|_| corrupt("a service transition"))?;
            let value: Value =
                serde_json::from_slice(&body).map_err(|_| corrupt("a service transition"))?;
            match ServiceTransition::from_value(&value)
                .map_err(|_| corrupt("a service transition"))?
            {
                ServiceTransition::ConversationAdd { context, .. } => {
                    if reader.has_permission(Permission::ListsRead) {
                        Shown::Full {
                            context: Some(context),
                        }
                    } else {
                        Shown::Stub
                    }
                }
                _ => full,
            }
        }
        ItemType::Op => {
            let op = SignedOp::peek(item).map_err(|_| corrupt("a signed operation"))?;
            let body = op.body();
            match &body.kind {
                OpKind::Claim(_) => shown_if(
                    reader.has_permission(Permission::ClaimsRead)
                        && current.claim_entries.contains(&row.seq),
                ),
                OpKind::RecordPut(_) => shown_if(
                    current
                        .records
                        .get(&row.seq)
                        .is_some_and(|read_scope| reader.holds_scope(read_scope)),
                ),
                OpKind::AllowPut { .. }
                | OpKind::AllowDelete { .. }
                | OpKind::DenyPut { .. }
                | OpKind::DenyDelete { .. } => {
                    shown_if(reader.has_permission(Permission::ListsRead))
                }
                OpKind::InviteCodePut(_) | OpKind::InviteCodeDelete { .. } => shown_if(
                    reader.has_permission(Permission::ListsRead)
                        || reader.has_permission(Permission::ConversationAdd),
                ),
                OpKind::AppPut { record } => shown_if(body.app_id.is_some_and(|app| {
                    current
                        .apps
                        .get(&app)
                        .is_some_and(|docs| docs.record.as_ref() == Some(record))
                })),
                OpKind::ReceiveKeyPut { .. } => full,
                OpKind::KeyBundlePut(_) => shown_if(
                    row.only_for == Some(reader.app_id()) && current.bundles.contains(&row.seq),
                ),
                OpKind::CertPut {
                    target_app_id,
                    cert,
                } => shown_if(
                    current
                        .apps
                        .get(target_app_id)
                        .is_some_and(|docs| docs.renewed_cert.as_ref() == Some(cert)),
                ),
            }
        }
    })
}

/// The feed item of chain item `row` as it shows (Switch wire 7.5).
fn item_value(row: &FeedRow, shown: Shown) -> Value {
    let stub = row.stub.to_value();
    match (shown, &row.item) {
        (Shown::Full { context }, Some(item)) => {
            let mut value = json!({
                "type": "chain",
                "seq": row.seq,
                "stub": stub,
                "item_type": row.item_type.as_str(),
                "item": item,
            });
            if let Some(context) = context {
                value["context"] = context;
            }
            if let (ItemType::Op, Some(proof)) = (row.item_type, &row.proof) {
                value["proof"] = json!(proof);
            }
            value
        }
        _ => json!({ "type": "stub", "seq": row.seq, "stub": stub }),
    }
}

/// A page as it is built from the items of a snapshot, in `seq` order (Switch wire 7.4.4):
/// it ends after `limit` items or before an item that would take its items' bytes past the
/// budget, but never inside a batch, whose items count together; its first item or batch
/// is shown whatever its size.
#[derive(Debug)]
pub(crate) struct PageBuilder<'a> {
    reader: &'a AppCert,
    limit: usize,
    budget: usize,
    items: Vec<Value>,
    bytes: usize,
    /// The items of the group being read: one batch's, or one item of no batch.
    group: Vec<Value>,
    group_bytes: usize,
    group_batch: Option<[u8; 16]>,
    group_last: u64,
    /// The last `seq` of the last group the page took.
    covered: Option<u64>,
    /// Whether the limit or the budget ended the page.
    cut: bool,
    error: Option<StoreError>,
}

/// A page, finished.
#[derive(Debug, PartialEq)]
pub(crate) struct Page {
    pub(crate) items: Vec<Value>,
    /// The last `seq` the page examined, shown or not.
    pub(crate) scanned_through: u64,
    /// Whether items follow it.
    pub(crate) more: bool,
}

impl<'a> PageBuilder<'a> {
    pub(crate) fn new(reader: &'a AppCert, limit: usize, budget: usize) -> Self {
        Self {
            reader,
            limit,
            budget,
            items: Vec::new(),
            bytes: 0,
            group: Vec::new(),
            group_bytes: 0,
            group_batch: None,
            group_last: 0,
            covered: None,
            cut: false,
            error: None,
        }
    }

    /// Take the group read so far, unless the page ends before it; whether it did.
    fn close_group(&mut self) -> bool {
        if self.group.is_empty() {
            return true;
        }
        if !self.items.is_empty()
            && (self.items.len() >= self.limit
                || self.bytes.saturating_add(self.group_bytes) > self.budget)
        {
            self.cut = true;
            self.group.clear();
            return false;
        }
        self.items.append(&mut self.group);
        self.bytes = self.bytes.saturating_add(self.group_bytes);
        self.group_bytes = 0;
        self.covered = Some(self.group_last);
        true
    }

    /// See the next item of `snapshot`; whether the page wants the one after.
    pub(crate) fn take(&mut self, snapshot: &FeedSnapshot, row: FeedRow) -> bool {
        let batch = match ChainEnvelope::parse(&row.stub.envelope) {
            Ok(envelope) => envelope.batch.map(|batch| batch.id),
            Err(_) => {
                self.error = Some(corrupt("a chain envelope"));
                return false;
            }
        };
        // A batch's items take consecutive seqs (Switch wire 6.4).
        let continues = batch.is_some()
            && batch == self.group_batch
            && !self.group.is_empty()
            && row.seq == self.group_last.saturating_add(1);
        // Past the positions a page examines, only the rest of the batch it is in.
        if row.seq > snapshot.window_end && !continues {
            return false;
        }
        if !continues && !self.close_group() {
            return false;
        }
        let shown = match shows(&row, self.reader, &snapshot.current) {
            Ok(shown) => shown,
            Err(error) => {
                self.error = Some(error);
                return false;
            }
        };
        let value = item_value(&row, shown);
        let size = serde_json::to_vec(&value).map_or(0, |bytes| bytes.len());
        self.group.push(value);
        self.group_bytes = self.group_bytes.saturating_add(size);
        self.group_batch = batch;
        self.group_last = row.seq;
        true
    }

    /// Finish the page read from `snapshot`.
    ///
    /// # Errors
    ///
    /// A [`StoreError`] for an item that didn't read.
    pub(crate) fn finish(mut self, snapshot: &FeedSnapshot) -> Result<Page, StoreError> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        if !self.cut {
            self.close_group();
        }
        let scanned_through = if self.cut {
            self.covered.unwrap_or(snapshot.start)
        } else {
            snapshot
                .start
                .max(snapshot.window_end)
                .max(self.covered.unwrap_or(0))
        };
        Ok(Page {
            items: self.items,
            scanned_through,
            more: scanned_through < snapshot.last_seq,
        })
    }
}

fn temporary() -> ApiError {
    ApiError::unavailable("7.6: a temporary failure")
}

impl Service {
    /// `GET /v1/{id}/feed` under the lock, from an own app (Switch wire 7.4.4): the query
    /// read; the page is read once the lock is gone ([`FeedRead`]).
    pub(super) fn feed(
        &self,
        account: &str,
        identity_key: [u8; 32],
        service_key: &KeyId,
        writer: Option<&AppCert>,
        query: &Result<BTreeMap<String, String>, crate::http::route::QueryError>,
    ) -> Result<Answer, ApiError> {
        let Some(reader) = writer else {
            return Err(ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4.4: only own apps read the feed",
            ));
        };
        let query = query
            .as_ref()
            .map_err(|_| ApiError::bad_request("7.1: the query doesn't decode"))?;
        let query = FeedQuery::parse(query)?;
        let mut answer = Answer::ok(Vec::new());
        answer.deferred = Some(super::Deferred::Feed(Box::new(FeedRead {
            account: account.to_string(),
            identity_key,
            service_key: service_key.clone(),
            reader: reader.clone(),
            query,
        })));
        Ok(answer)
    }

    /// The feed page of `read`, once the lock is gone: at once when it shows an item or
    /// more follow, or without `wait`; otherwise when the account changes or `wait` seconds
    /// pass, with the page as it is then (Switch wire 7.4.4).
    pub(super) async fn feed_page(
        &self,
        read: &FeedRead,
        signer: &ServiceSigner,
    ) -> Result<Answer, ApiError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(read.query.wait);
        // Subscribed before the first read, so no change after it is missed.
        let mut changes = self.changes.subscribe(&read.account);
        loop {
            changes.borrow_and_update();
            let (snapshot, page, head) = self.read_page(read, signer).await?;
            let waited_out = tokio::time::Instant::now() >= deadline;
            if !page.items.is_empty() || page.more || waited_out {
                return self.page_answer(read, &snapshot, page, head).await;
            }
            tokio::select! {
                changed = changes.changed() => {
                    // The hub went away: answer with the page as it is.
                    if changed.is_err() {
                        return self.page_answer(read, &snapshot, page, head).await;
                    }
                }
                () = tokio::time::sleep_until(deadline) => {}
            }
        }
    }

    /// One page from one snapshot, and its head, signed. The key's mark is read before the
    /// snapshot, so the snapshot's head is at or past it unless the state went back.
    async fn read_page(
        &self,
        read: &FeedRead,
        signer: &ServiceSigner,
    ) -> Result<(FeedSnapshot, Page, pubky_switch_core::chain::SignedHead), ApiError> {
        let mark = self
            .keys
            .mark(&read.service_key)
            .await
            .map_err(|_| temporary())?;
        let budget = usize::try_from(self.limits.max_page_bytes).unwrap_or(usize::MAX);
        let mut builder = PageBuilder::new(&read.reader, read.query.limit, budget);
        let snapshot = self
            .store
            .read_feed(
                &read.account,
                read.query.after,
                POSITIONS_PER_PAGE,
                (MAX_BATCH_ENTRIES as u64).saturating_sub(1),
                |snapshot, row| builder.take(snapshot, row),
            )
            .await
            .map_err(|error| super::store_error(&error))?
            .ok_or_else(|| ApiError::not_found("no such account"))?;
        let page = builder
            .finish(&snapshot)
            .map_err(|error| super::store_error(&error))?;
        let (seq, chain_hash) = snapshot.chain.unwrap_or((0, ZERO_HASH));
        let tip = ChainTip {
            generation: snapshot.generation,
            seq,
            chain_hash,
        };
        let head = sign_head(signer, mark.as_ref(), &read.identity_key, &tip).map_err(|_| {
            ApiError::unavailable(
                "7.3: the state is behind its service key's mark; a new generation is needed",
            )
        })?;
        Ok((snapshot, page, head))
    }

    /// The page's answer. The key's mark moves to its head first, so no head goes out that
    /// the mark is behind (Switch wire 7.3 step 10).
    async fn page_answer(
        &self,
        read: &FeedRead,
        snapshot: &FeedSnapshot,
        page: Page,
        head: pubky_switch_core::chain::SignedHead,
    ) -> Result<Answer, ApiError> {
        if let Some((seq, chain_hash)) = snapshot.chain {
            self.keys
                .advance_mark(
                    &read.service_key,
                    Mark {
                        generation: snapshot.generation,
                        seq,
                        chain_hash,
                    },
                )
                .await
                .map_err(|_| temporary())?;
        }
        let body = json!({
            "items": page.items,
            "next": format!("{}:{}", snapshot.generation, page.scanned_through),
            "scanned_through": page.scanned_through,
            "more": page.more,
            "head": head.to_value(),
        });
        let body = serde_json::to_vec(&body).map_err(|_| temporary())?;
        Ok(Answer::ok(body).with_head(Some(head)))
    }
}

#[cfg(test)]
mod tests {
    use pubky_switch_core::{chain::Stub, keys::IdentityKey, records::AppCertBody, sig::SignedDoc};

    use super::*;
    use crate::store::AppDocs;

    fn vectors(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec/vectors")
            .join(name);
        serde_json::from_slice(&std::fs::read(path).expect("vectors")).expect("json")
    }

    fn hex32(text: &Value) -> [u8; 32] {
        let bytes = hex::decode(text.as_str().expect("hex")).expect("hex");
        <[u8; 32]>::try_from(bytes.as_slice()).expect("32 bytes")
    }

    /// `chain.json`'s items as a page reads them, the record's delete at seq 10 last.
    fn rows() -> Vec<FeedRow> {
        let chain = vectors("chain.json");
        let mut items: Vec<Value> = chain["items"].as_array().expect("items").clone();
        items.push(chain["record_delete"]["item"].clone());
        items
            .iter()
            .map(|item| FeedRow {
                seq: item["seq"].as_u64().expect("seq"),
                item_type: match item["item_type"].as_str().expect("type") {
                    "op" => ItemType::Op,
                    "identity" => ItemType::Identity,
                    _ => ItemType::Service,
                },
                item: Some(serde_json::from_value(item["item"].clone()).expect("item")),
                stub: Stub::from_value(&item["stub"]).expect("stub"),
                proof: None,
                only_for: None,
            })
            .collect()
    }

    fn row(seq: u64) -> FeedRow {
        rows().into_iter().find(|row| row.seq == seq).expect("row")
    }

    /// A certificate of alice's for an app with `scopes` and `permissions`.
    fn reader(scopes: &[&str], permissions: &[Permission]) -> AppCert {
        let keys = vectors("keys.json");
        let alice = keys["identities"]
            .as_array()
            .expect("identities")
            .iter()
            .find(|identity| identity["name"] == "alice")
            .expect("alice");
        let key = IdentityKey::from_secret(hex32(&alice["secret_hex"]));
        AppCert::issue(
            &key,
            AppCertBody::new(
                key.public(),
                [7; 32],
                [8; 32],
                scopes.iter().map(|scope| (*scope).to_string()).collect(),
                permissions,
                0,
                u64::from(u32::MAX),
            ),
        )
        .expect("cert")
    }

    /// The documents current after `chain.json`'s seq 9: the record's write at seq 8, the
    /// live claim's attempt at seq 7, and the wallet's record from seq 3.
    fn current_at_nine() -> CurrentDocs {
        let mut current = CurrentDocs::default();
        current.records.insert(8, "pay".into());
        current.claim_entries.insert(7);
        let op = SignedOp::peek(row(3).item.as_ref().expect("item")).expect("op");
        let (OpKind::AppPut { record }, Some(app)) = (&op.body().kind, op.body().app_id) else {
            panic!("seq 3 is the wallet's app.put");
        };
        current.apps.insert(
            app,
            AppDocs {
                record: Some(record.clone()),
                renewed_cert: None,
            },
        );
        current
    }

    fn shown(reader: &AppCert, current: &CurrentDocs) -> Vec<(u64, bool)> {
        rows()
            .iter()
            .filter(|row| row.seq <= 9)
            .map(|row| {
                let shown = shows(row, reader, current).expect("shows");
                (row.seq, matches!(shown, Shown::Full { .. }))
            })
            .collect()
    }

    #[test]
    fn test_feed_visibility_by_scope_and_permission() {
        let current = current_at_nine();
        let all = reader(&["pay"], &[Permission::ClaimsRead, Permission::ListsRead]);
        // The create at seq 6 is superseded by the update at seq 8: a stub (Switch wire 7.5).
        assert_eq!(
            shown(&all, &current),
            vec![
                (1, true),
                (2, true),
                (3, true),
                (4, true),
                (6, false),
                (7, true),
                (8, true),
                (9, true)
            ]
        );
        // Without the record's read scope, or claims.read: their items are stubs.
        let neither = reader(&["allowance"], &[]);
        assert_eq!(
            shown(&neither, &current),
            vec![
                (1, true),
                (2, true),
                (3, true),
                (4, true),
                (6, false),
                (7, false),
                (8, false),
                (9, true)
            ]
        );
        // A scope's parent name holds its sub-scopes, not the reverse (Switch wire 3.1).
        let sub = reader(&["pay:shop"], &[Permission::ClaimsRead]);
        assert!(!matches!(
            shows(&row(8), &sub, &current).expect("shows"),
            Shown::Full { .. }
        ));
    }

    #[test]
    fn test_feed_visibility_of_superseded_and_deleted_documents() {
        let mut current = current_at_nine();
        let all = reader(&["pay"], &[Permission::ClaimsRead]);
        // The record's delete at seq 10 supersedes the update at seq 8.
        current.records.clear();
        current.records.insert(10, "pay".into());
        assert_eq!(shows(&row(8), &all, &current).expect("shows"), Shown::Stub);
        assert!(matches!(
            shows(&row(10), &all, &current).expect("shows"),
            Shown::Full { .. }
        ));
        // A claim compacted to a tombstone, or deleted: its entries are stubs.
        current.claim_entries.clear();
        assert_eq!(shows(&row(7), &all, &current).expect("shows"), Shown::Stub);
        // An app record the app replaced since.
        for docs in current.apps.values_mut() {
            docs.record = Some(SignedDoc::from_parts(b"{}", &[0; 64]));
        }
        assert_eq!(shows(&row(3), &all, &current).expect("shows"), Shown::Stub);
        // A document the service deleted keeps only its stub, whoever reads.
        let mut gone = row(1);
        gone.item = None;
        assert_eq!(shows(&gone, &all, &current).expect("shows"), Shown::Stub);
    }

    fn snapshot(start: u64, window_end: u64, last_seq: u64) -> FeedSnapshot {
        FeedSnapshot {
            generation: 1,
            last_seq,
            chain: None,
            start,
            window_end,
            current: current_at_nine(),
        }
    }

    /// The seqs of the page `reader` reads of `chain.json` from `snapshot`.
    fn page(snapshot: &FeedSnapshot, limit: usize, budget: usize) -> (Vec<u64>, u64, bool) {
        let reader = reader(&["pay"], &[Permission::ClaimsRead]);
        let mut builder = PageBuilder::new(&reader, limit, budget);
        for row in rows()
            .into_iter()
            .filter(|row| row.seq > snapshot.start && row.seq <= 9)
        {
            if !builder.take(snapshot, row) {
                break;
            }
        }
        let page = builder.finish(snapshot).expect("page");
        let seqs = page
            .items
            .iter()
            .map(|item| item["seq"].as_u64().expect("seq"))
            .collect();
        (seqs, page.scanned_through, page.more)
    }

    #[test]
    fn test_feed_page_ends_by_limit_never_inside_a_batch() {
        // Seqs 3 and 4 are one batch, 6 a batch of one, 7 and 8 one batch.
        assert_eq!(
            page(&snapshot(0, 9, 9), 100, usize::MAX),
            (vec![1, 2, 3, 4, 6, 7, 8, 9], 9, false)
        );
        assert_eq!(page(&snapshot(0, 9, 9), 1, usize::MAX), (vec![1], 1, true));
        // A limit of 1 still takes the whole batch.
        assert_eq!(
            page(&snapshot(2, 9, 9), 1, usize::MAX),
            (vec![3, 4], 4, true)
        );
        assert_eq!(
            page(&snapshot(2, 9, 9), 3, usize::MAX),
            (vec![3, 4, 6], 6, true)
        );
        // The limit reached at the last item: nothing follows.
        assert_eq!(
            page(&snapshot(6, 9, 9), 3, usize::MAX),
            (vec![7, 8, 9], 9, false)
        );
    }

    #[test]
    fn test_feed_page_ends_by_budget_with_its_first_group_whole() {
        // The first item or batch is shown whatever its size, then the budget ends the page.
        assert_eq!(page(&snapshot(0, 9, 9), 100, 1), (vec![1], 1, true));
        assert_eq!(page(&snapshot(2, 9, 9), 100, 1), (vec![3, 4], 4, true));
    }

    #[test]
    fn test_feed_page_ends_by_positions_after_the_batch() {
        // The positions end at seq 7, inside the batch of 7 and 8: the page runs on to 8.
        assert_eq!(
            page(&snapshot(6, 7, 9), 100, usize::MAX),
            (vec![7, 8], 8, true)
        );
        // They end at 6, before the next batch: it waits for the next page.
        assert_eq!(
            page(&snapshot(4, 6, 9), 100, usize::MAX),
            (vec![6], 6, true)
        );
        // Positions after the last item are examined too: 5 is no chain item.
        assert_eq!(page(&snapshot(4, 5, 9), 100, usize::MAX), (vec![], 5, true));
        // A position past the sequence keeps its place.
        assert_eq!(
            page(&snapshot(12, 9, 9), 100, usize::MAX),
            (vec![], 12, false)
        );
    }

    fn query(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn test_feed_query_defaults_and_bounds() {
        let parsed = FeedQuery::parse(&query(&[])).expect("query");
        assert_eq!(
            parsed,
            FeedQuery {
                after: None,
                limit: 100,
                wait: 0
            }
        );
        let parsed = FeedQuery::parse(&query(&[
            ("after", "1:4"),
            ("limit", "500"),
            ("wait", "25"),
        ]))
        .expect("query");
        assert_eq!(
            parsed.after,
            Some(Position {
                generation: 1,
                seq: 4
            })
        );
        assert_eq!((parsed.limit, parsed.wait), (500, 25));
        // Parameters the feed doesn't define are ignored.
        assert!(FeedQuery::parse(&query(&[("other", "x")])).is_ok());
    }

    #[test]
    fn test_feed_query_refuses_malformed_values() {
        for pairs in [
            [("after", "4")],
            [("after", "1:")],
            [("after", "x:1")],
            [("limit", "0")],
            [("limit", "501")],
            [("limit", "-1")],
            [("limit", "1.5")],
            [("wait", "26")],
            [("wait", "")],
        ] {
            let error = FeedQuery::parse(&query(&pairs)).expect_err("refused");
            assert_eq!(error.status(), 400, "{pairs:?}");
        }
    }
}
