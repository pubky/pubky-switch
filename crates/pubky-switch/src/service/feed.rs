//! `GET /v1/{id}/feed` (Switch wire 7.4.4): a page of the account's sequence, each chain
//! item shown in full to the apps that may read it and as a stub to the others (7.5).
//!
//! The request runs the processing order under the account's lock like any other, and its
//! page is read once the lock is gone, from one snapshot ([`crate::store::FeedSnapshot`]).
//! A long-poll waits there for the account's next change, holding no lock.

use std::{collections::BTreeMap, future::Future, time::Duration};

use pubky_switch_core::{
    chain::{ChainEnvelope, ChainTip, ItemType, ServiceTransition, SignedHead, ZERO_HASH},
    ops::{MAX_BATCH_ENTRIES, OpKind, Position, SignedOp},
    records::{AppCert, IdentityDoc},
    scopes::Permission,
};
use serde_json::Value;

use super::{
    Answer, Service,
    batch::{Stop, VerifiedApp, check_own_app},
    keyed::Signing,
};
use crate::{
    changes::ChangeHub,
    http::error::{ApiError, ErrorCode},
    keys::{KeyId, KeyStoreError, Mark, ServiceSigner, check_mark},
    store::{CurrentDocs, FeedRow, FeedSnapshot, PageReader, StoreError},
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

/// A feed read taken under the lock, whose page is read after it. The reader is checked
/// again for every page, in the snapshot the page comes from: a long-poll that outlives the
/// app's standing, its certificate or the account's key answers as a fresh request would.
#[derive(Debug)]
pub(super) struct FeedRead {
    account: String,
    identity_key: [u8; 32],
    service_key: KeyId,
    /// The reader, with the signing key its request verified with.
    reader: VerifiedApp,
    query: FeedQuery,
    /// The service time the request stamped.
    time_ms: u64,
}

/// How a feed read that can't answer with a page is answered.
#[derive(Debug)]
pub(super) enum FeedStop {
    /// The account is gone: `404`, signed with the operator key (Switch wire 7.3 step 2).
    Gone,
    /// The account's key changed since the request: a temporary failure, signed with the
    /// operator key, since the request's key is retired.
    Retired,
    /// An error answer.
    Refused(Box<PageRefusal>),
}

/// An error answer to a feed read, at `time_ms`. A refusal decided from a page's snapshot
/// carries that snapshot's head, the newest the service read (Switch wire 7.1), once the
/// key's mark has moved to it, as a page's does; any other with `head` carries the head the
/// request itself committed, which the mark covers already. So no refusal shows a head the
/// mark is behind (Switch wire 7.3 step 10). The mark's `503` and an unauthenticated
/// reader's `401` carry none.
#[derive(Debug)]
pub(super) struct PageRefusal {
    /// The error.
    pub(super) error: ApiError,
    /// Whether it carries a head.
    pub(super) head: bool,
    /// The snapshot it was decided from, whose head it carries; `None` for the request's.
    pub(super) snapshot: Option<SnapshotHead>,
    /// The service time to sign at.
    pub(super) time_ms: u64,
}

/// The head of the snapshot a refusal was decided from, signed inside its answer's proof.
#[derive(Debug)]
pub(super) struct SnapshotHead {
    tip: ChainTip,
    /// The key's mark, read before the snapshot.
    key_mark: Option<Mark>,
    identity_key: [u8; 32],
}

impl SnapshotHead {
    /// The head, unless the key's mark is past it.
    pub(super) fn sign(&self, signing: &Signing<'_>) -> Option<SignedHead> {
        signing.head(self.key_mark.as_ref(), &self.identity_key, &self.tip)
    }
}

impl FeedStop {
    fn refused(error: ApiError, head: bool, time_ms: u64) -> Self {
        Self::Refused(Box::new(PageRefusal {
            error,
            head,
            snapshot: None,
            time_ms,
        }))
    }
}

/// How an item shows to a reader (Switch wire 7.5).
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Shown {
    /// In full, with the conversation entry's context for a service-written one.
    Full { context: Option<Value> },
    /// Its stub only.
    Stub,
}

/// A read whose account no longer names its key, by the operator's answer `error`: gone, as an
/// account the service doesn't host, or its key retired (Switch wire 7.4.16).
fn gone_or_retired(error: &ApiError) -> FeedStop {
    if error.code == ErrorCode::NotFound {
        FeedStop::Gone
    } else {
        FeedStop::Retired
    }
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

/// The feed item of chain item `row` as it shows (Switch wire 7.5), as JSON in the member
/// order of the wire's example (7.4.4).
fn item_json(row: &FeedRow, shown: Shown) -> Vec<u8> {
    let mut out = Vec::new();
    let stub = row.stub.to_json();
    match (shown, &row.item) {
        (Shown::Full { context }, Some(item)) => {
            out.extend_from_slice(b"{\"type\":\"chain\",\"seq\":");
            out.extend_from_slice(row.seq.to_string().as_bytes());
            out.extend_from_slice(b",\"stub\":");
            out.extend_from_slice(&stub);
            out.extend_from_slice(b",\"item_type\":\"");
            out.extend_from_slice(row.item_type.as_str().as_bytes());
            out.extend_from_slice(b"\",\"item\":");
            out.extend_from_slice(&doc_json(item));
            if let Some(context) = context {
                out.extend_from_slice(b",\"context\":");
                out.extend_from_slice(context.to_string().as_bytes());
            }
            if let (ItemType::Op, Some(proof)) = (row.item_type, &row.proof) {
                out.extend_from_slice(b",\"proof\":");
                out.extend_from_slice(&doc_json(proof));
            }
            out.push(b'}');
        }
        _ => {
            out.extend_from_slice(b"{\"type\":\"stub\",\"seq\":");
            out.extend_from_slice(row.seq.to_string().as_bytes());
            out.extend_from_slice(b",\"stub\":");
            out.extend_from_slice(&stub);
            out.push(b'}');
        }
    }
    out
}

/// An inbox item's JSON (Switch wire 7.5): an `entry`, an `unreadable` item or a `missed`
/// item.
fn inbox_item_json(item: &crate::store::InboxItem) -> Vec<u8> {
    use crate::store::InboxItem;
    use pubky_switch_core::{enc, time::rfc3339};
    match item {
        InboxItem::Entry(entry) => entry_json(entry),
        InboxItem::Unreadable {
            seq,
            entry_id,
            sender,
            accepted_at_ms,
        } => format!(
            "{{\"type\":\"unreadable\",\"seq\":{seq},\"entry_id\":\"{}\",\"sender\":\"{}\",\
             \"accepted_at\":\"{}\"}}",
            enc::b64(entry_id),
            enc::pubky_id(sender),
            rfc3339(*accepted_at_ms),
        )
        .into_bytes(),
        InboxItem::Missed {
            seq,
            entries,
            from_ms,
            until_ms,
        } => format!(
            "{{\"type\":\"missed\",\"seq\":{seq},\"entries\":{entries},\
             \"accepted_from\":\"{}\",\"accepted_until\":\"{}\"}}",
            rfc3339(*from_ms),
            rfc3339(*until_ms),
        )
        .into_bytes(),
    }
}

/// An inbox entry's feed item (Switch wire 7.5), in the member order of the wire's example
/// (7.4.4): `type, seq, entry_id, sender, cert, accepted_at`, the invite code's `context` as
/// stored when one admitted the sender, then `envelope`.
fn entry_json(entry: &crate::store::StoredEntry) -> Vec<u8> {
    let mut out = b"{\"type\":\"entry\",\"seq\":".to_vec();
    out.extend_from_slice(entry.seq.to_string().as_bytes());
    out.extend_from_slice(b",\"entry_id\":\"");
    out.extend_from_slice(pubky_switch_core::enc::b64(&entry.entry_id).as_bytes());
    out.extend_from_slice(b"\",\"sender\":\"");
    out.extend_from_slice(pubky_switch_core::enc::pubky_id(&entry.sender).as_bytes());
    out.extend_from_slice(b"\",\"cert\":");
    out.extend_from_slice(&doc_json(&entry.cert));
    out.extend_from_slice(b",\"accepted_at\":\"");
    out.extend_from_slice(pubky_switch_core::time::rfc3339(entry.accepted_at_ms).as_bytes());
    out.push(b'"');
    if let Some(context) = &entry.context {
        out.extend_from_slice(b",\"context\":");
        out.extend_from_slice(context);
    }
    out.extend_from_slice(b",\"envelope\":\"");
    out.extend_from_slice(pubky_switch_core::enc::b64(&entry.envelope).as_bytes());
    out.extend_from_slice(b"\"}");
    out
}

/// A signed document's carrying form, `{"body","sig"}` (Switch wire 2.2).
fn doc_json(doc: &pubky_switch_core::sig::SignedDoc) -> Vec<u8> {
    // Two strings: their serialization can't fail; the empty object stands in if it did.
    serde_json::to_vec(doc).unwrap_or_else(|_| b"{}".to_vec())
}

/// Who reads a page.
#[derive(Debug)]
enum Reader {
    /// Checked again from each snapshot, as a fresh request (Switch wire 7.2).
    Checked {
        identity_key: [u8; 32],
        service_key: String,
        /// The service key's public key and the service's origin, for the staged gate.
        service_public: [u8; 32],
        origin: String,
        verified: VerifiedApp,
        time_ms: u64,
    },
    /// A certificate taken as it is, for tests of the visibility rules.
    #[cfg(test)]
    Fixed(AppCert),
}

/// A page as it is built from the items of a snapshot, in `seq` order (Switch wire 7.4.4):
/// it ends after `limit` items or before an item that would take its items' bytes past the
/// budget, but never inside a batch, whose items count together; its first item or batch
/// is shown whatever its size.
#[derive(Debug)]
pub(crate) struct PageBuilder {
    reader: Reader,
    /// The certificate the reader is checked against in this snapshot.
    cert: Option<AppCert>,
    limit: usize,
    budget: usize,
    items: Vec<Vec<u8>>,
    bytes: usize,
    /// The items of the group being read: one batch's, or one item of no batch.
    group: Vec<Vec<u8>>,
    group_bytes: usize,
    group_batch: Option<[u8; 16]>,
    group_last: u64,
    /// The last `seq` of the last group the page took.
    covered: Option<u64>,
    /// Whether the limit or the budget ended the page.
    cut: bool,
    error: Option<StoreError>,
    /// Why the reader may not read this snapshot, as a fresh request would be refused.
    refusal: Option<Stop>,
    /// The key changed since the request.
    retired: bool,
    /// The service time the page answers at: the later of the request's and the
    /// snapshot's.
    time_ms: u64,
}

/// A page, finished.
#[derive(Debug, PartialEq)]
pub(crate) struct Page {
    /// Each item's JSON.
    pub(crate) items: Vec<Vec<u8>>,
    /// The last `seq` the page examined, shown or not.
    pub(crate) scanned_through: u64,
    /// Whether items follow it.
    pub(crate) more: bool,
}

impl PageBuilder {
    fn with(reader: Reader, limit: usize, budget: usize) -> Self {
        Self {
            reader,
            cert: None,
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
            refusal: None,
            retired: false,
            time_ms: 0,
        }
    }

    /// A page for `reader`, taken as it is.
    #[cfg(test)]
    pub(crate) fn new(reader: AppCert, limit: usize, budget: usize) -> Self {
        Self::with(Reader::Fixed(reader), limit, budget)
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

impl PageReader for PageBuilder {
    /// An entry shows to its target apps only, an unreadable item to every current app and
    /// a `missed` item to its app, and to no other app at all: no stub, and nothing counted
    /// against the page's limit or budget (Switch wire 7.5). The page's query reads only
    /// the items the reader is shown (`store::feed::read_feed`), and the reader is a
    /// current app (`begin`). None is part of a batch.
    fn take_entry(&mut self, snapshot: &FeedSnapshot, item: crate::store::InboxItem) -> bool {
        if self.cert.is_none() {
            return false;
        }
        let seq = item.seq();
        if seq > snapshot.window_end {
            return false;
        }
        if !self.close_group() {
            return false;
        }
        let json = inbox_item_json(&item);
        self.group_bytes = self.group_bytes.saturating_add(json.len());
        self.group.push(json);
        self.group_batch = None;
        self.group_last = seq;
        true
    }

    /// Check the reader against the snapshot as a fresh request is checked (Switch wire 7.2):
    /// the account's key unchanged; the certificate it is checked against, with the key its
    /// request verified with; unexpired at the page's service time; not revoked or departed,
    /// listed and carried by its record. Its scopes and permissions are that certificate's.
    fn begin(&mut self, snapshot: &FeedSnapshot) -> bool {
        match &self.reader {
            #[cfg(test)]
            Reader::Fixed(cert) => {
                self.cert = Some(cert.clone());
                true
            }
            Reader::Checked {
                identity_key,
                service_key,
                service_public,
                origin,
                verified,
                time_ms,
            } => {
                // Expiry is judged in service time: the later of the request's stamp and the
                // last time the account committed. A quiet wait with no commit can so answer
                // an empty page a few seconds past the certificate's expiry; nothing new
                // reaches the app, and any commit after the expiry refuses it.
                self.time_ms = (*time_ms).max(snapshot.stamped_time_ms);
                if snapshot.service_key != *service_key {
                    self.retired = true;
                    return false;
                }
                let doc = match snapshot
                    .identity_doc
                    .as_ref()
                    .map(|doc| IdentityDoc::verify(doc, identity_key))
                    .transpose()
                {
                    Ok(doc) => doc,
                    Err(_) => {
                        self.error = Some(corrupt("the account's identity.json"));
                        return false;
                    }
                };
                match check_own_app(
                    identity_key,
                    doc.as_ref(),
                    snapshot.reader.as_ref(),
                    snapshot.reader_kept,
                    verified,
                    self.time_ms,
                ) {
                    Ok(cert) => {
                        // Then the staged gate, step 7 after step 5, as for a new request
                        // (Switch wire 7.3): a version delivered during the wait that no
                        // longer names this service ends the page.
                        if !super::rules::names_this_service(doc.as_ref(), origin, service_public) {
                            self.refusal = Some(Stop::Refused(ApiError::new(
                                ErrorCode::Staged,
                                "7.3: the account isn't named by its identity.json",
                            )));
                            return false;
                        }
                        self.cert = Some(cert);
                        true
                    }
                    Err(stop) => {
                        self.refusal = Some(stop);
                        false
                    }
                }
            }
        }
    }

    fn take(&mut self, snapshot: &FeedSnapshot, row: FeedRow) -> bool {
        let Some(cert) = self.cert.as_ref() else {
            return false;
        };
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
        let shown = match shows(&row, cert, &snapshot.current) {
            Ok(shown) => shown,
            Err(error) => {
                self.error = Some(error);
                return false;
            }
        };
        if !continues && !self.close_group() {
            return false;
        }
        let item = item_json(&row, shown);
        self.group_bytes = self.group_bytes.saturating_add(item.len());
        self.group.push(item);
        self.group_batch = batch;
        self.group_last = row.seq;
        true
    }
}

/// What one read of a long-poll gives: a page to answer with, or an empty one to answer
/// with only once the wait is over.
#[derive(Debug)]
pub(crate) enum Polled<T> {
    /// Answer with it.
    Ready(T),
    /// Nothing to read yet.
    Empty(T),
}

/// The long-poll (Switch wire 7.4.4): read, and answer at once with a page to show;
/// otherwise wait until `account` changes or `wait` passes, read again, and answer with the
/// page as it is then. The subscription comes before the first read, and each wake-up is
/// marked seen before the read that follows it, so no change after a read goes unseen.
pub(crate) async fn long_poll<T, E, F, Fut>(
    hub: &ChangeHub,
    account: &str,
    wait: Duration,
    mut read: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Polled<T>, E>>,
{
    let deadline = tokio::time::Instant::now() + wait;
    let mut changes = hub.subscribe(account);
    loop {
        changes.borrow_and_update();
        let page = match read().await? {
            Polled::Ready(page) => return Ok(page),
            Polled::Empty(page) => page,
        };
        if tokio::time::Instant::now() >= deadline {
            return Ok(page);
        }
        tokio::select! {
            changed = changes.changed() => {
                // The hub went away: answer with the page as it is.
                if changed.is_err() {
                    return Ok(page);
                }
            }
            () = tokio::time::sleep_until(deadline) => {}
        }
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
        time_ms: u64,
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
            reader: VerifiedApp::reading(reader.app_id(), reader.signing_key()),
            query,
            time_ms,
        })));
        Ok(answer)
    }

    /// The feed page of `read`, once the lock is gone, and the service time to sign it at:
    /// at once when it shows an item or more follow, or without `wait`; otherwise when the
    /// account changes or `wait` seconds pass, with the page as it is then (Switch wire
    /// 7.4.4).
    pub(super) async fn feed_page(
        &self,
        read: &FeedRead,
        signer: &ServiceSigner,
    ) -> Result<Answered, FeedStop> {
        // The latest service time a read of this wait has seen: no answer is signed at an
        // earlier one, so a refusal after a wait never shows the service's time going back
        // behind a page the same client was answered meanwhile (Switch spec 10.1).
        let latest = std::sync::atomic::AtomicU64::new(read.time_ms);
        let polled = long_poll(
            &self.changes,
            &read.account,
            Duration::from_secs(read.query.wait),
            || async {
                let answered = match self.read_page(read, signer).await {
                    Ok(answered) => answered,
                    Err(FeedStop::Refused(mut refusal)) => {
                        refusal.time_ms = refusal
                            .time_ms
                            .max(latest.load(std::sync::atomic::Ordering::Relaxed));
                        return Err(FeedStop::Refused(refusal));
                    }
                    Err(stop) => return Err(stop),
                };
                latest.fetch_max(answered.time_ms, std::sync::atomic::Ordering::Relaxed);
                Ok(if answered.ready {
                    Polled::Ready(answered)
                } else {
                    Polled::Empty(answered)
                })
            },
        )
        .await;
        let answered = match polled {
            Ok(answered) => answered,
            // A refusal from a snapshot moves the mark to its head first, as a page does; if
            // it can't, the refusal carries the request's own head instead.
            Err(FeedStop::Refused(mut refusal)) => {
                if let Some(snapshot) = &refusal.snapshot
                    && snapshot.tip.seq > 0
                {
                    let mark = Mark::from(snapshot.tip);
                    match self.keys.advance_mark(&read.service_key, mark).await {
                        Ok(_) | Err(KeyStoreError::NotFound) => {}
                        Err(_) => refusal.snapshot = None,
                    }
                }
                return Err(FeedStop::Refused(refusal));
            }
            Err(stop) => return Err(stop),
        };
        // The key's mark moves to the page's head first, so no head goes out that the mark
        // is behind, also when the page shows a commit whose own request hasn't moved it
        // yet (Switch wire 7.3 step 10).
        if let Some(mark) = answered.mark {
            match self.keys.advance_mark(&read.service_key, mark).await {
                // Erased once the page was read, its key deleted: never answered with it
                // (Switch wire 7.4.16).
                Ok(_) | Err(KeyStoreError::NotFound) => {}
                Err(_) => return Err(FeedStop::refused(temporary(), true, answered.time_ms)),
            }
        }
        // Signed by the caller under its proof (keyed.rs): only while the account still names
        // the key the read loaded, whatever its mark did (7.4.16).
        Ok(answered)
    }

    /// One page from one snapshot, and its head, signed. The key's mark is read before the
    /// snapshot, so the snapshot's head is at or past it unless the state went back.
    async fn read_page(
        &self,
        read: &FeedRead,
        signer: &ServiceSigner,
    ) -> Result<Answered, FeedStop> {
        let fallback = |error: ApiError, time_ms| FeedStop::refused(error, true, time_ms);
        let mark = match self.keys.mark(&read.service_key).await {
            Ok(mark) => mark,
            // An erasure deletes the account, then its key (Switch wire 7.4.16): a read that
            // waited on an account erased meanwhile answers as for one the service doesn't
            // host (7.3 step 2). Never with the key it loaded, which the erasure's answer was
            // the last to use: an account found again, as after a new enrollment, or one that
            // can't be looked up, gets the operator's temporary failure.
            Err(KeyStoreError::NotFound) => {
                return Err(
                    match self
                        .no_longer_keyed(&read.account, &read.service_key, false)
                        .await
                    {
                        Some(error) => gone_or_retired(&error),
                        None => fallback(temporary(), read.time_ms),
                    },
                );
            }
            Err(_) => return Err(fallback(temporary(), read.time_ms)),
        };
        let budget = usize::try_from(self.limits.max_page_bytes).unwrap_or(usize::MAX);
        let mut builder = PageBuilder::with(
            Reader::Checked {
                identity_key: read.identity_key,
                service_key: read.service_key.as_str().to_string(),
                service_public: super::PublicKeyBytes::public_key_bytes(signer),
                origin: self.origin.clone(),
                verified: read.reader.clone(),
                time_ms: read.time_ms,
            },
            read.query.limit,
            budget,
        );
        let snapshot = self
            .store
            .read_feed(
                &read.account,
                &read.reader.app_id(),
                read.query.after,
                POSITIONS_PER_PAGE,
                (MAX_BATCH_ENTRIES as u64).saturating_sub(1),
                &mut builder,
            )
            .await
            .map_err(|error| fallback(super::store_error(&error), read.time_ms))?
            .ok_or(FeedStop::Gone)?;
        if builder.retired {
            return Err(FeedStop::Retired);
        }
        let time_ms = builder.time_ms;
        let (seq, chain_hash) = snapshot.chain.unwrap_or((0, ZERO_HASH));
        let tip = ChainTip {
            generation: snapshot.generation,
            seq,
            chain_hash,
        };
        // The head is signed only when the page is answered, inside its proof (keyed.rs);
        // the key's mark is checked here, so each read of the wait refuses a state behind it.
        if !check_mark(mark.as_ref(), &Mark::from(tip)).allows_signing() {
            return Err(FeedStop::refused(behind_the_mark(), false, time_ms));
        }
        match builder.refusal.take() {
            Some(Stop::Refused(error)) => {
                return Err(FeedStop::Refused(Box::new(PageRefusal {
                    error,
                    head: true,
                    snapshot: Some(SnapshotHead {
                        tip,
                        key_mark: mark,
                        identity_key: read.identity_key,
                    }),
                    time_ms,
                })));
            }
            Some(Stop::Unauthenticated(error)) => {
                return Err(FeedStop::refused(error, false, time_ms));
            }
            None => {}
        }
        let page = builder
            .finish(&snapshot)
            .map_err(|error| fallback(super::store_error(&error), time_ms))?;
        Ok(Answered {
            ready: !page.items.is_empty() || page.more,
            page,
            mark: snapshot.chain.map(|(seq, chain_hash)| Mark {
                generation: snapshot.generation,
                seq,
                chain_hash,
            }),
            generation: snapshot.generation,
            // The caller's own cursor, from the page's snapshot (Switch spec 8.3, wire
            // 7.4.4). Its `seq` alone: a cooperative move and a key change in place continue
            // the sequence, and a recovery starts the account's apps afresh, so every cursor
            // the account holds is a position of its current sequence.
            cursor: snapshot
                .reader
                .as_ref()
                .and_then(|app| app.cursor)
                .map_or(0, |cursor| cursor.seq),
            tip,
            checkpoint: snapshot.checkpoint,
            key_mark: mark,
            identity_key: read.identity_key,
            time_ms,
        })
    }
}

/// The refusal of a page whose state is behind its key's mark (Switch wire 7.3 step 10).
fn behind_the_mark() -> ApiError {
    ApiError::unavailable(
        "7.3: the state is behind its service key's mark; a new generation is needed",
    )
}

/// A page read, before it is answered with its signed head.
#[derive(Debug)]
pub(super) struct Answered {
    page: Page,
    ready: bool,
    /// The head as a mark, `None` before the first chain item.
    mark: Option<Mark>,
    generation: u64,
    /// The `seq` of the caller's cursor the service holds, 0 before its first move.
    cursor: u64,
    /// The chain's head as the page shows it.
    tip: ChainTip,
    /// The latest checkpoint, which the page carries (Switch wire 7.4.4).
    checkpoint: Option<SignedHead>,
    /// The key's mark when the page was read, which its head must not be behind.
    key_mark: Option<Mark>,
    identity_key: [u8; 32],
    time_ms: u64,
}

impl Answered {
    /// The page's answer at its service time, `{ items, next, scanned_through, more, cursor,
    /// head, checkpoint }` in the member order of the wire's example (Switch wire 7.4.4), with the
    /// head, signed here inside the answer's proof, also in `Switch-Head`; `checkpoint` only
    /// once there is one.
    pub(super) fn answer(&self, signing: &Signing<'_>) -> (Answer, u64) {
        let Some(head) = signing.head(self.key_mark.as_ref(), &self.identity_key, &self.tip) else {
            return (Answer::error(&behind_the_mark()), self.time_ms);
        };
        let mut body = b"{\"items\":[".to_vec();
        for (index, item) in self.page.items.iter().enumerate() {
            if index > 0 {
                body.push(b',');
            }
            body.extend_from_slice(item);
        }
        body.extend_from_slice(b"],\"next\":\"");
        body.extend_from_slice(
            format!("{}:{}", self.generation, self.page.scanned_through).as_bytes(),
        );
        body.extend_from_slice(b"\",\"scanned_through\":");
        body.extend_from_slice(self.page.scanned_through.to_string().as_bytes());
        body.extend_from_slice(b",\"more\":");
        body.extend_from_slice(if self.page.more { b"true" } else { b"false" });
        body.extend_from_slice(b",\"cursor\":");
        body.extend_from_slice(self.cursor.to_string().as_bytes());
        body.extend_from_slice(b",\"head\":");
        body.extend_from_slice(&head.to_json());
        if let Some(checkpoint) = &self.checkpoint {
            body.extend_from_slice(b",\"checkpoint\":");
            body.extend_from_slice(&checkpoint.to_json());
        }
        body.push(b'}');
        (Answer::ok(body).with_head(Some(head)), self.time_ms)
    }
}

#[cfg(test)]
mod tests {
    use pubky_switch_core::{chain::Stub, keys::IdentityKey, records::AppCertBody, sig::SignedDoc};

    use super::*;
    use crate::store::{AppDocs, PageReader};

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
        reader_keyed([7; 32], scopes, permissions)
    }

    /// The same, for the app of signing key `signing`.
    fn reader_keyed(signing: [u8; 32], scopes: &[&str], permissions: &[Permission]) -> AppCert {
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
                signing,
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
        current.records.insert(8, "tasks".into());
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
        let all = reader(&["tasks"], &[Permission::ClaimsRead, Permission::ListsRead]);
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
        let neither = reader(&["tasks_share"], &[]);
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
        let sub = reader(&["tasks:team1"], &[Permission::ClaimsRead]);
        assert!(!matches!(
            shows(&row(8), &sub, &current).expect("shows"),
            Shown::Full { .. }
        ));
    }

    #[test]
    fn test_feed_visibility_of_superseded_and_deleted_documents() {
        let mut current = current_at_nine();
        let all = reader(&["tasks"], &[Permission::ClaimsRead]);
        // The record's delete at seq 10 supersedes the update at seq 8.
        current.records.clear();
        current.records.insert(10, "tasks".into());
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

    fn alice_key() -> IdentityKey {
        let keys = vectors("keys.json");
        let alice = keys["identities"]
            .as_array()
            .expect("identities")
            .iter()
            .find(|identity| identity["name"] == "alice")
            .expect("alice")
            .clone();
        IdentityKey::from_secret(hex32(&alice["secret_hex"]))
    }

    /// A chain item at `seq` of the signer's operation `kind`, shown in full only to
    /// `only_for` when given.
    fn op_row(seq: u64, kind: OpKind, only_for: Option<[u8; 16]>) -> FeedRow {
        let key = alice_key();
        let ops = pubky_switch_core::ops::sign_batch(
            &key,
            &key.public(),
            None,
            1,
            [seq.to_le_bytes()[0]; 16],
            vec![(Vec::new(), kind)],
        )
        .expect("batch");
        FeedRow {
            seq,
            item_type: ItemType::Op,
            item: Some(ops[0].signed().clone()),
            stub: row(3).stub,
            proof: None,
            only_for,
        }
    }

    fn full(row: &FeedRow, reader: &AppCert, current: &CurrentDocs) -> bool {
        matches!(
            shows(row, reader, current).expect("shows"),
            Shown::Full { .. }
        )
    }

    #[test]
    fn test_feed_visibility_of_the_lists() {
        use pubky_switch_core::ops::{AllowKind, InviteCodePut, InviteContext};
        let current = CurrentDocs::default();
        let none = reader(&["tasks"], &[]);
        let lists = reader(&["tasks"], &[Permission::ListsRead]);
        let adder = reader(&["tasks"], &[Permission::ConversationAdd]);
        for kind in [
            OpKind::AllowPut {
                pubky: [1; 32],
                kind: AllowKind::Contact,
            },
            OpKind::AllowDelete {
                pubky: [1; 32],
                kind: AllowKind::Conversation,
            },
            OpKind::DenyPut { pubky: [1; 32] },
            OpKind::DenyDelete { pubky: [1; 32] },
        ] {
            let row = op_row(20, kind, None);
            // allow.* and deny.*: lists.read only, not conversation.add.
            assert!(full(&row, &lists, &current));
            assert!(!full(&row, &adder, &current));
            assert!(!full(&row, &none, &current));
        }
        for kind in [
            OpKind::InviteCodePut(InviteCodePut {
                code_hash: [2; 32],
                expires_at: 1,
                max_uses: 1,
                context: InviteContext::new(serde_json::json!({ "order": 7 })),
            }),
            OpKind::InviteCodeDelete { code_hash: [2; 32] },
        ] {
            // invite_code.*: lists.read or conversation.add.
            let row = op_row(21, kind, None);
            assert!(full(&row, &lists, &current));
            assert!(full(&row, &adder, &current));
            assert!(!full(&row, &none, &current));
        }
    }

    #[test]
    fn test_feed_visibility_of_conversation_add() {
        let context = serde_json::json!({ "order": 7 });
        let transition = ServiceTransition::ConversationAdd {
            pubky: [1; 32],
            code_hash: [2; 32],
            context: context.clone(),
            at: 0,
        };
        let signed = transition
            .sign(
                &ed25519_dalek::SigningKey::from_bytes(&[5; 32]),
                &alice_key().public(),
            )
            .expect("sign");
        let row = FeedRow {
            seq: 22,
            item_type: ItemType::Service,
            item: Some(signed),
            stub: row(3).stub,
            proof: None,
            only_for: None,
        };
        let current = CurrentDocs::default();
        // lists.read sees it, with the invite code's context; conversation.add alone doesn't.
        assert_eq!(
            shows(&row, &reader(&[], &[Permission::ListsRead]), &current).expect("shows"),
            Shown::Full {
                context: Some(context)
            }
        );
        assert_eq!(
            shows(&row, &reader(&[], &[Permission::ConversationAdd]), &current).expect("shows"),
            Shown::Stub
        );
        let item: Value = serde_json::from_slice(&item_json(
            &row,
            Shown::Full {
                context: Some(serde_json::json!({ "order": 7 })),
            },
        ))
        .expect("json");
        assert_eq!(item["context"], serde_json::json!({ "order": 7 }));
    }

    #[test]
    fn test_feed_visibility_of_key_bundles_and_renewed_certificates() {
        use pubky_switch_core::ops::KeyBundlePut;
        let target = reader(&["tasks"], &[]);
        let other = reader_keyed(
            [9; 32],
            &["tasks"],
            &[Permission::ClaimsRead, Permission::ListsRead],
        );
        let part =
            pubky_switch_core::records::seal_bundle_parts(&alice_key(), &target, 1, 1, &|_| true)
                .expect("bundle")
                .remove(0);
        let bundle = op_row(
            23,
            OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: target.app_id(),
                bundle: part.bundle,
                first_epoch: 1,
                last_epoch: 1,
            }),
            Some(target.app_id()),
        );
        let mut current = CurrentDocs::default();
        current.bundles.insert(23);
        // Only its target reads a stored part; a part replaced since is a stub to it too.
        assert!(full(&bundle, &target, &current));
        assert!(!full(&bundle, &other, &current));
        current.bundles.clear();
        assert!(!full(&bundle, &target, &current));
        // A cert.put is shown while its certificate is the one stored, to every own app.
        let cert = op_row(
            24,
            OpKind::CertPut {
                target_app_id: target.app_id(),
                cert: target.signed().clone(),
            },
            None,
        );
        current.apps.insert(
            target.app_id(),
            AppDocs {
                record: None,
                renewed_cert: Some(target.signed().clone()),
            },
        );
        assert!(full(&cert, &other, &current));
        // Replaced, or carried by the record since, which drops it: a stub.
        current.apps.insert(target.app_id(), AppDocs::default());
        assert!(!full(&cert, &other, &current));
    }

    /// Whether some reader of `readers` is shown `row` in full.
    fn some_full(row: &FeedRow, readers: &[&AppCert], current: &CurrentDocs) -> bool {
        readers.iter().any(|reader| full(row, reader, current))
    }

    #[test]
    fn test_feed_documents_some_app_may_read_are_the_ones_shown_in_full() {
        // The store deletes a document exactly when no app may read it in full: its rule
        // (`CurrentDocs::shows_in_full_to_some_app`) agrees with `shows` over every reader,
        // the most permitted one and a key bundle's target among them, in each state below.
        use pubky_switch_core::ops::KeyBundlePut;
        let all = reader(
            &["tasks", "tasks_share"],
            &[
                Permission::ClaimsRead,
                Permission::ListsRead,
                Permission::ConversationAdd,
            ],
        );
        let target = reader_keyed([9; 32], &["tasks"], &[]);
        let readers = [&all, &target];
        let part =
            pubky_switch_core::records::seal_bundle_parts(&alice_key(), &target, 1, 1, &|_| true)
                .expect("bundle")
                .remove(0);
        let mut items = rows();
        items.push(op_row(
            23,
            OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: target.app_id(),
                bundle: part.bundle,
                first_epoch: 1,
                last_epoch: 1,
            }),
            Some(target.app_id()),
        ));
        items.push(op_row(
            24,
            OpKind::CertPut {
                target_app_id: target.app_id(),
                cert: target.signed().clone(),
            },
            None,
        ));
        let mut gone = row(1);
        gone.item = None;
        items.push(gone);
        let mut states = vec![current_at_nine()];
        let mut later = current_at_nine();
        later.records.clear();
        later.records.insert(10, "tasks".into());
        later.claim_entries.clear();
        for docs in later.apps.values_mut() {
            docs.record = Some(SignedDoc::from_parts(b"{}", &[0; 64]));
        }
        states.push(later);
        let mut stored = current_at_nine();
        stored.bundles.insert(23);
        stored.apps.insert(
            target.app_id(),
            AppDocs {
                record: None,
                renewed_cert: Some(target.signed().clone()),
            },
        );
        states.push(stored);
        // The target app known, its renewed certificate replaced or carried since.
        let mut carried = current_at_nine();
        carried.apps.insert(target.app_id(), AppDocs::default());
        states.push(carried);
        states.push(CurrentDocs::default());
        for (n, current) in states.iter().enumerate() {
            for row in &items {
                assert_eq!(
                    current.shows_in_full_to_some_app(row).expect("rule"),
                    some_full(row, &readers, current),
                    "state {n}, seq {}",
                    row.seq
                );
            }
        }
    }

    fn signed(name: &str) -> pubky_switch_core::sig::SignedDoc {
        let documents = vectors("documents.json");
        let doc = documents["documents"]
            .as_array()
            .expect("documents")
            .iter()
            .find(|doc| doc["name"] == name)
            .unwrap_or_else(|| panic!("no {name}"))
            .clone();
        serde_json::from_value(doc["signed"].clone()).expect("signed")
    }

    #[test]
    fn test_feed_reader_takes_a_reducing_renewal_in_the_snapshot() {
        // The wallet's renewal, which drops tasks_people_admin, lands during a wait: the next
        // page reads with the renewed certificate, the one the wallet is checked against now.
        let alice = alice_key();
        let op = SignedOp::peek(row(3).item.as_ref().expect("item")).expect("op");
        let OpKind::AppPut { record } = &op.body().kind else {
            panic!("seq 3 is the wallet's app.put");
        };
        let held =
            pubky_switch_core::records::AppRecord::verify(record, &alice.public()).expect("record");
        let renewed = signed("wallet certificate, renewed");
        let renewed_cert = AppCert::verify(&renewed, &alice.public()).expect("renewed");
        let doc = signed("alice identity.json, wallet renewal in progress");
        let identity = IdentityDoc::verify(&doc, &alice.public()).expect("doc");
        let app = held.cert().app_id();
        let mut snapshot = snapshot(7, 9, 9);
        snapshot.service_key = "key".into();
        snapshot.stamped_time_ms = renewed_cert.issued_at() + 1;
        snapshot.identity_doc = Some(doc);
        snapshot.reader = Some(crate::store::StoredApp {
            app_id: app,
            record: Some(record.clone()),
            record_at_ms: Some(0),
            renewed_cert: Some(renewed.clone()),
            receive_key: None,
            cursor: None,
            reachable_since: None,
            full_requested_ms: None,
            full_completed_seq: None,
        });
        snapshot
            .current
            .records
            .insert(8, "tasks_people_admin".into());
        let mut builder = PageBuilder::with(
            Reader::Checked {
                identity_key: alice.public(),
                service_key: "key".into(),
                service_public: identity.inbox().service_key,
                origin: identity.inbox().url.clone(),
                verified: VerifiedApp::reading(app, held.cert().signing_key()),
                time_ms: 0,
            },
            100,
            usize::MAX,
        );
        assert!(builder.begin(&snapshot));
        assert_eq!(
            builder.cert.as_ref().map(AppCert::hash),
            Some(renewed_cert.hash())
        );
        assert!(builder.take(&snapshot, row(8)));
        let page = builder.finish(&snapshot).expect("page");
        let item: Value = serde_json::from_slice(&page.items[0]).expect("json");
        assert_eq!(item["type"], "stub");
    }

    #[tokio::test]
    async fn test_feed_long_poll_sees_a_change_during_its_read() {
        // A change committed while the first read runs wakes the wait: the subscription comes
        // before the read, and each wake-up is marked seen before the read after it.
        let hub = ChangeHub::new();
        let reads = std::cell::Cell::new(0u32);
        let started = std::time::Instant::now();
        let answer: Result<u32, ()> = long_poll(&hub, "account", Duration::from_secs(10), || {
            let call = reads.get() + 1;
            reads.set(call);
            let hub = hub.clone();
            async move {
                if call == 1 {
                    hub.notify("account");
                    Ok(Polled::Empty(call))
                } else {
                    Ok(Polled::Ready(call))
                }
            }
        })
        .await;
        assert_eq!(answer, Ok(2));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "woken, not waited out"
        );
    }

    fn snapshot(start: u64, window_end: u64, last_seq: u64) -> FeedSnapshot {
        FeedSnapshot {
            generation: 1,
            last_seq,
            chain: None,
            start,
            window_end,
            current: current_at_nine(),
            ..FeedSnapshot::default()
        }
    }

    /// The seqs of the page `reader` reads of `chain.json` from `snapshot`.
    fn page(snapshot: &FeedSnapshot, limit: usize, budget: usize) -> (Vec<u64>, u64, bool) {
        let reader = reader(&["tasks"], &[Permission::ClaimsRead]);
        let mut builder = PageBuilder::new(reader, limit, budget);
        assert!(builder.begin(snapshot));
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
            .map(|item| {
                let item: Value = serde_json::from_slice(item).expect("json");
                item["seq"].as_u64().expect("seq")
            })
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
