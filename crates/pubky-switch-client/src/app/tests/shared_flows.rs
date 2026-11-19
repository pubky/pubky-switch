//! Sending, admission, shared records and claims against the scripted switch, with bob's
//! switch as the counterparty's, and a neutral protocol with one collection.

use std::sync::Arc;

use pubky_switch_core::claims::{Basis, ClaimStatus, ClaimView, RECONCILIATION_MS};
use pubky_switch_core::envelope::parse_header;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ident::{Policy, invite_code_hash};
use pubky_switch_core::message::MessagePlaintext;
use pubky_switch_core::ops::{AllowKind, Condition, KeyBundlePut, OpKind, RecordVersion, SignedOp};
use pubky_switch_core::records::{
    AppRecord, AppRecordBody, CLOCK_TOLERANCE_MS, DAY_MS, RemovedApp, RenewedCert,
    seal_bundle_parts,
};
use pubky_switch_core::scopes::Permission;
use serde_json::{Map, json};

use super::*;
use crate::app::{
    Alarm, AppError, AppEvent, ClaimOp, Collection, Delivery, IdentityRefresh, KeptReason,
    MAX_REGRESSION_REASON_BYTES, MAX_SEEN_MARK_BYTES, ObligationDeadline, OpBatch, OutgoingMessage,
    RecordContent, RecordJob, RecordRead, RecordTarget, Refusal, SentMessage, UndeliverableReason,
    Unopened, WriteBase, claim_conflict,
};
use crate::store::StoreHandle;
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::SWITCH_ORIGIN as ORIGIN;
use crate::testing::{Fault, PeerSwitch, Router};
use crate::transport::Transport;

const HOUR: u64 = 3_600_000;

/// A neutral protocol: [`SampleProtocol`]'s kinds, `sample.resend` as its re-send kind, and
/// one collection, `sample.items`, whose values list item IDs. What an app has seen of a
/// record is the IDs it held; a write that drops one goes back on it.
#[derive(Default)]
pub(crate) struct ItemsProtocol {
    pub(crate) sample: SampleProtocol,
    /// Bytes added to each mark, and to each rule a regression gives.
    pub(crate) pad: std::sync::Mutex<usize>,
    /// Bytes added to the next marks, one each, ahead of `pad`.
    pub(crate) pads: std::sync::Mutex<std::collections::VecDeque<usize>>,
    /// What each newer write checked against a mark built on.
    pub(crate) bases: std::sync::Mutex<Vec<WriteBase>>,
    /// The collections in place of `sample.items` alone, when set.
    pub(crate) collections: std::sync::Mutex<Option<Vec<Collection>>>,
    /// Whether a delete goes back on what was seen, as for a protocol whose seen records
    /// are never let go.
    pub(crate) deletes_regress: std::sync::atomic::AtomicBool,
    qualify_items: std::sync::atomic::AtomicBool,
    append_item_on_note: std::sync::atomic::AtomicBool,
    observe_values: std::sync::atomic::AtomicBool,
    observation_bytes: std::sync::atomic::AtomicUsize,
    observe_deletes: std::sync::atomic::AtomicBool,
    end_mark_at_delete: std::sync::atomic::AtomicBool,
    hold_deletes: std::sync::atomic::AtomicBool,
    pending_publication: Mutex<Option<RecordVersion>>,
    publish_records: std::sync::atomic::AtomicBool,
    replacement_value: Mutex<Option<Vec<u8>>>,
    observation_unavailable: std::sync::atomic::AtomicBool,
    /// Whether a delete fails a check of the protocol's own, seen or not.
    pub(crate) refuses_deletes: std::sync::atomic::AtomicBool,
    /// An item no write may hold, seen or not: a check of the protocol's own that a first
    /// write fails too.
    pub(crate) forbidden: std::sync::Mutex<Option<String>>,
    keep_receipts: std::sync::atomic::AtomicBool,
    read_previous: std::sync::atomic::AtomicBool,
    previous_must_be_empty: std::sync::atomic::AtomicBool,
    previous_read_count: std::sync::atomic::AtomicUsize,
    large_receipt: std::sync::atomic::AtomicBool,
}

pub(crate) fn items() -> Collection {
    Collection::new("sample.items", Policy::new("sample-a", &["sample-a"]))
}

pub(crate) fn value(ids: &[&str]) -> Vec<u8> {
    json!({ "items": ids }).to_string().into_bytes()
}

pub(crate) fn ids(bytes: Option<&[u8]>) -> Vec<String> {
    bytes
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
        .and_then(|v| v["items"].as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

impl Protocol for ItemsProtocol {
    fn name(&self) -> String {
        "sample".into()
    }

    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.sample.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        let mut kinds = self.sample.accepts(cert);
        if !kinds.is_empty() {
            kinds.push("sample.resend".into());
        }
        kinds
    }

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(message)
    }

    fn receive(
        &self,
        message: &ReceivedMessage,
        cx: &mut crate::app::ReceiveContext<'_>,
    ) -> Outcome {
        if self
            .append_item_on_note
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            let target = RecordTarget::new(items(), b"n1");
            let key = cx.record_key(&target).unwrap();
            let held = cx.record(&target).unwrap().unwrap();
            let seen = cx.record_seen(&key).unwrap().unwrap();
            assert_eq!(held.content.value(), Some(seen.as_slice()));
            assert!(!held.flagged && !held.not_taken && !held.divergent);
            assert!(matches!(
                cx.put_record(&target, &value(&["n1", "first"]), vec![]),
                Err(AppError::Refused(Refusal::Usage(_)))
            ));
            let condition = cx.record_condition(&key).unwrap();
            cx.put_record(
                &target,
                &value(&["n1", "first", "second", "third"]),
                vec![condition],
            )
            .unwrap();
            return Outcome::Apply(Effect::default());
        }
        self.sample.receive(message, cx)
    }

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.missed(missed)
    }

    fn adds_conversation(&self, kind: &str) -> bool {
        kind != "sample.resend"
    }

    fn collections(&self) -> Vec<Collection> {
        self.collections
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| vec![items()])
    }

    fn qualify_record_mark(
        &self,
        input: &crate::app::RecordMarkContext<'_>,
        seen: Option<&[u8]>,
        value: &[u8],
    ) -> Option<Result<Vec<u8>, String>> {
        if !self
            .qualify_items
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return None;
        }
        let items_seen = ids(Some(value));
        let result = match items_seen.first() {
            Some(name)
                if input
                    .record_key(&RecordTarget::new(items(), name.as_bytes()))
                    .ok()
                    == Some(input.key)
                    && items_seen.starts_with(&ids(seen)) =>
            {
                Ok(value.to_vec())
            }
            _ => Err("item names differ from the target or previously listed items".to_owned()),
        };
        Some(result)
    }

    fn observe_record(
        &self,
        observed: &crate::app::RecordObservation<'_>,
        cx: &crate::app::ReceiveContext<'_>,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        use std::sync::atomic::Ordering::Relaxed;
        if !self.observe_values.load(Relaxed) || !observed.current || observed.record.divergent {
            return Ok(Vec::new());
        }
        let targets = [
            RecordTarget::new(items(), b"n1"),
            RecordTarget::new(items(), b"n2"),
        ];
        let Some(target) = targets
            .iter()
            .find(|target| observed.record.key == cx.record_key(target).unwrap())
        else {
            return Ok(Vec::new());
        };
        let signed = SignedOp::peek(observed.operation).unwrap();
        assert_eq!(signed.item_hash().unwrap(), observed.application.item_hash);
        assert_eq!(signed.body().app_id, Some(observed.record.writer));
        assert_eq!(observed.record.policy, target.collection.policy);
        assert!(observed.record.authenticated);
        let mut kept = ids(cx.local_get(b"accepted-items").unwrap().as_deref());
        let mut changed = false;
        for id in ids(observed.record.content.value()) {
            if !kept.contains(&id) {
                kept.push(id);
                changed = true;
            }
        }
        if !changed {
            return Ok(Vec::new());
        }
        let mut value = value(&kept.iter().map(String::as_str).collect::<Vec<_>>());
        value.resize(value.len() + self.observation_bytes.load(Relaxed), b' ');
        let mut transitions: Vec<Vec<String>> = cx
            .local_get(b"previous-items")
            .unwrap()
            .map(|v| serde_json::from_slice(&v).unwrap())
            .unwrap_or_default();
        transitions.push(ids(observed
            .previous
            .and_then(|prior| prior.content.value())));
        Ok(vec![
            LocalWrite::Put {
                key: b"accepted-items".to_vec(),
                value,
            },
            LocalWrite::Put {
                key: b"previous-items".to_vec(),
                value: serde_json::to_vec(&transitions).unwrap(),
            },
        ])
    }

    fn mark_ends_at_delete(&self, collection: &str) -> bool {
        collection == items().name
            && self
                .end_mark_at_delete
                .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn record_lifetime_ended(
        &self,
        record: &crate::app::RecordMarkContext<'_>,
        version: RecordVersion,
        cx: &crate::app::ReceiveContext<'_>,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        use std::sync::atomic::Ordering::SeqCst;
        assert_eq!(record.collection.name, items().name);
        if self.observation_unavailable.load(SeqCst) {
            return Err(crate::app::StoreFailure::unavailable(
                crate::error::StoreError::Unavailable,
            ));
        }
        let mut value = lifetime_version(version);
        if self.large_receipt.load(SeqCst) {
            value.resize(crate::app::MAX_STEP_LOCAL_BYTES + 1, 0);
        }
        if cx.local_get(&record.key).unwrap().as_ref() == Some(&value) {
            return Ok(Vec::new());
        }
        Ok(vec![LocalWrite::Put {
            key: record.key.to_vec(),
            value,
        }])
    }

    fn record_seen(&self, _: &str, seen: Option<&[u8]>, value: Option<&[u8]>) -> Option<Vec<u8>> {
        let mut all = ids(seen);
        for id in ids(value) {
            if !all.contains(&id) {
                all.push(id);
            }
        }
        let all: Vec<&str> = all.iter().map(String::as_str).collect();
        let mut mark = super::shared_flows::value(&all);
        let pad = self.pads.lock().unwrap().pop_front();
        let pad = pad.unwrap_or(*self.pad.lock().unwrap());
        mark.extend(std::iter::repeat_n(b' ', pad));
        Some(mark)
    }

    fn record_put_back_successor(
        &self,
        deletion: &crate::app::RecordDeletion<'_>,
        successor: &crate::app::RecordSuccessor<'_>,
        _: &crate::app::ReceiveContext<'_>,
    ) -> Result<crate::app::PutBackSuccessor, crate::app::StoreFailure> {
        let current = ids(Some(successor.value));
        let covered = *self.pending_publication.lock().unwrap() != Some(deletion.version)
            && deletion
                .exact_value
                .is_some_and(|v| ids(Some(v)).iter().all(|id| current.contains(id)));
        Ok(if covered {
            crate::app::PutBackSuccessor::Covered
        } else if self
            .publish_records
            .load(std::sync::atomic::Ordering::SeqCst)
            && let Some(prior) = deletion.exact_value
            && deletion.exact_version_authenticated
        {
            let mut merged: serde_json::Value = serde_json::from_slice(successor.value).unwrap();
            let items = merged["items"].as_array_mut().unwrap();
            for id in ids(Some(prior)).into_iter().map(serde_json::Value::String) {
                if !items.contains(&id) {
                    items.push(id);
                }
            }
            crate::app::PutBackSuccessor::Merge {
                value: merged.to_string().into_bytes(),
            }
        } else {
            crate::app::PutBackSuccessor::Wait
        })
    }

    fn record_put_back(
        &self,
        deletion: &crate::app::RecordDeletion<'_>,
        cx: &crate::app::ReceiveContext<'_>,
    ) -> Result<Option<crate::app::PutBack>, crate::app::StoreFailure> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.publish_records.load(SeqCst)
            && deletion.original_in_current_generation
            && deletion.exact_version_authenticated
            && let Some(value) = deletion.exact_value
        {
            return Ok(Some(crate::app::PutBack::Write {
                value: self
                    .replacement_value
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| value.to_vec()),
                observed: vec![],
            }));
        }
        if self.hold_deletes.load(SeqCst) && deletion.exact_value.is_some() {
            return Ok(Some(crate::app::PutBack::Prepare { observed: vec![] }));
        }
        if !self.observe_deletes.load(SeqCst) {
            return Ok(None);
        }
        if self.observation_unavailable.load(SeqCst) {
            return Err(crate::app::StoreFailure::unavailable(
                crate::error::StoreError::Unavailable,
            ));
        }
        let mut receipts: Vec<serde_json::Value> = cx
            .local_get(b"delete receipts")
            .unwrap()
            .map(|v| serde_json::from_slice(&v).unwrap())
            .unwrap_or_default();
        if self.large_receipt.load(SeqCst) {
            return Ok(Some(crate::app::PutBack::Observe {
                observed: vec![LocalWrite::Put {
                    key: b"oversize".to_vec(),
                    value: vec![1; crate::app::MAX_STEP_LOCAL_BYTES + 1],
                }],
            }));
        }
        receipts.push(json!({"key": deletion.key, "hash": deletion.item_hash, "writer":deletion.writer,
            "version": [deletion.version.generation, deletion.version.version], "page": deletion.page_time_ms,
            "seen": deletion.seen.map(|v| String::from_utf8_lossy(v)), "value": deletion.exact_value.map(|v|String::from_utf8_lossy(v)),
            "policy": deletion.policy.is_some(), "original": deletion.original_in_current_generation, "dated": deletion.exact_version_authenticated}));
        Ok(Some(crate::app::PutBack::Observe {
            observed: vec![LocalWrite::Put {
                key: b"delete receipts".to_vec(),
                value: serde_json::to_vec(&receipts).unwrap(),
            }],
        }))
    }

    fn restore_layer(
        &self,
        layer: Option<&crate::app::ProtocolLayer>,
        restoring: &crate::app::RestoreContext<'_>,
    ) -> Result<Vec<LocalWrite>, String> {
        let mut writes = self.sample.restore_layer(layer, restoring)?;
        if self.read_previous.load(std::sync::atomic::Ordering::SeqCst) {
            for record in restoring.previous_records_of("sample.items") {
                let record = record.map_err(|e| e.to_string())?;
                self.previous_read_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if self
                    .previous_must_be_empty
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    return Err("the destination unexpectedly supplied records".into());
                }
                writes.push(LocalWrite::Put {
                    key: record.key.to_vec(),
                    value: serde_json::to_vec(&json!({"value":record.content.value(), "writer":record.writer,
                        "version":[record.version.generation,record.version.version], "authenticated":record.authenticated,
                        "divergent":record.divergent,"doubtful":record.doubtful})).unwrap(),
                });
            }
        }
        if self.keep_receipts.load(std::sync::atomic::Ordering::SeqCst) {
            for (key, value) in restoring
                .previous_local_scan(b"delete receipts")
                .map_err(|e| e.to_string())?
            {
                writes.push(LocalWrite::Put { key, value });
            }
        }
        Ok(writes)
    }

    fn record_regression(
        &self,
        _: &str,
        seen: Option<&[u8]>,
        value: Option<&[u8]>,
        base: WriteBase,
    ) -> Option<String> {
        self.bases.lock().unwrap().push(base);
        let Some(value) = value else {
            return ((seen.is_some()
                && self
                    .deletes_regress
                    .load(std::sync::atomic::Ordering::SeqCst))
                || self
                    .refuses_deletes
                    .load(std::sync::atomic::Ordering::SeqCst))
            .then(|| "sample: a record seen was deleted".to_owned());
        };
        let held = ids(Some(value));
        if let Some(forbidden) = self.forbidden.lock().unwrap().as_ref()
            && held.contains(forbidden)
        {
            return Some("sample: a forbidden item".to_owned());
        }
        let pad = "é".repeat(*self.pad.lock().unwrap());
        ids(seen)
            .iter()
            .any(|id| !held.contains(id))
            .then(|| format!("sample: an item seen was dropped{pad}"))
    }

    fn sent_record(
        &self,
        _: &RecordJob,
        sent: &SentMessage,
        current: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        let mut all = ids(current);
        if all.contains(&sent.msg_id) {
            return None;
        }
        all.push(sent.msg_id.clone());
        let all: Vec<&str> = all.iter().map(String::as_str).collect();
        Some(value(&all))
    }
}

const ALL_PERMISSIONS: [Permission; 5] = Permission::ALL;

/// Alice's world, bob's switch, and a router between them.
struct Setup {
    w: World,
    peer: Arc<PeerSwitch>,
    protocol: Arc<ItemsProtocol>,
    router: Arc<Router>,
}

impl Setup {
    fn new() -> Self {
        let w = World::new();
        let peer = PeerSwitch::new(
            identity("bob"),
            PEER_ORIGIN,
            Arc::clone(&w.clock),
            Arc::clone(&w.homeserver),
        );
        peer.add_app(
            "shop",
            &AppSpec::new(&["sample-a"]),
            &["sample.note", "sample.resend"],
            false,
        )
        .unwrap();
        let router = Arc::new(Router::new());
        router.add_switch(ORIGIN, &w.switch);
        router.add(PEER_ORIGIN, peer.transport());
        Self {
            w,
            peer,
            protocol: Arc::new(ItemsProtocol::default()),
            router,
        }
    }

    fn env_on(&self, store: Arc<dyn StateStore>) -> AppEnv {
        self.w
            .signer
            .env_with(store, Arc::clone(&self.router) as Arc<dyn Transport>)
    }

    fn env(&self) -> AppEnv {
        self.env_on(Arc::clone(&self.w.store) as Arc<dyn StateStore>)
    }

    /// The signer approves `keys` with `permissions`.
    fn approve(&self, keys: &AppKeys, permissions: &[Permission]) -> JoinRequest {
        let app = AppSpec::new(&["sample-a"]).with_permissions(permissions);
        self.w.signer.approve(keys, &app).unwrap()
    }

    async fn join_with(&self, name: &str, permissions: &[Permission]) -> App {
        let request = self.approve(&app_keys(name), permissions);
        App::join(self.env(), self.protocol.clone(), World::config(), request)
            .await
            .unwrap()
    }

    async fn join(&self, name: &str) -> App {
        self.join_with(name, &ALL_PERMISSIONS).await
    }

    fn note(&self, text: &str) -> OutgoingMessage {
        let mut body = Map::new();
        body.insert("text".into(), json!(text));
        OutgoingMessage::new(self.w.bob.public(), "sample.note", body)
    }

    fn conversation_entries(&self, pubky: &[u8; 32]) -> usize {
        self.w
            .switch
            .applied()
            .iter()
            .filter(|op| {
                matches!(op.body().kind, OpKind::AllowPut { pubky: p, kind: AllowKind::Conversation }
                         if p == *pubky)
            })
            .count()
    }

    fn log(&self) -> Vec<String> {
        self.router.log()
    }

    fn target(&self, natural: &str) -> RecordTarget {
        RecordTarget::new(items(), natural.as_bytes())
    }
}

fn accepted(delivery: &Delivery) -> bool {
    matches!(delivery, Delivery::Accepted { .. })
}

fn position(log: &[String], what: &str) -> usize {
    log.iter()
        .position(|line| line.contains(what))
        .unwrap_or_else(|| panic!("{what} isn't in {log:?}"))
}

// -------------------------------------------------------------------------------------
// Sending

#[tokio::test]
async fn test_send_first_message_adds_the_conversation_entry_before_sending() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let bob = s.w.bob.public();
    let (msg_id, delivery) = app.send(s.note("hello")).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    assert_eq!(s.peer.received(), vec![msg_id.clone()]);
    assert_eq!(s.conversation_entries(&bob), 1);
    // The entry, then the own identity.json at bob's switch, then the append.
    let log = s.log();
    let entry = position(&log, &format!("POST {ORIGIN}"));
    let peers = position(&log, &format!("PUT {PEER_ORIGIN}"));
    let append = position(&log, &format!("POST {PEER_ORIGIN}"));
    assert!(entry < peers && peers < append, "{log:?}");
    // A later message adds no second entry.
    let (second, delivery) = app.send(s.note("again")).await.unwrap();
    assert!(accepted(&delivery));
    assert_eq!(s.conversation_entries(&bob), 1);
    assert_eq!(s.peer.received(), vec![msg_id, second]);
}

#[tokio::test]
async fn test_send_resend_kind_adds_no_conversation_entry() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let mut message = s.note("asking");
    message.kind = "sample.resend".into();
    let (_, delivery) = app.send(message).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    assert_eq!(s.conversation_entries(&s.w.bob.public()), 0);
}

#[tokio::test]
async fn test_send_without_conversation_add_writes_no_entry() {
    let s = Setup::new();
    let mut app = s.join_with("wallet", &[]).await;
    let (_, delivery) = app.send(s.note("hello")).await.unwrap();
    assert!(accepted(&delivery));
    assert_eq!(s.conversation_entries(&s.w.bob.public()), 0);
}

#[tokio::test]
async fn test_send_stale_key_checks_the_record_and_seals_again() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let (first, _) = app.send(s.note("one")).await.unwrap();
    // Bob rotates; the cached directory still names the old key.
    s.peer.rotate(0).unwrap();
    let (second, delivery) = app.send(s.note("two")).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    assert_eq!(s.peer.received(), vec![first, second]);
    let inner = s.peer.lock();
    let last = &inner.inbox.last().unwrap().envelope;
    let new_kid = inner.apps[0].receive_keys[1].0.kid;
    assert_eq!(
        parse_header(last).unwrap().kids().collect::<Vec<_>>(),
        vec![new_kid]
    );
    let appends = inner
        .requests
        .iter()
        .filter(|(m, r)| m == "POST" && r == "inbox")
        .count();
    // One for the first message, two for the second: refused, then sealed again.
    assert_eq!(appends, 3);
}

#[tokio::test]
async fn test_send_stale_key_with_an_older_record_is_not_sealed_to() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.peer.rotate(0).unwrap();
    app.send(s.note("one")).await.unwrap();
    // A stale_key answer offering the key of n 0, after n 1 was seen: ignored.
    let (old, app_id) = {
        let inner = s.peer.lock();
        (
            inner.apps[0].receive_keys[0].1.clone(),
            inner.apps[0].cert.app_id(),
        )
    };
    s.peer.fail_next(
        "inbox",
        ErrorCode::StaleKey,
        json!({ "receive_keys": [ { "app_id": pubky_switch_core::enc::zbase32_encode(&app_id),
                                    "record": old } ],
                "not_current": [], "unknown_kids": [], "added_apps": [], "apps_version": 1 }),
    );
    let (_, delivery) = app.send(s.note("two")).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    let inner = s.peer.lock();
    let current = inner.apps[0].receive_keys[1].0.kid;
    let last = &inner.inbox.last().unwrap().envelope;
    assert_eq!(
        parse_header(last).unwrap().kids().collect::<Vec<_>>(),
        vec![current]
    );
}

#[tokio::test]
async fn test_send_stale_key_naming_an_app_twice_reads_the_directory_again() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.send(s.note("one")).await.unwrap();
    let (record, app_id) = {
        let inner = s.peer.lock();
        (
            inner.apps[0].receive_keys[0].1.clone(),
            pubky_switch_core::enc::zbase32_encode(&inner.apps[0].cert.app_id()),
        )
    };
    s.peer.fail_next(
        "inbox",
        ErrorCode::StaleKey,
        json!({ "receive_keys": [ { "app_id": app_id, "record": record },
                                  { "app_id": app_id, "record": record } ],
                "not_current": [], "unknown_kids": [], "added_apps": [], "apps_version": 1 }),
    );
    s.peer.lock().requests.clear();
    let (_, delivery) = app.send(s.note("two")).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    // Nothing is taken from it: the directory is read again (Switch wire 7.6).
    let routes = s.peer.routes();
    assert_eq!(
        routes,
        vec!["POST inbox", "GET directory", "POST inbox"],
        "{routes:?}"
    );
}

#[tokio::test]
async fn test_directory_naming_an_app_twice_is_refused() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.peer
        .add_app("till", &AppSpec::new(&["sample-a"]), &["sample.note"], true)
        .unwrap();
    {
        let mut inner = s.peer.lock();
        let copy = crate::testing::PeerApp {
            keys: inner.apps[1].keys.clone(),
            cert: inner.apps[1].cert.clone(),
            record: inner.apps[1].record.clone(),
            receive_keys: inner.apps[1].receive_keys.clone(),
            since: inner.apps[1].since,
        };
        inner.apps.push(copy);
    }
    // None of it is used, not even the app listed once: the message waits for a directory
    // read again later (Switch wire 7.4.10).
    let (msg_id, delivery) = app.send(s.note("hello")).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    assert!(s.peer.received().is_empty());
    s.peer.lock().apps.pop();
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()]);
    assert_eq!(s.peer.received(), vec![msg_id]);
}

#[tokio::test]
async fn test_send_added_app_joins_the_recipients_after_stale_key() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.send(s.note("one")).await.unwrap();
    let till = s
        .peer
        .add_app("till", &AppSpec::new(&["sample-a"]), &["sample.note"], true)
        .unwrap();
    let (_, delivery) = app.send(s.note("two")).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    let inner = s.peer.lock();
    let last = &inner.inbox.last().unwrap().envelope;
    assert_eq!(parse_header(last).unwrap().kids().count(), 2);
    assert!(inner.apps.iter().any(|a| a.cert.app_id() == till));
}

#[tokio::test]
async fn test_send_identity_needed_delivers_then_retries() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.send(s.note("one")).await.unwrap();
    // Bob's switch dropped its copy of alice's identity.json.
    s.peer.lock().peers.clear();
    s.peer.lock().requests.clear();
    let (_, delivery) = app.send(s.note("two")).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    let routes = s.peer.routes();
    assert_eq!(
        routes,
        vec!["POST inbox", "PUT peers", "POST inbox"],
        "{routes:?}"
    );
}

#[tokio::test]
async fn test_send_identity_needed_twice_stays_queued_then_goes() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    for _ in 0..2 {
        s.peer.fail_next(
            "inbox",
            ErrorCode::IdentityNeeded,
            json!({ "version": null }),
        );
    }
    let (msg_id, delivery) = app.send(s.note("one")).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    assert!(s.peer.received().is_empty());
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()]);
    assert_eq!(s.peer.received(), vec![msg_id]);
}

#[tokio::test]
async fn test_send_refused_for_good_is_failed_not_retried() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.peer.fail_next("inbox", ErrorCode::TooLarge, json!(null));
    let (msg_id, delivery) = app.send(s.note("one")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Failed { failed_at_ms, .. } if failed_at_ms == s.w.clock.now_ms()),
        "{delivery:?}"
    );
    s.w.clock.advance_ms(1000);
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.failed, vec![msg_id.clone()]);
    // The time it was refused, not the time it was last read.
    assert!(matches!(
        app.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Failed { failed_at_ms, .. }) if failed_at_ms == s.w.clock.now_ms() - 1000
    ));
    assert!(s.peer.received().is_empty());
    // Forgotten, plaintext and all, after the retention of sent messages.
    s.w.clock.advance_ms(29 * DAY_MS);
    assert_eq!(
        app.flush_outbox().await.unwrap().failed,
        vec![msg_id.clone()]
    );
    s.w.clock.advance_ms(2 * DAY_MS);
    let report = app.flush_outbox().await.unwrap();
    assert!(report.failed.is_empty(), "{report:?}");
    assert_eq!(app.delivery(&msg_id).await.unwrap(), None);
}

#[tokio::test]
async fn test_send_refused_for_good_is_failed_at_the_refusal_not_the_queueing() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let msg_id = app.queue(s.note("one")).await.unwrap();
    s.w.clock.advance_ms(1000);
    s.peer.fail_next("inbox", ErrorCode::TooLarge, json!(null));
    app.flush_outbox().await.unwrap();
    s.w.clock.advance_ms(1000);
    assert!(matches!(
        app.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Failed { failed_at_ms, .. }) if failed_at_ms == s.w.clock.now_ms() - 1000
    ));
}

/// `403 not_current` is about the sender's own certificate, not the recipient: the queued
/// delivery says so, apart from `403 not_admitted`.
#[tokio::test]
async fn test_send_sender_not_current_is_queued_with_its_reason() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let first = s.w.clock.now_ms();
    s.peer
        .fail_next("inbox", ErrorCode::NotCurrent, json!(null));
    let (msg_id, delivery) = app.send(s.note("one")).await.unwrap();
    assert!(
        matches!(
            delivery,
            Delivery::Queued {
                undeliverable_since_ms: Some(at),
                undeliverable_reason: Some(UndeliverableReason::NotCurrent),
                ..
            } if at == first
        ),
        "{delivery:?}"
    );
    // Accepted once the certificate is current again: the reason goes with the wait.
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()]);
    assert!(matches!(
        app.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
}

#[tokio::test]
async fn test_send_not_admitted_stays_queued_and_goes_once_admitted() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.peer.lock().admitted = Some(Default::default());
    let first = s.w.clock.now_ms();
    let (msg_id, delivery) = app.send(s.note("one")).await.unwrap();
    assert!(
        matches!(
            delivery,
            Delivery::Queued {
                undeliverable_since_ms: Some(at),
                undeliverable_reason: Some(UndeliverableReason::NotAdmitted),
                ..
            } if at == first
        ),
        "{delivery:?}"
    );
    // A later try answered the same keeps the time of the first.
    s.w.clock.advance_ms(HOUR);
    assert_eq!(
        app.flush_outbox().await.unwrap().queued,
        vec![msg_id.clone()]
    );
    assert!(matches!(
        app.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Queued { undeliverable_since_ms: Some(at), .. }) if at == first
    ));
    assert!(s.peer.received().is_empty());
    // Bob adds alice as a contact: the same message goes.
    s.peer.lock().admitted = None;
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()]);
    assert_eq!(s.peer.received(), vec![msg_id]);
}

#[tokio::test]
async fn test_send_not_admitted_is_deleted_after_30_days() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.peer.lock().admitted = Some(Default::default());
    let (msg_id, _) = app.send(s.note("one")).await.unwrap();
    app.take_events();
    // Queued for 30 days from the first such answer, over tries spread across them
    // (Switch spec 11).
    for _ in 2..crate::app::UNDELIVERABLE_TRIES {
        s.w.clock
            .advance_ms(crate::app::UNDELIVERABLE_TRY_SPACING_MS);
        assert_eq!(
            app.flush_outbox().await.unwrap().queued,
            vec![msg_id.clone()]
        );
    }
    s.w.clock
        .advance_ms(crate::app::UNDELIVERABLE_TRY_SPACING_MS);
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![msg_id.clone()]);
    assert!(report.queued.is_empty(), "{report:?}");
    // Deleted, plaintext and all, and the protocol told.
    assert_eq!(app.delivery(&msg_id).await.unwrap(), None);
    assert!(
        app.take_events().iter().any(|e| matches!(
            e,
            AppEvent::MessageUndelivered { msg_id: m, resend: false, .. } if *m == msg_id
        )),
        "the protocol is told"
    );
    // Durably: a load tells it again until it is acknowledged.
    let mut loaded = App::load(s.env(), s.protocol.clone(), World::config(), app.app_id())
        .await
        .unwrap();
    let told = loaded.take_events();
    assert!(
        told.iter().any(|e| matches!(
            e,
            AppEvent::MessageUndelivered { msg_id: m, .. } if *m == msg_id
        )),
        "{told:?}"
    );
    // Admitted later, it isn't sent.
    s.peer.lock().admitted = None;
    let report = app.flush_outbox().await.unwrap();
    assert!(report.done.is_empty(), "{report:?}");
    assert!(s.peer.received().is_empty());
}

#[tokio::test]
async fn test_send_not_admitted_is_tried_once_more_before_it_is_deleted() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.peer.lock().admitted = Some(Default::default());
    let (msg_id, _) = app.send(s.note("one")).await.unwrap();
    for _ in 2..crate::app::UNDELIVERABLE_TRIES {
        s.w.clock
            .advance_ms(crate::app::UNDELIVERABLE_TRY_SPACING_MS);
        app.flush_outbox().await.unwrap();
    }
    // Admitted on day 29; the next flush comes past day 30, and the message goes.
    s.peer.lock().admitted = None;
    s.w.clock.advance_ms(9 * DAY_MS);
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()], "{report:?}");
    assert_eq!(s.peer.received(), vec![msg_id]);
}

#[tokio::test]
async fn test_send_not_admitted_is_deleted_at_45_days_with_sparse_flushes() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.peer.lock().admitted = Some(Default::default());
    let (msg_id, _) = app.send(s.note("one")).await.unwrap();
    app.take_events();
    // Two flushes in 45 days: far fewer answers than confirm the 30 days.
    s.w.clock.advance_ms(20 * DAY_MS);
    app.flush_outbox().await.unwrap();
    s.w.clock
        .advance_ms(crate::app::UNDELIVERABLE_MAX_MS - 20 * DAY_MS - 1);
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.queued, vec![msg_id.clone()], "{report:?}");
    // At 45 days from the first answer it goes, plaintext and all, untried.
    s.w.clock.advance_ms(1);
    s.peer.lock().admitted = None;
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![msg_id.clone()], "{report:?}");
    assert_eq!(app.delivery(&msg_id).await.unwrap(), None);
    assert!(s.peer.received().is_empty());
    assert!(app.take_events().iter().any(|e| matches!(
        e,
        AppEvent::MessageUndelivered { id: _, msg_id: m, resend: false } if *m == msg_id
    )));
}

#[tokio::test]
async fn test_send_not_admitted_isnt_deleted_by_a_31_day_clock_jump() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.peer.lock().admitted = Some(Default::default());
    let (msg_id, _) = app.send(s.note("one")).await.unwrap();
    s.w.clock.advance_ms(31 * DAY_MS);
    for _ in 0..5 {
        let report = app.flush_outbox().await.unwrap();
        assert_eq!(report.queued, vec![msg_id.clone()], "{report:?}");
        s.w.clock.advance_ms(60_000);
    }
    assert!(app.delivery(&msg_id).await.unwrap().is_some());
}

#[tokio::test]
async fn test_send_not_admitted_isnt_deleted_by_a_clock_jump() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.peer.lock().admitted = Some(Default::default());
    let (msg_id, _) = app.send(s.note("one")).await.unwrap();
    // The clock jumps 40 days ahead: one try counts, and the tries right after add none.
    s.w.clock.advance_ms(40 * DAY_MS);
    for _ in 0..5 {
        let report = app.flush_outbox().await.unwrap();
        assert_eq!(report.queued, vec![msg_id.clone()], "{report:?}");
        s.w.clock.advance_ms(60_000);
    }
    assert!(app.delivery(&msg_id).await.unwrap().is_some());
}

#[tokio::test]
async fn test_send_with_an_invite_code_is_admitted() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let code = pubky_switch_core::enc::b64(&[4; 16]);
    s.peer.lock().admitted = Some(Default::default());
    s.peer.lock().codes.insert(code.clone(), 1);
    let mut message = s.note("hello");
    message.invite_code = Some(code);
    let (msg_id, delivery) = app.send(message).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    assert_eq!(s.peer.received(), vec![msg_id]);
    // An invite code that isn't one is refused before anything is kept.
    let mut bad = s.note("x");
    bad.invite_code = Some("short".into());
    assert!(app.send(bad).await.is_err());
}

#[tokio::test]
async fn test_send_resend_seals_the_same_plaintext_again() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let (msg_id, _) = app.send(s.note("hello")).await.unwrap();
    s.peer.rotate(0).unwrap();
    let delivery = app.resend(&msg_id).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    assert_eq!(s.peer.received(), vec![msg_id.clone(), msg_id.clone()]);
    {
        let inner = s.peer.lock();
        let bob = inner.identity.public();
        let open = |envelope: &[u8]| {
            inner.apps[0]
                .receive_keys
                .iter()
                .find_map(|(key, _)| MessagePlaintext::open(envelope, &bob, &key.secret()).ok())
                .unwrap()
        };
        let first = open(&inner.inbox[0].envelope);
        let again = open(&inner.inbox[1].envelope);
        assert_eq!(first, again);
        assert_ne!(inner.inbox[0].envelope, inner.inbox[1].envelope);
    }
    let sent = app.sent_to(&s.w.bob.public(), 0, u64::MAX).await.unwrap();
    assert_eq!(sent.len(), 1);
}

#[tokio::test]
async fn test_send_sent_message_shows_every_acceptance_time() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let (msg_id, delivery) = app.send(s.note("hello")).await.unwrap();
    let Delivery::Accepted {
        accepted_at_ms: first,
    } = delivery
    else {
        panic!("{delivery:?}");
    };
    s.w.clock.advance_ms(1000);
    s.peer.rotate(0).unwrap();
    app.resend(&msg_id).await.unwrap();
    s.w.clock.advance_ms(1000);
    app.resend(&msg_id).await.unwrap();
    let times = |sent: &[crate::app::SentMessage]| {
        sent.iter()
            .map(crate::app::SentMessage::accepted_times_ms)
            .collect::<Vec<_>>()
    };
    let all = app.sent_to(&s.w.bob.public(), 0, u64::MAX).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].accepted_at_ms, Some(first));
    assert_eq!(all[0].resent_at_ms.len(), 2);
    let every = all[0].accepted_times_ms();
    assert_eq!(every.len(), 3);
    assert_eq!(every[0], first);
    assert!(every.windows(2).all(|w| w[0] < w[1]), "{every:?}");
    // A window around a re-send's acceptance alone selects it too, with all its times
    // (Switch spec 11).
    let resent = every[2];
    let selected = app
        .sent_to(&s.w.bob.public(), resent, resent)
        .await
        .unwrap();
    assert_eq!(times(&selected), vec![every.clone()]);
    // A time no acceptance has selects nothing.
    let none = app
        .sent_to(&s.w.bob.public(), first + 1, every[1] - 1)
        .await
        .unwrap();
    assert!(none.is_empty());
}

#[tokio::test]
async fn test_send_resend_of_an_unknown_message_is_refused() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let error = app.resend("no-such-message").await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_send_sent_messages_go_after_30_days() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let (msg_id, _) = app.send(s.note("hello")).await.unwrap();
    s.w.clock.advance_ms(29 * DAY_MS);
    app.flush_outbox().await.unwrap();
    assert!(app.delivery(&msg_id).await.unwrap().is_some());
    s.w.clock.advance_ms(2 * DAY_MS);
    app.flush_outbox().await.unwrap();
    assert!(app.delivery(&msg_id).await.unwrap().is_none());
    assert!(app.resend(&msg_id).await.is_err());
}

#[tokio::test]
async fn test_send_record_job_writes_the_message_into_its_record() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let target = s.target("bob");
    let mut message = s.note("hello");
    message.record = Some(RecordJob {
        target: target.clone(),
        tag: b"sent".to_vec(),
    });
    let (msg_id, delivery) = app.send(message).await.unwrap();
    assert!(accepted(&delivery));
    let key = app.record_key(&target).unwrap();
    let record = app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()), vec![msg_id]);
    assert!(record.authenticated);
}

/// One run of the sending scenario: join, then one message to bob. Returns at the first
/// error, as a process that died.
async fn send_scenario(
    s: &Setup,
    store: Arc<dyn StateStore>,
    approval: &mut Option<JoinRequest>,
    queued: &mut Option<String>,
) -> Result<(), AppError> {
    let keys = app_keys("wallet");
    let env = s.env_on(Arc::clone(&store));
    let mut app = match App::load(
        env.clone(),
        s.protocol.clone(),
        World::config(),
        keys.app_id_bytes(),
    )
    .await
    {
        Ok(app) => app,
        Err(AppError::Refused(Refusal::NotJoined)) => {
            let request = approval
                .get_or_insert_with(|| s.approve(&keys, &ALL_PERMISSIONS))
                .clone();
            App::join(env, s.protocol.clone(), World::config(), request).await?
        }
        Err(error) => return Err(error),
    };
    app.receive(None).await?;
    // A message queued before a crash whose answer the host didn't get is in the outbox.
    let report = app.flush_outbox().await?;
    if queued.is_none() {
        *queued = report.done.first().or(report.queued.first()).cloned();
    }
    if queued.is_none() {
        let msg_id = app.queue(s.note("hello")).await?;
        *queued = Some(msg_id);
        app.flush_outbox().await?;
    }
    Ok(())
}

#[tokio::test]
async fn test_send_crash_at_each_commit_point_never_sends_twice() {
    let commits = {
        let s = Setup::new();
        let counting = Arc::new(FaultStore::new(
            Arc::new(MemoryStore::new()) as Arc<dyn StateStore>,
            StoreFault::None,
        ));
        send_scenario(
            &s,
            Arc::clone(&counting) as Arc<dyn StateStore>,
            &mut None,
            &mut None,
        )
        .await
        .unwrap();
        counting.commits()
    };
    assert!(commits > 6, "the scenario commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let s = Setup::new();
            let inner = Arc::new(MemoryStore::new());
            let fault = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let mut approval = None;
            let mut queued = None;
            let first = send_scenario(
                &s,
                Arc::clone(&fault) as Arc<dyn StateStore>,
                &mut approval,
                &mut queued,
            )
            .await;
            assert!(fault.stopped(), "commit {n} of {commits} is reached");
            assert!(first.is_err());
            send_scenario(
                &s,
                Arc::clone(&inner) as Arc<dyn StateStore>,
                &mut approval,
                &mut queued,
            )
            .await
            .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            let received = s.peer.received();
            assert_eq!(received.len(), 1, "commit {n} ({stop_after}): {received:?}");
            assert_eq!(Some(&received[0]), queued.as_ref());
            assert_eq!(
                s.conversation_entries(&s.w.bob.public()),
                1,
                "commit {n} ({stop_after})"
            );
            let app = App::load(
                s.env_on(Arc::clone(&inner) as Arc<dyn StateStore>),
                s.protocol.clone(),
                World::config(),
                app_keys("wallet").app_id_bytes(),
            )
            .await
            .unwrap();
            assert!(accepted(
                &app.delivery(&received[0]).await.unwrap().unwrap()
            ));
        }
    }
}

#[tokio::test]
async fn test_send_own_identity_goes_to_recent_peers_after_a_removal() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.send(s.note("hello")).await.unwrap();
    let held = s.peer.lock().peers[&s.w.alice.public()].version();
    assert_eq!(held, app.own_identity().version());
    let doc = s.w.next_doc(|body| {
        body.removed.push(RemovedApp {
            app_id: [9; 16],
            distrust_from: START,
        })
    });
    assert!(matches!(
        app.refresh_identity().await.unwrap(),
        crate::app::IdentityRefresh::Newer { .. }
    ));
    app.flush_outbox().await.unwrap();
    assert_eq!(
        s.peer.lock().peers[&s.w.alice.public()].version(),
        doc.version()
    );
    // A version that removes nothing more goes to nobody.
    s.peer.lock().requests.clear();
    s.w.next_doc(|_| {});
    app.refresh_identity().await.unwrap();
    app.flush_outbox().await.unwrap();
    assert!(s.peer.routes().is_empty(), "{:?}", s.peer.routes());
}

#[tokio::test]
async fn test_send_no_delivery_to_a_peer_written_to_long_ago() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.send(s.note("hello")).await.unwrap();
    let before = s.peer.lock().peers[&s.w.alice.public()].version();
    s.w.clock.advance_ms(31 * DAY_MS);
    s.w.next_doc(|body| {
        body.removed.push(RemovedApp {
            app_id: [9; 16],
            distrust_from: START,
        })
    });
    app.refresh_identity().await.unwrap();
    app.flush_outbox().await.unwrap();
    assert_eq!(s.peer.lock().peers[&s.w.alice.public()].version(), before);
}

// -------------------------------------------------------------------------------------
// Admission

#[tokio::test]
async fn test_admission_invite_code_registers_shows_and_withdraws() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let expires = START + HOUR;
    let code = app
        .register_invite_code(expires, 1, json!({ "order": "o-1" }))
        .await
        .unwrap();
    assert_eq!(invite_code_hash(&code.code).unwrap(), code.code_hash);
    assert_eq!(
        code.uri(&s.w.alice.public()),
        format!(
            "pubky://{}?switch=invite&code={}",
            pubky_switch_core::enc::pubky_id(&s.w.alice.public()),
            code.code
        )
    );
    assert!(s.w.switch.applied().iter().any(
        |op| matches!(&op.body().kind, OpKind::InviteCodePut(put) if put.code_hash == code.code_hash)
    ));
    assert_eq!(app.invite_codes().await.unwrap(), vec![code.clone()]);
    let list = app.allow_list().await.unwrap();
    assert_eq!(list.invite_codes.len(), 1);
    app.withdraw_invite_code(&code.code_hash).await.unwrap();
    assert!(app.invite_codes().await.unwrap().is_empty());
    // Withdrawn already: the switch has none.
    let error = app.withdraw_invite_code(&code.code_hash).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotFound));
}

#[tokio::test]
async fn test_admission_invite_code_refusals() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let error = app
        .register_invite_code(START + HOUR, 0, json!(null))
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::Refused(Refusal::Usage(_))));
    let mut plain = s.join_with("phone", &[]).await;
    let error = plain
        .register_invite_code(START + HOUR, 1, json!(null))
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_admission_connect_request_allowed_becomes_an_invite() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let carol = [21; 32];
    let dave = [22; 32];
    s.w.switch.push_connect(carol);
    s.w.switch.push_connect(dave);
    let list = app.connect_requests().await.unwrap();
    assert_eq!(list.requests.len(), 2);
    app.allow_connect(&carol).await.unwrap();
    assert_eq!(s.w.switch.connects(), vec![dave]);
    assert_eq!(s.conversation_entries(&carol), 1);
    assert!(app.admits(&carol).await.unwrap());
    app.decline_connect(&dave).await.unwrap();
    assert!(s.w.switch.connects().is_empty());
    assert!(!app.admits(&dave).await.unwrap());
    let error = app.decline_connect(&dave).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotFound));
}

#[tokio::test]
async fn test_admission_ask_to_connect_delivers_the_identity_first() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    assert!(app.ask_to_connect(&s.w.bob.public()).await.unwrap());
    assert_eq!(s.peer.lock().connects, vec![s.w.alice.public()]);
    assert_eq!(
        s.peer.routes(),
        vec!["POST connect", "PUT peers", "POST connect"]
    );
    // Where connect requests are off: refused.
    s.peer
        .fail_next("connect", ErrorCode::NotAdmitted, json!({}));
    let error = app.ask_to_connect(&s.w.bob.public()).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotAdmitted));
}

#[tokio::test]
async fn test_admission_contacts_and_deny_list() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let carol = [21; 32];
    let dave = [22; 32];
    app.add_contact(&carol).await.unwrap();
    app.deny(&dave).await.unwrap();
    let list = app.allow_list().await.unwrap();
    assert_eq!(list.contacts, vec![carol]);
    assert_eq!(list.deny, vec![dave]);
    assert!(app.admits(&carol).await.unwrap());
    app.remove_contact(&carol).await.unwrap();
    app.undeny(&dave).await.unwrap();
    let list = app.allow_list().await.unwrap();
    assert!(list.contacts.is_empty() && list.deny.is_empty());
    assert!(!app.admits(&carol).await.unwrap());
    // Without lists.manage: refused before anything is sent.
    let mut plain = s.join_with("phone", &[Permission::ConversationAdd]).await;
    let error = plain.add_contact(&carol).await.unwrap_err();
    assert!(matches!(error, AppError::Refused(Refusal::Usage(_))));
    let error = plain.allow_list().await.unwrap_err();
    assert!(matches!(error, AppError::Refused(Refusal::Usage(_))));
}

#[tokio::test]
async fn test_admission_list_changes_in_the_feed_are_followed() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let carol = [21; 32];
    wallet.invite(&carol).await.unwrap();
    phone.receive(None).await.unwrap();
    assert!(phone.admits(&carol).await.unwrap());
    wallet.remove_conversation(&carol).await.unwrap();
    phone.receive(None).await.unwrap();
    assert!(!phone.admits(&carol).await.unwrap());
}

// -------------------------------------------------------------------------------------
// Shared records

#[tokio::test]
async fn test_record_conflict_batch_takes_the_competing_write_and_can_build_on_it() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("shared");
    let entry = wallet
        .record_op(&target, Some(&value(&["first"])), vec![])
        .await
        .unwrap();
    let won = phone
        .put_record(&target, &value(&["second"]), vec![])
        .await
        .unwrap();

    let error = wallet
        .submit_batch(OpBatch::new().entry(entry))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    let held = wallet.shared_record(&won.key).await.unwrap().unwrap();
    assert!(held.authenticated);
    assert_eq!((held.version, held.writer), (won.version, won.writer));
    assert_eq!(held.content, won.content);
    assert_eq!(wallet.read_record(&target).await.unwrap(), Some(held));
    let built = wallet
        .put_record(&target, &value(&["second", "third"]), vec![])
        .await
        .unwrap();
    assert!(built.version > won.version);
}

#[tokio::test]
async fn test_record_conflict_condition_judges_the_guarded_key() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let guard = s.target("guard");
    let output = s.target("output");
    let output_key = wallet.record_key(&output).unwrap();
    let first = phone
        .put_record(&guard, &value(&["first"]), vec![])
        .await
        .unwrap();
    let view = wallet.client.record(&first.key).await.unwrap().view;
    let condition = Condition::RecordCurrent {
        key: first.key,
        revision: view.revision,
        deleted: false,
    };
    let entry = wallet
        .record_op(&output, Some(&value(&["output"])), vec![condition])
        .await
        .unwrap();
    let next = phone
        .put_record(&guard, &value(&["first", "second"]), vec![])
        .await
        .unwrap();
    let error = wallet
        .submit_batch(OpBatch::new().entry(entry))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    assert_eq!(wallet.shared_record(&output_key).await.unwrap(), None);
    assert_eq!(wallet.shared_record(&first.key).await.unwrap(), Some(next));
}

#[tokio::test]
async fn test_record_conflict_position_and_read_scope_preserve_held_content() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let mut wallet = s.join("wallet").await;
    let mut limited = join_scoped(&s, "tablet", &["sample-b"]).await;
    let target = s.target("guard");
    let first = phone
        .put_record(&target, &value(&["first"]), vec![])
        .await
        .unwrap();
    let held = wallet.read_record(&target).await.unwrap().unwrap();
    let newer = phone
        .put_record(&target, &value(&["first", "second"]), vec![])
        .await
        .unwrap();
    let batch = OpBatch::new().op_if(
        OpKind::DenyPut { pubky: [9; 32] },
        vec![Condition::RecordVersion {
            key: first.key,
            version: first.version,
        }],
    );
    let current = |error: AppError| match error {
        AppError::Switch(crate::error::ClientError::Switch {
            code: ErrorCode::Conflict,
            current,
            ..
        }) => current,
        other => panic!("expected a write conflict, got {other:?}"),
    };
    let shown = current(wallet.submit_batch(batch.clone()).await.unwrap_err());
    assert_eq!(shown["record_version"]["version"], newer.version.version);
    assert_eq!(wallet.shared_record(&first.key).await.unwrap(), Some(held));
    assert_eq!(wallet.read_record(&target).await.unwrap(), Some(newer));
    assert_eq!(
        current(limited.submit_batch(batch).await.unwrap_err()),
        json!({})
    );
    assert_eq!(limited.shared_record(&first.key).await.unwrap(), None);
}

#[tokio::test]
async fn test_record_conflict_stored_retry_takes_the_competing_write() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let mut wallet = s.join("wallet").await;
    let target = s.target("shared");
    let entry = wallet
        .record_op(&target, Some(&value(&["first"])), vec![])
        .await
        .unwrap();
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    let error = wallet
        .submit_batch(OpBatch::new().entry(entry))
        .await
        .unwrap_err();
    let id = error.kept_batch().unwrap();
    let winner = phone
        .put_record(&target, &value(&["second"]), vec![])
        .await
        .unwrap();

    let mut wallet = App::load(
        s.env(),
        s.protocol.clone(),
        World::config(),
        wallet.app_id(),
    )
    .await
    .unwrap();
    wallet.resume_batches().await.unwrap();
    assert_eq!(
        wallet.shared_record(&winner.key).await.unwrap(),
        Some(winner)
    );
    assert!(
        matches!(wallet.kept_batch(id).await.unwrap(), Some(crate::app::KeptBatchStatus::Dropped {
        reason: crate::app::KeptBatchDrop::Refused {code}, ..
    }) if code == "conflict")
    );
}

#[tokio::test]
async fn test_record_conflict_overtaken_by_a_later_read_keeps_the_later_write() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("shared");
    let entry = wallet
        .record_op(&target, Some(&value(&["first"])), vec![])
        .await
        .unwrap();
    let batch = wallet.sign_ops(vec![entry], None).unwrap();
    phone
        .put_record(&target, &value(&["second"]), vec![])
        .await
        .unwrap();
    let service_key = wallet.client.pinned_key().unwrap();
    let failure = wallet
        .client
        .submit_proved_by(&batch, &service_key)
        .await
        .unwrap_err();
    let crate::error::ClientError::Switch {
        code: ErrorCode::Conflict,
        current,
        ..
    } = failure.error
    else {
        panic!("expected a competing write")
    };
    let later = phone
        .put_record(&target, &value(&["second", "third"]), vec![])
        .await
        .unwrap();
    assert_eq!(
        wallet.read_record(&target).await.unwrap(),
        Some(later.clone())
    );
    wallet
        .note_record_conflict(&batch, &current, failure.head.as_deref())
        .await
        .unwrap();
    assert_eq!(wallet.shared_record(&later.key).await.unwrap(), Some(later));
}

#[tokio::test]
async fn test_record_conflict_absence_after_a_forgotten_delete_allows_a_new_create() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("shared");
    let key = created_and_deleted(&mut wallet, &target).await;
    let entry = wallet
        .record_op(&target, Some(&value(&["new"])), vec![])
        .await
        .unwrap();
    read_on(&mut wallet).await;
    read_on(&mut phone).await;
    assert!(!held_at_switch(&s, &key));
    let error = wallet
        .submit_batch(OpBatch::new().entry(entry))
        .await
        .unwrap_err();
    let AppError::Switch(crate::error::ClientError::Switch {
        code: ErrorCode::Conflict,
        current,
        ..
    }) = error
    else {
        panic!("expected a forgotten delete")
    };
    assert_eq!(
        current,
        json!({"record": {"key": pubky_switch_core::enc::b64(&key), "generation": 0, "version": 0}, "record_view": null})
    );
    assert_eq!(
        wallet.record_condition(&key).await.unwrap(),
        Condition::RecordVersion {
            key,
            version: RecordVersion::NONE
        }
    );
    let created = wallet
        .put_record(&target, &value(&["new"]), vec![])
        .await
        .unwrap();
    assert!(created.authenticated);
    assert_eq!(wallet.read_record(&target).await.unwrap(), Some(created));
}

#[tokio::test]
async fn test_records_put_conflict_reads_again_and_recomputes() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    // The phone holds nothing yet: its create conflicts, then it builds on what it reads.
    let mut calls = 0;
    let written = phone
        .update_record(&target, vec![], |current| {
            calls += 1;
            let mut all = ids(current);
            all.push("b".into());
            let all: Vec<&str> = all.iter().map(String::as_str).collect();
            Some(value(&all))
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(ids(written.content.value()), vec!["a", "b"]);
    let read = wallet.read_record(&target).await.unwrap().unwrap();
    assert_eq!(ids(read.content.value()), vec!["a", "b"]);
    assert!(read.authenticated);
    // The wallet's stale write now conflicts, and it reads the newer one again.
    let key = wallet.record_key(&target).unwrap();
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    let error = wallet
        .put_record(
            &target,
            &value(&["x"]),
            vec![Condition::RecordVersion {
                key,
                version: pubky_switch_core::ops::RecordVersion::new(1, 1),
            }],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    assert_eq!(wallet.shared_record(&key).await.unwrap().unwrap(), held);
}

#[tokio::test]
async fn test_records_delete_then_create_again() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let target = s.target("n1");
    app.put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let deleted = app.delete_record(&target, vec![]).await.unwrap();
    assert_eq!(deleted.content, RecordContent::Deleted);
    let again = app
        .put_record(&target, &value(&["c"]), vec![])
        .await
        .unwrap();
    assert_eq!(ids(again.content.value()), vec!["c"]);
    assert!(again.version > deleted.version);
}

#[tokio::test]
async fn test_records_value_that_isnt_json_is_refused_before_it_is_sent() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let target = s.target("n1");
    let written = s.w.switch.applied().len();
    for bad in [
        &b"not json"[..],
        b"",
        b"{\"a\":1} trailing",
        b"\xEF\xBB\xBF{}",
    ] {
        let error = app.put_record(&target, bad, vec![]).await.unwrap_err();
        assert!(
            matches!(error, AppError::Refused(Refusal::Usage(_))),
            "{error:?}"
        );
        assert!(app.record_op(&target, Some(bad), vec![]).await.is_err());
    }
    // Refused before the protocol marks it: the mark queued for the next write is still
    // there.
    s.protocol.pads.lock().unwrap().push_back(0);
    assert!(
        app.record_op(&target, Some(b"not json"), vec![])
            .await
            .is_err()
    );
    assert_eq!(s.protocol.pads.lock().unwrap().len(), 1);
    s.protocol.pads.lock().unwrap().clear();
    // Nothing was signed, kept or sent.
    assert_eq!(s.w.switch.applied().len(), written);
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert!(
        app.shared_record(&app.record_key(&target).unwrap())
            .await
            .unwrap()
            .is_none()
    );
    // A JSON value goes as before.
    app.put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
}

#[tokio::test]
async fn test_records_stale_epoch_takes_the_new_keys_and_writes_again() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let cert = app.cert().clone();
    let has_keys = |scope: &str| SampleProtocol::default().has_keys(scope);
    s.w.next_doc(|body| body.data_epoch = 2);
    for part in seal_bundle_parts(&s.w.alice, &cert, 1, 2, &has_keys).unwrap() {
        s.w.switch
            .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: app.app_id(),
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
    }
    let target = s.target("n1");
    let written = app
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    assert_eq!(app.data_epoch(), 2);
    let key = app.record_key(&target).unwrap();
    let held = s.w.switch.record(&key).unwrap();
    let OpKind::RecordPut(put) = SignedOp::peek(&held.op).unwrap().body().kind.clone() else {
        panic!("a record.put")
    };
    assert_eq!(put.value_sealed.data_epoch, 2);
    assert_eq!(ids(written.content.value()), vec!["a"]);
}

#[tokio::test]
async fn test_records_without_the_current_key_writes_nothing() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.w.next_doc(|body| body.data_epoch = 2);
    let target = s.target("n1");
    let error = app
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::NotNow(_))),
        "{error:?}"
    );
    assert!(
        s.w.switch
            .record(&app.record_key(&target).unwrap())
            .is_none()
    );
}

fn uncheckable(events: &[AppEvent], key: &[u8; 32]) -> bool {
    events.iter().any(|e| {
        matches!(
            e,
            AppEvent::RecordUncheckable { key: k, mark_bytes, .. }
                if k == key && *mark_bytes > MAX_SEEN_MARK_BYTES as u64
        )
    })
}

#[tokio::test]
async fn test_records_unmarkable_write_from_another_app_keeps_the_mark_held() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    // The wallet's next write is one the phone's mark of can't be kept.
    wallet
        .put_record(&target, &value(&["a", "b", "c"]), vec![])
        .await
        .unwrap();
    *s.protocol.pad.lock().unwrap() = MAX_SEEN_MARK_BYTES;
    let report = phone.receive(None).await.unwrap();
    *s.protocol.pad.lock().unwrap() = 0;
    // The write is taken, the protocol is told, durably, and the mark held stays.
    let shared = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(shared.content.value()), ["a", "b", "c"]);
    assert!(uncheckable(&report.events, &key), "{:?}", report.events);
    assert!(uncheckable(&phone.kept_duties().await.unwrap(), &key));
    let held = phone.record_seen(&key).await.unwrap().unwrap();
    assert_eq!(ids(Some(&held)), ["a", "b"]);
    // So a later write that drops what was seen before is still flagged.
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let report = phone.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::WriteFlagged { .. })),
        "{:?}",
        report.events
    );
}

#[tokio::test]
async fn test_records_own_write_whose_mark_wont_fit_is_refused() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = phone.record_key(&target).unwrap();
    *s.protocol.pad.lock().unwrap() = MAX_SEEN_MARK_BYTES;
    let error = phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error:?}"
    );
    assert!(s.w.switch.record(&key).is_none());
    // Within the bound, it is sent.
    *s.protocol.pad.lock().unwrap() = 0;
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    assert!(s.w.switch.record(&key).is_some());
}

#[tokio::test]
async fn test_records_own_write_unmarkable_once_taken_drops_the_mark_held() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    // The phone drops b itself. Its mark fits when the write is built, not once taken.
    s.protocol
        .pads
        .lock()
        .unwrap()
        .extend([0, MAX_SEEN_MARK_BYTES]);
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    assert!(s.protocol.pads.lock().unwrap().is_empty());
    assert!(uncheckable(
        &phone.unacknowledged_events().await.unwrap(),
        &key
    ));
    assert_eq!(phone.record_seen(&key).await.unwrap(), None);
    // The wallet builds on the phone's write, honestly: nothing it drops was seen after it.
    wallet.receive(None).await.unwrap();
    wallet
        .put_record(&target, &value(&["a", "c"]), vec![])
        .await
        .unwrap();
    let report = phone.receive(None).await.unwrap();
    assert!(
        !report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::WriteFlagged { .. })),
        "{:?}",
        report.events
    );
    let shared = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(shared.content.value()), ["a", "c"]);
}

/// The later-write check is told what the write builds on, and whether the app holds that
/// version: it does for the first write, a create over nothing held, and for a write read
/// in the feed after the one it holds, and doesn't for the current view of a record written
/// twice since.
#[tokio::test]
async fn test_records_regression_check_sees_the_write_base() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    let version = |record: Option<crate::app::SharedRecord>| record.unwrap().version;
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let first = version(phone.shared_record(&key).await.unwrap());
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let second = version(phone.shared_record(&key).await.unwrap());
    assert_eq!(
        *s.protocol.bases.lock().unwrap(),
        vec![
            WriteBase {
                repair: None,
                expected_version: RecordVersion::NONE,
                held: true,
                conditions: Vec::new(),
                written_at_ms: Some(s.w.clock.now_ms()),
            },
            WriteBase {
                repair: None,
                expected_version: first,
                held: true,
                conditions: Vec::new(),
                written_at_ms: Some(s.w.clock.now_ms()),
            }
        ]
    );
    // Two writes later, the phone reads only the record's current view: it builds on the
    // write after the one the phone holds.
    wallet
        .put_record(&target, &value(&["a", "b", "c"]), vec![])
        .await
        .unwrap();
    let third = version(wallet.shared_record(&key).await.unwrap());
    wallet
        .put_record(&target, &value(&["a", "b", "c", "d"]), vec![])
        .await
        .unwrap();
    let fourth = version(phone.read_record(&target).await.unwrap());
    assert!(second < third && third < fourth);
    assert_eq!(
        s.protocol.bases.lock().unwrap().last(),
        Some(&WriteBase {
            repair: None,
            expected_version: third,
            held: false,
            conditions: Vec::new(),
            written_at_ms: Some(s.w.clock.now_ms()),
        })
    );
}

/// A write over a record the app holds deleted names the delete, and builds on what it
/// holds.
#[tokio::test]
async fn test_records_regression_base_of_a_write_over_a_held_delete_is_held() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let deleted = wallet.delete_record(&target, vec![]).await.unwrap().version;
    phone.receive(None).await.unwrap();
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let last = s.protocol.bases.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        last,
        WriteBase {
            repair: None,
            expected_version: deleted,
            held: true,
            conditions: Vec::new(),
            written_at_ms: Some(s.w.clock.now_ms()),
        }
    );
}

/// A write built on one the app refused and only follows doesn't build on what it holds.
#[tokio::test]
async fn test_records_regression_base_of_a_write_on_a_flagged_one_isnt_held() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    // The wallet drops b, which the phone flags and follows; then writes on it.
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    assert!(phone.shared_record(&key).await.unwrap().unwrap().flagged);
    let flagged = version_of(&wallet, &key).await;
    wallet
        .put_record(&target, &value(&["a", "b", "c"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let last = s.protocol.bases.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        last,
        WriteBase {
            repair: None,
            expected_version: flagged,
            held: false,
            conditions: Vec::new(),
            written_at_ms: Some(s.w.clock.now_ms()),
        }
    );
}

/// The later-write check is told the conditions the write's operation signed, in order, so
/// a protocol's reader rule can require one, such as a `claim_step` on the claim of what the
/// write drops (Switch spec 8.2).
#[tokio::test]
async fn test_records_regression_check_sees_the_write_conditions() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let now = s.w.clock.now_ms();
    let conditions = vec![
        Condition::ClaimStep {
            claim_key: [9; 32],
            step: 0,
        },
        Condition::ServerTimeIn {
            start: None,
            end: Some(now + HOUR),
        },
    ];
    wallet
        .put_record(&target, &value(&["a", "b"]), conditions.clone())
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let last = s.protocol.bases.lock().unwrap().last().unwrap().clone();
    assert_eq!(last.conditions, conditions);
    assert!(last.held);
}

async fn version_of(app: &App, key: &[u8; 32]) -> RecordVersion {
    app.shared_record(key).await.unwrap().unwrap().version
}

#[tokio::test]
async fn test_records_flagged_rule_is_cut_to_its_bound() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    // A rule of two-byte characters, well over the bound.
    *s.protocol.pad.lock().unwrap() = 300;
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let report = phone.receive(None).await.unwrap();
    let reason = report
        .events
        .iter()
        .find_map(|e| match e {
            AppEvent::WriteFlagged { reason, .. } => Some(reason.clone()),
            _ => None,
        })
        .unwrap();
    assert!(
        reason.len() <= MAX_REGRESSION_REASON_BYTES,
        "{}",
        reason.len()
    );
    assert!(reason.starts_with("sample: an item seen was dropped"));
}

#[tokio::test]
async fn test_records_flagged_write_is_refused_on_use_and_followed() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    assert_eq!(
        ids(phone
            .shared_record(&key)
            .await
            .unwrap()
            .unwrap()
            .content
            .value()),
        vec!["a", "b"]
    );
    // The wallet drops an item the phone has seen.
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let report = phone.receive(None).await.unwrap();
    assert!(
        report.events.iter().any(
            |e| matches!(e, AppEvent::WriteFlagged { writer, .. } if *writer == wallet.app_id())
        ),
        "{:?}",
        report.events
    );
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert!(held.flagged);
    assert_eq!(ids(held.content.value()), vec!["a", "b"]);
    let flagged = phone.flagged_writes().await.unwrap();
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0].writer, wallet.app_id());
    // The phone's next write builds on the flagged one and puts back what it trusts.
    let written = phone
        .update_record(&target, vec![], |current| {
            let mut all = ids(current);
            all.push("c".into());
            let all: Vec<&str> = all.iter().map(String::as_str).collect();
            Some(value(&all))
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ids(written.content.value()), vec!["a", "b", "c"]);
    assert!(!written.flagged);
    // A write that drops nothing is taken.
    wallet.receive(None).await.unwrap();
    wallet
        .put_record(&target, &value(&["a", "b", "c", "d"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert!(!held.flagged);
    assert_eq!(ids(held.content.value()), vec!["a", "b", "c", "d"]);
}

/// A delayed read between the content taken and the later refused write describes that
/// earlier snapshot. The repair builds directly on the refused write, also after restart.
#[tokio::test]
async fn test_records_followed_write_survives_an_overtaken_read_and_reload() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("shared");
    let held = wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    phone.read_record(&target).await.unwrap();
    let middle = wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    let earlier = phone.client.record(&held.key).await.unwrap();
    let refused = wallet
        .put_record(&target, &value(&["c"]), vec![])
        .await
        .unwrap();
    let displayed = phone.read_record(&target).await.unwrap().unwrap();
    assert!(displayed.flagged);
    assert_eq!(displayed.content, held.content);

    let at = crate::app::records::CurrentAt::Answer(RecordVersion::new(
        earlier.head.generation,
        earlier.head.seq,
    ));
    let mut tx = phone.tx().unwrap();
    let read = phone
        .take_view(
            &earlier.view,
            at,
            Some((&held.key, &target.collection)),
            true,
            &mut tx,
        )
        .await
        .unwrap();
    assert!(
        matches!(read, crate::app::records::WriteRead::Overtaken(w, _) if w.version == middle.version)
    );
    phone.commit(tx).await.unwrap();
    assert_eq!(
        phone.shared_record(&held.key).await.unwrap(),
        Some(displayed.clone())
    );
    let id = phone.app_id();
    drop(phone);
    let mut phone = App::load(s.env(), s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    assert_eq!(
        phone.shared_record(&held.key).await.unwrap(),
        Some(displayed)
    );
    let condition = phone.record_condition(&held.key).await.unwrap();
    assert_eq!(
        condition,
        Condition::RecordVersion {
            key: held.key,
            version: refused.version
        }
    );
    let repaired = phone
        .put_record(&target, &value(&["a", "b", "c"]), vec![condition])
        .await
        .unwrap();
    let applied = s.w.switch.record(&held.key).unwrap();
    let signed = SignedOp::peek(&applied.op).unwrap();
    assert!(
        matches!(&signed.body().kind, OpKind::RecordPut(p) if p.expected_version == refused.version)
    );
    assert_eq!(applied.state.version, repaired.version);
    assert!(!repaired.flagged && !repaired.not_taken);
    assert_eq!(ids(repaired.content.value()), ["a", "b", "c"]);
}

/// Two devices prepared distinct creates before a loss. Each is applied by an upload
/// to a successor service. Their lower-bound versions match, their applications differ.
#[tokio::test]
async fn test_records_followed_upload_keeps_its_application_across_an_earlier_view() {
    use crate::client::answers::{RecoveryUpload, UploadedOp};

    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("uploaded");
    let key = phone.record_key(&target).unwrap();
    let mut uploads = Vec::new();
    for (writer, text) in [(&mut wallet, "one"), (&mut phone, "two")] {
        let op = writer
            .record_op(&target, Some(&value(&[text])), vec![])
            .await
            .unwrap();
        let batch = writer.sign_ops(vec![op], None).unwrap();
        uploads.push(RecoveryUpload {
            records: vec![UploadedOp {
                op: batch.ops()[0].signed().clone(),
                cert: writer.cert().signed().clone(),
                proof: None,
            }],
            ..Default::default()
        });
    }
    let mut views = Vec::new();
    for (lost, upload) in [1, 2].into_iter().zip(uploads) {
        let prev = s.w.switch.identity_doc().unwrap().hash();
        let doc =
            s.w.signer
                .sign_next(|body| {
                    body.generation = lost + 1;
                    body.recovery_from = Some(lost);
                })
                .unwrap();
        s.w.switch.recover_in_place(&doc, prev).unwrap();
        wallet.receive(None).await.unwrap();
        let answer = wallet.client.recovery_upload(&upload, false).await.unwrap();
        assert!(answer.result.unwrap().records.contains(&key));
        phone.receive(None).await.unwrap();
        phone.read_record(&target).await.unwrap();
        views.push(phone.client.record(&key).await.unwrap());
    }
    let [first, later] = &views[..] else {
        unreachable!()
    };
    assert_eq!(
        (first.view.generation, first.view.version),
        (later.view.generation, later.view.version)
    );
    assert_ne!(first.view.revision, later.view.revision);
    let condition = Condition::RecordCurrent {
        key,
        revision: later.view.revision,
        deleted: false,
    };
    assert_eq!(phone.record_condition(&key).await.unwrap(), condition);
    let displayed = phone.shared_record(&key).await.unwrap().unwrap();
    assert!(displayed.different_write_at_held_version);
    assert_eq!(ids(displayed.content.value()), ["one"]);
    let mut tx = phone.tx().unwrap();
    let at = crate::app::records::CurrentAt::Answer(RecordVersion::new(
        first.head.generation,
        first.head.seq,
    ));
    let read = phone
        .take_view(
            &first.view,
            at,
            Some((&key, &target.collection)),
            true,
            &mut tx,
        )
        .await
        .unwrap();
    assert!(matches!(
        read,
        crate::app::records::WriteRead::Overtaken(..)
    ));
    phone.commit(tx).await.unwrap();
    let id = phone.app_id();
    drop(phone);
    let mut phone = App::load(s.env(), s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    assert_eq!(phone.shared_record(&key).await.unwrap(), Some(displayed));
    assert_eq!(phone.record_condition(&key).await.unwrap(), condition);
    if phone.reconcile_mode() {
        phone
            .end_reconcile(crate::app::UserConfirmed::new())
            .await
            .unwrap();
    }
    let taken = phone
        .put_record(&target, &value(&["one", "two"]), vec![])
        .await
        .unwrap();
    assert!(!taken.different_write_at_held_version);
    let signed = SignedOp::peek(&s.w.switch.record(&key).unwrap().op).unwrap();
    assert!(signed.body().conditions.contains(&condition));
}

/// A service-only read, a proved read of the same write, and a later proofless repeat
/// all concern one operation. Only the proved read authenticates its version.
#[tokio::test]
async fn test_records_followed_proof_upgrades_and_survives_a_proofless_read() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("shared");
    let held = wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    phone.read_record(&target).await.unwrap();
    *s.protocol.forbidden.lock().unwrap() = Some("b".into());
    let refused = wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    let proved = s.w.switch.record(&held.key).unwrap().proof.unwrap();
    for (with_proof, authenticated) in [(false, false), (true, true), (false, true)] {
        s.w.switch.lock().shared.hide_proofs = !with_proof;
        let displayed = phone.read_record(&target).await.unwrap().unwrap();
        assert_eq!(displayed.content, held.content);
        assert!(displayed.flagged);
        let stored =
            serde_json::to_value(phone.held_record(&held.key).await.unwrap().unwrap()).unwrap();
        let f = &stored["follow"];
        assert_eq!(
            f["version"]["expected"],
            json!([held.version.generation, held.version.version])
        );
        if authenticated {
            assert_eq!(f["version"]["authenticated"], true);
            assert_eq!(f["proof"], json!(proved));
        } else {
            assert_eq!(f["version"]["authenticated"], false);
            assert!(f["proof"].is_null());
        }
    }
    let id = phone.app_id();
    drop(phone);
    let mut phone = App::load(s.env(), s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    let stored =
        serde_json::to_value(phone.held_record(&held.key).await.unwrap().unwrap()).unwrap();
    assert_eq!(stored["follow"]["proof"], json!(proved));
    assert_eq!(stored["follow"]["version"]["authenticated"], true);
    assert_eq!(
        phone.record_condition(&held.key).await.unwrap(),
        Condition::RecordVersion {
            key: held.key,
            version: refused.version
        }
    );
    // Local reopening and the previous-install reader decode the same record fields.
    let mut mismatched = stored;
    mismatched["follow"]["applied"] = mismatched["applied"].clone();
    assert!(serde_json::from_value::<crate::app::records::HeldRecord>(mismatched).is_err());
    *s.protocol.forbidden.lock().unwrap() = None;
    let promoted = phone.read_record(&target).await.unwrap().unwrap();
    assert!(promoted.authenticated && !promoted.flagged && !promoted.not_taken);
    assert_eq!(ids(promoted.content.value()), ["a", "b"]);
    let stored =
        serde_json::to_value(phone.held_record(&held.key).await.unwrap().unwrap()).unwrap();
    assert!(stored["follow"].is_null());
    assert_eq!(stored["proof"], json!(proved));
}

#[tokio::test]
async fn test_current_collection_uses_completed_pages_and_subsequent_writes() {
    let s = Setup::new();
    let mut writer = s.join("wallet").await;
    for n in 0..6 {
        let name = format!("item-{n}");
        writer
            .put_record(&s.target(&name), &value(&[&name]), vec![])
            .await
            .unwrap();
    }
    let page_bytes = s.w.switch.lock().max_page_bytes;
    s.w.switch.lock().max_page_bytes = 1;
    let mut reader = s.join("phone").await;
    let partial = reader.receive(None).await.unwrap();
    assert!(
        reader
            .current_collection(&items(), &partial)
            .await
            .unwrap()
            .is_none()
    );
    s.w.switch.lock().max_page_bytes = page_bytes;
    let report = reader.receive(None).await.unwrap();
    let listed = s.w.switch.lock().shared.listings;
    let current = reader
        .current_collection(&items(), &report)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.identity, reader.identity());
    assert_eq!(current.live.len(), 6);
    assert!(current.uncertain_keys.is_empty());
    assert!(
        writer
            .current_collection(&items(), &report)
            .await
            .unwrap()
            .is_none()
    );

    let local = s.target("new-local");
    reader
        .put_record(&local, &value(&["placed"]), vec![])
        .await
        .unwrap();
    let current = reader
        .current_collection(&items(), &report)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.live.len(), 7);
    assert!(current.uncertain_keys.is_empty());
    reader.delete_record(&local, vec![]).await.unwrap();
    assert_eq!(
        reader
            .current_collection(&items(), &report)
            .await
            .unwrap()
            .unwrap()
            .live
            .len(),
        6
    );
    assert_eq!(s.w.switch.lock().shared.listings, listed);

    writer
        .delete_record(&s.target("item-3"), vec![])
        .await
        .unwrap();
    let later = reader.receive(None).await.unwrap();
    assert!(
        reader
            .current_collection(&items(), &report)
            .await
            .unwrap()
            .is_none()
    );
    let current = reader
        .current_collection(&items(), &later)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.live.len(), 5);
    assert!(current.uncertain_keys.is_empty());
}

#[tokio::test]
async fn test_current_collection_keeps_an_unaccepted_member_and_excludes_a_listed_absence() {
    let s = Setup::new();
    let mut writer = s.join("wallet").await;
    let accepted = s.target("accepted");
    let paused = s.target("paused");
    for (target, item) in [(&accepted, "a"), (&paused, "b")] {
        writer
            .put_record(target, &value(&[item]), vec![])
            .await
            .unwrap();
    }
    *s.protocol.forbidden.lock().unwrap() = Some("b".into());
    let mut reader = s.join("phone").await;
    let report = reader.receive(None).await.unwrap();
    let current = reader
        .current_collection(&items(), &report)
        .await
        .unwrap()
        .unwrap();
    let key = reader.record_key(&accepted).unwrap();
    assert_eq!(
        current.live.iter().map(|r| r.key).collect::<Vec<_>>(),
        [key]
    );
    assert_eq!(
        current.uncertain_keys,
        [reader.record_key(&paused).unwrap()]
    );

    writer.delete_record(&accepted, vec![]).await.unwrap();
    assert!(!reader.list_collections().await.unwrap());
    assert_eq!(
        ids(reader
            .shared_record(&key)
            .await
            .unwrap()
            .unwrap()
            .content
            .value()),
        ["a"]
    );
    assert!(
        reader
            .current_collection(&items(), &report)
            .await
            .unwrap()
            .is_none()
    );
    let latest = reader.receive(None).await.unwrap();
    let current = reader
        .current_collection(&items(), &latest)
        .await
        .unwrap()
        .unwrap();
    assert!(current.live.is_empty());
    assert_eq!(
        current.uncertain_keys,
        [reader.record_key(&paused).unwrap()]
    );
}

#[tokio::test]
async fn test_records_listed_at_join_and_other_collections_left_alone() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    let key = phone.record_key(&target).unwrap();
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    // A collection the protocol doesn't name: the phone takes nothing of it.
    let other = RecordTarget::new(
        Collection::new("sample.other", Policy::new("sample-a", &["sample-a"])),
        b"n2",
    );
    wallet
        .put_record(&other, &value(&["z"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let other_key = phone.record_key(&other).unwrap();
    assert!(phone.shared_record(&other_key).await.unwrap().is_none());
}

#[tokio::test]
async fn test_records_missed_item_lists_the_collections_again() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    let listings = |s: &Setup| {
        s.log()
            .iter()
            .filter(|l| l.contains("records?collection"))
            .count()
    };
    let before = listings(&s);
    app.receive(None).await.unwrap();
    assert_eq!(listings(&s), before);
    s.w.switch.push_missed(3, START, START + 1);
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(listings(&s), before + 1);
}

#[tokio::test]
async fn test_records_same_write_without_its_proof_stays_authenticated() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let key = phone.record_key(&target).unwrap();
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    // The switch serves the older write again, without its proof.
    {
        let mut inner = s.w.switch.lock();
        inner.shared.hide_proofs = true;
    }
    phone.read_record(&target).await.unwrap();
    assert_eq!(phone.shared_record(&key).await.unwrap().unwrap(), held);
}

#[tokio::test]
async fn test_records_older_write_shown_as_newer_without_a_proof_is_not_taken() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    let older = s.w.switch.record(&key).unwrap();
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    // The switch shows the first write again, at a version past the newest, without proof.
    {
        let mut inner = s.w.switch.lock();
        let mut replayed = older;
        replayed.state.version = pubky_switch_core::ops::RecordVersion::new(1, 999);
        inner.shared.records.insert(key, replayed);
        inner.shared.hide_proofs = true;
    }
    phone.read_record(&target).await.unwrap();
    assert_eq!(phone.shared_record(&key).await.unwrap().unwrap(), held);
}

/// The phone holds the wallet's second write; the switch's record of the first is returned,
/// for [`show_older`] to show it again.
async fn older_write_held() -> (
    Setup,
    App,
    App,
    RecordTarget,
    crate::app::SharedRecord,
    crate::testing::HeldRecord,
) {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    let older = s.w.switch.record(&key).unwrap();
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert!(held.authenticated);
    // The held write shown again reads as fresh, never as an older one.
    assert!(matches!(
        phone.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(_)
    ));
    (s, wallet, phone, target, held, older)
}

/// The switch shows `older` as the record's current write, with its proof when `proven`.
fn show_older(
    s: &Setup,
    app: &App,
    target: &RecordTarget,
    older: crate::testing::HeldRecord,
    proven: bool,
) {
    let key = app.record_key(target).unwrap();
    let mut inner = s.w.switch.lock();
    inner.shared.records.insert(key, older);
    inner.shared.hide_proofs = !proven;
}

/// An older write than the one held, both versions authenticated, shown by an answer
/// current past the held write, is the switch going back on its state: the app raises the
/// alarm itself (Switch spec 10.1, 10.3).
#[tokio::test]
async fn test_records_older_authenticated_write_shown_current_raises_the_alarm() {
    let (s, _wallet, mut phone, target, _, older) = older_write_held().await;
    show_older(&s, &phone, &target, older, true);
    let read = phone.read_record_fresh(&target).await;
    assert!(
        matches!(read, Err(AppError::Alarm(Alarm::Rollback { .. }))),
        "{read:?}"
    );
    assert!(matches!(phone.alarm(), Some(Alarm::Rollback { .. })));
}

/// An answer whose head is before the held write was overtaken by it: the read keeps the
/// held write and hands the shown one over apart from an older one, with what the answer is
/// current at, and nothing about the record's divergence changes (Switch spec 10.3).
#[tokio::test]
async fn test_records_overtaken_answer_is_handed_apart_from_an_older_one() {
    let (s, _wallet, mut phone, target, held, older) = older_write_held().await;
    let at = older.seq;
    let shown = older.state.version;
    show_older(&s, &phone, &target, older, true);
    // The overtaken view says the record is divergent: that says nothing of it now.
    let key = phone.record_key(&target).unwrap();
    s.w.switch
        .lock()
        .shared
        .divergent
        .insert(key, vec![[1; 32]]);
    s.w.switch.fail_next(Fault::Head {
        path: "/records/".into(),
        at: Some(at),
        forked: false,
    });
    phone.take_events();
    let read = phone.read_record_fresh(&target).await.unwrap();
    let RecordRead::Kept {
        record,
        reason: KeptReason::Overtaken { write, current_at },
    } = read
    else {
        panic!("{read:?}");
    };
    assert_eq!(record, Some(held));
    assert_eq!(write.version, shown);
    assert!(write.authenticated);
    assert_eq!(current_at.version, at);
    assert!(phone.alarm().is_none());
    let events = phone.take_events();
    assert!(!events.iter().any(|e| matches!(
        e,
        AppEvent::RecordShownOlder { .. } | AppEvent::RecordDivergent { .. }
    )));
    assert!(!phone.shared_record(&key).await.unwrap().unwrap().divergent);
}

/// A read whose head contradicts the verified chain at its `seq` is the switch's fork: the
/// app raises the rollback alarm before it judges the view (Switch spec 10.1).
#[tokio::test]
async fn test_records_read_with_a_forked_head_raises_the_alarm() {
    let (s, _wallet, mut phone, target, _, older) = older_write_held().await;
    let at = older.seq;
    show_older(&s, &phone, &target, older, true);
    s.w.switch.fail_next(Fault::Head {
        path: "/records/".into(),
        at: Some(at),
        forked: true,
    });
    let read = phone.read_record_fresh(&target).await;
    assert!(
        matches!(read, Err(AppError::Alarm(Alarm::Rollback { .. }))),
        "{read:?}"
    );
}

/// A record read without a head isn't the service's answer (Switch wire 7.1): it is refused,
/// never read as an older write.
#[tokio::test]
async fn test_records_read_without_a_head_is_refused() {
    let (s, _wallet, mut phone, target, held, older) = older_write_held().await;
    show_older(&s, &phone, &target, older, true);
    s.w.switch.fail_next(Fault::Head {
        path: "/records/".into(),
        at: None,
        forked: false,
    });
    let read = phone.read_record_fresh(&target).await.unwrap();
    assert!(
        matches!(
            &read,
            RecordRead::Kept {
                record: Some(kept),
                reason: KeptReason::Unreachable(_),
            } if *kept == held
        ),
        "{read:?}"
    );
    assert!(phone.alarm().is_none());
}

/// The switch's view of `key`, as `GET /records/{key}` answers `app` (Switch wire 7.4.9).
async fn raw_view(app: &App, key: &[u8; 32]) -> serde_json::Value {
    use pubky_switch_core::enc::{b64, pubky_id};
    let path = format!(
        "/v1/{}/records/{}",
        pubky_id(&app.own_identity().identity()),
        b64(key)
    );
    let request = app
        .client
        .sign_request(
            "GET",
            &path,
            Vec::new(),
            None,
            crate::transport::TimeoutClass::Bulk,
        )
        .unwrap();
    serde_json::from_slice(&app.client.send(request).await.unwrap().body).unwrap()
}

/// Two views of one key on one list page are each judged against what the other left: a
/// page that shows the newer write and then an older one, both authenticated, is the
/// switch's rollback, never the older write taken over the newer (Switch spec 10.1, 10.3).
#[tokio::test]
async fn test_records_two_views_of_one_key_on_a_page_are_judged_together() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let first = raw_view(&wallet, &key).await;
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    let second = raw_view(&wallet, &key).await;
    assert!(phone.shared_record(&key).await.unwrap().is_none());
    s.w.switch.fail_next(Fault::Replace {
        path: "records?collection".into(),
        member: "records".into(),
        value: json!([second, first]),
    });
    let listed = phone.list_collection(&items()).await;
    assert!(
        matches!(listed, Err(AppError::Alarm(Alarm::Rollback { .. }))),
        "{listed:?}"
    );
    let held = phone.shared_record(&key).await.unwrap();
    assert!(held.is_none_or(|held| ids(held.content.value()) == ["a", "b"]));
}

/// An older write whose version is only the switch's word is kept apart from the held one:
/// the read keeps the held write and hands the older one over with its version, item hash
/// and writer, and that the version isn't authenticated (Switch spec 10.3).
#[tokio::test]
async fn test_records_older_unauthenticated_write_is_handed_as_older() {
    let (s, wallet, mut phone, target, held, older) = older_write_held().await;
    show_older(&s, &phone, &target, older.clone(), false);
    let key = phone.record_key(&target).unwrap();
    let RecordRead::Kept {
        record,
        reason: KeptReason::Older(write),
    } = phone.read_record_fresh(&target).await.unwrap()
    else {
        panic!("not kept as older");
    };
    assert_eq!(record, Some(held));
    assert_eq!(write.version, older.state.version);
    assert!(!write.authenticated);
    assert_eq!(
        write.item_hash,
        SignedOp::peek(&older.op).unwrap().item_hash().unwrap()
    );
    assert_eq!(write.writer, wallet.app_id());
    assert!(phone.alarm().is_none());
    // A listing that shows it tells it too.
    phone.take_events();
    phone.list_collection(&items()).await.unwrap();
    assert!(phone.take_events().iter().any(
        |e| matches!(e, AppEvent::RecordShownOlder { key: k, write: w } if *k == key && *w == write)
    ));
}

/// After a provider loss declared at the same service, under its same key, the lost
/// generation's proofs verify with the key the new generation names but date nothing (Switch
/// wire 3.3, 6.2 step 2): an older write the switch shows with such a proof is only the
/// switch's word, handed over as older, never a rollback.
#[tokio::test]
async fn test_records_lost_generation_proof_under_the_same_key_is_no_rollback() {
    let (s, _wallet, mut phone, target, _, older) = older_write_held().await;
    let key = s.w.switch.service_key();
    let prev = s.w.switch.identity_doc().unwrap().hash();
    let doc =
        s.w.signer
            .sign_next(|body| {
                body.generation = 2;
                body.inbox = pubky_switch_core::records::Inbox::new(ORIGIN, key);
                body.recovery_from = Some(1);
            })
            .unwrap();
    s.w.switch.recover_in_place(&doc, prev).unwrap();
    phone.receive(None).await.unwrap();
    assert_eq!(phone.cursor().generation, 2);
    show_older(&s, &phone, &target, older, true);
    let read = phone.read_record_fresh(&target).await;
    assert!(phone.alarm().is_none(), "{:?}", phone.alarm());
    assert!(
        matches!(
            read,
            Ok(RecordRead::Kept {
                reason: KeptReason::Older(write),
                ..
            }) if !write.authenticated
        ),
        "{read:?}"
    );
}

/// The protocol's check is handed the service time the newer write's stub or proof dates it
/// at, not the time the app reads it: from a read, and from the feed.
#[tokio::test]
async fn test_records_regression_base_carries_the_write_time() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let first = s.w.clock.now_ms();
    s.w.clock.advance_ms(60_000);
    phone.read_record(&target).await.unwrap();
    let last = || s.protocol.bases.lock().unwrap().last().unwrap().clone();
    assert_eq!(last().written_at_ms, Some(first));
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    let second = s.w.clock.now_ms();
    s.w.clock.advance_ms(60_000);
    phone.receive(None).await.unwrap();
    assert_eq!(last().written_at_ms, Some(second));
    assert_ne!(first, second);
}

/// The protocol's check runs on the first write the app reads of a record too, against
/// nothing seen: a write that fails it is flagged with the app that signed it, its value not
/// trusted, and the app's repair builds on its version and lands (Switch spec 8.2); a first
/// write that passes is taken.
#[tokio::test]
async fn test_records_regression_check_runs_on_a_first_read() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    *s.protocol.forbidden.lock().unwrap() = Some("x".into());
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    wallet
        .put_record(&target, &value(&["x"]), vec![])
        .await
        .unwrap();
    let refused = s.w.switch.record(&key).unwrap().state.version;
    phone.take_events();
    let RecordRead::Kept {
        record: Some(held),
        reason: KeptReason::Refused,
    } = phone.read_record_fresh(&target).await.unwrap()
    else {
        panic!("not kept as refused");
    };
    assert!(held.flagged);
    assert_eq!(held.content, RecordContent::Unreadable(Unopened::Refused));
    assert!(flagged_by(&phone.take_events(), &key, wallet.app_id()));
    // The repair builds on the refused write's version, and lands.
    let repaired = phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    assert!(!repaired.flagged);
    assert!(repaired.version > refused);
    let op = SignedOp::peek(&s.w.switch.record(&key).unwrap().op).unwrap();
    let OpKind::RecordPut(put) = &op.body().kind else {
        panic!("a record write");
    };
    assert_eq!(put.expected_version, refused);
    let other = s.target("n2");
    wallet
        .put_record(&other, &value(&["a"]), vec![])
        .await
        .unwrap();
    assert!(matches!(
        phone.read_record_fresh(&other).await.unwrap(),
        RecordRead::Fresh(_)
    ));
}

#[tokio::test]
async fn test_records_write_by_a_removed_app_after_distrust_is_flagged() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    // The signer removes the wallet, distrusted from an hour ago, and publishes the document
    // before the switch takes it: the wallet's write the switch still accepts has no
    // standing for the phone, which read the document first.
    let me = wallet.app_id();
    let doc =
        s.w.signer
            .sign_next(|body| {
                body.apps.retain(|app| app.app_id != me);
                body.removed.push(RemovedApp {
                    app_id: me,
                    distrust_from: START - HOUR,
                })
            })
            .unwrap();
    wallet
        .put_record(&target, &value(&["a", "z"]), vec![])
        .await
        .unwrap();
    assert!(matches!(
        phone.refresh_identity().await.unwrap(),
        IdentityRefresh::Newer { .. }
    ));
    s.w.switch.deliver_identity(&doc).unwrap();
    phone.receive(None).await.unwrap();
    let key = phone.record_key(&target).unwrap();
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    assert!(held.flagged);
    let flagged = phone.flagged_writes().await.unwrap();
    assert!(
        flagged
            .iter()
            .any(|f| f.writer == me && f.reason.contains("distrust")),
        "{flagged:?}"
    );
}

/// `name` joins with `scopes` and every switch permission.
async fn join_scoped(s: &Setup, name: &str, scopes: &[&str]) -> App {
    let app = AppSpec::new(scopes).with_permissions(&ALL_PERMISSIONS);
    let request = s.w.signer.approve(&app_keys(name), &app).unwrap();
    App::join(s.env(), s.protocol.clone(), World::config(), request)
        .await
        .unwrap()
}

fn split_role_target(s: &Setup) -> RecordTarget {
    let collection = Collection::new(
        "sample.items",
        Policy::new("sample-a", &["sample-update"])
            .with_create_scope("sample-create")
            .permanent(None),
    );
    *s.protocol.collections.lock().unwrap() = Some(vec![collection.clone()]);
    RecordTarget::new(collection, b"shared")
}

/// A creator and an updater operate on the same permanent named record. Both verify
/// the original application on read, including the creator after reloading its store.
#[tokio::test]
async fn test_records_split_role_create_and_update_share_the_signed_address() {
    let s = Setup::new();
    let target = split_role_target(&s);
    let mut creator = join_scoped(&s, "wallet", &["sample-a", "sample-create"]).await;
    let mut updater = join_scoped(&s, "phone", &["sample-a", "sample-update"]).await;
    assert!(matches!(
        updater.put_record(&target, &value(&["a"]), vec![]).await,
        Err(AppError::Refused(Refusal::Usage(_)))
    ));
    creator
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = creator.record_key(&target).unwrap();
    assert_eq!(updater.record_key(&target).unwrap(), key);
    assert!(
        matches!(updater.read_record_fresh(&target).await.unwrap(), RecordRead::Fresh(record)
        if ids(record.content.value()) == ["a"])
    );
    assert!(matches!(
        creator
            .put_record(&target, &value(&["a", "b"]), vec![])
            .await,
        Err(AppError::Refused(Refusal::Usage(_)))
    ));
    updater
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();

    let mut creator = App::load(
        s.env(),
        s.protocol.clone(),
        World::config(),
        creator.app_id(),
    )
    .await
    .unwrap();
    assert!(
        matches!(creator.read_record_fresh(&target).await.unwrap(), RecordRead::Fresh(record)
        if ids(record.content.value()) == ["a", "b"])
    );
    let ops = s.w.switch.applied();
    let writes: Vec<_> = ops
        .iter()
        .filter_map(|op| match &op.body().kind {
            OpKind::RecordPut(put) if put.key == key => Some(put),
            _ => None,
        })
        .collect();
    assert_eq!(writes.len(), 2);
    assert!(writes[0].expected_version.is_none());
    assert!(!writes[1].expected_version.is_none());
    assert_eq!(writes[0].id_inputs, writes[1].id_inputs);
    assert!(
        writes
            .iter()
            .all(|put| put.check_address(&s.w.alice.public()).is_ok())
    );
}

/// A reader has the signed original and its writer's valid certificate but has yet to
/// authenticate when the original was applied. On reopen the proof settles that same item.
#[tokio::test]
async fn test_records_split_role_read_waits_for_the_original_write_time() {
    let s = Setup::new();
    let target = split_role_target(&s);
    let mut writer = join_scoped(&s, "wallet", &["sample-a", "sample-create"]).await;
    let mut reader = join_scoped(&s, "phone", &["sample-a"]).await;
    writer
        .put_record(&target, &value(&["original"]), vec![])
        .await
        .unwrap();
    reader.refresh_identity().await.unwrap();
    reader.refresh_own_apps().await.unwrap();
    s.w.switch.lock().shared.hide_proofs = true;
    assert!(matches!(
        reader.read_record_fresh(&target).await.unwrap(),
        RecordRead::Kept { .. }
    ));
    let key = reader.record_key(&target).unwrap();
    assert!(reader.shared_record(&key).await.unwrap().is_none());
    let mut reader = App::load(
        s.env(),
        s.protocol.clone(),
        World::config(),
        reader.app_id(),
    )
    .await
    .unwrap();
    assert!(matches!(
        reader.read_record_fresh(&target).await.unwrap(),
        RecordRead::Kept { .. }
    ));
    s.w.switch.lock().shared.hide_proofs = false;
    assert!(
        matches!(reader.read_record_fresh(&target).await.unwrap(), RecordRead::Fresh(record)
        if ids(record.content.value()) == ["original"])
    );
}

/// A fresh installation of the original writer has the same signing key and a backup
/// taken before the write. It needs a date to use that signed write under separate roles.
#[tokio::test]
async fn test_records_split_role_restored_own_key_waits_for_original_authority() {
    let s = Setup::new();
    let target = split_role_target(&s);
    let mut writer = join_scoped(&s, "wallet", &["sample-a", "sample-create"]).await;
    let backup = writer.backup().await.unwrap();
    writer
        .put_record(&target, &value(&["original"]), vec![])
        .await
        .unwrap();
    let key = writer.record_key(&target).unwrap();
    let id = writer.app_id();
    drop(writer);

    let fresh = Arc::new(MemoryStore::new());
    let env = || s.env_on(fresh.clone());
    let mut own = Box::pin(App::restore(
        env(),
        s.protocol.clone(),
        World::config(),
        &backup,
    ))
    .await
    .unwrap();
    assert_eq!(own.app_id(), id);
    s.w.switch.lock().shared.hide_proofs = true;
    for reload in [false, true] {
        if reload {
            drop(own);
            own = App::load(env(), s.protocol.clone(), World::config(), id)
                .await
                .unwrap();
        }
        assert!(matches!(
            own.read_record_fresh(&target).await.unwrap(),
            RecordRead::Kept {
                reason: KeptReason::Refused,
                ..
            }
        ));
        assert!(own.shared_record(&key).await.unwrap().is_none());
    }
    s.w.switch.lock().shared.hide_proofs = false;
    let RecordRead::Fresh(record) = own.read_record_fresh(&target).await.unwrap() else {
        panic!("the dated original should qualify");
    };
    assert_eq!(record.writer, id);
    assert_eq!(ids(record.content.value()), ["original"]);
}

/// When a writer renews the same signing key, both grants can hold the create scope.
/// The later listed grant cannot stand in for the one in force at the verified write.
#[tokio::test]
async fn test_records_split_role_keeps_the_grant_issued_by_the_original_write_time() {
    let s = Setup::new();
    let target = split_role_target(&s);
    let mut writer = join_scoped(&s, "wallet", &["sample-a", "sample-create"]).await;
    let first = writer.cert().clone();
    let mut reader = s.join("phone").await;
    reader.receive(None).await.unwrap();
    reader.refresh_own_apps().await.unwrap();
    writer
        .put_record(&target, &value(&["original"]), vec![])
        .await
        .unwrap();

    s.w.clock.advance_ms(HOUR);
    let renewed = renewed_cert(
        &s,
        "wallet",
        &["sample-a", "sample-create", "sample-update"],
    );
    s.w.next_doc(|body| list_renewal(body, &first, &renewed, None));
    writer.receive(None).await.unwrap();
    assert_eq!(writer.cert().hash(), renewed.hash());
    reader.refresh_identity().await.unwrap();
    reader.refresh_own_apps().await.unwrap();
    reader.receive(None).await.unwrap();

    let key = reader.record_key(&target).unwrap();
    let held = reader.shared_record(&key).await.unwrap().unwrap();
    let written_at = held.written_at_ms.unwrap();
    assert!(first.issued_at() <= written_at && written_at < renewed.issued_at());
    assert_eq!(ids(held.content.value()), ["original"]);
    let evidence = reader.shared_evidence().await.unwrap();
    assert_eq!(evidence.ops.len(), 1);
    assert_eq!(evidence.ops[0].cert, *first.signed());
}

/// A scope family admits only its exact create role as well as its read and update roles.
#[test]
fn test_records_split_role_fixed_and_family_members_keep_the_create_scope() {
    let policy = Policy::new("sample-a", &["sample-update"]).with_create_scope("sample-a");
    let fixed = Collection::new("sample.items", policy.clone());
    assert!(fixed.admits(&policy));
    assert!(!fixed.admits(&Policy::new("sample-a", &["sample-update"])));
    let family = Collection::with_sub_scopes("sample.items", policy);
    let shop = family.sub_scope_policy("shop").unwrap();
    assert_eq!(shop.create_scope.as_deref(), Some("sample-a:shop"));
    assert!(family.admits(&shop));
    assert!(!family.admits(&shop.clone().with_create_scope("sample-a")));
    let separate = Collection::with_sub_scopes(
        "sample.items",
        family.policy.clone().with_create_scope("sample-create"),
    );
    assert_eq!(
        separate
            .sub_scope_policy("shop")
            .unwrap()
            .create_scope
            .as_deref(),
        Some("sample-create")
    );

    let generations =
        Collection::with_permanent_generations("sample.items", "sample-a", &["sample-update"]);
    let member = generations.policy.clone().permanent(Some(2));
    assert!(generations.admits(&member));
    assert!(!generations.admits(&member.with_create_scope("sample-create")));
}

/// A certificate renewing `name`'s with `scopes`, issued now.
fn renewal_of(s: &Setup, name: &str, scopes: &[&str]) -> AppCert {
    let app = AppSpec::new(scopes).with_permissions(&ALL_PERMISSIONS);
    crate::testing::issue_cert(&s.w.alice, &app_keys(name), &app, s.w.clock.now_ms()).unwrap()
}

/// The signer renews `name`'s certificate with `scopes` and stores it at the switch with the
/// key bundle made for it (Switch wire 3.8 step 1). Returns it.
fn renewed_cert(s: &Setup, name: &str, scopes: &[&str]) -> AppCert {
    let renewed = renewal_of(s, name, scopes);
    let target_app_id = renewed.app_id();
    let has_keys = |scope: &str| SampleProtocol::default().has_keys(scope);
    let epoch = s.w.switch.identity_doc().unwrap().data_epoch();
    let mut batch = vec![OpKind::CertPut {
        target_app_id,
        cert: renewed.signed().clone(),
    }];
    for part in seal_bundle_parts(&s.w.alice, &renewed, 1, epoch, &has_keys).unwrap() {
        batch.push(OpKind::KeyBundlePut(KeyBundlePut {
            target_app_id,
            bundle: part.bundle,
            first_epoch: part.first_epoch,
            last_epoch: part.last_epoch,
        }));
    }
    s.w.switch.signer_batch(batch).unwrap();
    renewed
}

/// The `identity.json` change that lists `renewed` in place of `earlier`, with `earlier` in
/// `renewed` and `until` as given (Switch wire 3.3, 3.8 step 2 and "Reductions").
fn list_renewal(body: &mut IdentityBody, earlier: &AppCert, renewed: &AppCert, until: Option<u64>) {
    let app_id = renewed.app_id();
    body.apps.retain(|app| app.app_id != app_id);
    body.apps.push(ListedApp {
        app_id,
        cert: renewed.hash(),
    });
    body.renewed.retain(|entry| entry.app_id != app_id);
    body.renewed.push(RenewedCert {
        app_id,
        cert: earlier.hash(),
        until,
    });
}

/// The rules of the `WriteFlagged` events among `events`.
fn flagged_rules(events: &[AppEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            AppEvent::WriteFlagged { reason, .. } => Some(reason.clone()),
            _ => None,
        })
        .collect()
}

/// The scripted switch keeps, with a record, the certificate it checked the write against,
/// and serves it in the record's views, by key and in a list, after a reduction that the
/// writer has followed (Switch wire 7.4.9).
#[tokio::test]
async fn test_scripted_record_view_keeps_the_certificate_the_write_was_checked_against() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    wallet.receive(None).await.unwrap();
    assert_eq!(
        s.w.switch.app(&wallet.app_id()).cert.map(|c| c.hash()),
        Some(renewed.hash())
    );
    let view = phone.client.record(&key).await.unwrap().view;
    assert_eq!(view.cert, *earlier.signed());
    let id = items().id(&s.w.alice.public());
    let page = phone.client.records(&id, None, None).await.unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].cert, *earlier.signed());
}

/// A reduction (Switch wire 3.8 "Reductions"): the wallet's renewed certificate lacks the
/// collection's scope, and the earlier one closes at once. A record view carries the
/// certificate the write was checked against (Switch wire 7.4.9), and the write, dated
/// before `until`, is judged with it (Switch wire 6.2 "Accepting a write" step 4): the
/// phone, which held the record and has since kept the renewed certificate, takes it again,
/// and so does a tablet that joins afterwards.
#[tokio::test]
async fn test_records_write_before_a_reduction_is_kept_by_every_reader() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    phone.receive(None).await.unwrap();
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert!(!held.flagged);

    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    // The switch keeps the certificate it checked the write against.
    let at_switch = s.w.switch.record(&key).unwrap();
    assert_eq!(at_switch.cert.as_ref(), Some(earlier.signed()));

    // (a) The phone keeps the renewed certificate from the wallet's record in its feed, and
    // reads the record again.
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    phone.read_record(&target).await.unwrap();
    let events = phone.take_events();
    assert!(flagged_rules(&events).is_empty(), "{events:?}");
    assert!(phone.flagged_writes().await.unwrap().is_empty());
    let again = phone.shared_record(&key).await.unwrap().unwrap();
    assert!(!again.flagged);
    assert_eq!(again, held);

    // (b) A tablet that joins after the renewal lists the collection and reads the record.
    s.w.clock.advance_ms(HOUR);
    let mut tablet = s.join("tablet").await;
    assert_eq!(tablet.list_collection(&items()).await.unwrap().records, 1);
    let listed = tablet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(listed.content.value()), vec!["a"]);
    assert!(!listed.flagged);
    let read = tablet.read_record(&target).await.unwrap().unwrap();
    assert_eq!(ids(read.content.value()), vec!["a"]);
    let events = tablet.take_events();
    assert!(flagged_rules(&events).is_empty(), "{events:?}");
    assert!(tablet.flagged_writes().await.unwrap().is_empty());
    // The write is kept with the certificate it was made under, as its evidence.
    let evidence = tablet.shared_evidence().await.unwrap();
    assert_eq!(evidence.ops.len(), 1);
    assert_eq!(evidence.ops[0].cert, *earlier.signed());
}

/// The failure path: a write under the earlier certificate dated after its `until`. It
/// models a faulty ordering, which an honest switch refuses: the signer publishes the
/// closed renewal before the switch takes it, so the switch still checks the wallet against
/// the earlier certificate and takes a write ten minutes past the cutoff. A compliant
/// switch checks the wallet against the renewed certificate from the renewing delivery on
/// (Switch wire 3.8), so no write under the earlier one is dated past `until`. Once the
/// wallet published its record with the renewed certificate, which lacks the write scope,
/// every reader flags it (Switch wire 6.2 "Accepting a write" step 4), from the feed and
/// from the record view alike: the phone, and a tablet that joins afterwards.
#[tokio::test]
async fn test_records_write_after_a_reduction_closed_is_flagged_by_every_reader() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();

    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewal_of(&s, "wallet", &["sample-c"]);
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    let opened =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, None))
            .unwrap();
    let closed =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, Some(until)))
            .unwrap();
    s.w.clock.advance_ms(2 * CLOCK_TOLERANCE_MS);
    let target = s.target("n2");
    wallet
        .put_record(&target, &value(&["late"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    assert_eq!(
        s.w.switch.record(&key).unwrap().cert.as_ref(),
        Some(earlier.signed())
    );
    s.w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: wallet.app_id(),
            cert: renewed.signed().clone(),
        })
        .unwrap();
    s.w.switch.deliver_identity(&opened).unwrap();
    s.w.switch.deliver_identity(&closed).unwrap();
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());

    // The phone, from its feed (no record view), then from the record view.
    assert!(matches!(
        phone.refresh_identity().await.unwrap(),
        IdentityRefresh::Newer { .. }
    ));
    // The feed judges it with the certificate in force at its time, the renewed one, which
    // holds no write scope (step 5); the view with its `cert`, the earlier one (step 4).
    let report = phone.receive(None).await.unwrap();
    let from_feed = flagged_rules(&report.events);
    assert!(
        from_feed.iter().any(|rule| rule.contains("step 5")),
        "{from_feed:?}"
    );
    assert!(phone.shared_record(&key).await.unwrap().is_none());
    phone.read_record(&target).await.unwrap();
    let from_view = flagged_rules(&phone.take_events());
    assert!(
        from_view.iter().any(|rule| rule.contains("step 4")),
        "{from_view:?}"
    );
    assert!(phone.shared_record(&key).await.unwrap().is_none());

    // A tablet that joins afterwards, from the list, then from the record view.
    let mut tablet = s.join("tablet").await;
    tablet.list_collection(&items()).await.unwrap();
    let from_list = flagged_rules(&tablet.take_events());
    assert!(
        from_list.iter().any(|rule| rule.contains("step 4")),
        "{from_list:?}"
    );
    assert!(tablet.read_record(&target).await.unwrap().is_none());
    let from_view = flagged_rules(&tablet.take_events());
    assert!(
        from_view.iter().any(|rule| rule.contains("step 4")),
        "{from_view:?}"
    );
}

/// A write read from the feed carries no certificate: the reader takes the one in force at
/// the write's time. The phone was away through a reduction, and knows both of the wallet's
/// certificates from its directory when it reads its feed: the write, dated before the
/// earlier certificate's `until`, is judged with it (Switch wire 6.2 "Accepting a write"
/// step 4) and taken.
#[tokio::test]
async fn test_records_feed_write_before_a_reduction_is_taken() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();

    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());

    phone.refresh_identity().await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    let report = phone.receive(None).await.unwrap();
    let events = report.events;
    assert!(flagged_rules(&events).is_empty(), "{events:?}");
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    assert!(!held.flagged);
}

/// Of the certificates in force at a feed write's time that hold a write scope, the reader
/// takes the one in the best standing now, and keeps it with the write as its evidence: a
/// renewal that only adds a scope, still open, leaves both counting, and the listed one is
/// kept, which still authorizes the write when nothing dates it, as after an upload.
#[tokio::test]
async fn test_records_feed_write_keeps_the_best_standing_certificate_in_force() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();

    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-a", "sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());

    phone.refresh_identity().await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    let evidence = phone.shared_evidence().await.unwrap();
    assert_eq!(evidence.ops.len(), 1);
    assert_eq!(evidence.ops[0].cert, *renewed.signed());
}

/// A certificate expired at a feed write's time isn't in force then: the wallet's
/// certificate expired, the signer renewed it, and the wallet writes under the renewed one
/// while the earlier is still in `renewed` with `until` `null`. The reader judges the write
/// with the renewed certificate (Switch wire 6.2 "Accepting a write" step 4) and takes it.
#[tokio::test]
async fn test_records_feed_write_after_an_expiry_renewal_is_taken() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a"]).await;
    let earlier = wallet.cert().clone();
    s.w.clock.set_ms(earlier.expires_at() - HOUR);
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    phone.refresh_own_apps().await.unwrap();

    s.w.clock.set_ms(earlier.expires_at() + 1);
    let renewed = renewed_cert(&s, "wallet", &["sample-a"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();

    phone.refresh_identity().await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
}

/// A closed renewal's earlier certificate isn't in force after its `until`: the wallet
/// writes under its renewed certificate once the renewal closed, a scope both hold, and the
/// reader judges the write with the renewed one (Switch wire 6.2 "Accepting a write" step 4)
/// and takes it.
#[tokio::test]
async fn test_records_feed_write_after_a_renewal_closed_is_taken() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    phone.refresh_own_apps().await.unwrap();

    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-a", "sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    s.w.clock.advance_ms(HOUR);
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();

    phone.refresh_identity().await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
}

/// A write from the feed under a scope a renewal added, made while the earlier certificate
/// still counts: of the certificates in force at the write's time, the reader takes one
/// that holds a write scope (Switch wire 6.2 "Accepting a write" steps 4 and 5).
#[tokio::test]
async fn test_records_feed_write_under_a_scope_a_renewal_added_is_taken() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    phone.refresh_own_apps().await.unwrap();

    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-a", "sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();

    phone.refresh_identity().await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    let report = phone.receive(None).await.unwrap();
    let events = report.events;
    assert!(flagged_rules(&events).is_empty(), "{events:?}");
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
}

/// A renewal that adds a collection's read scope owes a listing: the writes there before it
/// showed as stubs in the app's feed, so only the next read's listing brings them (Switch
/// spec 8.3, Switch wire 7.4.9).
#[tokio::test]
async fn test_records_renewal_adding_a_read_scope_lists_the_collection() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-c"]).await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&target).unwrap();
    wallet.receive(None).await.unwrap();
    assert!(wallet.shared_record(&key).await.unwrap().is_none());

    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-a", "sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    // The renewal's part came before the document that lists it, and was skipped: the
    // signer stores the renewed certificate's keys again.
    store_parts_for(&s, &renewed);
    wallet.receive(None).await.unwrap();
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
}

/// The signer stores the key bundle made for `cert` over every epoch so far.
fn store_parts_for(s: &Setup, cert: &AppCert) {
    let has_keys = |scope: &str| SampleProtocol::default().has_keys(scope);
    let epoch = s.w.switch.identity_doc().unwrap().data_epoch();
    for part in seal_bundle_parts(&s.w.alice, cert, 1, epoch, &has_keys).unwrap() {
        s.w.switch
            .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: cert.app_id(),
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
    }
}

/// A renewal that adds a sub-scope to a family the app already read part of owes a
/// listing: the records under the new sub-scope were stubs in its feed.
#[tokio::test]
async fn test_records_renewal_adding_a_sub_scope_lists_its_records() {
    let s = Setup::new();
    let family =
        Collection::with_sub_scopes("sample.items", Policy::new("sample-a", &["sample-a"]));
    *s.protocol.collections.lock().unwrap() = Some(vec![family.clone()]);
    let mut wallet = join_scoped(&s, "wallet", &["sample-a:kiosk"]).await;
    let mut phone = s.join("phone").await;
    let target = RecordTarget::new(family.sub_scope("till").unwrap(), b"t1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&target).unwrap();
    wallet.receive(None).await.unwrap();
    assert!(wallet.shared_record(&key).await.unwrap().is_none());
    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-a:kiosk", "sample-a:till"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    store_parts_for(&s, &renewed);
    wallet.receive(None).await.unwrap();
    wallet.receive(None).await.unwrap();
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
}

/// A renewal that adds no read scope of a collection owes no listing.
#[tokio::test]
async fn test_records_renewal_adding_no_read_scope_lists_nothing() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    wallet.receive(None).await.unwrap();
    let listings = s.w.switch.lock().shared.listings;

    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-a", "sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.receive(None).await.unwrap();
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    assert_eq!(s.w.switch.lock().shared.listings, listings);
}

/// A feed write under a certificate the reader never held: the phone joined after the
/// wallet and kept none of its certificates, the wallet wrote while the phone was away, and
/// a reduction dropped the record's scope. The newest `identity.json` names the earlier
/// certificate as in force at the write's time, so the phone reads the record's view and
/// judges the write with its `cert` (Switch wire 6.2 "Accepting a write" step 1, 7.4.9),
/// and takes it, as a reader that kept that certificate does.
#[tokio::test]
async fn test_records_feed_write_under_a_certificate_never_held_is_judged_by_its_view() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();

    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());

    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    assert!(phone.flagged_writes().await.unwrap().is_empty());
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    let evidence = phone.shared_evidence().await.unwrap();
    assert_eq!(evidence.ops[0].cert, *earlier.signed());
}

/// A feed write under a certificate the reader never held, whose view the switch shows with
/// the renewed certificate, which lacks the write scope, as a faulty switch would. The write
/// names no certificate, so the view's `cert` is only the switch's pick, and the earlier
/// certificate the reader lacks was in force at the write: the write is neither taken nor
/// flagged (Switch wire 6.2 "Accepting a write" steps 1 and 5).
#[tokio::test]
async fn test_records_feed_write_whose_view_lacks_the_write_scope_names_no_app() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();

    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    wallet.receive(None).await.unwrap();
    s.w.switch.lock().shared.records.get_mut(&key).unwrap().cert = Some(renewed.signed().clone());

    let before = s.log().len();
    let report = phone.receive(None).await.unwrap();
    let rules = flagged_rules(&report.events);
    assert!(rules.is_empty(), "{rules:?}");
    assert!(phone.flagged_writes().await.unwrap().is_empty());
    assert!(phone.shared_record(&key).await.unwrap().is_none());
    let path = format!("/records/{}", pubky_switch_core::enc::b64(&key));
    assert!(
        s.log()[before..]
            .iter()
            .any(|line| line.starts_with("GET ") && line.ends_with(&path)),
        "{:?}",
        &s.log()[before..]
    );
}

/// A write nothing dates, read from a view whose `cert` isn't the writer's: of the
/// writer's certificates that count without a time (listed, or renewed with `until`
/// `null`), the reader takes one that holds a write scope (Switch wire 6.2 "Accepting a
/// write" steps 1, 4 and 5). The renewal drops the scope and is still open.
#[tokio::test]
async fn test_records_undated_write_is_judged_with_a_certificate_holding_a_write_scope() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();

    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    {
        let mut inner = s.w.switch.lock();
        inner.shared.records.get_mut(&key).unwrap().cert = Some(phone.cert().signed().clone());
        inner.shared.hide_proofs = true;
    }
    phone.refresh_identity().await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    phone.read_record(&target).await.unwrap();
    let events = phone.take_events();
    assert!(flagged_rules(&events).is_empty(), "{events:?}");
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
}

/// The wallet's record writes, after a reduction that dropped their scope and closed the
/// earlier certificate at once: `count` records written under the earlier certificate, a
/// day before the renewal, whose keys it returns. The phone joined before the writes and
/// keeps none of the wallet's certificates.
async fn writes_before_a_reduction(s: &Setup, count: usize) -> (App, App, Vec<[u8; 32]>, AppCert) {
    let mut wallet = join_scoped(s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    let mut keys = Vec::new();
    for n in 0..count {
        let target = s.target(&format!("n{n}"));
        wallet
            .put_record(&target, &value(&["a"]), vec![])
            .await
            .unwrap();
        keys.push(wallet.record_key(&target).unwrap());
    }
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(s, "wallet", &["sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    (wallet, phone, keys, renewed)
}

/// The `GET /records/{key}` requests in `log`.
fn record_reads(log: &[String]) -> Vec<String> {
    log.iter()
        .filter(|line| line.starts_with("GET ") && line.contains("/records/"))
        .cloned()
        .collect()
}

/// Feed writes under one certificate the reader never held: the first write's view gives
/// the certificate, kept with that write in the page, and it serves the page's other writes
/// without reading their views (Switch wire 6.2 "Accepting a write" step 1).
#[tokio::test]
async fn test_records_feed_writes_under_one_unheld_certificate_read_one_view() {
    let s = Setup::new();
    let (_wallet, mut phone, keys, _) = writes_before_a_reduction(&s, 5).await;
    let before = s.log().len();
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    for key in &keys {
        assert!(phone.shared_record(key).await.unwrap().is_some());
    }
    let reads = record_reads(&s.log()[before..]);
    assert_eq!(reads.len(), 1, "{reads:?}");
}

/// A view read that fails, for a feed write under a certificate the reader never held,
/// fails the read: nothing is committed and the cursor stays, so the next read judges the
/// write again.
#[tokio::test]
async fn test_records_failed_view_read_for_a_feed_write_fails_the_read() {
    let s = Setup::new();
    let (_wallet, mut phone, keys, _) = writes_before_a_reduction(&s, 1).await;
    let cursor = phone.cursor();
    s.w.switch.fail_next(Fault::Unreachable {
        path: "/records/".into(),
        after: 0,
    });
    assert!(phone.receive(None).await.is_err());
    assert_eq!(phone.cursor(), cursor);
    assert!(phone.shared_record(&keys[0]).await.unwrap().is_none());
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    assert!(phone.shared_record(&keys[0]).await.unwrap().is_some());
}

/// Feed writes whose views carry a certificate without the write scope, as a faulty switch
/// shows them: a write left untaken keeps no certificate, so each write's view is read, and
/// none is flagged (Switch wire 6.2 "Accepting a write" steps 1 and 5).
#[tokio::test]
async fn test_records_feed_writes_whose_views_lack_the_write_scope_each_name_no_app() {
    let s = Setup::new();
    let (_wallet, mut phone, keys, renewed) = writes_before_a_reduction(&s, 3).await;
    for key in &keys {
        s.w.switch.lock().shared.records.get_mut(key).unwrap().cert =
            Some(renewed.signed().clone());
    }
    let before = s.log().len();
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    assert!(phone.flagged_writes().await.unwrap().is_empty());
    assert_eq!(record_reads(&s.log()[before..]).len(), 3);
}

/// A feed write under a certificate the reader never held, whose view the switch answers
/// `404` for, as for a record it forgot: no view decides, so the write is neither taken nor
/// flagged, and the cursor moves past it; a later read of the record takes it.
#[tokio::test]
async fn test_records_feed_write_whose_view_is_gone_is_left_unjudged() {
    let s = Setup::new();
    let (_wallet, mut phone, keys, _) = writes_before_a_reduction(&s, 1).await;
    let key = keys[0];
    let cursor = phone.cursor();
    s.w.switch.fail_next(Fault::Error {
        path: "/records/".into(),
        code: ErrorCode::NotFound,
        current: serde_json::Value::Null,
    });
    let before = s.log().len();
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    assert_eq!(record_reads(&s.log()[before..]).len(), 1);
    assert!(phone.cursor().seq > cursor.seq);
    assert!(phone.shared_record(&key).await.unwrap().is_none());
    assert!(phone.flagged_writes().await.unwrap().is_empty());
    phone.read_record(&s.target("n0")).await.unwrap();
    assert!(phone.shared_record(&key).await.unwrap().is_some());
}

/// A feed write judged by its record's view keeps what the feed gave it: the view of the
/// same operation, shown without its proof, is dated and versioned by the verified stub of
/// the feed (Switch wire 6.2 "Accepting a write" steps 2 and 6). The write, dated before the
/// earlier certificate's `until`, is taken with an authenticated version.
#[tokio::test]
async fn test_records_feed_write_judged_by_a_proofless_view_keeps_its_stub() {
    let s = Setup::new();
    let (_wallet, mut phone, keys, _) = writes_before_a_reduction(&s, 1).await;
    let key = keys[0];
    let written = s.w.switch.record(&key).unwrap();
    s.w.switch.lock().shared.hide_proofs = true;
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert!(held.authenticated);
    assert!(!held.doubtful);
    assert_eq!(held.version, written.state.version);
}

/// The failure path of the same: a removed writer's write after its `distrust_from`, taken
/// by a faulty switch that shows the record's view without its proof. The feed's stub dates
/// the write after the cutoff, so the reader that never held the writer's certificate flags
/// it, as one that held it does, instead of holding it as doubtful (Switch wire 6.2
/// "Accepting a write" step 4).
#[tokio::test]
async fn test_records_proofless_view_of_a_removed_writers_late_feed_write_is_flagged() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    let mut tablet = s.join("tablet").await;
    tablet.receive(None).await.unwrap();
    tablet.refresh_own_apps().await.unwrap();
    s.w.clock.advance_ms(HOUR);
    let distrust_from = s.w.clock.now_ms();
    let me = wallet.app_id();
    let doc =
        s.w.signer
            .sign_next(|body| {
                body.apps.retain(|app| app.app_id != me);
                body.removed.push(RemovedApp {
                    app_id: me,
                    distrust_from,
                })
            })
            .unwrap();
    s.w.clock.advance_ms(HOUR);
    let late = s.target("late");
    wallet
        .put_record(&late, &value(&["l"]), vec![])
        .await
        .unwrap();
    s.w.switch.deliver_identity(&doc).unwrap();
    let key = phone.record_key(&late).unwrap();
    s.w.switch.lock().shared.hide_proofs = true;

    tablet.refresh_identity().await.unwrap();
    let report = tablet.receive(None).await.unwrap();
    let rules = flagged_rules(&report.events);
    assert!(
        rules.iter().any(|rule| rule.contains("distrust")),
        "{rules:?}"
    );
    assert!(tablet.shared_record(&key).await.unwrap().is_none());
    phone.refresh_identity().await.unwrap();
    let before = s.log().len();
    let report = phone.receive(None).await.unwrap();
    assert_eq!(record_reads(&s.log()[before..]).len(), 1);
    let rules = flagged_rules(&report.events);
    assert!(
        rules.iter().any(|rule| rule.contains("distrust")),
        "{rules:?}"
    );
    assert!(phone.shared_record(&key).await.unwrap().is_none());
}

/// A feed write whose record's view shows another, later write of the record: the view's
/// write is judged with the view's own evidence, and the feed write isn't judged at all, so
/// the feed's stub, which names the other operation, dates nothing of it (Switch wire 6.2
/// "Accepting a write" step 2). The switch shows the earlier write in the feed while its
/// view already serves the later one.
#[tokio::test]
async fn test_records_feed_write_whose_view_is_of_a_later_write_judges_only_that_write() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    let first = s.w.switch.record(&key).unwrap();
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    let later = s.w.switch.record(&key).unwrap();
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    wallet.receive(None).await.unwrap();
    {
        let mut shown = later.clone();
        shown.seq = first.seq;
        s.w.switch.lock().shared.records.insert(key, shown);
    }
    let report = phone.receive(None).await.unwrap();
    assert!(
        !report
            .events
            .iter()
            .any(|event| matches!(event, AppEvent::Alarm(_))),
        "{:?}",
        report.events
    );
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a", "b"]);
    assert_eq!(held.version, later.state.version);
    assert!(held.authenticated);
}

/// A feed write the reader holds every named certificate for reads no view: the wallet's
/// write after a reduction closed, under the dropped scope, which the phone, holding both
/// certificates, flags from its feed at step 5 (Switch wire 6.2 "Accepting a write"). The
/// signer publishes the renewal before the switch takes it, a faulty ordering an honest
/// switch refuses, as in the failure path above.
#[tokio::test]
async fn test_records_feed_write_under_held_certificates_reads_no_view() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewal_of(&s, "wallet", &["sample-c"]);
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    let opened =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, None))
            .unwrap();
    let closed =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, Some(until)))
            .unwrap();
    s.w.clock.advance_ms(2 * CLOCK_TOLERANCE_MS);
    let target = s.target("n2");
    wallet
        .put_record(&target, &value(&["late"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: wallet.app_id(),
            cert: renewed.signed().clone(),
        })
        .unwrap();
    s.w.switch.deliver_identity(&opened).unwrap();
    s.w.switch.deliver_identity(&closed).unwrap();
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());

    phone.refresh_identity().await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    let before = s.log().len();
    let report = phone.receive(None).await.unwrap();
    let rules = flagged_rules(&report.events);
    assert!(
        rules.iter().any(|rule| rule.contains("step 5")),
        "{rules:?}"
    );
    assert!(phone.shared_record(&key).await.unwrap().is_none());
    assert!(record_reads(&s.log()[before..]).is_empty());
}

/// A removed writer's write, dated before its `distrust_from`, read from the feed by a
/// reader that never held its certificate: the directory lists only current apps, so it
/// gives none, and the record's view decides (Switch wire 6.2 "Accepting a write" steps 1
/// and 4). The reader takes the write, as one that held the certificate does from the same
/// feed and one that joins afterwards does from the list.
#[tokio::test]
async fn test_records_feed_write_by_a_removed_writer_never_held_is_judged_by_its_view() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    let mut tablet = s.join("tablet").await;
    tablet.receive(None).await.unwrap();
    tablet.refresh_own_apps().await.unwrap();
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.clock.advance_ms(HOUR);
    let me = wallet.app_id();
    let distrust_from = s.w.clock.now_ms();
    s.w.next_doc(|body| {
        body.apps.retain(|app| app.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from,
        })
    });

    let report = tablet.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    assert!(tablet.shared_record(&key).await.unwrap().is_some());
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    let mut laptop = s.join("laptop").await;
    laptop.list_collection(&items()).await.unwrap();
    assert!(laptop.shared_record(&key).await.unwrap().is_some());
}

/// A feed write by a writer whose certificate the reader never held, while the directory
/// read fails: the record's view decides, so the write isn't passed with the cursor
/// unjudged (Switch wire 6.2 "Accepting a write" step 1).
#[tokio::test]
async fn test_records_feed_write_while_the_directory_fails_is_judged_by_its_view() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.switch.fail_next(Fault::Unreachable {
        path: "/directory".into(),
        after: 0,
    });
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
}

/// A removed writer's writes: one before `distrust_from` is taken and one after is flagged
/// (Switch wire 6.2 "Accepting a write" step 4), by a reader from its feed, again from the
/// views, and by a reader that joins after the removal from the list. The signer publishes
/// the removal before the switch takes it, so the switch takes the later write.
#[tokio::test]
async fn test_records_removed_writer_is_judged_by_distrust_from_by_every_reader() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    let early = s.target("early");
    wallet
        .put_record(&early, &value(&["e"]), vec![])
        .await
        .unwrap();
    s.w.clock.advance_ms(HOUR);
    let distrust_from = s.w.clock.now_ms();
    let me = wallet.app_id();
    let doc =
        s.w.signer
            .sign_next(|body| {
                body.apps.retain(|app| app.app_id != me);
                body.removed.push(RemovedApp {
                    app_id: me,
                    distrust_from,
                })
            })
            .unwrap();
    s.w.clock.advance_ms(HOUR);
    let late = s.target("late");
    wallet
        .put_record(&late, &value(&["l"]), vec![])
        .await
        .unwrap();
    s.w.switch.deliver_identity(&doc).unwrap();
    let early_key = phone.record_key(&early).unwrap();
    let late_key = phone.record_key(&late).unwrap();

    phone.refresh_identity().await.unwrap();
    let report = phone.receive(None).await.unwrap();
    let rules = flagged_rules(&report.events);
    assert_eq!(rules.len(), 1, "{rules:?}");
    assert!(rules[0].contains("distrust"), "{rules:?}");
    let held = phone.shared_record(&early_key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["e"]);
    assert!(phone.shared_record(&late_key).await.unwrap().is_none());
    phone.read_record(&early).await.unwrap();
    assert!(flagged_rules(&phone.take_events()).is_empty());
    phone.read_record(&late).await.unwrap();
    let rules = flagged_rules(&phone.take_events());
    assert!(
        rules.iter().any(|rule| rule.contains("distrust")),
        "{rules:?}"
    );

    let mut tablet = s.join("tablet").await;
    assert_eq!(tablet.list_collection(&items()).await.unwrap().records, 2);
    let rules = flagged_rules(&tablet.take_events());
    assert_eq!(rules.len(), 1, "{rules:?}");
    assert!(rules[0].contains("distrust"), "{rules:?}");
    assert!(tablet.shared_record(&early_key).await.unwrap().is_some());
    assert!(tablet.shared_record(&late_key).await.unwrap().is_none());
}

/// A write under the dropped scope dated after the renewing delivery but before `until`,
/// within the reduction's tolerance. It models a faulty ordering, which an honest switch
/// refuses: the switch takes the write under the earlier certificate before it takes the
/// renewal. The earlier certificate counts for a write dated before `until` (Switch wire
/// 6.2 "Accepting a write" step 4), so every reader takes it: the phone from its feed and
/// from the view, and a tablet that joins afterwards from the list.
#[tokio::test]
async fn test_records_write_within_a_reductions_tolerance_is_taken_by_every_reader() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewal_of(&s, "wallet", &["sample-c"]);
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    let opened =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, None))
            .unwrap();
    let closed =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, Some(until)))
            .unwrap();
    s.w.clock.advance_ms(CLOCK_TOLERANCE_MS / 2);
    let target = s.target("n2");
    wallet
        .put_record(&target, &value(&["late"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: wallet.app_id(),
            cert: renewed.signed().clone(),
        })
        .unwrap();
    s.w.switch.deliver_identity(&opened).unwrap();
    s.w.switch.deliver_identity(&closed).unwrap();
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());

    phone.refresh_identity().await.unwrap();
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    phone.read_record(&target).await.unwrap();
    let from_view = flagged_rules(&phone.take_events());
    assert!(from_view.is_empty(), "{from_view:?}");
    assert!(phone.shared_record(&key).await.unwrap().is_some());
    let mut tablet = s.join("tablet").await;
    tablet.list_collection(&items()).await.unwrap();
    let from_list = flagged_rules(&tablet.take_events());
    assert!(from_list.is_empty(), "{from_list:?}");
    assert!(tablet.shared_record(&key).await.unwrap().is_some());
}

/// A view whose `cert` is a certificate of the writer, signed by the identity and holding
/// the write scope, that no `identity.json` lists, on a write after the cutoff: it has no
/// standing (Switch wire 6.2 "Accepting a write" step 4), and every reader refuses the
/// write, from the feed, the view and the list, once the wallet published its record with
/// the renewed certificate, which lacks the write scope. The signer publishes the renewal
/// before the switch takes it, as in the failure path above.
#[tokio::test]
async fn test_records_view_cert_no_identity_json_lists_is_refused() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewal_of(&s, "wallet", &["sample-c"]);
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    let opened =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, None))
            .unwrap();
    let closed =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, Some(until)))
            .unwrap();
    s.w.clock.advance_ms(2 * CLOCK_TOLERANCE_MS);
    let target = s.target("n2");
    wallet
        .put_record(&target, &value(&["late"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    let unlisted = renewal_of(&s, "wallet", &["sample-a", "sample-c"]);
    s.w.switch.lock().shared.records.get_mut(&key).unwrap().cert = Some(unlisted.signed().clone());
    s.w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: wallet.app_id(),
            cert: renewed.signed().clone(),
        })
        .unwrap();
    s.w.switch.deliver_identity(&opened).unwrap();
    s.w.switch.deliver_identity(&closed).unwrap();
    wallet.receive(None).await.unwrap();

    phone.refresh_identity().await.unwrap();
    let report = phone.receive(None).await.unwrap();
    assert!(
        !flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
    assert!(phone.shared_record(&key).await.unwrap().is_none());
    phone.read_record(&target).await.unwrap();
    let from_view = flagged_rules(&phone.take_events());
    assert!(
        from_view.iter().any(|rule| rule.contains("no standing")),
        "{from_view:?}"
    );
    assert!(phone.shared_record(&key).await.unwrap().is_none());
    let mut tablet = s.join("tablet").await;
    tablet.list_collection(&items()).await.unwrap();
    let from_list = flagged_rules(&tablet.take_events());
    assert!(
        from_list.iter().any(|rule| rule.contains("no standing")),
        "{from_list:?}"
    );
    assert!(tablet.shared_record(&key).await.unwrap().is_none());
}

/// A write under the earlier certificate dated `before` milliseconds before its `until`,
/// which the switch takes before it takes the closed renewal the signer published, as in
/// the failure path above: what a tablet that joins afterwards flags of it from the list.
async fn rules_for_a_write_before_until(before: u64) -> (Vec<String>, bool) {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewal_of(&s, "wallet", &["sample-c"]);
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    let opened =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, None))
            .unwrap();
    let closed =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, Some(until)))
            .unwrap();
    s.w.clock.set_ms(until - before);
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: wallet.app_id(),
            cert: renewed.signed().clone(),
        })
        .unwrap();
    s.w.switch.deliver_identity(&opened).unwrap();
    s.w.switch.deliver_identity(&closed).unwrap();
    wallet.receive(None).await.unwrap();
    let mut tablet = s.join("tablet").await;
    tablet.list_collection(&items()).await.unwrap();
    let rules = flagged_rules(&tablet.take_events());
    let held = tablet.shared_record(&key).await.unwrap().is_some();
    (rules, held)
}

/// A write dated exactly at the earlier certificate's `until` isn't before it: the
/// certificate doesn't count for it (Switch wire 6.2 "Accepting a write" step 4).
#[tokio::test]
async fn test_records_write_dated_at_until_is_flagged() {
    let (rules, held) = rules_for_a_write_before_until(0).await;
    assert!(
        rules.iter().any(|rule| rule.contains("step 4")),
        "{rules:?}"
    );
    assert!(!held);
}

/// A write dated a millisecond before the earlier certificate's `until` counts under it
/// (Switch wire 6.2 "Accepting a write" step 4).
#[tokio::test]
async fn test_records_write_dated_just_before_until_is_taken() {
    let (rules, held) = rules_for_a_write_before_until(1).await;
    assert!(rules.is_empty(), "{rules:?}");
    assert!(held);
}

// -------------------------------------------------------------------------------------
// Claims

const CLAIM: [u8; 32] = [5; 32];
const ATTEMPT: [u8; 16] = [6; 16];

#[tokio::test]
async fn test_claims_attempt_then_done_keeps_the_settled_proof() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let deadline = START + DAY_MS;
    let written = app
        .write_claim(
            ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, Some(deadline)),
            vec![],
            ObligationDeadline::At(deadline),
        )
        .await
        .unwrap();
    assert_eq!(written.view.status, ClaimStatus::Attempting);
    assert_eq!(written.view.owner, Some(app.app_id()));
    let condition = app.claim_condition(&CLAIM).await.unwrap();
    let done = app
        .write_claim(
            ClaimOp::done(CLAIM, 1, ATTEMPT, Basis::Owner, None).unwrap(),
            vec![condition],
            ObligationDeadline::At(deadline),
        )
        .await
        .unwrap();
    assert_eq!(done.view.status, ClaimStatus::Settled);
    let evidence = app.claim_evidence(&CLAIM).await.unwrap().unwrap();
    assert_eq!(evidence.settled_proof.as_ref(), Some(done.proof.signed()));
    assert_eq!(evidence.keep_until_ms, Some(deadline + RECONCILIATION_MS));
    // A second attempt on a settled claim is refused, with the claim.
    let error = app
        .write_claim(
            ClaimOp::attempt(CLAIM, 2, [7; 16], 3600, Some(deadline)),
            vec![],
            ObligationDeadline::At(deadline),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    assert_eq!(claim_conflict(&error).unwrap().status, ClaimStatus::Settled);
}

async fn settled(s: &Setup) -> (App, u64) {
    let mut app = s.join("wallet").await;
    let deadline = START + DAY_MS;
    app.write_claim(
        ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, Some(deadline)),
        vec![],
        ObligationDeadline::At(deadline),
    )
    .await
    .unwrap();
    app.write_claim(
        ClaimOp::done(CLAIM, 1, ATTEMPT, Basis::Owner, None).unwrap(),
        vec![],
        ObligationDeadline::At(deadline),
    )
    .await
    .unwrap();
    (app, deadline)
}

#[tokio::test]
async fn test_claims_and_records_hand_over_their_evidence() {
    let s = Setup::new();
    let (mut app, deadline) = settled(&s).await;
    app.put_record(&s.target("n1"), &value(&["a"]), vec![])
        .await
        .unwrap();
    let evidence = app.shared_evidence().await.unwrap();
    // The record write and the two claim entries, each with its certificate and proof, and
    // the SETTLED proof.
    assert_eq!(evidence.ops.len(), 3);
    assert!(
        evidence
            .ops
            .iter()
            .all(|op| op.proof.is_some() && op.cert == *app.cert().signed())
    );
    assert_eq!(evidence.proofs.len(), 1);
    // Once the window ends, the claim's evidence goes, and only the record's stays.
    s.w.clock.set_ms(deadline + RECONCILIATION_MS + HOUR);
    assert!(app.read_claim(&CLAIM).await.unwrap().is_none());
    app.prune_claim_evidence().await.unwrap();
    let evidence = app.shared_evidence().await.unwrap();
    assert_eq!(evidence.ops.len(), 1);
    assert!(evidence.proofs.is_empty());
}

#[tokio::test]
async fn test_shared_evidence_goes_into_the_uploads() {
    let s = Setup::new();
    let (mut app, _) = settled(&s).await;
    app.put_record(&s.target("n1"), &value(&["a"]), vec![])
        .await
        .unwrap();
    // A move's or a loss's uploads carry the shared state's proofs with the evidence kept
    // on its own (Switch spec 12.5 step 3, 12.6 step 3).
    let shared = app.shared_evidence().await.unwrap();
    let proofs = app.kept_proofs(None).await.unwrap();
    for proof in shared
        .proofs
        .iter()
        .chain(shared.ops.iter().filter_map(|op| op.proof.as_ref()))
    {
        assert!(proofs.contains(proof));
    }
    // Each proof once: the SETTLED proof is the `done` entry's own.
    for (i, proof) in proofs.iter().enumerate() {
        assert!(!proofs[i + 1..].contains(proof), "a proof twice");
    }
    assert_eq!(proofs.len(), 3);
}

#[tokio::test]
async fn test_claims_tombstone_kept_until_its_window_ends() {
    let s = Setup::new();
    let (mut app, deadline) = settled(&s).await;
    // Inside the window: the switch shows the tombstone, and the evidence stays.
    s.w.clock.set_ms(deadline + 10 * DAY_MS);
    let read = app.read_claim(&CLAIM).await.unwrap().unwrap();
    assert!(read.view.tombstone);
    assert!(read.entries.is_empty());
    assert_eq!(app.prune_claim_evidence().await.unwrap(), 0);
    assert!(app.claim_evidence(&CLAIM).await.unwrap().is_some());
    // Past it: the switch deleted it honestly, and the evidence goes.
    s.w.clock.set_ms(deadline + RECONCILIATION_MS + HOUR);
    assert!(app.read_claim(&CLAIM).await.unwrap().is_none());
    assert!(app.alarm().is_none());
    assert_eq!(app.prune_claim_evidence().await.unwrap(), 1);
    assert!(app.claim_evidence(&CLAIM).await.unwrap().is_none());
}

#[tokio::test]
async fn test_claims_missing_before_its_window_is_a_rollback() {
    let s = Setup::new();
    let (mut app, deadline) = settled(&s).await;
    s.w.clock.set_ms(deadline + DAY_MS);
    s.w.switch.lock().shared.claims.remove(&CLAIM);
    let error = app.read_claim(&CLAIM).await.unwrap_err();
    assert!(
        matches!(error, AppError::Alarm(Alarm::Rollback { .. })),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_claims_seen_in_the_feed_and_orphaned_is_doubtful() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    phone
        .write_claim(
            ClaimOp::attempt(CLAIM, 0, ATTEMPT, 60, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap();
    let report = wallet.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::ClaimChanged { claim_key } if *claim_key == CLAIM)),
        "{:?}",
        report.events
    );
    let doubt = wallet.claim_doubt(&CLAIM).await.unwrap().unwrap();
    assert!(!doubt.doubtful(), "{doubt:?}");
    s.w.clock.advance_ms(120_000);
    wallet.receive(None).await.unwrap();
    let doubt = wallet.claim_doubt(&CLAIM).await.unwrap().unwrap();
    assert_eq!(doubt.orphaned, vec![ATTEMPT]);
    assert_eq!(wallet.doubtful_claims().await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_claims_attempt_refused_in_reconcile_mode() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let backup = app.backup().await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        s.env_on(store as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    let error = restored
        .write_claim(
            ClaimOp::attempt(CLAIM, 0, ATTEMPT, 60, None),
            vec![],
            ObligationDeadline::NotKnown,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::Refused(_)), "{error:?}");
    // Outcomes aren't attempts.
    app.write_claim(
        ClaimOp::attempt(CLAIM, 0, ATTEMPT, 60, None),
        vec![],
        ObligationDeadline::NotKnown,
    )
    .await
    .unwrap();
}

// -------------------------------------------------------------------------------------
// Batches

#[tokio::test]
async fn test_batch_carries_the_deferred_cursor_move() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let me = app.app_id();
    // A note whose body fails check 10: dropped, the cursor move deferred.
    let (seq, _) =
        s.w.switch
            .send(
                &s.w.bob,
                &s.w.bob_keys,
                &s.w.bob_cert,
                "sample.note",
                json!({ "nothing": 1 }),
                &[me],
            )
            .unwrap();
    app.receive(None).await.unwrap();
    assert!(app.cursor().seq >= seq);
    assert!(s.w.switch.app(&me).cursor < seq);
    app.submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
        .await
        .unwrap();
    assert!(s.w.switch.app(&me).cursor >= seq);
}

#[tokio::test]
async fn test_batch_sent_again_never_takes_the_service_cursor_back() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let me = app.app_id();
    let dropped = |s: &Setup| {
        s.w.switch
            .send(
                &s.w.bob,
                &s.w.bob_keys,
                &s.w.bob_cert,
                "sample.note",
                json!({ "nothing": 1 }),
                &[me],
            )
            .unwrap()
    };
    // A dropped note defers the cursor move; the next batch carries it, but the service
    // is unavailable, so the batch is kept with that cursor move.
    let (first, _) = dropped(&s);
    app.receive(None).await.unwrap();
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    assert!(
        app.submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
            .await
            .is_err()
    );
    // The cursor moves on past a later note, on its own.
    let (second, _) = dropped(&s);
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    assert!(s.w.switch.app(&me).cursor >= second && second > first);
    // The kept batch goes again with its signed operations, but not its stale cursor move.
    app.submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [8; 32] }))
        .await
        .unwrap();
    assert!(s.w.switch.app(&me).cursor >= second);
}

#[tokio::test]
async fn test_batch_of_eight_has_no_room_for_the_cursor_and_nine_is_refused() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let me = app.app_id();
    let (seq, _) =
        s.w.switch
            .send(
                &s.w.bob,
                &s.w.bob_keys,
                &s.w.bob_cert,
                "sample.note",
                json!({ "nothing": 1 }),
                &[me],
            )
            .unwrap();
    app.receive(None).await.unwrap();
    let mut eight = OpBatch::new();
    for n in 0..8u8 {
        eight = eight.op(OpKind::DenyPut { pubky: [n; 32] });
    }
    app.submit_batch(eight.clone()).await.unwrap();
    assert!(s.w.switch.app(&me).cursor < seq);
    let nine = eight.op(OpKind::DenyPut { pubky: [9; 32] });
    let error = app.submit_batch(nine).await.unwrap_err();
    assert!(matches!(error, AppError::Refused(Refusal::Usage(_))));
}

/// Join, write a record, attempt a claim and settle it; what is done is read from the
/// app's state, so a restart goes on from there.
async fn shared_scenario(
    s: &Setup,
    store: Arc<dyn StateStore>,
    approval: &mut Option<JoinRequest>,
) -> Result<(), AppError> {
    let keys = app_keys("wallet");
    let env = s.env_on(Arc::clone(&store));
    let mut app = match App::load(
        env.clone(),
        s.protocol.clone(),
        World::config(),
        keys.app_id_bytes(),
    )
    .await
    {
        Ok(app) => app,
        Err(AppError::Refused(Refusal::NotJoined)) => {
            let request = approval
                .get_or_insert_with(|| s.approve(&keys, &ALL_PERMISSIONS))
                .clone();
            App::join(env, s.protocol.clone(), World::config(), request).await?
        }
        Err(error) => return Err(error),
    };
    app.receive(None).await?;
    app.flush_outbox().await?;
    let target = s.target("n1");
    let key = app.record_key(&target)?;
    if app.shared_record(&key).await?.is_none() {
        app.put_record(&target, &value(&["a"]), vec![]).await?;
    }
    let view = app.claim_evidence(&CLAIM).await?.map(|e| e.view);
    if view.is_none() {
        app.write_claim(
            ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await?;
    }
    let view = app.claim_evidence(&CLAIM).await?.map(|e| e.view);
    if view.is_some_and(|v| v.status != ClaimStatus::Settled) {
        app.write_claim(
            ClaimOp::done(CLAIM, 1, ATTEMPT, Basis::Owner, None)?,
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn test_records_and_claims_crash_at_each_commit_point_apply_once() {
    let commits = {
        let s = Setup::new();
        let counting = Arc::new(FaultStore::new(
            Arc::new(MemoryStore::new()) as Arc<dyn StateStore>,
            StoreFault::None,
        ));
        shared_scenario(&s, Arc::clone(&counting) as Arc<dyn StateStore>, &mut None)
            .await
            .unwrap();
        counting.commits()
    };
    for stop_after in [false, true] {
        for n in 1..=commits {
            let s = Setup::new();
            let inner = Arc::new(MemoryStore::new());
            let fault = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let mut approval = None;
            let first =
                shared_scenario(&s, Arc::clone(&fault) as Arc<dyn StateStore>, &mut approval).await;
            assert!(fault.stopped() && first.is_err(), "commit {n} of {commits}");
            shared_scenario(&s, Arc::clone(&inner) as Arc<dyn StateStore>, &mut approval)
                .await
                .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            let applied = s.w.switch.applied();
            let puts = applied
                .iter()
                .filter(|op| matches!(op.body().kind, OpKind::RecordPut(_)))
                .count();
            let entries = applied
                .iter()
                .filter(|op| matches!(op.body().kind, OpKind::Claim(_)))
                .count();
            assert_eq!(puts, 1, "commit {n} ({stop_after})");
            assert_eq!(entries, 2, "commit {n} ({stop_after})");
            assert!(
                s.w.switch.claim(&CLAIM).is_some_and(|c| c.settled),
                "commit {n} ({stop_after})"
            );
        }
    }
}

// -------------------------------------------------------------------------------------
// Kept batches, acceptance, peers, directories and listings

fn denied(s: &Setup, pubky: [u8; 32]) -> usize {
    s.w.switch
        .applied()
        .iter()
        .filter(|op| matches!(op.body().kind, OpKind::DenyPut { pubky: p } if p == pubky))
        .count()
}

/// Whether `events` holds [`AppEvent::KeptBatchesWaiting`] for `kept` batches and `code`.
fn kept_waiting(events: &[AppEvent], kept: u64, code: Option<ErrorCode>) -> bool {
    let code = code.map(|code| code.as_str().to_owned());
    events.iter().any(|event| {
        matches!(event, AppEvent::KeptBatchesWaiting { kept: k, code: c } if *k == kept && *c == code)
    })
}

/// Keep a batch whose answer was lost: the switch applied it.
async fn keep_lost_batch(s: &Setup, app: &mut App, pubky: [u8; 32]) {
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let error = app
        .submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky }))
        .await
        .unwrap_err();
    assert!(error.kept_batch().is_some(), "{error:?}");
}

#[tokio::test]
async fn test_receive_waits_out_the_retry_after_of_a_kept_batch() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    keep_lost_batch(&s, &mut app, [9; 32]).await;
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::RateLimited,
        current: json!(null),
    });
    let report = app.receive(None).await.unwrap();
    let limited = Some(ErrorCode::RateLimited);
    assert!(
        kept_waiting(&report.events, 1, limited),
        "{:?}",
        report.events
    );
    // Inside the `retry_after`: the read sends nothing again, and says why.
    let retry_ms = crate::testing::SCRIPTED_RETRY_AFTER_S * 1000;
    s.w.clock.advance_ms(retry_ms - 1_000);
    let report = app.receive(None).await.unwrap();
    assert!(
        kept_waiting(&report.events, 1, limited),
        "{:?}",
        report.events
    );
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
    // Once it passed, the next read sends it, and its original proof settles it.
    s.w.clock.advance_ms(1_000);
    let report = app.receive(None).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert!(
        !report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::KeptBatchesWaiting { .. })),
        "{:?}",
        report.events
    );
    assert_eq!(denied(&s, [9; 32]), 1);
}

/// A refusal about the caller, such as `403 cert_expired`, comes when a request is
/// authenticated, so every request of the read is refused, the kept batch's resend and the
/// feed alike: the read fails, and the batch stays kept until the app's requests are
/// accepted again.
#[tokio::test]
async fn test_receive_refused_about_the_caller_fails_and_keeps_the_batch() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    keep_lost_batch(&s, &mut app, [9; 32]).await;
    for _ in 0..8 {
        s.w.switch.fail_next(Fault::Error {
            path: "/v1/".into(),
            code: ErrorCode::CertExpired,
            current: json!({}),
        });
    }
    let error = app.receive(None).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::CertExpired), "{error:?}");
    s.w.switch.lock().faults.clear();
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
    let report = app.receive(None).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert!(
        !report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::KeptBatchesWaiting { .. })),
        "{:?}",
        report.events
    );
}

/// A kept batch whose record doesn't read fails every read, as it fails every write:
/// corruption doesn't pass silently.
#[tokio::test]
async fn test_receive_with_a_kept_batch_that_doesnt_read_fails() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let mut tx = app.tx().unwrap();
    let id = pubky_switch_core::enc::b64(&[7; 16]);
    tx.put(&format!("opq/{id}"), &json!("not a batch")).unwrap();
    app.commit(tx).await.unwrap();
    for _ in 0..2 {
        let error = app.receive(None).await.unwrap_err();
        assert!(
            matches!(error, AppError::Store(crate::error::StoreError::Corrupt)),
            "{error:?}"
        );
    }
    let error = app
        .submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Store(crate::error::StoreError::Corrupt)),
        "{error:?}"
    );
}

/// A read whose kept batch can't be sent goes on to its feed; when the feed fails too, the
/// read fails, and the wait it met is in no later read's report.
#[tokio::test]
async fn test_receive_that_fails_reports_its_kept_batch_waiting_in_no_later_read() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    keep_lost_batch(&s, &mut app, [9; 32]).await;
    s.w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    // The kept batch's send first takes a fresh service time, a feed read of one item,
    // which passes; the read's page then fails.
    s.w.switch.fail_next(Fault::Unreachable {
        path: "feed".into(),
        after: 1,
    });
    assert!(app.receive(None).await.is_err());
    s.w.switch.lock().faults.clear();
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
    // The next read settles the batch: nothing waits.
    let report = app.receive(None).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert!(
        !report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::KeptBatchesWaiting { .. })),
        "{:?}",
        report.events
    );
}

/// Every way a write's own batch fails once it is kept, at the service time read before its
/// first send or at its send: the error says [`AppError::Kept`] exactly when the batch is
/// still kept, and the batch is kept or dropped as each answer tells (Switch wire 6.4).
#[tokio::test]
async fn test_batch_error_says_kept_exactly_when_the_batch_stays() {
    let error_at = |path: &str, code: ErrorCode| Fault::Error {
        path: path.into(),
        code,
        current: json!(null),
    };
    let unreachable = |path: &str| Fault::Unreachable {
        path: path.into(),
        after: 0,
    };
    let cases = [
        // The service time read before the first send: never sent, so kept.
        (
            "time read 403 cert_expired",
            error_at("feed", ErrorCode::CertExpired),
            true,
        ),
        (
            "time read 401 bad_signature",
            error_at("feed", ErrorCode::BadSignature),
            true,
        ),
        (
            "time read 403 not_current",
            error_at("feed", ErrorCode::NotCurrent),
            true,
        ),
        (
            "time read 429",
            error_at("feed", ErrorCode::RateLimited),
            true,
        ),
        (
            "time read 503",
            error_at("feed", ErrorCode::Unavailable),
            true,
        ),
        ("time read network", unreachable("feed"), true),
        // The send, refused at authentication: never applied, dropped.
        (
            "401 bad_signature",
            error_at("ops", ErrorCode::BadSignature),
            false,
        ),
        (
            "403 cert_expired",
            error_at("ops", ErrorCode::CertExpired),
            false,
        ),
        (
            "403 not_current",
            error_at("ops", ErrorCode::NotCurrent),
            false,
        ),
        // Refused for good at or after the lookup: dropped.
        ("409 conflict", error_at("ops", ErrorCode::Conflict), false),
        ("400", error_at("ops", ErrorCode::BadRequest), false),
        // Anything that may pass with the same bytes later: kept.
        (
            "401 stale_timestamp",
            error_at("ops", ErrorCode::StaleTimestamp),
            true,
        ),
        (
            "409 identity_needed",
            error_at("ops", ErrorCode::IdentityNeeded),
            true,
        ),
        ("410 moved", error_at("ops", ErrorCode::Moved), true),
        ("429", error_at("ops", ErrorCode::RateLimited), true),
        ("503", error_at("ops", ErrorCode::Unavailable), true),
        ("503 staged", error_at("ops", ErrorCode::Staged), true),
        ("network", unreachable("ops"), true),
        (
            "answer lost",
            Fault::LoseAnswer { path: "ops".into() },
            true,
        ),
        (
            "answer that doesn't read",
            Fault::LeaveOut {
                path: "ops".into(),
                member: "proofs".into(),
            },
            true,
        ),
    ];
    for (name, fault, stays) in cases {
        let s = Setup::new();
        let mut app = s.join("wallet").await;
        // A first send reads the service time only when the one held is over a day old.
        if name.starts_with("time read") {
            s.w.clock
                .advance_ms(crate::app::provider::RECENT_SERVICE_TIME_MS + 1);
        }
        s.w.switch.fail_next(fault);
        let error = app
            .submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
            .await
            .unwrap_err();
        let kept = app.kept_batches().await.unwrap();
        assert_eq!(kept.len(), usize::from(stays), "{name}: {error:?}");
        assert_eq!(
            error.kept_batch(),
            kept.first().map(|(id, _)| *id),
            "{name}: {error:?}"
        );
    }
}

/// An alarm raised once the write's own batch is kept, here by a service time that goes
/// back (Switch spec 10.1): the app stops, the batch stays kept, and the error says so
/// with the alarm inside.
#[tokio::test]
async fn test_batch_kept_when_an_alarm_stops_the_write_says_so() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    s.w.clock.set_ms(s.w.clock.now_ms() - 60_000);
    let error = app
        .submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
        .await
        .unwrap_err();
    assert!(matches!(error.unkept(), AppError::Alarm(_)), "{error:?}");
    let kept = app.kept_batches().await.unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(error.kept_batch(), Some(kept[0].0), "{error:?}");
}

/// The conversation entry a send owes goes in a kept batch of its own; an alarm that stops
/// it is the app's own failure, kept batch or not, and fails the send rather than queueing
/// the message for another try.
#[tokio::test]
async fn test_send_stopped_by_an_alarm_in_its_kept_conversation_entry_fails() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    s.w.clock.set_ms(s.w.clock.now_ms() - 60_000);
    let error = app.send(s.note("one")).await.unwrap_err();
    assert!(matches!(error.unkept(), AppError::Alarm(_)), "{error:?}");
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_batch_kept_on_a_retryable_refusal_and_sent_again() {
    for code in [
        ErrorCode::Unavailable,
        ErrorCode::RateLimited,
        ErrorCode::StaleTimestamp,
    ] {
        let s = Setup::new();
        let mut app = s.join("wallet").await;
        s.w.switch.fail_next(Fault::Error {
            path: "ops".into(),
            code,
            current: json!(null),
        });
        let error = app
            .submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(code));
        assert_eq!(denied(&s, [9; 32]), 0);
        // The next write sends the kept batch first, the same bytes, then its own.
        app.submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [8; 32] }))
            .await
            .unwrap();
        assert_eq!(denied(&s, [9; 32]), 1, "{code}");
        assert_eq!(denied(&s, [8; 32]), 1, "{code}");
        let events = app.take_events();
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, AppEvent::BatchRefused { .. })),
            "{code}: {events:?}"
        );
    }
}

#[tokio::test]
async fn test_batch_kept_and_refused_for_good_later_is_reported() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    assert!(
        app.submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
            .await
            .is_err()
    );
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::PermissionMissing,
        current: json!(null),
    });
    app.submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [8; 32] }))
        .await
        .unwrap();
    let events = app.take_events();
    assert!(
        events.iter().any(
            |e| matches!(e, AppEvent::BatchRefused { code, .. } if code == "permission_missing")
        ),
        "{events:?}"
    );
    assert_eq!(denied(&s, [9; 32]), 0);
    assert_eq!(denied(&s, [8; 32]), 1);
    // Dropped: not sent again.
    app.flush_outbox().await.unwrap();
    assert_eq!(denied(&s, [9; 32]), 0);
    // A duty event: a load delivers it again until it is acknowledged.
    let mut loaded = App::load(s.env(), s.protocol.clone(), World::config(), app.app_id())
        .await
        .unwrap();
    let again = loaded.take_events();
    assert!(
        again.iter().any(|e| e.is_duty()
            && matches!(e, AppEvent::BatchRefused { code, .. } if code == "permission_missing")),
        "{again:?}"
    );
}

#[tokio::test]
async fn test_batch_refused_for_good_is_the_callers_error_and_not_kept() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::PermissionMissing,
        current: json!(null),
    });
    let error = app
        .submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::PermissionMissing));
    app.flush_outbox().await.unwrap();
    assert_eq!(denied(&s, [9; 32]), 0);
}

#[tokio::test]
async fn test_claims_attempt_answer_lost_is_checked_when_sent_again() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(
        app.write_claim(
            ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .is_err()
    );
    // The next write sends it again; its proof gets the attempt's checks and is kept.
    app.submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
        .await
        .unwrap();
    let events = app.take_events();
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, AppEvent::AttemptNotHeld { .. })),
        "{events:?}"
    );
    let evidence = app.claim_evidence(&CLAIM).await.unwrap().unwrap();
    assert_eq!(evidence.view.status, ClaimStatus::Attempting);
    assert_eq!(evidence.view.owner, Some(app.app_id()));
}

fn claim_changes(events: &[AppEvent]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, AppEvent::ClaimChanged { claim_key } if *claim_key == CLAIM))
        .count()
}

#[tokio::test]
async fn test_claims_entry_met_again_raises_one_change() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(
        app.write_claim(
            ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .is_err()
    );
    // The read sends the kept attempt again, whose proof the app keeps, then meets the
    // same entry in its feed: one change.
    let report = app.receive(None).await.unwrap();
    assert_eq!(claim_changes(&report.events), 1, "{:?}", report.events);
    let evidence = app.claim_evidence(&CLAIM).await.unwrap().unwrap();
    assert_eq!(evidence.view.status, ClaimStatus::Attempting);
    // Its own next entry changes the claim again.
    let done = app
        .write_claim(
            ClaimOp::done(CLAIM, 1, ATTEMPT, Basis::Owner, None).unwrap(),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap();
    assert_eq!(done.view.status, ClaimStatus::Settled);
    assert_eq!(claim_changes(&app.take_events()), 1);
}

/// The claim reads (`GET /claims`) in the router's log from `from` on.
fn claim_reads(s: &Setup, from: usize) -> usize {
    s.log()[from..]
        .iter()
        .filter(|line| line.starts_with("GET ") && line.contains("/claims/"))
        .count()
}

async fn attempt_as(app: &mut App, claim: [u8; 32], step: u64, attempt: [u8; 16]) {
    app.write_claim(
        ClaimOp::attempt(claim, step, attempt, 3600, None),
        vec![],
        ObligationDeadline::NoDeadline,
    )
    .await
    .unwrap();
}

async fn report_as(app: &mut App, claim: [u8; 32], step: u64, attempt: [u8; 16], done: bool) {
    let op = if done {
        ClaimOp::done(claim, step, attempt, Basis::Owner, None).unwrap()
    } else {
        ClaimOp::failed(claim, step, attempt)
    };
    app.write_claim(op, vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_claims_compacted_entry_has_the_claim_read_again() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    attempt_as(&mut wallet, CLAIM, 0, ATTEMPT).await;
    phone.receive(None).await.unwrap();
    let held = phone.claim_evidence(&CLAIM).await.unwrap().unwrap();
    assert_eq!(held.view.status, ClaimStatus::Attempting);
    // The done settles the claim, which is compacted at once: the phone's feed shows both
    // entries as stubs, naming no claim, so it reads the claim again at the end of its read.
    report_as(&mut wallet, CLAIM, 1, ATTEMPT, true).await;
    let from = s.log().len();
    let report = phone.receive(None).await.unwrap();
    assert_eq!(claim_reads(&s, from), 1);
    let feed = s.log()[from..]
        .iter()
        .rposition(|line| line.contains("/feed"))
        .unwrap();
    let read = s.log()[from..]
        .iter()
        .position(|line| line.contains("/claims/"))
        .unwrap();
    assert!(read > feed, "the claim is read after the feed");
    assert_eq!(claim_changes(&report.events), 1, "{:?}", report.events);
    let held = phone.claim_evidence(&CLAIM).await.unwrap().unwrap();
    assert_eq!(held.view.status, ClaimStatus::Settled);
    assert!(held.view.tombstone);
    // Held as finished now: later stubs don't have it read again.
    let other = [0x41; 32];
    attempt_as(&mut wallet, other, 0, ATTEMPT).await;
    report_as(&mut wallet, other, 1, ATTEMPT, false).await;
    let from = s.log().len();
    let report = phone.receive(None).await.unwrap();
    assert_eq!(claim_reads(&s, from), 0, "{:?}", &s.log()[from..]);
    assert_eq!(claim_changes(&report.events), 0);
}

#[tokio::test]
async fn test_claims_settled_with_an_attempt_open_is_still_read_again() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    // The first attempt fails; a second is opened; late evidence settles the first, so the
    // claim is SETTLED with the second attempt still open, and stays live.
    attempt_as(&mut wallet, CLAIM, 0, ATTEMPT).await;
    report_as(&mut wallet, CLAIM, 1, ATTEMPT, false).await;
    attempt_as(&mut wallet, CLAIM, 2, [7; 16]).await;
    wallet
        .write_claim(
            ClaimOp::done(CLAIM, 3, ATTEMPT, Basis::Evidence, Some([8; 32])).unwrap(),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let held = phone.claim_evidence(&CLAIM).await.unwrap().unwrap();
    assert_eq!(held.view.status, ClaimStatus::Settled);
    assert!(!held.view.tombstone);
    // The open attempt's outcome compacts the claim: it comes as a stub, and the phone,
    // which holds the claim SETTLED but not finished, reads it again.
    report_as(&mut wallet, CLAIM, 4, [7; 16], false).await;
    let from = s.log().len();
    phone.receive(None).await.unwrap();
    assert_eq!(claim_reads(&s, from), 1);
    let held = phone.claim_evidence(&CLAIM).await.unwrap().unwrap();
    assert!(held.view.tombstone);
    assert_eq!(held.view.step, 5);
}

#[tokio::test]
async fn test_claims_own_compacted_entries_of_a_finished_claim_read_nothing() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    attempt_as(&mut wallet, CLAIM, 0, ATTEMPT).await;
    report_as(&mut wallet, CLAIM, 1, ATTEMPT, true).await;
    // The wallet holds the claim finished from its own proofs; its own entries, compacted,
    // come as stubs in its feed and have nothing read.
    let from = s.log().len();
    wallet.receive(None).await.unwrap();
    assert_eq!(claim_reads(&s, from), 0, "{:?}", &s.log()[from..]);
}

#[tokio::test]
async fn test_claims_read_again_at_most_a_bound_per_read() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let claims: Vec<[u8; 32]> = (0..=crate::app::CLAIM_REREADS_PER_READ)
        .map(|n| [u8::try_from(n).unwrap() + 0x50; 32])
        .collect();
    for claim in &claims {
        attempt_as(&mut wallet, *claim, 0, ATTEMPT).await;
    }
    phone.receive(None).await.unwrap();
    // One claim's done compacts it: every claim the phone follows is marked, and one read
    // reads the bound of them; the rest wait for the next read, which sees no new stub.
    report_as(&mut wallet, claims[0], 1, ATTEMPT, true).await;
    let from = s.log().len();
    phone.receive(None).await.unwrap();
    assert_eq!(claim_reads(&s, from), crate::app::CLAIM_REREADS_PER_READ);
    let from = s.log().len();
    phone.receive(None).await.unwrap();
    assert_eq!(claim_reads(&s, from), 1);
    let from = s.log().len();
    phone.receive(None).await.unwrap();
    assert_eq!(claim_reads(&s, from), 0);
    let held = phone.claim_evidence(&claims[0]).await.unwrap().unwrap();
    assert!(held.view.tombstone);
}

#[tokio::test]
async fn test_claims_read_again_that_fails_stays_marked() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    attempt_as(&mut wallet, CLAIM, 0, ATTEMPT).await;
    phone.receive(None).await.unwrap();
    report_as(&mut wallet, CLAIM, 1, ATTEMPT, true).await;
    // The claim's read doesn't reach the switch: the feed's read still succeeds, and the
    // claim stays marked.
    s.w.switch.fail_next(Fault::Unreachable {
        path: "claims".into(),
        after: 0,
    });
    let report = phone.receive(None).await.unwrap();
    assert_eq!(claim_changes(&report.events), 0);
    let held = phone.claim_evidence(&CLAIM).await.unwrap().unwrap();
    assert_eq!(held.view.status, ClaimStatus::Attempting);
    // Loaded again, as after a crash: the mark was kept, and the next read reads the claim,
    // though its feed shows nothing new.
    let me = phone.app_id();
    drop(phone);
    let mut phone = App::load(s.env(), s.protocol.clone(), World::config(), me)
        .await
        .unwrap();
    let from = s.log().len();
    let report = phone.receive(None).await.unwrap();
    assert_eq!(claim_reads(&s, from), 1);
    assert_eq!(claim_changes(&report.events), 1);
    let held = phone.claim_evidence(&CLAIM).await.unwrap().unwrap();
    assert_eq!(held.view.status, ClaimStatus::Settled);
}

#[tokio::test]
async fn test_claims_app_without_claims_read_reads_nothing_again() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut writer = s
        .join_with("phone", &[Permission::ClaimsWrite, Permission::ListsRead])
        .await;
    attempt_as(&mut writer, CLAIM, 0, ATTEMPT).await;
    attempt_as(&mut wallet, [0x42; 32], 0, ATTEMPT).await;
    // Every claim item is a stub to it, and it holds its own claim open, but it can't read
    // claims: nothing is read.
    let from = s.log().len();
    writer.receive(None).await.unwrap();
    assert_eq!(claim_reads(&s, from), 0, "{:?}", &s.log()[from..]);
}

/// Write `op` with its answer lost: the switch took it, and the batch is kept.
async fn lost(s: &Setup, app: &mut App, op: ClaimOp) {
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let error = app
        .write_claim(op, vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap_err();
    assert!(error.kept_batch().is_some(), "{error:?}");
}

/// An `attempt` kept and never sent, its service time unverifiable when it was written, and
/// reconcile mode begun before it goes: the read that sends it again first can't verify a
/// time either, and its feed shows the continuity unverified (Switch spec 8.3). No new
/// attempt is made in reconcile mode (Switch spec 12.4): the batch, never applied, is
/// dropped, and the protocol told of it and its attempt.
#[tokio::test]
async fn test_claims_unsent_kept_attempt_isnt_sent_in_reconcile_mode() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    app.receive(None).await.unwrap();
    s.w.switch.fail_next(Fault::Unreachable {
        path: "feed".into(),
        after: 0,
    });
    s.w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let error = app
        .write_claim(
            ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap_err();
    s.w.switch.lock().faults.clear();
    let kept = error.kept_batch().unwrap();
    assert_eq!(app.kept_batches().await.unwrap()[0].1.kept_ms, None);
    // A month later the service checkpointed past the app's position and dropped the
    // stubs behind it.
    s.w.clock.advance_ms(31 * DAY_MS);
    phone
        .submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
        .await
        .unwrap();
    {
        let mut inner = s.w.switch.lock();
        inner.checkpoint = Some(pubky_switch_core::chain::SignedHead::sign(
            &inner.service,
            &inner.identity.public(),
            &inner.tip,
        ));
        inner.dropped_through = inner.seq;
    }
    s.w.switch.fail_next(Fault::Unreachable {
        path: "feed".into(),
        after: 0,
    });
    app.receive(None).await.unwrap();
    assert!(app.reconcile_mode());
    assert_eq!(app.kept_batches().await.unwrap()[0].0, kept);
    // The next read doesn't send it.
    let report = app.receive(None).await.unwrap();
    let attempts = |s: &Setup| {
        s.w.switch
            .applied()
            .iter()
            .filter(|op| matches!(op.body().kind, OpKind::Claim(_)))
            .count()
    };
    assert_eq!(attempts(&s), 0);
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::KeptBatchDropped { batch_id, .. } if *batch_id == kept)),
        "{:?}",
        report.events
    );
    assert!(
        report.events.iter().any(|e| matches!(
            e,
            AppEvent::AttemptDropped { attempt_id, .. } if *attempt_id == ATTEMPT
        )),
        "{:?}",
        report.events
    );
    // Never sent, so never applied: its end says so, by its ID and by its attempt.
    let dropped = Some(crate::app::KeptBatchStatus::Dropped {
        dropped_at_ms: s.w.clock.now_ms(),
        reason: crate::app::KeptBatchDrop::Unsent,
    });
    assert_eq!(app.kept_batch(kept).await.unwrap(), dropped);
    let by_attempt = app
        .kept_attempt(crate::app::ClaimAttempt {
            claim_key: CLAIM,
            attempt_id: ATTEMPT,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (Some(by_attempt.batch_id), Some(by_attempt.status)),
        (Some(kept), dropped)
    );
}

#[tokio::test]
async fn test_claims_attempt_made_again_returns_the_kept_attempt() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None);
    lost(&s, &mut app, attempt).await;
    app.take_events();
    // Made again at once: the kept batch goes first and takes the claim; this call's own
    // attempt meets `409 conflict` showing the claim held by that attempt, so the call
    // returns its outcome, with its proof.
    let written = app
        .write_claim(attempt, vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
    assert!(written.repeated);
    assert_eq!(written.attempt_id, ATTEMPT);
    assert_eq!(written.view.status, ClaimStatus::Attempting);
    assert_eq!(written.view.owner, Some(app.app_id()));
    assert_eq!(written.proof.body().step, Some(1));
    // The kept batch's settle, in this call, changed the claim the app holds.
    assert_eq!(claim_changes(&app.take_events()), 1);
    assert!(app.kept_batches().await.unwrap().is_empty());
    // Made again once more: nothing changes in that call, and nothing is raised.
    let written = app
        .write_claim(attempt, vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
    assert!(written.repeated);
    assert_eq!(claim_changes(&app.take_events()), 0);
}

#[tokio::test]
async fn test_claims_attempt_with_a_new_id_gets_the_conflict() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    lost(
        &s,
        &mut app,
        ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
    )
    .await;
    // A read settles the kept attempt; the protocol, which never saw it, attempts again
    // under a new ID: the earlier attempt isn't this one, so the conflict stands, and its
    // claim shows the app's own attempt holding the claim.
    app.receive(None).await.unwrap();
    let error = app
        .write_claim(
            ClaimOp::attempt(CLAIM, 0, [9; 16], 3600, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    let view = claim_conflict(&error).unwrap();
    assert_eq!(view.attempt_id, Some(ATTEMPT));
    assert_eq!(view.owner, Some(app.app_id()));
}

/// Two devices of one app share its keys (Switch spec 3.1 "Several devices"). Device A
/// attempts; device B, which read its feed, attempts the same claim under an ID of its own:
/// A's entry is the app's own, but not B's attempt, so B gets the conflict, and only A
/// carries its attempt out.
#[tokio::test]
async fn test_claims_second_device_attempt_under_its_own_id_gets_the_conflict() {
    let s = Setup::new();
    let mut a = s.join("wallet").await;
    a.set_multi_device(true).await.unwrap();
    let backup = a.backup().await.unwrap();
    let store_b = Arc::new(MemoryStore::new());
    let mut b = App::restore(
        s.env_on(Arc::clone(&store_b) as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    b.receive(None).await.unwrap();
    b.end_reconcile(crate::app::UserConfirmed::new())
        .await
        .unwrap();
    assert_eq!(a.app_id(), b.app_id());
    attempt_as(&mut a, CLAIM, 0, ATTEMPT).await;
    // Device B reads its feed: A's attempt is the app's own entry, kept at step 0.
    b.receive(None).await.unwrap();
    let error = b
        .write_claim(
            ClaimOp::attempt(CLAIM, 0, [9; 16], 3600, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    let view = claim_conflict(&error).unwrap();
    assert_eq!(view.attempt_id, Some(ATTEMPT), "device A's attempt");
    assert_eq!(view.owner, Some(b.app_id()));
    // The same attempt asked again is the app's own entry: repeated.
    let written = b
        .write_claim(
            ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap();
    assert!(written.repeated);
    assert_eq!(written.attempt_id, ATTEMPT);
}

/// An own attempt asked again once it is orphaned, its `orphan_after` passed, isn't held by
/// the caller any more: any app may resolve it `unknown` (Switch spec 10.2), so the conflict
/// stands.
#[tokio::test]
async fn test_claims_attempt_made_again_once_orphaned_gets_the_conflict() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 60, None);
    lost(&s, &mut app, attempt).await;
    s.w.clock.advance_ms(120_000);
    let error = app
        .write_claim(attempt, vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    let view = claim_conflict(&error).unwrap();
    assert!(view.attempt(&ATTEMPT).unwrap().orphaned, "{view:?}");
    let doubt = app.claim_doubt(&CLAIM).await.unwrap().unwrap();
    assert!(doubt.doubtful(), "{doubt:?}");
}

/// An own outcome of another attempt held at the step asked for is not this entry's
/// outcome: the conflict stands.
#[tokio::test]
async fn test_claims_own_outcome_of_another_attempt_at_the_step_gets_the_conflict() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let other = [0x0d; 16];
    attempt_as(&mut app, CLAIM, 0, ATTEMPT).await;
    report_as(&mut app, CLAIM, 1, ATTEMPT, false).await;
    attempt_as(&mut app, CLAIM, 2, other).await;
    report_as(&mut app, CLAIM, 3, other, false).await;
    // `failed` of the first attempt, asked at step 3, where the own `failed` of the second
    // is held.
    let result = app
        .write_claim(
            ClaimOp::failed(CLAIM, 3, ATTEMPT),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await;
    assert!(
        result
            .as_ref()
            .is_err_and(|e| e.code() == Some(ErrorCode::Conflict)),
        "{result:?}"
    );
}

#[tokio::test]
async fn test_claims_outcome_made_again_returns_the_kept_outcome() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    attempt_as(&mut app, CLAIM, 0, ATTEMPT).await;
    let done = ClaimOp::done(CLAIM, 1, ATTEMPT, Basis::Owner, None).unwrap();
    lost(&s, &mut app, done).await;
    app.take_events();
    let written = app
        .write_claim(done, vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
    assert!(written.repeated);
    assert_eq!(written.attempt_id, ATTEMPT);
    assert_eq!(written.view.status, ClaimStatus::Settled);
    assert_eq!(written.proof.body().step, Some(2));
    assert_eq!(claim_changes(&app.take_events()), 1);
    // A `failed` the same way.
    let other = [0x43; 32];
    attempt_as(&mut app, other, 0, ATTEMPT).await;
    let failed = ClaimOp::failed(other, 1, ATTEMPT);
    lost(&s, &mut app, failed).await;
    let written = app
        .write_claim(failed, vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
    assert!(written.repeated);
    assert_eq!(written.view.status, ClaimStatus::Free);
}

#[tokio::test]
async fn test_claims_unknown_made_again_returns_the_kept_unknown() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    wallet
        .write_claim(
            ClaimOp::attempt(CLAIM, 0, ATTEMPT, 60, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap();
    s.w.clock.advance_ms(120_000);
    let unknown = ClaimOp::unknown(CLAIM, 1, ATTEMPT);
    lost(&s, &mut phone, unknown).await;
    let written = phone
        .write_claim(unknown, vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
    assert!(written.repeated);
    assert_eq!(written.view.status, ClaimStatus::Free);
}

#[tokio::test]
async fn test_claims_repeated_entry_needs_the_conflict_to_show_it() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let me = app.app_id();
    attempt_as(&mut app, CLAIM, 0, ATTEMPT).await;
    let attempting = app.claim_evidence(&CLAIM).await.unwrap().unwrap().view;
    report_as(&mut app, CLAIM, 1, ATTEMPT, true).await;
    let settled = app.claim_evidence(&CLAIM).await.unwrap().unwrap().view;
    let conflict = |view: &ClaimView| Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!({ "claim": view.to_value() }),
    };
    // The own done is held at the step asked for, but the conflict shows the attempt still
    // open: not that done's outcome.
    let mut open = settled.clone();
    open.status = ClaimStatus::Attempting;
    open.attempts[0].outcome = pubky_switch_core::claims::Outcome::Open;
    open.attempts[0].resolved_by = None;
    s.w.switch.fail_next(conflict(&open));
    let error = app
        .write_claim(
            ClaimOp::done(CLAIM, 1, ATTEMPT, Basis::Owner, None).unwrap(),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    // The own attempt is held at the step asked for, but the conflict shows another owner.
    let mut theirs = attempting.clone();
    theirs.owner = Some([0x55; 16]);
    assert_ne!(theirs.owner, Some(me));
    s.w.switch.fail_next(conflict(&theirs));
    let error = app
        .write_claim(
            ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
}

#[tokio::test]
async fn test_claims_conflict_not_of_the_own_entry_stands() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    // Another app's attempt holds the claim: the conflict stands.
    attempt_as(&mut phone, CLAIM, 0, ATTEMPT).await;
    wallet.receive(None).await.unwrap();
    let error = wallet
        .write_claim(
            ClaimOp::attempt(CLAIM, 0, [9; 16], 3600, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    // The app's own attempt, past the step asked for: the conflict stands too.
    let other = [0x44; 32];
    attempt_as(&mut wallet, other, 0, ATTEMPT).await;
    report_as(&mut wallet, other, 1, ATTEMPT, false).await;
    let error = wallet
        .write_claim(
            ClaimOp::attempt(other, 0, [9; 16], 3600, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    // Its `failed` made again is its own outcome; a `done` where the own attempt was
    // resolved `failed` is of another type: the conflict.
    let error = wallet
        .write_claim(
            ClaimOp::failed(other, 1, ATTEMPT),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await;
    assert!(error.as_ref().is_ok_and(|w| w.repeated), "{error:?}");
    let error = wallet
        .write_claim(
            ClaimOp::done(other, 1, ATTEMPT, Basis::Owner, None).unwrap(),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
}

#[tokio::test]
async fn test_send_acceptance_committed_before_the_follow_ups() {
    // The first commit after the append is answered: stopped right after it, the restart
    // sends nothing again.
    let appends = |s: &Setup| {
        s.peer
            .lock()
            .requests
            .iter()
            .filter(|(m, r)| m == "POST" && r == "inbox")
            .count()
    };
    let mut n = 1;
    let (s, inner, approval, queued) = loop {
        let s = Setup::new();
        let inner = Arc::new(MemoryStore::new());
        let fault = Arc::new(FaultStore::new(
            Arc::clone(&inner) as Arc<dyn StateStore>,
            StoreFault::StopAfter(n),
        ));
        let mut approval = None;
        let mut queued = None;
        let first = send_scenario(
            &s,
            Arc::clone(&fault) as Arc<dyn StateStore>,
            &mut approval,
            &mut queued,
        )
        .await;
        assert!(first.is_err(), "the scenario commits more than {n} times");
        if appends(&s) > 0 {
            break (s, inner, approval, queued);
        }
        n += 1;
    };
    let mut approval = approval;
    let mut queued = queued;
    send_scenario(
        &s,
        Arc::clone(&inner) as Arc<dyn StateStore>,
        &mut approval,
        &mut queued,
    )
    .await
    .unwrap();
    assert_eq!(appends(&s), 1, "the commit after the append is {n}");
    let app = App::load(
        s.env_on(inner as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    let msg_id = queued.unwrap();
    assert!(accepted(&app.delivery(&msg_id).await.unwrap().unwrap()));
}

#[tokio::test]
async fn test_send_record_job_owed_still_finds_the_sent_message() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let (first, _) = app.send(s.note("first")).await.unwrap();
    let target = s.target("bob");
    let mut message = s.note("hello");
    message.record = Some(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    // The record write can't be made now: the record job stays owed.
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    let (msg_id, delivery) = app.send(message).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    // The protocol's answer to a re-send request finds it, and a re-send goes.
    let sent = app.sent_to(&s.w.bob.public(), 0, u64::MAX).await.unwrap();
    let ids: Vec<&str> = sent.iter().map(|m| m.msg_id.as_str()).collect();
    assert!(ids.contains(&msg_id.as_str()), "{ids:?}");
    s.peer.rotate(0).unwrap();
    let delivery = app.resend(&msg_id).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    assert_eq!(s.peer.received(), vec![first, msg_id.clone(), msg_id]);
    let report = app.flush_outbox().await.unwrap();
    assert!(report.queued.is_empty(), "{report:?}");
}

/// A counterparty whose Pubky ID sorts before bob's, so it is met first.
fn before_bob(s: &Setup) -> [u8; 32] {
    let bob = pubky_switch_core::enc::pubky_id(&s.w.bob.public());
    (0..100)
        .map(|n| IdentityKey::from_secret(seed(&format!("peer/{n}/identity"))).public())
        .find(|pubky| pubky_switch_core::enc::pubky_id(pubky) < bob)
        .unwrap()
}

#[tokio::test]
async fn test_send_unreachable_peer_doesnt_hold_up_the_others() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.send(s.note("hello")).await.unwrap();
    // A counterparty written to recently, whose switch can't be reached now.
    let other = before_bob(&s);
    let ns = crate::store::client_namespace(&app.app_id());
    let mut tx = crate::app::state::Tx::new(&ns);
    crate::app::directory::put_peer(
        &mut tx,
        &other,
        &crate::app::directory::PeerSwitch {
            known_version: Some(1),
            last_sent_ms: Some(s.w.clock.now_ms()),
        },
    )
    .unwrap();
    tx.commit(&StoreHandle::inline(
        Arc::clone(&s.w.store) as Arc<dyn StateStore>
    ))
    .await
    .unwrap();
    let doc = s.w.next_doc(|body| {
        body.removed.push(RemovedApp {
            app_id: [9; 16],
            distrust_from: START,
        })
    });
    assert!(matches!(
        app.refresh_identity().await.unwrap(),
        crate::app::IdentityRefresh::Newer { .. }
    ));
    app.flush_outbox().await.unwrap();
    assert_eq!(
        s.peer.lock().peers[&s.w.alice.public()].version(),
        doc.version()
    );
    // Only the switch still owed is tried again.
    s.peer.lock().requests.clear();
    app.flush_outbox().await.unwrap();
    assert!(s.peer.routes().is_empty(), "{:?}", s.peer.routes());
}

/// A switch that takes `ms` of the app's clock for each request and then fails to connect,
/// as a slow switch that is down.
struct SlowDown {
    clock: Arc<crate::clock::TestClock>,
    ms: u64,
}

impl Transport for SlowDown {
    fn send(
        &self,
        _: crate::transport::Request,
    ) -> crate::transport::BoxFuture<
        '_,
        Result<crate::transport::Response, crate::error::TransportError>,
    > {
        Box::pin(async move {
            self.clock.advance_ms(self.ms);
            Err(crate::error::TransportError::Connect("down".into()))
        })
    }
}

/// A slow switch that keeps failing, met first among those owed an app's removal, uses each
/// flush's budget: the healthy switch behind it still gets the removal within two flushes.
#[tokio::test]
async fn test_send_slow_failing_peer_doesnt_starve_the_others() {
    const SLOW: &str = "https://slow.example";
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.send(s.note("hello")).await.unwrap();
    let bob = pubky_switch_core::enc::pubky_id(&s.w.bob.public());
    let slow_key = (0..100)
        .map(|n| identity(&format!("peer{n}")))
        .find(|key| pubky_switch_core::enc::pubky_id(&key.public()) < bob)
        .unwrap();
    let slow = slow_key.public();
    // Its identity.json is published, naming the slow switch.
    let published = PeerSwitch::new(
        slow_key,
        SLOW,
        Arc::clone(&s.w.clock),
        Arc::clone(&s.w.homeserver),
    );
    published
        .add_app(
            "shop",
            &AppSpec::new(&["sample-a"]),
            &["sample.note"],
            false,
        )
        .unwrap();
    s.router.add(
        SLOW,
        Arc::new(SlowDown {
            clock: Arc::clone(&s.w.clock),
            ms: 25_000,
        }) as Arc<dyn Transport>,
    );
    let ns = crate::store::client_namespace(&app.app_id());
    let mut tx = crate::app::state::Tx::new(&ns);
    crate::app::directory::put_peer(
        &mut tx,
        &slow,
        &crate::app::directory::PeerSwitch {
            known_version: Some(1),
            last_sent_ms: Some(s.w.clock.now_ms()),
        },
    )
    .unwrap();
    tx.commit(&StoreHandle::inline(
        Arc::clone(&s.w.store) as Arc<dyn StateStore>
    ))
    .await
    .unwrap();
    let doc = s.w.next_doc(|body| {
        body.removed.push(RemovedApp {
            app_id: [9; 16],
            distrust_from: START,
        })
    });
    app.refresh_identity().await.unwrap();
    let bob_has_it = || {
        s.peer
            .lock()
            .peers
            .get(&s.w.alice.public())
            .is_some_and(|held| held.version() == doc.version())
    };
    for _ in 0..2 {
        app.flush_outbox().await.unwrap();
        if bob_has_it() {
            break;
        }
    }
    assert!(bob_has_it(), "the healthy switch has the removal");
}

#[tokio::test]
async fn test_directory_floor_only_rises_within_one_answer() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.send(s.note("one")).await.unwrap();
    s.peer.rotate(0).unwrap();
    let (app_id, older, newer) = {
        let inner = s.peer.lock();
        (
            inner.apps[0].cert.app_id(),
            inner.apps[0].receive_keys[0].1.clone(),
            inner.apps[0].receive_keys[1].1.clone(),
        )
    };
    let id = pubky_switch_core::enc::zbase32_encode(&app_id);
    s.peer.fail_next(
        "inbox",
        ErrorCode::StaleKey,
        json!({ "receive_keys": [ { "app_id": id, "record": newer },
                                  { "app_id": id, "record": older } ],
                "not_current": [], "unknown_kids": [], "added_apps": [], "apps_version": 1 }),
    );
    s.peer.lock().requests.clear();
    let (_, delivery) = app.send(s.note("two")).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    let inner = s.peer.lock();
    let current = inner.apps[0].receive_keys[1].0.kid;
    let last = &inner.inbox.last().unwrap().envelope;
    assert_eq!(
        parse_header(last).unwrap().kids().collect::<Vec<_>>(),
        vec![current]
    );
    // Refused once by the script, then sealed to the newer key and taken.
    let appends = inner
        .requests
        .iter()
        .filter(|(m, r)| m == "POST" && r == "inbox")
        .count();
    assert_eq!(appends, 2);
}

#[tokio::test]
async fn test_directory_bad_app_is_skipped_and_the_others_used() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let till = s
        .peer
        .add_app("till", &AppSpec::new(&["sample-a"]), &["sample.note"], true)
        .unwrap();
    {
        let mut inner = s.peer.lock();
        // Till's entry carries the shop's record: it doesn't verify for its App ID.
        inner.apps[1].record = inner.apps[0].record.clone();
    }
    let (msg_id, delivery) = app.send(s.note("hello")).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    assert_eq!(s.peer.received(), vec![msg_id]);
    let events = app.take_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AppEvent::UnreachableApp { app_id, .. } if *app_id == till)),
        "{events:?}"
    );
    let inner = s.peer.lock();
    let last = &inner.inbox.last().unwrap().envelope;
    assert_eq!(parse_header(last).unwrap().kids().count(), 1);
}

#[tokio::test]
async fn test_records_listing_stops_when_next_doesnt_move_on() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let listed_before = s.w.switch.lock().shared.listings;
    s.w.switch.lock().shared.alternate_next = Some(([200; 32], [1; 32]));
    app.list_collection(&items()).await.unwrap();
    let pages = s.w.switch.lock().shared.listings - listed_before;
    assert_eq!(pages, 2);
}

#[tokio::test]
async fn test_records_listing_page_of_full_marks_commits_early() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let phone = s.join("phone").await;
    let id = phone.app_id();
    // 420 records on one page, each listed with a mark near the bound: 87 KiB each as
    // stored, about 35 MiB in all, more than one commit takes.
    let names: Vec<String> = (0..420).map(|n| format!("n{n:03}")).collect();
    for name in &names {
        wallet
            .put_record(&s.target(name), &value(&[name.as_str()]), vec![])
            .await
            .unwrap();
    }
    *s.protocol.pad.lock().unwrap() = MAX_SEEN_MARK_BYTES - 64;
    s.w.note(id, "after the writes");
    let mut ordered: Vec<_> = names
        .iter()
        .map(|name| {
            let target = s.target(name);
            let key = phone.record_key(&target).unwrap();
            (pubky_switch_core::enc::b64(&key), key, target)
        })
        .collect();
    ordered.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let (_, first, target) = ordered.first().unwrap();
    let (_, last, _) = ordered.last().unwrap();
    drop(phone);
    let store = Arc::new(FaultStore::new(s.w.store.clone(), StoreFault::None));
    let mut phone = App::load(
        s.env_on(store.clone()),
        s.protocol.clone(),
        World::config(),
        id,
    )
    .await
    .unwrap();
    store.fail_put_once(crate::app::records::record_key_of(last).as_bytes());
    assert!(phone.list_collection(&items()).await.is_err());
    drop(phone);
    let mut phone = App::load(s.env(), s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    assert!(phone.shared_record(first).await.unwrap().is_some());
    assert!(phone.shared_record(last).await.unwrap().is_none());
    assert!(matches!(
        phone.read_record_fresh(target).await.unwrap(),
        RecordRead::Fresh(_)
    ));
    assert_eq!(phone.list_collection(&items()).await.unwrap().records, 420);
    for name in [&names[0], &names[419]] {
        let key = phone.record_key(&s.target(name)).unwrap();
        assert!(phone.shared_record(&key).await.unwrap().is_some());
        let mark = phone.record_seen(&key).await.unwrap().unwrap();
        assert!(mark.len() > MAX_SEEN_MARK_BYTES - 64, "{}", mark.len());
    }
}

#[tokio::test]
async fn test_records_listing_pages_by_bytes() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    for name in ["n1", "n2", "n3"] {
        app.put_record(&s.target(name), &value(&[name]), vec![])
            .await
            .unwrap();
    }
    // A budget below one view: each page holds its first view alone (Switch wire 7.4.9).
    s.w.switch.lock().max_page_bytes = 1;
    let id = items().id(&s.w.alice.public());
    let first = app.client.records(&id, None, None).await.unwrap();
    assert_eq!(first.records.len(), 1);
    let next = first.next.unwrap();
    let second = app.client.records(&id, Some(&next), None).await.unwrap();
    assert_eq!(second.records.len(), 1);
    assert_ne!(second.records[0].key, first.records[0].key);
    // The app lists the whole collection by `next`.
    let before = s.w.switch.lock().shared.listings;
    assert_eq!(app.list_collection(&items()).await.unwrap().records, 3);
    assert_eq!(s.w.switch.lock().shared.listings - before, 3);
    // Within the budget, one page holds them all.
    s.w.switch.lock().max_page_bytes = crate::testing::MAX_PAGE_BYTES;
    let all = app.client.records(&id, None, None).await.unwrap();
    assert_eq!(all.records.len(), 3);
    assert!(all.next.is_none());
}

/// The wallet writes `n1` under its first certificate, which is then renewed and the
/// renewal closed; the wallet takes the renewal. Returns the wallet, the record's key and
/// the earlier certificate.
async fn own_write_under_a_closed_renewal(s: &Setup) -> (App, RecordTarget, [u8; 32], AppCert) {
    write_under_a_renewal_closed_to(s, &["sample-a", "sample-c"]).await
}

/// As [`own_write_under_a_closed_renewal`], with a renewed certificate holding `scopes`.
async fn write_under_a_renewal_closed_to(
    s: &Setup,
    scopes: &[&str],
) -> (App, RecordTarget, [u8; 32], AppCert) {
    let mut wallet = join_scoped(s, "wallet", &["sample-a", "sample-c"]).await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewal_of(s, "wallet", scopes);
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    let opened =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, None))
            .unwrap();
    let closed =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, Some(until)))
            .unwrap();
    s.w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: wallet.app_id(),
            cert: renewed.signed().clone(),
        })
        .unwrap();
    s.w.switch.deliver_identity(&opened).unwrap();
    s.w.switch.deliver_identity(&closed).unwrap();
    s.w.clock.advance_ms(2 * CLOCK_TOLERANCE_MS);
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    (wallet, target, key, earlier)
}

/// Whether `app` flagged nothing that names itself, in `events` or among its flagged writes,
/// and holds the record at `key` unflagged.
async fn no_self_flag(app: &App, events: &[AppEvent], key: &[u8; 32]) {
    let me = app.app_id();
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, AppEvent::WriteFlagged { writer, .. } if *writer == me)),
        "{events:?}"
    );
    assert!(
        app.flagged_writes()
            .await
            .unwrap()
            .iter()
            .all(|flagged| flagged.writer != me)
    );
    let held = app.shared_record(key).await.unwrap().unwrap();
    assert!(!held.flagged);
}

/// An own write that nothing dates, as a record the next service took from a recovery
/// upload after a loss, under a certificate whose renewal has closed since: the app's own
/// key signed it, so it isn't flagged at the app, read from its view.
#[tokio::test]
async fn test_records_own_undated_write_after_its_renewal_closed_isnt_flagged() {
    let s = Setup::new();
    let (mut wallet, target, key, _) = own_write_under_a_closed_renewal(&s).await;
    {
        let mut switch = s.w.switch.lock();
        let held = switch.shared.records.get_mut(&key).unwrap();
        held.proof = None;
        held.uploaded = Some(false);
    }
    wallet.read_record(&target).await.unwrap();
    let events = wallet.take_events();
    no_self_flag(&wallet, &events, &key).await;
}

/// An own write under a certificate whose renewal entry the signer has since purged from
/// `identity.json`: it has no standing there, but the app's own key signed it, so it isn't
/// flagged at the app.
#[tokio::test]
async fn test_records_own_write_after_its_renewal_entry_is_purged_isnt_flagged() {
    let s = Setup::new();
    let (mut wallet, target, key, earlier) = own_write_under_a_closed_renewal(&s).await;
    let purged =
        s.w.signer
            .sign_next(|body| body.renewed.retain(|entry| entry.cert != earlier.hash()))
            .unwrap();
    s.w.switch.deliver_identity(&purged).unwrap();
    wallet.refresh_identity().await.unwrap();
    wallet.read_record(&target).await.unwrap();
    let events = wallet.take_events();
    no_self_flag(&wallet, &events, &key).await;
}

/// The same write read by another own app, the renewed certificate holding the write scope
/// too: the write names no certificate, and the wallet's listed one counts for it (Switch
/// wire 6.2 "Accepting a write" steps 1 and 4), so it is taken, naming no app.
#[tokio::test]
async fn test_records_other_apps_write_after_its_renewal_entry_is_purged_is_taken() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let (wallet, target, key, earlier) = own_write_under_a_closed_renewal(&s).await;
    let purged =
        s.w.signer
            .sign_next(|body| body.renewed.retain(|entry| entry.cert != earlier.hash()))
            .unwrap();
    s.w.switch.deliver_identity(&purged).unwrap();
    phone.refresh_identity().await.unwrap();
    phone.read_record(&target).await.unwrap();
    let events = phone.take_events();
    assert!(flagged_rules(&events).is_empty(), "{events:?}");
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    assert_eq!(held.writer, wallet.app_id());
}

/// The same write when the renewal dropped the write scope: no certificate of the wallet
/// counts for it, so the checks of what the writer may write fail as before, and it is
/// flagged there with no standing, naming the wallet.
#[tokio::test]
async fn test_records_other_apps_write_after_its_renewal_entry_is_purged_is_flagged() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let (wallet, target, _key, earlier) = write_under_a_renewal_closed_to(&s, &["sample-c"]).await;
    let purged =
        s.w.signer
            .sign_next(|body| body.renewed.retain(|entry| entry.cert != earlier.hash()))
            .unwrap();
    s.w.switch.deliver_identity(&purged).unwrap();
    phone.refresh_identity().await.unwrap();
    phone.read_record(&target).await.unwrap();
    let events = phone.take_events();
    assert!(
        events.iter().any(|e| matches!(
            e,
            AppEvent::WriteFlagged { writer, reason, .. }
                if *writer == wallet.app_id() && reason.contains("no standing")
        )),
        "{events:?}"
    );
}

/// A write whose body names an app but whose signature doesn't verify, served as a record's
/// current write: nothing names that app. Its body names another identity, a check made
/// before the signature on main.
#[tokio::test]
async fn test_records_unverified_write_names_no_app() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&target).unwrap();
    wallet.receive(None).await.unwrap();
    // The phone's write, its body naming bob's identity, with a signature that doesn't
    // verify.
    let genuine = s.w.switch.lock().shared.records[&key].op.clone();
    let mut body = SignedOp::peek(&genuine).unwrap().body().clone();
    body.identity = s.w.bob.public();
    let resigned = SignedOp::sign(&app_keys("phone"), body).unwrap();
    let mut sig = resigned.signed().sig_bytes().unwrap();
    sig[0] ^= 1;
    let forged = pubky_switch_core::sig::SignedDoc::from_parts(
        &resigned.signed().body_bytes().unwrap(),
        &sig,
    );
    s.w.switch.lock().shared.records.get_mut(&key).unwrap().op = forged;
    wallet.read_record(&target).await.unwrap();
    let events = wallet.take_events();
    assert!(flagged_rules(&events).is_empty(), "{events:?}");
    assert!(wallet.flagged_writes().await.unwrap().is_empty());
}

/// A record's view whose version isn't of the write's generation, and nothing else gives one:
/// the version is the service's word, so nothing names the writer.
#[tokio::test]
async fn test_records_implausible_version_names_no_app() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&target).unwrap();
    {
        let mut switch = s.w.switch.lock();
        let held = switch.shared.records.get_mut(&key).unwrap();
        held.proof = None;
        held.state.version = RecordVersion::new(99, held.state.version.version);
    }
    wallet.read_record(&target).await.unwrap();
    let events = wallet.take_events();
    assert!(flagged_rules(&events).is_empty(), "{events:?}");
    assert!(wallet.flagged_writes().await.unwrap().is_empty());
}

/// A record's view that carries the genuine write of another record: its writer wrote it
/// for that record, so the service, not the writer, is at fault, and nothing names the
/// writer.
#[tokio::test]
async fn test_records_write_of_another_record_names_no_app() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let (one, two) = (s.target("n1"), s.target("n2"));
    for target in [&one, &two] {
        phone
            .put_record(target, &value(&["a"]), vec![])
            .await
            .unwrap();
    }
    let (key_one, key_two) = (
        phone.record_key(&one).unwrap(),
        phone.record_key(&two).unwrap(),
    );
    wallet.receive(None).await.unwrap();
    {
        let mut switch = s.w.switch.lock();
        let other = switch.shared.records[&key_one].op.clone();
        switch.shared.records.get_mut(&key_two).unwrap().op = other;
    }
    wallet.read_record(&two).await.unwrap();
    let events = wallet.take_events();
    assert!(flagged_rules(&events).is_empty(), "{events:?}");
    assert!(wallet.flagged_writes().await.unwrap().is_empty());
    assert!(wallet.shared_record(&key_two).await.unwrap().is_some());
}

#[tokio::test]
async fn test_records_listing_reads_at_most_its_page_budget_and_goes_on() {
    // Six records, one a page: a call lists four and says more; the next goes on from
    // there to the end. The call after that starts at the beginning again.
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    for n in 0..6 {
        let name = format!("n{n}");
        app.put_record(&s.target(&name), &value(&[name.as_str()]), vec![])
            .await
            .unwrap();
    }
    s.w.switch.lock().max_page_bytes = 1;
    let listings = || s.w.switch.lock().shared.listings;
    let before = listings();
    let first = app.list_collection(&items()).await.unwrap();
    assert!(first.more, "{first:?}");
    assert_eq!(first.records, 4);
    assert_eq!(
        listings() - before,
        u64::from(crate::app::LISTING_PAGES_PER_READ)
    );
    let second = app.list_collection(&items()).await.unwrap();
    assert!(!second.more, "{second:?}");
    assert_eq!(second.records, 2);
    let third = app.list_collection(&items()).await.unwrap();
    assert!(third.more, "{third:?}");
    assert_eq!(third.records, 4);
}

#[tokio::test]
async fn test_records_listing_named_generations_waits_for_the_new_child_or_parent_key() {
    for grant in ["sample-a:shop", "sample-a"] {
        let s = Setup::new();
        let family = Collection::with_permanent_generations(
            "sample.items",
            "sample-a:shop",
            &["sample-a:shop"],
        );
        *s.protocol.collections.lock().unwrap() = Some(vec![family.clone()]);
        let mut writer = join_scoped(&s, "phone", &["sample-a"]).await;
        let target = RecordTarget::new(
            Collection::new(&family.name, family.policy.clone().permanent(Some(1))),
            b"shop",
        );
        writer
            .put_record(&target, &value(&["issued"]), vec![])
            .await
            .unwrap();
        let key = writer.record_key(&target).unwrap();
        let mut reader = join_scoped(&s, "wallet", &["sample-a:other"]).await;
        reader.receive(None).await.unwrap();
        assert!(!reader.listing_owed().await.unwrap());
        assert!(reader.shared_record(&key).await.unwrap().is_none());
        s.w.clock.advance_ms(HOUR);
        let earlier = reader.cert().clone();
        let renewed = renewed_cert(&s, "wallet", &[grant]);
        s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
        reader.receive(None).await.unwrap();
        assert_eq!(reader.cert().hash(), renewed.hash());
        assert!(family.readable_by(reader.cert()));
        assert!(reader.listing_owed().await.unwrap(), "{grant}");
        let before = s.w.switch.lock().shared.listings;
        reader.receive(None).await.unwrap();
        assert_eq!(s.w.switch.lock().shared.listings, before, "{grant}");
        assert!(reader.shared_record(&key).await.unwrap().is_none());
        store_parts_for(&s, &renewed);
        reader.receive(None).await.unwrap();
        reader.receive(None).await.unwrap();
        assert!(!reader.listing_owed().await.unwrap());
        let held = reader.shared_record(&key).await.unwrap().unwrap();
        assert_eq!(ids(held.content.value()), ["issued"], "{grant}");
    }
}

#[tokio::test]
async fn test_records_retained_child_key_reads_the_same_collection_after_a_parent_grant() {
    let s = Setup::new();
    let family =
        Collection::with_permanent_generations("sample.items", "sample-a:shop", &["sample-a:shop"]);
    *s.protocol.collections.lock().unwrap() = Some(vec![family.clone()]);
    let member = Collection::new(&family.name, family.policy.clone().permanent(Some(1)));
    let mut writer = join_scoped(&s, "phone", &["sample-a"]).await;
    let first = RecordTarget::new(member.clone(), b"first");
    writer
        .put_record(&first, &value(&["one"]), vec![])
        .await
        .unwrap();
    let mut reader = join_scoped(&s, "wallet", &["sample-a:shop"]).await;
    reader.receive(None).await.unwrap();
    let key = reader.record_key(&first).unwrap();
    let held = reader.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), ["one"]);
    s.w.clock.advance_ms(HOUR);
    let old = reader.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-a"]);
    s.w.next_doc(|body| list_renewal(body, &old, &renewed, None));
    reader.receive(None).await.unwrap();
    assert_eq!(reader.cert().hash(), renewed.hash());
    assert!(!reader.listing_owed().await.unwrap());

    let second = RecordTarget::new(member, b"second");
    writer
        .put_record(&second, &value(&["two"]), vec![])
        .await
        .unwrap();
    reader.receive(None).await.unwrap();
    let key = reader.record_key(&second).unwrap();
    let held = reader.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), ["two"]);

    // An independent gap still needs its listing. Its records use the child key the
    // reader already holds even though the wider bundle has not arrived.
    let now = s.w.clock.now_ms();
    s.w.switch.push_missed(1, now - 1, now);
    let before = s.w.switch.lock().shared.listings;
    let report = reader.receive(None).await.unwrap();
    assert!(
        !report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::ListingWaitsForKey))
    );
    assert!(s.w.switch.lock().shared.listings > before);
    assert!(!reader.listing_owed().await.unwrap());
}

#[tokio::test]
async fn test_records_listing_named_permanent_generations_restarts_a_narrow_scan() {
    let s = Setup::new();
    let family = Collection::with_permanent_generations("sample.items", "sample-a", &["sample-a"]);
    *s.protocol.collections.lock().unwrap() = Some(vec![family.clone()]);
    let mut reader = s.join("wallet").await;
    let mut writer = s.join("phone").await;
    let named = |g| Collection::new(&family.name, family.policy.clone().permanent(Some(g)));
    for n in 0..6 {
        let key = format!("recipient-{n}");
        writer
            .put_record(
                &RecordTarget::new(named(1), key.as_bytes()),
                &value(&["issued"]),
                vec![],
            )
            .await
            .unwrap();
    }
    s.w.switch.lock().max_page_bytes = 1;
    let first = reader.list_collection(&named(2)).await.unwrap();
    assert!(first.more);
    assert_eq!(first.records, 4);
    assert!(reader.records_of(&family.name).await.unwrap().is_empty());

    let first = reader.list_collection(&family).await.unwrap();
    assert!(first.more);
    assert_eq!(first.records, 4);
    let second = reader.list_collection(&family).await.unwrap();
    assert!(!second.more);
    assert_eq!(second.records, 2);
    let found = reader.records_of(&family.name).await.unwrap();
    assert_eq!(found.len(), 6);
    assert!(
        found
            .iter()
            .all(|r| r.policy == named(1).policy && r.content.value().is_some())
    );
    let template = RecordTarget::new(family, b"recipient-7");
    assert!(reader.record_key(&template).is_err());
    assert!(
        reader
            .record_op(&template, Some(&value(&["issued"])), vec![])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_records_list_collections_reads_at_most_its_page_budget_and_goes_on() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    for n in 0..6 {
        let name = format!("n{n}");
        app.put_record(&s.target(&name), &value(&[name.as_str()]), vec![])
            .await
            .unwrap();
    }
    s.w.switch.lock().max_page_bytes = 1;
    let listings = || s.w.switch.lock().shared.listings;
    let before = listings();
    assert!(app.list_collections().await.unwrap(), "more");
    assert_eq!(
        listings() - before,
        u64::from(crate::app::LISTING_PAGES_PER_READ)
    );
    assert!(!app.list_collections().await.unwrap(), "to the end");
    assert_eq!(listings() - before, 6);
    assert!(!app.listing_owed().await.unwrap());
}

#[test]
fn test_push_setting_debug_hides_the_handles() {
    let setting = crate::client::answers::PushSetting {
        relay_url: "https://relay.example".into(),
        handles: vec!["secret-handle".into()],
        push_key: Some([1; 32]),
        replaces: None,
    };
    let text = format!("{setting:?}");
    assert!(!text.contains("secret"), "{text}");
    assert!(text.contains("handles: 1"), "{text}");
}

// -------------------------------------------------------------------------------------
// The scripted switch's record and claim reads, as the service answers them
// (`crates/pubky-switch/src/service/records.rs`, `claims.rs`; Switch wire 7.4.8, 7.4.9)

/// A `GET` of `rest` at alice's scripted switch from her app `app`, `None` for the signer:
/// the status, the error code, and whether the answer carries the head.
fn scripted_get(s: &Setup, app: Option<[u8; 16]>, rest: &str) -> (u16, Value, bool) {
    let (status, body, head) = scripted_answer(s, app, rest);
    (status, body["code"].clone(), head)
}

/// The body of a `GET` of `rest` that the scripted switch answers `200`.
fn scripted_page(s: &Setup, app: Option<[u8; 16]>, rest: &str) -> Value {
    let (status, body, _) = scripted_answer(s, app, rest);
    assert_eq!(status, 200, "{body}");
    body
}

/// A `GET` of `rest` at alice's scripted switch: the status, the body and whether the answer
/// carries the head.
fn scripted_answer(s: &Setup, app: Option<[u8; 16]>, rest: &str) -> (u16, Value, bool) {
    use crate::transport::Header;
    use pubky_switch_core::http::{self, RequestHeaders, RequestTarget, header};

    let path = format!("/v1/{}/{rest}", s.w.alice.id());
    let mut headers = vec![crate::transport::Header::new(
        pubky_switch_core::http::header::IDENTITY,
        &s.w.alice.id(),
    )];
    if let Some(app) = app {
        headers.push(crate::transport::Header::new(
            pubky_switch_core::http::header::APP,
            &pubky_switch_core::enc::zbase32_encode(&app),
        ));
    } else {
        let created = pubky_switch_core::time::rfc3339(s.w.switch.created());
        let fields = RequestHeaders {
            identity: s.w.alice.id(),
            timestamp: pubky_switch_core::time::rfc3339_seconds(s.w.clock.now_ms()),
            created: Some(created.clone()),
            ..RequestHeaders::default()
        };
        let signature = http::sign_request(
            &s.w.alice,
            &RequestTarget {
                method: "GET",
                path_and_query: &path,
                body: &[],
                origin: ORIGIN,
            },
            &fields,
        );
        headers.extend([
            Header::new(header::TIMESTAMP, &fields.timestamp),
            Header::new(header::CREATED, &created),
            Header::new(header::SIGNATURE, &pubky_switch_core::enc::b64(&signature)),
        ]);
    }
    let response =
        s.w.switch
            .handle(&crate::transport::Request {
                method: "GET".into(),
                origin: ORIGIN.into(),
                path_and_query: path,
                headers,
                body: Vec::new(),
                timeout: crate::transport::TimeoutClass::Bulk,
            })
            .unwrap();
    let head = response
        .header(pubky_switch_core::http::header::HEAD)
        .is_some();
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    (response.status, body, head)
}

/// A record in `sample.items`, written by the phone; the record's key, as text.
async fn phone_record(s: &Setup, phone: &mut App) -> String {
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    pubky_switch_core::enc::b64(&phone.record_key(&target).unwrap())
}

fn items_id(s: &Setup) -> String {
    pubky_switch_core::enc::b64(&items().id(&s.w.alice.public()))
}

#[tokio::test]
async fn test_scripted_records_by_key_needs_the_read_scope() {
    let s = Setup::new();
    let wallet = join_scoped(&s, "wallet", &["sample-c"]).await;
    let mut phone = s.join("phone").await;
    let key = phone_record(&s, &mut phone).await;
    let rest = format!("records/{key}");
    assert_eq!(
        scripted_get(&s, Some(phone.app_id()), &rest),
        (200, Value::Null, true)
    );
    // Refused with the head, as at the service.
    assert_eq!(
        scripted_get(&s, Some(wallet.app_id()), &rest),
        (403, json!("permission_missing"), true)
    );
}

#[tokio::test]
async fn test_scripted_records_signer_reads_none_and_an_app_without_a_record_is_refused_first() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let key = phone_record(&s, &mut phone).await;
    let by_key = format!("records/{key}");
    let list = format!("records?collection={}", items_id(&s));
    // The query is read before the caller: a parameter given twice is 400, the signer's
    // included.
    assert_eq!(
        scripted_get(&s, None, &format!("{list}&limit=1&limit=2")),
        (400, json!("bad_request"), true)
    );
    // The signer reads no records.
    for rest in [&by_key, &list] {
        assert_eq!(
            scripted_get(&s, None, rest),
            (403, json!("permission_missing"), true),
            "{rest}"
        );
    }
    // An own app the switch holds no record for has no key its request verifies with: it
    // meets the first-call refusal at both reads, before the lock, so without the head, as
    // at the service (Switch wire 7.1, 7.2; `verify_own_app`). The phone's list shows the
    // record.
    let unknown = Some(app_keys("unknown").app_id_bytes());
    for rest in [&by_key, &list] {
        assert_eq!(
            scripted_get(&s, unknown, rest),
            (403, json!("not_current"), false),
            "{rest}"
        );
    }
    // A query given twice is the endpoint's to refuse, after that refusal.
    assert_eq!(
        scripted_get(&s, unknown, &format!("{list}&limit=1&limit=2")),
        (403, json!("not_current"), false)
    );
    let shown = scripted_page(&s, Some(phone.app_id()), &list)["records"]
        .as_array()
        .map(Vec::len);
    assert_eq!(shown, Some(1));
}

#[tokio::test]
async fn test_scripted_records_query_and_key_are_read_as_the_service_reads_them() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let key = phone_record(&s, &mut phone).await;
    let me = Some(phone.app_id());
    let id = items_id(&s);
    let refused = [
        "records".to_owned(),
        "records?after=AAAA".to_owned(),
        "records?collection=AAAA".to_owned(),
        format!("records?collection={id}&after=AAAA"),
        format!("records?collection={id}&after={key}="),
        format!("records?collection={id}&limit=+5"),
        format!("records?collection={id}&limit=0"),
        format!("records?collection={id}&limit=1001"),
        "records/AAAA".to_owned(),
        format!("records/{key}="),
        format!("records?collection={id}&collection={id}"),
        format!("records?collection={id}&limit=%zz"),
    ];
    for rest in &refused {
        assert_eq!(
            scripted_get(&s, me, rest),
            (400, json!("bad_request"), true),
            "{rest}"
        );
    }
    // Percent-decoded, as at the service.
    let escaped = id.replace('-', "%2D").replace('_', "%5F");
    for rest in [
        format!("records?collection={id}&limit=5"),
        format!("records?collection={id}&after={key}"),
        format!("records?collection={escaped}&limit=%35"),
    ] {
        assert_eq!(scripted_get(&s, me, &rest).0, 200, "{rest}");
    }
}

#[tokio::test]
async fn test_scripted_records_list_after_compares_the_key_text() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let first = phone_record(&s, &mut phone).await;
    let target = s.target("n2");
    phone
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    let id = items().id(&s.w.alice.public());
    let all = phone.client.records(&id, None, None).await.unwrap();
    let keys: Vec<String> = all
        .records
        .iter()
        .map(|view| pubky_switch_core::enc::b64(&view.key))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "by the key text, in ASCII order");
    // Exclusive: after the first key, only the second.
    let after = pubky_switch_core::enc::unb64_array::<32>(&keys[0]).unwrap();
    let page = phone.client.records(&id, Some(&after), None).await.unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(pubky_switch_core::enc::b64(&page.records[0].key), keys[1]);
    assert!(keys.contains(&first));
}

#[tokio::test]
async fn test_scripted_claims_read_needs_claims_read() {
    let s = Setup::new();
    let reader = s.join("phone").await;
    let tablet = s.join_with("tablet", &[Permission::ConversationAdd]).await;
    let claim = pubky_switch_core::enc::b64(&[9u8; 32]);
    let rest = format!("claims/{claim}");
    assert_eq!(
        scripted_get(&s, Some(reader.app_id()), &rest),
        (404, json!("not_found"), true)
    );
    assert_eq!(
        scripted_get(&s, Some(reader.app_id()), "claims/AAAA"),
        (400, json!("bad_request"), true)
    );
    // Without `claims.read`, and the signer, refused before the key is read.
    for app in [Some(tablet.app_id()), None] {
        for rest in [rest.as_str(), "claims/AAAA"] {
            assert_eq!(
                scripted_get(&s, app, rest),
                (403, json!("permission_missing"), true),
                "{app:?} {rest}"
            );
        }
    }
}

/// The peer switch's `409 identity_needed` carries `known_version` beside `current`, as the
/// service's does (Switch wire 7.1, 7.6).
#[tokio::test]
async fn test_scripted_peer_identity_needed_carries_known_version() {
    let s = Setup::new();
    let wallet = s.join("wallet").await;
    let request = crate::transport::Request {
        method: "POST".into(),
        origin: PEER_ORIGIN.into(),
        path_and_query: format!("/v1/{}/inbox?apps_version=0", s.w.bob.id()),
        headers: vec![
            crate::transport::Header::new(
                pubky_switch_core::http::header::IDENTITY,
                &s.w.alice.id(),
            ),
            crate::transport::Header::new(
                pubky_switch_core::http::header::APP,
                &pubky_switch_core::enc::zbase32_encode(&wallet.app_id()),
            ),
        ],
        body: Vec::new(),
        timeout: crate::transport::TimeoutClass::Bulk,
    };
    let response = s.peer.transport().send(request).await.unwrap();
    assert_eq!(response.status, 409);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["code"], json!("identity_needed"));
    assert_eq!(body["current"], json!({ "version": null }));
    assert_eq!(
        body.as_object().unwrap().get("known_version"),
        Some(&Value::Null)
    );
}

// -------------------------------------------------------------------------------------
// Records held unreadable until their keys arrive (Switch spec 3.5)

/// A listing a widening renewal owes waits for the keys of the scope it added: listed
/// before them, the record would be held `Unreadable`.
#[tokio::test]
async fn test_records_listing_after_a_widening_waits_for_the_keys() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-c"]).await;
    let mut phone = s.join("phone").await;
    let key =
        pubky_switch_core::enc::unb64_array::<32>(&phone_record(&s, &mut phone).await).unwrap();
    wallet.receive(None).await.unwrap();
    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-a", "sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    // The renewal's part came before the document listing it and was skipped: the key of
    // sample-a is missing, so the listing waits.
    let listings = s.w.switch.lock().shared.listings;
    wallet.receive(None).await.unwrap();
    assert_eq!(
        s.w.switch.lock().shared.listings,
        listings,
        "no listing yet"
    );
    assert!(wallet.shared_record(&key).await.unwrap().is_none());
    // Once the keys arrive, the next read lists, and the record opens.
    store_parts_for(&s, &renewed);
    wallet.receive(None).await.unwrap();
    wallet.receive(None).await.unwrap();
    assert!(s.w.switch.lock().shared.listings > listings);
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
}

/// The wallet and the phone at data epoch 2, the phone holding its key and the wallet not;
/// the phone writes `n1` sealed at epoch 2, and the wallet reads it from the feed.
async fn record_at_a_new_epoch(s: &Setup, wallet: &mut App, phone: &mut App) -> [u8; 32] {
    wallet.receive(None).await.unwrap();
    s.w.next_doc(|body| body.data_epoch = 2);
    store_parts_for(s, &phone.cert().clone());
    phone.receive(None).await.unwrap();
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    phone.record_key(&target).unwrap()
}

/// A record written at a new data epoch whose key reaches the app late is held
/// `Unreadable`, then opened when the key arrives, without a listing.
#[tokio::test]
async fn test_records_held_unreadable_opens_once_its_key_arrives() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let key = record_at_a_new_epoch(&s, &mut wallet, &mut phone).await;
    wallet.receive(None).await.unwrap();
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(
        held.content,
        RecordContent::Unreadable(Unopened::KeyNotHeld { data_epoch: 2 }),
        "for now"
    );
    let listings = s.w.switch.lock().shared.listings;
    store_parts_for(&s, &wallet.cert().clone());
    let report = wallet.receive(None).await.unwrap();
    assert_eq!(s.w.switch.lock().shared.listings, listings, "no listing");
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::RecordChanged { key: k } if *k == key)),
        "{:?}",
        report.events
    );
}

/// A store whose commits that end an owed reopening fail, as many times as `failing` says.
struct FailingReopen {
    inner: MemoryStore,
    failing: std::sync::Mutex<u32>,
}

impl StateStore for FailingReopen {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, crate::error::StoreError> {
        self.inner.get(ns, key)
    }

    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<crate::store::KeyValue>, crate::error::StoreError> {
        self.inner.scan(ns, prefix, after, limit)
    }

    fn commit(&self, batch: crate::store::WriteBatch) -> Result<(), crate::error::StoreError> {
        let ends_reopen = batch.writes().iter().any(|write| {
            matches!(write, crate::store::Write::Delete { key, .. } if key.as_slice() == b"reopen")
        });
        let fails = ends_reopen && {
            let mut left = self.failing.lock().unwrap();
            let fails = *left > 0;
            *left = left.saturating_sub(1);
            fails
        };
        if fails {
            return Err(crate::error::StoreError::Unavailable);
        }
        self.inner.commit(batch)
    }

    fn acquire(
        &self,
        ns: &str,
        owner: crate::store::StoreOwner,
    ) -> Result<crate::store::AcquireOutcome, crate::store::StoreError> {
        self.inner.acquire(ns, owner)
    }

    fn commit_if(
        &self,
        ns: &str,
        owner: crate::store::StoreOwner,
        batch: crate::store::WriteBatch,
    ) -> Result<crate::store::CommitOutcome, crate::store::StoreError> {
        let ends_reopen = batch.writes().iter().any(|write| {
            matches!(write, crate::store::Write::Delete { key, .. } if key.as_slice() == b"reopen")
        });
        let fails = ends_reopen && {
            let mut left = self.failing.lock().unwrap();
            let fails = *left > 0;
            *left = left.saturating_sub(1);
            fails
        };
        if fails {
            return Err(crate::error::StoreError::Unavailable);
        }
        self.inner.commit_if(ns, owner, batch)
    }
}

/// The reopening a key owes is kept with the key: when its own commit fails after the key
/// was taken, the read goes on and reports it, and the next read reopens the record held
/// `Unreadable`, though no fetch takes a key again.
#[tokio::test]
async fn test_records_reopening_that_fails_is_made_at_the_next_read() {
    let s = Setup::new();
    let store = Arc::new(FailingReopen {
        inner: MemoryStore::new(),
        failing: std::sync::Mutex::new(0),
    });
    let request = s.approve(&app_keys("wallet"), &ALL_PERMISSIONS);
    let mut wallet = App::join(
        s.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        request,
    )
    .await
    .unwrap();
    let mut phone = s.join("phone").await;
    let key = record_at_a_new_epoch(&s, &mut wallet, &mut phone).await;
    wallet.receive(None).await.unwrap();
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(
        held.content,
        RecordContent::Unreadable(Unopened::KeyNotHeld { data_epoch: 2 }),
    );
    // The key arrives, and the reopening's commit fails at each try of that read: after
    // the page, and at the read's end.
    *store.failing.lock().unwrap() = 2;
    store_parts_for(&s, &wallet.cert().clone());
    let report = wallet.receive(None).await.unwrap();
    assert_eq!(*store.failing.lock().unwrap(), 0);
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::ReopeningOwed { .. })),
        "{:?}",
        report.events
    );
    assert!(
        wallet.scope_key(2, "sample-a").is_some(),
        "the key was taken"
    );
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert!(held.content.value().is_none(), "not reopened yet");
    // The next read reopens it.
    wallet.receive(None).await.unwrap();
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    let ns = crate::store::client_namespace(&wallet.app_id());
    assert!(
        store.get(&ns, b"reopen").unwrap().is_none(),
        "nothing owed after"
    );
}

/// An explicit listing of a record held `Unreadable` opens it once its key is held: the
/// same write, by its item hash, is taken as opened.
#[tokio::test]
async fn test_records_relist_opens_a_record_held_unreadable() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let key = record_at_a_new_epoch(&s, &mut wallet, &mut phone).await;
    wallet.list_collection(&items()).await.unwrap();
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(
        held.content,
        RecordContent::Unreadable(Unopened::KeyNotHeld { data_epoch: 2 }),
        "for now"
    );
    store_parts_for(&s, &wallet.cert().clone());
    wallet.receive(None).await.unwrap();
    wallet.list_collection(&items()).await.unwrap();
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
}

/// A record whose value doesn't open with its key held stays `Unreadable`: tried again
/// once, when the key arrives, and flagged then; a later read doesn't try it again.
#[tokio::test]
async fn test_records_unopenable_with_its_key_held_is_tried_once() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    wallet.receive(None).await.unwrap();
    s.w.next_doc(|body| body.data_epoch = 2);
    store_parts_for(&s, &phone.cert().clone());
    phone.receive(None).await.unwrap();
    // The phone writes a value sealed under a key that isn't epoch 2's.
    let target = s.target("n1");
    let (_, kind) = phone
        .record_op(&target, Some(&value(&["a"])), vec![])
        .await
        .unwrap();
    let OpKind::RecordPut(mut put) = kind else {
        unreachable!("a record op");
    };
    put.value_sealed = pubky_switch_core::sealed::SealedValue::seal(
        &[3; 32],
        &s.w.alice.public(),
        2,
        "sample-a",
        &put.key,
        &value(&["a"]),
    )
    .unwrap();
    let key = put.key;
    s.w.switch
        .app_op(&app_keys("phone"), OpKind::RecordPut(put))
        .unwrap();
    wallet.receive(None).await.unwrap();
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(
        held.content,
        RecordContent::Unreadable(Unopened::KeyNotHeld { data_epoch: 2 }),
        "for now"
    );
    store_parts_for(&s, &wallet.cert().clone());
    let report = wallet.receive(None).await.unwrap();
    assert_eq!(
        flagged_rules(&report.events).len(),
        1,
        "{:?}",
        report.events
    );
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(
        held.content,
        RecordContent::Unreadable(Unopened::DoesNotOpen),
        "for good"
    );
    // Not tried at every read, nor at a fetch that takes no key.
    for _ in 0..2 {
        let report = wallet.receive(None).await.unwrap();
        assert!(
            flagged_rules(&report.events).is_empty(),
            "{:?}",
            report.events
        );
    }
    wallet.fetch_key_bundle().await.unwrap();
    assert!(flagged_rules(&wallet.take_events()).is_empty());
    // Nor at a later key's arrival: it won't open.
    s.w.next_doc(|body| body.data_epoch = 3);
    store_parts_for(&s, &wallet.cert().clone());
    let report = wallet.receive(None).await.unwrap();
    assert!(wallet.scope_key(3, "sample-a").is_some());
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
}

// -------------------------------------------------------------------------------------
// A record read now, or an earlier copy kept (Switch wire 7.4.9)

#[tokio::test]
async fn test_records_fresh_read_after_a_list_ending_at_an_inbox_entry() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("notes");
    let written = phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let id = wallet.app_id();
    let (entry, _) = s.w.note(id, "after the record");
    let page = wallet
        .client
        .records(&target.collection.id(&s.w.alice.public()), None, Some(10))
        .await
        .unwrap();
    assert_eq!(page.seq, entry);
    assert!(page.seq > page.head.seq);
    let get = wallet.client.record(&written.key).await.unwrap();
    assert_eq!(get.head, page.head);
    let listed = page.records.iter().find(|r| r.key == written.key).unwrap();
    assert_eq!(get.view.op, listed.op);
    assert_eq!(get.view.revision, listed.revision);
    assert!(
        !wallet
            .list_collection(&target.collection)
            .await
            .unwrap()
            .more
    );
    for reopen in [false, true] {
        if reopen {
            drop(wallet);
            wallet = App::load(s.env(), s.protocol.clone(), World::config(), id)
                .await
                .unwrap();
        }
        match wallet.read_record_fresh(&target).await.unwrap() {
            RecordRead::Fresh(record) => {
                assert_eq!(record.version, written.version);
                assert_eq!(ids(record.content.value()), ["a"]);
            }
            other => panic!("read after listing: {other:?}"),
        }
    }
    // A later hosted absence carries a newer chain head even when the key
    // doesn't have a cached row. Remember it across a cold start.
    phone
        .put_record(&s.target("another"), &value(&["b"]), vec![])
        .await
        .unwrap();
    assert!(matches!(
        wallet.read_record_fresh(&s.target("absent")).await.unwrap(),
        RecordRead::Kept {
            reason: KeptReason::NotFound,
            ..
        }
    ));
    drop(wallet);
    let mut wallet = App::load(s.env(), s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    s.w.switch.fail_next(Fault::Head {
        path: "/records/".into(),
        at: Some(page.head.seq),
        forked: false,
    });
    assert!(matches!(
        wallet.read_record_fresh(&target).await.unwrap(),
        RecordRead::Kept {
            reason: KeptReason::Overtaken { .. },
            ..
        }
    ));
    assert!(matches!(
        wallet.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(_)
    ));
}

#[tokio::test]
async fn test_records_key_read_remembers_a_new_head_after_an_interrupted_list() {
    use crate::app::state::{ChainRecord, key};

    let s = Setup::new();
    let wallet = s.join("wallet").await;
    let id = wallet.app_id();
    drop(wallet);
    let store = Arc::new(FaultStore::new(s.w.store.clone(), StoreFault::None));
    let mut wallet = App::load(
        s.env_on(store.clone()),
        s.protocol.clone(),
        World::config(),
        id,
    )
    .await
    .unwrap();
    let mut phone = s.join("phone").await;
    let target = s.target("notes");
    let written = phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let (inbox, _) = s.w.note(id, "after the record");
    let earlier = wallet.client.record(&written.key).await.unwrap().head;
    assert!(earlier.seq < inbox);
    assert!(
        !wallet
            .list_collection(&target.collection)
            .await
            .unwrap()
            .more
    );

    phone
        .put_record(&s.target("another"), &value(&["b"]), vec![])
        .await
        .unwrap();
    let later = wallet.client.record(&written.key).await.unwrap().head;
    assert!(later.seq > inbox);
    // The page arrives, but the local certificate read fails before its first commit.
    let certs = format!(
        "ocert/{}/",
        pubky_switch_core::enc::zbase32_encode(&phone.app_id())
    );
    store.fail_scan(certs.as_bytes(), 0);
    assert!(matches!(
        wallet.list_collection(&target.collection).await,
        Err(AppError::Store(crate::error::StoreError::Unavailable))
    ));
    assert_eq!(wallet.state.chain.as_ref().unwrap().newest, Some(later));
    assert_eq!(
        wallet
            .reader()
            .get::<ChainRecord>(key::CHAIN)
            .await
            .unwrap()
            .unwrap()
            .newest,
        Some(earlier.to_value())
    );

    assert!(matches!(
        wallet.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(_)
    ));
    drop(wallet);
    let mut wallet = App::load(s.env(), s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    s.w.switch.fail_next(Fault::Head {
        path: "/records/".into(),
        at: Some(earlier.seq),
        forked: false,
    });
    assert!(matches!(
        wallet.read_record_fresh(&target).await.unwrap(),
        RecordRead::Kept {
            reason: KeptReason::Overtaken { .. },
            ..
        }
    ));
    assert!(matches!(
        wallet.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(_)
    ));
}

#[tokio::test]
async fn test_records_read_fresh_tells_a_fresh_read_from_a_kept_copy() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    // Read now.
    match phone.read_record_fresh(&target).await.unwrap() {
        RecordRead::Fresh(record) => assert_eq!(ids(record.content.value()), ["a", "b"]),
        other => panic!("{other:?}"),
    }
    // The wallet drops b, which the phone has seen: the newer write is refused, and the
    // phone keeps its copy.
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    match phone.read_record_fresh(&target).await.unwrap() {
        RecordRead::Kept {
            record: Some(record),
            reason: KeptReason::Refused,
        } => assert_eq!(ids(record.content.value()), ["a", "b"]),
        other => panic!("{other:?}"),
    }
    // The switch forgets the record: a 404, and the copy kept.
    s.w.switch.lock().shared.records.remove(&key);
    match phone.read_record_fresh(&target).await.unwrap() {
        RecordRead::Kept {
            record: Some(record),
            reason: KeptReason::NotFound,
        } => assert_eq!(ids(record.content.value()), ["a", "b"]),
        other => panic!("{other:?}"),
    }
    // The switch can't be reached: the copy kept.
    s.w.switch.fail_next(Fault::Unreachable {
        path: "records/".into(),
        after: 0,
    });
    assert!(matches!(
        phone.read_record_fresh(&target).await.unwrap(),
        RecordRead::Kept {
            record: Some(_),
            reason: KeptReason::Unreachable(_),
        }
    ));
    // The read the existing call makes still returns the copy.
    assert!(phone.read_record(&target).await.unwrap().is_some());
}

/// A newer write that fails a check, a value that doesn't open with its key held, keeps
/// the earlier copy.
#[tokio::test]
async fn test_records_read_fresh_keeps_a_copy_past_a_write_that_fails_a_check() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    assert!(matches!(
        wallet.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(_)
    ));
    let (_, kind) = phone
        .record_op(&target, Some(&value(&["a", "b"])), vec![])
        .await
        .unwrap();
    let OpKind::RecordPut(mut put) = kind else {
        unreachable!("a record op");
    };
    put.value_sealed = pubky_switch_core::sealed::SealedValue::seal(
        &[3; 32],
        &s.w.alice.public(),
        1,
        "sample-a",
        &put.key,
        &value(&["a", "b"]),
    )
    .unwrap();
    s.w.switch
        .app_op(&app_keys("phone"), OpKind::RecordPut(put))
        .unwrap();
    match wallet.read_record_fresh(&target).await.unwrap() {
        RecordRead::Kept {
            record: Some(record),
            reason: KeptReason::Refused,
        } => assert_eq!(ids(record.content.value()), ["a"]),
        other => panic!("{other:?}"),
    }
}

/// The feed's query, as the service reads it: decoded, a parameter given twice refused, and
/// `limit` and `wait` digits only in their ranges; the signer is refused first.
#[tokio::test]
async fn test_scripted_feed_query_is_read_as_the_service_reads_it() {
    let s = Setup::new();
    let phone = s.join("phone").await;
    let me = Some(phone.app_id());
    for rest in [
        "feed?after=1:0&after=1:1",
        "feed?limit=%zz",
        "feed?limit=+5",
        "feed?limit=0&wait=1",
        "feed?limit=501",
        "feed?wait=26",
        "feed?wait=+1",
    ] {
        assert_eq!(
            scripted_get(&s, me, rest),
            (400, json!("bad_request"), true),
            "{rest}"
        );
    }
    for rest in [
        "feed?limit=%35",
        "feed?limit=0",
        "feed?limit=500",
        "feed?after=1%3A0&wait=0",
    ] {
        assert_eq!(scripted_get(&s, me, rest).0, 200, "{rest}");
    }
    assert_eq!(
        scripted_get(&s, None, "feed?limit=1&limit=2"),
        (403, json!("permission_missing"), true)
    );
}

/// A page with no items, as the service answers it (Switch wire 7.4.4): no item, `next`
/// where the page starts, `more` when anything follows, the head and the cursor of any page,
/// and the reader's lagging mark kept.
#[tokio::test]
async fn test_scripted_feed_page_with_no_items_ends_where_it_starts() {
    let s = Setup::new();
    let phone = s.join("phone").await;
    let me = Some(phone.app_id());
    let generation = s.w.switch.lock().tip.generation;
    let last = s.w.switch.seq();
    let full = scripted_page(&s, me, "feed");
    s.w.switch
        .lock()
        .apps
        .get_mut(&phone.app_id())
        .unwrap()
        .lagging = true;
    let page = scripted_page(&s, me, "feed?limit=0");
    assert_eq!(page["items"], json!([]));
    assert_eq!(
        (
            page["next"].clone(),
            page["scanned_through"].clone(),
            page["more"].clone()
        ),
        (json!(format!("{generation}:0")), json!(0), json!(true))
    );
    assert_eq!(
        (page["head"].clone(), page["cursor"].clone()),
        (full["head"].clone(), full["cursor"].clone())
    );
    let page = scripted_page(&s, me, &format!("feed?after={generation}:{last}&limit=0"));
    assert_eq!(
        (
            page["items"].clone(),
            page["next"].clone(),
            page["more"].clone()
        ),
        (
            json!([]),
            json!(format!("{generation}:{last}")),
            json!(false)
        )
    );
    assert!(
        s.w.switch.app(&phone.app_id()).lagging,
        "a page with no items keeps the mark"
    );
}

/// A feed read of `rest` by own app `app` at alice's switch, as the holding transport takes
/// it.
fn feed_read(s: &Setup, app: [u8; 16], rest: &str) -> crate::transport::Request {
    crate::transport::Request {
        method: "GET".into(),
        origin: ORIGIN.into(),
        path_and_query: format!("/v1/{}/{rest}", s.w.alice.id()),
        headers: vec![
            crate::transport::Header::new(
                pubky_switch_core::http::header::IDENTITY,
                &s.w.alice.id(),
            ),
            crate::transport::Header::new(
                pubky_switch_core::http::header::APP,
                &pubky_switch_core::enc::zbase32_encode(&app),
            ),
        ],
        body: Vec::new(),
        timeout: crate::transport::TimeoutClass::Bulk,
    }
}

/// `limit=0` with `wait` at the holding transport, as at the service: `400` from the query,
/// before the read is admitted, so the app's lagging mark stays (Switch wire 7.4.4).
#[tokio::test]
async fn test_scripted_feed_page_with_no_items_and_a_wait_keeps_the_lagging_mark() {
    let s = Setup::new();
    let phone = s.join("phone").await;
    let app = phone.app_id();
    let transport = s.w.switch.holding_transport();
    s.w.switch.lock().apps.get_mut(&app).unwrap().lagging = true;
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        transport.send(feed_read(&s, app, "feed?limit=0&wait=5")),
    )
    .await
    .expect("answered")
    .unwrap();
    assert_eq!(answer.status, 400);
    assert!(s.w.switch.app(&app).lagging, "a refused read ends no mark");
}

/// `limit=0` with `wait` and nothing to show at the holding transport, as at the service:
/// `400` at once, never held (Switch wire 7.4.4).
#[tokio::test]
async fn test_scripted_feed_page_with_no_items_and_a_wait_is_never_held() {
    let s = Setup::new();
    let phone = s.join("phone").await;
    let app = phone.app_id();
    let generation = s.w.switch.lock().tip.generation;
    let last = s.w.switch.seq();
    let transport = s.w.switch.holding_transport();
    let rest = format!("feed?after={generation}:{last}&limit=0&wait=5");
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        transport.send(feed_read(&s, app, &rest)),
    )
    .await
    .expect("answered at once, not held")
    .unwrap();
    assert_eq!(answer.status, 400);
    assert_eq!(s.w.switch.held_reads(), 0);
}

/// The peer switch reads an append's query first: decoded, a parameter given twice and a
/// missing `apps_version` refused, before admission and the listing.
#[tokio::test]
async fn test_scripted_peer_append_query_is_read_first() {
    let s = Setup::new();
    let wallet = s.join("wallet").await;
    for query in ["apps_version=0&apps_version=0", "apps_version=%zz", ""] {
        let request = crate::transport::Request {
            method: "POST".into(),
            origin: PEER_ORIGIN.into(),
            path_and_query: format!("/v1/{}/inbox?{query}", s.w.bob.id()),
            headers: vec![
                crate::transport::Header::new(
                    pubky_switch_core::http::header::IDENTITY,
                    &s.w.alice.id(),
                ),
                crate::transport::Header::new(
                    pubky_switch_core::http::header::APP,
                    &pubky_switch_core::enc::zbase32_encode(&wallet.app_id()),
                ),
            ],
            body: Vec::new(),
            timeout: crate::transport::TimeoutClass::Bulk,
        };
        let response = s.peer.transport().send(request).await.unwrap();
        assert_eq!(response.status, 400, "{query}");
    }
}

/// The wallet holding `n1` sealed at epoch 2, whose key it lacks, and the key of epoch 3,
/// the current one, so it could write.
async fn record_waiting_for_an_older_key(
    s: &Setup,
    wallet: &mut App,
    phone: &mut App,
) -> RecordTarget {
    record_at_a_new_epoch(s, wallet, phone).await;
    s.w.next_doc(|body| body.data_epoch = 3);
    let has_keys = |scope: &str| SampleProtocol::default().has_keys(scope);
    let cert = wallet.cert().clone();
    for part in seal_bundle_parts(&s.w.alice, &cert, 3, 3, &has_keys).unwrap() {
        s.w.switch
            .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: cert.app_id(),
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
    }
    wallet.receive(None).await.unwrap();
    assert!(wallet.scope_key(3, "sample-a").is_some());
    assert!(wallet.scope_key(2, "sample-a").is_none());
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    assert_eq!(
        wallet.shared_record(&key).await.unwrap().unwrap().content,
        RecordContent::Unreadable(Unopened::KeyNotHeld { data_epoch: 2 })
    );
    target
}

/// A value the app can't open yet isn't overwritten by an update built on nothing.
#[tokio::test]
async fn test_records_update_waits_for_the_key_of_a_held_value() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = record_waiting_for_an_older_key(&s, &mut wallet, &mut phone).await;
    let key = wallet.record_key(&target).unwrap();
    let held = s.w.switch.record(&key).unwrap().state.version;
    let error = wallet
        .update_record(&target, vec![], |_| Some(value(&["mine"])))
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::NotNow(_))),
        "{error:?}"
    );
    assert_eq!(s.w.switch.record(&key).unwrap().state.version, held);
}

/// An explicit write overwrites a value held unopened for want of its key: the caller saw
/// it in `content` and chose to, and the write builds on the version held.
#[tokio::test]
async fn test_records_explicit_write_overwrites_a_value_waiting_for_its_key() {
    for delete in [false, true] {
        let s = Setup::new();
        let mut wallet = s.join("wallet").await;
        let mut phone = s.join("phone").await;
        let target = record_waiting_for_an_older_key(&s, &mut wallet, &mut phone).await;
        let key = wallet.record_key(&target).unwrap();
        let held = s.w.switch.record(&key).unwrap().state.version;
        let written = if delete {
            wallet.delete_record(&target, vec![]).await.unwrap()
        } else {
            wallet
                .put_record(&target, &value(&["mine"]), vec![])
                .await
                .unwrap()
        };
        let expected: Vec<&str> = if delete { vec![] } else { vec!["mine"] };
        assert_eq!(ids(written.content.value()), expected, "delete: {delete}");
        assert!(s.w.switch.record(&key).unwrap().state.version > held);
    }
}

/// A message's record job waits the same way: the message is delivered, the record left
/// as it is until the key arrives.
#[tokio::test]
async fn test_records_sent_record_job_waits_for_the_key_of_a_held_value() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = record_waiting_for_an_older_key(&s, &mut wallet, &mut phone).await;
    let key = wallet.record_key(&target).unwrap();
    let held = s.w.switch.record(&key).unwrap().state.version;
    let mut note = s.note("hello");
    note.record = Some(RecordJob {
        target: target.clone(),
        tag: Vec::new(),
    });
    let (msg_id, delivery) = wallet.send(note).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert_eq!(s.w.switch.record(&key).unwrap().state.version, held);
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.queued, vec![msg_id], "the record job is still owed");
}

/// A read the switch refuses for good is told apart from one it can't answer for now.
#[tokio::test]
async fn test_records_read_fresh_tells_a_refusal_from_an_unreachable_switch() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-c"]).await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    // Without the record's read scope: 403 permission_missing.
    assert_eq!(
        wallet.read_record_fresh(&target).await.unwrap(),
        RecordRead::Kept {
            record: None,
            reason: KeptReason::SwitchRefused {
                code: ErrorCode::PermissionMissing
            }
        }
    );
    // A 400, for good; a 503, for now.
    s.w.switch.fail_next(Fault::Error {
        path: "records/".into(),
        code: ErrorCode::BadRequest,
        current: Value::Null,
    });
    assert!(matches!(
        phone.read_record_fresh(&target).await.unwrap(),
        RecordRead::Kept {
            reason: KeptReason::SwitchRefused {
                code: ErrorCode::BadRequest
            },
            ..
        }
    ));
    s.w.switch.fail_next(Fault::Error {
        path: "records/".into(),
        code: ErrorCode::Unavailable,
        current: Value::Null,
    });
    assert!(matches!(
        phone.read_record_fresh(&target).await.unwrap(),
        RecordRead::Kept {
            reason: KeptReason::Unreachable(_),
            ..
        }
    ));
}

/// A sent message's record job whose held value waits for a key that never comes is tried
/// at every flush only until [`crate::app::SENT_RETENTION_MS`] after the message's first
/// acceptance: then it is given up, with a duty event naming the message, and the outbox
/// forgets the message, plaintext and all.
#[tokio::test]
async fn test_records_record_job_waiting_for_a_key_ends_at_the_retention() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let key = record_at_a_new_epoch(&s, &mut wallet, &mut phone).await;
    wallet.receive(None).await.unwrap();
    assert_eq!(
        wallet.shared_record(&key).await.unwrap().unwrap().content,
        RecordContent::Unreadable(Unopened::KeyNotHeld { data_epoch: 2 }),
    );
    let signed = wallet
        .sign_message(s.note("hello"))
        .unwrap()
        .with_record(crate::app::RecordJob {
            target: s.target("n1"),
            tag: b"sent".to_vec(),
        });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    let Some(Delivery::Accepted { accepted_at_ms }) = wallet.delivery(&msg_id).await.unwrap()
    else {
        panic!("accepted");
    };
    let out = format!("out/{msg_id}");
    let told = |events: &[AppEvent]| {
        events.iter().any(|e| {
            matches!(e, AppEvent::RecordJobDropped { msg_id: m, .. } if *m == msg_id) && e.is_duty()
        })
    };
    // Still owed, the value waiting for its key, just inside the retention.
    s.w.clock
        .set_ms(accepted_at_ms + crate::app::SENT_RETENTION_MS - 1);
    wallet.flush_outbox().await.unwrap();
    assert!(wallet.reader().exists(&out).await.unwrap());
    assert!(!told(&wallet.unacknowledged_events().await.unwrap()));
    // At it: given up and told, and the message forgotten.
    s.w.clock
        .set_ms(accepted_at_ms + crate::app::SENT_RETENTION_MS);
    wallet.flush_outbox().await.unwrap();
    assert!(!wallet.reader().exists(&out).await.unwrap());
    assert!(told(&wallet.unacknowledged_events().await.unwrap()));
    assert_eq!(wallet.delivery(&msg_id).await.unwrap(), None);
}

/// Giving up a record job leaves the message in the outbox while a re-send of it is owed:
/// only the record job goes, told by its duty event, and the re-send is still tried.
#[tokio::test]
async fn test_records_record_job_given_up_keeps_an_owed_resend() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    record_at_a_new_epoch(&s, &mut wallet, &mut phone).await;
    wallet.receive(None).await.unwrap();
    let signed = wallet
        .sign_message(s.note("hello"))
        .unwrap()
        .with_record(crate::app::RecordJob {
            target: s.target("n1"),
            tag: b"sent".to_vec(),
        });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    let Some(Delivery::Accepted { accepted_at_ms }) = wallet.delivery(&msg_id).await.unwrap()
    else {
        panic!("accepted");
    };
    // A re-send asked, and its delivery fails for now.
    s.peer
        .fail_next("inbox", ErrorCode::Unavailable, json!(null));
    let delivery = wallet.resend(&msg_id).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    s.w.clock
        .set_ms(accepted_at_ms + crate::app::SENT_RETENTION_MS);
    s.peer
        .fail_next("inbox", ErrorCode::Unavailable, json!(null));
    wallet.flush_outbox().await.unwrap();
    assert!(
        wallet
            .unacknowledged_events()
            .await
            .unwrap()
            .iter()
            .any(|e| matches!(
                e,
                AppEvent::RecordJobDropped { msg_id: m, .. } if *m == msg_id
            ))
    );
    assert!(
        wallet
            .reader()
            .exists(&format!("out/{msg_id}"))
            .await
            .unwrap()
    );
    assert!(matches!(
        wallet.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
}

/// The key of `target`'s record, created by `app` and then deleted.
async fn created_and_deleted(app: &mut App, target: &RecordTarget) -> [u8; 32] {
    app.put_record(target, &value(&["a"]), vec![])
        .await
        .unwrap();
    app.delete_record(target, vec![]).await.unwrap();
    app.record_key(target).unwrap()
}

/// A refused first write that is a delete is followed as a delete: once the service forgets
/// it, the app's write creates the record instead of naming it for good (Switch spec 8.2,
/// 10.3).
#[tokio::test]
async fn test_records_refused_first_delete_is_written_over_after_a_forget() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    s.protocol
        .refuses_deletes
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut phone = s.join("phone").await;
    let read = phone.read_record_fresh(&target).await.unwrap();
    assert!(
        matches!(&read, RecordRead::Kept { record: Some(held), reason: KeptReason::Refused }
            if held.flagged && held.content == RecordContent::Unreadable(Unopened::Refused)),
        "{read:?}"
    );
    s.protocol
        .refuses_deletes
        .store(false, std::sync::atomic::Ordering::SeqCst);
    read_on(&mut wallet).await;
    read_on(&mut phone).await;
    assert!(!held_at_switch(&s, &key), "forgotten");
    let written = put_over_a_forgotten_delete(&mut phone, &target, &value(&["b"])).await;
    assert_eq!(ids(written.content.value()), ["b"]);
}

/// `app` reads its feed and moves its cursor at the switch past what it read.
async fn read_on(app: &mut App) {
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
}

/// `app`'s write of `value` at `target`, whose delete the switch forgot: the first write
/// names the delete and is refused with nothing current, and the next creates the record
/// (Switch spec 10.3).
async fn put_over_a_forgotten_delete(
    app: &mut App,
    target: &RecordTarget,
    value: &[u8],
) -> crate::app::SharedRecord {
    let refused = app.put_record(target, value, vec![]).await;
    assert_eq!(
        refused.as_ref().err().and_then(AppError::code),
        Some(ErrorCode::Conflict),
        "{refused:?}"
    );
    app.put_record(target, value, vec![]).await.unwrap()
}

fn held_at_switch(s: &Setup, key: &[u8; 32]) -> bool {
    s.w.switch.lock().shared.records.contains_key(key)
}

#[tokio::test]
async fn test_scripted_records_deleted_key_is_forgotten_once_every_reader_passed() {
    // As at the service (Switch spec 10.3): once every current app's cursor is past the
    // delete, the key is forgotten, its read is `404`, and a create at it starts afresh,
    // after the write naming the delete is refused.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    read_on(&mut wallet).await;
    assert!(held_at_switch(&s, &key), "the phone hasn't passed it");
    read_on(&mut phone).await;
    assert!(!held_at_switch(&s, &key));
    let rest = format!("records/{}", pubky_switch_core::enc::b64(&key));
    assert_eq!(
        scripted_get(&s, Some(phone.app_id()), &rest),
        (404, json!("not_found"), true)
    );
    put_over_a_forgotten_delete(&mut wallet, &target, &value(&["b"])).await;
    read_on(&mut phone).await;
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["b"]);
}

#[tokio::test]
async fn test_scripted_records_deleted_key_waits_for_a_lagging_app_too() {
    // As at the service: a lagging app holds the key, with a `missed` item to pass or not,
    // since a listing doesn't show a key the switch forgot; once it reads past the delete,
    // the key goes.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    s.w.switch
        .lock()
        .apps
        .get_mut(&phone.app_id())
        .unwrap()
        .lagging = true;
    read_on(&mut wallet).await;
    assert!(held_at_switch(&s, &key), "lagging, nothing to pass");
    let now = s.w.clock.now_ms();
    s.w.switch.push_missed(1, now, now);
    read_on(&mut wallet).await;
    assert!(held_at_switch(&s, &key), "lagging, a missed item ahead");
    read_on(&mut phone).await;
    assert!(!held_at_switch(&s, &key));
}

#[tokio::test]
async fn test_scripted_records_deleted_key_a_divergent_upload_names_is_kept() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    s.w.switch
        .lock()
        .shared
        .divergent
        .insert(key, vec![[1; 32]]);
    read_on(&mut wallet).await;
    read_on(&mut phone).await;
    assert!(held_at_switch(&s, &key));
}

#[tokio::test]
async fn test_scripted_records_create_after_a_forget_is_taken_only_at_its_newer_version() {
    // The wallet holds the phone's record at version N. The phone deletes it; once both
    // have read past the delete the key is forgotten, and the phone creates it again,
    // keeping what the wallet saw (the sample protocol refuses a write that drops a seen
    // item). The wallet takes the new create, whose version is past every one the key had.
    // A switch that then shows the old write at N again, current past the newer one, gets
    // nothing taken: both versions are authenticated, so it is the switch's rollback, and the
    // wallet raises the alarm and keeps the newer write (Switch spec 10.1, 10.3, 8.2).
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&target).unwrap();
    read_on(&mut wallet).await;
    let old = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(old.content.value()), vec!["a"]);
    let old_write = s.w.switch.lock().shared.records.get(&key).cloned().unwrap();
    phone.delete_record(&target, vec![]).await.unwrap();
    read_on(&mut phone).await;
    assert!(
        held_at_switch(&s, &key),
        "the wallet hasn't read the delete"
    );
    read_on(&mut wallet).await;
    assert!(!held_at_switch(&s, &key), "forgotten");
    put_over_a_forgotten_delete(&mut phone, &target, &value(&["a", "b"])).await;
    read_on(&mut wallet).await;
    let new = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(new.content.value()), vec!["a", "b"]);
    assert!(
        new.version > old.version,
        "{:?} after {:?}",
        new.version,
        old.version
    );
    // The old write shown again, as a switch replaying it would.
    s.w.switch.lock().shared.records.insert(key, old_write);
    let listed = wallet.list_collection(&items()).await;
    assert!(
        matches!(listed, Err(AppError::Alarm(Alarm::Rollback { .. }))),
        "{listed:?}"
    );
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a", "b"]);
    assert_eq!(held.version, new.version);
}

#[tokio::test]
async fn test_scripted_records_create_after_a_forget_is_refused_where_the_mark_rules_it_out() {
    // As above, but the create after the forget drops an item the wallet saw: newer as it
    // is, the protocol's regression check refuses it against the wallet's seen mark, which
    // neither the delete nor the forget clears, and the wallet keeps the delete it held.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&target).unwrap();
    read_on(&mut wallet).await;
    phone.delete_record(&target, vec![]).await.unwrap();
    read_on(&mut phone).await;
    assert!(
        held_at_switch(&s, &key),
        "the wallet hasn't read the delete"
    );
    read_on(&mut wallet).await;
    assert!(!held_at_switch(&s, &key), "forgotten");
    put_over_a_forgotten_delete(&mut phone, &target, &value(&["b"])).await;
    read_on(&mut wallet).await;
    // The wallet keeps the delete it read, not the create.
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(held.content, RecordContent::Deleted);
}

/// A request of `method` to `rest` at alice's scripted switch from her app `app`, as it
/// arrives: the status, the code, whether it carries the head, and its `Switch-Server-Time`.
fn scripted_call(
    s: &Setup,
    app: [u8; 16],
    method: &str,
    rest: &str,
) -> (u16, Value, bool, Option<String>) {
    // A `GET` takes no body (Switch wire 7.1 Body caps).
    let body = if method == "GET" {
        Vec::new()
    } else {
        b"{}".to_vec()
    };
    scripted_request(s, app, method, rest, body)
}

/// As [`scripted_call`], a `POST` with `body`.
fn scripted_post(
    s: &Setup,
    app: [u8; 16],
    rest: &str,
    body: Vec<u8>,
) -> (u16, Value, bool, Option<String>) {
    scripted_request(s, app, "POST", rest, body)
}

fn scripted_request(
    s: &Setup,
    app: [u8; 16],
    method: &str,
    rest: &str,
    body: Vec<u8>,
) -> (u16, Value, bool, Option<String>) {
    use pubky_switch_core::http::header;
    let response =
        s.w.switch
            .handle(&crate::transport::Request {
                method: method.into(),
                origin: ORIGIN.into(),
                path_and_query: format!("/v1/{}/{rest}", s.w.alice.id()),
                headers: vec![
                    crate::transport::Header::new(header::IDENTITY, &s.w.alice.id()),
                    crate::transport::Header::new(
                        header::APP,
                        &pubky_switch_core::enc::zbase32_encode(&app),
                    ),
                ],
                body,
                timeout: crate::transport::TimeoutClass::Bulk,
            })
            .unwrap();
    let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    (
        response.status,
        body["code"].clone(),
        response.header(header::HEAD).is_some(),
        response.header(header::SERVER_TIME).map(str::to_owned),
    )
}

/// Switch wire 7.1 "`Switch-Head` on refusals", 7.2: every first call of an own app the
/// switch holds no record for but a batch is refused alike, whatever the route, before the
/// account's lock, as the service does (`verify_own_app`).
#[tokio::test]
async fn test_scripted_first_call_without_a_record_is_refused_alike_at_every_route() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    let committed = s.w.switch.lock().stamped_ms;
    s.w.clock.advance_ms(61_000);
    // At the last time stamped, since the refusal commits nothing (Switch wire 7.1
    // Timestamp).
    let service_time = pubky_switch_core::time::rfc3339(committed);
    let unknown = app_keys("unknown").app_id_bytes();
    let claim = pubky_switch_core::enc::b64(&[7; 32]);
    for (method, rest) in [
        ("GET", "feed".to_owned()),
        ("GET", "allow".to_owned()),
        ("GET", format!("claims/{claim}")),
        ("POST", "recovery/upload".to_owned()),
        ("GET", "directory".to_owned()),
        ("GET", "apps".to_owned()),
        ("PUT", "identity".to_owned()),
    ] {
        assert_eq!(
            scripted_call(&s, unknown, method, &rest),
            (403, json!("not_current"), false, Some(service_time.clone())),
            "{method} {rest}"
        );
    }
    // Not seen, and nothing stamped.
    assert_eq!(s.w.switch.app(&unknown).last_seen, None);
    assert_eq!(s.w.switch.lock().stamped_ms, committed);
    // A batch that doesn't parse goes on to the batch's checks; one that parses without
    // the app's `app.put` is refused alike (Switch wire 7.2).
    let (status, code, _, _) = scripted_call(&s, unknown, "POST", "ops");
    assert_ne!((status, code), (403, json!("not_current")));
    let cursor_only = crate::client::Batch::cursor_only(pubky_switch_core::ops::Position {
        generation: 1,
        seq: 1,
    });
    let stamped = pubky_switch_core::time::rfc3339(s.w.switch.lock().stamped_ms);
    assert_eq!(
        scripted_post(&s, unknown, "ops", cursor_only.body().to_vec()),
        (403, json!("not_current"), false, Some(stamped))
    );
    // An app the switch holds a record for goes on to the route.
    let (status, _, head, _) = scripted_call(&s, phone.app_id(), "GET", "allow");
    assert_eq!((status, head), (200, true));
    // Authentication comes before the staged answer (Switch wire 7.3 steps 5 and 7): at a
    // staged account the unrecorded app is refused alike, the phone answered `503 staged`.
    s.w.switch.lock().staged = true;
    for rest in ["feed", "recovery/upload"] {
        let (status, code, head, _) = scripted_call(
            &s,
            unknown,
            if rest == "feed" { "GET" } else { "POST" },
            rest,
        );
        assert_eq!(
            (status, code, head),
            (403, json!("not_current"), false),
            "{rest}"
        );
    }
    let (status, code, head, _) = scripted_call(&s, phone.app_id(), "GET", "feed");
    assert_eq!((status, code, head), (503, json!("staged"), true));
    // An account the switch doesn't hold is found missing first (Switch wire 7.3 step 2).
    s.w.switch.lock().not_hosted_unpinned = true;
    let (status, code, head, _) = scripted_call(&s, unknown, "GET", "feed");
    assert_eq!((status, code, head), (404, json!("not_found"), false));
}

/// The position in the request log of the last request matching `what`.
fn last_request(s: &Setup, what: impl Fn(&str) -> bool) -> Option<usize> {
    s.log().iter().rposition(|line| what(line))
}

/// How many times the protocol was handed the message `msg_id`.
fn handed(s: &Setup, msg_id: &str) -> usize {
    s.protocol
        .sample
        .received
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, id, _)| id == msg_id)
        .count()
}

/// Switch wire 7.4.4: after a `missed` item the app lists its collections before it hands
/// any later item of the read to its protocol, so an entry behind the item is never judged
/// on records the listing would change. Here the note's effect batch follows the listing.
#[tokio::test]
async fn test_records_missed_item_lists_before_a_later_entry_in_the_same_read() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    let missed = s.w.switch.push_missed(3, START, START + 1);
    let shop = s.peer.apps()[0].cert.app_id();
    let (seq, note) = s
        .peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "after the miss" }),
            &[app.app_id()],
        )
        .unwrap();
    assert!(seq > missed);
    let report = app.receive(None).await.unwrap();
    assert!(super::moves::has(&report.events, |e| matches!(
        e,
        AppEvent::Missed { .. }
    )));
    // The read stopped at the item, listed, and read on from it: the note came after.
    let listed = last_request(&s, |l| l.contains("records?collection")).unwrap();
    let from_item = format!("feed?after=1:{missed}&");
    let read_on = last_request(&s, |l| l.contains(&from_item)).unwrap();
    assert!(listed < read_on, "{:?}", s.log());
    // Processed once, in that read.
    assert_eq!(handed(&s, &note.msg_id), 1);
    assert!(app.cursor().seq >= seq);
    app.receive(None).await.unwrap();
    assert_eq!(handed(&s, &note.msg_id), 1);
}

/// A listing a `missed` item owes that fails ends the read at the item: nothing after it
/// is handed over or passed, and the next read lists first, then processes the entry once.
#[tokio::test]
async fn test_records_missed_item_listing_failure_consumes_nothing_after_it() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    let missed = s.w.switch.push_missed(3, START, START + 1);
    let shop = s.peer.apps()[0].cert.app_id();
    let (seq, note) = s
        .peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "after the miss" }),
            &[app.app_id()],
        )
        .unwrap();
    s.w.switch.fail_next(Fault::Unreachable {
        path: "records?collection".into(),
        after: 0,
    });
    app.receive(None).await.unwrap_err();
    assert_eq!(handed(&s, &note.msg_id), 0);
    assert!(app.cursor().seq >= missed && app.cursor().seq < seq);
    // Neither the owed listing nor the re-send notice is lost: the notice's writes are
    // committed with the item, and the listing stays owed.
    assert_eq!(s.protocol.sample.missed.lock().unwrap().len(), 1);
    assert!(
        app.protocol_get("sample", format!("missed/{missed}").as_bytes())
            .await
            .unwrap()
            .is_some()
    );
    let ns = crate::store::client_namespace(&app.app_id());
    assert!(s.w.store.get(&ns, b"list_due").unwrap().is_some());
    app.receive(None).await.unwrap();
    // The protocol was told of the miss once; the note handed over once, after the listing
    // the next read made first.
    assert_eq!(s.protocol.sample.missed.lock().unwrap().len(), 1);
    assert_eq!(handed(&s, &note.msg_id), 1);
    assert!(app.cursor().seq >= seq);
    let listed = last_request(&s, |l| l.contains("records?collection")).unwrap();
    let read_on = last_request(&s, |l| l.contains("/feed?")).unwrap();
    assert!(listed < read_on, "{:?}", s.log());
}

/// A switch that shows one `missed` item after another can't make a read list again and
/// again: each read lists at most once, a later item that owes a listing ends the read
/// there, and the next read lists first. Every entry is still handed over once.
#[tokio::test]
async fn test_records_missed_items_in_a_row_list_once_a_read() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    let shop = s.peer.apps()[0].cert.app_id();
    let mut notes = Vec::new();
    for text in ["one", "two", "three"] {
        s.w.switch.push_missed(3, START, START + 1);
        let (_, note) = s
            .peer
            .send_to(
                &s.w.switch,
                shop,
                "sample.note",
                json!({ "text": text }),
                &[app.app_id()],
            )
            .unwrap();
        notes.push(note);
    }
    let listings = |s: &Setup| {
        s.log()
            .iter()
            .filter(|l| l.contains("records?collection"))
            .count()
    };
    for read in 0..3 {
        let before = listings(&s);
        app.receive(None).await.unwrap();
        assert_eq!(listings(&s), before + 1, "read {read}");
        assert_eq!(handed(&s, &notes[read].msg_id), 1, "read {read}");
        if let Some(next) = notes.get(read + 1) {
            assert_eq!(handed(&s, &next.msg_id), 0, "read {read}");
        }
    }
    let before = listings(&s);
    app.receive(None).await.unwrap();
    assert_eq!(listings(&s), before);
    assert!(notes.iter().all(|note| handed(&s, &note.msg_id) == 1));
}

/// `missed` items in a row owe one listing, made after the last of them and before the
/// entry behind them, in one read.
#[tokio::test]
async fn test_records_missed_items_side_by_side_share_one_listing() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    let shop = s.peer.apps()[0].cert.app_id();
    let mut last = 0;
    for _ in 0..3 {
        last = s.w.switch.push_missed(3, START, START + 1);
    }
    let (seq, note) = s
        .peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "behind them" }),
            &[app.app_id()],
        )
        .unwrap();
    let listings = |s: &Setup| {
        s.log()
            .iter()
            .filter(|l| l.contains("records?collection"))
            .count()
    };
    let before = listings(&s);
    app.receive(None).await.unwrap();
    assert_eq!(listings(&s), before + 1);
    assert_eq!(s.protocol.sample.missed.lock().unwrap().len(), 3);
    assert_eq!(handed(&s, &note.msg_id), 1);
    assert!(app.cursor().seq >= seq);
    let from_last = format!("feed?after=1:{last}&");
    assert!(
        s.log().iter().any(|l| l.contains(&from_last)),
        "{:?}",
        s.log()
    );
}

/// Switch spec 8.2, wire 7.4.4: a `missed` item whose times don't parse asks for no
/// re-send, but still owes the listing, made before the entry behind it.
#[tokio::test]
async fn test_records_missed_item_with_unparsable_times_still_owes_the_listing() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    let missed = s.w.switch.push_missed_unparsable(3);
    let shop = s.peer.apps()[0].cert.app_id();
    let (seq, note) = s
        .peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "behind it" }),
            &[app.app_id()],
        )
        .unwrap();
    app.receive(None).await.unwrap();
    assert!(s.protocol.sample.missed.lock().unwrap().is_empty());
    let listed = last_request(&s, |l| l.contains("records?collection")).unwrap();
    let from_item = format!("feed?after=1:{missed}&");
    let read_on = last_request(&s, |l| l.contains(&from_item)).unwrap();
    assert!(listed < read_on, "{:?}", s.log());
    assert_eq!(handed(&s, &note.msg_id), 1);
    assert!(app.cursor().seq >= seq);
}

/// While a listing is owed and fails, no owed call of the protocol is made again before
/// it: the read ends at the listing (Switch spec 8.2). Once it succeeds, the owed call is
/// made.
#[tokio::test]
async fn test_records_owed_listing_goes_before_the_protocols_owed_calls() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    // The protocol fails its missed-entries call once: the call is owed.
    *s.protocol.sample.failing.lock().unwrap() = 1;
    s.w.switch.push_missed(3, START, START + 1);
    // The read that fails the call stops after the item, the listing owed.
    assert!(app.receive(None).await.unwrap().stopped);
    for _ in 0..2 {
        s.w.switch.fail_next(Fault::Unreachable {
            path: "records?collection".into(),
            after: 0,
        });
        app.receive(None).await.unwrap_err();
        assert!(s.protocol.sample.missed.lock().unwrap().is_empty());
    }
    app.receive(None).await.unwrap();
    assert_eq!(s.protocol.sample.missed.lock().unwrap().len(), 1);
}

/// A listing that can't be made yet, for want of the scope key of a collection's read
/// scope, stops the read before any entry is handed over; receiving waits for the key, and
/// nothing is passed or lost meanwhile.
#[tokio::test]
async fn test_records_owed_listing_waiting_for_a_key_hands_nothing_over() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    // The app lacks the key of its read scope at the current epoch.
    let held = app.state.scope_keys.keys.clone();
    app.state.scope_keys.keys.clear();
    let mut tx = app.tx().unwrap();
    tx.delete_prefix("scope/").unwrap();
    app.commit(tx).await.unwrap();
    let missed = s.w.switch.push_missed(3, START, START + 1);
    let shop = s.peer.apps()[0].cert.app_id();
    let (seq, note) = s
        .peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "behind it" }),
            &[app.app_id()],
        )
        .unwrap();
    for _ in 0..2 {
        app.receive(None).await.unwrap();
        assert_eq!(handed(&s, &note.msg_id), 0);
        assert!(app.cursor().seq >= missed && app.cursor().seq < seq);
    }
    // The key comes back: the next read lists, then hands the entry over once.
    let mut tx = app.tx().unwrap();
    for key in &held {
        tx.put(
            &crate::app::state::key::scope(key.data_epoch, &key.scope),
            key,
        )
        .unwrap();
    }
    app.commit(tx).await.unwrap();
    app.state.scope_keys.keys = held;
    app.receive(None).await.unwrap();
    assert_eq!(handed(&s, &note.msg_id), 1);
    assert!(app.cursor().seq >= seq);
}

/// `listing_owed` is true from a join, a restore and a `missed` item until a listing runs:
/// while it is, a record's absence from the copy decides nothing.
#[tokio::test]
async fn test_records_listing_owed_until_a_listing_runs() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    assert!(app.listing_owed().await.unwrap(), "after joining");
    app.receive(None).await.unwrap();
    assert!(
        !app.listing_owed().await.unwrap(),
        "after the first read's listing"
    );
    // A missed item whose listing fails: still owed.
    s.w.switch.push_missed(3, START, START + 1);
    s.w.switch.fail_next(Fault::Unreachable {
        path: "records?collection".into(),
        after: 0,
    });
    app.receive(None).await.unwrap_err();
    assert!(app.listing_owed().await.unwrap(), "after a missed item");
    app.receive(None).await.unwrap();
    assert!(!app.listing_owed().await.unwrap(), "after the listing ran");
    // A restore owes one too.
    let backup = app.backup().await.unwrap();
    let restored = App::restore(
        s.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert!(restored.listing_owed().await.unwrap(), "after a restore");
}

/// A listing that waits for a scope key reads no feed, so the part that answers a
/// full-bundle request never shows there: the app asks again once `KEY_REQUEST_RETRY_MS`
/// has passed. The signer's first answer still lacks the key; its second has it, and the
/// read after lists and hands the entry over. Each waiting read says why nothing arrives,
/// and rotates its receive key when due.
#[tokio::test]
async fn test_records_owed_listing_waiting_for_a_key_asks_again() {
    use crate::app::keys::KEY_REQUEST_RETRY_MS;
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    let shop = s.peer.apps()[0].cert.app_id();
    // A note opened, so a rotation comes due with time.
    s.peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "first" }),
            &[me],
        )
        .unwrap();
    app.receive(None).await.unwrap();
    app.state.scope_keys.keys.clear();
    let mut tx = app.tx().unwrap();
    tx.delete_prefix("scope/").unwrap();
    app.commit(tx).await.unwrap();
    s.w.switch.push_missed(3, START, START + 1);
    let (_, note) = s
        .peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "behind it" }),
            &[me],
        )
        .unwrap();
    let asked = |events: &[AppEvent]| {
        events
            .iter()
            .filter(|e| matches!(e, AppEvent::FullBundleRequested))
            .count()
    };
    let waits = |events: &[AppEvent]| {
        events
            .iter()
            .any(|e| matches!(e, AppEvent::ListingWaitsForKey))
    };
    // The read that passes the missed item asks once.
    let report = app.receive(None).await.unwrap();
    assert_eq!(asked(&report.events), 1, "{:?}", report.events);
    // The signer answers with a part that lacks the key: no request again yet.
    let no_keys = |_: &str| false;
    let epoch = s.w.switch.identity_doc().unwrap().data_epoch();
    for part in seal_bundle_parts(&s.w.alice, &cert, 1, epoch, &no_keys).unwrap() {
        s.w.switch
            .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: me,
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
    }
    let report = app.receive(None).await.unwrap();
    assert!(waits(&report.events), "{:?}", report.events);
    assert_eq!(asked(&report.events), 0);
    assert_eq!(handed(&s, &note.msg_id), 0);
    // Past the interval, and a day on so a rotation is due: asked again, and rotated.
    let keys = app.receive_key_numbers();
    s.w.clock.advance_ms(KEY_REQUEST_RETRY_MS.max(DAY_MS));
    let report = app.receive(None).await.unwrap();
    assert!(waits(&report.events), "{:?}", report.events);
    assert_eq!(asked(&report.events), 1, "{:?}", report.events);
    assert!(app.receive_key_numbers().len() > keys.len());
    assert_eq!(handed(&s, &note.msg_id), 0);
    // The second answer has the key: the next read lists, then hands the entry over.
    store_parts_for(&s, &cert);
    let report = app.receive(None).await.unwrap();
    assert!(!waits(&report.events), "{:?}", report.events);
    assert_eq!(handed(&s, &note.msg_id), 1);
}

/// A `missed` item met mid-read owes a listing that waits for a key no read fetches at its
/// start, a full-bundle request being outstanding: the read fetches the bundle at the item,
/// takes the key the signer stored since, lists, and hands the entry behind it over in the
/// same read.
#[tokio::test]
async fn test_records_listing_at_a_missed_item_fetches_the_key_and_reads_on() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    app.receive(None).await.unwrap();
    app.state.scope_keys.keys.clear();
    app.state.bundle.full_requested_ms = Some(s.w.clock.now_ms());
    let mut tx = app.tx().unwrap();
    tx.delete_prefix("scope/").unwrap();
    tx.put(crate::app::state::key::BUNDLE, &app.state.bundle)
        .unwrap();
    app.commit(tx).await.unwrap();
    s.w.switch.push_missed(3, START, START + 1);
    store_parts_for(&s, &cert);
    let shop = s.peer.apps()[0].cert.app_id();
    let (_, note) = s
        .peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "behind it" }),
            &[me],
        )
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert_eq!(handed(&s, &note.msg_id), 1, "{:?}", report.events);
    assert!(!app.listing_owed().await.unwrap());
}

/// Records held `Unreadable` whose reopened writes together pass one commit's size: the
/// reopening owed once their key arrives must not keep every later read from the feed.
#[tokio::test]
async fn test_records_reopening_too_large_for_one_commit_keeps_reads_going() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    wallet.receive(None).await.unwrap();
    s.w.next_doc(|body| body.data_epoch = 2);
    store_parts_for(&s, &phone.cert().clone());
    phone.receive(None).await.unwrap();
    let pad = "x".repeat(200 * 1024);
    let mut keys = Vec::new();
    for n in 0..80 {
        let target = s.target(&format!("big{n}"));
        let big = json!({ "items": ["a"], "pad": pad })
            .to_string()
            .into_bytes();
        phone.put_record(&target, &big, vec![]).await.unwrap();
        keys.push(phone.record_key(&target).unwrap());
    }
    // The records take more pages than one read's budget: reads go on while it says so.
    for _ in 0..8 {
        if !wallet.receive(None).await.unwrap().more {
            break;
        }
    }
    for key in &keys {
        let held = wallet.shared_record(key).await.unwrap().unwrap();
        assert!(held.content.value().is_none(), "held unreadable for now");
    }
    store_parts_for(&s, &wallet.cert().clone());
    let first = wallet.receive(None).await;
    // A note sent after the key: a read that gets to the feed takes it.
    let (seq, _) = s.w.note(wallet.app_id(), "after the key");
    let mut results = Vec::new();
    for _ in 0..3 {
        results.push(wallet.receive(None).await.map(|_| ()));
    }
    assert!(
        results.iter().all(Result::is_ok),
        "the first read after the key: {first:?}; later reads: {results:?}"
    );
    assert!(wallet.cursor().seq >= seq, "the feed is read on");
    for key in &keys {
        let held = wallet.shared_record(key).await.unwrap().unwrap();
        assert_eq!(ids(held.content.value()), vec!["a"]);
    }
}

/// A store whose commits that put a held record fail once, after `pass` of them went
/// through, while armed.
struct FailingRecordCommit {
    inner: MemoryStore,
    armed: std::sync::Mutex<Option<u32>>,
}

impl StateStore for FailingRecordCommit {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, crate::error::StoreError> {
        self.inner.get(ns, key)
    }

    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<crate::store::KeyValue>, crate::error::StoreError> {
        self.inner.scan(ns, prefix, after, limit)
    }

    fn commit(&self, batch: crate::store::WriteBatch) -> Result<(), crate::error::StoreError> {
        let puts_record = batch.writes().iter().any(|write| {
            matches!(write, crate::store::Write::Put { key, .. } if key.starts_with(b"rec/"))
        });
        if puts_record {
            let mut armed = self.armed.lock().unwrap();
            match *armed {
                Some(0) => {
                    *armed = None;
                    return Err(crate::error::StoreError::Unavailable);
                }
                Some(pass) => *armed = Some(pass - 1),
                None => {}
            }
        }
        self.inner.commit(batch)
    }

    fn acquire(
        &self,
        ns: &str,
        owner: crate::store::StoreOwner,
    ) -> Result<crate::store::AcquireOutcome, crate::store::StoreError> {
        self.inner.acquire(ns, owner)
    }

    fn commit_if(
        &self,
        ns: &str,
        owner: crate::store::StoreOwner,
        batch: crate::store::WriteBatch,
    ) -> Result<crate::store::CommitOutcome, crate::store::StoreError> {
        let puts_record = batch.writes().iter().any(|write| {
            matches!(write, crate::store::Write::Put { key, .. } if key.starts_with(b"rec/"))
        });
        if puts_record {
            let mut armed = self.armed.lock().unwrap();
            match *armed {
                Some(0) => {
                    *armed = None;
                    return Err(crate::error::StoreError::Unavailable);
                }
                Some(pass) => *armed = Some(pass - 1),
                None => {}
            }
        }
        self.inner.commit_if(ns, owner, batch)
    }
}

/// A reopening of more records than one commit takes that fails after its first commit:
/// the mark stays, since only the last commit clears it, and the rest open at the next
/// try.
#[tokio::test]
async fn test_records_reopening_cut_short_keeps_the_rest_owed() {
    let s = Setup::new();
    let store = Arc::new(FailingRecordCommit {
        inner: MemoryStore::new(),
        armed: std::sync::Mutex::new(None),
    });
    let request = s.approve(&app_keys("wallet"), &ALL_PERMISSIONS);
    let mut wallet = App::join(
        s.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        request,
    )
    .await
    .unwrap();
    let mut phone = s.join("phone").await;
    wallet.receive(None).await.unwrap();
    s.w.next_doc(|body| body.data_epoch = 2);
    store_parts_for(&s, &phone.cert().clone());
    phone.receive(None).await.unwrap();
    let pad = "x".repeat(200 * 1024);
    let mut keys = Vec::new();
    for n in 0..80 {
        let target = s.target(&format!("big{n}"));
        let big = json!({ "items": ["a"], "pad": pad })
            .to_string()
            .into_bytes();
        phone.put_record(&target, &big, vec![]).await.unwrap();
        keys.push(phone.record_key(&target).unwrap());
    }
    wallet.receive(None).await.unwrap();
    // The key arrives; the reopening's first commit goes through and its second fails.
    *store.armed.lock().unwrap() = Some(1);
    store_parts_for(&s, &wallet.cert().clone());
    let report = wallet.receive(None).await.unwrap();
    assert!(
        store.armed.lock().unwrap().is_none(),
        "the second commit failed"
    );
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::ReopeningOwed { .. })),
        "{:?}",
        report.events
    );
    wallet.receive(None).await.unwrap();
    for key in &keys {
        let held = wallet.shared_record(key).await.unwrap().unwrap();
        assert_eq!(ids(held.content.value()), vec!["a"]);
    }
    let ns = crate::store::client_namespace(&wallet.app_id());
    assert!(store.get(&ns, b"reopen").unwrap().is_none());
}

/// [`ItemsProtocol`], whose receive step reads the record `shared`: held not open for want
/// of a key, it waits for that key; open, it writes the note's own record.
struct SharedReader {
    items: ItemsProtocol,
    runs: std::sync::Mutex<usize>,
}

impl Protocol for SharedReader {
    fn name(&self) -> String {
        "sample".into()
    }

    fn has_keys(&self, scope: &str) -> bool {
        self.items.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.items.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.items.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.items.accepts(cert)
    }

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.items.check_body(message)
    }

    fn receive(
        &self,
        message: &ReceivedMessage,
        cx: &mut crate::app::ReceiveContext<'_>,
    ) -> Outcome {
        *self.runs.lock().unwrap() += 1;
        let shared = RecordTarget::new(items(), b"shared");
        match cx
            .record(&shared)
            .ok()
            .flatten()
            .map(|record| record.content)
        {
            Some(RecordContent::Unreadable(Unopened::KeyNotHeld { data_epoch })) => {
                Outcome::AwaitKey { data_epoch }
            }
            _ => {
                let own = RecordTarget::new(items(), message.message.msg_id.as_bytes());
                let _ = cx.put_record(&own, &value(&["seen"]), vec![]);
                Outcome::Apply(Effect::default())
            }
        }
    }

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.items.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.items.missed(missed)
    }

    fn collections(&self) -> Vec<Collection> {
        vec![items()]
    }
}

/// alice's wallet on a store whose reopening commits fail, with [`SharedReader`], and a note
/// waiting for the epoch-2 key that opens the record `shared`: the wallet, its store, the
/// protocol and the note's `seq`.
async fn waiting_on_shared(s: &Setup) -> (App, Arc<FailingReopen>, Arc<SharedReader>, u64) {
    let store = Arc::new(FailingReopen {
        inner: MemoryStore::new(),
        failing: std::sync::Mutex::new(0),
    });
    let protocol = Arc::new(SharedReader {
        items: ItemsProtocol::default(),
        runs: std::sync::Mutex::new(0),
    });
    let request = s.approve(&app_keys("wallet"), &ALL_PERMISSIONS);
    let mut wallet = App::join(
        s.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        protocol.clone(),
        World::config(),
        request,
    )
    .await
    .unwrap();
    let mut phone = s.join("phone").await;
    record_at_a_new_epoch(s, &mut wallet, &mut phone).await;
    phone
        .put_record(
            &RecordTarget::new(items(), b"shared"),
            &value(&["a"]),
            vec![],
        )
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let shop = s.peer.apps()[0].cert.app_id();
    let (seq, _) = s
        .peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "reads shared" }),
            &[wallet.app_id()],
        )
        .unwrap();
    wallet.receive(None).await.unwrap();
    assert_eq!(*protocol.runs.lock().unwrap(), 1);
    assert!(wallet.stored_at(seq).is_some(), "waits for the key");
    (wallet, store, protocol, seq)
}

/// An entry waiting for a key reads a record the key opens. The key arrives in a read whose
/// reopening fails at both its tries: the entry isn't run on the record still held not
/// open. The next read reopens at its start and takes the entry there, before the feed.
#[tokio::test]
async fn test_records_waiting_entry_waits_for_an_owed_reopening() {
    let s = Setup::new();
    let (mut wallet, store, protocol, seq) = waiting_on_shared(&s).await;
    // The key comes; both tries of that read's reopening fail.
    *store.failing.lock().unwrap() = 2;
    store_parts_for(&s, &wallet.cert().clone());
    wallet.receive(None).await.unwrap();
    assert_eq!(*store.failing.lock().unwrap(), 0);
    assert_eq!(
        *protocol.runs.lock().unwrap(),
        1,
        "not run on a record still not open"
    );
    // The next read reopens, then takes the entry before it reads the feed.
    let from = s.log().len();
    wallet.receive(None).await.unwrap();
    assert_eq!(*protocol.runs.lock().unwrap(), 2);
    assert!(wallet.stored_at(seq).is_none());
    let log = s.log();
    let read = &log[from..];
    let effect = read.iter().position(|line| line.contains("/ops")).unwrap();
    // The read of a page with no items that verifies a service time before the effect is
    // sent isn't the feed's (Switch spec 10.1).
    let feed = read
        .iter()
        .position(|line| line.contains("/feed") && !line.ends_with("limit=0"))
        .unwrap();
    assert!(effect < feed, "{read:?}");
}

/// The same, with the next read's reopening at its start failing too: the retries there
/// pass the entry over, and it is taken at the read's end, once the reopening after the
/// page went through.
#[tokio::test]
async fn test_records_waiting_entry_passed_over_while_the_start_reopening_fails() {
    let s = Setup::new();
    let (mut wallet, store, protocol, seq) = waiting_on_shared(&s).await;
    *store.failing.lock().unwrap() = 3;
    store_parts_for(&s, &wallet.cert().clone());
    wallet.receive(None).await.unwrap();
    assert_eq!(*protocol.runs.lock().unwrap(), 1);
    wallet.receive(None).await.unwrap();
    assert_eq!(*store.failing.lock().unwrap(), 0);
    assert!(
        wallet.stored_at(seq).is_none(),
        "taken once the records opened"
    );
    assert_eq!(*protocol.runs.lock().unwrap(), 2);
}

/// A new entry read after the key bundle part on the same page, whose step reads a record
/// held `Unreadable` that the key opens: the reopening waits for the page's end, so the
/// step still finds the record not open and waits for a key the app now holds. Once the
/// record opens the entry is taken.
#[tokio::test]
async fn test_records_entry_after_the_key_on_its_page_is_taken_once_the_record_opens() {
    let s = Setup::new();
    let protocol = Arc::new(SharedReader {
        items: ItemsProtocol::default(),
        runs: std::sync::Mutex::new(0),
    });
    let request = s.approve(&app_keys("wallet"), &ALL_PERMISSIONS);
    let mut wallet = App::join(s.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap();
    let mut phone = s.join("phone").await;
    record_at_a_new_epoch(&s, &mut wallet, &mut phone).await;
    let shared = RecordTarget::new(items(), b"shared");
    phone
        .put_record(&shared, &value(&["a"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let key = wallet.record_key(&shared).unwrap();
    assert!(
        wallet
            .shared_record(&key)
            .await
            .unwrap()
            .unwrap()
            .content
            .value()
            .is_none(),
        "held unreadable for now"
    );
    // The key's part, then a note, both unread: one page.
    store_parts_for(&s, &wallet.cert().clone());
    let shop = s.peer.apps()[0].cert.app_id();
    let (seq, _) = s
        .peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "after the key" }),
            &[wallet.app_id()],
        )
        .unwrap();
    let mut events = Vec::new();
    for _ in 0..4 {
        s.w.clock.advance_ms(crate::app::MAX_CURSOR_DEFER_MS + 1);
        events.extend(wallet.receive(None).await.unwrap().events);
    }
    assert_eq!(
        ids(wallet
            .shared_record(&key)
            .await
            .unwrap()
            .unwrap()
            .content
            .value()),
        vec!["a"],
        "the record opened"
    );
    assert!(
        wallet.stored_at(seq).is_none(),
        "still stored as {:?} after {} runs; {:?}",
        wallet.stored_at(seq).map(|stored| stored.reason),
        *protocol.runs.lock().unwrap(),
        events
            .iter()
            .filter(|e| matches!(e, AppEvent::Parked { .. } | AppEvent::AwaitingKeys { .. }))
            .collect::<Vec<_>>()
    );
}

/// The same with the key taken by the step's own fetch. The wallet read `shared`, sealed
/// at a data epoch it doesn't know yet, from the switch: held `Unreadable`, and no key is
/// missing for the epoch it knows, so no full bundle is asked for. The feed then shows the
/// epoch rise, then a note whose step reads `shared` and fetches the key bundle, whose part
/// the feed shows only after the note. The step runs again on the record still not open, as
/// the reopening waits for the page's end; once the record opens the entry is taken in the
/// same read.
#[tokio::test]
async fn test_records_entry_whose_own_fetch_takes_the_key_is_taken_once_the_record_opens() {
    let s = Setup::new();
    let protocol = Arc::new(SharedReader {
        items: ItemsProtocol::default(),
        runs: std::sync::Mutex::new(0),
    });
    let request = s.approve(&app_keys("wallet"), &ALL_PERMISSIONS);
    let mut wallet = App::join(s.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap();
    let mut phone = s.join("phone").await;
    wallet.receive(None).await.unwrap();
    s.w.next_doc(|body| body.data_epoch = 2);
    store_parts_for(&s, &phone.cert().clone());
    phone.receive(None).await.unwrap();
    let shared = RecordTarget::new(items(), b"shared");
    phone
        .put_record(&shared, &value(&["a"]), vec![])
        .await
        .unwrap();
    let held = wallet.read_record(&shared).await.unwrap().unwrap();
    assert!(held.content.value().is_none(), "{:?}", held.content);
    let key = wallet.record_key(&shared).unwrap();
    let shop = s.peer.apps()[0].cert.app_id();
    let (seq, _) = s
        .peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "reads shared" }),
            &[wallet.app_id()],
        )
        .unwrap();
    // The wallet's part is stored after the note: the feed shows it after the note, and
    // a fetch made at the note reads it.
    store_parts_for(&s, &wallet.cert().clone());
    let report = wallet.receive(None).await.unwrap();
    assert_eq!(
        ids(wallet
            .shared_record(&key)
            .await
            .unwrap()
            .unwrap()
            .content
            .value()),
        vec!["a"],
        "the record opened"
    );
    assert!(
        wallet.stored_at(seq).is_none(),
        "still stored as {:?} after {} runs; {:?}",
        wallet.stored_at(seq).map(|stored| stored.reason),
        *protocol.runs.lock().unwrap(),
        report.events
    );
}

/// An alarm raised in the reopening at a read's start ends the read: nothing is handed to
/// the protocol after it, and no feed is read and nothing sent. Here a held record's proof
/// is another write's, which the reopening judges a rollback (Switch wire 6.2 step 2).
#[tokio::test]
async fn test_records_alarm_in_the_reopening_ends_the_read() {
    let s = Setup::new();
    let (mut wallet, store, protocol, _) = waiting_on_shared(&s).await;
    // The key comes; the reopening fails at both tries of that read, and stays owed.
    *store.failing.lock().unwrap() = 2;
    store_parts_for(&s, &wallet.cert().clone());
    wallet.receive(None).await.unwrap();
    assert!(
        wallet
            .reader()
            .exists(crate::app::records::REOPEN_DUE)
            .await
            .unwrap()
    );
    // `n1`, held `Unreadable`, now carries the proof of `shared`'s write.
    let n1 = crate::app::records::record_key_of(&wallet.record_key(&s.target("n1")).unwrap());
    let shared = crate::app::records::record_key_of(
        &wallet
            .record_key(&RecordTarget::new(items(), b"shared"))
            .unwrap(),
    );
    let mut held: serde_json::Value = wallet.reader().get(&n1).await.unwrap().unwrap();
    let other: serde_json::Value = wallet.reader().get(&shared).await.unwrap().unwrap();
    assert!(
        other["proof"].is_object() || other["proof"].is_string(),
        "{other}"
    );
    held["proof"] = other["proof"].clone();
    let mut tx = wallet.tx().unwrap();
    tx.put(&n1, &held).unwrap();
    wallet.commit(tx).await.unwrap();
    // A new note in the feed, whose step would run once the read reached it.
    let shop = s.peer.apps()[0].cert.app_id();
    s.peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "after the alarm" }),
            &[wallet.app_id()],
        )
        .unwrap();
    let runs = *protocol.runs.lock().unwrap();
    let from = s.log().len();
    let (error, events) = match wallet.receive(None).await {
        Ok(report) => (None, report.events),
        Err(error) => (Some(error), wallet.take_events()),
    };
    let alarm = events
        .iter()
        .position(|e| matches!(e, AppEvent::Alarm(Alarm::Rollback { .. })));
    assert!(alarm.is_some(), "{error:?} {events:?}");
    assert!(
        matches!(error, Some(AppError::Alarm(Alarm::Rollback { .. }))),
        "{error:?} {events:?}"
    );
    assert_eq!(
        *protocol.runs.lock().unwrap(),
        runs,
        "nothing handed over: {events:?}"
    );
    let after: Vec<&AppEvent> = events[alarm.unwrap()..]
        .iter()
        .filter(|e| {
            matches!(
                e,
                AppEvent::MessageReceived { .. }
                    | AppEvent::Unparked { .. }
                    | AppEvent::ReopeningOwed { .. }
            )
        })
        .collect();
    assert!(after.is_empty(), "{after:?}");
    let log = s.log();
    let read = &log[from..];
    assert!(
        !read
            .iter()
            .any(|line| line.contains("/ops") || line.contains("/feed")),
        "{read:?}"
    );
}

/// A reopening that keeps failing is tried at most twice a read, and once more at the
/// next read: each failed try is reported once.
#[tokio::test]
async fn test_records_failing_reopening_is_tried_twice_a_read() {
    let s = Setup::new();
    let (mut wallet, store, _, _) = waiting_on_shared(&s).await;
    *store.failing.lock().unwrap() = 100;
    store_parts_for(&s, &wallet.cert().clone());
    let owed = |events: &[AppEvent]| {
        events
            .iter()
            .filter(|e| matches!(e, AppEvent::ReopeningOwed { .. }))
            .count()
    };
    let report = wallet.receive(None).await.unwrap();
    assert_eq!(owed(&report.events), 2, "{:?}", report.events);
    // A note, so the next read reads a page past its start.
    let shop = s.peer.apps()[0].cert.app_id();
    s.peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "another" }),
            &[wallet.app_id()],
        )
        .unwrap();
    let report = wallet.receive(None).await.unwrap();
    assert_eq!(owed(&report.events), 2, "{:?}", report.events);
    // Outside a read it is tried again.
    wallet.fetch_key_bundle().await.unwrap();
    assert_eq!(owed(&wallet.take_events()), 1);
    // Once the store takes it, the record opens.
    *store.failing.lock().unwrap() = 0;
    wallet.receive(None).await.unwrap();
    assert!(
        !wallet
            .reader()
            .exists(crate::app::records::REOPEN_DUE)
            .await
            .unwrap()
    );
}

/// A record write sealed at an epoch whose key a later item of the same page brings: the
/// write is taken unreadable in the page's open writes, the key's fetch reopens what the
/// store holds, and the record must still open once the key is held.
#[tokio::test]
async fn test_records_key_on_the_same_page_as_the_unreadable_write_opens_it() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    wallet.receive(None).await.unwrap();
    s.w.next_doc(|body| body.data_epoch = 2);
    store_parts_for(&s, &phone.cert().clone());
    phone.receive(None).await.unwrap();
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&target).unwrap();
    // The wallet's key comes after the write, and both are read in one page.
    store_parts_for(&s, &wallet.cert().clone());
    wallet.receive(None).await.unwrap();
    assert!(
        wallet.scope_key(2, "sample-a").is_some(),
        "the key was taken"
    );
    for _ in 0..2 {
        wallet.receive(None).await.unwrap();
    }
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(
        ids(held.content.value()),
        vec!["a"],
        "held {:?} with its key held",
        held.content
    );
}

#[tokio::test]
async fn test_scripted_records_condition_zero_names_only_an_absent_key() {
    // As at the service (Switch wire 6.3): a `record_version` condition of `{0, 0}` holds
    // only where the switch holds nothing; a live record and a kept delete both fail it,
    // and the delete holds by its own version, which the app's condition names.
    use pubky_switch_core::ops::Condition;
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    let fenced = |version: RecordVersion, pubky: u8| {
        OpBatch::new().op_if(
            OpKind::DenyPut { pubky: [pubky; 32] },
            vec![Condition::RecordVersion { key, version }],
        )
    };
    wallet
        .submit_batch(fenced(RecordVersion::NONE, 7))
        .await
        .unwrap();
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    assert!(
        wallet
            .submit_batch(fenced(RecordVersion::NONE, 9))
            .await
            .is_err(),
        "live"
    );
    let deleted = wallet.delete_record(&target, vec![]).await.unwrap();
    assert!(
        wallet
            .submit_batch(fenced(RecordVersion::NONE, 8))
            .await
            .is_err(),
        "a kept delete"
    );
    assert_eq!(
        wallet.record_condition(&key).await.unwrap(),
        Condition::RecordVersion {
            key,
            version: deleted.version
        }
    );
    wallet
        .submit_batch(fenced(deleted.version, 6))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_scripted_records_deleted_key_taken_from_an_upload_is_kept() {
    // As at the service: a delete taken from a recovery upload has no chain item here to
    // stand for it, so its key stays, every reader past it or not.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    s.w.switch
        .lock()
        .shared
        .records
        .get_mut(&key)
        .unwrap()
        .uploaded = Some(true);
    read_on(&mut wallet).await;
    read_on(&mut phone).await;
    assert!(held_at_switch(&s, &key));
}

#[tokio::test]
async fn test_scripted_records_deleted_key_doesnt_wait_for_a_revoked_app() {
    // As at the service: a revoked or departed app no longer reads or uploads, so the keys
    // it hadn't passed go once every other listed app has.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let phone = s.join("phone").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    read_on(&mut wallet).await;
    assert!(held_at_switch(&s, &key), "the phone hasn't passed it");
    s.w.switch
        .lock()
        .apps
        .get_mut(&phone.app_id())
        .unwrap()
        .departed = true;
    // The switch judges at a cursor move: the wallet's next write gives it one.
    wallet
        .put_record(&s.target("n2"), &value(&["b"]), vec![])
        .await
        .unwrap();
    read_on(&mut wallet).await;
    assert!(!held_at_switch(&s, &key));
}

#[tokio::test]
async fn test_scripted_records_refused_delete_is_written_over_after_a_forget() {
    // The signer removes the wallet, distrusted from an hour ago, while the switch still
    // takes its delete: the phone refuses the delete and follows its version, so its next
    // write builds on it and puts back what it trusts (Switch spec 8.2). The phone is the
    // only app the switch waits for, so once it reads past the delete the key may be
    // forgotten; the phone's write must still be taken.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    read_on(&mut phone).await;
    let me = wallet.app_id();
    let doc =
        s.w.signer
            .sign_next(|body| {
                body.apps.retain(|app| app.app_id != me);
                body.removed.push(RemovedApp {
                    app_id: me,
                    distrust_from: START - HOUR,
                })
            })
            .unwrap();
    wallet.delete_record(&target, vec![]).await.unwrap();
    assert!(matches!(
        phone.refresh_identity().await.unwrap(),
        IdentityRefresh::Newer { .. }
    ));
    s.w.switch.deliver_identity(&doc).unwrap();
    read_on(&mut phone).await;
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    assert!(held.flagged);
    assert!(
        !held.not_taken,
        "a write naming its writer is flagged instead"
    );
    // Its write names the delete; once the switch forgot it, that write is refused with
    // nothing current, and the next one creates the record.
    let forgotten = !held_at_switch(&s, &key);
    let mut written = phone.put_record(&target, &value(&["a"]), vec![]).await;
    if forgotten {
        assert_eq!(
            written.as_ref().err().and_then(AppError::code),
            Some(ErrorCode::Conflict),
            "{written:?}"
        );
        written = phone.put_record(&target, &value(&["a"]), vec![]).await;
    }
    assert!(written.is_ok(), "forgotten: {forgotten}; {written:?}");
}

#[tokio::test]
async fn test_scripted_records_delete_flagged_as_a_regression_is_written_over_after_a_forget() {
    // A delete the protocol finds goes back on what the phone has seen: the phone keeps the
    // record and follows the delete's version, so its next write names that delete. Once
    // both readers have passed it and the switch forgot the key, that write is refused with
    // nothing current, and the phone's next write creates the record.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    read_on(&mut phone).await;
    s.protocol
        .deletes_regress
        .store(true, std::sync::atomic::Ordering::SeqCst);
    wallet.delete_record(&target, vec![]).await.unwrap();
    read_on(&mut phone).await;
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    assert!(held.flagged);
    read_on(&mut wallet).await;
    assert!(!held_at_switch(&s, &key), "both readers passed the delete");
    let refused = phone.put_record(&target, &value(&["a"]), vec![]).await;
    assert_eq!(
        refused.as_ref().err().and_then(AppError::code),
        Some(ErrorCode::Conflict),
        "{refused:?}"
    );
    let written = phone.put_record(&target, &value(&["a"]), vec![]).await;
    assert!(written.is_ok(), "{written:?}");
    assert_eq!(
        ids(written.unwrap().content.value()),
        vec!["a"],
        "the phone put back what it trusts"
    );
}

#[tokio::test]
async fn test_scripted_records_deleted_key_waits_for_a_listed_app_not_registered() {
    // As at the service: an app the held `identity.json` lists that hasn't registered here
    // yet holds every key, so the readers that have passed the delete free nothing.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let _later = s.approve(&app_keys("later"), &ALL_PERMISSIONS);
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    read_on(&mut wallet).await;
    read_on(&mut phone).await;
    assert!(held_at_switch(&s, &key), "the listed app hasn't registered");
}

#[tokio::test]
async fn test_scripted_records_deleted_key_doesnt_wait_for_a_kept_app_id() {
    // As at the service: an App ID kept for good (revoked) isn't waited for, though the held
    // `identity.json` still lists it.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let phone = s.join("phone").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    read_on(&mut wallet).await;
    assert!(held_at_switch(&s, &key), "the phone hasn't passed it");
    s.w.switch.lock().kept_app_ids.push(phone.app_id());
    wallet
        .put_record(&s.target("n2"), &value(&["b"]), vec![])
        .await
        .unwrap();
    read_on(&mut wallet).await;
    assert!(!held_at_switch(&s, &key));
}

#[tokio::test]
async fn test_scripted_records_condition_on_a_forgotten_delete_is_refused_once() {
    use pubky_switch_core::ops::Condition;
    // The app's condition on a record it holds as deleted names the delete, which holds
    // while the switch keeps it (Switch wire 6.3, spec 10.3). Once the switch forgets the
    // key the condition fails with `{0, 0}` current: the app takes the key as absent, so
    // the protocol's next condition holds, with no refusal for good.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    let fenced = |condition: Condition, pubky: u8| {
        OpBatch::new().op_if(OpKind::DenyPut { pubky: [pubky; 32] }, vec![condition])
    };
    let condition = wallet.record_condition(&key).await.unwrap();
    let Condition::RecordVersion { version, .. } = condition else {
        panic!("{condition:?}")
    };
    assert!(!version.is_none(), "the delete is named by its version");
    wallet.submit_batch(fenced(condition, 8)).await.unwrap();
    read_on(&mut wallet).await;
    read_on(&mut phone).await;
    assert!(!held_at_switch(&s, &key), "forgotten");
    let refused = wallet.submit_batch(fenced(condition, 9)).await;
    assert_eq!(
        refused.as_ref().err().and_then(AppError::code),
        Some(ErrorCode::Conflict),
        "{refused:?}"
    );
    let absent = wallet.record_condition(&key).await.unwrap();
    assert_eq!(
        absent,
        Condition::RecordVersion {
            key,
            version: RecordVersion::NONE
        }
    );
    wallet.submit_batch(fenced(absent, 10)).await.unwrap();
}

#[tokio::test]
async fn test_records_read_finding_a_delete_forgotten_lets_the_next_write_create() {
    // A read answered `404` over a held delete takes the key as forgotten, so the next
    // write creates the record at once rather than naming the delete and being refused
    // (Switch spec 10.3).
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    read_on(&mut wallet).await;
    read_on(&mut phone).await;
    assert!(!held_at_switch(&s, &key), "forgotten");
    wallet.read_record(&target).await.unwrap();
    let created = wallet.put_record(&target, &value(&["b"]), vec![]).await;
    assert!(created.is_ok(), "{created:?}");
}

/// The key was absent both before the create and after the service forgot its delete.
/// Only the latter head covers the application's intervening observations.
#[tokio::test]
async fn test_records_hosted_absence_covers_the_write_the_wallet_follows() {
    Box::pin(async {
        let s = Setup::new();
        let mut wallet = s.join("wallet").await;
        let mut phone = s.join("phone").await;
        let target = s.target("shared");
        let before = s.w.switch.seq();
        assert!(matches!(
            wallet.read_record_fresh(&target).await.unwrap(),
            RecordRead::Kept {
                record: None,
                reason: KeptReason::NotFound
            }
        ));
        let first = wallet
            .put_record(&target, &value(&["a"]), vec![])
            .await
            .unwrap();
        phone.read_record(&target).await.unwrap();
        phone.delete_record(&target, vec![]).await.unwrap();
        s.protocol
            .refuses_deletes
            .store(true, std::sync::atomic::Ordering::SeqCst);
        read_on(&mut wallet).await;
        read_on(&mut phone).await;
        assert!(!held_at_switch(&s, &first.key));
        let held = wallet.shared_record(&first.key).await.unwrap().unwrap();
        assert_eq!(held.content, first.content);
        assert!(held.flagged);

        // The hosted absence at the earlier genuine chain head predates this key's
        // creation. It cannot describe the currently followed write or clear it.
        s.w.switch.fail_next(Fault::Head {
            path: "/records/".into(),
            at: Some(before),
            forked: false,
        });
        assert_eq!(
            wallet.read_record_fresh(&target).await.unwrap(),
            RecordRead::Kept {
                record: Some(held.clone()),
                reason: KeptReason::Refused
            }
        );
        let id = wallet.app_id();
        drop(wallet);
        let mut wallet = App::load(s.env(), s.protocol.clone(), World::config(), id)
            .await
            .unwrap();
        assert_eq!(wallet.shared_record(&first.key).await.unwrap(), Some(held));

        // Both readers passed the actual delete. The current hosted answer now covers
        // it, and an ordinary new write uses the absent base.
        assert!(matches!(
            wallet.read_record_fresh(&target).await.unwrap(),
            RecordRead::Kept {
                reason: KeptReason::NotFound,
                ..
            }
        ));
        let written = wallet
            .put_record(&target, &value(&["a", "b"]), vec![])
            .await
            .unwrap();
        assert_eq!(ids(written.content.value()), ["a", "b"]);
    })
    .await;
}

#[tokio::test]
async fn test_records_not_hosted_read_over_a_held_delete_marks_nothing_gone() {
    // The `404` saying the switch doesn't host the identity says nothing of the record
    // (Switch spec 12.7 step 5): over a held delete the switch still keeps, the next write
    // names that delete, as before the read, rather than creating at `{0, 0}`.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    assert!(held_at_switch(&s, &key), "kept");
    s.w.switch.fail_next(Fault::Error {
        path: "/records/".into(),
        code: ErrorCode::NotFound,
        current: pubky_switch_core::http::not_hosted_current(),
    });
    let read = wallet.read_record_fresh(&target).await;
    assert!(
        matches!(
            read,
            Ok(RecordRead::Kept {
                reason: KeptReason::Unreachable(_),
                ..
            })
        ),
        "{read:?}"
    );
    let written = wallet.put_record(&target, &value(&["b"]), vec![]).await;
    assert!(written.is_ok(), "{written:?}");
    // A `404` at an account the switch hosts does mark the delete gone: the next write
    // creates, and the switch, which still keeps the delete, refuses it.
    wallet.delete_record(&target, vec![]).await.unwrap();
    s.w.switch.fail_next(Fault::Error {
        path: "/records/".into(),
        code: ErrorCode::NotFound,
        current: serde_json::Value::Null,
    });
    wallet.read_record_fresh(&target).await.unwrap();
    let refused = wallet.put_record(&target, &value(&["c"]), vec![]).await;
    assert_eq!(
        refused.as_ref().err().and_then(AppError::code),
        Some(ErrorCode::Conflict),
        "{refused:?}"
    );
}

#[tokio::test]
async fn test_records_write_followed_after_a_forgotten_delete_is_named() {
    // The wallet's delete is forgotten, and a read marks it so. The phone then creates the
    // record without what the wallet saw, which the wallet follows rather than takes
    // (Switch spec 8.2): the next write names that create, not the absence before it.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    read_on(&mut wallet).await;
    read_on(&mut phone).await;
    assert!(!held_at_switch(&s, &key), "forgotten");
    wallet.read_record(&target).await.unwrap();
    let created = put_over_a_forgotten_delete(&mut phone, &target, &value(&["p"])).await;
    read_on(&mut wallet).await;
    assert!(wallet.shared_record(&key).await.unwrap().unwrap().flagged);
    let written = wallet
        .put_record(&target, &value(&["a", "w"]), vec![])
        .await;
    assert!(written.is_ok(), "{written:?}");
    let at_switch = s.w.switch.lock().shared.records.get(&key).cloned().unwrap();
    assert!(at_switch.state.version > created.version);
}

#[tokio::test]
async fn test_records_view_of_the_held_delete_after_a_404_is_named() {
    // A `404` marks the held delete forgotten; a later view shows the switch holding that
    // very delete, as a new service does once the delete is uploaded to it (Switch spec
    // 12.6). The mark goes, and the next write names the delete.
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    s.w.switch.fail_next(Fault::Error {
        path: format!("records/{}", pubky_switch_core::enc::b64(&key)),
        code: ErrorCode::NotFound,
        current: json!(null),
    });
    wallet.read_record(&target).await.unwrap();
    wallet.read_record(&target).await.unwrap();
    let written = wallet.put_record(&target, &value(&["b"]), vec![]).await;
    assert!(written.is_ok(), "{written:?}");
}

#[tokio::test]
async fn test_records_update_returns_the_conflict_when_a_delete_lands() {
    // A try built on a value never turns into a create over a delete: the call returns
    // the conflict, and `change` isn't asked again with nothing (Switch spec 10.3).
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    read_on(&mut phone).await;
    phone.delete_record(&target, vec![]).await.unwrap();
    let mut asked = Vec::new();
    let updated = wallet
        .update_record(&target, vec![], |current| {
            asked.push(current.map(<[u8]>::to_vec));
            Some(value(&["a", "b"]))
        })
        .await;
    assert_eq!(
        updated.as_ref().err().and_then(AppError::code),
        Some(ErrorCode::Conflict),
        "{updated:?}"
    );
    assert_eq!(asked, vec![Some(value(&["a"]))], "asked once, on the value");
    let key = wallet.record_key(&target).unwrap();
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(held.content, RecordContent::Deleted);
}

/// What the record job of the test below was queued against.
#[derive(Clone, Copy, Debug)]
enum JobBase {
    /// A live value.
    Value,
    /// A delete the wallet holds.
    Delete,
    /// Nothing: the key was never written.
    Nothing,
}

/// A record job queued against `base`, its first write refused for now; then the phone
/// writes the record and deletes it, and the wallet flushes without reading. Its first try
/// is refused and its read takes the phone's delete: the job doesn't write over it. It
/// stops, and the protocol is told which record and which delete, once (Switch spec 10.3).
async fn record_job_stops_at_a_later_delete(base: JobBase) {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("bob");
    let key = wallet.record_key(&target).unwrap();
    match base {
        JobBase::Value => {
            wallet
                .put_record(&target, &value(&["a"]), vec![])
                .await
                .unwrap();
        }
        JobBase::Delete => {
            created_and_deleted(&mut wallet, &target).await;
        }
        JobBase::Nothing => {}
    }
    // A first message adds the conversation, so the fault below meets the record job.
    wallet.send(s.note("first")).await.unwrap();
    let mut message = s.note("hello");
    message.record = Some(RecordJob {
        target: target.clone(),
        tag: b"sent".to_vec(),
    });
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    let (msg_id, delivery) = wallet.send(message).await.unwrap();
    assert!(accepted(&delivery), "{base:?}: {delivery:?}");
    read_on(&mut phone).await;
    phone
        .put_record(&target, &value(&["p"]), vec![])
        .await
        .unwrap();
    let deleted = phone.delete_record(&target, vec![]).await.unwrap();
    let report = wallet.flush_outbox().await.unwrap();
    assert!(report.queued.is_empty(), "{base:?}: {report:?}");
    let told = record_jobs_stopped(&mut wallet).await;
    assert!(
        matches!(
            told.as_slice(),
            [AppEvent::RecordJobStopped { msg_id: m, key: k, generation, version, .. }]
                if *m == msg_id
                    && *k == key
                    && RecordVersion::new(*generation, *version) == deleted.version
        ),
        "{base:?}: {told:?}"
    );
    let at_switch = s.w.switch.lock().shared.records.get(&key).cloned().unwrap();
    assert!(at_switch.state.deleted, "{base:?}: nothing written over it");
    assert_eq!(at_switch.state.version, deleted.version, "{base:?}");
    wallet.flush_outbox().await.unwrap();
    assert_eq!(
        record_jobs_stopped(&mut wallet).await.len(),
        1,
        "{base:?}: told once"
    );
}

#[tokio::test]
async fn test_send_record_job_queued_on_a_value_stops_at_a_later_delete() {
    Box::pin(record_job_stops_at_a_later_delete(JobBase::Value)).await;
}

#[tokio::test]
async fn test_send_record_job_queued_on_a_delete_stops_at_a_later_delete() {
    Box::pin(record_job_stops_at_a_later_delete(JobBase::Delete)).await;
}

#[tokio::test]
async fn test_send_record_job_queued_on_nothing_stops_at_a_later_delete() {
    Box::pin(record_job_stops_at_a_later_delete(JobBase::Nothing)).await;
}

/// The record job's duty events not yet acknowledged that stopped it.
async fn record_jobs_stopped(app: &mut App) -> Vec<AppEvent> {
    app.unacknowledged_events()
        .await
        .unwrap()
        .into_iter()
        .filter(|e| matches!(e, AppEvent::RecordJobStopped { .. }) && e.is_duty())
        .collect()
}

/// A record job queued on a value, its first try made with the switch acting as `fault`
/// says; returns the wallet, the phone, the record key, the message ID and the batch the
/// try left kept.
async fn record_job_left_kept(
    s: &Setup,
    target: &RecordTarget,
    fault: Fault,
) -> (App, App, [u8; 32], String, [u8; 16]) {
    let mut wallet = s.join("wallet").await;
    let phone = s.join("phone").await;
    let key = wallet.record_key(target).unwrap();
    wallet
        .put_record(target, &value(&["a"]), vec![])
        .await
        .unwrap();
    // A first message adds the conversation, so the fault below meets the record job.
    wallet.send(s.note("first")).await.unwrap();
    let mut message = s.note("hello");
    message.record = Some(RecordJob {
        target: target.clone(),
        tag: b"sent".to_vec(),
    });
    s.w.switch.fail_next(fault);
    let (msg_id, delivery) = wallet.send(message).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    let kept = wallet.kept_batches().await.unwrap();
    let [(batch_id, _)] = kept.as_slice() else {
        panic!("{kept:?}")
    };
    let batch_id = *batch_id;
    (wallet, phone, key, msg_id, batch_id)
}

/// The record job's first try applies, its answer lost; the phone reads it, then writes
/// the record again: a delete, or a value without the message (`delete`). The wallet reads,
/// which settles the kept batch as applied, and flushes. The job's write is made, so the
/// job is done: it isn't stopped, and nothing is written again over the phone's write.
async fn record_job_applied_before_a_later_write(delete: bool) {
    let s = Setup::new();
    let target = s.target("bob");
    let (mut wallet, mut phone, key, msg_id, _) =
        record_job_left_kept(&s, &target, Fault::LoseAnswer { path: "ops".into() }).await;
    read_on(&mut phone).await;
    let written = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(
        written.content.value(),
        Some(value(&["a", msg_id.as_str()]).as_slice())
    );
    let later = if delete {
        phone.delete_record(&target, vec![]).await.unwrap()
    } else {
        phone
            .put_record(&target, &value(&["p"]), vec![])
            .await
            .unwrap()
    };
    wallet.receive(None).await.unwrap();
    let report = wallet.flush_outbox().await.unwrap();
    assert!(report.queued.is_empty(), "{report:?}");
    let told = record_jobs_stopped(&mut wallet).await;
    assert!(told.is_empty(), "delete {delete}: {told:?}");
    let at_switch = s.w.switch.lock().shared.records.get(&key).cloned().unwrap();
    assert_eq!(at_switch.state.version, later.version, "delete {delete}");
    assert_eq!(at_switch.state.deleted, delete);
}

#[tokio::test]
async fn test_send_record_job_applied_before_a_later_delete_is_done() {
    Box::pin(record_job_applied_before_a_later_write(true)).await;
}

#[tokio::test]
async fn test_send_record_job_applied_before_a_later_put_is_done() {
    Box::pin(record_job_applied_before_a_later_write(false)).await;
}

#[tokio::test]
async fn test_send_record_job_waits_while_its_try_is_still_kept() {
    // The job's first try applies, its answer lost; the phone deletes the record, and the
    // wallet takes the delete by reading that record alone, its kept batch still kept. A
    // flush that can't send the batch again doesn't stop the job, whose write may yet show
    // as applied; the next flush settles the batch as applied, and the job is done.
    let s = Setup::new();
    let target = s.target("bob");
    let (mut wallet, mut phone, key, _, batch_id) =
        record_job_left_kept(&s, &target, Fault::LoseAnswer { path: "ops".into() }).await;
    read_on(&mut phone).await;
    let deleted = phone.delete_record(&target, vec![]).await.unwrap();
    wallet.read_record(&target).await.unwrap();
    let unavailable = || Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    };
    for _ in 0..4 {
        s.w.switch.fail_next(unavailable());
    }
    let report = wallet.flush_outbox().await.unwrap();
    s.w.switch.lock().faults.clear();
    assert_eq!(report.queued.len(), 1, "{report:?}");
    assert!(record_jobs_stopped(&mut wallet).await.is_empty());
    assert!(matches!(
        wallet.kept_batch(batch_id).await.unwrap(),
        Some(crate::app::KeptBatchStatus::Kept { .. })
    ));
    let report = wallet.flush_outbox().await.unwrap();
    assert!(report.queued.is_empty(), "{report:?}");
    let told = record_jobs_stopped(&mut wallet).await;
    assert!(told.is_empty(), "{told:?}");
    let at_switch = s.w.switch.lock().shared.records.get(&key).cloned().unwrap();
    assert!(at_switch.state.deleted);
    assert_eq!(at_switch.state.version, deleted.version);
}

/// The record job's first try is never answered and never applied; the phone deletes the
/// record. With `past` the wallet reads only past the window in which a resend tells, so
/// the batch is dropped with its fate unknown; without, the read sends it again and the
/// switch refuses it. The flush stops the job: the protocol is told the batch only while it
/// may have applied.
async fn record_job_unapplied_stops_at_a_delete(past: bool) {
    let s = Setup::new();
    let target = s.target("bob");
    let (mut wallet, mut phone, key, msg_id, batch_id) = record_job_left_kept(
        &s,
        &target,
        Fault::Unanswered {
            path: "ops".into(),
            after: 0,
        },
    )
    .await;
    if past {
        s.w.clock
            .advance_ms(crate::app::provider::KEPT_BATCH_ANSWER_MS);
    }
    read_on(&mut phone).await;
    let deleted = phone.delete_record(&target, vec![]).await.unwrap();
    wallet.receive(None).await.unwrap();
    let status = wallet.kept_batch(batch_id).await.unwrap();
    assert!(
        matches!(
            status,
            Some(crate::app::KeptBatchStatus::Dropped { ref reason, .. })
                if matches!(reason, crate::app::KeptBatchDrop::Uncertain) == past
        ),
        "past {past}: {status:?}"
    );
    let report = wallet.flush_outbox().await.unwrap();
    assert!(report.queued.is_empty(), "{report:?}");
    let told = record_jobs_stopped(&mut wallet).await;
    let named = past.then_some(batch_id);
    assert!(
        matches!(
            told.as_slice(),
            [AppEvent::RecordJobStopped { msg_id: m, key: k, version, batch_id, .. }]
                if *m == msg_id && *k == key && *version == deleted.version.version
                    && *batch_id == named
        ),
        "past {past}: {told:?}"
    );
    let at_switch = s.w.switch.lock().shared.records.get(&key).cloned().unwrap();
    assert!(at_switch.state.deleted);
    assert_eq!(at_switch.state.version, deleted.version);
}

#[tokio::test]
async fn test_send_record_job_refused_try_stops_naming_no_batch() {
    Box::pin(record_job_unapplied_stops_at_a_delete(false)).await;
}

#[tokio::test]
async fn test_send_record_job_unknown_try_stops_naming_its_batch() {
    Box::pin(record_job_unapplied_stops_at_a_delete(true)).await;
}

#[tokio::test]
async fn test_send_record_job_restored_before_its_write_stops_at_a_later_delete() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("bob");
    let key = created_and_deleted(&mut wallet, &target).await;
    let mut message = s.note("hello");
    message.record = Some(RecordJob {
        target: target.clone(),
        tag: vec![],
    });
    let msg_id = wallet.queue(message).await.unwrap();
    let backup = wallet.backup().await.unwrap();

    wallet.flush_outbox().await.unwrap();
    let written = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(written.content.value()), std::slice::from_ref(&msg_id));
    read_on(&mut phone).await;
    phone.delete_record(&target, vec![]).await.unwrap();
    let deleted = s.w.switch.record(&key).unwrap().revision;

    drop(wallet);
    let mut restored = Box::pin(App::restore(
        s.env(),
        s.protocol.clone(),
        World::config(),
        &backup,
    ))
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    restored
        .end_reconcile(crate::app::UserConfirmed::new())
        .await
        .unwrap();
    restored.flush_outbox().await.unwrap();
    let events = record_jobs_stopped(&mut restored).await;
    assert!(
        matches!(events.as_slice(), [AppEvent::RecordJobStopped {
        msg_id: stopped, item_hash, batch_id: None, ..
    }] if stopped == &msg_id && *item_hash == deleted.item_hash),
        "{events:?}"
    );
    assert_eq!(s.w.switch.record(&key).unwrap().revision, deleted);
}

async fn deletion_receipts(app: &App) -> Vec<serde_json::Value> {
    app.protocol_get("sample", b"delete receipts")
        .await
        .unwrap()
        .map(|v| serde_json::from_slice(&v).unwrap())
        .unwrap_or_default()
}

async fn unread_deletion(
    s: &Setup,
    original: &[u8],
) -> (App, App, RecordTarget, [u8; 32], RecordVersion) {
    use std::sync::atomic::Ordering::SeqCst;
    let mut writer = s.join("wallet").await;
    let mut reader = s.join("phone").await;
    let target = s.target("collection item");
    writer.put_record(&target, original, vec![]).await.unwrap();
    read_on(&mut reader).await;
    s.protocol.observe_deletes.store(true, SeqCst);
    let deleted = writer.delete_record(&target, vec![]).await.unwrap();
    let evidence = writer.shared_evidence().await.unwrap();
    let hash = SignedOp::peek(
        &evidence
            .ops
            .iter()
            .find(|op| {
                SignedOp::peek(&op.op).is_ok_and(
                    |p| matches!(&p.body().kind, OpKind::RecordPut(put) if put.key == deleted.key),
                )
            })
            .unwrap()
            .op,
    )
    .unwrap()
    .item_hash()
    .unwrap();
    (writer, reader, target, hash, deleted.version)
}

#[tokio::test]
async fn test_record_deletion_observes_the_signed_source_and_passes_its_cursor() {
    let s = Setup::new();
    let mut original = value(&["trusted"]);
    original.resize(MAX_SEEN_MARK_BYTES + 30, b' ');
    let (writer, mut reader, target, hash, ver) = unread_deletion(&s, &original).await;
    read_on(&mut reader).await;
    let receipts = deletion_receipts(&reader).await;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["hash"], json!(hash));
    assert_eq!(receipts[0]["writer"], json!(writer.app_id()));
    assert_eq!(receipts[0]["version"], json!([ver.generation, ver.version]));
    assert_eq!(receipts[0]["value"].as_str().unwrap().as_bytes(), original);
    assert_eq!(
        receipts[0]["seen"].as_str().unwrap().as_bytes(),
        value(&["trusted"])
    );
    assert!(receipts[0]["page"].as_u64().is_some());
    assert!(receipts[0]["policy"].as_bool().unwrap());
    assert_eq!(receipts[0]["dated"], true);
    reader.flush_cursor().await.unwrap();
    assert!(reader.service_cursor().seq >= ver.version);
    reader.read_record(&target).await.unwrap();
    read_on(&mut reader).await;
    assert_eq!(deletion_receipts(&reader).await.len(), 1);
    assert!(reader.state.deletions.is_empty());
}

#[derive(Clone, Copy)]
enum DeletionInstall {
    Original,
    Fresh,
    OlderInPlace,
}

async fn resume_deletion(install: DeletionInstall) {
    use std::sync::atomic::Ordering::SeqCst;
    let s = Setup::new();
    let original = value(&["first"]);
    let (mut writer, mut reader, target, hash, _) = unread_deletion(&s, &original).await;
    let older = reader.backup_layered().await.unwrap();
    s.protocol.observation_unavailable.store(true, SeqCst);
    read_on(&mut reader).await;
    assert_eq!(reader.state.deletions.len(), 1);
    assert!(deletion_receipts(&reader).await.is_empty());
    let successor = value(&["first", "next"]);
    writer
        .put_record(&target, &successor, vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    let key = reader.record_key(&target).unwrap();
    assert_ne!(
        reader
            .shared_record(&key)
            .await
            .unwrap()
            .unwrap()
            .content
            .value(),
        Some(successor.as_slice())
    );
    let mut restored = match install {
        DeletionInstall::Original => App::load(
            s.env(),
            s.protocol.clone(),
            World::config(),
            reader.app_id(),
        )
        .await
        .unwrap(),
        DeletionInstall::Fresh => {
            let backup = reader.backup_layered().await.unwrap();
            Box::pin(App::restore(
                s.env_on(Arc::new(MemoryStore::new())),
                s.protocol.clone(),
                World::config(),
                &backup,
            ))
            .await
            .unwrap()
        }
        DeletionInstall::OlderInPlace => Box::pin(App::restore(
            s.env(),
            s.protocol.clone(),
            World::config(),
            &older,
        ))
        .await
        .unwrap(),
    };
    assert_eq!(restored.state.deletions.len(), 1);
    s.protocol.observation_unavailable.store(false, SeqCst);
    restored.refresh_identity().await.unwrap();
    read_on(&mut restored).await;
    read_on(&mut restored).await;
    let receipts = deletion_receipts(&restored).await;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["hash"], json!(hash));
    assert_eq!(receipts[0]["value"].as_str().unwrap().as_bytes(), original);
    assert!(restored.state.deletions.is_empty());
    assert_eq!(
        restored
            .shared_record(&key)
            .await
            .unwrap()
            .unwrap()
            .content
            .value(),
        Some(successor.as_slice())
    );
}

#[tokio::test]
async fn test_record_deletion_layered_receipt_survives_a_fresh_read_of_the_same_delete() {
    let s = Setup::new();
    let original = value(&["issued"]);
    let (_writer, mut reader, target, _, _) = unread_deletion(&s, &original).await;
    read_on(&mut reader).await;
    let saved = deletion_receipts(&reader).await;
    assert_eq!(saved.len(), 1);
    let backup = reader.backup_layered().await.unwrap();
    let mut restored = Box::pin(App::restore(
        s.env_on(Arc::new(MemoryStore::new())),
        s.protocol.clone(),
        World::config(),
        &backup,
    ))
    .await
    .unwrap();
    restored.refresh_identity().await.unwrap();
    read_on(&mut restored).await;
    let current = restored.read_record(&target).await.unwrap().unwrap();
    assert_eq!(current.content, RecordContent::Deleted);
    assert_eq!(deletion_receipts(&restored).await, saved);
}

#[tokio::test]
async fn test_record_deletion_restore_reads_the_existing_installation_without_the_feed() {
    use std::sync::atomic::Ordering::SeqCst;
    let s = Setup::new();
    let mut writer = s.join("wallet").await;
    let mut reader = s.join("phone").await;
    let target = s.target("issued");
    let source = value(&["issued"]);
    let older = reader.backup_layered().await.unwrap();
    let written = writer.put_record(&target, &source, vec![]).await.unwrap();
    let held = reader.read_record(&target).await.unwrap().unwrap();
    assert_eq!(held.content.value(), Some(source.as_slice()));
    let foreign_store = Arc::new(MemoryStore::new());
    let mut tablet = Box::pin(App::join(
        s.env_on(foreign_store.clone()),
        s.protocol.clone(),
        World::config(),
        s.approve(&app_keys("tablet"), &ALL_PERMISSIONS),
    ))
    .await
    .unwrap();
    assert_eq!(
        tablet.read_record(&target).await.unwrap().unwrap().content,
        held.content
    );
    writer.delete_record(&target, vec![]).await.unwrap();
    writer
        .put_record(&target, &value(&["successor"]), vec![])
        .await
        .unwrap();
    s.protocol.read_previous.store(true, SeqCst);
    s.protocol.previous_must_be_empty.store(true, SeqCst);
    reader.backup().await.unwrap();
    reader.backup_layered().await.unwrap();
    let fresh = Box::pin(App::restore(
        s.env_on(Arc::new(MemoryStore::new())),
        s.protocol.clone(),
        World::config(),
        &older,
    ))
    .await
    .unwrap();
    assert!(
        fresh
            .protocol_get("sample", &written.key)
            .await
            .unwrap()
            .is_none()
    );
    let different = Box::pin(App::restore(
        s.env_on(foreign_store),
        s.protocol.clone(),
        World::config(),
        &older,
    ))
    .await
    .unwrap();
    assert!(
        different
            .protocol_get("sample", &written.key)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        tablet
            .shared_record(&written.key)
            .await
            .unwrap()
            .unwrap()
            .content,
        held.content
    );
    assert_eq!(s.protocol.previous_read_count.load(SeqCst), 0);
    s.protocol.previous_must_be_empty.store(false, SeqCst);
    let restored = Box::pin(App::restore(
        s.env(),
        s.protocol.clone(),
        World::config(),
        &older,
    ))
    .await
    .unwrap();
    let preserved: serde_json::Value = serde_json::from_slice(
        &restored
            .protocol_get("sample", &written.key)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        preserved,
        json!({"value":source, "writer":writer.app_id(), "version":[written.version.generation,written.version.version],
        "authenticated":held.authenticated,"divergent":held.divergent,"doubtful":held.doubtful})
    );
    assert!(
        restored
            .shared_record(&written.key)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_record_deletion_restore_preserves_an_unproved_version_on_an_open_signed_value() {
    use std::sync::atomic::Ordering::SeqCst;
    let s = Setup::new();
    let mut writer = s.join("wallet").await;
    let mut reader = s.join("phone").await;
    let backup = reader.backup_layered().await.unwrap();
    let target = s.target("record");
    let source = value(&["issued"]);
    let written = writer.put_record(&target, &source, vec![]).await.unwrap();
    s.w.switch.lock().shared.hide_proofs = true;
    let held = reader.read_record(&target).await.unwrap().unwrap();
    assert!(!held.authenticated);
    assert_eq!(held.content.value(), Some(source.as_slice()));
    s.protocol.read_previous.store(true, SeqCst);
    let restored = Box::pin(App::restore(
        s.env(),
        s.protocol.clone(),
        World::config(),
        &backup,
    ))
    .await
    .unwrap();
    let prior: serde_json::Value = serde_json::from_slice(
        &restored
            .protocol_get("sample", &written.key)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(prior["authenticated"], false);
    assert_eq!(prior["value"], json!(source));
}

#[tokio::test]
async fn test_record_deletion_restore_refuses_content_changed_after_the_signed_write() {
    use std::sync::atomic::Ordering::SeqCst;
    let s = Setup::new();
    let mut writer = s.join("wallet").await;
    let mut reader = s.join("phone").await;
    let backup = reader.backup_layered().await.unwrap();
    let target = s.target("issued");
    let written = writer
        .put_record(&target, &value(&["issued"]), vec![])
        .await
        .unwrap();
    reader.read_record(&target).await.unwrap();
    let record_key = crate::app::records::record_key_of(&written.key);
    let mut stored: serde_json::Value = reader.reader().get(&record_key).await.unwrap().unwrap();
    stored["content"] = serde_json::to_value(RecordContent::Value(value(&["other"]))).unwrap();
    let mut edit = reader.tx().unwrap();
    edit.put(&record_key, &stored).unwrap();
    reader.commit(edit).await.unwrap();
    s.protocol.read_previous.store(true, SeqCst);
    let refused = Box::pin(App::restore(
        s.env(),
        s.protocol.clone(),
        World::config(),
        &backup,
    ))
    .await;
    assert!(matches!(refused, Err(AppError::InvalidData(_))));
    assert_eq!(
        reader
            .reader()
            .get::<serde_json::Value>(&record_key)
            .await
            .unwrap(),
        Some(stored)
    );
    assert!(
        reader
            .protocol_get("sample", &written.key)
            .await
            .unwrap()
            .is_none()
    );
}

async fn scope_of_previous_record(selected_wider: bool) {
    use std::sync::atomic::Ordering::SeqCst;
    let s = Setup::new();
    let mut writer = s.join("wallet").await;
    let broad = &["sample-a", "sample-c"][..];
    let narrow = &["sample-c"][..];
    let mut reader = join_scoped(&s, "phone", if selected_wider { broad } else { narrow }).await;
    let older = reader.backup_layered().await.unwrap();
    let target = s.target("private");
    let written = writer
        .put_record(&target, &value(&["private"]), vec![])
        .await
        .unwrap();
    if selected_wider {
        reader.read_record(&target).await.unwrap();
    }
    reader.receive(None).await.unwrap();
    s.w.clock.advance_ms(HOUR);
    let earlier = reader.cert().clone();
    let renewed = renewed_cert(&s, "phone", if selected_wider { narrow } else { broad });
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    if selected_wider {
        let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
        s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    }
    reader.receive(None).await.unwrap();
    assert_eq!(reader.cert().hash(), renewed.hash());
    if !selected_wider {
        store_parts_for(&s, &renewed);
        reader.receive(None).await.unwrap();
        reader.read_record(&target).await.unwrap();
    }
    assert_eq!(
        reader
            .shared_record(&written.key)
            .await
            .unwrap()
            .unwrap()
            .content
            .value(),
        Some(value(&["private"]).as_slice())
    );
    s.protocol.read_previous.store(true, SeqCst);
    s.protocol.previous_must_be_empty.store(true, SeqCst);
    let restored = Box::pin(App::restore(
        s.env(),
        s.protocol.clone(),
        World::config(),
        &older,
    ))
    .await
    .unwrap();
    assert!(
        restored
            .protocol_get("sample", &written.key)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_record_deletion_restore_checks_the_selected_certificate_read_scope() {
    Box::pin(scope_of_previous_record(false)).await;
}
#[tokio::test]
async fn test_record_deletion_restore_checks_the_installed_certificate_read_scope() {
    Box::pin(scope_of_previous_record(true)).await;
}

#[tokio::test]
async fn test_record_deletion_earlier_layer_can_observe_the_current_delete_again() {
    let s = Setup::new();
    let (_writer, mut reader, target, hash, _) = unread_deletion(&s, &value(&["issued"])).await;
    let older = reader.backup_layered().await.unwrap();
    read_on(&mut reader).await;
    assert_eq!(deletion_receipts(&reader).await.len(), 1);
    let mut restored = Box::pin(App::restore(
        s.env(),
        s.protocol.clone(),
        World::config(),
        &older,
    ))
    .await
    .unwrap();
    assert!(deletion_receipts(&restored).await.is_empty());
    restored.refresh_identity().await.unwrap();
    restored.read_record(&target).await.unwrap();
    let receipts = deletion_receipts(&restored).await;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["hash"], json!(hash));
    assert!(receipts[0]["value"].is_null());
    assert_eq!(receipts[0]["policy"], false);
}

#[tokio::test]
async fn test_record_deletion_owner_keeps_an_issued_receipt_when_installing_an_earlier_layer() {
    use std::sync::atomic::Ordering::SeqCst;
    let s = Setup::new();
    let (mut writer, mut reader, target, _, _) = unread_deletion(&s, &value(&["issued"])).await;
    let older = reader.backup_layered().await.unwrap();
    read_on(&mut reader).await;
    let saved = deletion_receipts(&reader).await;
    assert_eq!(saved.len(), 1);
    writer
        .put_record(&target, &value(&["issued", "renewed"]), vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    assert!(reader.state.deletion_receipts.is_empty());
    s.protocol.keep_receipts.store(true, SeqCst);
    for (env, expect) in [
        (s.env_on(Arc::new(MemoryStore::new())), false),
        (s.env(), true),
    ] {
        let mut restored = Box::pin(App::restore(
            env,
            s.protocol.clone(),
            World::config(),
            &older,
        ))
        .await
        .unwrap();
        restored.refresh_identity().await.unwrap();
        assert_eq!(
            restored
                .read_record(&target)
                .await
                .unwrap()
                .unwrap()
                .content
                .value(),
            Some(value(&["issued", "renewed"]).as_slice())
        );
        assert_eq!(
            deletion_receipts(&restored).await,
            if expect { saved.clone() } else { vec![] }
        );
    }
}

#[tokio::test]
async fn test_record_deletion_next_delete_has_its_own_receipt_and_hosted_absence_retires_it() {
    let s = Setup::new();
    let (mut writer, mut reader, target, first, _) = unread_deletion(&s, &value(&["issued"])).await;
    read_on(&mut reader).await;
    assert_eq!(reader.state.deletion_receipts.len(), 1);
    writer
        .put_record(&target, &value(&["issued", "another"]), vec![])
        .await
        .unwrap();
    reader.read_record(&target).await.unwrap();
    assert!(reader.state.deletion_receipts.is_empty());
    let key = writer.delete_record(&target, vec![]).await.unwrap().key;
    reader.read_record(&target).await.unwrap();
    let receipts = deletion_receipts(&reader).await;
    assert_eq!(receipts.len(), 2);
    assert_ne!(receipts[1]["hash"], json!(first));
    assert_eq!(reader.state.deletion_receipts.len(), 1);
    s.w.switch.lock().shared.records.remove(&key);
    reader.read_record(&target).await.unwrap();
    assert!(reader.state.deletion_receipts.is_empty());
    assert_eq!(deletion_receipts(&reader).await, receipts);
}

#[tokio::test]
async fn test_record_deletion_large_owner_write_keeps_the_original_observation() {
    use std::sync::atomic::Ordering::SeqCst;
    let s = Setup::new();
    let (_, mut reader, _, hash, _) = unread_deletion(&s, &value(&["issued"])).await;
    s.protocol.large_receipt.store(true, SeqCst);
    read_on(&mut reader).await;
    assert_eq!(reader.state.deletions.len(), 1);
    assert!(
        reader
            .protocol_get("sample", b"oversize")
            .await
            .unwrap()
            .is_none()
    );
    s.protocol.large_receipt.store(false, SeqCst);
    read_on(&mut reader).await;
    let receipts = deletion_receipts(&reader).await;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["hash"], json!(hash));
    assert!(reader.state.deletions.is_empty());
}

#[tokio::test]
async fn test_record_deletion_restored_named_source_needs_its_own_version_proof() {
    use std::sync::atomic::Ordering::SeqCst;
    let s = Setup::new();
    let mut writer = s.join("wallet").await;
    let mut reader = s.join("phone").await;
    let target = s.target("collection item");
    let source = value(&["issued"]);
    let key = writer
        .put_record(&target, &source, vec![])
        .await
        .unwrap()
        .key;
    read_on(&mut reader).await;
    let applied = s.w.switch.record(&key).unwrap().revision;
    let when = Condition::RecordCurrent {
        key,
        revision: applied,
        deleted: false,
    };
    s.protocol.observe_deletes.store(true, SeqCst);
    s.protocol.observation_unavailable.store(true, SeqCst);
    writer.delete_record(&target, vec![when]).await.unwrap();
    read_on(&mut reader).await;
    let mut backup = reader.backup_layered().await.unwrap();
    backup.deletions[0]
        .predecessor
        .as_mut()
        .unwrap()
        .source
        .proof = None;
    let mut restored = Box::pin(App::restore(
        s.env_on(Arc::new(MemoryStore::new())),
        s.protocol.clone(),
        World::config(),
        &backup,
    ))
    .await
    .unwrap();
    s.protocol.observation_unavailable.store(false, SeqCst);
    restored.refresh_identity().await.unwrap();
    read_on(&mut restored).await;
    let receipt = &deletion_receipts(&restored).await[0];
    assert_eq!(receipt["value"].as_str().unwrap().as_bytes(), source);
    assert_eq!(receipt["dated"], false);
}

#[tokio::test]
async fn test_record_deletion_restore_an_older_signed_source_is_not_the_exact_predecessor() {
    use std::sync::atomic::Ordering::SeqCst;
    let s = Setup::new();
    let mut writer = s.join("wallet").await;
    let mut reader = s.join("phone").await;
    let target = s.target("protected");
    writer
        .put_record(&target, &value(&["older"]), vec![])
        .await
        .unwrap();
    let older = writer.shared_evidence().await.unwrap().ops.pop().unwrap();
    writer
        .put_record(&target, &value(&["older", "current"]), vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    s.protocol.observe_deletes.store(true, SeqCst);
    s.protocol.observation_unavailable.store(true, SeqCst);
    writer.delete_record(&target, vec![]).await.unwrap();
    read_on(&mut reader).await;
    let mut backup = reader.backup().await.unwrap();
    backup.deletions[0].predecessor.as_mut().unwrap().source = older;
    let mut restored = Box::pin(App::restore(
        s.env_on(Arc::new(MemoryStore::new())),
        s.protocol.clone(),
        World::config(),
        &backup,
    ))
    .await
    .unwrap();
    restored.refresh_identity().await.unwrap();
    s.protocol.observation_unavailable.store(false, SeqCst);
    read_on(&mut restored).await;
    let receipts = deletion_receipts(&restored).await;
    assert_eq!(receipts.len(), 1);
    assert!(receipts[0]["value"].is_null());
}

#[tokio::test]
async fn test_record_deletion_an_earlier_view_preserves_the_restored_acknowledgement() {
    use std::sync::atomic::Ordering::SeqCst;
    let s = Setup::new();
    let mut writer = s.join("wallet").await;
    let mut reader = s.join("phone").await;
    let target = s.target("issued item");
    let key = writer
        .put_record(&target, &value(&["issued"]), vec![])
        .await
        .unwrap()
        .key;
    read_on(&mut reader).await;
    let prior = s.w.switch.record(&key).unwrap();
    let before = prior.seq;
    s.protocol.observe_deletes.store(true, SeqCst);
    writer.delete_record(&target, vec![]).await.unwrap();
    read_on(&mut reader).await;
    let receipts = deletion_receipts(&reader).await;
    assert_eq!(receipts.len(), 1);
    let backup = reader.backup_layered().await.unwrap();
    let mut restored = Box::pin(App::restore(
        s.env_on(Arc::new(MemoryStore::new())),
        s.protocol.clone(),
        World::config(),
        &backup,
    ))
    .await
    .unwrap();
    restored.refresh_identity().await.unwrap();
    let current = s.w.switch.record(&key).unwrap();
    show_older(&s, &restored, &target, prior, true);
    s.w.switch.fail_next(Fault::Head {
        path: "/records/".into(),
        at: Some(before),
        forked: false,
    });
    restored.read_record(&target).await.unwrap();
    assert_eq!(restored.state.deletion_receipts.len(), 1);
    show_older(&s, &restored, &target, current, true);
    restored.read_record(&target).await.unwrap();
    assert_eq!(deletion_receipts(&restored).await, receipts);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OwnTarget {
    New,
    Existing,
    Deleted,
}

async fn own_write_while_deletion_is_owed(which: OwnTarget) {
    use std::sync::atomic::Ordering::SeqCst;
    let s = Setup::new();
    let original = value(&["issued"]);
    let (mut writer, mut reader, deleted, hash, _) = unread_deletion(&s, &original).await;
    let target = if which == OwnTarget::Deleted {
        deleted
    } else {
        s.target("another record")
    };
    if which == OwnTarget::Existing {
        reader
            .put_record(&target, &value(&["older"]), vec![])
            .await
            .unwrap();
    }
    s.protocol.observation_unavailable.store(true, SeqCst);
    read_on(&mut reader).await;
    assert_eq!(reader.state.deletions.len(), 1);

    let new = value(&["issued", "older", "updated"]);
    let result = reader.put_record(&target, &new, vec![]).await;
    let service = writer.read_record(&target).await.unwrap().unwrap();
    assert_eq!(service.content.value(), Some(new.as_slice()));
    let reported = result.unwrap();
    assert_eq!(reported.version, service.version);
    assert_eq!(reported.content, service.content);
    assert!(deletion_receipts(&reader).await.is_empty());
    assert_eq!(reader.state.deletions.len(), 1);

    s.protocol.observation_unavailable.store(false, SeqCst);
    read_on(&mut reader).await;
    let receipts = deletion_receipts(&reader).await;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["hash"], json!(hash));
    assert_eq!(receipts[0]["value"].as_str().unwrap().as_bytes(), original);
    assert!(reader.state.deletions.is_empty());
    let current = reader.read_record(&target).await.unwrap().unwrap();
    assert_eq!(current.content, service.content);
    if which == OwnTarget::Deleted {
        assert!(reader.state.deletion_receipts.is_empty());
    }
}

#[tokio::test]
async fn test_record_deletion_own_creation_while_observation_is_owed() {
    Box::pin(own_write_while_deletion_is_owed(OwnTarget::New)).await;
}

#[tokio::test]
async fn test_record_deletion_own_update_while_observation_is_owed() {
    Box::pin(own_write_while_deletion_is_owed(OwnTarget::Existing)).await;
}

#[tokio::test]
async fn test_record_deletion_own_successor_while_observation_is_owed() {
    Box::pin(own_write_while_deletion_is_owed(OwnTarget::Deleted)).await;
}

#[tokio::test]
async fn test_record_deletion_unavailable_owner_resumes_before_the_successor() {
    Box::pin(resume_deletion(DeletionInstall::Original)).await;
}
#[tokio::test]
async fn test_record_deletion_fresh_restore_of_an_unanswered_observation() {
    Box::pin(resume_deletion(DeletionInstall::Fresh)).await;
}
#[tokio::test]
async fn test_record_deletion_older_in_place_restore_of_an_unanswered_observation() {
    Box::pin(resume_deletion(DeletionInstall::OlderInPlace)).await;
}

#[tokio::test]
async fn test_records_refused_reread_follows_the_delete_in_the_view() {
    use crate::client::answers::{FeedItem, FeedQuery};
    use pubky_switch_core::chain::ChainEnvelope;
    use pubky_switch_core::ops::Position;

    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    let target = s.target("n1");
    let key = phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap()
        .key;
    wallet.receive(None).await.unwrap();
    let first = wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    let page = phone
        .client
        .feed(FeedQuery {
            after: Some(Position {
                generation: first.version.generation,
                seq: first.version.version - 1,
            }),
            limit: Some(1),
            wait: None,
        })
        .await
        .unwrap();
    let [FeedItem::Chain(item)] = page.items.as_slice() else {
        panic!("expected the first write");
    };
    let envelope = ChainEnvelope::parse(&item.stub.envelope).unwrap();
    wallet.delete_record(&target, vec![]).await.unwrap();
    let deleted = s.w.switch.record(&key).unwrap();

    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    wallet.receive(None).await.unwrap();
    phone.refresh_identity().await.unwrap();
    // The read has the earlier certificate, but no proof to date its delete before
    // the reduction. The phone keeps its own value and follows the delete.
    s.w.switch.lock().shared.hide_proofs = true;
    let mut tx = phone.tx().unwrap();
    assert_eq!(
        phone
            .feed_record_write(item, &envelope, page.server_time_ms, &mut tx)
            .await
            .unwrap(),
        crate::app::records::WriteRead::Refused
    );
    phone.commit(tx).await.unwrap();
    let held = phone.held_record(&key).await.unwrap().unwrap();
    let base = held
        .delete_base()
        .expect("the followed write is the reread delete");
    assert_eq!(base.version, deleted.state.version);
    assert_eq!(base.item_hash, deleted.revision.item_hash);
}

#[tokio::test]
async fn test_records_delete_view_requires_the_signed_operation_hash() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("bob");
    wallet
        .put_record(&target, &value(&["one"]), vec![])
        .await
        .unwrap();
    let before = phone.read_record(&target).await.unwrap().unwrap();
    let key = wallet.delete_record(&target, vec![]).await.unwrap().key;
    let observed = phone
        .record_view(&key, &target.collection)
        .await
        .unwrap()
        .unwrap();
    assert!(observed.covers_uploads);
    let (mut view, at) = (observed.view, observed.at);
    let signed = SignedOp::peek(&view.op).unwrap().item_hash().unwrap();
    view.revision.item_hash[0] ^= 1;
    view.divergent = true;
    let mut tx = phone.tx().unwrap();
    let read = phone
        .take_view(&view, at, Some((&key, &target.collection)), true, &mut tx)
        .await;
    assert!(
        matches!(
            read,
            Err(AppError::Switch(
                crate::error::ClientError::InvalidResponse(_)
            ))
        ),
        "{read:?}"
    );
    assert!(tx.is_empty());
    assert!(!phone.is_divergent(&key).await.unwrap());
    assert_eq!(phone.shared_record(&key).await.unwrap(), Some(before));
    assert!(phone.flagged_writes().await.unwrap().is_empty());

    view.revision.item_hash = signed;
    let mut tx = phone.tx().unwrap();
    let read = phone
        .take_view(&view, at, Some((&key, &target.collection)), true, &mut tx)
        .await
        .unwrap();
    assert_eq!(read, crate::app::records::WriteRead::Taken);
    phone.commit(tx).await.unwrap();
    assert_eq!(
        phone
            .held_record(&key)
            .await
            .unwrap()
            .unwrap()
            .delete_base()
            .unwrap()
            .item_hash,
        signed
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UploadedDelete {
    Same,
    Other,
    // A delete without its proof takes the next version after the one it was built on.
    SameAtEarlierVersion,
}

/// Queue a job on a delete, then recover the account with that operation or a different
/// delete at its version. A restore in place takes the queued job back from backup bytes.
async fn record_job_after_delete_upload(uploaded: UploadedDelete, restore: bool) {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let mut reader = if restore {
        None
    } else {
        Some(s.join("reader").await)
    };
    let target = s.target("bob");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    if uploaded == UploadedDelete::SameAtEarlierVersion {
        wallet
            .put_record(&s.target("other"), &value(&["b"]), vec![])
            .await
            .unwrap();
    }
    let key = wallet.delete_record(&target, vec![]).await.unwrap().key;
    let original_delete = s.w.switch.record(&key).unwrap();
    assert!(original_delete.state.deleted);
    if let Some(reader) = &mut reader {
        s.protocol
            .observe_deletes
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let held = reader.read_record(&target).await.unwrap().unwrap();
        assert_eq!(held.content, RecordContent::Deleted);
        assert_eq!(reader.state.deletion_receipts.len(), 1);
        assert_eq!(deletion_receipts(reader).await[0]["original"], true);
        assert_eq!(
            deletion_receipts(reader).await[0]["hash"],
            json!(original_delete.revision.item_hash)
        );
    }
    wallet.send(s.note("first")).await.unwrap();
    let mut message = s.note("hello");
    message.record = Some(RecordJob {
        target: target.clone(),
        tag: b"sent".to_vec(),
    });
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    let (msg_id, delivery) = wallet.send(message).await.unwrap();
    assert!(accepted(&delivery), "{delivery:?}");
    if restore {
        let bytes = wallet.backup().await.unwrap().to_bytes().unwrap();
        let backup = crate::app::AppBackup::from_bytes(&bytes).unwrap();
        drop(wallet);
        wallet = Box::pin(App::restore(
            s.env(),
            s.protocol.clone(),
            World::config(),
            &backup,
        ))
        .await
        .unwrap();
    }
    let original = SignedOp::peek(&original_delete.op).unwrap();
    let (op, cert) = if uploaded != UploadedDelete::Other {
        (original, wallet.cert().signed().clone())
    } else {
        let mut body = original.body().clone();
        body.batch.id = [70; 16];
        body.app_id = Some(app_keys("phone").app_id_bytes());
        (
            SignedOp::sign(&app_keys("phone"), body).unwrap(),
            phone.cert().signed().clone(),
        )
    };
    let prev = s.w.switch.identity_doc().unwrap().hash();
    let doc =
        s.w.signer
            .sign_next(|body| {
                body.generation = 2;
                body.recovery_from = Some(1);
            })
            .unwrap();
    s.w.switch.recover_in_place(&doc, prev).unwrap();
    phone.receive(None).await.unwrap();
    let upload = json!({ "records": [{ "op": op.signed(), "cert": cert }] });
    let answer =
        s.w.switch
            .handle(&crate::transport::Request {
                method: "POST".into(),
                origin: ORIGIN.into(),
                path_and_query: format!("/v1/{}/recovery/upload", s.w.alice.id()),
                headers: vec![crate::transport::Header::new(
                    "switch-app",
                    &pubky_switch_core::enc::zbase32_encode(&app_keys("phone").app_id_bytes()),
                )],
                body: upload.to_string().into_bytes(),
                timeout: crate::transport::TimeoutClass::Bulk,
            })
            .unwrap();
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let taken = s.w.switch.record(&key).unwrap();
    assert_eq!(
        taken.state.version == original_delete.state.version,
        uploaded != UploadedDelete::SameAtEarlierVersion
    );
    assert_ne!(
        taken.revision.generation,
        original_delete.revision.generation
    );
    assert_eq!(
        taken.revision.item_hash == original_delete.revision.item_hash,
        uploaded != UploadedDelete::Other
    );
    if !restore && uploaded == UploadedDelete::Same {
        phone.read_record(&target).await.unwrap();
        let receipts = deletion_receipts(&phone).await;
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0]["hash"],
            json!(original_delete.revision.item_hash)
        );
        assert_eq!(receipts[0]["original"], false);
    }
    if let Some(reader) = &mut reader {
        reader.receive(None).await.unwrap();
        let held = reader.read_record(&target).await.unwrap().unwrap();
        assert_eq!(
            held.different_write_at_held_version,
            uploaded == UploadedDelete::Other,
            "only a different signed delete at the held version changes the write base"
        );
        assert_eq!(
            reader.state.deletion_receipts.is_empty(),
            uploaded == UploadedDelete::Other
        );
        let receipts = deletion_receipts(reader).await;
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0]["hash"],
            json!(original_delete.revision.item_hash)
        );
    }
    wallet.receive(None).await.unwrap();
    if wallet.reconcile_mode() {
        wallet
            .end_reconcile(crate::app::UserConfirmed::new())
            .await
            .unwrap();
    }
    wallet.flush_outbox().await.unwrap();
    let at_switch = s.w.switch.record(&key).unwrap();
    let told = record_jobs_stopped(&mut wallet).await;
    if uploaded == UploadedDelete::Same {
        assert!(!at_switch.state.deleted, "the queued write applied");
        let held = wallet.shared_record(&key).await.unwrap().unwrap();
        assert_eq!(ids(held.content.value()), [msg_id]);
        assert!(told.is_empty(), "{told:?}");
    } else {
        assert_eq!(
            at_switch.revision, taken.revision,
            "the delete stays current"
        );
        assert!(
            matches!(told.as_slice(), [AppEvent::RecordJobStopped {
                msg_id: stopped, key: record, generation, version, item_hash, ..
            }] if stopped == &msg_id && *record == key
                && RecordVersion::new(*generation, *version) == taken.state.version
                && *item_hash == op.item_hash().unwrap()),
            "{told:?}"
        );
        if let Some(reader) = &mut reader {
            // The service reports that it has forgotten the delete. The next write creates
            // the record, and no longer builds on either signed delete.
            s.w.switch.lock().shared.records.remove(&key);
            let held = reader.read_record(&target).await.unwrap().unwrap();
            assert!(!held.different_write_at_held_version);
            assert_eq!(
                reader.record_condition(&key).await.unwrap(),
                Condition::RecordVersion {
                    key,
                    version: RecordVersion::NONE
                }
            );
        }
    }
}

#[tokio::test]
async fn test_send_record_job_stops_at_another_delete_at_its_version() {
    Box::pin(record_job_after_delete_upload(UploadedDelete::Other, false)).await;
}

#[tokio::test]
async fn test_send_record_job_applies_over_the_same_uploaded_delete() {
    Box::pin(record_job_after_delete_upload(UploadedDelete::Same, false)).await;
}

#[tokio::test]
async fn test_send_record_job_restored_in_place_keeps_its_delete() {
    for uploaded in [
        UploadedDelete::Same,
        UploadedDelete::Other,
        UploadedDelete::SameAtEarlierVersion,
    ] {
        Box::pin(record_job_after_delete_upload(uploaded, true)).await;
    }
}

#[tokio::test]
async fn test_scripted_records_current_condition_on_a_forgotten_delete_shows_zero() {
    // A `record_current` naming a delete the switch forgot fails with version 0 current
    // (Switch wire 6.3): the app takes the key as absent, so its next condition holds.
    use pubky_switch_core::ops::Condition;
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = created_and_deleted(&mut wallet, &target).await;
    read_on(&mut wallet).await;
    read_on(&mut phone).await;
    assert!(!held_at_switch(&s, &key), "forgotten");
    // The held delete named exactly, as over a write not read since a provider loss.
    let held = wallet.held_record(&key).await.unwrap().unwrap();
    let named = held.condition(&key, Some(u64::MAX));
    assert!(
        matches!(named, Condition::RecordCurrent { deleted: true, .. }),
        "{named:?}"
    );
    let fenced = |condition: Condition, pubky: u8| {
        OpBatch::new().op_if(OpKind::DenyPut { pubky: [pubky; 32] }, vec![condition])
    };
    let refused = wallet.submit_batch(fenced(named, 9)).await;
    let Err(AppError::Switch(crate::error::ClientError::Switch { current, .. })) = &refused else {
        panic!("{refused:?}")
    };
    assert_eq!(
        current["record_version"],
        json!({"key": pubky_switch_core::enc::b64(&key), "generation": 0, "version": 0})
    );
    let absent = wallet.record_condition(&key).await.unwrap();
    assert_eq!(
        absent,
        Condition::RecordVersion {
            key,
            version: RecordVersion::NONE
        }
    );
    wallet.submit_batch(fenced(absent, 10)).await.unwrap();
}

/// A listing stopped on the read's page budget has listed the family `sample.items` to its
/// end under the kiosk sub-scope and stopped inside `sample.big`. A renewal that adds the
/// till sub-scope is taken before the next read, from the Homeserver. The till record of
/// `sample.items` came as a stub in the feed, so only a listing brings it: the renewal owes
/// a listing from the beginning, the family included.
#[tokio::test]
async fn test_records_renewal_widening_a_listing_under_way_lists_from_the_beginning() {
    renewal_widening_a_listing(true).await;
}

/// The same with the listing made in one read: the widening owes a listing of its own.
#[tokio::test]
async fn test_records_renewal_widening_after_a_whole_listing_lists_again() {
    renewal_widening_a_listing(false).await;
}

async fn renewal_widening_a_listing(split: bool) {
    let s = Setup::new();
    let family =
        Collection::with_sub_scopes("sample.items", Policy::new("sample-a", &["sample-a"]));
    let big = Collection::with_sub_scopes("sample.big", Policy::new("sample-a", &["sample-a"]));
    *s.protocol.collections.lock().unwrap() = Some(vec![family.clone(), big.clone()]);
    let mut wallet = join_scoped(&s, "wallet", &["sample-a:kiosk"]).await;
    let mut phone = s.join("phone").await;
    let till = RecordTarget::new(family.sub_scope("till").unwrap(), b"t1");
    phone
        .put_record(&till, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&till).unwrap();
    for n in 0..6 {
        let target = RecordTarget::new(big.sub_scope("kiosk").unwrap(), format!("b{n}").as_bytes());
        phone
            .put_record(&target, &value(&["b"]), vec![])
            .await
            .unwrap();
    }
    wallet.receive(None).await.unwrap();
    s.w.clock.advance_ms(3_000);
    wallet.receive(None).await.unwrap();
    assert!(!wallet.listing_owed().await.unwrap());
    assert!(wallet.shared_record(&key).await.unwrap().is_none());
    // The renewal is stored at the switch: the wallet sees it in its feed and keeps it.
    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-a:kiosk", "sample-a:till"]);
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), earlier.hash());
    // A missed item owes a listing; with one record a page, the family's one page, then
    // three of the six of `sample.big`.
    if split {
        s.w.switch.lock().max_page_bytes = 1;
    }
    s.w.switch.push_missed(1, START, START);
    let report = wallet.receive(None).await.unwrap();
    assert_eq!(report.more, split, "{:?}", report.events);
    assert_eq!(wallet.listing_owed().await.unwrap(), split);
    // The document listing the renewal, taken from the Homeserver before the next read.
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.refresh_identity().await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    assert!(wallet.listing_owed().await.unwrap());
    store_parts_for(&s, &renewed);
    for _ in 0..8 {
        let report = wallet.receive(None).await.unwrap();
        if !report.more && !wallet.listing_owed().await.unwrap() {
            break;
        }
    }
    assert!(!wallet.listing_owed().await.unwrap(), "the listing ended");
    assert!(
        wallet.shared_record(&key).await.unwrap().is_some(),
        "the till record of the family listed before the renewal is listed"
    );
}

/// A record change whose delivery failed goes to the switch at the next read, before the
/// feed, also in a read whose owed listing waits for a scope key: senders reading the
/// directory see the new record without waiting for the key.
#[tokio::test]
async fn test_records_listing_waiting_for_a_key_still_delivers_a_kept_record() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    app.state.scope_keys.keys.clear();
    let mut tx = app.tx().unwrap();
    tx.delete_prefix("scope/").unwrap();
    app.commit(tx).await.unwrap();
    s.w.switch.push_missed(3, START, START + 1);
    app.receive(None).await.unwrap();
    assert!(app.listing_owed().await.unwrap());
    s.w.clock.advance_ms(1_000);
    s.w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    let member = serde_json::Map::from_iter([("a".to_owned(), json!(1))]);
    app.set_protocol_member("sample", Some(member), None)
        .await
        .unwrap_err();
    let kept = app.record().clone();
    assert_ne!(s.w.switch.app(&me).record.as_ref(), Some(&kept));
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::ListingWaitsForKey)),
        "{:?}",
        report.events
    );
    assert_eq!(s.w.switch.app(&me).record.as_ref(), Some(&kept));
}

/// An owed publication goes at the next read, also one whose owed listing waits for a scope
/// key, for an app whose devices don't share its keys: nothing a feed shows bears on it.
#[tokio::test]
async fn test_records_listing_waiting_for_a_key_still_publishes_what_is_owed() {
    let s = Setup::new();
    let request = s.approve(&app_keys("wallet"), &ALL_PERMISSIONS);
    let config = AppConfig {
        publishes_record: true,
        ..World::config()
    };
    let mut app = App::join(s.env(), s.protocol.clone(), config, request)
        .await
        .unwrap();
    let me = app.app_id();
    let path = pubky_switch_core::records::app_record_path(&me);
    app.receive(None).await.unwrap();
    app.state.scope_keys.keys.clear();
    let mut tx = app.tx().unwrap();
    tx.delete_prefix("scope/").unwrap();
    app.commit(tx).await.unwrap();
    s.w.switch.push_missed(3, START, START + 1);
    app.receive(None).await.unwrap();
    assert!(app.listing_owed().await.unwrap());
    s.w.clock.advance_ms(1_000);
    s.w.homeserver.fail_writes(1, false);
    let member = serde_json::Map::from_iter([("a".to_owned(), json!(1))]);
    app.set_protocol_member("sample", Some(member), None)
        .await
        .unwrap();
    let accepted = app.record().clone();
    assert_eq!(s.w.switch.app(&me).record.as_ref(), Some(&accepted));
    for _ in 0..2 {
        app.receive(None).await.unwrap();
        s.w.clock.advance_ms(crate::app::PUBLISHED_CHECK_MS);
    }
    assert!(
        s.w.homeserver.file(s.w.alice.public(), &path)
            == Some(serde_json::to_vec(&accepted).unwrap()),
        "the switch holds the new record, the Homeserver still the old one"
    );
}

/// A read that delivers a kept record publishes it too, also when its owed listing then
/// waits for a scope key: the switch accepted the record in that read, so the app is
/// current, and the Homeserver needn't keep the older record meanwhile.
#[tokio::test]
async fn test_records_listing_waiting_for_a_key_publishes_the_record_it_delivers() {
    let s = Setup::new();
    let request = s.approve(&app_keys("wallet"), &ALL_PERMISSIONS);
    let config = AppConfig {
        publishes_record: true,
        ..World::config()
    };
    let mut app = App::join(s.env(), s.protocol.clone(), config, request)
        .await
        .unwrap();
    let me = app.app_id();
    let path = pubky_switch_core::records::app_record_path(&me);
    app.receive(None).await.unwrap();
    app.state.scope_keys.keys.clear();
    let mut tx = app.tx().unwrap();
    tx.delete_prefix("scope/").unwrap();
    app.commit(tx).await.unwrap();
    s.w.switch.push_missed(3, START, START + 1);
    app.receive(None).await.unwrap();
    s.w.clock.advance_ms(1_000);
    s.w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    let member = serde_json::Map::from_iter([("a".to_owned(), json!(1))]);
    app.set_protocol_member("sample", Some(member), None)
        .await
        .unwrap_err();
    let kept = app.record().clone();
    app.receive(None).await.unwrap();
    assert_eq!(s.w.switch.app(&me).record.as_ref(), Some(&kept));
    assert!(
        s.w.homeserver.file(s.w.alice.public(), &path) == Some(serde_json::to_vec(&kept).unwrap()),
        "delivered in the read, not published"
    );
}

/// A read whose owed listing waits for a scope key reads no feed, so an app whose devices
/// share its keys writes no missing Homeserver copy back in it: another device may have
/// deleted the copy to leave, and only a feed would show the departure (Switch spec 4.2).
#[tokio::test]
async fn test_records_listing_waiting_for_a_key_writes_no_missing_copy_back() {
    let s = Setup::new();
    let request = s.approve(&app_keys("wallet"), &ALL_PERMISSIONS);
    let config = AppConfig {
        publishes_record: true,
        ..World::config()
    };
    let mut app = App::join(s.env(), s.protocol.clone(), config, request)
        .await
        .unwrap();
    let me = app.app_id();
    let path = pubky_switch_core::records::app_record_path(&me);
    app.set_multi_device(true).await.unwrap();
    app.receive(None).await.unwrap();
    app.state.scope_keys.keys.clear();
    let mut tx = app.tx().unwrap();
    tx.delete_prefix("scope/").unwrap();
    app.commit(tx).await.unwrap();
    s.w.switch.push_missed(3, START, START + 1);
    app.receive(None).await.unwrap();
    assert!(app.listing_owed().await.unwrap());
    s.w.homeserver.remove(s.w.alice.public(), &path);
    s.w.clock.advance_ms(crate::app::PUBLISHED_CHECK_MS);
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::ListingWaitsForKey)),
        "{:?}",
        report.events
    );
    assert!(s.w.homeserver.file(s.w.alice.public(), &path).is_none());
}

/// A publishing app whose owed listing waits for a scope key: joined, its scope keys
/// dropped, and a `missed` item read so that the listing is owed.
async fn publishing_app_waiting_for_a_key(s: &Setup) -> App {
    let request = s.approve(&app_keys("wallet"), &ALL_PERMISSIONS);
    let config = AppConfig {
        publishes_record: true,
        ..World::config()
    };
    let mut app = App::join(s.env(), s.protocol.clone(), config, request)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    app.state.scope_keys.keys.clear();
    let mut tx = app.tx().unwrap();
    tx.delete_prefix("scope/").unwrap();
    app.commit(tx).await.unwrap();
    s.w.switch.push_missed(3, START, START + 1);
    app.receive(None).await.unwrap();
    assert!(app.listing_owed().await.unwrap());
    app
}

/// A single-device app revoked while offline, whose publication is owed and
/// whose copy the signer's clean-up deleted, writes nothing back in a read that waits for
/// a key: the key bundle read is refused first.
#[tokio::test]
async fn test_records_listing_waiting_for_a_key_revoked_app_writes_nothing_back() {
    let s = Setup::new();
    let mut app = publishing_app_waiting_for_a_key(&s).await;
    let me = app.app_id();
    let path = pubky_switch_core::records::app_record_path(&me);
    s.w.clock.advance_ms(1_000);
    s.w.homeserver.fail_writes(1, false);
    let member = serde_json::Map::from_iter([("a".to_owned(), json!(1))]);
    app.set_protocol_member("sample", Some(member), None)
        .await
        .unwrap();
    assert!(app.state.pending_publish.is_some());
    s.w.switch.revoke(me).unwrap();
    s.w.homeserver.remove(s.w.alice.public(), &path);
    let outcome = app.receive(None).await;
    assert!(
        s.w.homeserver.file(s.w.alice.public(), &path).is_none(),
        "{outcome:?}"
    );
}

/// A read that delivers a kept record and then waits for a key, with the
/// Homeserver down, reports the failed publication once.
#[tokio::test]
async fn test_records_listing_waiting_for_a_key_reports_a_failed_publication_once() {
    let s = Setup::new();
    let mut app = publishing_app_waiting_for_a_key(&s).await;
    s.w.clock.advance_ms(1_000);
    s.w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    let member = serde_json::Map::from_iter([("a".to_owned(), json!(1))]);
    app.set_protocol_member("sample", Some(member), None)
        .await
        .unwrap_err();
    app.take_events();
    s.w.homeserver.set_down(true);
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::ListingWaitsForKey)),
        "{:?}",
        report.events
    );
    let failed = report
        .events
        .iter()
        .filter(|e| matches!(e, AppEvent::RecordPublishFailed { .. }))
        .count();
    assert_eq!(failed, 1, "{:?}", report.events);
}

/// An owed publication goes at a read whose owed listing goes on at the next read, as at one
/// whose listing waits for a key: that read reads no feed and hands nothing over, and makes
/// one publication attempt.
#[tokio::test]
async fn test_records_listing_that_goes_on_still_publishes_what_is_owed_once_a_read() {
    let s = Setup::new();
    let request = s.approve(&app_keys("wallet"), &ALL_PERMISSIONS);
    let config = AppConfig {
        publishes_record: true,
        ..World::config()
    };
    let mut app = App::join(s.env(), s.protocol.clone(), config, request)
        .await
        .unwrap();
    let me = app.app_id();
    let path = pubky_switch_core::records::app_record_path(&me);
    // Fourteen records, one a listing page: a listing takes four reads.
    for n in 0..14 {
        let target = RecordTarget::new(items(), format!("n{n}").as_bytes());
        app.put_record(&target, &value(&["a"]), vec![])
            .await
            .unwrap();
    }
    app.receive(None).await.unwrap();
    s.w.clock.advance_ms(3_000);
    app.receive(None).await.unwrap();
    s.w.switch.lock().max_page_bytes = 1;
    s.w.switch.push_missed(1, START, START);
    let shop = s.peer.apps()[0].cert.app_id();
    let (_, note) = s
        .peer
        .send_to(
            &s.w.switch,
            shop,
            "sample.note",
            json!({ "text": "behind it" }),
            &[me],
        )
        .unwrap();
    assert!(app.receive(None).await.unwrap().more);
    assert!(app.listing_owed().await.unwrap());
    // A record change the switch accepts and the Homeserver doesn't take: owed.
    s.w.clock.advance_ms(1_000);
    s.w.homeserver.fail_writes(1, false);
    let member = serde_json::Map::from_iter([("a".to_owned(), json!(1))]);
    app.set_protocol_member("sample", Some(member), None)
        .await
        .unwrap();
    assert!(app.state.pending_publish.is_some());
    app.take_events();
    let accepted = app.record().clone();
    // The Homeserver down: the read tries once, and reports it once.
    s.w.homeserver.set_down(true);
    let report = app.receive(None).await.unwrap();
    assert!(report.more, "{:?}", report.events);
    let failed = report
        .events
        .iter()
        .filter(|e| matches!(e, AppEvent::RecordPublishFailed { .. }))
        .count();
    assert_eq!(failed, 1, "{:?}", report.events);
    assert_eq!(handed(&s, &note.msg_id), 0);
    // Back up: the next read, its listing still going on, publishes.
    s.w.homeserver.set_down(false);
    let report = app.receive(None).await.unwrap();
    assert!(report.more, "{:?}", report.events);
    assert_eq!(
        s.w.homeserver.file(s.w.alice.public(), &path),
        Some(serde_json::to_vec(&accepted).unwrap())
    );
    assert_eq!(handed(&s, &note.msg_id), 0);
    // The listing ends, and the entry behind the item is handed over.
    let report = app.receive(None).await.unwrap();
    assert!(!report.more, "{:?}", report.events);
    assert_eq!(handed(&s, &note.msg_id), 1);
}

/// Another device of the wallet took `renewed` and put its record carrying it, so the
/// wallet's feed shows the renewal's `cert.put` only as a stub: the wallet takes it from its
/// record in the directory at a read's start.
fn renewal_another_device_took(s: &Setup, earlier: &AppCert, renewed: &AppCert) {
    s.w.next_doc(|body| list_renewal(body, earlier, renewed, None));
    let accepts = s.protocol.accepts(renewed);
    let record = AppRecordBody::new(renewed, accepts, s.w.clock.now_ms());
    let record = AppRecord::sign(&app_keys("wallet"), record).unwrap();
    s.w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
}

#[tokio::test]
async fn test_records_renewal_another_device_took_that_widens_lists_the_family() {
    let s = Setup::new();
    let family =
        Collection::with_sub_scopes("sample.items", Policy::new("sample-a", &["sample-a"]));
    *s.protocol.collections.lock().unwrap() = Some(vec![family.clone()]);
    let mut wallet = join_scoped(&s, "wallet", &["sample-a:kiosk"]).await;
    let mut phone = s.join("phone").await;
    let till = RecordTarget::new(family.sub_scope("till").unwrap(), b"t1");
    phone
        .put_record(&till, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&till).unwrap();
    wallet.receive(None).await.unwrap();
    s.w.clock.advance_ms(3_000);
    wallet.receive(None).await.unwrap();
    assert!(wallet.shared_record(&key).await.unwrap().is_none());
    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-a:kiosk", "sample-a:till"]);
    store_parts_for(&s, &renewed);
    renewal_another_device_took(&s, &earlier, &renewed);
    for _ in 0..4 {
        wallet.receive(None).await.unwrap();
        if wallet.cert().hash() == renewed.hash() && !wallet.listing_owed().await.unwrap() {
            break;
        }
    }
    assert_eq!(wallet.cert().hash(), renewed.hash());
    assert!(!wallet.listing_owed().await.unwrap());
    assert!(
        wallet.shared_record(&key).await.unwrap().is_some(),
        "the widened family is listed"
    );
}

#[tokio::test]
async fn test_records_renewal_another_device_took_that_narrows_owes_no_listing() {
    let s = Setup::new();
    let family =
        Collection::with_sub_scopes("sample.items", Policy::new("sample-a", &["sample-a"]));
    *s.protocol.collections.lock().unwrap() = Some(vec![family.clone()]);
    let mut wallet = join_scoped(&s, "wallet", &["sample-a:kiosk", "sample-a:till"]).await;
    wallet.receive(None).await.unwrap();
    s.w.clock.advance_ms(3_000);
    wallet.receive(None).await.unwrap();
    assert!(!wallet.listing_owed().await.unwrap());
    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-a:kiosk"]);
    store_parts_for(&s, &renewed);
    renewal_another_device_took(&s, &earlier, &renewed);
    for _ in 0..3 {
        wallet.receive(None).await.unwrap();
        if wallet.cert().hash() == renewed.hash() {
            break;
        }
    }
    assert_eq!(wallet.cert().hash(), renewed.hash());
    assert!(
        !wallet.listing_owed().await.unwrap(),
        "a narrowing owes none"
    );
    wallet.receive(None).await.unwrap();
}

/// The wallet saw a record, then deleted it itself. What it saw stays seen: the phone's
/// write that brings the record back without it is flagged, and one that holds it is taken
/// (Switch spec 8.2).
#[tokio::test]
async fn test_records_own_delete_keeps_what_was_seen() {
    for (back, taken) in [(&["b"][..], false), (&["a", "c"][..], true)] {
        let s = Setup::new();
        let mut wallet = s.join("wallet").await;
        let mut phone = s.join("phone").await;
        let target = s.target("n1");
        phone
            .put_record(&target, &value(&["a"]), vec![])
            .await
            .unwrap();
        wallet.receive(None).await.unwrap();
        let key = wallet.record_key(&target).unwrap();
        let before = wallet.record_seen(&key).await.unwrap();
        assert!(before.is_some());
        wallet.delete_record(&target, vec![]).await.unwrap();
        assert_eq!(
            wallet.record_seen(&key).await.unwrap(),
            before,
            "the mark stays after the own delete"
        );
        phone.receive(None).await.unwrap();
        phone
            .put_record(&target, &value(back), vec![])
            .await
            .unwrap();
        let report = wallet.receive(None).await.unwrap();
        let flagged = report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::WriteFlagged { .. }));
        let held = wallet.shared_record(&key).await.unwrap().unwrap();
        if taken {
            assert!(!flagged, "{:?}", report.events);
            assert_eq!(ids(held.content.value()), back.to_vec());
        } else {
            assert!(
                flagged,
                "a write that drops what was seen: {:?}",
                report.events
            );
            assert_eq!(held.content, RecordContent::Deleted, "not taken");
        }
    }
}

/// Whether `events` hold a flagged write of `key` by `writer`.
fn flagged_by(events: &[AppEvent], key: &[u8; 32], writer: [u8; 16]) -> bool {
    events.iter().any(|e| {
        matches!(e, AppEvent::WriteFlagged { key: k, writer: w, .. } if k == key && *w == writer)
    })
}

/// The wallet saw `["a"]`, the phone's, and deleted the record itself.
async fn seen_then_deleted(s: &Setup) -> (App, App, RecordTarget, [u8; 32]) {
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let key = wallet.record_key(&target).unwrap();
    wallet.delete_record(&target, vec![]).await.unwrap();
    (wallet, phone, target, key)
}

fn lifetime_version(version: RecordVersion) -> Vec<u8> {
    serde_json::to_vec(&[version.generation, version.version]).unwrap()
}

/// Both the author and an app reading a verified deletion accept a new first value
/// after reloading. A live write that drops a seen item still fails its ordinary check.
#[tokio::test]
async fn test_record_lifetime_ends_for_the_deleting_app_and_its_reader() {
    let s = Setup::new();
    s.protocol
        .end_mark_at_delete
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (wallet, mut phone, target, key) = seen_then_deleted(&s).await;
    let wallet_id = wallet.app_id();
    assert_eq!(wallet.record_seen(&key).await.unwrap(), None);
    assert!(matches!(phone.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if r.content == RecordContent::Deleted));
    assert_eq!(phone.record_seen(&key).await.unwrap(), None);
    let ended = lifetime_version(phone.shared_record(&key).await.unwrap().unwrap().version);
    assert_eq!(
        wallet.protocol_get("sample", &key).await.unwrap(),
        Some(ended.clone())
    );
    assert_eq!(
        phone.protocol_get("sample", &key).await.unwrap(),
        Some(ended.clone())
    );
    drop(wallet);
    let mut wallet = App::load(s.env(), s.protocol.clone(), World::config(), wallet_id)
        .await
        .unwrap();
    phone
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    assert!(matches!(wallet.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if ids(r.content.value()) == ["b"]));
    phone
        .put_record(&target, &value(&["c"]), vec![])
        .await
        .unwrap();
    assert!(matches!(
        wallet.read_record_fresh(&target).await.unwrap(),
        RecordRead::Kept {
            reason: KeptReason::Refused,
            ..
        }
    ));
    assert_eq!(
        ids(wallet.record_seen(&key).await.unwrap().as_deref()),
        ["b"]
    );
    assert_eq!(
        wallet.protocol_get("sample", &key).await.unwrap(),
        Some(ended)
    );
}

#[tokio::test]
async fn test_record_lifetime_keeps_its_mark_through_an_unreadable_value_and_reload() {
    let s = Setup::new();
    s.protocol
        .end_mark_at_delete
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (wallet, _phone, target, key) = second_device_write_unopened(&s).await;
    let id = wallet.app_id();
    drop(wallet);
    let mut wallet = App::load(s.env(), s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    assert!(matches!(
        wallet.shared_record(&key).await.unwrap().unwrap().content,
        RecordContent::Unreadable(Unopened::KeyNotHeld { .. })
    ));
    assert_eq!(
        ids(wallet.record_seen(&key).await.unwrap().as_deref()),
        ["a", "x"]
    );
    wallet.receive(None).await.unwrap();
    assert!(matches!(wallet.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if ids(r.content.value()) == ["a", "x", "y"]));
    assert_eq!(
        ids(wallet.record_seen(&key).await.unwrap().as_deref()),
        ["a", "x", "y"]
    );
    assert_eq!(wallet.protocol_get("sample", &key).await.unwrap(), None);
}

#[tokio::test]
async fn test_record_lifetime_waits_for_a_delete_view_covering_the_upload() {
    Box::pin(async {
        let s = Setup::new();
        s.protocol
            .end_mark_at_delete
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut wallet = s.join("wallet").await;
        let mut phone = s.join("phone").await;
        let target = s.target("shared");
        let key = wallet.record_key(&target).unwrap();
        phone
            .put_record(&target, &value(&["a"]), vec![])
            .await
            .unwrap();
        wallet.read_record_fresh(&target).await.unwrap();
        let mark = wallet.record_seen(&key).await.unwrap().unwrap();
        phone.delete_record(&target, vec![]).await.unwrap();
        let deletion = s.w.switch.seq();

        // The upload duty is recorded before its key GET is answered.
        let mut changes = pubky_switch_core::recovery::UploadChanges::default();
        changes.record(key);
        s.w.switch
            .chain_upload(phone.app_id(), changes.to_value())
            .unwrap();
        let upload = crate::app::FeedPosition {
            generation: wallet.own_identity().generation(),
            seq: s.w.switch.seq(),
        };
        let mut tx = wallet.tx().unwrap();
        wallet
            .mark_uploaded(upload, vec![key], vec![], &mut tx)
            .await
            .unwrap();
        wallet.commit(tx).await.unwrap();
        s.w.switch.fail_next(Fault::Head {
            path: "/records/".into(),
            at: Some(deletion),
            forked: false,
        });
        assert!(matches!(
            wallet.read_record_fresh(&target).await.unwrap(),
            RecordRead::Kept { .. }
        ));
        let id = wallet.app_id();
        drop(wallet);
        let mut wallet = App::load(s.env(), s.protocol.clone(), World::config(), id)
            .await
            .unwrap();
        assert_eq!(
            wallet.record_seen(&key).await.unwrap().as_deref(),
            Some(mark.as_slice())
        );
        // Reading the same held delete from that earlier position still keeps the mark.
        s.w.switch.fail_next(Fault::Head {
            path: "/records/".into(),
            at: Some(deletion),
            forked: false,
        });
        assert!(matches!(
            wallet.read_record_fresh(&target).await.unwrap(),
            RecordRead::Kept { .. }
        ));
        // The listing omits deleted keys. Its empty page cannot finish this lifetime.
        s.w.switch.fail_next(Fault::Head {
            path: "records?collection".into(),
            at: Some(deletion),
            forked: false,
        });
        let listed = wallet.list_collection(&target.collection).await.unwrap();
        assert_eq!(listed.records, 0);
        assert_eq!(wallet.protocol_get("sample", &key).await.unwrap(), None);
        assert_eq!(wallet.record_seen(&key).await.unwrap(), Some(mark));
        assert!(matches!(wallet.read_record_fresh(&target).await.unwrap(),
            RecordRead::Fresh(r) if r.content == RecordContent::Deleted));
        let version = wallet.shared_record(&key).await.unwrap().unwrap().version;
        assert_eq!(
            wallet.protocol_get("sample", &key).await.unwrap(),
            Some(lifetime_version(version))
        );
        assert_eq!(wallet.record_seen(&key).await.unwrap(), None);
    })
    .await;
}

#[tokio::test]
async fn test_record_lifetime_commits_the_deleted_value_and_mark_together() {
    let s = Setup::new();
    s.protocol
        .end_mark_at_delete
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let store = Arc::new(FailingRecordCommit {
        inner: MemoryStore::new(),
        armed: std::sync::Mutex::new(None),
    });
    let env = || s.env_on(Arc::clone(&store) as Arc<dyn StateStore>);
    let mut wallet = App::join(
        env(),
        s.protocol.clone(),
        World::config(),
        s.approve(&app_keys("wallet"), &ALL_PERMISSIONS),
    )
    .await
    .unwrap();
    let mut phone = s.join("phone").await;
    let target = s.target("shared");
    let key = wallet.record_key(&target).unwrap();
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    wallet.read_record_fresh(&target).await.unwrap();
    phone.delete_record(&target, vec![]).await.unwrap();
    *store.armed.lock().unwrap() = Some(0);
    assert!(wallet.read_record_fresh(&target).await.is_err());
    let id = wallet.app_id();
    drop(wallet);
    let mut wallet = App::load(env(), s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    assert_eq!(
        ids(wallet
            .shared_record(&key)
            .await
            .unwrap()
            .unwrap()
            .content
            .value()),
        ["a"]
    );
    assert_eq!(
        ids(wallet.record_seen(&key).await.unwrap().as_deref()),
        ["a"]
    );
    assert_eq!(wallet.protocol_get("sample", &key).await.unwrap(), None);
    assert!(matches!(wallet.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(r) if r.content == RecordContent::Deleted));
    assert_eq!(wallet.record_seen(&key).await.unwrap(), None);
    let version = wallet.shared_record(&key).await.unwrap().unwrap().version;
    assert_eq!(
        wallet.protocol_get("sample", &key).await.unwrap(),
        Some(lifetime_version(version))
    );
}

/// An installation that has not read the original value can still observe its
/// verified deletion. A callback failure or oversized local write leaves it for retry.
#[tokio::test]
async fn test_record_lifetime_owner_can_retry_a_deletion_without_a_native_mark() {
    use std::sync::atomic::Ordering::SeqCst;
    let s = Setup::new();
    s.protocol.end_mark_at_delete.store(true, SeqCst);
    let mut phone = s.join("phone").await;
    let mut wallet = s.join("wallet").await;
    let target = s.target("shared");
    let key = wallet.record_key(&target).unwrap();
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    phone.delete_record(&target, vec![]).await.unwrap();
    assert_eq!(wallet.record_seen(&key).await.unwrap(), None);
    for setting in [
        &s.protocol.observation_unavailable,
        &s.protocol.large_receipt,
    ] {
        setting.store(true, SeqCst);
        assert!(wallet.read_record_fresh(&target).await.is_err());
        setting.store(false, SeqCst);
        assert_eq!(wallet.protocol_get("sample", &key).await.unwrap(), None);
    }
    let RecordRead::Fresh(deleted) = wallet.read_record_fresh(&target).await.unwrap() else {
        panic!("the read covers the deletion");
    };
    assert_eq!(deleted.content, RecordContent::Deleted);
    assert_eq!(
        wallet.protocol_get("sample", &key).await.unwrap(),
        Some(lifetime_version(deleted.version))
    );
}

/// The mark after an own delete is the one before it, not a mark of nothing.
#[tokio::test]
async fn test_records_own_delete_mark_is_the_one_before() {
    let s = Setup::new();
    let (wallet, _phone, _target, key) = seen_then_deleted(&s).await;
    let held = wallet.record_seen(&key).await.unwrap().unwrap();
    assert_eq!(ids(Some(&held)), ["a"]);
}

/// The app's own write back after its own delete is never checked against the mark: it is
/// taken, and its mark is the one of what it wrote.
#[tokio::test]
async fn test_records_own_delete_then_own_write_back_marks_what_it_wrote() {
    let s = Setup::new();
    let (mut wallet, mut phone, target, key) = seen_then_deleted(&s).await;
    let back = wallet
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    assert_eq!(ids(back.content.value()), ["b"]);
    assert!(!back.flagged);
    let events = wallet.unacknowledged_events().await.unwrap();
    assert!(!flagged_by(&events, &key, wallet.app_id()), "{events:?}");
    let held = wallet.record_seen(&key).await.unwrap().unwrap();
    assert_eq!(ids(Some(&held)), ["b"]);
    // The phone took the wallet's delete and keeps what it saw: the wallet's write back,
    // which drops a, is flagged there.
    let report = phone.receive(None).await.unwrap();
    assert!(
        flagged_by(&report.events, &key, wallet.app_id()),
        "{:?}",
        report.events
    );
}

/// Two own deletes keep the mark from before the first.
#[tokio::test]
async fn test_records_own_delete_twice_keeps_the_mark() {
    let s = Setup::new();
    let (mut wallet, mut phone, target, key) = seen_then_deleted(&s).await;
    let again = wallet.delete_record(&target, vec![]).await;
    assert!(again.is_ok(), "{again:?}");
    let held = wallet.record_seen(&key).await.unwrap().unwrap();
    assert_eq!(ids(Some(&held)), ["a"]);
    phone.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    let report = wallet.receive(None).await.unwrap();
    assert!(
        flagged_by(&report.events, &key, phone.app_id()),
        "{:?}",
        report.events
    );
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(held.content, RecordContent::Deleted);
}

/// Another app's delete the wallet took keeps the mark too, and the same write back is
/// flagged the same way.
#[tokio::test]
async fn test_records_another_apps_delete_keeps_the_mark() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let key = wallet.record_key(&target).unwrap();
    phone.delete_record(&target, vec![]).await.unwrap();
    wallet.receive(None).await.unwrap();
    let held = wallet.record_seen(&key).await.unwrap().unwrap();
    assert_eq!(ids(Some(&held)), ["a"]);
    phone
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    let report = wallet.receive(None).await.unwrap();
    assert!(
        flagged_by(&report.events, &key, phone.app_id()),
        "{:?}",
        report.events
    );
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(held.content, RecordContent::Deleted);
}

/// An own delete of a record the app never saw leaves no mark, and the phone's write after
/// it is taken.
#[tokio::test]
async fn test_records_own_delete_of_a_record_never_seen_keeps_no_mark() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n9");
    let key = wallet.record_key(&target).unwrap();
    let _ = wallet.delete_record(&target, vec![]).await;
    assert_eq!(wallet.record_seen(&key).await.unwrap(), None);
    phone.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    let report = wallet.receive(None).await.unwrap();
    assert!(
        !report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::WriteFlagged { .. })),
        "{:?}",
        report.events
    );
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), ["b"]);
}

/// A backup carries no mark: an app restored between its own delete and the phone's write
/// back takes the write.
#[tokio::test]
async fn test_records_own_delete_mark_isnt_carried_by_a_backup() {
    let s = Setup::new();
    let (wallet, mut phone, target, key) = seen_then_deleted(&s).await;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let mut restored = App::restore(
        s.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(restored.record_seen(&key).await.unwrap(), None);
    phone.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    let report = restored.receive(None).await.unwrap();
    assert!(
        !report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::WriteFlagged { .. })),
        "{:?}",
        report.events
    );
    let held = restored.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), ["b"]);
}

/// An own delete is never refused for a mark, and keeps the one held whatever the
/// protocol's marks weigh now.
#[tokio::test]
async fn test_records_own_delete_is_never_refused_for_its_mark() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let key = wallet.record_key(&target).unwrap();
    *s.protocol.pad.lock().unwrap() = MAX_SEEN_MARK_BYTES;
    let deleted = wallet.delete_record(&target, vec![]).await;
    *s.protocol.pad.lock().unwrap() = 0;
    assert!(deleted.is_ok(), "{deleted:?}");
    assert!(!uncheckable(
        &wallet.unacknowledged_events().await.unwrap(),
        &key
    ));
    let held = wallet.record_seen(&key).await.unwrap().unwrap();
    assert_eq!(ids(Some(&held)), ["a"]);
}

/// The phone's write back is checked against the mark held, as built on what the wallet
/// holds; the wallet puts its delete back over the flagged write, keeping the mark, and the
/// phone's next write that still drops what was seen is flagged again.
#[tokio::test]
async fn test_records_own_delete_put_back_over_a_flagged_write_keeps_the_mark() {
    let s = Setup::new();
    let (mut wallet, mut phone, target, key) = seen_then_deleted(&s).await;
    let deleted = wallet.shared_record(&key).await.unwrap().unwrap().version;
    phone.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    s.protocol.bases.lock().unwrap().clear();
    let report = wallet.receive(None).await.unwrap();
    assert!(flagged_by(&report.events, &key, phone.app_id()));
    assert_eq!(
        *s.protocol.bases.lock().unwrap(),
        vec![WriteBase {
            repair: None,
            expected_version: deleted,
            held: true,
            conditions: Vec::new(),
            written_at_ms: Some(s.w.clock.now_ms()),
        }]
    );
    let put_back = wallet.delete_record(&target, vec![]).await.unwrap();
    assert_eq!(put_back.content, RecordContent::Deleted);
    let held = wallet.record_seen(&key).await.unwrap().unwrap();
    assert_eq!(ids(Some(&held)), ["a"]);
    phone.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["c"]), vec![])
        .await
        .unwrap();
    let report = wallet.receive(None).await.unwrap();
    assert!(
        flagged_by(&report.events, &key, phone.app_id()),
        "{:?}",
        report.events
    );
}

/// The wallet's own write back after its own delete, its answer lost and its resend held
/// back by `429`, is read in the feed first, as any write there is.
#[tokio::test]
async fn test_records_own_write_back_read_in_the_feed_first_isnt_flagged() {
    let s = Setup::new();
    let (mut wallet, _phone, target, key) = seen_then_deleted(&s).await;
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let error = wallet
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap_err();
    assert!(error.kept_batch().is_some(), "{error:?}");
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::RateLimited,
        current: json!(null),
    });
    let report = wallet.receive(None).await.unwrap();
    let me = wallet.app_id();
    let self_flagged = flagged_by(&report.events, &key, me);
    // Once the resend goes, its original proof settles the write either way.
    s.w.clock
        .advance_ms(crate::testing::SCRIPTED_RETRY_AFTER_S * 1000);
    wallet.receive(None).await.unwrap();
    assert!(wallet.kept_batches().await.unwrap().is_empty());
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), ["b"]);
    assert!(!self_flagged, "{:?}", report.events);
    assert!(
        wallet
            .flagged_writes()
            .await
            .unwrap()
            .iter()
            .all(|flagged| flagged.writer != me),
        "no flagged write names the app itself"
    );
}

/// The same for an own write that drops what the app wrote before, no delete between: the
/// feed shows it before its answer, and it isn't flagged either.
#[tokio::test]
async fn test_records_own_write_read_in_the_feed_first_isnt_flagged() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let error = wallet
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap_err();
    assert!(error.kept_batch().is_some(), "{error:?}");
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::RateLimited,
        current: json!(null),
    });
    let report = wallet.receive(None).await.unwrap();
    let me = wallet.app_id();
    assert!(!flagged_by(&report.events, &key, me), "{:?}", report.events);
    assert!(
        wallet
            .flagged_writes()
            .await
            .unwrap()
            .iter()
            .all(|flagged| flagged.writer != me),
        "no flagged write names the app itself"
    );
}

/// Make the wallet's write of `ids` at `target` reach its feed before its answer: the answer
/// is lost, the resend at the next read is held back by `429`, and that read reads the feed.
/// A second read once the `retry_after` passed settles it from its original proof.
async fn own_write_read_in_the_feed_first(
    s: &Setup,
    wallet: &mut App,
    target: &RecordTarget,
    ids: &[&str],
) {
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let error = wallet
        .put_record(target, &value(ids), vec![])
        .await
        .unwrap_err();
    assert!(error.kept_batch().is_some(), "{error:?}");
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::RateLimited,
        current: json!(null),
    });
    wallet.receive(None).await.unwrap();
    s.w.clock
        .advance_ms(crate::testing::SCRIPTED_RETRY_AFTER_S * 1000);
    wallet.receive(None).await.unwrap();
    assert!(wallet.kept_batches().await.unwrap().is_empty());
}

/// An own write the feed showed before its answer marks what it wrote, as one taken from
/// its answer does: an app added later that builds on it, keeping what it holds, isn't
/// flagged at the wallet.
#[tokio::test]
async fn test_records_own_write_read_in_the_feed_first_marks_what_it_wrote() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a", "x"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    own_write_read_in_the_feed_first(&s, &mut wallet, &target, &["b"]).await;
    let held = wallet.record_seen(&key).await.unwrap().unwrap();
    let mark = ids(Some(&held));
    let mut till = s.join("till").await;
    till.receive(None).await.unwrap();
    till.put_record(&target, &value(&["b", "c"]), vec![])
        .await
        .unwrap();
    let report = wallet.receive(None).await.unwrap();
    assert!(
        !flagged_by(&report.events, &key, till.app_id()),
        "mark {mark:?}: {:?}",
        report.events
    );
    assert_eq!(mark, ["b"]);
}

/// The same after an own delete: the write back the feed showed first marks what it wrote,
/// not what the wallet saw before the delete.
#[tokio::test]
async fn test_records_own_write_back_read_in_the_feed_first_marks_what_it_wrote() {
    let s = Setup::new();
    let (mut wallet, _phone, target, key) = seen_then_deleted(&s).await;
    own_write_read_in_the_feed_first(&s, &mut wallet, &target, &["b"]).await;
    let held = wallet.record_seen(&key).await.unwrap().unwrap();
    let mark = ids(Some(&held));
    let mut till = s.join("till").await;
    till.receive(None).await.unwrap();
    till.put_record(&target, &value(&["b", "c"]), vec![])
        .await
        .unwrap();
    let report = wallet.receive(None).await.unwrap();
    assert!(
        !flagged_by(&report.events, &key, till.app_id()),
        "mark {mark:?}: {:?}",
        report.events
    );
    assert_eq!(mark, ["b"]);
}

/// Two devices of one app share its keys (Switch spec 3.1 "Several devices"). Device B's
/// write that drops what device A saw is the app's own: A takes it, flags nothing, and marks
/// what B wrote.
#[tokio::test]
async fn test_records_second_device_write_is_the_apps_own() {
    let s = Setup::new();
    let mut a = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    a.set_multi_device(true).await.unwrap();
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a", "x"]), vec![])
        .await
        .unwrap();
    a.receive(None).await.unwrap();
    let key = a.record_key(&target).unwrap();
    let backup = a.backup().await.unwrap();
    let store_b = Arc::new(MemoryStore::new());
    let mut b = App::restore(
        s.env_on(Arc::clone(&store_b) as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    b.receive(None).await.unwrap();
    b.end_reconcile(crate::app::UserConfirmed::new())
        .await
        .unwrap();
    assert_eq!(a.app_id(), b.app_id());
    b.put_record(&target, &value(&["a"]), vec![]).await.unwrap();
    let report = a.receive(None).await.unwrap();
    assert!(
        !flagged_by(&report.events, &key, a.app_id()),
        "{:?}",
        report.events
    );
    let held = a.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), ["a"]);
    assert!(!held.flagged);
    let mark = a.record_seen(&key).await.unwrap().unwrap();
    assert_eq!(ids(Some(&mark)), ["a"]);
}

/// A message following a record in one feed page checks the new mark and
/// signs its effect against the application that established it.
#[tokio::test]
async fn test_records_receive_checks_the_mark_of_the_preceding_write() {
    use std::sync::atomic::Ordering::Relaxed;
    let s = Setup::new();
    s.protocol.qualify_items.store(true, Relaxed);
    s.protocol.observe_values.store(true, Relaxed);
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    wallet.receive(None).await.unwrap();
    phone.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["n1", "first"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["n1", "first", "second"]), vec![])
        .await
        .unwrap();
    s.protocol.append_item_on_note.store(true, Relaxed);
    {
        let bob = s.peer.lock();
        let shop = &bob.apps[0];
        s.w.switch
            .send(
                bob.identity.key(),
                &shop.keys,
                &shop.cert,
                "sample.note",
                json!({ "text": "another item" }),
                &[wallet.app_id()],
            )
            .unwrap();
    }
    let report = wallet.receive(None).await.unwrap();
    let expected = value(&["n1", "first", "second", "third"]);
    let RecordRead::Fresh(current) = wallet.read_record_fresh(&target).await.unwrap() else {
        panic!("the message added its item");
    };
    assert_eq!(current.writer, wallet.app_id(), "{:?}", report.events);
    assert_eq!(current.content.value(), Some(expected.as_slice()));
    assert_eq!(
        wallet
            .protocol_get("sample", b"accepted-items")
            .await
            .unwrap()
            .as_deref(),
        Some(expected.as_slice())
    );
    assert_eq!(wallet.record_seen(&key).await.unwrap(), Some(expected));
}

/// A second installation reports an incomplete list. Keep the qualified list and
/// the service's new revision until a write at that revision restores all its items.
#[tokio::test]
async fn test_records_qualified_mark_holds_an_incomplete_own_write_across_load() {
    use std::sync::atomic::Ordering::Relaxed;
    let s = Setup::new();
    s.protocol.qualify_items.store(true, Relaxed);
    s.protocol.end_mark_at_delete.store(true, Relaxed);
    let mut wallet = s.join("wallet").await;
    let id = wallet.app_id();
    wallet.set_multi_device(true).await.unwrap();
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    let original = value(&["n1", "first", "second"]);
    let short = value(&["n1", "first"]);
    wallet.put_record(&target, &original, vec![]).await.unwrap();
    let applied = s.w.switch.applied().len();
    assert!(matches!(
        wallet.put_record(&s.target("n2"), &original, vec![]).await,
        Err(AppError::Refused(Refusal::Usage(_)))
    ));
    assert!(matches!(
        wallet.put_record(&target, &short, vec![]).await,
        Err(AppError::Refused(Refusal::Usage(_)))
    ));
    assert_eq!(s.w.switch.applied().len(), applied);
    let mut other = App::restore(
        s.env_on(Arc::new(MemoryStore::new())),
        Arc::new(ItemsProtocol::default()),
        World::config(),
        &wallet.backup().await.unwrap(),
    )
    .await
    .unwrap();
    other.receive(None).await.unwrap();
    other
        .end_reconcile(crate::app::UserConfirmed::new())
        .await
        .unwrap();
    assert_eq!(other.app_id(), id);
    other.put_record(&target, &short, vec![]).await.unwrap();
    let report = wallet.receive(None).await.unwrap();
    assert!(!flagged_by(&report.events, &key, id));
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert!(held.not_taken);
    assert_eq!(held.content.value(), Some(original.as_slice()));
    drop(wallet);
    let mut wallet = App::load(s.env(), s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    assert!(wallet.shared_record(&key).await.unwrap().unwrap().not_taken);
    assert_eq!(
        wallet.record_seen(&key).await.unwrap().as_deref(),
        Some(original.as_slice())
    );
    wallet.read_record_fresh(&target).await.unwrap();
    assert!(wallet.shared_record(&key).await.unwrap().unwrap().not_taken);
    let complete = value(&["n1", "first", "second", "third"]);
    wallet.put_record(&target, &complete, vec![]).await.unwrap();
    let RecordRead::Fresh(held) = wallet.read_record_fresh(&target).await.unwrap() else {
        panic!("the completed list is current");
    };
    assert!(!held.not_taken && !held.flagged);
    assert_eq!(held.content.value(), Some(complete.as_slice()));
    assert_eq!(
        wallet.record_seen(&key).await.unwrap().as_deref(),
        Some(complete.as_slice())
    );
    wallet.delete_record(&target, vec![]).await.unwrap();
    assert!(wallet.record_seen(&key).await.unwrap().is_none());
    wallet.put_record(&target, &short, vec![]).await.unwrap();
    assert_eq!(
        wallet.record_seen(&key).await.unwrap().as_deref(),
        Some(short.as_slice())
    );
}

/// Device A of the wallet has seen `["a", "x"]`, the phone's; device B, restored from A's
/// backup on a store of its own, shares the app's keys.
async fn second_device(s: &Setup) -> (App, App, RecordTarget, [u8; 32]) {
    let mut a = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    a.set_multi_device(true).await.unwrap();
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a", "x"]), vec![])
        .await
        .unwrap();
    a.receive(None).await.unwrap();
    let key = a.record_key(&target).unwrap();
    let backup = a.backup().await.unwrap();
    let store_b = Arc::new(MemoryStore::new());
    let mut b = App::restore(
        s.env_on(Arc::clone(&store_b) as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    b.receive(None).await.unwrap();
    b.end_reconcile(crate::app::UserConfirmed::new())
        .await
        .unwrap();
    (a, b, target, key)
}

/// Device B's write that drops what A saw, read by A in the record's view before its feed:
/// taken as the app's own and marked from what B wrote.
#[tokio::test]
async fn test_records_second_device_write_read_in_a_view_is_the_apps_own() {
    let s = Setup::new();
    let (mut a, mut b, target, key) = second_device(&s).await;
    b.put_record(&target, &value(&["a"]), vec![]).await.unwrap();
    let read = a.read_record(&target).await.unwrap().unwrap();
    assert_eq!(ids(read.content.value()), ["a"]);
    assert!(!read.flagged);
    let mark = a.record_seen(&key).await.unwrap().unwrap();
    assert_eq!(ids(Some(&mark)), ["a"]);
    let report = a.receive(None).await.unwrap();
    assert!(
        !flagged_by(&report.events, &key, a.app_id()),
        "{:?}",
        report.events
    );
    assert!(a.flagged_writes().await.unwrap().is_empty());
}

/// The same read in a listing a `missed` item owes, ahead of the write's chain item.
#[tokio::test]
async fn test_records_second_device_write_read_in_a_listing_is_the_apps_own() {
    let s = Setup::new();
    let (mut a, mut b, target, key) = second_device(&s).await;
    let now = s.w.clock.now_ms();
    s.w.switch.push_missed(1, now, now);
    b.put_record(&target, &value(&["a"]), vec![]).await.unwrap();
    let report = a.receive(None).await.unwrap();
    assert!(
        !flagged_by(&report.events, &key, a.app_id()),
        "{:?}",
        report.events
    );
    assert!(a.flagged_writes().await.unwrap().is_empty());
    let held = a.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), ["a"]);
    let mark = a.record_seen(&key).await.unwrap().unwrap();
    assert_eq!(ids(Some(&mark)), ["a"]);
}

/// An own delete the feed shows before its answer keeps the mark held, as at its answer.
#[tokio::test]
async fn test_records_own_delete_read_in_the_feed_first_keeps_the_mark() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(wallet.delete_record(&target, vec![]).await.is_err());
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::RateLimited,
        current: json!(null),
    });
    wallet.receive(None).await.unwrap();
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(held.content, RecordContent::Deleted);
    let mark = wallet.record_seen(&key).await.unwrap().unwrap();
    assert_eq!(ids(Some(&mark)), ["a"]);
}

/// Seal the next data epoch's keys for `apps`, after the signer moved the identity to it.
fn rotate_data_epoch(s: &Setup, apps: &[&App]) {
    let has_keys = |scope: &str| SampleProtocol::default().has_keys(scope);
    s.w.next_doc(|body| body.data_epoch = 2);
    for app in apps {
        for part in seal_bundle_parts(&s.w.alice, app.cert(), 1, 2, &has_keys).unwrap() {
            s.w.switch
                .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                    target_app_id: app.app_id(),
                    bundle: part.bundle,
                    first_epoch: part.first_epoch,
                    last_epoch: part.last_epoch,
                }))
                .unwrap();
        }
    }
}

/// Device B writes at a data epoch whose key device A doesn't hold yet, and A reads it in
/// the record's view, unopened. A keeps what it saw: the phone's later write that drops it
/// is flagged once A opens it.
#[tokio::test]
async fn test_records_second_device_write_waiting_for_its_key_keeps_the_mark() {
    let s = Setup::new();
    let mut a = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    a.set_multi_device(true).await.unwrap();
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a", "x"]), vec![])
        .await
        .unwrap();
    a.receive(None).await.unwrap();
    let key = a.record_key(&target).unwrap();
    let backup = a.backup().await.unwrap();
    let mut b = App::restore(
        s.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    b.receive(None).await.unwrap();
    b.end_reconcile(crate::app::UserConfirmed::new())
        .await
        .unwrap();
    rotate_data_epoch(&s, &[&a, &phone]);
    // B keeps everything, at the new epoch.
    b.put_record(&target, &value(&["a", "x", "y"]), vec![])
        .await
        .unwrap();
    assert_eq!(b.data_epoch(), 2);
    let read = a.read_record(&target).await.unwrap().unwrap();
    assert!(
        matches!(
            read.content,
            RecordContent::Unreadable(Unopened::KeyNotHeld { .. })
        ),
        "{:?}",
        read.content
    );
    let after_b = ids(a.record_seen(&key).await.unwrap().as_deref());
    // The phone drops x and y, and A reads that unopened too before its feed.
    phone.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    a.read_record(&target).await.unwrap();
    let report = a.receive(None).await.unwrap();
    let held = a.shared_record(&key).await.unwrap().unwrap();
    assert!(
        flagged_by(&report.events, &key, phone.app_id()),
        "mark after B's unopened write {after_b:?}, held {:?}: {:?}",
        held.content,
        report.events
    );
    assert_eq!(after_b, ["a", "x"]);
}

/// A record first taken from the feed and an own replacement share the observations
/// kept for this protocol, including when its selected backup restores on a new store.
#[tokio::test]
async fn test_records_protocol_observations_follow_the_record_and_its_selected_backup() {
    use std::sync::atomic::Ordering::Relaxed;
    let s = Setup::new();
    s.protocol.observe_values.store(true, Relaxed);
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    wallet.receive(None).await.unwrap();
    phone.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["first"]), vec![])
        .await
        .unwrap();
    // A superseded record is served as a stub (Switch wire 7.5). Read the first
    // value before its replacement, then read two still-live writes in one page.
    wallet.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["first", "second"]), vec![])
        .await
        .unwrap();
    phone
        .put_record(&s.target("n2"), &value(&["other"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    assert_eq!(
        ids(wallet
            .protocol_get("sample", b"accepted-items")
            .await
            .unwrap()
            .as_deref()),
        ["first", "second", "other"]
    );
    wallet
        .put_record(&target, &value(&["third"]), vec![])
        .await
        .unwrap();
    assert!(matches!(
        wallet.read_record_fresh(&target).await.unwrap(),
        RecordRead::Fresh(_)
    ));
    assert_eq!(
        ids(wallet
            .shared_record(&key)
            .await
            .unwrap()
            .unwrap()
            .content
            .value()),
        ["third"]
    );
    let before: Vec<Vec<String>> = serde_json::from_slice(
        &wallet
            .protocol_get("sample", b"previous-items")
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        before,
        [
            Vec::<String>::new(),
            vec!["first".to_owned()],
            Vec::<String>::new(),
            vec!["first".to_owned(), "second".to_owned()]
        ]
    );
    let backup = wallet.backup_layered().await.unwrap();
    let restored = App::restore(
        s.env_on(Arc::new(MemoryStore::new())),
        s.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(
        ids(restored
            .protocol_get("sample", b"accepted-items")
            .await
            .unwrap()
            .as_deref()),
        ["first", "second", "other", "third"]
    );
}

/// A local effect that doesn't fit cannot advance the record or its feed position.
/// The same signed application is taken after the owner can store its restriction.
#[tokio::test]
async fn test_records_protocol_observation_waits_for_its_local_writes() {
    use std::sync::atomic::Ordering::Relaxed;
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    let key = wallet.record_key(&target).unwrap();
    wallet.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["first"]), vec![])
        .await
        .unwrap();
    s.protocol.observe_values.store(true, Relaxed);
    s.protocol
        .observation_bytes
        .store(crate::app::MAX_STEP_LOCAL_BYTES, Relaxed);
    let error = wallet.receive(None).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Store(crate::error::StoreError::TooLarge { .. })
        ),
        "{error:?}"
    );
    assert!(wallet.shared_record(&key).await.unwrap().is_none());
    assert!(
        wallet
            .protocol_get("sample", b"accepted-items")
            .await
            .unwrap()
            .is_none()
    );
    let me = wallet.app_id();
    drop(wallet);
    s.protocol.observation_bytes.store(0, Relaxed);
    let mut wallet = App::load(s.env(), s.protocol.clone(), World::config(), me)
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    assert_eq!(
        ids(wallet
            .shared_record(&key)
            .await
            .unwrap()
            .unwrap()
            .content
            .value()),
        ["first"]
    );
    assert_eq!(
        ids(wallet
            .protocol_get("sample", b"accepted-items")
            .await
            .unwrap()
            .as_deref()),
        ["first"]
    );
}

/// The wallet changes `["a"]` to `["b"]`, loses the answer, and its feed shows the write
/// first: its mark is `["b"]` from then on, through the answer of the resend. Another app's
/// `["b", "c"]` on top of it is taken, not flagged.
#[tokio::test]
async fn test_records_own_write_read_in_the_feed_first_marks_b_before_and_after_its_answer() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    let me = wallet.app_id();
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let error = wallet
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap_err();
    assert!(error.kept_batch().is_some(), "{error:?}");
    // The resend is held back, so the feed shows the write first.
    s.w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::RateLimited,
        current: json!(null),
    });
    let report = wallet.receive(None).await.unwrap();
    assert!(!flagged_by(&report.events, &key, me), "{:?}", report.events);
    assert_eq!(
        wallet.kept_batches().await.unwrap().len(),
        1,
        "the answer is still owed"
    );
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), ["b"]);
    let after_feed = ids(wallet.record_seen(&key).await.unwrap().as_deref());
    assert_eq!(after_feed, ["b"], "the mark after the feed");
    // The resend's answer: the same write, which changes nothing.
    s.w.clock
        .advance_ms(crate::testing::SCRIPTED_RETRY_AFTER_S * 1000);
    wallet.receive(None).await.unwrap();
    assert!(wallet.kept_batches().await.unwrap().is_empty());
    let after_answer = ids(wallet.record_seen(&key).await.unwrap().as_deref());
    assert_eq!(after_answer, ["b"], "the mark after the answer");
    // Another app, which took ["b"], writes ["b", "c"] on top of it.
    let mut till = s.join("till").await;
    till.receive(None).await.unwrap();
    till.put_record(&target, &value(&["b", "c"]), vec![])
        .await
        .unwrap();
    let report = wallet.receive(None).await.unwrap();
    assert!(
        !flagged_by(&report.events, &key, till.app_id()),
        "{:?}",
        report.events
    );
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), ["b", "c"]);
    assert!(!held.flagged);
    assert!(wallet.flagged_writes().await.unwrap().is_empty());
}

/// Device A of the wallet holds device B's `["a", "x", "y"]` unopened, sealed at data epoch
/// 2, its mark still `["a", "x"]`; the phone holds B's write. Returns A, the phone, the
/// target and the key.
async fn second_device_write_unopened(s: &Setup) -> (App, App, RecordTarget, [u8; 32]) {
    let mut a = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    a.set_multi_device(true).await.unwrap();
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a", "x"]), vec![])
        .await
        .unwrap();
    a.receive(None).await.unwrap();
    let key = a.record_key(&target).unwrap();
    let backup = a.backup().await.unwrap();
    let mut b = App::restore(
        s.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    b.receive(None).await.unwrap();
    b.end_reconcile(crate::app::UserConfirmed::new())
        .await
        .unwrap();
    rotate_data_epoch(s, &[&a, &phone]);
    b.put_record(&target, &value(&["a", "x", "y"]), vec![])
        .await
        .unwrap();
    assert_eq!(b.data_epoch(), 2);
    let read = a.read_record(&target).await.unwrap().unwrap();
    assert!(
        matches!(
            read.content,
            RecordContent::Unreadable(Unopened::KeyNotHeld { .. })
        ),
        "{:?}",
        read.content
    );
    assert_eq!(
        ids(a.record_seen(&key).await.unwrap().as_deref()),
        ["a", "x"]
    );
    phone.receive(None).await.unwrap();
    let at_phone = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(at_phone.content.value()), ["a", "x", "y"]);
    (a, phone, target, key)
}

/// Once A reads on and takes the epoch's key, B's write opens: A's mark is what B wrote,
/// and the phone's later write that drops y is flagged.
#[tokio::test]
async fn test_records_second_device_write_reopened_with_its_key_marks_its_value() {
    let s = Setup::new();
    s.protocol
        .observe_values
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let (mut a, mut phone, target, key) = second_device_write_unopened(&s).await;
    assert_eq!(
        ids(a
            .protocol_get("sample", b"accepted-items")
            .await
            .unwrap()
            .as_deref()),
        ["a", "x"],
    );
    a.receive(None).await.unwrap();
    assert_eq!(
        ids(a
            .protocol_get("sample", b"accepted-items")
            .await
            .unwrap()
            .as_deref()),
        ["a", "x", "y"],
    );
    let held = a.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), ["a", "x", "y"]);
    assert_eq!(
        ids(a.record_seen(&key).await.unwrap().as_deref()),
        ["a", "x", "y"],
        "the mark once the record reopens"
    );
    phone
        .put_record(&target, &value(&["a", "x"]), vec![])
        .await
        .unwrap();
    let report = a.receive(None).await.unwrap();
    assert!(
        flagged_by(&report.events, &key, phone.app_id()),
        "{:?}",
        report.events
    );
    let held = a.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), ["a", "x", "y"], "not taken");
}

/// The same when A takes the key in a write of its own elsewhere (`409 stale_epoch`): the
/// key fetch reopens the record there (`reopen_unreadable`), with no read of its feed.
#[tokio::test]
async fn test_records_second_device_write_reopened_by_a_key_fetch_marks_its_value() {
    let s = Setup::new();
    let (mut a, mut phone, target, key) = second_device_write_unopened(&s).await;
    a.put_record(&s.target("n2"), &value(&["z"]), vec![])
        .await
        .unwrap();
    assert_eq!(a.data_epoch(), 2, "the key taken by the write");
    let held = a.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), ["a", "x", "y"], "reopened");
    assert_eq!(
        ids(a.record_seen(&key).await.unwrap().as_deref()),
        ["a", "x", "y"],
        "the mark once the record reopens"
    );
    phone
        .put_record(&target, &value(&["a", "x"]), vec![])
        .await
        .unwrap();
    let report = a.receive(None).await.unwrap();
    assert!(
        flagged_by(&report.events, &key, phone.app_id()),
        "{:?}",
        report.events
    );
}

/// Two slow switches that keep failing, met first among those owed an app's removal: the
/// healthy switch behind them gets it within one loop "flush while more" of the host.
#[tokio::test]
async fn test_send_two_slow_failing_peers_dont_starve_the_others() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.send(s.note("hello")).await.unwrap();
    let bob = pubky_switch_core::enc::pubky_id(&s.w.bob.public());
    let slow: Vec<_> = (0..300)
        .map(|n| identity(&format!("peer{n}")))
        .filter(|key| pubky_switch_core::enc::pubky_id(&key.public()) < bob)
        .take(2)
        .collect();
    assert_eq!(slow.len(), 2);
    let ns = crate::store::client_namespace(&app.app_id());
    for (n, key) in slow.into_iter().enumerate() {
        let origin = format!("https://slow{n}.example");
        let pubky = key.public();
        let published = PeerSwitch::new(
            key,
            &origin,
            Arc::clone(&s.w.clock),
            Arc::clone(&s.w.homeserver),
        );
        published
            .add_app(
                "shop",
                &AppSpec::new(&["sample-a"]),
                &["sample.note"],
                false,
            )
            .unwrap();
        s.router.add(
            &origin,
            Arc::new(SlowDown {
                clock: Arc::clone(&s.w.clock),
                ms: 25_000,
            }) as Arc<dyn Transport>,
        );
        let mut tx = crate::app::state::Tx::new(&ns);
        crate::app::directory::put_peer(
            &mut tx,
            &pubky,
            &crate::app::directory::PeerSwitch {
                known_version: Some(1),
                last_sent_ms: Some(s.w.clock.now_ms()),
            },
        )
        .unwrap();
        tx.commit(&StoreHandle::inline(
            Arc::clone(&s.w.store) as Arc<dyn StateStore>
        ))
        .await
        .unwrap();
    }
    let doc = s.w.next_doc(|body| {
        body.removed.push(RemovedApp {
            app_id: [9; 16],
            distrust_from: START,
        })
    });
    app.refresh_identity().await.unwrap();
    let mut flushes = 0;
    loop {
        flushes += 1;
        if !app.flush_outbox().await.unwrap().more {
            break;
        }
        assert!(flushes < 10, "the loop settles");
    }
    let held = s.peer.lock().peers.get(&s.w.alice.public()).cloned();
    assert!(
        held.is_some_and(|held| held.version() == doc.version()),
        "the healthy switch has the removal after {flushes} flushes"
    );
}

/// The wallet and a second device of it, restored from its backup into a store of its own;
/// then the signer removes the wallet, distrusted from an hour later, and publishes that
/// before the switch takes it, as after a lost device. Returns the wallet, the second
/// device, which has read the removal, and `distrust_from`.
async fn removed_app_and_its_second_device(s: &Setup) -> (App, App, u64) {
    let wallet = s.join("wallet").await;
    let backup = wallet.backup().await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let mut device = App::restore(
        s.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    device
        .end_reconcile(crate::app::UserConfirmed::new())
        .await
        .ok();
    s.w.clock.advance_ms(HOUR);
    let distrust_from = s.w.clock.now_ms();
    let me = wallet.app_id();
    s.w.signer
        .sign_next(|body| {
            body.apps.retain(|app| app.app_id != me);
            body.removed.push(RemovedApp {
                app_id: me,
                distrust_from,
            })
        })
        .unwrap();
    device.refresh_identity().await.unwrap();
    s.w.clock.advance_ms(HOUR);
    (wallet, device, distrust_from)
}

/// A write signed with the app's key, dated after the app's own `distrust_from`: the lost
/// device's, for all the identity can tell (Switch spec 3.1, 12.2 step 3). The app's other
/// device, which read its removal, doesn't take it as a trusted write of its own.
#[tokio::test]
async fn test_records_own_key_write_after_its_removal_cutoff_isnt_trusted() {
    let s = Setup::new();
    let (mut wallet, mut device, _) = removed_app_and_its_second_device(&s).await;
    let late = s.target("late");
    wallet
        .put_record(&late, &value(&["l"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&late).unwrap();
    device.read_record(&late).await.unwrap();
    let held = device.shared_record(&key).await.unwrap();
    assert!(held.as_ref().is_none_or(|held| held.doubtful), "{held:?}");
}

/// The same write with nothing dating it: a removed app's write without a time is doubtful
/// (Switch wire 6.2 "Accepting a write" step 4), at the app's other device too.
#[tokio::test]
async fn test_records_own_key_undated_write_after_its_removal_is_doubtful() {
    let s = Setup::new();
    let (mut wallet, mut device, _) = removed_app_and_its_second_device(&s).await;
    let late = s.target("late");
    wallet
        .put_record(&late, &value(&["l"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&late).unwrap();
    s.w.switch.lock().shared.hide_proofs = true;
    device.read_record(&late).await.unwrap();
    let held = device.shared_record(&key).await.unwrap();
    assert!(held.as_ref().is_none_or(|held| held.doubtful), "{held:?}");
}

/// Another app's write that drops what the reader saw, shown first with a version the
/// service made implausible: ignored, nothing taken. Shown as it is, and from the feed with
/// a write on top of it, the mark of what the reader saw still catches both.
#[tokio::test]
async fn test_records_regression_shown_at_an_implausible_version_is_caught_later() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&target).unwrap();
    wallet.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    let honest = s.w.switch.record(&key).unwrap();
    {
        let mut switch = s.w.switch.lock();
        let held = switch.shared.records.get_mut(&key).unwrap();
        held.proof = None;
        held.state.version = RecordVersion::new(99, held.state.version.version);
    }
    wallet.read_record(&target).await.unwrap();
    let events = wallet.take_events();
    assert!(flagged_rules(&events).is_empty(), "{events:?}");
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    assert!(!held.flagged);
    s.w.switch.lock().shared.records.insert(key, honest);
    wallet.read_record(&target).await.unwrap();
    let rules = flagged_rules(&wallet.take_events());
    assert!(
        rules.iter().any(|rule| rule.contains("dropped")),
        "{rules:?}"
    );
    phone
        .put_record(&target, &value(&["b", "c"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let held = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    let flagged = wallet.flagged_writes().await.unwrap();
    assert!(
        flagged
            .iter()
            .filter(|f| f.writer == phone.app_id() && f.reason.contains("dropped"))
            .count()
            >= 2,
        "{flagged:?}"
    );
}

/// The wallet's honest write under its renewed certificate, after the earlier one's renewal
/// closed, served with that earlier certificate, which verifies the signature too since
/// the key is the same: the service picked the certificate, so nothing names the wallet.
#[tokio::test]
async fn test_records_write_served_with_an_earlier_cert_names_no_app() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let (mut wallet, _, _, earlier) = own_write_under_a_closed_renewal(&s).await;
    let target = s.target("n2");
    wallet
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.switch.lock().shared.records.get_mut(&key).unwrap().cert = Some(earlier.signed().clone());
    phone.refresh_identity().await.unwrap();
    phone.read_record(&target).await.unwrap();
    let events = phone.take_events();
    assert!(flagged_rules(&events).is_empty(), "{events:?}");
    assert!(phone.flagged_writes().await.unwrap().is_empty());
}

/// The wallet's honest write under its renewed certificate, served with the earlier one,
/// read by a phone that holds only the earlier one, and `phone` after it: the phone reads
/// the directory for the renewed certificate, which counts, and takes the write. With
/// `fail_first`, that directory read fails to connect first.
async fn earlier_cert_view_read_with_the_directory(fail_first: bool) -> (Setup, App, [u8; 32]) {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let (mut wallet, _, _, earlier) = own_write_under_a_closed_renewal(&s).await;
    let target = s.target("n2");
    wallet
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.switch.lock().shared.records.get_mut(&key).unwrap().cert = Some(earlier.signed().clone());
    phone.refresh_identity().await.unwrap();
    if fail_first {
        s.w.switch.fail_next(Fault::Unreachable {
            path: "/directory".into(),
            after: 0,
        });
        phone.read_record(&target).await.unwrap();
        assert!(phone.shared_record(&key).await.unwrap().is_none());
        s.w.clock.advance_ms(crate::app::SENDER_REREAD_MS);
    }
    phone.read_record(&target).await.unwrap();
    (s, phone, key)
}

/// A healthy directory: the phone takes the wallet's write at its first read.
#[tokio::test]
async fn test_records_view_cert_settled_by_the_directory_is_taken() {
    let (_s, phone, key) = earlier_cert_view_read_with_the_directory(false).await;
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["b"]);
    assert!(phone.flagged_writes().await.unwrap().is_empty());
}

/// The directory read fails to connect at the first read: nothing marks the certificate
/// asked, and a later read, past the pacing, reads the directory again and takes the write.
#[tokio::test]
async fn test_records_failed_directory_read_is_tried_again_later() {
    let (_s, phone, key) = earlier_cert_view_read_with_the_directory(true).await;
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["b"]);
    assert!(phone.flagged_writes().await.unwrap().is_empty());
}

/// The wallet's honest write under its earlier certificate, made before the renewal
/// closed, served without the proof that dates it: the service withheld the proof, so
/// nothing names the wallet.
#[tokio::test]
async fn test_records_write_under_a_closed_renewal_served_without_its_proof_names_no_app() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let (_wallet, target, key, _) = own_write_under_a_closed_renewal(&s).await;
    s.w.switch
        .lock()
        .shared
        .records
        .get_mut(&key)
        .unwrap()
        .proof = None;
    phone.refresh_identity().await.unwrap();
    phone.read_record(&target).await.unwrap();
    let events = phone.take_events();
    assert!(flagged_rules(&events).is_empty(), "{events:?}");
    assert!(phone.flagged_writes().await.unwrap().is_empty());
}

/// Another app's write with no standing, shown without its proof at a new version at each
/// read: the same write is one flagged write, at the version it was last shown at, however
/// often and at whatever version the service shows it.
#[tokio::test]
async fn test_records_one_write_shown_at_new_versions_is_flagged_once() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let (wallet, target, key, earlier) = write_under_a_renewal_closed_to(&s, &["sample-c"]).await;
    let purged =
        s.w.signer
            .sign_next(|body| body.renewed.retain(|entry| entry.cert != earlier.hash()))
            .unwrap();
    s.w.switch.deliver_identity(&purged).unwrap();
    phone.refresh_identity().await.unwrap();
    let mut last = None;
    for bump in 0..4 {
        {
            let mut switch = s.w.switch.lock();
            let held = switch.shared.records.get_mut(&key).unwrap();
            held.proof = None;
            held.state.version = RecordVersion::new(
                held.state.version.generation,
                held.state.version.version + bump,
            );
            last = Some(held.state.version);
        }
        phone.read_record(&target).await.unwrap();
    }
    let flagged = phone.flagged_writes().await.unwrap();
    assert_eq!(flagged.len(), 1, "{flagged:?}");
    assert_eq!(flagged[0].writer, wallet.app_id());
    assert_eq!(Some(flagged[0].version), last);
}

/// Ten writes of the phone, each dropping what the wallet saw, each read from the feed: each
/// is flagged, and the record keeps the eight shown at the highest versions.
#[tokio::test]
async fn test_records_flagged_writes_are_bounded_per_record() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let mut versions = Vec::new();
    let mut flags = 0;
    for n in 0..10 {
        let item = format!("b{n}");
        phone
            .put_record(&target, &value(&[item.as_str()]), vec![])
            .await
            .unwrap();
        let key = phone.record_key(&target).unwrap();
        versions.push(s.w.switch.record(&key).unwrap().state.version);
        flags += flagged_rules(&wallet.receive(None).await.unwrap().events).len();
    }
    assert_eq!(flags, 10);
    let flagged = wallet.flagged_writes().await.unwrap();
    let mut kept: Vec<RecordVersion> = flagged.iter().map(|f| f.version).collect();
    kept.sort();
    assert_eq!(kept, versions[2..].to_vec());
    assert!(flagged.iter().all(|f| f.writer == phone.app_id()));
}

/// The wallet's write under its earlier certificate, before a reduction dropped the
/// record's write scope and closed, without a proof, as a recovery upload leaves it: the
/// phone doesn't take it and names no app, but follows its version, so it writes the record
/// over it.
#[tokio::test]
async fn test_records_upload_under_a_reduced_renewal_is_written_over() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    phone.receive(None).await.unwrap();
    assert!(phone.shared_record(&key).await.unwrap().is_some());
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewal_of(&s, "wallet", &["sample-c"]);
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    let opened =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, None))
            .unwrap();
    let closed =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, Some(until)))
            .unwrap();
    s.w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: wallet.app_id(),
            cert: renewed.signed().clone(),
        })
        .unwrap();
    s.w.switch.deliver_identity(&opened).unwrap();
    s.w.switch.deliver_identity(&closed).unwrap();
    s.w.clock.advance_ms(2 * CLOCK_TOLERANCE_MS);
    {
        let mut switch = s.w.switch.lock();
        let held = switch.shared.records.get_mut(&key).unwrap();
        held.proof = None;
        held.uploaded = Some(false);
    }
    phone.refresh_identity().await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    // Read, the write isn't taken, names no app, and the record doesn't read as flagged.
    phone.read_record(&target).await.unwrap();
    let held = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(held.content.value()), vec!["a"]);
    assert!(!held.flagged);
    assert!(phone.flagged_writes().await.unwrap().is_empty());
    let written = phone
        .update_record(&target, vec![], |_| Some(value(&["a", "c"])))
        .await;
    assert!(written.is_ok(), "{written:?}");
}

/// A view of the key read whose write, signed by the phone, names another collection: the
/// phone signed that collection, so the write is flagged naming the phone.
#[tokio::test]
async fn test_records_write_of_another_collection_at_the_key_read_is_flagged() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    phone
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&target).unwrap();
    let genuine = s.w.switch.lock().shared.records[&key].op.clone();
    let mut body = SignedOp::peek(&genuine).unwrap().body().clone();
    if let OpKind::RecordPut(put) = &mut body.kind {
        put.collection = [7; 32];
    }
    let resigned = SignedOp::sign(&app_keys("phone"), body).unwrap();
    {
        let mut switch = s.w.switch.lock();
        let held = switch.shared.records.get_mut(&key).unwrap();
        held.op = resigned.signed().clone();
        held.revision.item_hash = resigned.item_hash().unwrap();
        held.proof = None;
    }
    wallet.read_record(&target).await.unwrap();
    let events = wallet.take_events();
    assert!(
        events.iter().any(|e| matches!(
            e,
            AppEvent::WriteFlagged { writer, .. } if *writer == phone.app_id()
        )),
        "{events:?}"
    );
}

/// A directory that keeps failing, read for a writer's listed certificate: three reads of
/// the record within a minute send one directory request, and the write isn't taken.
#[tokio::test]
async fn test_records_failing_directory_is_asked_once_a_minute() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let (mut wallet, _, _, earlier) = own_write_under_a_closed_renewal(&s).await;
    let target = s.target("n2");
    wallet
        .put_record(&target, &value(&["b"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.switch.lock().shared.records.get_mut(&key).unwrap().cert = Some(earlier.signed().clone());
    phone.refresh_identity().await.unwrap();
    for _ in 0..4 {
        s.w.switch.fail_next(Fault::Unreachable {
            path: "/directory".into(),
            after: 0,
        });
    }
    let directory_reads = |s: &Setup| {
        s.log()
            .iter()
            .filter(|line| line.contains("/directory"))
            .count()
    };
    let before = directory_reads(&s);
    for _ in 0..3 {
        phone.read_record(&target).await.unwrap();
    }
    assert_eq!(directory_reads(&s) - before, 1);
    assert!(phone.shared_record(&key).await.unwrap().is_none());
    s.w.clock.advance_ms(crate::app::SENDER_REREAD_MS);
    phone.read_record(&target).await.unwrap();
    assert_eq!(directory_reads(&s) - before, 2);
}

/// The wallet's honest write under its renewed certificate, served with the earlier one, a
/// proof that gives its version, and a view whose version the service raised, read by a
/// phone that holds only the earlier certificate while the directory fails: the write
/// names nobody, and the phone follows the version the proof gives, not the view's. The
/// record reads as not flagged, but as one whose current write the phone didn't take.
#[tokio::test]
async fn test_records_unnamed_write_follows_the_version_its_proof_gives() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let (mut wallet, target, key, earlier) = own_write_under_a_closed_renewal(&s).await;
    phone.refresh_identity().await.unwrap();
    phone.read_record(&target).await.unwrap();
    let taken = phone.shared_record(&key).await.unwrap().unwrap();
    assert!(!taken.not_taken && !taken.flagged);
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    let proven = {
        let mut switch = s.w.switch.lock();
        let held = switch.shared.records.get_mut(&key).unwrap();
        held.cert = Some(earlier.signed().clone());
        let proven = held.state.version;
        held.state.version = RecordVersion::new(proven.generation, proven.version + 3);
        proven
    };
    s.w.switch.fail_next(Fault::Unreachable {
        path: "/directory".into(),
        after: 0,
    });
    phone.take_events();
    phone.read_record(&target).await.unwrap();
    let told = phone
        .take_events()
        .iter()
        .filter(|e| matches!(e, AppEvent::WriteNotTaken { key: k } if *k == key))
        .count();
    assert_eq!(told, 1, "the protocol is told once");
    assert!(phone.flagged_writes().await.unwrap().is_empty());
    let held = phone.held_record(&key).await.unwrap().unwrap();
    assert_eq!(held.base(&key, None).0, proven);
    let shared = phone.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(shared.content.value()), vec!["a"]);
    assert!(!shared.flagged);
    assert!(shared.not_taken);
}

/// The wallet's write served with its earlier certificate, which a renewal closed, and no
/// proof: nothing dates it, so the phone doesn't take it, names nobody, is told so, and
/// builds on its version. A later write the phone takes ends that.
#[tokio::test]
async fn test_records_undated_write_under_a_closed_renewal_is_not_taken_until_one_is() {
    let s = Setup::new();
    let mut phone = s.join("phone").await;
    let (mut wallet, target, key, earlier) = own_write_under_a_closed_renewal(&s).await;
    phone.refresh_identity().await.unwrap();
    phone.read_record(&target).await.unwrap();
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    let (cert, proof) = {
        let mut switch = s.w.switch.lock();
        let held = switch.shared.records.get_mut(&key).unwrap();
        let kept = (held.cert.clone(), held.proof.clone());
        held.cert = Some(earlier.signed().clone());
        held.proof = None;
        kept
    };
    s.w.switch.fail_next(Fault::Unreachable {
        path: "/directory".into(),
        after: 0,
    });
    phone.take_events();
    phone.read_record(&target).await.unwrap();
    let told = phone
        .take_events()
        .iter()
        .filter(|e| matches!(e, AppEvent::WriteNotTaken { key: k } if *k == key))
        .count();
    assert_eq!(told, 1);
    let shared = phone.shared_record(&key).await.unwrap().unwrap();
    assert!(shared.not_taken && !shared.flagged, "{shared:?}");
    assert!(
        !shared.different_write_at_held_version,
        "the refused write is newer"
    );
    assert_eq!(ids(shared.content.value()), vec!["a"]);
    {
        let mut switch = s.w.switch.lock();
        let held = switch.shared.records.get_mut(&key).unwrap();
        held.cert = cert;
        held.proof = proof;
    }
    wallet
        .put_record(&target, &value(&["a", "b", "c"]), vec![])
        .await
        .unwrap();
    phone.read_record(&target).await.unwrap();
    let shared = phone.shared_record(&key).await.unwrap().unwrap();
    assert!(!shared.not_taken, "{shared:?}");
    assert_eq!(ids(shared.content.value()), vec!["a", "b", "c"]);
}

/// A collection of the neutral protocol under a permanent policy naming no generation
/// (Switch spec 10.3.1).
fn kept_items() -> Collection {
    Collection::new(
        "sample.kept",
        Policy::new("sample-a", &["sample-a"]).permanent(None),
    )
}

/// A setup whose protocol has [`items`] and [`kept_items`], with one record written in each
/// by the wallet and taken by the phone: the setup, the wallet, the phone, and the two
/// targets, the ordinary one first.
async fn with_kept_records() -> (Setup, App, App, RecordTarget, RecordTarget) {
    let s = Setup::new();
    *s.protocol.collections.lock().unwrap() = Some(vec![items(), kept_items()]);
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let ordinary = s.target("n1");
    let kept = RecordTarget::new(kept_items(), b"n1");
    for target in [&ordinary, &kept] {
        wallet
            .put_record(target, &value(&["a"]), vec![])
            .await
            .unwrap();
    }
    phone.receive(None).await.unwrap();
    (s, wallet, phone, ordinary, kept)
}

#[tokio::test]
async fn test_permanent_delete_refused_before_it_is_sent() {
    let (s, mut wallet, _, ordinary, kept) = with_kept_records().await;
    let written = s.w.switch.applied().len();
    let error = wallet.delete_record(&kept, vec![]).await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error:?}"
    );
    // Nothing was signed, kept or sent.
    assert_eq!(s.w.switch.applied().len(), written);
    assert!(wallet.kept_batches().await.unwrap().is_empty());
    // An ordinary record is deleted as before, and the permanent one is still written to.
    let deleted = wallet.delete_record(&ordinary, vec![]).await.unwrap();
    assert_eq!(deleted.content, RecordContent::Deleted);
    let changed = wallet
        .put_record(&kept, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    assert_eq!(ids(changed.content.value()), vec!["a", "b"]);
}

#[tokio::test]
async fn test_permanent_delete_a_switch_applied_raises_the_alarm() {
    let (s, mut wallet, mut phone, ordinary, kept) = with_kept_records().await;
    // A faulty switch applies the wallet's deletes without the shape check: the ordinary
    // one is taken, the permanent one, which its proof shows applied, is a rollback.
    for target in [&ordinary, &kept] {
        let (_, delete) = wallet.record_op(target, None, vec![]).await.unwrap();
        s.w.switch.skip_next_shape_check();
        s.w.switch.app_op(&app_keys("wallet"), delete).unwrap();
        let _ = phone.receive(None).await;
        let key = phone.record_key(target).unwrap();
        if target == &ordinary {
            assert!(phone.alarm().is_none(), "{:?}", phone.alarm());
            let held = phone.shared_record(&key).await.unwrap().unwrap();
            assert_eq!(held.content, RecordContent::Deleted);
        } else {
            assert!(
                matches!(phone.alarm(), Some(Alarm::Rollback { .. })),
                "{:?}",
                phone.alarm()
            );
        }
    }
}

#[tokio::test]
async fn test_permanent_absent_raises_the_alarm() {
    let (s, _, mut phone, ordinary, kept) = with_kept_records().await;
    let mut tablet = s.join("tablet").await;
    tablet.list_collection(&kept_items()).await.unwrap();
    let kept_key = tablet.record_key(&kept).unwrap();
    assert!(tablet.shared_record(&kept_key).await.unwrap().is_some());
    // An ordinary record the switch no longer holds reads as not found.
    s.w.switch
        .drop_record(&phone.record_key(&ordinary).unwrap())
        .unwrap();
    let read = phone.read_record_fresh(&ordinary).await.unwrap();
    assert!(
        matches!(
            read,
            RecordRead::Kept {
                reason: KeptReason::NotFound,
                ..
            }
        ),
        "{read:?}"
    );
    assert!(phone.alarm().is_none());
    // A permanent one seen live in this generation is a rollback, at a read of the key and
    // at a listing that leaves it out.
    s.w.switch
        .drop_record(&phone.record_key(&kept).unwrap())
        .unwrap();
    assert!(phone.read_record_fresh(&kept).await.is_err());
    assert!(matches!(phone.alarm(), Some(Alarm::Rollback { .. })));
    assert!(tablet.list_collection(&kept_items()).await.is_err());
    assert!(matches!(tablet.alarm(), Some(Alarm::Rollback { .. })));
}

#[tokio::test]
async fn test_permanent_not_hosted_read_raises_no_alarm() {
    let (s, _, mut phone, _, kept) = with_kept_records().await;
    let key = phone.record_key(&kept).unwrap();
    assert!(phone.shared_record(&key).await.unwrap().is_some());
    // The switch lost the account with its mark: its signed `404` says it doesn't host the
    // identity, which says nothing of the record (Switch spec 12.7 step 5).
    s.w.switch.lose_account();
    s.w.switch.lose_mark();
    let read = phone.read_record_fresh(&kept).await;
    // The read keeps the copy, as for a switch it couldn't reach: not a record not found.
    assert!(
        matches!(
            read,
            Ok(RecordRead::Kept {
                record: Some(_),
                reason: KeptReason::Unreachable(_),
            })
        ),
        "{read:?}"
    );
    assert!(phone.alarm().is_none(), "{:?}", phone.alarm());
    assert!(phone.shared_record(&key).await.unwrap().is_some());
}

/// A setup where the phone holds a permanent record live, its own create, and its next
/// read finds in the feed the wallet's later write of it, under a certificate the phone never
/// holds, which a renewal then reduced: the phone judges that write by the record's view
/// (Switch wire 6.2 "Accepting a write" step 1). The setup, the phone and the record's key.
async fn unheld_write_at_a_kept_record() -> (Setup, App, [u8; 32]) {
    let s = Setup::new();
    *s.protocol.collections.lock().unwrap() = Some(vec![items(), kept_items()]);
    let mut wallet = join_scoped(&s, "wallet", &["sample-a", "sample-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    let kept = RecordTarget::new(kept_items(), b"n1");
    phone
        .put_record(&kept, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&kept).unwrap();
    wallet.receive(None).await.unwrap();
    wallet
        .put_record(&kept, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    (s, phone, key)
}

#[tokio::test]
async fn test_permanent_feed_write_judged_by_a_view_that_reads_absent_raises_the_alarm() {
    let (s, mut phone, key) = unheld_write_at_a_kept_record().await;
    // The switch lets the record go after its feed showed the write: the view is a `404`
    // at an account it hosts.
    s.w.switch.fail_next(Fault::Error {
        path: "/records/".into(),
        code: ErrorCode::NotFound,
        current: serde_json::Value::Null,
    });
    let before = s.log().len();
    let read = phone.receive(None).await;
    assert!(read.is_err(), "{read:?}");
    assert_eq!(record_reads(&s.log()[before..]).len(), 1);
    assert!(phone.shared_record(&key).await.unwrap().is_some());
    assert!(
        matches!(phone.alarm(), Some(Alarm::Rollback { .. })),
        "{:?}",
        phone.alarm()
    );
}

#[tokio::test]
async fn test_permanent_feed_write_judged_by_a_not_hosted_view_raises_no_alarm() {
    let (s, mut phone, key) = unheld_write_at_a_kept_record().await;
    // The view answered with the `404` saying the switch doesn't host the identity: the
    // switch is unreachable, and the record isn't absent.
    s.w.switch.fail_next(Fault::Error {
        path: "/records/".into(),
        code: ErrorCode::NotFound,
        current: pubky_switch_core::http::not_hosted_current(),
    });
    let before = s.log().len();
    let read = phone.receive(None).await;
    assert!(
        matches!(&read, Err(AppError::Switch(error)) if error.is_not_hosted()),
        "{read:?}"
    );
    assert_eq!(record_reads(&s.log()[before..]).len(), 1);
    assert!(phone.alarm().is_none(), "{:?}", phone.alarm());
    assert!(phone.shared_record(&key).await.unwrap().is_some());
}

#[tokio::test]
async fn test_permanent_upload_reread_that_reads_absent_raises_the_alarm() {
    let (s, _, mut phone, _, kept) = with_kept_records().await;
    let key = phone.record_key(&kept).unwrap();
    let changes = pubky_switch_core::recovery::UploadChanges {
        records: [key].into(),
        ..Default::default()
    };
    s.w.switch
        .chain_upload([9; 16], changes.to_value())
        .unwrap();
    // The read again answered with the `404` saying the switch doesn't host the identity:
    // unreachable, so the record stays marked and nothing is absent.
    s.w.switch.fail_next(Fault::Error {
        path: "/records/".into(),
        code: ErrorCode::NotFound,
        current: pubky_switch_core::http::not_hosted_current(),
    });
    let before = s.log().len();
    phone.receive(None).await.unwrap();
    assert_eq!(record_reads(&s.log()[before..]).len(), 1);
    assert!(phone.alarm().is_none(), "{:?}", phone.alarm());
    // The switch lets the record go: the next read again is a `404` at an account it hosts.
    s.w.switch.drop_record(&key).unwrap();
    let before = s.log().len();
    let read = phone.receive(None).await;
    assert!(read.is_err(), "{read:?}");
    assert_eq!(record_reads(&s.log()[before..]).len(), 1);
    assert!(
        matches!(phone.alarm(), Some(Alarm::Rollback { .. })),
        "{:?}",
        phone.alarm()
    );
}

#[tokio::test]
async fn test_permanent_listing_of_another_collection_raises_no_alarm() {
    let (_, _, mut phone, _, kept) = with_kept_records().await;
    let key = phone.record_key(&kept).unwrap();
    assert!(phone.shared_record(&key).await.unwrap().is_some());
    // A listing of the ordinary collection covers every key, and lists none of the
    // permanent collection's: that says nothing of them.
    let listed = phone.list_collection(&items()).await;
    assert!(listed.is_ok(), "{listed:?}");
    assert!(phone.alarm().is_none(), "{:?}", phone.alarm());
}

#[tokio::test]
async fn test_permanent_listing_across_pages_judges_each_page_by_its_range() {
    let (s, mut wallet, mut phone, _, kept) = with_kept_records().await;
    let mut targets = vec![kept];
    for natural in [b"n2", b"n3"] {
        let target = RecordTarget::new(kept_items(), natural);
        wallet
            .put_record(&target, &value(&["a"]), vec![])
            .await
            .unwrap();
        targets.push(target);
    }
    phone.receive(None).await.unwrap();
    let mut keys: Vec<[u8; 32]> = targets
        .iter()
        .map(|target| phone.record_key(target).unwrap())
        .collect();
    keys.sort_by_key(|key| pubky_switch_core::enc::b64(key));
    // One record to a page: each page covers the keys after the one before it, through its
    // own, and the records of the other pages are outside its range, on either side.
    s.w.switch.lock().max_page_bytes = 1;
    let pages = s.w.switch.lock().shared.listings;
    let mut listed = 0;
    loop {
        let page = phone.list_collection(&kept_items()).await.unwrap();
        listed += page.records;
        if !page.more {
            break;
        }
    }
    assert_eq!(listed, 3);
    assert_eq!(s.w.switch.lock().shared.listings - pages, 3);
    assert!(phone.alarm().is_none(), "{:?}", phone.alarm());
    // The middle record gone: the page after the first covers its key without it.
    s.w.switch.drop_record(&keys[1]).unwrap();
    let mut outcome = Ok(());
    for _ in 0..3 {
        match phone.list_collection(&kept_items()).await {
            Ok(page) if page.more => {}
            Ok(_) => break,
            Err(error) => {
                outcome = Err(error);
                break;
            }
        }
    }
    assert!(outcome.is_err(), "{outcome:?}");
    assert!(
        matches!(phone.alarm(), Some(Alarm::Rollback { .. })),
        "{:?}",
        phone.alarm()
    );
}

/// A signer can narrow the reader before its next feed call. The filtered page
/// keeps the held key, and the pending listing can discover the renewal even
/// when an earlier inbox item belongs to the protocol that owes the listing.
#[tokio::test]
async fn test_permanent_listing_waits_for_the_service_reader_across_load() {
    let s = Setup::new();
    let family = Collection::with_sub_scopes(
        "sample.kept",
        Policy::new("sample-a", &["sample-a"]).permanent(None),
    );
    *s.protocol.collections.lock().unwrap() = Some(vec![family.clone()]);
    let mut wallet = join_scoped(&s, "wallet", &["sample-a"]).await;
    let mut phone = s.join("phone").await;
    let till = RecordTarget::new(family.sub_scope("till").unwrap(), b"t1");
    phone
        .put_record(&till, &value(&["first"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&till).unwrap();
    wallet.receive(None).await.unwrap();
    assert!(wallet.shared_record(&key).await.unwrap().is_some());
    let id = wallet.app_id();
    let at = wallet.cursor();
    let earlier = wallet.cert().clone();
    s.w.clock.advance_ms(HOUR);
    s.peer
        .send_to(
            &s.w.switch,
            s.peer.apps()[0].cert.app_id(),
            "sample.note",
            json!({ "text": "before renewal" }),
            &[id],
        )
        .unwrap();
    let renewed = renewed_cert(&s, "wallet", &["sample-a:kiosk"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.config.page_size = 1;
    let page = wallet.list_collection(&family).await.unwrap();
    assert!(page.more);
    assert_eq!(wallet.cursor(), at);
    assert!(wallet.alarm().is_none());
    let config = wallet.config.clone();
    drop(wallet);
    let mut wallet = App::load(s.env(), s.protocol.clone(), config, id)
        .await
        .unwrap();
    let mut done = false;
    for _ in 0..12 {
        if !wallet.list_collection(&family).await.unwrap().more {
            done = true;
            break;
        }
    }
    assert!(done);
    assert_eq!(wallet.cert().hash(), renewed.hash());
    assert_eq!(wallet.cursor(), at);
    assert!(wallet.alarm().is_none());
    assert_eq!(
        ids(wallet
            .shared_record(&key)
            .await
            .unwrap()
            .unwrap()
            .content
            .value()),
        ["first"]
    );
}

/// The narrow reader has never seen the till record. Its old empty range cannot
/// complete the wider inventory or let the owner pass the pending listing.
#[tokio::test]
async fn test_wider_record_reader_lists_from_the_start_before_delivering_after_load() {
    let s = Setup::new();
    let family = Collection::with_sub_scopes(
        "sample.items",
        Policy::new("sample-a", &["sample-a"]).permanent(None),
    );
    *s.protocol.collections.lock().unwrap() = Some(vec![family.clone()]);
    let mut wallet = join_scoped(&s, "wallet", &["sample-a:kiosk"]).await;
    let mut phone = s.join("phone").await;
    let till = RecordTarget::new(family.sub_scope("till").unwrap(), b"t1");
    phone
        .put_record(&till, &value(&["sale"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&till).unwrap();
    let empty = wallet.list_collection(&family).await.unwrap();
    assert_eq!(empty.records, 0);
    assert!(!empty.more);
    let calls = s.log().len();
    assert!(!wallet.list_collection(&family).await.unwrap().more);
    assert_eq!(
        s.log()[calls..]
            .iter()
            .filter(|call| call.contains("/directory"))
            .count(),
        0
    );
    assert!(wallet.shared_record(&key).await.unwrap().is_none());
    assert!(wallet.listing_owed().await.unwrap());
    let id = wallet.app_id();
    let at = wallet.cursor();
    let owner_at = wallet.told("sample");
    let earlier = wallet.cert().clone();
    s.w.clock.advance_ms(HOUR);
    let missed = s.w.switch.push_missed(1, START, START);
    let renewed = renewed_cert(&s, "wallet", &["sample-a"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.config.page_size = 1;
    let config = wallet.config.clone();
    drop(wallet);
    let mut wallet = App::load(s.env(), s.protocol.clone(), config, id)
        .await
        .unwrap();
    assert!(wallet.list_collection(&family).await.unwrap().more);
    let blocked = wallet.receive(None).await.unwrap();
    assert!(blocked.more);
    assert_eq!(wallet.cursor(), at);
    assert_eq!(wallet.told("sample"), owner_at);
    assert!(
        wallet
            .current_collection(&family, &blocked)
            .await
            .unwrap()
            .is_none()
    );
    assert!(s.protocol.sample.missed.lock().unwrap().is_empty());
    for _ in 0..16 {
        if wallet.cert().hash() == renewed.hash() {
            break;
        }
        assert!(wallet.list_collection(&family).await.unwrap().more);
    }
    let published = s.w.switch.app(&id).record.unwrap();
    let reader = AppRecord::verify(&published, &s.w.alice.public()).unwrap();
    assert_eq!(reader.cert().hash(), renewed.hash());
    assert!(reader.accepts("sample.note"));
    assert_eq!(wallet.cursor(), at);
    assert_eq!(wallet.told("sample"), owner_at);
    assert!(s.protocol.sample.missed.lock().unwrap().is_empty());
    let (_, note) = s
        .peer
        .send_to(
            &s.w.switch,
            s.peer.apps()[0].cert.app_id(),
            "sample.note",
            json!({ "text": "after the miss" }),
            &[id],
        )
        .unwrap();
    let mut current = None;
    for _ in 0..32 {
        let report = wallet.receive(None).await.unwrap();
        current = wallet.current_collection(&family, &report).await.unwrap();
        if current.is_some() && wallet.cursor().seq >= missed && handed(&s, &note.msg_id) == 1 {
            break;
        }
    }
    let current = current.expect("the wider inventory reached the end");
    assert_eq!(
        current.live.iter().map(|r| r.key).collect::<Vec<_>>(),
        [key]
    );
    assert!(current.uncertain_keys.is_empty());
    assert_eq!(wallet.cert().hash(), renewed.hash());
    assert_eq!(
        s.protocol
            .sample
            .missed
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.seq == missed)
            .count(),
        1
    );
    assert_eq!(handed(&s, &note.msg_id), 1);
    wallet.receive(None).await.unwrap();
    assert_eq!(handed(&s, &note.msg_id), 1);
}

/// A restored installation can gain its first readable collection before its
/// initial listing. Neither path may settle that listing under its old grant.
#[tokio::test]
async fn test_restored_receive_waits_for_the_first_readable_collection() {
    restored_first_readable_collection(false).await;
}

#[tokio::test]
async fn test_host_list_all_waits_for_the_first_readable_collection() {
    restored_first_readable_collection(true).await;
}

async fn restored_first_readable_collection(host: bool) {
    let s = Setup::new();
    let mut original = join_scoped(&s, "wallet", &["sample-c"]).await;
    let mut phone = s.join("phone").await;
    let target = s.target("sale");
    let key = phone
        .put_record(&target, &value(&["sale"]), vec![])
        .await
        .unwrap()
        .key;
    assert!(!original.list_collections().await.unwrap());
    assert!(original.shared_record(&key).await.unwrap().is_none());
    let backup = original.backup().await.unwrap();
    let earlier = original.cert().clone();
    let store = Arc::new(MemoryStore::new());
    let config = AppConfig {
        page_size: 1,
        ..World::config()
    };
    let mut restored = Box::pin(App::restore(
        s.env_on(store.clone()),
        s.protocol.clone(),
        config.clone(),
        &backup,
    ))
    .await
    .unwrap();
    let at = restored.cursor();
    let owner_at = restored.told("sample");
    s.w.clock.advance_ms(HOUR);
    let renewed = renewed_cert(&s, "wallet", &["sample-c", "sample-a"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    assert!(restored.listing_owed().await.unwrap());
    if host {
        assert!(restored.list_collections().await.unwrap());
    } else {
        let held = restored.receive(None).await.unwrap();
        assert!(held.more);
        assert!(
            restored
                .current_collection(&items(), &held)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(restored.listing_owed().await.unwrap());
    assert_eq!(restored.cursor(), at);
    assert_eq!(restored.told("sample"), owner_at);
    let id = restored.app_id();
    drop(restored);
    let mut restored = App::load(s.env_on(store), s.protocol.clone(), config, id)
        .await
        .unwrap();
    assert!(restored.listing_owed().await.unwrap());
    store_parts_for(&s, &renewed);
    let mut current = None;
    for _ in 0..32 {
        let report = restored.receive(None).await.unwrap();
        current = restored
            .current_collection(&items(), &report)
            .await
            .unwrap();
        if current.as_ref().is_some_and(|range| !range.live.is_empty()) {
            break;
        }
    }
    let current = current.expect("the newly readable collection reached its end");
    assert_eq!(
        current.live.iter().map(|r| r.key).collect::<Vec<_>>(),
        [key]
    );
    assert!(current.uncertain_keys.is_empty());
    assert_eq!(restored.cert().hash(), renewed.hash());
    assert!(!restored.listing_owed().await.unwrap());
    assert!(!restored.list_collections().await.unwrap());
}

#[tokio::test]
async fn test_permanent_listing_after_a_narrowing_raises_no_alarm() {
    let s = Setup::new();
    let family = Collection::with_sub_scopes(
        "sample.kept",
        Policy::new("sample-a", &["sample-a"]).permanent(None),
    );
    *s.protocol.collections.lock().unwrap() = Some(vec![family.clone()]);
    let mut wallet = join_scoped(&s, "wallet", &["sample-a:kiosk", "sample-a:till"]).await;
    let mut phone = s.join("phone").await;
    let till = RecordTarget::new(family.sub_scope("till").unwrap(), b"t1");
    phone
        .put_record(&till, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = phone.record_key(&till).unwrap();
    wallet.receive(None).await.unwrap();
    s.w.clock.advance_ms(3_000);
    wallet.receive(None).await.unwrap();
    assert!(wallet.shared_record(&key).await.unwrap().is_some());
    // A renewal drops `sample-a:till`: the listing leaves the record out, as any record
    // the wallet can't read.
    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["sample-a:kiosk"]);
    store_parts_for(&s, &renewed);
    renewal_another_device_took(&s, &earlier, &renewed);
    for _ in 0..3 {
        wallet.receive(None).await.unwrap();
        if wallet.cert().hash() == renewed.hash() {
            break;
        }
    }
    assert_eq!(wallet.cert().hash(), renewed.hash());
    let listed = wallet.list_collection(&family).await;
    assert!(listed.is_ok(), "{listed:?}");
    assert!(wallet.alarm().is_none(), "{:?}", wallet.alarm());
}

#[tokio::test]
async fn test_permanent_create_over_a_record_seen_live_raises_the_alarm() {
    let (s, _, mut phone, ordinary, kept) = with_kept_records().await;
    let mut tablet = s.join("tablet").await;
    // A switch that lets each record go takes another app's create at `{0, 0}` in its
    // place: taken for an ordinary record, a rollback for a permanent one seen live.
    for target in [&ordinary, &kept] {
        let key = phone.record_key(target).unwrap();
        s.w.switch.drop_record(&key).unwrap();
        tablet
            .put_record(target, &value(&["a", "b"]), vec![])
            .await
            .unwrap();
        let _ = phone.receive(None).await;
        if target == &ordinary {
            assert!(phone.alarm().is_none(), "{:?}", phone.alarm());
            let held = phone.shared_record(&key).await.unwrap().unwrap();
            assert_eq!(ids(held.content.value()), vec!["a", "b"]);
        } else {
            assert!(
                matches!(phone.alarm(), Some(Alarm::Rollback { .. })),
                "{:?}",
                phone.alarm()
            );
        }
    }
}

fn replacement_at<'a>(
    app: &'a App,
    key: &[u8; 32],
) -> Option<&'a super::super::put_back::RecordHold> {
    app.state
        .put_backs
        .values()
        .find(|hold| hold.observation.key == *key)
}

async fn delete_for_put_back(s: &Setup) -> (App, App, RecordTarget, u64) {
    let mut writer = s.join("wallet").await;
    let mut reader = s.join("phone").await;
    let target = s.target("protected");
    writer
        .put_record(&target, &value(&["trusted"]), vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    s.protocol
        .hold_deletes
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let deleted = writer.delete_record(&target, vec![]).await.unwrap();
    read_on(&mut writer).await;
    (writer, reader, target, deleted.version.version)
}

#[tokio::test]
async fn test_record_put_back_release_from_prior_wait_notice_respects_its_delete() {
    let s = Setup::new();
    let (mut writer, mut reader, target, _) = delete_for_put_back(&s).await;
    let first = reader
        .receive(None)
        .await
        .unwrap()
        .events
        .into_iter()
        .find_map(|e| match e {
            AppEvent::PutBackWaits {
                key,
                item_hash,
                generation,
                version,
                ..
            } => Some((key, item_hash, RecordVersion::new(generation, version))),
            _ => None,
        })
        .unwrap();
    writer
        .put_record(&target, &value(&["trusted", "next"]), vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    writer.delete_record(&target, vec![]).await.unwrap();
    let second = reader
        .receive(None)
        .await
        .unwrap()
        .events
        .into_iter()
        .find_map(|e| match e {
            AppEvent::PutBackWaits {
                key,
                item_hash,
                generation,
                version,
                ..
            } => Some((key, item_hash, RecordVersion::new(generation, version))),
            _ => None,
        })
        .unwrap();
    assert_eq!(first.0, second.0);
    assert_ne!(first.1, second.1);
    assert!(
        reader
            .unacknowledged_events_for("sample")
            .await
            .unwrap()
            .iter()
            .any(|e| matches!(e,AppEvent::PutBackWaits{item_hash,..} if *item_hash==first.1))
    );
    assert!(
        reader
            .release_put_back(&first.0, first.2, &first.1)
            .await
            .is_err()
    );
    assert!(replacement_at(&reader, &second.0).is_some());
    assert!(
        reader
            .release_put_back(&second.0, first.2, &second.1)
            .await
            .is_err()
    );
    assert!(
        reader
            .release_put_back(&second.0, second.2, &second.1)
            .await
            .is_err()
    );
    s.protocol
        .hold_deletes
        .store(false, std::sync::atomic::Ordering::SeqCst);
    s.protocol
        .observe_deletes
        .store(true, std::sync::atomic::Ordering::SeqCst);
    reader
        .release_put_back(&second.0, second.2, &second.1)
        .await
        .unwrap();
    assert!(replacement_at(&reader, &second.0).is_none());
}

#[tokio::test]
async fn test_record_put_back_provider_loss_ends_the_hold() {
    use super::moves::{NEXT, next_key, publish_at};
    let s = Setup::new();
    let (_writer, mut reader, target, _) = delete_for_put_back(&s).await;
    let key = reader.record_key(&target).unwrap();
    read_on(&mut reader).await;
    assert!(replacement_at(&reader, &key).is_some());
    s.w.clock.advance_ms(60_000);
    let signing = next_key();
    let next = crate::testing::ScriptedSwitch::recovering(
        &s.w.alice,
        signing.to_bytes(),
        Arc::clone(&s.w.clock),
        2,
        1,
    )
    .unwrap();
    s.router.add_switch(NEXT, &next);
    publish_at(
        &s.w,
        &next,
        pubky_switch_core::records::Inbox::new(NEXT, signing.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    s.w.switch.lock().not_hosted_unpinned = true;
    reader.refresh_identity().await.unwrap();
    reader.receive(None).await.unwrap();
    assert!(reader.state.put_backs.is_empty());
    assert!(
        reader
            .reader()
            .scan_raw(super::super::put_back::PREFIX)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_record_put_back_renewal_without_write_scope_releases() {
    let s = Setup::new();
    let (_writer, mut reader, target, _) = delete_for_put_back(&s).await;
    read_on(&mut reader).await;
    let key = reader.record_key(&target).unwrap();
    let earlier = reader.cert().clone();
    s.w.clock.advance_ms(DAY_MS);
    let renewed = renewal_of(&s, "phone", &["sample-c"]);
    let opened =
        s.w.signer
            .sign_next(|body| list_renewal(body, &earlier, &renewed, None))
            .unwrap();
    s.w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: reader.app_id(),
            cert: renewed.signed().clone(),
        })
        .unwrap();
    s.w.switch.deliver_identity(&opened).unwrap();
    let report = reader.receive(None).await.unwrap();
    assert_eq!(reader.cert().hash(), renewed.hash());
    assert!(report.events.iter().any(|e| matches!(e, AppEvent::PutBackRefused{key:k,reason,..} if *k==key && reason=="permission_missing")));
    assert!(replacement_at(&reader, &key).is_none());
}

#[tokio::test]
async fn test_record_put_back_older_backup_keeps_in_place_work_but_respects_release() {
    let s = Setup::new();
    let (_writer, mut reader, target, _) = delete_for_put_back(&s).await;
    let key = reader.record_key(&target).unwrap();
    let before = reader.backup().await.unwrap();
    read_on(&mut reader).await;
    let held = reader.backup().await.unwrap();
    let mut restored = Box::pin(App::restore(
        s.env(),
        s.protocol.clone(),
        World::config(),
        &before,
    ))
    .await
    .unwrap();
    assert!(replacement_at(&restored, &key).is_some());
    let delete = replacement_at(&restored, &key).unwrap().observation.delete;
    restored.refresh_identity().await.unwrap();
    read_on(&mut restored).await;
    assert!(
        restored
            .release_put_back(&key, delete.version, &delete.item_hash)
            .await
            .is_err()
    );
    s.protocol
        .hold_deletes
        .store(false, std::sync::atomic::Ordering::SeqCst);
    s.protocol
        .observe_deletes
        .store(true, std::sync::atomic::Ordering::SeqCst);
    restored
        .release_put_back(&key, delete.version, &delete.item_hash)
        .await
        .unwrap();
    restored.refresh_identity().await.unwrap();
    read_on(&mut restored).await;
    let restored = Box::pin(App::restore(
        s.env(),
        s.protocol.clone(),
        World::config(),
        &held,
    ))
    .await
    .unwrap();
    assert!(replacement_at(&restored, &key).is_none());
}

#[tokio::test]
async fn test_record_put_back_leave_releases_the_protocol_with_its_notice() {
    let s = Setup::new();
    let (_writer, mut reader, target, _) = delete_for_put_back(&s).await;
    let key = reader.record_key(&target).unwrap();
    read_on(&mut reader).await;
    reader.leave(crate::app::LeaveMode::TwoStep).await.unwrap();
    assert!(replacement_at(&reader, &key).is_none());
    assert!(reader.take_events().iter().any(
        |e| matches!(e,AppEvent::PutBackRefused{key:k, reason,..} if *k==key && reason=="left")
    ));
}

#[tokio::test]
async fn test_record_publication_checks_a_second_delete_while_the_first_waits() {
    let s = Setup::new();
    let (mut writer, mut reader, target, first) = delete_for_put_back(&s).await;
    let key = reader.record_key(&target).unwrap();
    read_on(&mut reader).await;
    *s.protocol.pending_publication.lock().unwrap() = Some(
        replacement_at(&reader, &key)
            .unwrap()
            .observation
            .delete
            .version,
    );
    let updated = value(&["trusted", "next"]);
    writer.put_record(&target, &updated, vec![]).await.unwrap();
    read_on(&mut reader).await;
    let second = writer.delete_record(&target, vec![]).await.unwrap().version;
    read_on(&mut reader).await;
    assert_eq!(reader.state.put_backs.len(), 2);
    writer.put_record(&target, &updated, vec![]).await.unwrap();
    read_on(&mut reader).await;
    read_on(&mut reader).await;
    assert_eq!(reader.state.put_backs.len(), 1);
    assert_eq!(
        replacement_at(&reader, &key).unwrap().observation.seq,
        first
    );
    reader.flush_cursor().await.unwrap();
    assert!(s.w.switch.app(&reader.app_id()).cursor < first);
    *s.protocol.pending_publication.lock().unwrap() = None;
    read_on(&mut reader).await;
    reader.flush_cursor().await.unwrap();
    assert!(s.w.switch.app(&reader.app_id()).cursor >= second.version);
}

#[tokio::test]
async fn test_record_publication_keeps_the_cursor_until_a_read_covers_an_upload() {
    for retry_first in [false, true] {
        Box::pin(async {
            let s = Setup::new();
            let (mut writer, mut reader, target, deleted) = delete_for_put_back(&s).await;
            let key = reader.record_key(&target).unwrap();
            let id = reader.app_id();
            read_on(&mut reader).await;
            *s.protocol.pending_publication.lock().unwrap() = Some(
                replacement_at(&reader, &key)
                    .unwrap()
                    .observation
                    .delete
                    .version,
            );
            let following = writer
                .put_record(&target, &value(&["trusted", "next"]), vec![])
                .await
                .unwrap();
            read_on(&mut reader).await;
            s.w.switch
                .make_divergent(writer.app_id(), key, [2; 32])
                .unwrap();
            let uploaded = s.w.switch.seq();
            assert!(following.version.version < uploaded);
            // Neither the publication retry nor the scheduled key read can reach the service yet.
            for _ in 0..8 {
                s.w.switch.fail_next(Fault::Unreachable {
                    path: "/records/".into(),
                    after: 0,
                });
            }
            read_on(&mut reader).await;
            assert_eq!(
                reader.record_upload(&key).await.unwrap().unwrap().seq,
                uploaded
            );
            assert!(s.w.switch.app(&id).cursor < deleted);
            drop(reader);
            let mut reader = App::load(s.env(), s.protocol.clone(), World::config(), id)
                .await
                .unwrap();
            // Enter through the public app to load its saved protocol positions before a retry.
            reader.flush_cursor().await.unwrap();
            assert!(s.w.switch.app(&id).cursor < deleted);
            *s.protocol.pending_publication.lock().unwrap() = None;
            s.w.switch.lock().faults.clear();
            let divergent = s.w.switch.lock().shared.divergent.remove(&key).unwrap();
            let earlier = || {
                s.w.switch.fail_next(Fault::Head {
                    path: "/records/".into(),
                    at: Some(following.version.version),
                    forked: false,
                })
            };
            // Both paths read the same signed application as it stood just before the upload.
            earlier();
            let hold = replacement_at(&reader, &key).unwrap().clone();
            let reads = s.w.switch.lock().shared.record_reads.len();
            reader.try_put_back(hold).await.unwrap();
            assert_eq!(&s.w.switch.lock().shared.record_reads[reads..], &[key]);
            assert!(replacement_at(&reader, &key).is_some());
            earlier();
            assert!(matches!(
                reader.read_record_fresh(&target).await.unwrap(),
                RecordRead::Kept { record: Some(held), reason: KeptReason::Refused }
                    if held.version == following.version && held.content == following.content
            ));
            assert!(replacement_at(&reader, &key).is_some());
            let now = std::mem::replace(&mut s.w.switch.lock().seq, following.version.version);
            s.w.switch.fail_next(Fault::Head {
                path: "records?collection".into(),
                at: Some(following.version.version),
                forked: false,
            });
            assert_eq!(
                reader
                    .list_collection(&target.collection)
                    .await
                    .unwrap()
                    .records,
                1
            );
            s.w.switch.lock().seq = now;
            assert!(replacement_at(&reader, &key).is_some());
            assert!(s.w.switch.lock().faults.is_empty());
            assert_eq!(
                reader.record_upload(&key).await.unwrap().unwrap().seq,
                uploaded
            );
            reader.flush_cursor().await.unwrap();
            assert!(s.w.switch.app(&id).cursor < deleted);

            s.w.switch.lock().shared.divergent.insert(key, divergent);
            if retry_first {
                let hold = replacement_at(&reader, &key).unwrap().clone();
                reader.try_put_back(hold).await.unwrap();
                assert!(replacement_at(&reader, &key).is_none());
            }
            let current = reader.read_record_fresh(&target).await.unwrap();
            let RecordRead::Fresh(record) = current else {
                panic!("covering read after retry {retry_first}: {current:?}");
            };
            assert_eq!(record.version, following.version);
            assert!(record.divergent, "covering read after retry {retry_first}");
            assert!(replacement_at(&reader, &key).is_none());
            read_on(&mut reader).await;
            assert!(reader.record_upload(&key).await.unwrap().is_none());
            assert!(s.w.switch.app(&id).cursor >= uploaded);
        })
        .await;
    }
}

#[tokio::test]
async fn test_record_publication_protection_covers_the_interval_before_a_later_read() {
    Box::pin(async {
        let s = Setup::new();
        let (mut writer, mut reader, target, deleted) = delete_for_put_back(&s).await;
        let key = reader.record_key(&target).unwrap();
        read_on(&mut reader).await;
        let generation = replacement_at(&reader, &key)
            .unwrap()
            .observation
            .generation;
        writer
            .put_record(&s.target("other"), &value(&["new"]), vec![])
            .await
            .unwrap();
        reader.read_record(&target).await.unwrap();
        let latest = reader
            .record_view(&key, &target.collection)
            .await
            .unwrap()
            .unwrap()
            .at;
        assert!(matches!(latest, crate::app::records::CurrentAt::Answer(v) if v.version > deleted));

        let at = |seq| crate::app::records::CurrentAt::Answer(RecordVersion::new(generation, seq));
        let answer = crate::app::records::MissingFrom::Key;
        let mut tx = reader.tx().unwrap();
        assert!(
            !reader
                .note_absent(&key, at(deleted - 1), answer, &mut tx)
                .await
                .unwrap()
        );
        assert!(replacement_at(&reader, &key).is_some());
        let outcome = reader.note_absent(&key, at(deleted), answer, &mut tx).await;
        assert!(matches!(
            outcome,
            Err(AppError::Alarm(Alarm::Rollback { .. }))
        ));
    })
    .await;
}

#[tokio::test]
async fn test_record_publication_waits_for_the_owner_before_changing_divergence() {
    Box::pin(async {
        let s = Setup::new();
        let (mut writer, mut reader, target, _, _) = unread_deletion(&s, &value(&["first"])).await;
        let key = reader.record_key(&target).unwrap();
        s.protocol
            .observation_unavailable
            .store(true, std::sync::atomic::Ordering::SeqCst);
        read_on(&mut reader).await;
        let mut tx = reader.tx().unwrap();
        reader
            .note_view_divergence(&key, true, &mut tx)
            .await
            .unwrap();
        reader.commit(tx).await.unwrap();
        writer
            .put_record(&target, &value(&["first", "next"]), vec![])
            .await
            .unwrap();

        let id = reader.app_id();
        drop(reader);
        let mut reader = App::load(s.env(), s.protocol.clone(), World::config(), id)
            .await
            .unwrap();
        let waiting = reader.read_record_fresh(&target).await.unwrap();
        assert!(matches!(
            waiting,
            RecordRead::Kept {
                reason: KeptReason::Refused,
                ..
            }
        ));
        assert!(reader.is_divergent(&key).await.unwrap());
        s.protocol
            .observation_unavailable
            .store(false, std::sync::atomic::Ordering::SeqCst);
        read_on(&mut reader).await;
        assert!(matches!(
            reader.read_record_fresh(&target).await.unwrap(),
            RecordRead::Fresh(_)
        ));
        assert!(!reader.is_divergent(&key).await.unwrap());
    })
    .await;
}

/// Collection pages list only live records. A held deletion stays available by key
/// through a completed listing and a restart, until a later publication covers it.
#[tokio::test]
async fn test_record_publication_listing_preserves_the_deletion_returned_by_key() {
    let s = Setup::new();
    let (mut writer, mut reader, target, deleted) = delete_for_put_back(&s).await;
    let key = reader.record_key(&target).unwrap();
    let id = reader.app_id();
    read_on(&mut reader).await;
    let page = reader.list_collection(&target.collection).await.unwrap();
    assert_eq!(page.records, 0);
    assert!(!page.more);
    drop(reader);

    let mut reader = App::load(s.env(), s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    let read = reader.read_record_fresh(&target).await.unwrap();
    assert!(
        matches!(&read, RecordRead::Fresh(record) if record.content == RecordContent::Deleted
        && record.version.version == deleted),
        "{read:?}"
    );
    assert_eq!(
        replacement_at(&reader, &key).unwrap().observation.seq,
        deleted
    );
    reader.flush_cursor().await.unwrap();
    assert!(s.w.switch.app(&id).cursor < deleted);
    writer
        .put_record(&target, &value(&["trusted", "next"]), vec![])
        .await
        .unwrap();
    read_on(&mut reader).await;
    assert!(replacement_at(&reader, &key).is_none());
    assert!(s.w.switch.app(&id).cursor >= deleted);
}

/// A new service cursor changes a kept request even when every signed operation is
/// unchanged. After reload only the request that already reached the service may go late.
#[tokio::test]
async fn test_record_publication_kept_batch_rechecks_its_cursor_after_reload() {
    use crate::app::KeptBatchStatus;
    use std::sync::atomic::Ordering::SeqCst;

    for covered in [false, true] {
        let s = Setup::new();
        let mut writer = s.join("wallet").await;
        let mut app = s.join("phone").await;
        let app_id = app.app_id();
        let target = s.target("protected");
        read_on(&mut app).await;
        writer
            .put_record(&target, &value(&["trusted"]), vec![])
            .await
            .unwrap();
        app.receive(None).await.unwrap();
        let cursor = app.cursor().seq;
        assert!(app.service_cursor().seq < cursor);
        let before = s.w.clock.now_ms() + 600_000;
        let unavailable = || {
            s.w.switch.fail_next(Fault::Error {
                path: "ops".into(),
                code: ErrorCode::Unavailable,
                current: json!(null),
            })
        };
        unavailable();
        let id = app
            .submit_batch(super::moves::contact_batch(s.w.bob.public()).first_send_before(before))
            .await
            .unwrap_err()
            .kept_batch()
            .unwrap();

        s.protocol.hold_deletes.store(true, SeqCst);
        let deleted = writer
            .delete_record(&target, vec![])
            .await
            .unwrap()
            .version
            .version;
        unavailable();
        app.receive(None).await.unwrap();
        let key = app.record_key(&target).unwrap();
        assert_eq!(replacement_at(&app, &key).unwrap().observation.seq, deleted);
        assert!(cursor < deleted);
        if covered {
            writer
                .put_record(&target, &value(&["trusted", "next"]), vec![])
                .await
                .unwrap();
            unavailable();
            app.receive(None).await.unwrap();
            assert!(replacement_at(&app, &key).is_none());
            app.flush_cursor().await.unwrap();
            assert!(app.service_cursor().seq > cursor);
        }
        drop(app);
        let mut app = App::load(s.env(), s.protocol.clone(), World::config(), app_id)
            .await
            .unwrap();
        s.w.clock.set_ms(before);
        let start = s.router.log().len();
        if covered {
            assert!(app.resume_batches().await.is_err());
            assert!(matches!(
                app.kept_batch(id).await.unwrap(),
                Some(KeptBatchStatus::Kept { .. })
            ));
        } else {
            app.resume_batches().await.unwrap();
            assert!(matches!(
                app.kept_batch(id).await.unwrap(),
                Some(KeptBatchStatus::Applied { .. })
            ));
        }
        let posts = s.router.log()[start..]
            .iter()
            .filter(|request| request.starts_with("POST ") && request.ends_with("/ops"))
            .count();
        assert_eq!(posts, usize::from(!covered));
    }
}

#[tokio::test]
async fn test_record_publication_shared_store_handoff_keeps_the_real_service_cursor() {
    let s = Setup::new();
    let (mut writer, reader, target, _) = delete_for_put_back(&s).await;
    let id = reader.app_id();
    drop(reader);
    let host = StoreHandle::inline(Arc::clone(&s.w.store) as Arc<dyn StateStore>);
    let owner = host.acquire("host/phone/session").await.unwrap();
    let mut reader = App::load(s.env(), s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    read_on(&mut reader).await;
    let key = reader.record_key(&target).unwrap();
    let delete = replacement_at(&reader, &key).unwrap().observation.delete;
    assert!(matches!(
        host.acquire("host/phone/session").await,
        Err(crate::error::StoreError::InUse)
    ));
    reader.flush_cursor().await.unwrap();
    drop(reader);
    drop(owner);
    let _new_owner = host.acquire("host/phone/session").await.unwrap();
    let mut next = App::load(s.env(), s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    assert_eq!(
        replacement_at(&next, &key).unwrap().observation.delete,
        delete
    );
    read_on(&mut next).await;
    next.flush_cursor().await.unwrap();
    assert!(s.w.switch.app(&id).cursor < delete.version.version);
    assert!(held_at_switch(&s, &key));
    writer
        .put_record(&target, &value(&["trusted", "next"]), vec![])
        .await
        .unwrap();
    read_on(&mut next).await;
    next.flush_cursor().await.unwrap();
    assert!(s.w.switch.app(&id).cursor >= delete.version.version);
}

#[tokio::test]
async fn test_record_publication_waits_for_the_qualified_successor_after_a_lifetime_ends() {
    use std::sync::atomic::Ordering::SeqCst;
    Box::pin(async {
        let s = Setup::new();
        s.protocol.qualify_items.store(true, SeqCst);
        s.protocol.observe_values.store(true, SeqCst);
        s.protocol.end_mark_at_delete.store(true, SeqCst);
        s.protocol.hold_deletes.store(true, SeqCst);
        let request = s.approve(&app_keys("wallet"), &ALL_PERMISSIONS);
        let mut writer = App::join(
            s.env(),
            Arc::new(ItemsProtocol::default()),
            World::config(),
            request,
        )
        .await
        .unwrap();
        let mut reader = s.join("phone").await;
        let target = s.target("n1");
        let key = reader.record_key(&target).unwrap();
        let first = value(&["n1", "first"]);
        writer.put_record(&target, &first, vec![]).await.unwrap();
        read_on(&mut reader).await;
        let deletion = writer.delete_record(&target, vec![]).await.unwrap().version;
        read_on(&mut reader).await;
        assert_eq!(reader.record_seen(&key).await.unwrap(), None);
        assert_eq!(
            reader.protocol_get("sample", &key).await.unwrap(),
            Some(lifetime_version(deletion))
        );
        assert!(replacement_at(&reader, &key).is_some());

        // Both earlier items are present, but this value names a different record.
        writer
            .put_record(&target, &value(&["n2", "n1", "first"]), vec![])
            .await
            .unwrap();
        reader.read_record_fresh(&target).await.unwrap();
        assert!(replacement_at(&reader, &key).is_some());
        assert_eq!(
            reader
                .protocol_get("sample", b"accepted-items")
                .await
                .unwrap(),
            Some(first)
        );
        reader.flush_cursor().await.unwrap();
        assert!(s.w.switch.app(&reader.app_id()).cursor < deletion.version);

        let complete = value(&["n1", "first", "n2"]);
        writer.put_record(&target, &complete, vec![]).await.unwrap();
        read_on(&mut reader).await;
        reader.flush_cursor().await.unwrap();
        assert!(replacement_at(&reader, &key).is_none());
        assert_eq!(
            reader.record_seen(&key).await.unwrap(),
            Some(complete.clone())
        );
        assert_eq!(
            reader
                .protocol_get("sample", b"accepted-items")
                .await
                .unwrap(),
            Some(complete)
        );
        assert!(s.w.switch.app(&reader.app_id()).cursor >= deletion.version);
    })
    .await;
}

#[tokio::test]
async fn test_record_publication_retries_the_signed_merge_after_reopening() {
    Box::pin(async {
        let s = Setup::new();
        let (mut writer, mut reader, target, deleted) = delete_for_put_back(&s).await;
        let key = reader.record_key(&target).unwrap();
        read_on(&mut reader).await;
        let later = writer
            .put_record(&target, br#"{"items":["next"],"note":"keep"}"#, vec![])
            .await
            .unwrap();
        let base = Condition::RecordCurrent {
            key,
            revision: pubky_switch_core::shared::ApplicationRef {
                generation: later.version.generation,
                seq: later.version.version,
                item_hash: s.w.switch.applied().last().unwrap().item_hash().unwrap(),
            },
            deleted: false,
        };
        s.protocol
            .publish_records
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let count = s.w.switch.applied().len();
        s.w.switch.fail_next(Fault::Unanswered {
            path: "ops".into(),
            after: 0,
        });
        read_on(&mut reader).await;
        assert_eq!(s.w.switch.applied().len(), count);
        assert!(s.w.switch.app(&reader.app_id()).cursor < deleted);
        let hold = replacement_at(&reader, &key).unwrap();
        let pending = hold.pending.as_ref().unwrap();
        assert!(pending.kept_ms.is_some());
        let batch = crate::client::Batch::from_body(pending.body.clone()).unwrap();
        assert_eq!(batch.ops()[0].body().conditions, vec![base]);
        let item = batch.ops()[0].item_hash().unwrap();
        let id = reader.app_id();
        drop(reader);
        let mut reader = App::load(s.env(), s.protocol.clone(), World::config(), id)
            .await
            .unwrap();
        read_on(&mut reader).await;
        reader.flush_cursor().await.unwrap();
        let current = writer.read_record_fresh(&target).await.unwrap();
        let RecordRead::Fresh(current) = current else {
            panic!("expected current record")
        };
        assert!(current.version > later.version);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(current.content.value().unwrap()).unwrap(),
            json!({"items":["next","trusted"],"note":"keep"})
        );
        assert_eq!(s.w.switch.applied().len(), count + 1);
        assert_eq!(
            s.w.switch.applied().last().unwrap().item_hash().unwrap(),
            item
        );
        assert!(s.w.switch.app(&id).cursor >= deleted);
    })
    .await;
}

#[tokio::test]
async fn test_record_publication_lost_reply_keeps_one_signed_replacement() {
    Box::pin(async {
        let s = Setup::new();
        let (mut writer, mut reader, target, deleted) = delete_for_put_back(&s).await;
        let key = reader.record_key(&target).unwrap();
        let base = Condition::RecordCurrent {
            key,
            revision: pubky_switch_core::shared::ApplicationRef {
                generation: reader.cursor().generation,
                seq: deleted,
                item_hash: s.w.switch.applied().last().unwrap().item_hash().unwrap(),
            },
            deleted: true,
        };
        let count = s.w.switch.applied().len();
        s.protocol
            .publish_records
            .store(true, std::sync::atomic::Ordering::SeqCst);
        s.w.switch
            .fail_next(Fault::LoseAnswer { path: "ops".into() });
        read_on(&mut reader).await;
        let pending = replacement_at(&reader, &key)
            .unwrap()
            .pending
            .as_ref()
            .unwrap();
        let batch = crate::client::Batch::from_body(pending.body.clone()).unwrap();
        assert_eq!(batch.ops()[0].body().conditions, vec![base]);
        assert_eq!(
            s.w.switch.applied().last().unwrap().item_hash().unwrap(),
            batch.ops()[0].item_hash().unwrap()
        );
        assert_eq!(s.w.switch.app(&reader.app_id()).cursor, deleted);
        let id = reader.app_id();
        drop(reader);
        let mut reader = App::load(s.env(), s.protocol.clone(), World::config(), id)
            .await
            .unwrap();
        read_on(&mut reader).await;
        reader.flush_cursor().await.unwrap();
        assert!(replacement_at(&reader, &key).is_none());
        assert_eq!(s.w.switch.applied().len(), count + 1);
        assert_eq!(
            writer
                .read_record(&target)
                .await
                .unwrap()
                .unwrap()
                .content
                .value(),
            Some(value(&["trusted"]).as_slice())
        );
    })
    .await;
}

#[tokio::test]
async fn test_record_publication_restores_an_original_result_after_a_complete_successor() {
    use crate::app::{KeptBatchDrop, KeptBatchStatus};
    for applied in [false, true] {
        Box::pin(async {
            let s = Setup::new();
            let (mut writer, mut reader, target, deleted) = delete_for_put_back(&s).await;
            let key = reader.record_key(&target).unwrap();
            s.protocol
                .publish_records
                .store(true, std::sync::atomic::Ordering::SeqCst);
            s.w.switch.fail_next(if applied {
                Fault::LoseAnswer { path: "ops".into() }
            } else {
                Fault::Unanswered {
                    path: "ops".into(),
                    after: 0,
                }
            });
            read_on(&mut reader).await;
            let sent = replacement_at(&reader, &key)
                .unwrap()
                .pending
                .clone()
                .unwrap();
            let id = crate::client::Batch::from_body(sent.body.clone())
                .unwrap()
                .id()
                .unwrap();
            assert_eq!(s.w.switch.app(&reader.app_id()).cursor >= deleted, applied);
            let now = writer.read_record(&target).await.unwrap().unwrap();
            assert_eq!(now.content.value().is_some(), applied);
            writer
                .put_record(&target, &value(&["trusted", "other"]), vec![])
                .await
                .unwrap();
            let count = s.w.switch.applied().len();
            let current = reader.read_record_fresh(&target).await.unwrap();
            assert!(matches!(current, RecordRead::Fresh(_)));
            assert!(replacement_at(&reader, &key).is_none());
            let backup = reader.backup_layered().await.unwrap();
            drop(reader);
            let mut reader = App::restore(
                s.env_on(Arc::new(MemoryStore::new())),
                s.protocol.clone(),
                World::config(),
                &backup,
            )
            .await
            .unwrap();
            let batches = reader.kept_batches().await.unwrap();
            assert_eq!(batches.len(), 1);
            assert_eq!(batches[0].0, id);
            assert_eq!(batches[0].1.body, sent.body);
            assert_eq!(batches[0].1.kept_ms, sent.kept_ms);
            read_on(&mut reader).await;
            match reader.kept_batch(id).await.unwrap().unwrap() {
                KeptBatchStatus::Applied { .. } => assert!(applied),
                KeptBatchStatus::Dropped {
                    reason: KeptBatchDrop::Refused { .. },
                    ..
                } => assert!(!applied),
                other => panic!("unexpected original outcome {other:?}"),
            }
            assert_eq!(s.w.switch.applied().len(), count);
        })
        .await;
    }
}

#[tokio::test]
async fn test_record_publication_commits_the_acknowledged_cursor_with_the_signed_replacement() {
    Box::pin(async {
        let s = Setup::new();
        let (_writer, mut reader, target, deleted) = delete_for_put_back(&s).await;
        let key = reader.record_key(&target).unwrap();
        read_on(&mut reader).await;
        assert!(reader.service_cursor().seq < deleted);
        s.protocol
            .publish_records
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let id = reader.app_id();
        let hold = replacement_at(&reader, &key).unwrap().clone();
        reader.try_put_back(hold).await.unwrap();
        assert!(replacement_at(&reader, &key).is_none());
        let written = s.w.switch.applied().len();
        assert_eq!(s.w.switch.app(&id).cursor, deleted);
        // Reopen at the submission commit before a later feed page could advance it.
        drop(reader);
        let mut reopened = App::load(s.env(), s.protocol.clone(), World::config(), id)
            .await
            .unwrap();
        assert!(replacement_at(&reopened, &key).is_none());
        assert_eq!(reopened.service_cursor().seq, deleted);
        assert_eq!(reopened.cursor().seq, deleted);
        read_on(&mut reopened).await;
        assert_eq!(s.w.switch.applied().len(), written);
    })
    .await;
}

#[tokio::test]
async fn test_record_publication_restoring_an_earlier_merge_keeps_only_its_original_result() {
    Box::pin(async {
        let s = Setup::new();
        let (mut writer, mut reader, first, _) = delete_for_put_back(&s).await;
        read_on(&mut reader).await;
        let first_key = reader.record_key(&first).unwrap();
        *s.protocol.pending_publication.lock().unwrap() = Some(
            replacement_at(&reader, &first_key)
                .unwrap()
                .observation
                .delete
                .version,
        );
        writer
            .put_record(&first, &value(&["trusted"]), vec![])
            .await
            .unwrap();
        read_on(&mut reader).await;
        let target = s.target("other watched record");
        let key = reader.record_key(&target).unwrap();
        writer
            .put_record(&target, &value(&["trusted"]), vec![])
            .await
            .unwrap();
        read_on(&mut reader).await;
        reader.read_record(&target).await.unwrap().unwrap();
        let deleted = writer
            .delete_record(&target, vec![])
            .await
            .unwrap()
            .version
            .version;
        read_on(&mut reader).await;
        assert_eq!(reader.state.put_backs.len(), 2);
        let successor = writer
            .put_record(&target, &value(&["next"]), vec![])
            .await
            .unwrap();
        s.protocol
            .publish_records
            .store(true, std::sync::atomic::Ordering::SeqCst);
        s.w.switch.fail_next(Fault::Unanswered {
            path: "ops".into(),
            after: 0,
        });
        reader.receive(None).await.unwrap();
        let duty = replacement_at(&reader, &key).unwrap();
        let original_delete = duty.observation.delete;
        let original = duty.pending.clone().unwrap();
        let batch = crate::client::Batch::from_body(original.body.clone()).unwrap();
        let expected_seq = successor.version.version;
        assert!(matches!(
            batch.ops()[0].body().conditions.as_slice(),
            [Condition::RecordCurrent { deleted: false, revision, .. }]
                if revision.seq == expected_seq
        ));
        let backup = reader.backup_layered().await.unwrap();
        writer
            .put_record(&target, &value(&["next", "trusted"]), vec![])
            .await
            .unwrap();
        reader.read_record_fresh(&target).await.unwrap();
        assert!(replacement_at(&reader, &key).is_none());
        assert!(reader.service_cursor().seq < deleted);
        assert_eq!(
            reader.kept_batches().await.unwrap()[0].1.body,
            original.body
        );
        drop(reader);
        let mut restored = Box::pin(App::restore(
            s.env(),
            s.protocol.clone(),
            World::config(),
            &backup,
        ))
        .await
        .unwrap();
        let queued = restored.kept_batches().await.unwrap();
        assert!(replacement_at(&restored, &key).is_none());
        assert!(replacement_at(&restored, &first_key).is_some());
        assert_eq!(queued.len(), 1);
        assert_eq!(Some(queued[0].0), batch.id());
        assert_eq!(queued[0].1.body, original.body);
        assert_eq!(queued[0].1.kept_ms, original.kept_ms);
        assert_eq!(queued[0].1.record_deletion, Some(original_delete));
        read_on(&mut restored).await;
        assert!(matches!(
            restored.kept_batch(queued[0].0).await.unwrap(),
            Some(crate::app::KeptBatchStatus::Dropped {
                reason: crate::app::KeptBatchDrop::Refused { .. },
                ..
            })
        ));
    })
    .await;
}

#[tokio::test]
async fn test_record_publication_qualifies_the_value_before_its_conditional_send() {
    use std::sync::atomic::Ordering::SeqCst;
    Box::pin(async {
        let s = Setup::new();
        s.protocol.qualify_items.store(true, SeqCst);
        s.protocol.publish_records.store(true, SeqCst);
        let mut writer = s.join("wallet").await;
        let mut reader = s.join("phone").await;
        let target = s.target("n1");
        let key = reader.record_key(&target).unwrap();
        let original = value(&["n1", "first"]);
        writer.put_record(&target, &original, vec![]).await.unwrap();
        read_on(&mut reader).await;
        *s.protocol.replacement_value.lock().unwrap() = Some(value(&["n2", "first"]));
        let deleted = writer.delete_record(&target, vec![]).await.unwrap();
        let before = s.w.switch.applied().len();
        read_on(&mut reader).await;
        let duty = replacement_at(&reader, &key).unwrap();
        assert!(duty.pending.is_none());
        assert!(reader.service_cursor().seq < deleted.version.version);
        assert_eq!(s.w.switch.applied().len(), before);

        *s.protocol.replacement_value.lock().unwrap() = None;
        read_on(&mut reader).await;
        assert!(replacement_at(&reader, &key).is_none());
        let RecordRead::Fresh(restored) = reader.read_record_fresh(&target).await.unwrap() else {
            panic!("expected the applied restoration");
        };
        assert_eq!(restored.writer, reader.app_id());
        assert_eq!(restored.content.value(), Some(original.as_slice()));
        assert_eq!(reader.record_seen(&key).await.unwrap(), Some(original));
        assert_eq!(s.w.switch.applied().len(), before + 1);
    })
    .await;
}
