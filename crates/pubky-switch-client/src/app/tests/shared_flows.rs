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
    CLOCK_TOLERANCE_MS, DAY_MS, RemovedApp, RenewedCert, seal_bundle_parts,
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
}

pub(crate) fn items() -> Collection {
    Collection::new("sample.items", Policy::new("scope-a", &["scope-a"]))
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

    fn receive(&self, message: &ReceivedMessage) -> Outcome {
        self.sample.receive(message)
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

    fn record_regression_on(
        &self,
        collection: &str,
        seen: &[u8],
        value: Option<&[u8]>,
        base: WriteBase,
    ) -> Option<String> {
        self.bases.lock().unwrap().push(base);
        self.record_regression(collection, seen, value)
    }

    fn record_regression(&self, _: &str, seen: &[u8], value: Option<&[u8]>) -> Option<String> {
        let value = value?;
        let held = ids(Some(value));
        let pad = "é".repeat(*self.pad.lock().unwrap());
        ids(Some(seen))
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
            &AppSpec::new(&["scope-a"]),
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
        let app = AppSpec::new(&["scope-a"]).with_permissions(permissions);
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
        .add_app("till", &AppSpec::new(&["scope-a"]), &["sample.note"], true)
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
        .add_app("till", &AppSpec::new(&["scope-a"]), &["sample.note"], true)
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
    assert!(matches!(delivery, Delivery::Failed { .. }), "{delivery:?}");
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.failed, vec![msg_id.clone()]);
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
/// version: it does for a write read in the feed after the one it holds, and doesn't for
/// the current view of a record written twice since.
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
        vec![WriteBase {
            expected_version: first,
            held: true
        }]
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
            expected_version: third,
            held: false
        })
    );
}

/// A create over a record the app holds deleted builds on what it holds.
#[tokio::test]
async fn test_records_regression_base_of_a_create_over_a_held_delete_is_held() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    wallet.delete_record(&target, vec![]).await.unwrap();
    phone.receive(None).await.unwrap();
    wallet
        .put_record(&target, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    phone.receive(None).await.unwrap();
    let last = *s.protocol.bases.lock().unwrap().last().unwrap();
    assert_eq!(
        last,
        WriteBase {
            expected_version: RecordVersion::NONE,
            held: true
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
    let last = *s.protocol.bases.lock().unwrap().last().unwrap();
    assert_eq!(
        last,
        WriteBase {
            expected_version: flagged,
            held: false
        }
    );
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
        Collection::new("sample.other", Policy::new("scope-a", &["scope-a"])),
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-a", "scope-c"]).await;
    let phone = s.join("phone").await;
    let target = s.target("n1");
    wallet
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    let key = wallet.record_key(&target).unwrap();
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["scope-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    wallet.receive(None).await.unwrap();
    assert_eq!(
        s.w.switch.app(&wallet.app_id()).cert.map(|c| c.hash()),
        Some(renewed.hash())
    );
    let view = phone.client.record(&key).await.unwrap();
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-a", "scope-c"]).await;
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
    let renewed = renewed_cert(&s, "wallet", &["scope-c"]);
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
    assert_eq!(tablet.list_collection(&items()).await.unwrap(), 1);
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
/// (Switch wire 3.8), so no write under the earlier one is dated past `until`. Every reader
/// flags it (Switch wire 6.2 "Accepting a write" step 4), from the feed and from the record
/// view alike: the phone, and a tablet that joins afterwards.
#[tokio::test]
async fn test_records_write_after_a_reduction_closed_is_flagged_by_every_reader() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["scope-a", "scope-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();

    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewal_of(&s, "wallet", &["scope-c"]);
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

    // The phone, from its feed (no record view), then from the record view.
    assert!(matches!(
        phone.refresh_identity().await.unwrap(),
        IdentityRefresh::Newer { .. }
    ));
    let report = phone.receive(None).await.unwrap();
    let from_feed = flagged_rules(&report.events);
    assert!(
        from_feed.iter().any(|rule| rule.contains("step 4")),
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-a", "scope-c"]).await;
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
    let renewed = renewed_cert(&s, "wallet", &["scope-c"]);
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-a"]).await;
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
    let renewed = renewed_cert(&s, "wallet", &["scope-a", "scope-c"]);
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-a"]).await;
    let earlier = wallet.cert().clone();
    s.w.clock.set_ms(earlier.expires_at() - HOUR);
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    phone.refresh_own_apps().await.unwrap();

    s.w.clock.set_ms(earlier.expires_at() + 1);
    let renewed = renewed_cert(&s, "wallet", &["scope-a"]);
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-a"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    phone.refresh_own_apps().await.unwrap();

    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["scope-a", "scope-c"]);
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    phone.refresh_own_apps().await.unwrap();

    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["scope-a", "scope-c"]);
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-c"]).await;
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
    let renewed = renewed_cert(&s, "wallet", &["scope-a", "scope-c"]);
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
    let family = Collection::with_sub_scopes("sample.items", Policy::new("scope-a", &["scope-a"]));
    *s.protocol.collections.lock().unwrap() = Some(vec![family.clone()]);
    let mut wallet = join_scoped(&s, "wallet", &["scope-a:kiosk"]).await;
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
    let renewed = renewed_cert(&s, "wallet", &["scope-a:kiosk", "scope-a:till"]);
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
    let renewed = renewed_cert(&s, "wallet", &["scope-a", "scope-c"]);
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-a", "scope-c"]).await;
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
    let renewed = renewed_cert(&s, "wallet", &["scope-c"]);
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

/// The failure path of a feed write under a certificate the reader never held: the view's
/// `cert` decides, and a write it doesn't authorize is flagged. The switch shows the record
/// with the renewed certificate, which lacks the write scope, as a faulty switch would.
#[tokio::test]
async fn test_records_feed_write_whose_view_lacks_the_write_scope_is_flagged() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["scope-a", "scope-c"]).await;
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
    let renewed = renewed_cert(&s, "wallet", &["scope-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    let until = s.w.clock.now_ms() + CLOCK_TOLERANCE_MS;
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, Some(until)));
    wallet.receive(None).await.unwrap();
    s.w.switch.lock().shared.records.get_mut(&key).unwrap().cert = Some(renewed.signed().clone());

    let before = s.log().len();
    let report = phone.receive(None).await.unwrap();
    let rules = flagged_rules(&report.events);
    assert!(
        rules.iter().any(|rule| rule.contains("step 5")),
        "{rules:?}"
    );
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-a", "scope-c"]).await;
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
    let renewed = renewed_cert(&s, "wallet", &["scope-c"]);
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
    let mut wallet = join_scoped(s, "wallet", &["scope-a", "scope-c"]).await;
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
    let renewed = renewed_cert(s, "wallet", &["scope-c"]);
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
/// shows them: a flagged write keeps no certificate, so each write's view is read, and each
/// write is flagged (Switch wire 6.2 "Accepting a write" step 5).
#[tokio::test]
async fn test_records_feed_writes_whose_views_lack_the_write_scope_are_each_flagged() {
    let s = Setup::new();
    let (_wallet, mut phone, keys, renewed) = writes_before_a_reduction(&s, 3).await;
    for key in &keys {
        s.w.switch.lock().shared.records.get_mut(key).unwrap().cert =
            Some(renewed.signed().clone());
    }
    let before = s.log().len();
    let report = phone.receive(None).await.unwrap();
    assert_eq!(
        flagged_rules(&report.events).len(),
        3,
        "{:?}",
        report.events
    );
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-a", "scope-c"]).await;
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
    let renewed = renewed_cert(&s, "wallet", &["scope-c"]);
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-a", "scope-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    phone.refresh_own_apps().await.unwrap();
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewal_of(&s, "wallet", &["scope-c"]);
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
    assert_eq!(tablet.list_collection(&items()).await.unwrap(), 2);
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-a", "scope-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewal_of(&s, "wallet", &["scope-c"]);
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
/// write, from the feed, the view and the list. The signer publishes the renewal before the
/// switch takes it, as in the failure path above.
#[tokio::test]
async fn test_records_view_cert_no_identity_json_lists_is_refused() {
    let s = Setup::new();
    let mut wallet = join_scoped(&s, "wallet", &["scope-a", "scope-c"]).await;
    let mut phone = s.join("phone").await;
    phone.receive(None).await.unwrap();
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewal_of(&s, "wallet", &["scope-c"]);
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
    let unlisted = renewal_of(&s, "wallet", &["scope-a", "scope-c"]);
    s.w.switch.lock().shared.records.get_mut(&key).unwrap().cert = Some(unlisted.signed().clone());
    s.w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: wallet.app_id(),
            cert: renewed.signed().clone(),
        })
        .unwrap();
    s.w.switch.deliver_identity(&opened).unwrap();
    s.w.switch.deliver_identity(&closed).unwrap();

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
    let mut wallet = join_scoped(&s, "wallet", &["scope-a", "scope-c"]).await;
    s.w.clock.advance_ms(DAY_MS);
    let earlier = wallet.cert().clone();
    let renewed = renewal_of(&s, "wallet", &["scope-c"]);
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
    s.w.switch.fail_next(Fault::Unreachable {
        path: "feed".into(),
        after: 0,
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
        .add_app("till", &AppSpec::new(&["scope-a"]), &["sample.note"], true)
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
    let mut phone = s.join("phone").await;
    assert_eq!(phone.list_collection(&items()).await.unwrap(), 420);
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
    assert_eq!(app.list_collection(&items()).await.unwrap(), 3);
    assert_eq!(s.w.switch.lock().shared.listings - before, 3);
    // Within the budget, one page holds them all.
    s.w.switch.lock().max_page_bytes = crate::testing::MAX_PAGE_BYTES;
    let all = app.client.records(&id, None, None).await.unwrap();
    assert_eq!(all.records.len(), 3);
    assert!(all.next.is_none());
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
    let mut headers = vec![crate::transport::Header::new(
        pubky_switch_core::http::header::IDENTITY,
        &s.w.alice.id(),
    )];
    if let Some(app) = app {
        headers.push(crate::transport::Header::new(
            pubky_switch_core::http::header::APP,
            &pubky_switch_core::enc::zbase32_encode(&app),
        ));
    }
    let response =
        s.w.switch
            .handle(&crate::transport::Request {
                method: "GET".into(),
                origin: ORIGIN.into(),
                path_and_query: format!("/v1/{}/{rest}", s.w.alice.id()),
                headers,
                body: Vec::new(),
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
    let wallet = join_scoped(&s, "wallet", &["scope-c"]).await;
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
async fn test_scripted_records_signer_and_an_app_without_a_certificate_read_none() {
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
    // An own app the switch holds no certificate for holds no read scope: refused by key,
    // and its list shows nothing, where the phone's shows the record.
    let unknown = Some(app_keys("unknown").app_id_bytes());
    assert_eq!(
        scripted_get(&s, unknown, &by_key),
        (403, json!("permission_missing"), true)
    );
    let shown = |app| {
        scripted_page(&s, app, &list)["records"]
            .as_array()
            .map(Vec::len)
    };
    assert_eq!(shown(Some(phone.app_id())), Some(1));
    assert_eq!(shown(unknown), Some(0));
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
    let mut wallet = join_scoped(&s, "wallet", &["scope-c"]).await;
    let mut phone = s.join("phone").await;
    let key =
        pubky_switch_core::enc::unb64_array::<32>(&phone_record(&s, &mut phone).await).unwrap();
    wallet.receive(None).await.unwrap();
    s.w.clock.advance_ms(HOUR);
    let earlier = wallet.cert().clone();
    let renewed = renewed_cert(&s, "wallet", &["scope-a", "scope-c"]);
    s.w.next_doc(|body| list_renewal(body, &earlier, &renewed, None));
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cert().hash(), renewed.hash());
    // The renewal's part came before the document listing it and was skipped: the key of
    // scope-a is missing, so the listing waits.
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
        "scope-a",
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
    assert!(wallet.scope_key(3, "scope-a").is_some());
    assert!(
        flagged_rules(&report.events).is_empty(),
        "{:?}",
        report.events
    );
}

// -------------------------------------------------------------------------------------
// A record read now, or an earlier copy kept (Switch wire 7.4.9)

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
        "scope-a",
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
        "feed?limit=0",
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
        };
        let response = s.peer.transport().send(request).await.unwrap();
        assert_eq!(response.status, 400, "{query}");
    }
}
