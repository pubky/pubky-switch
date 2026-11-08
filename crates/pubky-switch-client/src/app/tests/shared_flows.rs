//! Sending, admission, shared records and claims against the scripted switch, with bob's
//! switch as the counterparty's, and a neutral protocol with one collection.

use std::sync::{Arc, Mutex};

use pubky_switch_core::claims::{Basis, ClaimStatus, RECONCILIATION_MS};
use pubky_switch_core::envelope::parse_header;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ident::{Policy, invite_code_hash};
use pubky_switch_core::message::MessagePlaintext;
use pubky_switch_core::ops::{AllowKind, Condition, KeyBundlePut, OpKind, SignedOp};
use pubky_switch_core::records::{DAY_MS, RemovedApp, seal_bundle_parts};
use pubky_switch_core::scopes::Permission;
use serde_json::{Map, json};

use super::fake::ORIGIN;
use super::peer::{PEER_ORIGIN, PeerSwitch, Router};
use super::*;
use crate::app::{
    Alarm, AppError, AppEvent, ClaimOp, Collection, Delivery, ObligationDeadline, OpBatch,
    OutgoingMessage, RecordContent, RecordJob, RecordTarget, Refusal, SentMessage, claim_conflict,
};
use crate::store::{Fault as StoreFault, FaultStore};
use crate::transport::Transport;

const HOUR: u64 = 3_600_000;

/// A neutral protocol: [`SampleProtocol`]'s kinds, `sample.resend` as its re-send kind, and
/// one collection, `sample.items`, whose values list item IDs. What an app has seen of a
/// record is the IDs it held; a write that drops one goes back on it.
#[derive(Default)]
pub(crate) struct ItemsProtocol {
    pub(crate) sample: SampleProtocol,
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

    fn receive(&self, message: &ReceivedMessage) -> Outcome {
        self.sample.receive(message)
    }

    fn resend_needed(&self, needed: &ResendNeeded) -> Vec<LocalWrite> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Vec<LocalWrite> {
        self.sample.missed(missed)
    }

    fn adds_conversation(&self, kind: &str) -> bool {
        kind != "sample.resend"
    }

    fn collections(&self) -> Vec<Collection> {
        vec![items()]
    }

    fn record_seen(&self, _: &str, seen: Option<&[u8]>, value: Option<&[u8]>) -> Option<Vec<u8>> {
        let mut all = ids(seen);
        for id in ids(value) {
            if !all.contains(&id) {
                all.push(id);
            }
        }
        let all: Vec<&str> = all.iter().map(String::as_str).collect();
        Some(super::shared_flows::value(&all))
    }

    fn record_regression(&self, _: &str, seen: &[u8], value: Option<&[u8]>) -> Option<String> {
        let value = value?;
        let held = ids(Some(value));
        ids(Some(seen))
            .iter()
            .any(|id| !held.contains(id))
            .then(|| "sample: an item seen was dropped".to_owned())
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
            &w.bob,
            Arc::clone(&w.clock),
            Arc::clone(&w.homeserver),
            &["sample.note", "sample.resend"],
        );
        let router = Arc::new(Router {
            routes: vec![
                (
                    ORIGIN.to_owned(),
                    w.switch.transport() as Arc<dyn Transport>,
                ),
                (PEER_ORIGIN.to_owned(), peer.transport()),
            ],
            log: Mutex::new(Vec::new()),
        });
        Self {
            w,
            peer,
            protocol: Arc::new(ItemsProtocol::default()),
            router,
        }
    }

    fn env_on(&self, store: Arc<dyn StateStore>) -> AppEnv {
        AppEnv {
            store: StoreHandle::inline(store),
            transport: Arc::clone(&self.router) as Arc<dyn Transport>,
            clock: Arc::clone(&self.w.clock) as Arc<dyn Clock>,
            homeserver: Arc::clone(&self.w.homeserver) as Arc<dyn HomeserverReader>,
        }
    }

    fn env(&self) -> AppEnv {
        self.env_on(Arc::clone(&self.w.store) as Arc<dyn StateStore>)
    }

    /// The signer approves `keys` with `permissions`.
    fn approve(&self, keys: &AppKeys, permissions: &[Permission]) -> JoinRequest {
        let now = self.w.clock.now_ms();
        let cert = AppCert::issue(
            &self.w.alice,
            AppCertBody::new(
                self.w.alice.public(),
                keys.signing_public(),
                keys.bundle_public(),
                vec!["scope-a".to_owned()],
                permissions,
                now,
                now + DEFAULT_CERT_LIFETIME_MS,
            ),
        )
        .unwrap();
        let auth = AuthRequest {
            client_id: "sample.example".into(),
            client_key: [7; 32],
            caps: format!("{}:rw", app_record_path(&keys.app_id_bytes())),
            secret: [8; 32],
        };
        let request = AppRequest::sign(
            keys,
            AppRequestBody::new(keys, vec!["scope-a".to_owned()], &auth),
        )
        .unwrap();
        let doc = self.w.next_doc(|body| {
            body.apps.push(ListedApp {
                app_id: cert.app_id(),
                cert: cert.hash(),
            })
        });
        let has = SampleProtocol::default();
        let approval =
            Approval::issue(&self.w.alice, &request, cert, doc, &|s| has.has_keys(s)).unwrap();
        JoinRequest {
            identity: self.w.alice.public(),
            keys: keys.clone(),
            request,
            approval: approval.to_json().unwrap(),
        }
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
        self.router.log.lock().unwrap().clone()
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
    s.peer.rotate(0);
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
    s.peer.rotate(0);
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
async fn test_send_added_app_joins_the_recipients_after_stale_key() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.send(s.note("one")).await.unwrap();
    let till = s.peer.add_app("till", &["sample.note"], true);
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
    s.peer.lock().admitted = Some(Default::default());
    let (msg_id, delivery) = app.send(s.note("one")).await.unwrap();
    assert!(matches!(delivery, Delivery::Failed { .. }), "{delivery:?}");
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.failed, vec![msg_id]);
    assert!(s.peer.received().is_empty());
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
    s.peer.rotate(0);
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
    assert!(app.refresh_identity().await.unwrap());
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
async fn test_records_stale_epoch_takes_the_new_keys_and_writes_again() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let cert = app.cert().clone();
    let has_keys = |scope: &str| SampleProtocol::default().has_keys(scope);
    s.w.next_doc(|body| body.data_epoch = 2);
    for part in seal_bundle_parts(&s.w.alice, &cert, 1, 2, &has_keys).unwrap() {
        s.w.switch.signer_op(OpKind::KeyBundlePut(KeyBundlePut {
            target_app_id: app.app_id(),
            bundle: part.bundle,
            first_epoch: part.first_epoch,
            last_epoch: part.last_epoch,
        }));
    }
    let target = s.target("n1");
    let written = app
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    assert_eq!(app.data_epoch(), 2);
    let key = app.record_key(&target).unwrap();
    let held = s.w.switch.record_view(&key).unwrap();
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
            .record_view(&app.record_key(&target).unwrap())
            .is_none()
    );
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
    let older = s.w.switch.record_view(&key).unwrap();
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
    // The signer removes the wallet, distrusted from an hour ago; its later write has no
    // standing.
    let me = wallet.app_id();
    s.w.next_doc(|body| {
        body.apps.retain(|app| app.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from: START - HOUR,
        })
    });
    wallet
        .put_record(&target, &value(&["a", "z"]), vec![])
        .await
        .unwrap();
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
    let backup = app.backup().unwrap();
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
    let (seq, _) = s.w.switch.send(
        &s.w.bob,
        &s.w.bob_keys,
        &s.w.bob_cert,
        "sample.note",
        json!({ "nothing": 1 }),
        &[me],
    );
    app.receive(None).await.unwrap();
    assert!(app.cursor().seq >= seq);
    assert!(s.w.switch.app(&me).cursor < seq);
    app.submit_batch(OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
        .await
        .unwrap();
    assert!(s.w.switch.app(&me).cursor >= seq);
}

#[tokio::test]
async fn test_batch_of_eight_has_no_room_for_the_cursor_and_nine_is_refused() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let me = app.app_id();
    let (seq, _) = s.w.switch.send(
        &s.w.bob,
        &s.w.bob_keys,
        &s.w.bob_cert,
        "sample.note",
        json!({ "nothing": 1 }),
        &[me],
    );
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
