//! The public `testing` module, used as a crate built on the Switch uses it: an identity and
//! an app with a neutral sample protocol join a scripted switch, receive a message from a
//! peer, write a shared record, and write a claim attempt and its `done`; another own app's
//! operations, injected, are applied as the switch applies a submitted batch.

// The helpers set up fixed test state, where a failure is a test failure.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use pubky_switch_client::app::{
    App, AppConfig, AppEvent, ClaimOp, Collection, ObligationDeadline, RecordContent, RecordTarget,
};
use pubky_switch_client::clock::TestClock;
use pubky_switch_client::store::{MemoryStore, StateStore};
use pubky_switch_client::testing::{
    AppSpec, PEER_ORIGIN, PeerSwitch, ProtocolSpec, Router, START_MS, SWITCH_ORIGIN, ScriptError,
    Seeds, TestHomeserver, TestIdentity, TestProtocol, TestSigner,
};
use pubky_switch_client::transport::{Header, Request, Response, Transport};
use pubky_switch_core::claims::{Basis, ClaimFields, ClaimStatus, ClaimType};
use pubky_switch_core::ident::{NamingKey, Policy, collection_id, record_key_from_blinded};
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::ops::{IdInputs, OpKind, RecordPut, RecordVersion};
use pubky_switch_core::records::DAY_MS;
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sealed::SealedValue;
use serde_json::json;

/// A neutral sample protocol: scope `notes` has keys, apps accept `example.note`, and one
/// collection, `example.items`, is read and written under `notes`.
fn sample_spec() -> ProtocolSpec {
    ProtocolSpec {
        keyed_scopes: vec!["notes".into()],
        collections: vec![items()],
        accepts: vec!["example.note".into()],
    }
}

fn items() -> Collection {
    Collection::new("example.items", Policy::new("notes", &["notes"]))
}

/// Alice's signer and account, bob's switch with one app, and a router between them.
struct Setup {
    clock: Arc<TestClock>,
    alice: TestSigner,
    bob: Arc<PeerSwitch>,
    shop: [u8; 16],
    router: Arc<Router>,
    protocol: Arc<TestProtocol>,
}

impl Setup {
    fn new() -> Self {
        let seeds = Seeds::default();
        let clock = Arc::new(TestClock::new(START_MS));
        let homeserver = Arc::new(TestHomeserver::new());
        let alice = TestSigner::new(
            TestIdentity::new(&seeds, "alice"),
            Arc::clone(&clock),
            Arc::clone(&homeserver),
            sample_spec(),
        );
        let bob = PeerSwitch::new(
            TestIdentity::new(&seeds, "bob"),
            PEER_ORIGIN,
            Arc::clone(&clock),
            Arc::clone(&homeserver),
        );
        let shop = bob
            .add_app("shop", &AppSpec::new(&["notes"]), &["example.note"], false)
            .unwrap();
        let router = Arc::new(Router::new());
        router.add_switch(SWITCH_ORIGIN, alice.switch());
        router.add(PEER_ORIGIN, bob.transport());
        Self {
            clock,
            alice,
            bob,
            shop,
            router,
            protocol: Arc::new(TestProtocol::new(sample_spec())),
        }
    }

    async fn join(&self, name: &str) -> App {
        let keys = self.alice.identity().app_keys(name);
        let app = AppSpec::new(&["notes"]).with_permissions(&Permission::ALL);
        let request = self.alice.approve(&keys, &app).unwrap();
        let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
        let env = self
            .alice
            .env_with(store, Arc::clone(&self.router) as Arc<dyn Transport>);
        App::join(env, self.protocol.clone(), AppConfig::default(), request)
            .await
            .unwrap()
    }

    /// Another own app, `name`, registered with `app`, whose operations the test injects.
    fn other_app(&self, name: &str, app: &AppSpec) -> AppKeys {
        let keys = self.alice.identity().app_keys(name);
        self.alice.register_app(&keys, app).unwrap();
        keys
    }

    /// A first write of `value` at `natural_key` of `example.items`, as an app of alice
    /// builds it.
    fn create(&self, natural_key: &[u8], value: &[u8]) -> RecordPut {
        let identity = self.alice.identity().key();
        let policy = items().policy;
        let blinded = NamingKey::from_root(&identity.switch_root()).blind(natural_key);
        let key = record_key_from_blinded("example.items", &blinded, &policy.hash().unwrap());
        let scope_key = identity.scope_key(1, "notes");
        let sealed =
            SealedValue::seal(&scope_key, &identity.public(), 1, "notes", &key, value).unwrap();
        RecordPut {
            key,
            collection: collection_id("example.items", &identity.public()),
            policy,
            expected_version: RecordVersion::NONE,
            value_sealed: sealed,
            id_inputs: Some(IdInputs {
                collection: "example.items".into(),
                blinded_key: blinded,
            }),
        }
    }
}

fn attempt(claim_key: [u8; 32], attempt_id: [u8; 16], expected_step: u64) -> OpKind {
    OpKind::Claim(ClaimFields {
        claim_key: claim_key.to_vec(),
        kind: ClaimType::Attempt,
        expected_step,
        attempt_id: attempt_id.to_vec(),
        orphan_after: Some(3600),
        deadline: Some(START_MS + DAY_MS),
        basis: None,
        evidence_ref: None,
    })
}

#[tokio::test]
async fn test_testing_app_joins_and_receives_a_peer_message() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let me = app.app_id();
    assert!(s.alice.switch().app(&me).receive_key.is_some());
    let (seq, message) = s
        .bob
        .send_to(
            s.alice.switch(),
            s.shop,
            "example.note",
            json!({ "text": "hello" }),
            &[me],
        )
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(
        report.events.iter().any(
            |e| matches!(e, AppEvent::MessageReceived { seq: s, msg_id, .. }
                         if *s == seq && *msg_id == message.msg_id)
        ),
        "{:?}",
        report.events
    );
    let received = s.protocol.received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].sender, s.bob.identity());
    assert_eq!(received[0].message.kind, "example.note");
    assert_eq!(received[0].message.body["text"], json!("hello"));
    assert!(app.cursor().seq >= seq);
}

#[tokio::test]
async fn test_testing_app_refuses_a_kind_the_protocol_does_not_accept() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let me = app.app_id();
    let (seq, _) = s
        .bob
        .send_to(
            s.alice.switch(),
            s.shop,
            "example.other",
            json!({ "text": "hello" }),
            &[me],
        )
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::MessageDropped { seq: s, check: 8, .. } if *s == seq)),
        "{:?}",
        report.events
    );
    assert!(s.protocol.received().is_empty());
}

#[tokio::test]
async fn test_testing_app_writes_a_shared_record() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let target = RecordTarget::new(items(), b"n1");
    let value = json!({ "items": ["a"] }).to_string().into_bytes();
    let written = app.put_record(&target, &value, vec![]).await.unwrap();
    assert_eq!(written.content, RecordContent::Value(value.clone()));
    let key = app.record_key(&target).unwrap();
    let held = s.alice.switch().record(&key).unwrap();
    assert_eq!(held.writer, app.app_id());
    assert!(!held.state.deleted);
    let read = app.read_record(&target).await.unwrap().unwrap();
    assert_eq!(read.content.value(), Some(value.as_slice()));
}

#[tokio::test]
async fn test_testing_app_writes_a_claim_attempt_and_done() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let claim_key = [5; 32];
    let attempt_id = [6; 16];
    let deadline = START_MS + DAY_MS;
    let attempt = app
        .write_claim(
            ClaimOp::attempt(claim_key, 0, attempt_id, 3600, Some(deadline)),
            vec![],
            ObligationDeadline::At(deadline),
        )
        .await
        .unwrap();
    assert_eq!(attempt.view.status, ClaimStatus::Attempting);
    assert_eq!(attempt.view.owner, Some(app.app_id()));
    let condition = app.claim_condition(&claim_key).await.unwrap();
    let done = app
        .write_claim(
            ClaimOp::done(claim_key, 1, attempt_id, Basis::Owner, None).unwrap(),
            vec![condition],
            ObligationDeadline::At(deadline),
        )
        .await
        .unwrap();
    assert_eq!(done.view.status, ClaimStatus::Settled);
    assert!(s.alice.switch().claim(&claim_key).unwrap().settled);
    // A second attempt on the settled claim is refused.
    let refused = app
        .write_claim(
            ClaimOp::attempt(claim_key, 2, [7; 16], 3600, Some(deadline)),
            vec![],
            ObligationDeadline::At(deadline),
        )
        .await;
    assert!(refused.is_err());
}

#[tokio::test]
async fn test_testing_injected_claim_attempt_is_applied() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let phone = s.other_app(
        "phone",
        &AppSpec::new(&["notes"]).with_permissions(&Permission::ALL),
    );
    let switch = s.alice.switch();
    let (claim_key, attempt_id) = ([5; 32], [6; 16]);
    let seq = switch
        .app_op(&phone, attempt(claim_key, attempt_id, 0))
        .unwrap();
    assert_eq!(seq, switch.seq());
    let claim = switch.claim(&claim_key).unwrap();
    assert_eq!(claim.step, 1);
    let current = claim.current_attempt().unwrap();
    assert_eq!(
        (current.attempt_id, current.owner),
        (attempt_id, phone.app_id_bytes())
    );
    // The wallet reads and checks the claim the phone wrote, with its entry and proof.
    let read = wallet.read_claim(&claim_key).await.unwrap().unwrap();
    assert_eq!(read.view.status, ClaimStatus::Attempting);
    assert_eq!(read.view.owner, Some(phone.app_id_bytes()));
    assert_eq!(read.entries.len(), 1);
}

#[tokio::test]
async fn test_testing_injected_claim_refused_changes_nothing() {
    let s = Setup::new();
    let switch = s.alice.switch();
    let phone = s.other_app(
        "phone",
        &AppSpec::new(&["notes"]).with_permissions(&Permission::ALL),
    );
    let reader = s.other_app("reader", &AppSpec::new(&["notes"]));
    let claim_key = [5; 32];
    switch
        .app_op(&phone, attempt(claim_key, [6; 16], 0))
        .unwrap();
    let seq = switch.seq();
    // Without `claims.write`, and at a step the claim isn't at.
    let missing = switch.app_op(&reader, attempt(claim_key, [7; 16], 1));
    assert!(
        matches!(missing, Err(ScriptError::Refused { status: 403, .. })),
        "{missing:?}"
    );
    let stale = switch.app_op(&phone, attempt(claim_key, [7; 16], 0));
    assert!(
        matches!(stale, Err(ScriptError::Refused { status: 409, .. })),
        "{stale:?}"
    );
    // An app that never delivered its record.
    let stranger = s.alice.identity().app_keys("stranger");
    let unknown = switch.app_op(&stranger, attempt([8; 32], [9; 16], 0));
    assert!(
        matches!(unknown, Err(ScriptError::Refused { status: 403, .. })),
        "{unknown:?}"
    );
    assert_eq!(switch.seq(), seq);
    assert_eq!(switch.claim(&claim_key).unwrap().step, 1);
    assert!(switch.claim(&[8; 32]).is_none());
}

#[tokio::test]
async fn test_testing_injected_record_write_is_applied() {
    let s = Setup::new();
    let mut wallet = s.join("wallet").await;
    let phone = s.other_app("phone", &AppSpec::new(&["notes"]));
    let switch = s.alice.switch();
    let value = json!({ "items": ["b"] }).to_string().into_bytes();
    let put = s.create(b"n1", &value);
    let key = put.key;
    let seq = switch.app_op(&phone, OpKind::RecordPut(put)).unwrap();
    let held = switch.record(&key).unwrap();
    assert_eq!(held.writer, phone.app_id_bytes());
    assert_eq!(held.seq, seq);
    assert_eq!(held.state.version, RecordVersion::new(1, seq));
    // The wallet reads the phone's write.
    let target = RecordTarget::new(items(), b"n1");
    assert_eq!(wallet.record_key(&target).unwrap(), key);
    let read = wallet.read_record(&target).await.unwrap().unwrap();
    assert_eq!(read.content.value(), Some(value.as_slice()));
}

#[tokio::test]
async fn test_testing_injected_record_conflict_changes_nothing() {
    let s = Setup::new();
    let phone = s.other_app("phone", &AppSpec::new(&["notes"]));
    let switch = s.alice.switch();
    let other = s.other_app("other", &AppSpec::new(&["other"]));
    let first = s.create(b"n1", b"{}");
    let key = first.key;
    let seq = switch.app_op(&phone, OpKind::RecordPut(first)).unwrap();
    // A second create of the same record: its expected version isn't the record's.
    let again = switch.app_op(&phone, OpKind::RecordPut(s.create(b"n1", b"[]")));
    assert!(
        matches!(again, Err(ScriptError::Refused { status: 409, .. })),
        "{again:?}"
    );
    // Without a write scope of the record.
    let unscoped = switch.app_op(&other, OpKind::RecordPut(s.create(b"n2", b"{}")));
    assert!(
        matches!(unscoped, Err(ScriptError::Refused { status: 403, .. })),
        "{unscoped:?}"
    );
    assert_eq!(switch.seq(), seq);
    assert_eq!(switch.record(&key).unwrap().seq, seq);
}

/// A feed read by `app` past everything it has read, with `wait`, as the client sends it.
fn waiting_read(s: &Setup, app: &App, wait: &str) -> Request {
    let cursor = app.cursor();
    Request {
        method: "GET".into(),
        origin: SWITCH_ORIGIN.into(),
        path_and_query: format!(
            "/v1/{}/feed?after={}:{}&wait={wait}",
            s.alice.identity().key().id(),
            cursor.generation,
            cursor.seq
        ),
        headers: vec![Header::new(
            "switch-app",
            &pubky_switch_core::enc::zbase32_encode(&app.app_id()),
        )],
        body: Vec::new(),
    }
}

/// Poll `read` once: its answer, or `None` while the switch holds it.
fn poll_once(
    read: &mut std::pin::Pin<Box<dyn std::future::Future<Output = AnswerOrError> + Send + '_>>,
) -> Option<Response> {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match read.as_mut().poll(&mut context) {
        std::task::Poll::Ready(answer) => Some(answer.unwrap()),
        std::task::Poll::Pending => None,
    }
}

type AnswerOrError = Result<Response, pubky_switch_client::TransportError>;

fn items_of(answer: &Response) -> usize {
    let body: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
    body["items"].as_array().unwrap().len()
}

#[tokio::test]
async fn test_testing_holding_transport_holds_a_waiting_read_until_an_item_comes() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    let me = app.app_id();
    let switch = s.alice.switch();
    let transport = switch.holding_transport();

    // Nothing to show: the read is held (Switch wire 7.4.4).
    let mut read = transport.send(waiting_read(&s, &app, "25"));
    assert!(poll_once(&mut read).is_none());
    assert_eq!(switch.held_reads(), 1);
    // An entry for the app comes: the read is woken and answered with it.
    s.bob
        .send_to(
            switch,
            s.shop,
            "example.note",
            json!({ "text": "hello" }),
            &[me],
        )
        .unwrap();
    assert_eq!(switch.held_reads(), 0, "the entry woke the read");
    let answer = poll_once(&mut read).expect("answered");
    assert_eq!((answer.status, items_of(&answer)), (200, 1));
}

#[tokio::test]
async fn test_testing_holding_transport_answers_a_waiting_read_once_its_wait_passed() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    let switch = s.alice.switch();
    let transport = switch.holding_transport();

    let mut read = transport.send(waiting_read(&s, &app, "25"));
    assert!(poll_once(&mut read).is_none());
    // One second short of the wait: still held, and told to look, it holds on.
    s.clock.advance_ms(24_000);
    switch.release_held_reads();
    assert!(poll_once(&mut read).is_none());
    assert_eq!(switch.held_reads(), 1);
    // The wait has passed by the switch's clock: an empty page.
    s.clock.advance_ms(1_000);
    switch.release_held_reads();
    assert_eq!(switch.held_reads(), 0);
    let answer = poll_once(&mut read).expect("answered");
    assert_eq!((answer.status, items_of(&answer)), (200, 0));
}

#[tokio::test]
async fn test_testing_waiting_read_is_not_held_without_cause() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    app.receive(None).await.unwrap();
    let me = app.app_id();
    let switch = s.alice.switch();
    let holding = switch.holding_transport();

    // A `wait` out of its range is refused at once.
    for wait in ["26", "soon"] {
        let mut read = holding.send(waiting_read(&s, &app, wait));
        let answer = poll_once(&mut read).expect("refused at once");
        assert_eq!(answer.status, 400, "wait={wait}");
    }
    // `wait=0` is no wait.
    let mut read = holding.send(waiting_read(&s, &app, "0"));
    assert_eq!(poll_once(&mut read).map(|answer| answer.status), Some(200));
    // The plain transport holds nothing.
    let plain = switch.transport();
    let mut read = plain.send(waiting_read(&s, &app, "25"));
    let answer = poll_once(&mut read).expect("answered at once");
    assert_eq!((answer.status, items_of(&answer)), (200, 0));
    // With something to show, a waiting read is answered at once.
    s.bob
        .send_to(
            switch,
            s.shop,
            "example.note",
            json!({ "text": "hello" }),
            &[me],
        )
        .unwrap();
    let mut read = holding.send(waiting_read(&s, &app, "25"));
    let answer = poll_once(&mut read).expect("answered at once");
    assert_eq!((answer.status, items_of(&answer)), (200, 1));
    assert_eq!(switch.held_reads(), 0);
}
