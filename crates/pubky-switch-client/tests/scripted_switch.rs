//! The public `testing` module, used as a crate built on the Switch uses it: an identity and
//! an app with a neutral sample protocol join a scripted switch, receive a message from a
//! peer, write a shared record, and write a claim attempt and its `done`.

// The helpers set up fixed test state, where a failure is a test failure.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use pubky_switch_client::app::{
    App, AppConfig, AppEvent, ClaimOp, Collection, ObligationDeadline, RecordContent, RecordTarget,
};
use pubky_switch_client::clock::TestClock;
use pubky_switch_client::store::{MemoryStore, StateStore};
use pubky_switch_client::testing::{
    AppSpec, PEER_ORIGIN, PeerSwitch, ProtocolSpec, Router, START_MS, SWITCH_ORIGIN, Seeds,
    TestHomeserver, TestIdentity, TestProtocol, TestSigner,
};
use pubky_switch_client::transport::Transport;
use pubky_switch_core::claims::{Basis, ClaimStatus};
use pubky_switch_core::ident::Policy;
use pubky_switch_core::records::DAY_MS;
use pubky_switch_core::scopes::Permission;
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
