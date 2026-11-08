//! A protocol built on the client through its public API alone, with a neutral sample
//! protocol: two identities, each on its own scripted switch, message each other. The
//! sender signs a message, writes the record named by its hash and queues the message in
//! one batch; the recipient's receive step writes the message's record in the batch that
//! moves its cursor; the sender looks the recipient's `identity.json` up at its switch; and
//! the recipient lists a collection whose records have one policy per sub-scope.

// The helpers set up fixed test state, where a failure is a test failure.
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use pubky_switch_client::app::{
    App, AppConfig, AppError, Collection, Delivery, Effect, Initiator, LocalWrite,
    MAX_CURSOR_DEFER_MS, MayAct, MissedEntries, OpBatch, Outcome, OutgoingMessage, Protocol,
    ReceiveContext, ReceivedMessage, RecordTarget, ResendNeeded, SwitchCopy,
};
use pubky_switch_client::clock::TestClock;
use pubky_switch_client::store::{MemoryStore, StateStore};
use pubky_switch_client::testing::{
    AppSpec, ProtocolSpec, Router, START_MS, Seeds, TestHomeserver, TestIdentity, TestSigner,
};
use pubky_switch_client::transport::Transport;
use pubky_switch_core::ident::Policy;
use pubky_switch_core::message::Message;
use pubky_switch_core::ops::{Condition, OpKind, RecordVersion};
use pubky_switch_core::records::AppCert;
use pubky_switch_core::scopes::Permission;
use serde_json::{Map, Value, json};

const ALICE_ORIGIN: &str = "https://alice-switch.example";
const BOB_ORIGIN: &str = "https://bob-switch.example";
const NOTE: &str = "example.note";

/// The sample protocol's one collection: a record per message, keyed by the message's hash,
/// under `notes`, or under `notes:<sub>` for an app that holds only a sub-scope.
fn notes() -> Collection {
    Collection::with_sub_scopes("example.notes", Policy::new("notes", &["notes"]))
}

/// The record of the message whose hash is `hash`.
fn note_record(hash: &[u8; 32]) -> RecordTarget {
    RecordTarget::new(notes(), hash)
}

fn spec() -> ProtocolSpec {
    ProtocolSpec {
        keyed_scopes: vec!["notes".into()],
        collections: vec![notes()],
        accepts: vec![NOTE.into()],
    }
}

/// A neutral protocol: apps holding `notes` send and receive `example.note`, and an app
/// that receives one writes the message's record, keyed by its hash, in the batch that moves
/// its cursor, unless the record holds it already.
#[derive(Default)]
struct NotesProtocol {
    received: Mutex<Vec<String>>,
}

impl Protocol for NotesProtocol {
    fn has_keys(&self, scope: &str) -> bool {
        spec().has_keys(scope)
    }

    fn sent_between_own_apps(&self, _kind: &str) -> bool {
        false
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        if message.kind == NOTE && sender.holds_scope("notes") && own.holds_scope("notes") {
            Ok(())
        } else {
            Err("example: a kind these scopes don't send or receive".into())
        }
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        if cert.holds_scope("notes") {
            vec![NOTE.into()]
        } else {
            Vec::new()
        }
    }

    fn receive_with(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        let Some(text) = message.message.body.get("text").and_then(Value::as_str) else {
            return Outcome::Drop {
                reason: "example: body.text isn't text".into(),
            };
        };
        let target = note_record(&message.plaintext.hash());
        // Another own app may have recorded it first: only the cursor moves then.
        match cx.record(&target) {
            Ok(Some(held)) if held.content.value().is_some() => {}
            Ok(_) => {
                let value = json!({ "msg_id": message.message.msg_id, "text": text });
                if cx
                    .put_record(&target, value.to_string().as_bytes(), vec![])
                    .is_err()
                {
                    return Outcome::Drop {
                        reason: "example: the record can't be written".into(),
                    };
                }
            }
            Err(_) => {
                return Outcome::Drop {
                    reason: "example: the record can't be read".into(),
                };
            }
        }
        cx.local(LocalWrite::Put {
            key: format!("seen/{}", message.message.msg_id).into_bytes(),
            value: b"1".to_vec(),
        });
        self.received
            .lock()
            .unwrap()
            .push(message.message.msg_id.clone());
        Outcome::Apply(Effect::default())
    }

    fn resend_needed(&self, _needed: &ResendNeeded) -> Vec<LocalWrite> {
        Vec::new()
    }

    fn missed(&self, _missed: &MissedEntries) -> Vec<LocalWrite> {
        Vec::new()
    }

    fn collections(&self) -> Vec<Collection> {
        vec![notes()]
    }
}

/// Alice and bob, each with a signer and a scripted switch at an origin of its own.
struct World {
    alice: TestSigner,
    bob: TestSigner,
    router: Arc<Router>,
}

impl World {
    fn new() -> Self {
        let seeds = Seeds::default();
        let clock = Arc::new(TestClock::new(START_MS));
        let homeserver = Arc::new(TestHomeserver::new());
        let signer = |name: &str, origin: &str| {
            TestSigner::at(
                TestIdentity::new(&seeds, name),
                origin,
                Arc::clone(&clock),
                Arc::clone(&homeserver),
                spec(),
            )
        };
        let alice = signer("alice", ALICE_ORIGIN);
        let bob = signer("bob", BOB_ORIGIN);
        let router = Arc::new(Router::new());
        router.add_switch(alice.origin(), alice.switch());
        router.add_switch(bob.origin(), bob.switch());
        Self { alice, bob, router }
    }

    async fn join(
        &self,
        signer: &TestSigner,
        name: &str,
        scopes: &[&str],
        protocol: &Arc<NotesProtocol>,
    ) -> App {
        let keys = signer.identity().app_keys(name);
        let app = AppSpec::new(scopes).with_permissions(&Permission::ALL);
        let request = signer.approve(&keys, &app).unwrap();
        let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
        let env = signer.env_with(store, Arc::clone(&self.router) as Arc<dyn Transport>);
        // A cursor move waits for the next batch as long as it may: the one the switch holds
        // after a read came with an effect.
        let config = AppConfig {
            cursor_defer_ms: MAX_CURSOR_DEFER_MS,
            ..AppConfig::default()
        };
        App::join(env, protocol.clone(), config, request)
            .await
            .unwrap()
    }
}

fn note(to: [u8; 32], text: &str) -> OutgoingMessage {
    let mut body = Map::new();
    body.insert("text".into(), json!(text));
    OutgoingMessage::new(to, NOTE, body)
}

fn record_puts(signer: &TestSigner) -> usize {
    signer
        .switch()
        .applied()
        .iter()
        .filter(|op| matches!(op.body().kind, OpKind::RecordPut(_)))
        .count()
}

/// Sign a note, write its record from its hash and queue it, in one batch.
async fn sign_and_record(app: &mut App, to: [u8; 32], text: &str) -> (String, [u8; 32]) {
    let signed = app.sign_message(note(to, text)).unwrap();
    let hash = signed.hash();
    let value = json!({ "msg_id": signed.msg_id(), "text": text }).to_string();
    let entry = app
        .record_op(&note_record(&hash), Some(value.as_bytes()), vec![])
        .await
        .unwrap();
    let msg_id = signed.msg_id().to_owned();
    app.submit_batch(OpBatch::new().entry(entry).queue(signed))
        .await
        .unwrap();
    (msg_id, hash)
}

#[tokio::test]
async fn test_protocol_api_two_identities_message_and_record_each_message() {
    let w = World::new();
    let alice_protocol = Arc::new(NotesProtocol::default());
    let bob_protocol = Arc::new(NotesProtocol::default());
    let mut wallet = w
        .join(&w.alice, "wallet", &["notes"], &alice_protocol)
        .await;
    let mut desk = w.join(&w.bob, "desk", &["notes"], &bob_protocol).await;
    let alice = w.alice.identity().public();
    let bob = w.bob.identity().public();

    // The sender signs the note, writes its record from the note's hash, and queues the
    // note, in one batch (item 3).
    let (msg_id, hash) = sign_and_record(&mut wallet, bob, "hello").await;
    let sent = wallet.record_key(&note_record(&hash)).unwrap();
    assert!(wallet.shared_record(&sent).await.unwrap().is_some());

    // Bob's switch doesn't admit alice yet: the note stays queued (item 8, admission).
    let delivery = wallet.flush_message(&msg_id).await.unwrap().unwrap();
    assert!(
        matches!(&delivery, Delivery::Queued { last_error: Some(e), .. } if e.contains("not_admitted")),
        "{delivery:?}"
    );
    // Once bob invites alice, it goes.
    desk.invite(&alice).await.unwrap();
    let delivery = wallet.flush_message(&msg_id).await.unwrap().unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert_eq!(w.bob.switch().entries_from(&alice), 1);

    // Bob's receive step writes the note's record in the batch that moves the cursor
    // (item 1): the switch holds the cursor past the entry with the one record write.
    let puts = record_puts(&w.bob);
    desk.receive(None).await.unwrap();
    assert_eq!(record_puts(&w.bob), puts + 1);
    assert_eq!(desk.service_cursor(), desk.cursor());
    let received = desk.record_key(&note_record(&hash)).unwrap();
    let record = desk.shared_record(&received).await.unwrap().unwrap();
    let value: Value = serde_json::from_slice(record.content.value().unwrap()).unwrap();
    assert_eq!(value["msg_id"], json!(msg_id));
    assert_eq!(bob_protocol.received.lock().unwrap().clone(), vec![msg_id]);
    let local = desk
        .protocol_scan(b"seen/")
        .await
        .unwrap()
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    assert_eq!(local.len(), 1);

    // Alice looks bob's identity.json up, at his switch too (item 5).
    let found = wallet.identity_of(&bob, true).await.unwrap();
    assert_eq!(found.switch_copy, SwitchCopy::Read);
    assert_eq!(found.doc.version(), w.bob.body().version);

    // Bob adds an app: alice's next note meets `stale_key` and is sealed to both (item 8).
    let mut phone = w.join(&w.bob, "phone", &["notes"], &bob_protocol).await;
    let (second, _) = sign_and_record(&mut wallet, bob, "again").await;
    let delivery = wallet.flush_message(&second).await.unwrap().unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    phone.receive(None).await.unwrap();
    assert!(bob_protocol.received.lock().unwrap().contains(&second));
    // The desk finds the phone's record of it, and writes nothing more.
    let puts = record_puts(&w.bob);
    desk.receive(None).await.unwrap();
    assert_eq!(record_puts(&w.bob), puts);

    // A kiosk holding only `notes:kiosk` writes under its sub-scope's policy; the desk,
    // holding `notes`, lists the collection's family and takes it (item 7).
    let mut kiosk = w
        .join(&w.bob, "kiosk", &["notes:kiosk"], &bob_protocol)
        .await;
    let kiosk_target = RecordTarget::new(notes().sub_scope("kiosk").unwrap(), b"k1");
    kiosk
        .put_record(&kiosk_target, br#"{"text":"at the kiosk"}"#, vec![])
        .await
        .unwrap();
    assert_eq!(desk.list_collection(&notes()).await.unwrap(), 3);
    let held = desk.records_of("example.notes").await.unwrap();
    assert_eq!(held.len(), 3);
    assert!(
        held.iter()
            .any(|r| r.policy == notes().sub_scope_policy("kiosk").unwrap())
    );
    assert!(desk.flagged_writes().await.unwrap().is_empty());
    // The kiosk lists only what its sub-scope reads.
    assert_eq!(kiosk.list_collection(&notes()).await.unwrap(), 1);
}

#[tokio::test]
async fn test_protocol_api_refused_batch_queues_no_message() {
    let w = World::new();
    let protocol = Arc::new(NotesProtocol::default());
    let mut wallet = w.join(&w.alice, "wallet", &["notes"], &protocol).await;
    let bob = w.bob.identity().public();
    let signed = wallet.sign_message(note(bob, "hello")).unwrap();
    let target = note_record(&signed.hash());
    let key = wallet.record_key(&target).unwrap();
    // A condition that fails: the batch, and the message in it, go nowhere.
    let mismatched = Condition::RecordVersion {
        key,
        version: RecordVersion::new(1, 99),
    };
    let entry = wallet
        .record_op(&target, Some(b"{}"), vec![mismatched])
        .await
        .unwrap();
    let error = wallet
        .submit_batch(OpBatch::new().entry(entry).queue(signed.clone()))
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::Switch(_)), "{error:?}");
    assert!(wallet.delivery(signed.msg_id()).await.unwrap().is_none());
    assert!(wallet.shared_record(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn test_protocol_api_unknown_identity_is_not_found_at_any_switch() {
    let w = World::new();
    let protocol = Arc::new(NotesProtocol::default());
    let mut wallet = w.join(&w.alice, "wallet", &["notes"], &protocol).await;
    let stranger = TestIdentity::new(&Seeds::default(), "stranger").public();
    assert!(wallet.identity_of(&stranger, false).await.is_err());
}

#[tokio::test]
async fn test_protocol_api_identity_lookup_in_two_halves() {
    let w = World::new();
    let protocol = Arc::new(NotesProtocol::default());
    let mut wallet = w.join(&w.alice, "wallet", &["notes"], &protocol).await;
    let _desk = w.join(&w.bob, "desk", &["notes"], &protocol).await;
    let bob = w.bob.identity().public();
    let grace_ms = 500;
    // The Homeserver's half is read now; the switch's half runs apart from the app, so a
    // caller waits for it at most the grace and lets it run on (Switch spec 4.3).
    let lookup = wallet.begin_identity_lookup(&bob, true).await.unwrap();
    assert_eq!(lookup.identity.switch_copy, SwitchCopy::Pending);
    assert_eq!(
        lookup
            .identity
            .may_act(START_MS + grace_ms, Initiator::User, grace_ms),
        MayAct::IfUserConfirms
    );
    let answer = lookup.switch.unwrap().await;
    let found = wallet.finish_identity_lookup(answer).await.unwrap();
    assert_eq!(
        found.may_act(START_MS + grace_ms, Initiator::Automatic, grace_ms),
        MayAct::Now
    );
}
