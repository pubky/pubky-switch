//! Push registration and the push extension's peek against the scripted switch.

use std::sync::{Arc, Mutex};

use pubky_switch_core::http::{sign_webhook, verify_webhook, webhook_body};

use super::moves::{NEXT, Router, freeze_for, has, join, join_on, next_key, publish_at};
use super::*;
use crate::app::{AppError, AppEvent, Peeked, PushRelay, Refusal};
use crate::error::TransportError;
use crate::store::StateStore;
use crate::testing::Fault;
use crate::transport::BoxFuture;

const RELAY: &str = "https://push.example/v1/hook";
const OTHER_RELAY: &str = "https://push.other.example/hook";

/// A registration a relay took: relay URL, device token, push key, handle.
type Taken = (String, String, [u8; 32], String);

/// A relay that binds a fresh handle to each registration it takes; `before` runs first.
#[derive(Default)]
struct FakeRelay {
    /// The registrations taken, in order.
    taken: Mutex<Vec<Taken>>,
    before: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    answer: Mutex<Option<String>>,
}

impl FakeRelay {
    fn last(&self) -> Taken {
        self.taken.lock().unwrap().last().cloned().unwrap()
    }
}

impl PushRelay for FakeRelay {
    fn register(
        &self,
        relay_url: String,
        device_token: String,
        push_key: [u8; 32],
    ) -> BoxFuture<'_, Result<String, TransportError>> {
        if let Some(before) = self.before.lock().unwrap().take() {
            before();
        }
        let mut taken = self.taken.lock().unwrap();
        let handle = self
            .answer
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| format!("handle-{}", taken.len()));
        taken.push((relay_url, device_token, push_key, handle.clone()));
        Box::pin(async move { Ok(handle) })
    }
}

/// The relay's check of a webhook for `handle` (Switch wire 8.3 check 3): it verifies with
/// the push key the handle is bound to.
fn relay_accepts(relay: &FakeRelay, handle: &str, signed_by: &ed25519_dalek::SigningKey) -> bool {
    let Some((url, _, bound, _)) = relay
        .taken
        .lock()
        .unwrap()
        .iter()
        .find(|(_, _, _, h)| h == handle)
        .cloned()
    else {
        return false;
    };
    let body = webhook_body(handle, START, &[1; 16]);
    let signature = sign_webhook(signed_by, &url, &body).unwrap();
    verify_webhook(&bound, &url, &body, &signature).is_ok()
}

fn push_key_at(switch: &ScriptedSwitch, app: &[u8; 16]) -> ed25519_dalek::SigningKey {
    switch.lock().push.get(app).unwrap().key.clone()
}

#[tokio::test]
async fn test_push_starts_registers_with_the_relay_and_sets_the_handle() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let relay = FakeRelay::default();
    let registration = app.register_push(&relay, RELAY, "device-1").await.unwrap();
    let (url, key, handles) = w.switch.push_of(&me).unwrap();
    assert_eq!(url, RELAY);
    assert_eq!(registration.push_key, key);
    assert_eq!(registration.handles, 1);
    // The relay bound the handle to the push key the switch minted.
    let (_, token, bound, handle) = relay.last();
    assert_eq!(token, "device-1");
    assert_eq!(bound, key);
    assert_eq!(handles, vec![handle.clone()]);
    assert!(relay_accepts(&relay, &handle, &push_key_at(&w.switch, &me)));
    assert_eq!(app.push_registration().await.unwrap(), Some(registration));
}

#[tokio::test]
async fn test_push_sets_the_handles_merged_with_the_other_devices() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let relay = FakeRelay::default();
    // Another device registered first, under the push key both share.
    app.register_push(&relay, RELAY, "device-1").await.unwrap();
    let (_, key, _) = w.switch.push_of(&me).unwrap();
    let theirs = crate::app::PushHandles {
        push_key: key,
        handles: vec!["their-handle".into()],
    };
    app.take_device_push_handles(theirs).await.unwrap();
    // This device's new handle goes with the other device's: the list replaces the one the
    // service holds (Switch wire 8.1).
    relay.answer.lock().unwrap().replace("my-handle".into());
    let registration = app.register_push(&relay, RELAY, "device-2").await.unwrap();
    assert_eq!(registration.handles, 2);
    let (_, _, handles) = w.switch.push_of(&me).unwrap();
    assert_eq!(
        handles,
        vec!["my-handle".to_owned(), "their-handle".to_owned()]
    );
    let mine = app.push_handles().await.unwrap().unwrap();
    assert_eq!(mine.push_key, key);
    assert_eq!(mine.handles, vec!["my-handle".to_owned()]);
    assert_eq!(format!("{mine:?}"), "PushHandles(1 handles)");
}

#[tokio::test]
async fn test_push_leaves_out_handles_of_another_push_key_or_too_many() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let relay = FakeRelay::default();
    let stale = crate::app::PushHandles {
        push_key: [9; 32],
        handles: vec!["stale-handle".into()],
    };
    app.take_device_push_handles(stale).await.unwrap();
    app.register_push(&relay, RELAY, "device-1").await.unwrap();
    let (_, _, handles) = w.switch.push_of(&me).unwrap();
    assert_eq!(handles.len(), 1);
    let too_many = crate::app::PushHandles {
        push_key: [9; 32],
        handles: (0..8).map(|i| format!("h{i}")).collect(),
    };
    assert!(matches!(
        app.take_device_push_handles(too_many).await.unwrap_err(),
        AppError::Refused(Refusal::Usage(_))
    ));
}

#[tokio::test]
async fn test_push_start_again_keeps_the_registration() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let relay = FakeRelay::default();
    let first = app.register_push(&relay, RELAY, "device-1").await.unwrap();
    let again = app.register_push(&relay, RELAY, "device-1").await.unwrap();
    assert_eq!(first.push_key, again.push_key);
    assert_eq!(w.switch.lock().minted, 1);
}

#[tokio::test]
async fn test_push_rotation_names_the_key_it_replaces() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let relay = FakeRelay::default();
    let first = app.register_push(&relay, RELAY, "device-1").await.unwrap();
    let old_handle = relay.last().3;
    let rotated = app.rotate_push_key(&relay).await.unwrap();
    assert_ne!(rotated.push_key, first.push_key);
    let (_, key, handles) = w.switch.push_of(&me).unwrap();
    assert_eq!(key, rotated.push_key);
    let new_handle = relay.last().3;
    assert_eq!(handles, vec![new_handle.clone()]);
    // The old handle is bound to the old key: the new key's webhooks don't verify for it.
    let now_signing = push_key_at(&w.switch, &me);
    assert!(!relay_accepts(&relay, &old_handle, &now_signing));
    assert!(relay_accepts(&relay, &new_handle, &now_signing));
}

#[tokio::test]
async fn test_push_rotation_after_a_lost_answer_takes_the_current_key() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let relay = FakeRelay::default();
    let first = app.register_push(&relay, RELAY, "device-1").await.unwrap();
    w.switch.fail_next(Fault::LoseAnswer {
        path: "push".into(),
    });
    assert!(matches!(
        app.rotate_push_key(&relay).await.unwrap_err(),
        AppError::Transport(_)
    ));
    // The rotation took: a retry naming the old key gets `409 conflict` with the new one.
    let rotated = app.rotate_push_key(&relay).await.unwrap();
    assert_ne!(rotated.push_key, first.push_key);
    assert_eq!(w.switch.push_of(&me).unwrap().1, rotated.push_key);
    assert_eq!(w.switch.lock().minted, 2);
}

#[tokio::test]
async fn test_push_moves_to_another_relay() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let relay = FakeRelay::default();
    let first = app.register_push(&relay, RELAY, "device-1").await.unwrap();
    let moved = app
        .register_push(&relay, OTHER_RELAY, "device-1")
        .await
        .unwrap();
    assert_ne!(moved.push_key, first.push_key);
    let (url, key, _) = w.switch.push_of(&me).unwrap();
    assert_eq!(url, OTHER_RELAY);
    assert_eq!(key, moved.push_key);
}

#[tokio::test]
async fn test_push_start_for_another_relays_registration_names_it() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    // Another device of the app registered for another relay; this device holds nothing.
    let relay = FakeRelay::default();
    let held = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    w.switch.lock().push.insert(
        me,
        crate::testing::PushReg {
            relay_url: OTHER_RELAY.into(),
            key: held.clone(),
            handles: vec!["other-device".into()],
        },
    );
    let registration = app.register_push(&relay, RELAY, "device-1").await.unwrap();
    let (url, key, _) = w.switch.push_of(&me).unwrap();
    assert_eq!(url, RELAY);
    assert_eq!(key, registration.push_key);
    assert_ne!(key, held.verifying_key().to_bytes());
}

#[tokio::test]
async fn test_push_handles_conflict_starts_again() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let relay = FakeRelay::default();
    app.register_push(&relay, RELAY, "device-1").await.unwrap();
    // While this device registers with the relay, another rotates the registration: the
    // handles name a key that isn't current.
    let switch = Arc::clone(&w.switch);
    *relay.before.lock().unwrap() = Some(Box::new(move || switch.rotate_push_behind(&me)));
    let registration = app.rotate_push_key(&relay).await.unwrap();
    let (_, key, handles) = w.switch.push_of(&me).unwrap();
    assert_eq!(registration.push_key, key);
    assert_eq!(handles, vec![relay.last().3]);
}

#[tokio::test]
async fn test_push_refuses_a_relay_url_or_handle_it_doesnt_keep() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let relay = FakeRelay::default();
    for url in [
        "http://push.example/hook",
        "https://push.example:8443/hook",
        "https://user@push.example/hook",
    ] {
        let error = app
            .register_push(&relay, url, "device-1")
            .await
            .unwrap_err();
        assert!(
            matches!(error, AppError::Refused(Refusal::Usage(_))),
            "{url}: {error:?}"
        );
    }
    *relay.answer.lock().unwrap() = Some(String::new());
    let error = app
        .register_push(&relay, RELAY, "device-1")
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::Refused(Refusal::Usage(_))));
    assert!(app.push_registration().await.unwrap().is_none());
}

#[tokio::test]
async fn test_push_registers_again_after_a_move() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let relay = FakeRelay::default();
    let before = app.register_push(&relay, RELAY, "device-1").await.unwrap();
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2)).unwrap();
    let next = w.switch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    app.receive(None).await.unwrap();
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(e, AppEvent::PushRemoved)));
    assert!(app.push_registration().await.unwrap().is_none());
    assert!(next.push_of(&me).is_none());
    // The next service mints a new push key; the device registers again under it.
    let after = app.reregister_push(&relay).await.unwrap().unwrap();
    assert_ne!(after.push_key, before.push_key);
    assert_eq!(next.push_of(&me).unwrap().1, after.push_key);
    assert_eq!(relay.last().2, after.push_key);
    // Nothing more to do.
    assert_eq!(
        app.reregister_push(&relay).await.unwrap().unwrap().push_key,
        after.push_key
    );
}

#[tokio::test]
async fn test_push_crash_at_each_commit_point_resumes() {
    let counting = Arc::new(crate::store::FaultStore::new(
        Arc::new(MemoryStore::new()) as Arc<dyn StateStore>,
        crate::store::Fault::None,
    ));
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&counting) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[],
    )
    .await;
    let joined = counting.commits();
    app.register_push(&FakeRelay::default(), RELAY, "device-1")
        .await
        .unwrap();
    let commits = counting.commits() - joined;
    assert!(commits >= 4, "the registration commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let inner = Arc::new(MemoryStore::new());
            let w = World::new();
            let router = Router::of(&w);
            let app = join_on(
                &w,
                &router,
                Arc::clone(&inner) as Arc<dyn StateStore>,
                w.protocol.clone(),
                &[],
            )
            .await;
            let me = app.app_id();
            let fault = Arc::new(crate::store::FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    crate::store::Fault::StopAfter(n)
                } else {
                    crate::store::Fault::StopBefore(n)
                },
            ));
            let relay = FakeRelay::default();
            let mut crashed = App::load(
                router.env(&w, Arc::clone(&fault) as Arc<dyn StateStore>),
                w.protocol.clone(),
                World::config(),
                me,
            )
            .await
            .unwrap();
            assert!(
                crashed
                    .register_push(&relay, RELAY, "device-1")
                    .await
                    .is_err()
            );
            assert!(fault.stopped());
            let mut app = App::load(
                router.env(&w, Arc::clone(&inner) as Arc<dyn StateStore>),
                w.protocol.clone(),
                World::config(),
                me,
            )
            .await
            .unwrap();
            let registration = match app.reregister_push(&relay).await.unwrap() {
                Some(registration) => registration,
                None => app.register_push(&relay, RELAY, "device-1").await.unwrap(),
            };
            let (_, key, handles) = w.switch.push_of(&me).unwrap();
            assert_eq!(registration.push_key, key, "commit {n} ({stop_after})");
            assert_eq!(handles, vec![relay.last().3], "commit {n} ({stop_after})");
            // A retried start minted nothing new.
            assert_eq!(w.switch.lock().minted, 1, "commit {n} ({stop_after})");
        }
    }
}

// -------------------------------------------------------------------------------------
// The push extension's peek (Switch spec 9 step 5)

/// Every record of the app's namespace.
fn snapshot(store: &MemoryStore, app: &[u8; 16]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let ns = crate::store::client_namespace(app);
    store.scan(&ns, b"", None, u32::MAX).unwrap()
}

#[tokio::test]
async fn test_peek_shows_a_note_and_changes_nothing() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    // Bob's identity.json is held fresh once a first note was read.
    w.note(me, "first");
    app.receive(None).await.unwrap();
    let (seq, message) = w.note(me, "second");
    let before = snapshot(&w.store, &me);
    let cursor = app.cursor();
    let report = app.peek().await.unwrap();
    assert!(report.chain_verified);
    match report.items.as_slice() {
        [
            Peeked::Show {
                seq: s,
                sender,
                message: m,
            },
        ] => {
            assert_eq!(*s, seq);
            assert_eq!(*sender, w.bob.public());
            assert_eq!(m.msg_id, message.msg_id);
        }
        other => panic!("{other:?}"),
    }
    // Nothing committed, nothing changed: the cursor, the chain view, the rotation.
    assert_eq!(snapshot(&w.store, &me), before);
    assert_eq!(app.cursor(), cursor);
    // The read processes it after.
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::MessageReceived { seq: s, .. } if *s == seq
    )));
}

#[tokio::test]
async fn test_peek_without_a_fresh_sender_copy_is_generic() {
    let w = World::new();
    let router = Router::of(&w);
    let app = join(&w, &router).await;
    let me = app.app_id();
    // No copy of bob's identity.json held: the peek fetches none.
    let seq = w.note(me, "hello").0;
    let report = app.peek().await.unwrap();
    assert_eq!(report.items, vec![Peeked::Generic { seq }]);
}

#[tokio::test]
async fn test_peek_of_a_body_the_protocol_refuses_is_generic() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    w.note(me, "first");
    app.receive(None).await.unwrap();
    // Signed by bob's current app, with a number where the kind needs text.
    let (seq, _) = w
        .switch
        .send(
            &w.bob,
            &w.bob_keys,
            &w.bob_cert,
            "sample.note",
            json!({ "text": 42 }),
            &[me],
        )
        .unwrap();
    let before = snapshot(&w.store, &me);
    let report = app.peek().await.unwrap();
    assert_eq!(report.items, vec![Peeked::Generic { seq }]);
    assert_eq!(snapshot(&w.store, &me), before);
    // The read drops it at check 10, as the peek judged it.
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::MessageDropped { seq: s, check: 10, .. } if *s == seq
    )));
}

#[tokio::test]
async fn test_peek_of_a_processed_message_shows_nothing() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let (_, message) = w.note(me, "once");
    app.receive(None).await.unwrap();
    // Bob re-sends the same signed message.
    let plaintext = message.sign(&w.bob_keys).unwrap();
    w.switch
        .send_plaintext(w.bob.public(), &w.bob_cert, &plaintext, &[me])
        .unwrap();
    let report = app.peek().await.unwrap();
    assert!(report.items.is_empty(), "{:?}", report.items);
}

#[tokio::test]
async fn test_peek_on_a_chain_that_doesnt_verify_is_generic_and_raises_nothing() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let phone = w.other_app("phone", &[Permission::ListsManage]);
    w.note(me, "first");
    app.receive(None).await.unwrap();
    let verified = w.switch.tip_seq();
    // The service rolls back its chain and forks it.
    w.switch.roll_back_to(verified - 1);
    w.switch
        .app_op(
            &phone,
            pubky_switch_core::ops::OpKind::DenyPut { pubky: [5; 32] },
        )
        .unwrap();
    let seq = w.note(me, "second").0;
    let before = snapshot(&w.store, &me);
    let report = app.peek().await.unwrap();
    assert!(!report.chain_verified);
    assert_eq!(report.items, vec![Peeked::Generic { seq }]);
    // The peek raised no alarm and kept none: the next read does.
    assert!(app.alarm().is_none());
    assert_eq!(snapshot(&w.store, &me), before);
}

#[test]
fn test_push_registration_debug_shows_no_key() {
    let registration = crate::app::PushRegistration {
        relay_url: RELAY.into(),
        push_key: [7; 32],
        handles: 1,
    };
    assert_eq!(format!("{registration:?}"), "PushRegistration(1 handles)");
}
