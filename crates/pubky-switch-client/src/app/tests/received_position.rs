//! The position a receive step is handed ([`ReceivedMessage::generation`] and `seq`): the
//! one the entry was read at, which an entry stored locally keeps across a provider change.

use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use pubky_switch_core::records::{AppCert, Inbox};
use pubky_switch_core::scopes::Permission;

use super::moves::{Router, has, join_on, note_at, publish_at};
use super::*;
use crate::app::{AppEvent, FeedPosition, ParkReason, ReceiveContext, StoreFailure};
use crate::error::StoreError;
use crate::testing::SWITCH_ORIGIN as ORIGIN;

/// [`SampleProtocol`], recording the position and `parked` of every message handed to its
/// receive step, and failing the step for the entry while `rejecting` holds.
#[derive(Default)]
struct PositionProtocol {
    sample: SampleProtocol,
    rejecting: Mutex<bool>,
    handed: Mutex<Vec<(u64, u64, bool)>>,
}

impl PositionProtocol {
    fn set_rejecting(&self, rejecting: bool) {
        *self.rejecting.lock().unwrap() = rejecting;
    }

    fn handed(&self) -> Vec<(u64, u64, bool)> {
        self.handed.lock().unwrap().clone()
    }
}

impl Protocol for PositionProtocol {
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
        self.sample.accepts(cert)
    }

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(message)
    }

    fn receive(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        self.handed
            .lock()
            .unwrap()
            .push((message.generation, message.seq, message.parked));
        if *self.rejecting.lock().unwrap() {
            return Outcome::Retry(StoreFailure::of_entry(StoreError::Unavailable));
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
}

/// The same origin under a new key at generation 2, published: the sequence goes on.
fn change_key(w: &World, router: &Router) -> Arc<ScriptedSwitch> {
    let pending = SigningKey::from_bytes(&seed("service/alice/pending"));
    let changed = w.switch.import_into(pending.to_bytes());
    router.add(ORIGIN, &changed);
    publish_at(
        w,
        &changed,
        Inbox::new(ORIGIN, pending.verifying_key().to_bytes()),
        2,
        None,
    );
    changed
}

#[tokio::test]
async fn test_received_position_of_a_feed_entry_is_the_cursors_generation() {
    let w = World::new();
    let router = Router::of(&w);
    let protocol = Arc::new(PositionProtocol::default());
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        protocol.clone(),
        &[Permission::ConversationAdd],
    )
    .await;
    let me = app.app_id();
    let first = note_at(&w, &w.switch, me, "before the change");
    app.receive(None).await.unwrap();
    assert_eq!(protocol.handed(), vec![(1, first, false)]);
    let changed = change_key(&w, &router);
    let second = note_at(&w, &changed, me, "after the change");
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    assert_eq!(
        protocol.handed(),
        vec![(1, first, false), (2, second, false)]
    );
}

#[tokio::test]
async fn test_received_position_of_a_stored_entry_retried_after_a_provider_change_is_its_first() {
    let w = World::new();
    let router = Router::of(&w);
    let protocol = Arc::new(PositionProtocol::default());
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        protocol.clone(),
        &[Permission::ConversationAdd],
    )
    .await;
    let me = app.app_id();
    // The step fails for the entry at generation 1: it is stored locally and passed.
    let stored = note_at(&w, &w.switch, me, "stored");
    protocol.set_rejecting(true);
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::Parked { seq, reason: ParkReason::StoreRejected, .. } if *seq == stored
        )),
        "{:?}",
        report.events
    );
    assert_eq!(app.cursor().generation, 1);
    assert!(app.cursor().seq >= stored);
    // A retry before the change fails too, and reports the same position.
    app.receive(None).await.unwrap();
    assert!(
        protocol
            .handed()
            .iter()
            .all(|at| (at.0, at.1) == (1, stored)),
        "{:?}",
        protocol.handed()
    );
    // The key changes in place, and a note comes at generation 2.
    let changed = change_key(&w, &router);
    let after = note_at(&w, &changed, me, "after the change");
    protocol.set_rejecting(false);
    let before = protocol.handed().len();
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    let mut handed = protocol.handed().split_off(before);
    handed.sort_unstable();
    handed.dedup();
    // Every retry reports the generation and `seq` the entry was read at, not the
    // cursor's.
    assert_eq!(handed, vec![(1, stored, true), (2, after, false)]);
    assert!(app.state.parked.is_empty());
}

fn at(generation: u64, seq: u64) -> FeedPosition {
    FeedPosition { generation, seq }
}

/// Across a key change in place the sequence goes on: positions compare by `seq` alone,
/// whatever generation they were read at, where the plain pair puts them the other way;
/// a generation past the followed one comes after everything.
#[tokio::test]
async fn test_received_order_compares_by_seq_across_a_key_change() {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let w = World::new();
    let router = Router::of(&w);
    let protocol = Arc::new(PositionProtocol::default());
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        protocol.clone(),
        &[Permission::ConversationAdd],
    )
    .await;
    let me = app.app_id();
    let before = note_at(&w, &w.switch, me, "before");
    app.receive(None).await.unwrap();
    let changed = change_key(&w, &router);
    let after = note_at(&w, &changed, me, "after the change");
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    assert!(after > before);
    assert_eq!(app.received_order(at(1, before), at(2, after)), Less);
    assert_eq!(app.received_order(at(2, before), at(1, after)), Less);
    assert!((2, before) > (1, after), "the plain pair says otherwise");
    assert_eq!(app.received_order(at(1, after), at(2, after)), Equal);
    assert_eq!(app.received_order(at(3, 1), at(2, after)), Greater);
    assert_eq!(app.received_order(at(3, 1), at(4, 1)), Less);
}

/// After a provider loss the lost sequence comes first, whatever its `seq`, and the new one
/// compares by `seq`.
#[tokio::test]
async fn test_received_order_puts_a_lost_sequence_first() {
    use std::cmp::Ordering::{Greater, Less};
    let store = Arc::new(MemoryStore::new());
    let lost = super::moves::lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let (app, _) = super::moves::follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert_eq!(app.cursor().generation, 2);
    assert_eq!(app.received_order(at(1, 100), at(2, 1)), Less);
    assert_eq!(app.received_order(at(2, 3), at(2, 5)), Less);
    assert_eq!(app.received_order(at(2, 1), at(1, 100)), Greater);
}
