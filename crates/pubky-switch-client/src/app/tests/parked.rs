//! What a host sees and settles of the entries stored locally (Switch spec 8.2): listing
//! and viewing them, forgetting one that isn't tried again, and releasing one whose effect
//! was uncertain to be tried once more; each change in one commit.

use std::sync::{Arc, Mutex};

use pubky_switch_core::message::Message;
use pubky_switch_core::ops::OpKind;
use pubky_switch_core::records::DAY_MS;

use super::flows::received;
use super::moves::has;
use super::*;
use crate::app::{AppError, AppEvent, ParkReason, ParkedSummary, Refusal, StoreFailure};
use crate::error::StoreError;
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::Fault;

/// What [`ParkingProtocol`]'s receive step does with a note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// The sample protocol's effect.
    Plain,
    /// Eight operations: more than one batch takes, stored and not tried again.
    Wide,
    /// The store fails for the entry: stored and tried again.
    Rejected,
    /// The sample protocol's effect, but a run the host released is declined.
    DeclineReleased,
    /// The sample protocol's effect, but the first run of an entry stored locally can't
    /// finish ([`Outcome::Retry`]).
    RetryFirstStoredRun,
    /// The protocol's store is unavailable: held, then stored after the bounded wait.
    Unavailable,
}

/// The sample protocol, whose receive step follows [`Mode`].
struct ParkingProtocol {
    sample: SampleProtocol,
    mode: Mutex<Mode>,
    /// [`ReceivedMessage::released`] at each receive step, in order.
    released: Mutex<Vec<bool>>,
    /// How many runs of entries stored locally there were.
    stored_runs: Mutex<u32>,
}

impl ParkingProtocol {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            sample: SampleProtocol::default(),
            mode: Mutex::new(mode),
            released: Mutex::new(Vec::new()),
            stored_runs: Mutex::new(0),
        })
    }

    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }

    /// How many times a note was handed over.
    fn handed(&self) -> usize {
        self.sample.received.lock().unwrap().len()
    }

    fn released(&self) -> Vec<bool> {
        self.released.lock().unwrap().clone()
    }
}

impl Protocol for ParkingProtocol {
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

    fn receive(&self, message: &ReceivedMessage) -> Outcome {
        self.released.lock().unwrap().push(message.released);
        let mode = *self.mode.lock().unwrap();
        match mode {
            Mode::Plain => self.sample.receive(message),
            Mode::Wide => {
                self.sample.received.lock().unwrap().push((
                    message.seq,
                    message.message.msg_id.clone(),
                    false,
                ));
                Outcome::Apply(Effect {
                    ops: (0..8u8)
                        .map(|n| (Vec::new(), OpKind::DenyPut { pubky: [n; 32] }))
                        .collect(),
                    local: Vec::new(),
                })
            }
            Mode::Rejected => Outcome::Retry(StoreFailure::of_entry(StoreError::Corrupt)),
            Mode::Unavailable => Outcome::Retry(StoreError::Unavailable.into()),
            Mode::DeclineReleased if message.released => Outcome::Drop {
                reason: "sample: it may have been applied".into(),
            },
            Mode::DeclineReleased => self.sample.receive(message),
            Mode::RetryFirstStoredRun => {
                if message.parked {
                    let mut runs = self.stored_runs.lock().unwrap();
                    *runs += 1;
                    if *runs == 1 {
                        return Outcome::Retry(StoreError::Unavailable.into());
                    }
                }
                self.sample.receive(message)
            }
        }
    }

    fn resend_needed(&self, needed: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.sample.missed(missed)
    }

    fn backup_name(&self) -> Option<String> {
        Some("sample.parking".into())
    }
}

/// Alice's wallet with `protocol`, on `store`.
async fn wallet_on(w: &World, protocol: &Arc<ParkingProtocol>, store: Arc<dyn StateStore>) -> App {
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    App::join(w.env_on(store), protocol.clone(), World::config(), request)
        .await
        .unwrap()
}

/// The wallet loaded again on `store`.
async fn load_on(w: &World, protocol: &Arc<ParkingProtocol>, store: Arc<dyn StateStore>) -> App {
    App::load(
        w.env_on(store),
        protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap()
}

/// The entry stored locally at local ID `id`, as listed.
async fn listed(app: &mut App, id: u64) -> Option<ParkedSummary> {
    let entries = app.parked_entries().await.unwrap();
    entries.into_iter().find(|entry| entry.stored_id == id)
}

/// The reasons the entries stored locally were stored for, by local ID.
async fn reasons(app: &mut App) -> Vec<(u64, ParkReason)> {
    let entries = app.parked_entries().await.unwrap();
    entries.iter().map(|e| (e.stored_id, e.reason)).collect()
}

/// A note from bob stored as `mode` makes it. Returns its listing and message.
async fn parked_as(
    w: &World,
    app: &mut App,
    protocol: &ParkingProtocol,
    mode: Mode,
) -> (ParkedSummary, Message) {
    protocol.set(mode);
    let (seq, message) = w.note(app.app_id(), "parked note");
    app.receive(None).await.unwrap();
    protocol.set(Mode::Plain);
    let id = app.stored_id_at(seq).unwrap();
    (listed(app, id).await.unwrap(), message)
}

/// A note whose effect was applied but whose answer was lost, kept past the window in
/// which a resend tells: stored as uncertain. Returns its listing and message.
async fn uncertain(w: &World, app: &mut App) -> (ParkedSummary, Message) {
    let (seq, message) = w.note(app.app_id(), "uncertain note");
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    w.clock.advance_ms(31 * DAY_MS);
    w.switch.lock().batches.clear();
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(seq).unwrap();
    let entry = listed(app, id).await.unwrap();
    assert_eq!(entry.reason, ParkReason::Uncertain);
    (entry, message)
}

/// Bob sends `message` again; returns its `seq`.
fn resend(w: &World, app: &App, message: &Message) -> u64 {
    let plaintext = message.sign(&w.bob_keys).unwrap();
    w.switch
        .send_plaintext(w.bob.public(), &w.bob_cert, &plaintext, &[app.app_id()])
        .unwrap()
}

/// Bob sends `message` again; returns whether the read took it as a duplicate.
async fn resent_is_duplicate(w: &World, app: &mut App, message: &Message) -> bool {
    let again = resend(w, app, message);
    let report = app.receive(None).await.unwrap();
    has(
        &report.events,
        |e| matches!(e, AppEvent::Duplicate { seq, conflicting: false } if *seq == again),
    )
}

/// The host acknowledges every duty event it was handed.
async fn ack_all(app: &mut App) {
    let events = app.unacknowledged_events().await.unwrap();
    if let Some(last) = events.iter().filter_map(AppEvent::id).next_back() {
        app.ack_events(last).await.unwrap();
    }
}

fn usage<T: std::fmt::Debug>(result: Result<T, AppError>) -> bool {
    matches!(result, Err(AppError::Refused(Refusal::Usage(_))))
}

#[tokio::test]
async fn test_parked_entries_are_listed_and_viewed_by_local_id() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (wide, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let (rejected, _) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    assert!(wide.stored_id < rejected.stored_id && wide.seq < rejected.seq);
    assert_eq!(
        reasons(&mut app).await,
        vec![
            (wide.stored_id, ParkReason::TooManyOperations),
            (rejected.stored_id, ParkReason::StoreRejected)
        ]
    );
    let plaintext = message.sign(&w.bob_keys).unwrap();
    assert_eq!(wide.hash, plaintext.hash());
    assert!(wide.readable);
    assert_eq!(wide.generation, 1);
    let view = app.parked_entry(wide.stored_id).await.unwrap().unwrap();
    assert_eq!((view.stored_id, view.seq), (wide.stored_id, wide.seq));
    assert_eq!(view.sender, w.bob.public());
    assert!(view.sender_verified);
    assert_eq!(view.reason, ParkReason::TooManyOperations);
    let read = view.message.clone().unwrap();
    assert_eq!(read.msg_id, message.msg_id);
    assert_eq!(read.kind, "sample.note");
    assert_eq!(view.plaintext.hash(), plaintext.hash());
    assert_eq!(view.retry_reads, 0);
    // Its Debug names the entry, never its content.
    let shown = format!("{view:?}");
    assert!(shown.contains(&message.msg_id) && shown.contains("TooManyOperations"));
    assert!(!shown.contains("parked note"), "{shown}");
}

#[tokio::test]
async fn test_parked_forget_of_a_final_entry_keeps_its_message_a_duplicate() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (wide, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let handed = protocol.handed();
    ack_all(&mut app).await;
    assert_eq!(
        app.forget_parked(wide.stored_id, &wide.hash).await.unwrap(),
        1
    );
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert!(app.parked_entry(wide.stored_id).await.unwrap().is_none());
    // So it stays after a reload, and a re-send of the message is a duplicate.
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    assert_eq!(protocol.handed(), handed);
}

#[tokio::test]
async fn test_parked_forget_removes_every_stored_copy_of_the_message() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    // The message stored as refused, then a re-send of it stored for the store's failure.
    let (wide, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    protocol.set(Mode::Rejected);
    let again = resend(&w, &app, &message);
    app.receive(None).await.unwrap();
    protocol.set(Mode::Plain);
    let copy = app.stored_id_at(again).unwrap();
    assert_eq!(
        reasons(&mut app).await,
        vec![
            (wide.stored_id, ParkReason::TooManyOperations),
            (copy, ParkReason::StoreRejected)
        ]
    );
    // An entry of another message stays.
    let (other, _) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    ack_all(&mut app).await;
    let handed = protocol.handed();
    assert_eq!(
        app.forget_parked(wide.stored_id, &wide.hash).await.unwrap(),
        2
    );
    assert_eq!(
        reasons(&mut app).await,
        vec![(other.stored_id, ParkReason::StoreRejected)]
    );
    // Both copies went in the commit: none is left to run after a reload.
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert_eq!(app.stored_id_at(again), None);
    app.receive(None).await.unwrap();
    assert_eq!(protocol.handed(), handed + 1);
}

#[tokio::test]
async fn test_parked_forget_while_a_duty_event_names_it_is_refused() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (wide, _) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    // `EffectRefused` and `Parked` name the entry and aren't acknowledged yet.
    let kept = app.unacknowledged_events().await.unwrap();
    assert!(has(&kept, |e| matches!(
        e,
        AppEvent::EffectRefused { stored_id, .. } if *stored_id == wide.stored_id
    )));
    assert!(usage(app.forget_parked(wide.stored_id, &wide.hash).await));
    assert_eq!(reasons(&mut app).await.len(), 1);
    ack_all(&mut app).await;
    assert_eq!(
        app.forget_parked(wide.stored_id, &wide.hash).await.unwrap(),
        1
    );
}

#[tokio::test]
async fn test_parked_forget_with_another_hash_is_refused() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (wide, _) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let (uncertain, _) = uncertain(&w, &mut app).await;
    ack_all(&mut app).await;
    // Each named with the other's hash.
    assert!(usage(
        app.forget_parked(wide.stored_id, &uncertain.hash).await
    ));
    assert!(usage(
        app.release_parked(uncertain.stored_id, &wide.hash).await
    ));
    assert_eq!(reasons(&mut app).await.len(), 2);
    assert_eq!(listed(&mut app, uncertain.stored_id).await, Some(uncertain));
}

/// The host forgets `entry` once the duty events are acknowledged: it goes alone, and a
/// re-send of `message` is a duplicate.
async fn forgotten(w: &World, app: &mut App, entry: ParkedSummary, message: &Message) {
    ack_all(app).await;
    assert_eq!(
        app.forget_parked(entry.stored_id, &entry.hash)
            .await
            .unwrap(),
        1
    );
    assert!(app.parked_entries().await.unwrap().is_empty(), "{entry:?}");
    assert!(resent_is_duplicate(w, app, message).await, "{entry:?}");
}

#[tokio::test]
async fn test_parked_forget_of_an_entry_stored_for_any_reason() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    // Tried again: a write over the quota.
    let (seq, message) = w.note(app.app_id(), "over the quota");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: pubky_switch_core::http::ErrorCode::QuotaExceeded,
        current: serde_json::json!({}),
    });
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(seq).unwrap();
    let quota = listed(&mut app, id).await.unwrap();
    assert_eq!(quota.reason, ParkReason::Quota);
    forgotten(&w, &mut app, quota, &message).await;
    // Tried again: the protocol's store refused the entry.
    let (rejected, message) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    assert_eq!(rejected.reason, ParkReason::StoreRejected);
    forgotten(&w, &mut app, rejected, &message).await;
    // Tried again: the protocol's store unavailable past the bounded wait.
    protocol.set(Mode::Unavailable);
    let (seq, message) = w.note(app.app_id(), "unavailable");
    app.receive(None).await.unwrap();
    w.clock.advance_ms(World::config().park_after_ms + 1);
    app.receive(None).await.unwrap();
    protocol.set(Mode::Plain);
    let id = app.stored_id_at(seq).unwrap();
    let unavailable = listed(&mut app, id).await.unwrap();
    assert_eq!(unavailable.reason, ParkReason::StoreUnavailable);
    // Stored after the app's checks of its sender passed.
    let view = app
        .parked_entry(unavailable.stored_id)
        .await
        .unwrap()
        .unwrap();
    assert!(view.sender_verified);
    forgotten(&w, &mut app, unavailable, &message).await;
    // Not tried again: an uncertain effect.
    let (uncertain_entry, message) = uncertain(&w, &mut app).await;
    forgotten(&w, &mut app, uncertain_entry, &message).await;
    // Tried again: an uncertain one the host released.
    let (released, message) = uncertain(&w, &mut app).await;
    app.release_parked(released.stored_id, &released.hash)
        .await
        .unwrap();
    let released = listed(&mut app, released.stored_id).await.unwrap();
    assert_eq!(released.reason, ParkReason::Released);
    forgotten(&w, &mut app, released, &message).await;
}

#[tokio::test]
async fn test_parked_forget_of_an_unverifiable_copy_keeps_a_checked_message_processed() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    // The message stored once with its sender checked, its effect over one batch.
    let (wide, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    // A re-send of it stored once more, its sender's standing not checked.
    w.homeserver.set_down(true);
    w.clock.advance_ms(11 * 60_000);
    let again = resend(&w, &app, &message);
    app.receive(None).await.unwrap();
    w.clock.advance_ms(25 * 3_600_000);
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(again).unwrap();
    let unverified = listed(&mut app, id).await.unwrap();
    assert_eq!(unverified.reason, ParkReason::Unverifiable);
    assert_eq!(unverified.hash, wide.hash);
    // Forgetting the unverified copy is being done with the message: both go, and since
    // one of them was checked, the message stays processed.
    ack_all(&mut app).await;
    let handed = protocol.handed();
    assert_eq!(
        app.forget_parked(unverified.stored_id, &unverified.hash)
            .await
            .unwrap(),
        2
    );
    assert!(app.parked_entries().await.unwrap().is_empty());
    w.homeserver.set_down(false);
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    assert_eq!(protocol.handed(), handed);
}

#[tokio::test]
async fn test_parked_forget_of_an_unverifiable_entry_keeps_no_processed_pair() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    w.homeserver.set_down(true);
    let (seq, message) = w.note(app.app_id(), "unverifiable note");
    app.receive(None).await.unwrap();
    w.clock.advance_ms(25 * 3_600_000);
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(seq).unwrap();
    let entry = listed(&mut app, id).await.unwrap();
    assert_eq!(entry.reason, ParkReason::Unverifiable);
    // Its sender wasn't checked: the view says so.
    let view = app.parked_entry(id).await.unwrap().unwrap();
    assert!(!view.sender_verified);
    assert!(format!("{view:?}").contains("sender_verified: false"));
    let handed = protocol.handed();
    assert_eq!(app.forget_parked(id, &entry.hash).await.unwrap(), 1);
    assert!(app.parked_entries().await.unwrap().is_empty());
    // A re-send once the sender can be checked is checked and applied as new.
    w.homeserver.set_down(false);
    w.clock.advance_ms(DAY_MS);
    assert!(!resent_is_duplicate(&w, &mut app, &message).await);
    assert_eq!(protocol.handed(), handed + 1);
}

#[tokio::test]
async fn test_parked_forget_of_a_corrupt_entry_removes_it() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (rejected, _) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    // Its stored plaintext no longer reads.
    let mut stored = app.state.parked.get(&rejected.stored_id).unwrap().clone();
    stored.plaintext = b"not a plaintext".to_vec();
    let mut tx = app.tx().unwrap();
    tx.put(&crate::app::state::key::parked(rejected.stored_id), &stored)
        .unwrap();
    app.commit(tx).await.unwrap();
    app.state.parked.insert(rejected.stored_id, stored);
    let entry = listed(&mut app, rejected.stored_id).await.unwrap();
    assert!(!entry.readable);
    assert_eq!(
        entry.hash,
        pubky_switch_core::message::message_hash(b"not a plaintext")
    );
    assert!(matches!(
        app.parked_entry(rejected.stored_id).await,
        Err(AppError::Store(StoreError::Corrupt))
    ));
    assert!(usage(
        app.forget_parked(rejected.stored_id, &rejected.hash).await
    ));
    assert_eq!(
        app.forget_parked(rejected.stored_id, &entry.hash)
            .await
            .unwrap(),
        1
    );
    assert!(app.parked_entries().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_parked_release_of_an_uncertain_entry_runs_it_once() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, message) = uncertain(&w, &mut app).await;
    let id = entry.stored_id;
    // Before the release, a re-send is a duplicate.
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    let handed = protocol.handed();
    app.release_parked(id, &entry.hash).await.unwrap();
    assert_eq!(reasons(&mut app).await, vec![(id, ParkReason::Released)]);
    // The next read runs it as a fresh receive, once, telling the protocol it was released.
    let report = app.receive(None).await.unwrap();
    assert!(
        has(
            &report.events,
            |e| matches!(e, AppEvent::Unparked { stored_id, .. } if *stored_id == id)
        ),
        "{:?}",
        report.events
    );
    assert_eq!(protocol.handed(), handed + 1);
    assert_eq!(protocol.released().last(), Some(&true));
    assert!(app.parked_entries().await.unwrap().is_empty());
    app.receive(None).await.unwrap();
    assert_eq!(protocol.handed(), handed + 1);
    // After its run, a re-send is a duplicate again, and not a released run.
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    assert_eq!(protocol.handed(), handed + 1);
    assert_eq!(protocol.released().iter().filter(|r| **r).count(), 1);
}

#[tokio::test]
async fn test_parked_release_declined_by_the_protocol_stays_processed() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, message) = uncertain(&w, &mut app).await;
    protocol.set(Mode::DeclineReleased);
    let handed = protocol.handed();
    app.release_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::MessageDropped { check: 10, .. }
    )));
    assert_eq!(protocol.handed(), handed);
    assert!(app.parked_entries().await.unwrap().is_empty());
    // Declined, the message stays processed: a re-send is a duplicate.
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    assert_eq!(protocol.handed(), handed);
}

/// An uncertain entry released, then a re-send of its message that arrives before the
/// released entry's run finishes: its first run can't finish, so the re-send is applied
/// first. Returns the entry's listing and the effects applied.
async fn resent_before_the_released_run(
    w: &World,
    app: &mut App,
    protocol: &ParkingProtocol,
) -> (ParkedSummary, usize) {
    let (entry, message) = uncertain(w, app).await;
    ack_all(app).await;
    protocol.set(Mode::RetryFirstStoredRun);
    let applied = w.effects();
    app.release_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap();
    let again = resend(w, app, &message);
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, again), "{:?}", report.events);
    assert_eq!(w.effects(), applied + 1);
    (entry, applied + 1)
}

#[tokio::test]
async fn test_parked_resend_between_release_and_run_is_applied_once() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (_, applied) = resent_before_the_released_run(&w, &mut app, &protocol).await;
    // The released entry runs next, and is a duplicate: not applied again.
    app.receive(None).await.unwrap();
    assert_eq!(w.effects(), applied, "applied twice");
    assert!(app.parked_entries().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_parked_released_entry_run_as_a_duplicate_keeps_a_duty_event() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, _) = resent_before_the_released_run(&w, &mut app, &protocol).await;
    app.receive(None).await.unwrap();
    // Kept, so the host learns how its release ended after a reload too.
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let kept = app.unacknowledged_events().await.unwrap();
    assert!(
        has(&kept, |e| matches!(
            e,
            AppEvent::ReleasedDuplicate { stored_id, seq, conflicting: false, .. }
                if *stored_id == entry.stored_id && *seq == entry.seq
        )),
        "{kept:?}"
    );
}

#[tokio::test]
async fn test_parked_release_of_another_reason_is_refused() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (wide, _) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let (rejected, _) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    assert!(usage(app.release_parked(wide.stored_id, &wide.hash).await));
    assert!(usage(
        app.release_parked(rejected.stored_id, &rejected.hash).await
    ));
    assert_eq!(
        reasons(&mut app).await,
        vec![
            (wide.stored_id, ParkReason::TooManyOperations),
            (rejected.stored_id, ParkReason::StoreRejected)
        ]
    );
}

#[tokio::test]
async fn test_parked_unknown_id_is_refused() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert!(app.parked_entry(99).await.unwrap().is_none());
    assert!(usage(app.forget_parked(99, &[0; 32]).await));
    assert!(usage(app.release_parked(99, &[0; 32]).await));
}

/// The store's keys for the wallet, to compare before and after a change.
fn snapshot(store: &MemoryStore) -> Vec<(Vec<u8>, Vec<u8>)> {
    let ns = crate::store::client_namespace(&app_keys("wallet").app_id_bytes());
    store.scan(&ns, b"", None, u32::MAX).unwrap()
}

#[tokio::test]
async fn test_parked_forget_crash_is_all_or_nothing() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    ack_all(&mut app).await;
    drop(app);
    let before = snapshot(&w.store);
    // The process stops before the forget's commit: nothing of it happened.
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopBefore(1),
    ));
    let mut app = load_on(&w, &protocol, fault.clone() as Arc<dyn StateStore>).await;
    assert!(
        app.forget_parked(entry.stored_id, &entry.hash)
            .await
            .is_err()
    );
    assert_eq!(fault.commits(), 1);
    assert_eq!(snapshot(&w.store), before);
    // It stops after the commit: all of it happened.
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopAfter(1),
    ));
    let mut app = load_on(&w, &protocol, fault.clone() as Arc<dyn StateStore>).await;
    assert!(
        app.forget_parked(entry.stored_id, &entry.hash)
            .await
            .is_err()
    );
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
}

#[tokio::test]
async fn test_parked_release_crash_is_all_or_nothing() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, _) = uncertain(&w, &mut app).await;
    drop(app);
    let before = snapshot(&w.store);
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopBefore(1),
    ));
    let mut app = load_on(&w, &protocol, fault.clone() as Arc<dyn StateStore>).await;
    assert!(
        app.release_parked(entry.stored_id, &entry.hash)
            .await
            .is_err()
    );
    assert_eq!(fault.commits(), 1);
    assert_eq!(snapshot(&w.store), before);
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopAfter(1),
    ));
    let mut app = load_on(&w, &protocol, fault.clone() as Arc<dyn StateStore>).await;
    assert!(
        app.release_parked(entry.stored_id, &entry.hash)
            .await
            .is_err()
    );
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert_eq!(
        reasons(&mut app).await,
        vec![(entry.stored_id, ParkReason::Released)]
    );
    // The processed pair went in the same commit: the next read runs the entry.
    let handed = protocol.handed();
    app.receive(None).await.unwrap();
    assert_eq!(protocol.handed(), handed + 1);
}

#[tokio::test]
async fn test_parked_forget_while_its_effect_is_kept_is_refused_until_a_read_settles_it() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (entry, _) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    assert_eq!(entry.reason, ParkReason::StoreRejected);
    // Its retry builds the effect, keeps it and sends it: applied, the answer lost.
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    ack_all(&mut app).await;
    let error = app
        .forget_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, AppError::Refused(Refusal::NotNow(why)) if why.contains("kept unanswered")),
        "{error:?}"
    );
    assert_eq!(listed(&mut app, entry.stored_id).await, Some(entry));
    // The next read settles it: the effect applied, the entry is processed and gone.
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::MessageReceived { .. }
        )),
        "{:?}",
        report.events
    );
    assert_eq!(listed(&mut app, entry.stored_id).await, None);
    assert!(usage(app.forget_parked(entry.stored_id, &entry.hash).await));
}

/// Bob's note `message` again under the same `msg_id` with other bytes, signed by an app of
/// his that isn't listed: stored as unverifiable while his Homeserver can't be reached.
async fn forged_copy(w: &World, app: &mut App, message: &Message) -> ParkedSummary {
    let keys = app_keys("removed-app");
    let cert = cert_for(&w.bob, &keys, w.clock.now_ms(), &["scope-a"]);
    let mut forged = message.clone();
    forged.from = pubky_switch_core::message::Sender::of_app(w.bob.public(), &keys);
    forged
        .body
        .insert("text".into(), serde_json::Value::from("forged"));
    let plaintext = forged.sign(&keys).unwrap();
    w.homeserver.set_down(true);
    w.clock.advance_ms(11 * 60_000);
    let seq = w
        .switch
        .send_plaintext(w.bob.public(), &cert, &plaintext, &[app.app_id()])
        .unwrap();
    app.receive(None).await.unwrap();
    w.clock.advance_ms(25 * 3_600_000);
    app.receive(None).await.unwrap();
    w.homeserver.set_down(false);
    let id = app.stored_id_at(seq).unwrap();
    let entry = listed(app, id).await.unwrap();
    assert_eq!(entry.reason, ParkReason::Unverifiable);
    entry
}

async fn processed(app: &App, message: &Message) -> bool {
    let pair = crate::app::state::key::processed(&message.from.identity, &message.msg_id);
    app.reader().exists(&pair).await.unwrap()
}

#[tokio::test]
async fn test_parked_forget_of_a_forgery_keeps_the_genuine_copy() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    // The genuine message, checked and stored for good; a forgery under its `msg_id`.
    let (genuine, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let forgery = forged_copy(&w, &mut app, &message).await;
    assert_ne!(forgery.hash, genuine.hash);
    ack_all(&mut app).await;
    // Forgetting the forgery takes it alone, and leaves the message unprocessed.
    assert_eq!(
        app.forget_parked(forgery.stored_id, &forgery.hash)
            .await
            .unwrap(),
        1
    );
    assert_eq!(listed(&mut app, genuine.stored_id).await, Some(genuine));
    assert!(!processed(&app, &message).await);
}

#[tokio::test]
async fn test_parked_forget_of_a_genuine_copy_takes_a_forgery_under_its_msg_id() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (genuine, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let forgery = forged_copy(&w, &mut app, &message).await;
    ack_all(&mut app).await;
    // Forgetting the checked copy is being done with its message, as the processed pairs
    // name it: the forgery under its `msg_id` goes too, and the message stays processed.
    assert_eq!(
        app.forget_parked(genuine.stored_id, &genuine.hash)
            .await
            .unwrap(),
        2
    );
    assert!(listed(&mut app, forgery.stored_id).await.is_none());
    assert!(processed(&app, &message).await);
}

/// An uncertain entry the host released, whose released run is stored again for `again`:
/// a quota the switch answers, a store that refuses the entry's state, or a sender that
/// can't be checked. Returns its listing.
async fn released_then_stored(
    w: &World,
    app: &mut App,
    protocol: &ParkingProtocol,
    again: ParkReason,
) -> ParkedSummary {
    let (entry, _) = uncertain(w, app).await;
    app.release_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap();
    match again {
        ParkReason::Quota => w.switch.fail_next(Fault::Error {
            path: "ops".into(),
            code: pubky_switch_core::http::ErrorCode::QuotaExceeded,
            current: serde_json::json!({}),
        }),
        ParkReason::StoreRejected => protocol.set(Mode::Rejected),
        ParkReason::Unverifiable => w.homeserver.set_down(true),
        _ => unreachable!(),
    }
    let _ = app.receive(None).await;
    protocol.set(Mode::Plain);
    w.homeserver.set_down(false);
    // A quota stores it again for its own reason; a store that refuses its state, or a
    // sender that can't be checked, leaves it stored as released, tried again.
    let stored = match again {
        ParkReason::Quota => ParkReason::Quota,
        _ => ParkReason::Released,
    };
    assert_eq!(reasons(app).await, vec![(entry.stored_id, stored)]);
    entry
}

/// The next run of `entry` is handed over as released: a protocol that declines released
/// runs drops it, and its effect isn't applied again.
async fn next_run_is_released(
    w: &World,
    app: &mut App,
    protocol: &ParkingProtocol,
    entry: &ParkedSummary,
) {
    protocol.set(Mode::DeclineReleased);
    let effects = w.effects();
    app.receive(None).await.unwrap();
    assert_eq!(protocol.released().last(), Some(&true));
    assert_eq!(w.effects(), effects);
    assert!(listed(app, entry.stored_id).await.is_none());
}

#[tokio::test]
async fn test_parked_release_survives_a_quota() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let entry = released_then_stored(&w, &mut app, &protocol, ParkReason::Quota).await;
    next_run_is_released(&w, &mut app, &protocol, &entry).await;
}

#[tokio::test]
async fn test_parked_release_survives_a_store_that_refuses() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let entry = released_then_stored(&w, &mut app, &protocol, ParkReason::StoreRejected).await;
    next_run_is_released(&w, &mut app, &protocol, &entry).await;
}

#[tokio::test]
async fn test_parked_release_survives_an_unverifiable_sender() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let entry = released_then_stored(&w, &mut app, &protocol, ParkReason::Unverifiable).await;
    next_run_is_released(&w, &mut app, &protocol, &entry).await;
}

#[tokio::test]
async fn test_parked_release_survives_a_backup_and_restore() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let entry = released_then_stored(&w, &mut app, &protocol, ParkReason::Quota).await;
    let backup = app.backup_layered().await.unwrap();
    drop(app);
    let restored_protocol = ParkingProtocol::new(Mode::Plain);
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        restored_protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert!(listed(&mut restored, entry.stored_id).await.is_some());
    next_run_is_released(&w, &mut restored, &restored_protocol, &entry).await;
}

#[tokio::test]
async fn test_parked_release_by_an_earlier_build_still_reads_as_released() {
    // An entry an earlier build stored as released, without the `released` field: its next
    // run is still handed over as released.
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let store = Arc::clone(&w.store) as Arc<dyn StateStore>;
    let mut app = wallet_on(&w, &protocol, Arc::clone(&store)).await;
    let (entry, _) = uncertain(&w, &mut app).await;
    app.release_parked(entry.stored_id, &entry.hash)
        .await
        .unwrap();
    let mut stored = app.state.parked.get(&entry.stored_id).cloned().unwrap();
    assert_eq!(stored.reason, ParkReason::Released);
    stored.released = false;
    let mut tx = app.tx().unwrap();
    tx.put(&crate::app::state::key::parked(entry.stored_id), &stored)
        .unwrap();
    app.commit(tx).await.unwrap();
    drop(app);
    let mut app = load_on(&w, &protocol, store).await;
    next_run_is_released(&w, &mut app, &protocol, &entry).await;
}
