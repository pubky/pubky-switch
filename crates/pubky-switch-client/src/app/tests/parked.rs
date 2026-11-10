//! What a host sees and settles of the entries stored locally (Switch spec 8.2): listing
//! and viewing them, forgetting one that isn't tried again, and releasing one whose effect
//! was uncertain to be tried once more; each change in one commit.

use std::sync::{Arc, Mutex};

use pubky_switch_core::message::Message;
use pubky_switch_core::ops::OpKind;
use pubky_switch_core::records::DAY_MS;

use super::moves::has;
use super::*;
use crate::app::{AppError, AppEvent, ParkReason, Refusal, StoreFailure};
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
}

/// The sample protocol, whose receive step follows [`Mode`].
struct ParkingProtocol {
    sample: SampleProtocol,
    mode: Mutex<Mode>,
}

impl ParkingProtocol {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            sample: SampleProtocol::default(),
            mode: Mutex::new(mode),
        })
    }

    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }

    /// How many times a note was handed over.
    fn handed(&self) -> usize {
        self.sample.received.lock().unwrap().len()
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
        }
    }

    fn resend_needed(&self, needed: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
        self.sample.missed(missed)
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

/// A note from bob stored as `mode` makes it. Returns its `seq` and message.
async fn parked_as(
    w: &World,
    app: &mut App,
    protocol: &ParkingProtocol,
    mode: Mode,
) -> (u64, Message) {
    protocol.set(mode);
    let (seq, message) = w.note(app.app_id(), "parked note");
    app.receive(None).await.unwrap();
    protocol.set(Mode::Plain);
    (seq, message)
}

/// A note whose effect was applied but whose answer was lost, kept past the window in
/// which a resend tells: stored as uncertain. Returns its `seq` and message.
async fn uncertain(w: &World, app: &mut App) -> (u64, Message) {
    let (seq, message) = w.note(app.app_id(), "uncertain note");
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    w.clock.advance_ms(31 * DAY_MS);
    w.switch.lock().batches.clear();
    app.receive(None).await.unwrap();
    assert_eq!(
        app.parked_entries().await.unwrap(),
        vec![(seq, ParkReason::Uncertain)]
    );
    (seq, message)
}

/// Bob sends `message` again; returns whether the read took it as a duplicate.
async fn resent_is_duplicate(w: &World, app: &mut App, message: &Message) -> bool {
    let plaintext = message.sign(&w.bob_keys).unwrap();
    let again = w
        .switch
        .send_plaintext(w.bob.public(), &w.bob_cert, &plaintext, &[app.app_id()])
        .unwrap();
    let report = app.receive(None).await.unwrap();
    has(
        &report.events,
        |e| matches!(e, AppEvent::Duplicate { seq, conflicting: false } if *seq == again),
    )
}

fn usage(result: Result<(), AppError>) -> bool {
    matches!(result, Err(AppError::Refused(Refusal::Usage(_))))
}

#[tokio::test]
async fn test_parked_entries_are_listed_and_viewed_in_seq_order() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (wide, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let (rejected, _) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    assert!(wide < rejected);
    assert_eq!(
        app.parked_entries().await.unwrap(),
        vec![
            (wide, ParkReason::TooManyOperations),
            (rejected, ParkReason::StoreRejected)
        ]
    );
    let view = app.parked_entry(wide).await.unwrap().unwrap();
    assert_eq!(view.seq, wide);
    assert_eq!(view.sender, w.bob.public());
    assert_eq!(view.reason, ParkReason::TooManyOperations);
    let read = view.message.clone().unwrap();
    assert_eq!(read.msg_id, message.msg_id);
    assert_eq!(read.kind, "sample.note");
    assert_eq!(
        view.plaintext.hash(),
        message.sign(&w.bob_keys).unwrap().hash()
    );
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
    let (seq, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let handed = protocol.handed();
    app.forget_parked(seq).await.unwrap();
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert!(app.parked_entry(seq).await.unwrap().is_none());
    // So it stays after a reload, and a re-send of the message is a duplicate.
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    assert_eq!(protocol.handed(), handed);
}

#[tokio::test]
async fn test_parked_forget_of_an_entry_tried_again_is_refused() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    protocol.set(Mode::Rejected);
    let (seq, _) = w.note(app.app_id(), "parked note");
    app.receive(None).await.unwrap();
    assert!(usage(app.forget_parked(seq).await));
    assert_eq!(
        app.parked_entries().await.unwrap(),
        vec![(seq, ParkReason::StoreRejected)]
    );
}

#[tokio::test]
async fn test_parked_release_of_an_uncertain_entry_runs_it_once() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (seq, message) = uncertain(&w, &mut app).await;
    // Before the release, a re-send is a duplicate.
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    let handed = protocol.handed();
    app.release_parked(seq).await.unwrap();
    assert_eq!(
        app.parked_entries().await.unwrap(),
        vec![(seq, ParkReason::Released)]
    );
    // The next read runs it as a fresh receive, once.
    let report = app.receive(None).await.unwrap();
    assert!(
        has(
            &report.events,
            |e| matches!(e, AppEvent::Unparked { seq: s } if *s == seq)
        ),
        "{:?}",
        report.events
    );
    assert_eq!(protocol.handed(), handed + 1);
    assert!(app.parked_entries().await.unwrap().is_empty());
    app.receive(None).await.unwrap();
    assert_eq!(protocol.handed(), handed + 1);
    // After its run, a re-send is a duplicate again.
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
    assert_eq!(protocol.handed(), handed + 1);
}

#[tokio::test]
async fn test_parked_release_of_another_reason_is_refused() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (wide, _) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    let (rejected, _) = parked_as(&w, &mut app, &protocol, Mode::Rejected).await;
    assert!(usage(app.release_parked(wide).await));
    assert!(usage(app.release_parked(rejected).await));
    assert_eq!(
        app.parked_entries().await.unwrap(),
        vec![
            (wide, ParkReason::TooManyOperations),
            (rejected, ParkReason::StoreRejected)
        ]
    );
}

#[tokio::test]
async fn test_parked_unknown_seq_is_refused() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert!(app.parked_entry(99).await.unwrap().is_none());
    assert!(usage(app.forget_parked(99).await));
    assert!(usage(app.release_parked(99).await));
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
    let (seq, message) = parked_as(&w, &mut app, &protocol, Mode::Wide).await;
    drop(app);
    let before = snapshot(&w.store);
    // The process stops before the forget's commit: nothing of it happened.
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopBefore(1),
    ));
    let mut app = load_on(&w, &protocol, fault.clone() as Arc<dyn StateStore>).await;
    assert!(app.forget_parked(seq).await.is_err());
    assert_eq!(fault.commits(), 1);
    assert_eq!(snapshot(&w.store), before);
    // It stops after the commit: all of it happened.
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopAfter(1),
    ));
    let mut app = load_on(&w, &protocol, fault.clone() as Arc<dyn StateStore>).await;
    assert!(app.forget_parked(seq).await.is_err());
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert!(app.parked_entries().await.unwrap().is_empty());
    assert!(resent_is_duplicate(&w, &mut app, &message).await);
}

#[tokio::test]
async fn test_parked_release_crash_is_all_or_nothing() {
    let w = World::new();
    let protocol = ParkingProtocol::new(Mode::Plain);
    let mut app = wallet_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    let (seq, _) = uncertain(&w, &mut app).await;
    drop(app);
    let before = snapshot(&w.store);
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopBefore(1),
    ));
    let mut app = load_on(&w, &protocol, fault.clone() as Arc<dyn StateStore>).await;
    assert!(app.release_parked(seq).await.is_err());
    assert_eq!(fault.commits(), 1);
    assert_eq!(snapshot(&w.store), before);
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopAfter(1),
    ));
    let mut app = load_on(&w, &protocol, fault.clone() as Arc<dyn StateStore>).await;
    assert!(app.release_parked(seq).await.is_err());
    let mut app = load_on(&w, &protocol, Arc::clone(&w.store) as Arc<dyn StateStore>).await;
    assert_eq!(
        app.parked_entries().await.unwrap(),
        vec![(seq, ParkReason::Released)]
    );
    // The processed pair went in the same commit: the next read runs the entry.
    let handed = protocol.handed();
    app.receive(None).await.unwrap();
    assert_eq!(protocol.handed(), handed + 1);
}
