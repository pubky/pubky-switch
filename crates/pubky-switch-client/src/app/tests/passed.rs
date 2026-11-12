//! A protocol's [`Outcome::Pass`]: an entry passed, not processed. The cursor moves past
//! it, no processed pair is kept, so a re-send of the same message is delivered again
//! (Switch spec 11); nothing is stored locally and no duty event is kept, and an entry
//! stored locally stays stored.

use std::sync::Mutex;

use super::moves::has;
use super::*;
use crate::app::state::key;
use crate::app::{AppEvent, ReceiveContext};
use pubky_switch_core::records::AppCert;

/// The text of a note the protocol passes while it is passing.
const PASS: &str = "pass";

/// [`SampleProtocol`], passing every note whose text is [`PASS`] while `passing` holds, and
/// counting the receive steps it runs for each `msg_id`.
#[derive(Default)]
struct PassProtocol {
    sample: SampleProtocol,
    passing: Mutex<bool>,
    calls: Mutex<Vec<String>>,
}

impl PassProtocol {
    fn passing(passing: bool) -> Arc<Self> {
        Arc::new(Self {
            passing: Mutex::new(passing),
            ..Self::default()
        })
    }

    fn set_passing(&self, passing: bool) {
        *self.passing.lock().unwrap() = passing;
    }

    fn calls(&self, msg_id: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|id| *id == msg_id)
            .count()
    }
}

impl Protocol for PassProtocol {
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

    fn receive_with(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        self.calls
            .lock()
            .unwrap()
            .push(message.message.msg_id.clone());
        let text = message.message.body.get("text").and_then(Value::as_str);
        if text == Some(PASS) && *self.passing.lock().unwrap() {
            // What the context added goes with the pass.
            cx.local(LocalWrite::Put {
                key: b"passed".to_vec(),
                value: b"1".to_vec(),
            })
            .unwrap();
            return Outcome::Pass;
        }
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
}

async fn join_with(w: &World, protocol: &Arc<PassProtocol>) -> App {
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap()
}

/// A re-send of `message` from bob, the same signed plaintext. Returns its `seq`.
fn resend(w: &World, message: &Message, to: [u8; 16]) -> u64 {
    let plaintext = message.sign(&w.bob_keys).unwrap();
    w.switch
        .send_plaintext(w.bob.public(), &w.bob_cert, &plaintext, &[to])
        .unwrap()
}

fn received(events: &[AppEvent], seq: u64) -> bool {
    has(
        events,
        |e| matches!(e, AppEvent::MessageReceived { seq: s, .. } if *s == seq),
    )
}

fn duplicate(events: &[AppEvent]) -> bool {
    has(events, |e| matches!(e, AppEvent::Duplicate { .. }))
}

/// A passed entry: the cursor moves past it, here and at the switch, and no processed pair
/// is kept, so a re-send of it, and a second copy in one read, come to the protocol again
/// as new entries, not as duplicates.
#[tokio::test]
async fn test_pass_resend_is_delivered_again_not_as_a_duplicate() {
    let w = World::new();
    let protocol = PassProtocol::passing(true);
    let mut app = join_with(&w, &protocol).await;
    let me = app.app_id();
    let (seq, message) = w.note(me, PASS);
    let copy = resend(&w, &message, me);
    let report = app.receive(None).await.unwrap();
    assert_eq!(protocol.calls(&message.msg_id), 2, "both copies asked");
    assert!(!received(&report.events, seq));
    assert!(!duplicate(&report.events), "{:?}", report.events);
    assert!(app.cursor().seq >= copy);
    // The deferred cursor move goes to the switch.
    app.flush_cursor().await.unwrap();
    assert!(w.switch.app(&me).cursor >= copy);
    let processed = key::processed(&w.bob.public(), &message.msg_id);
    assert!(!app.reader().exists(&processed).await.unwrap());
    // The protocol takes it now: a re-send is delivered and applied, once.
    protocol.set_passing(false);
    let again = resend(&w, &message, me);
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, again), "{:?}", report.events);
    assert!(!duplicate(&report.events));
    assert_eq!(protocol.calls(&message.msg_id), 3);
    assert_eq!(w.effects(), 1);
    assert!(app.reader().exists(&processed).await.unwrap());
}

/// A pass writes nothing: no entry stored locally, no duty event, no count of retries, no
/// processed pair, and nothing the context added. Other messages' processed pairs, and
/// their retention, are as they were.
#[tokio::test]
async fn test_pass_stores_nothing_and_leaves_retention_alone() {
    let w = World::new();
    let protocol = PassProtocol::passing(true);
    let mut app = join_with(&w, &protocol).await;
    let me = app.app_id();
    w.note(me, "kept");
    app.receive(None).await.unwrap();
    let count = |app: &App, prefix: &'static str| {
        let reader = app.reader();
        async move { reader.scan_raw(prefix).await.unwrap().len() }
    };
    let pairs = count(&app, "proc").await;
    let local = count(&app, "p/").await;
    assert!(pairs > 0);
    let (seq, _) = w.note(me, PASS);
    let report = app.receive(None).await.unwrap();
    assert!(app.cursor().seq >= seq);
    assert!(app.stored_seqs().is_empty());
    assert!(!has(&report.events, |e| matches!(
        e,
        AppEvent::Parked { .. }
    )));
    assert!(app.unacknowledged_events().await.unwrap().is_empty());
    assert!(app.no_retries());
    assert_eq!(count(&app, "proc").await, pairs);
    assert_eq!(count(&app, "p/").await, local);
    // The pair kept for the other message ages out when it would have.
    w.clock.advance_ms(crate::app::PROCESSED_RETENTION_MS + 1);
    app.receive(None).await.unwrap();
    assert_eq!(count(&app, "proc").await, 0);
}

/// An entry stored locally that the protocol passes when it is tried again stays stored as
/// it was, under its local ID, with no event; it is applied once the protocol takes it.
#[tokio::test]
async fn test_pass_of_a_stored_entry_leaves_it_stored() {
    let w = World::new();
    let protocol = PassProtocol::passing(true);
    let mut app = join_with(&w, &protocol).await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    // Stored as unverifiable: bob's document can't be read past the bounded wait.
    w.homeserver.set_down(true);
    let (seq, message) = w.note(me, PASS);
    app.receive(None).await.unwrap();
    w.clock.advance_ms(World::config().park_after_ms);
    app.receive(None).await.unwrap();
    let id = app.stored_id_at(seq).expect("stored");
    w.homeserver.set_down(false);
    let report = app.receive(None).await.unwrap();
    assert_eq!(protocol.calls(&message.msg_id), 1);
    assert_eq!(app.stored_id_at(seq), Some(id));
    assert!(!has(&report.events, |e| matches!(
        e,
        AppEvent::Unparked { .. }
    )));
    assert!(app.unacknowledged_events().await.unwrap().is_empty());
    protocol.set_passing(false);
    let report = app.receive(None).await.unwrap();
    assert_eq!(app.stored_id_at(seq), None);
    assert!(has(
        &report.events,
        |e| matches!(e, AppEvent::Unparked { seq: s, .. } if *s == seq)
    ));
    assert_eq!(w.effects(), 1);
}

/// A message applied before is a duplicate before its receive step: a protocol that would
/// pass it now isn't asked, so a pass can't make the app forget a message it applied.
#[tokio::test]
async fn test_pass_isnt_asked_of_an_applied_message() {
    let w = World::new();
    let protocol = PassProtocol::passing(false);
    let mut app = join_with(&w, &protocol).await;
    let me = app.app_id();
    let (_, message) = w.note(me, PASS);
    app.receive(None).await.unwrap();
    assert_eq!(w.effects(), 1);
    protocol.set_passing(true);
    let again = resend(&w, &message, me);
    let report = app.receive(None).await.unwrap();
    assert!(has(
        &report.events,
        |e| matches!(e, AppEvent::Duplicate { seq, .. } if *seq == again)
    ));
    assert_eq!(protocol.calls(&message.msg_id), 1);
    let processed = key::processed(&w.bob.public(), &message.msg_id);
    assert!(app.reader().exists(&processed).await.unwrap());
    assert_eq!(w.effects(), 1);
}
