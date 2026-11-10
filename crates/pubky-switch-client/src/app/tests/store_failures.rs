//! A protocol whose store or host fails: a receive step that can't finish for now
//! ([`Outcome::Retry`]) leaves its entry unprocessed until a later read (Switch spec 8.2).

use std::sync::Mutex;

use super::*;
use crate::app::{AppError, AppEvent, Peeked, RETRY_EVENT_READS, ReceiveContext, StoreFailure};
use crate::error::StoreError;

/// [`SampleProtocol`], whose receive step fails for want of its store while `fails` is
/// above zero for a note whose text is [`FLAKY`]: it adds a record write and a local write
/// through the context first, which must never be committed.
struct FlakyProtocol {
    sample: SampleProtocol,
    fails: Mutex<u32>,
    calls: Mutex<u32>,
}

/// The text of a note whose receive step fails while the store does.
const FLAKY: &str = "flaky";

/// The local key the failed step writes through the context.
const FAILED_STEP: &[u8] = b"failed-step";

impl FlakyProtocol {
    fn new(fails: u32) -> Arc<Self> {
        Arc::new(Self {
            sample: SampleProtocol::default(),
            fails: Mutex::new(fails),
            calls: Mutex::new(0),
        })
    }

    fn heal(&self) {
        *self.fails.lock().unwrap() = 0;
    }

    fn calls(&self) -> u32 {
        *self.calls.lock().unwrap()
    }

    /// How many notes were applied.
    fn applied(&self) -> usize {
        self.sample.received.lock().unwrap().len()
    }
}

impl Protocol for FlakyProtocol {
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
        *self.calls.lock().unwrap() += 1;
        let flaky = message.message.body.get("text").and_then(Value::as_str) == Some(FLAKY);
        let mut fails = self.fails.lock().unwrap();
        if flaky && *fails > 0 {
            *fails -= 1;
            cx.op(
                Vec::new(),
                OpKind::AllowPut {
                    pubky: message.sender,
                    kind: AllowKind::Conversation,
                },
            )
            .unwrap();
            cx.local(LocalWrite::Put {
                key: FAILED_STEP.to_vec(),
                value: b"1".to_vec(),
            });
            // A read of the protocol's own state, its store unavailable: the error that
            // read gives is a store failure, so the step is retried.
            let read = AppError::Store(StoreError::Unavailable);
            return match StoreFailure::try_from(read) {
                Ok(failure) => Outcome::Retry(failure),
                Err(error) => Outcome::Drop {
                    reason: error.to_string(),
                },
            };
        }
        drop(fails);
        self.sample.receive(message)
    }

    fn resend_needed(&self, needed: &ResendNeeded) -> Vec<LocalWrite> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Vec<LocalWrite> {
        self.sample.missed(missed)
    }
}

async fn join_flaky(w: &World, protocol: &Arc<FlakyProtocol>, name: &str) -> App {
    let request = w.approve(&app_keys(name), &["scope-a"]);
    App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap()
}

async fn load_flaky(w: &World, protocol: &Arc<FlakyProtocol>, app: [u8; 16]) -> App {
    App::load(w.env(), protocol.clone(), World::config(), app)
        .await
        .unwrap()
}

fn store_failing(events: &[AppEvent]) -> Vec<(u64, u32)> {
    events
        .iter()
        .filter_map(|e| match e {
            AppEvent::StoreFailing { seq, reads, .. } => Some((*seq, *reads)),
            _ => None,
        })
        .collect()
}

/// The note's text the protocol stored locally once it was applied.
async fn note_kept(app: &App, message: &Message) -> Option<Vec<u8>> {
    app.protocol_get(format!("notes/{}", message.msg_id).as_bytes())
        .await
        .unwrap()
}

#[tokio::test]
async fn test_receive_retry_keeps_the_entry_and_applies_it_at_the_next_read() {
    let w = World::new();
    let protocol = FlakyProtocol::new(1);
    let mut app = join_flaky(&w, &protocol, "wallet").await;
    let (seq, message) = w.note(app.app_id(), FLAKY);
    let report = app.receive(None).await.unwrap();
    assert_eq!(protocol.calls(), 1, "one try in the read, no loop");
    // Not processed: no event of it, the cursor before it, here and at the service.
    assert!(!report.events.iter().any(|e| matches!(
        e,
        AppEvent::MessageReceived { .. } | AppEvent::MessageDropped { .. }
    )));
    assert!(store_failing(&report.events).is_empty(), "below the bound");
    assert!(report.cursor.seq < seq);
    app.flush_cursor().await.unwrap();
    assert!(w.switch.app(&app.app_id()).cursor < seq);
    // Nothing of the failed step committed: no operation, no local write, no note.
    assert_eq!(w.effects(), 0);
    assert_eq!(app.protocol_get(FAILED_STEP).await.unwrap(), None);
    assert_eq!(note_kept(&app, &message).await, None);
    assert_eq!(app.state.retries.get(&seq).map(|r| r.reads), Some(1));
    // A peek still shows it: it runs no receive step.
    let peeked = app.peek().await.unwrap();
    assert!(
        peeked
            .items
            .iter()
            .any(|p| matches!(p, Peeked::Show { seq: s, .. } if *s == seq))
    );

    // The next read gives it again, and it applies once, with the cursor.
    let report = app.receive(None).await.unwrap();
    assert_eq!(protocol.calls(), 2);
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::MessageReceived { seq: s, .. } if *s == seq))
    );
    assert_eq!(report.cursor.seq, seq);
    assert_eq!(w.switch.app(&app.app_id()).cursor, seq);
    assert_eq!(w.effects(), 1);
    assert_eq!(protocol.applied(), 1);
    assert_eq!(
        note_kept(&app, &message).await,
        Some(FLAKY.as_bytes().to_vec())
    );
    assert_eq!(app.protocol_get(FAILED_STEP).await.unwrap(), None);
    assert!(
        app.state.retries.is_empty(),
        "the count goes with the entry"
    );
    // Reloaded from the store: nothing of the retry is left.
    let app = load_flaky(&w, &protocol, app.app_id()).await;
    assert!(app.state.retries.is_empty());
}

#[tokio::test]
async fn test_receive_retry_later_entries_go_on_and_the_cursor_stays_before_it() {
    let w = World::new();
    let protocol = FlakyProtocol::new(1);
    let mut app = join_flaky(&w, &protocol, "wallet").await;
    let (first, _) = w.note(app.app_id(), FLAKY);
    let (second, _) = w.note(app.app_id(), "steady");
    let report = app.receive(None).await.unwrap();
    // The later note is applied past it; the cursor stays before the unprocessed one.
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::MessageReceived { seq: s, .. } if *s == second))
    );
    assert_eq!(w.effects(), 1);
    assert!(report.cursor.seq < first);
    app.flush_cursor().await.unwrap();
    assert!(w.switch.app(&app.app_id()).cursor < first);
    // The next read applies the first, and passes both without applying the second again.
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::MessageReceived { seq: s, .. } if *s == first))
    );
    assert!(report.cursor.seq >= second, "past both");
    assert_eq!(w.effects(), 2);
    assert_eq!(protocol.applied(), 2);
}

#[tokio::test]
async fn test_receive_retry_repeated_raises_store_failing_and_keeps_the_entry() {
    let w = World::new();
    let protocol = FlakyProtocol::new(u32::MAX);
    let mut app = join_flaky(&w, &protocol, "wallet").await;
    let (seq, _) = w.note(app.app_id(), FLAKY);
    for read in 1..RETRY_EVENT_READS {
        let report = app.receive(None).await.unwrap();
        assert!(store_failing(&report.events).is_empty(), "read {read}");
    }
    let report = app.receive(None).await.unwrap();
    assert_eq!(
        store_failing(&report.events),
        vec![(seq, RETRY_EVENT_READS)]
    );
    let Some(AppEvent::StoreFailing { failure, .. }) = report
        .events
        .iter()
        .find(|e| matches!(e, AppEvent::StoreFailing { .. }))
    else {
        panic!("no event: {:?}", report.events)
    };
    assert_eq!(failure.error(), &StoreError::Unavailable);
    // Still unprocessed: never stored and passed, the inbox keeps it.
    assert!(report.cursor.seq < seq);
    assert!(app.state.parked.is_empty());
    app.flush_cursor().await.unwrap();
    assert!(w.switch.app(&app.app_id()).cursor < seq);
    assert_eq!(w.effects(), 0);

    // The count is kept in the store: an app loaded again counts on, and raises it again.
    let mut app = load_flaky(&w, &protocol, app.app_id()).await;
    let report = app.receive(None).await.unwrap();
    assert_eq!(
        store_failing(&report.events),
        vec![(seq, RETRY_EVENT_READS + 1)]
    );
    // Once the store works, the entry applies and the count goes.
    protocol.heal();
    let report = app.receive(None).await.unwrap();
    assert!(store_failing(&report.events).is_empty());
    assert_eq!(report.cursor.seq, seq);
    assert_eq!(w.effects(), 1);
    assert!(app.state.retries.is_empty());
}

#[test]
fn test_store_failure_is_built_only_from_a_store_error() {
    let failure = StoreFailure::try_from(AppError::Store(StoreError::Full)).unwrap();
    assert_eq!(failure.error(), &StoreError::Full);
    // Any other error isn't a store failure, and is given back.
    let other = AppError::InvalidData("a body".into());
    assert_eq!(StoreFailure::try_from(other.clone()).unwrap_err(), other);
}
