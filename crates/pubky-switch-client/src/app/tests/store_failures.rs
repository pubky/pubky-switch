//! A protocol whose store or host fails: a receive step that can't finish for now
//! ([`Outcome::Retry`]) leaves its entry unprocessed until a later read (Switch spec 8.2),
//! and a restore installs the protocol's backup layer with the app's state, in one commit,
//! or neither (Switch spec 12.4). A receive step reads its own local state as the earlier
//! entries of the same read left it, before they are committed.

use std::sync::Mutex;

use super::*;
use crate::app::{
    AppBackup, AppError, AppEvent, Need, ParkReason, Peeked, ProtocolLayer, RETRY_EVENT_READS,
    ReceiveContext, StoreFailure,
};
use crate::error::StoreError;
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::Fault;
use pubky_switch_core::http::ErrorCode;

/// When [`FlakyProtocol`]'s receive step fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// At its first call for the entry.
    Plain,
    /// After it asked for a claim ([`Need::Claim`]) and was given it.
    AfterNeed,
    /// When it builds the effect again after a `409 conflict`.
    AfterConflict,
}

/// The input of the claim [`Mode::AfterNeed`] asks for.
const OBLIGATION: &[u8] = b"sample obligation";

/// [`SampleProtocol`], whose receive step fails with `error` while `fails` is above zero, for
/// a note whose text is [`FLAKY`], at the point `mode` names: it adds a record write and a
/// local write through the context first, which must never be committed.
struct FlakyProtocol {
    sample: SampleProtocol,
    fails: Mutex<u32>,
    calls: Mutex<u32>,
    error: StoreError,
    mode: Mode,
}

/// The text of a note whose receive step fails while the store does.
const FLAKY: &str = "flaky";

/// The local key the failed step writes through the context.
const FAILED_STEP: &[u8] = b"failed-step";

impl FlakyProtocol {
    fn new(fails: u32) -> Arc<Self> {
        Self::failing(fails, StoreError::Unavailable, Mode::Plain)
    }

    fn failing(fails: u32, error: StoreError, mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            sample: SampleProtocol::default(),
            fails: Mutex::new(fails),
            calls: Mutex::new(0),
            error,
            mode,
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
        if flaky && self.mode == Mode::AfterNeed {
            let claim_key = cx.blind(OBLIGATION);
            if cx.switch_claim(&claim_key).is_none() {
                return Outcome::Need(vec![Need::Claim(claim_key)]);
            }
        }
        let at_point = match self.mode {
            Mode::Plain | Mode::AfterNeed => true,
            Mode::AfterConflict => message.conflict.is_some(),
        };
        let mut fails = self.fails.lock().unwrap();
        if flaky && at_point && *fails > 0 {
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
            // A read of the protocol's own state whose store failed: the error that read
            // gives is a store failure, so the step is retried.
            let read = AppError::Store(self.error.clone());
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

    fn backup_name(&self) -> Option<String> {
        Some(JOURNAL.into())
    }

    fn restore_layer(&self, layer: Option<&ProtocolLayer>) -> Result<Vec<LocalWrite>, String> {
        Ok(layer
            .map(|layer| LocalWrite::Put {
                key: JOURNAL_KEY.to_vec(),
                value: layer.data.clone(),
            })
            .into_iter()
            .collect())
    }

    fn resend_needed(&self, needed: &ResendNeeded) -> Vec<LocalWrite> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Vec<LocalWrite> {
        self.sample.missed(missed)
    }
}

/// The bounded wait of the tests' apps.
const PARK_AFTER_MS: u64 = 60_000;

fn flaky_config() -> AppConfig {
    AppConfig {
        park_after_ms: PARK_AFTER_MS,
        ..World::config()
    }
}

async fn join_flaky(w: &World, protocol: &Arc<FlakyProtocol>, name: &str) -> App {
    let request = w.approve(&app_keys(name), &["scope-a"]);
    App::join(w.env(), protocol.clone(), flaky_config(), request)
        .await
        .unwrap()
}

async fn load_flaky(w: &World, protocol: &Arc<FlakyProtocol>, app: [u8; 16]) -> App {
    App::load(w.env(), protocol.clone(), flaky_config(), app)
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
    assert!(!failure.is_of_entry(), "a full store frees");
    // A corrupt value fails for the entry every time.
    let corrupt = StoreFailure::try_from(AppError::Store(StoreError::Corrupt)).unwrap();
    assert!(corrupt.is_of_entry());
    assert!(StoreFailure::of_entry(StoreError::Other("refused".into())).is_of_entry());
    // Any other error isn't a store failure, and is given back.
    let other = AppError::InvalidData("a body".into());
    assert_eq!(StoreFailure::try_from(other.clone()).unwrap_err(), other);
}

#[tokio::test]
async fn test_receive_retry_after_a_need_commits_nothing_and_applies_later() {
    let w = World::new();
    let protocol = FlakyProtocol::failing(1, StoreError::Unavailable, Mode::AfterNeed);
    let mut app = join_flaky(&w, &protocol, "wallet").await;
    let (seq, message) = w.note(app.app_id(), FLAKY);
    let report = app.receive(None).await.unwrap();
    // Asked for the claim, given it, then retried.
    assert_eq!(protocol.calls(), 2);
    assert!(report.cursor.seq < seq);
    assert_eq!(w.effects(), 0);
    assert_eq!(app.protocol_get(FAILED_STEP).await.unwrap(), None);
    assert_eq!(app.state.retries.get(&seq).map(|r| r.reads), Some(1));
    // The next read asks again, and applies.
    let report = app.receive(None).await.unwrap();
    assert_eq!(protocol.calls(), 4);
    assert!(report.cursor.seq >= seq);
    assert_eq!(w.effects(), 1);
    assert_eq!(
        note_kept(&app, &message).await,
        Some(FLAKY.as_bytes().to_vec())
    );
}

#[tokio::test]
async fn test_receive_retry_after_a_conflict_commits_nothing_and_applies_later() {
    let w = World::new();
    let protocol = FlakyProtocol::failing(1, StoreError::Unavailable, Mode::AfterConflict);
    let mut app = join_flaky(&w, &protocol, "wallet").await;
    let (seq, message) = w.note(app.app_id(), FLAKY);
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!({ "record": null }),
    });
    let report = app.receive(None).await.unwrap();
    // Built, refused with a conflict, built again and retried: no batch kept or applied.
    assert_eq!(protocol.calls(), 2);
    assert!(report.cursor.seq < seq);
    assert!(app.state.pending_effect.is_none());
    assert_eq!(w.effects(), 0);
    assert_eq!(app.protocol_get(FAILED_STEP).await.unwrap(), None);
    assert_eq!(note_kept(&app, &message).await, None);
    let report = app.receive(None).await.unwrap();
    assert!(report.cursor.seq >= seq);
    assert_eq!(w.effects(), 1);
    assert_eq!(
        note_kept(&app, &message).await,
        Some(FLAKY.as_bytes().to_vec())
    );
}

fn parked_for(events: &[AppEvent], seq: u64) -> Option<ParkReason> {
    events.iter().find_map(|e| match e {
        AppEvent::Parked { seq: s, reason } if *s == seq => Some(*reason),
        _ => None,
    })
}

#[tokio::test]
async fn test_receive_retry_unavailable_is_held_for_the_wait_then_parked_and_processed() {
    let w = World::new();
    let protocol = FlakyProtocol::new(u32::MAX);
    let mut app = join_flaky(&w, &protocol, "wallet").await;
    let (seq, message) = w.note(app.app_id(), FLAKY);
    let report = app.receive(None).await.unwrap();
    assert!(report.cursor.seq < seq, "held");
    assert_eq!(parked_for(&report.events, seq), None);
    // Just short of the wait: still held.
    w.clock.advance_ms(PARK_AFTER_MS - 1);
    let report = app.receive(None).await.unwrap();
    assert!(report.cursor.seq < seq);
    // Past it: stored locally, and the cursor passes it, here and at the service.
    w.clock.advance_ms(1);
    let report = app.receive(None).await.unwrap();
    assert_eq!(
        parked_for(&report.events, seq),
        Some(ParkReason::StoreUnavailable)
    );
    assert!(report.cursor.seq >= seq, "the cursor isn't pinned");
    app.flush_cursor().await.unwrap();
    assert!(w.switch.app(&app.app_id()).cursor >= seq);
    assert!(app.state.retries.is_empty());
    assert_eq!(w.effects(), 0);
    // Stored, it is tried at the next read and stays stored while the store fails.
    let calls = protocol.calls();
    let report = app.receive(None).await.unwrap();
    assert_eq!(protocol.calls(), calls + 1);
    assert!(app.state.parked.contains_key(&seq));
    assert!(
        !report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::Unparked { .. }))
    );
    assert_eq!(app.protocol_get(FAILED_STEP).await.unwrap(), None);
    // Once the store works it is processed, once.
    protocol.heal();
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::Unparked { seq: s } if *s == seq))
    );
    assert!(app.state.parked.is_empty());
    assert_eq!(w.effects(), 1);
    assert_eq!(protocol.applied(), 1);
    assert_eq!(
        note_kept(&app, &message).await,
        Some(FLAKY.as_bytes().to_vec())
    );
    app.receive(None).await.unwrap();
    assert_eq!(protocol.applied(), 1);
}

#[tokio::test]
async fn test_receive_retry_of_the_entry_is_parked_at_once() {
    let w = World::new();
    let protocol = FlakyProtocol::failing(1, StoreError::Corrupt, Mode::Plain);
    let mut app = join_flaky(&w, &protocol, "wallet").await;
    let (seq, _) = w.note(app.app_id(), FLAKY);
    let (later, _) = w.note(app.app_id(), "steady");
    let report = app.receive(None).await.unwrap();
    assert_eq!(
        parked_for(&report.events, seq),
        Some(ParkReason::StoreRejected)
    );
    // Not held: the cursor passes it and the later note in the same read.
    assert!(report.cursor.seq >= later);
    assert!(app.state.retries.is_empty());
    assert_eq!(w.effects(), 1, "the later note only");
    assert_eq!(app.protocol_get(FAILED_STEP).await.unwrap(), None);
    // Tried again at the next read, in case the host repaired the store.
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::Unparked { seq: s } if *s == seq))
    );
    assert_eq!(w.effects(), 2);
}

// -------------------------------------------------------------------------------------
// Restoring the protocol's layer with the app's (Switch spec 12.4)

/// The backup name of [`JournalProtocol`].
const JOURNAL: &str = "journal-protocol";

/// The local key the protocol keeps its journal under.
const JOURNAL_KEY: &[u8] = b"journal";

/// [`SampleProtocol`], with a journal it backs up as a layer: the journal's bytes, under the
/// name `name`, refused when empty.
struct JournalProtocol {
    sample: SampleProtocol,
    name: Option<String>,
    /// Refuse every layer, as a later version of the protocol might.
    refuse: bool,
}

impl JournalProtocol {
    fn new(name: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            sample: SampleProtocol::default(),
            name: name.map(str::to_owned),
            refuse: false,
        })
    }

    fn refusing() -> Arc<Self> {
        Arc::new(Self {
            sample: SampleProtocol::default(),
            name: Some(JOURNAL.into()),
            refuse: true,
        })
    }
}

impl Protocol for JournalProtocol {
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

    fn resend_needed(&self, needed: &ResendNeeded) -> Vec<LocalWrite> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Vec<LocalWrite> {
        self.sample.missed(missed)
    }

    fn backup_name(&self) -> Option<String> {
        self.name.clone()
    }

    fn restore_layer(&self, layer: Option<&ProtocolLayer>) -> Result<Vec<LocalWrite>, String> {
        let Some(layer) = layer else {
            return Err("journal: the backup has no journal".into());
        };
        if layer.data.is_empty() {
            return Err("journal: the journal is empty".into());
        }
        if self.refuse {
            return Err("journal: a journal of another version".into());
        }
        Ok(vec![LocalWrite::Put {
            key: JOURNAL_KEY.to_vec(),
            value: layer.data.clone(),
        }])
    }
}

/// A journal layer of `data`, under `name`.
fn journal_layer(name: &str, data: &[u8]) -> ProtocolLayer {
    ProtocolLayer {
        protocol: name.into(),
        data: data.to_vec(),
    }
}

/// An app with the journal protocol on `store`, its journal at `journal`, and its backup
/// with the journal layer `layer`, read back from its bytes.
async fn journaled(
    w: &World,
    protocol: &Arc<JournalProtocol>,
    store: &Arc<MemoryStore>,
    journal: &[u8],
    layer: ProtocolLayer,
) -> (App, AppBackup) {
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let mut app = App::join(
        w.env_on(Arc::clone(store) as Arc<dyn StateStore>),
        protocol.clone(),
        World::config(),
        request,
    )
    .await
    .unwrap();
    app.protocol_commit(&[LocalWrite::Put {
        key: JOURNAL_KEY.to_vec(),
        value: journal.to_vec(),
    }])
    .await
    .unwrap();
    let backup = app.backup_with_protocol_layer(layer).await.unwrap();
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    (app, backup)
}

async fn restore_on(
    w: &World,
    protocol: Arc<dyn Protocol>,
    store: Arc<dyn StateStore>,
    backup: &AppBackup,
) -> Result<App, AppError> {
    App::restore(w.env_on(store), protocol, World::config(), backup).await
}

fn snapshot(store: &MemoryStore, app: &[u8; 16]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let ns = crate::store::client_namespace(app);
    store.scan(&ns, b"", None, u32::MAX).unwrap()
}

/// The msg IDs `protocol` was handed, in order.
fn handed(protocol: &FlakyProtocol) -> Vec<String> {
    protocol
        .sample
        .received
        .lock()
        .unwrap()
        .iter()
        .map(|(_, msg_id, _)| msg_id.clone())
        .collect()
}

/// `app`'s backup with a layer of its notes, read back from its bytes.
async fn layered(app: &App) -> AppBackup {
    let notes = app.protocol_scan(b"notes/").await.unwrap();
    let layer = journal_layer(JOURNAL, &serde_json::to_vec(&notes).unwrap());
    let backup = app.backup_with_protocol_layer(layer).await.unwrap();
    AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap()
}

#[tokio::test]
async fn test_restore_of_a_backup_taken_during_a_hold_hands_no_entry_over_twice() {
    let w = World::new();
    let protocol = FlakyProtocol::new(1);
    let mut app = join_flaky(&w, &protocol, "wallet").await;
    let (held, held_message) = w.note(app.app_id(), FLAKY);
    let (past, past_message) = w.note(app.app_id(), "steady");
    app.receive(None).await.unwrap();
    assert!(app.cursor().seq < held, "held");
    assert_eq!(handed(&protocol), vec![past_message.msg_id.clone()]);
    assert_eq!(w.effects(), 1);
    // The layer reflects the note applied past the held one.
    let backup = layered(&app).await;
    let again = FlakyProtocol::new(0);
    let store = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        again.clone(),
        flaky_config(),
        &backup,
    )
    .await
    .unwrap();
    // The processed pair came back with the layer.
    let pair: Option<crate::app::state::Processed> = restored
        .reader()
        .get(&crate::app::state::key::processed(
            &w.bob.public(),
            &past_message.msg_id,
        ))
        .await
        .unwrap();
    assert!(pair.is_some());
    let report = restored.receive(None).await.unwrap();
    // Only the held note is handed over; the one applied past it isn't, again.
    assert_eq!(handed(&again), vec![held_message.msg_id.clone()]);
    assert_eq!(w.effects(), 2, "one effect per message");
    assert!(report.cursor.seq >= past);
    restored.receive(None).await.unwrap();
    assert_eq!(handed(&again).len(), 1);
}

#[tokio::test]
async fn test_restore_of_a_layered_backup_keeps_the_entries_stored_locally() {
    let w = World::new();
    let protocol = FlakyProtocol::failing(u32::MAX, StoreError::Corrupt, Mode::Plain);
    let mut app = join_flaky(&w, &protocol, "wallet").await;
    let (seq, message) = w.note(app.app_id(), FLAKY);
    app.receive(None).await.unwrap();
    assert!(app.state.parked.contains_key(&seq));
    assert!(app.cursor().seq >= seq, "passed");
    let backup = layered(&app).await;
    // Restored with a store that works: the entry the cursor passed is still processed.
    let again = FlakyProtocol::new(0);
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        again.clone(),
        flaky_config(),
        &backup,
    )
    .await
    .unwrap();
    let report = restored.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::Unparked { seq: s } if *s == seq))
    );
    assert_eq!(handed(&again), vec![message.msg_id.clone()]);
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn test_restore_installs_the_protocol_layer_with_the_app_state() {
    let w = World::new();
    let protocol = JournalProtocol::new(Some(JOURNAL));
    let (app, backup) = journaled(
        &w,
        &protocol,
        &Arc::new(MemoryStore::new()),
        b"at the backup",
        journal_layer(JOURNAL, b"at the backup"),
    )
    .await;
    assert_eq!(
        backup.protocol_layer().unwrap(),
        Some(journal_layer(JOURNAL, b"at the backup"))
    );
    let store = Arc::new(MemoryStore::new());
    let restored = restore_on(
        &w,
        protocol.clone(),
        Arc::clone(&store) as Arc<dyn StateStore>,
        &backup,
    )
    .await
    .unwrap();
    assert!(restored.reconcile_mode());
    assert_eq!(
        restored.protocol_get(JOURNAL_KEY).await.unwrap(),
        Some(b"at the backup".to_vec())
    );
    // Both layers load from the store.
    let loaded = App::load(
        w.env_on(store as Arc<dyn StateStore>),
        protocol,
        World::config(),
        app.app_id(),
    )
    .await
    .unwrap();
    assert!(loaded.reconcile_mode());
    assert_eq!(
        loaded.protocol_get(JOURNAL_KEY).await.unwrap(),
        Some(b"at the backup".to_vec())
    );
}

#[tokio::test]
async fn test_restore_failed_commit_writes_neither_layer() {
    let w = World::new();
    let protocol = JournalProtocol::new(Some(JOURNAL));
    let store = Arc::new(MemoryStore::new());
    let (app, backup) = journaled(
        &w,
        &protocol,
        &store,
        b"before the restore",
        journal_layer(JOURNAL, b"from the backup"),
    )
    .await;
    let before = snapshot(&store, &app.app_id());
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        StoreFault::FailBefore(1),
    ));
    let error = restore_on(
        &w,
        protocol.clone(),
        fault.clone() as Arc<dyn StateStore>,
        &backup,
    )
    .await
    .unwrap_err();
    assert_eq!(error, AppError::Store(StoreError::Unavailable));
    assert_eq!(fault.commits(), 1, "one commit for both layers");
    // The store holds what it held: neither the app's restored state nor the journal.
    assert_eq!(snapshot(&store, &app.app_id()), before);
    let loaded = App::load(
        w.env_on(store as Arc<dyn StateStore>),
        protocol,
        World::config(),
        app.app_id(),
    )
    .await
    .unwrap();
    assert!(!loaded.reconcile_mode());
    assert_eq!(
        loaded.protocol_get(JOURNAL_KEY).await.unwrap(),
        Some(b"before the restore".to_vec())
    );
}

#[tokio::test]
async fn test_restore_commit_of_unknown_outcome_holds_both_layers_or_neither() {
    let w = World::new();
    let protocol = JournalProtocol::new(Some(JOURNAL));
    let (app, backup) = journaled(
        &w,
        &protocol,
        &Arc::new(MemoryStore::new()),
        b"at the backup",
        journal_layer(JOURNAL, b"at the backup"),
    )
    .await;
    let store = Arc::new(MemoryStore::new());
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        StoreFault::FailAfter(1),
    ));
    let error = restore_on(&w, protocol.clone(), fault as Arc<dyn StateStore>, &backup)
        .await
        .unwrap_err();
    assert_eq!(error, AppError::Store(StoreError::Unknown));
    // Applied after all: the store, read again, holds both.
    let loaded = App::load(
        w.env_on(store as Arc<dyn StateStore>),
        protocol,
        World::config(),
        app.app_id(),
    )
    .await
    .unwrap();
    assert!(loaded.reconcile_mode());
    assert_eq!(
        loaded.protocol_get(JOURNAL_KEY).await.unwrap(),
        Some(b"at the backup".to_vec())
    );
}

#[tokio::test]
async fn test_restore_refused_protocol_layer_writes_nothing() {
    let w = World::new();
    let protocol = JournalProtocol::new(Some(JOURNAL));
    // The app's own store, holding its state and journal: a refused restore leaves it as
    // it was.
    let store = Arc::new(MemoryStore::new());
    let (app, backup) = journaled(
        &w,
        &protocol,
        &store,
        b"at the backup",
        journal_layer(JOURNAL, b"at the backup"),
    )
    .await;
    let before = snapshot(&store, &app.app_id());
    assert!(!before.is_empty());
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    let error = restore_on(
        &w,
        JournalProtocol::refusing(),
        fault.clone() as Arc<dyn StateStore>,
        &backup,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, AppError::InvalidData(why) if why.contains("another version")),
        "{error:?}"
    );
    assert_eq!(fault.commits(), 0);
    assert_eq!(snapshot(&store, &app.app_id()), before);
    // A backup without the layer the protocol needs is refused the same way.
    let bare = AppBackup::from_bytes(&app.backup().unwrap().to_bytes().unwrap()).unwrap();
    assert_eq!(bare.protocol_layer().unwrap(), None);
    let error = restore_on(&w, protocol, fault.clone() as Arc<dyn StateStore>, &bare)
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    assert_eq!(fault.commits(), 0);
    assert_eq!(snapshot(&store, &app.app_id()), before);
}

#[tokio::test]
async fn test_backup_with_a_layer_that_could_never_be_restored_is_refused() {
    let w = World::new();
    let protocol = JournalProtocol::new(Some(JOURNAL));
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let app = App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap();
    // A layer the protocol refuses.
    let error = app
        .backup_with_protocol_layer(journal_layer(JOURNAL, b""))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, AppError::InvalidData(why) if why.contains("the journal is empty")),
        "{error:?}"
    );
    // A layer whose value is over the store's value size.
    let too_large = vec![7u8; usize::try_from(crate::store::MAX_VALUE_BYTES).unwrap() + 1];
    let error = app
        .backup_with_protocol_layer(journal_layer(JOURNAL, &too_large))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, AppError::Store(StoreError::Other(why)) if why.contains("value size")),
        "{error:?}"
    );
    // Within the sizes, it backs up.
    app.backup_with_protocol_layer(journal_layer(JOURNAL, b"fits"))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_backup_with_a_layer_carries_a_version_a_reader_without_layers_refuses() {
    let w = World::new();
    let protocol = JournalProtocol::new(Some(JOURNAL));
    let (app, _) = journaled(
        &w,
        &protocol,
        &Arc::new(MemoryStore::new()),
        b"at the backup",
        journal_layer(JOURNAL, b"at the backup"),
    )
    .await;
    let version = |bytes: &[u8]| serde_json::from_slice::<Value>(bytes).unwrap()["v"].clone();
    let with = |bytes: &[u8], v: u32| {
        let mut value: Value = serde_json::from_slice(bytes).unwrap();
        value["v"] = json!(v);
        serde_json::to_vec(&value).unwrap()
    };
    let bare = app.backup().unwrap().to_bytes().unwrap();
    let layered = app
        .backup_with_protocol_layer(journal_layer(JOURNAL, b"at the backup"))
        .await
        .unwrap()
        .to_bytes()
        .unwrap();
    // Without a layer, the schema's version, as before; with one, another, which a reader
    // that takes only the schema's version refuses.
    assert_eq!(version(&bare), json!(crate::app::SCHEMA_VERSION));
    assert_ne!(version(&layered), json!(crate::app::SCHEMA_VERSION));
    assert!(AppBackup::from_bytes(&bare).is_ok());
    assert!(AppBackup::from_bytes(&layered).is_ok());
    // A layer under the schema's version, or the layered version without a layer, doesn't
    // read.
    let layer_as_bare = with(&layered, crate::app::SCHEMA_VERSION);
    assert!(matches!(
        AppBackup::from_bytes(&layer_as_bare),
        Err(AppError::InvalidData(_))
    ));
    let bare_as_layered = with(&bare, version(&layered).as_u64().unwrap() as u32);
    assert!(matches!(
        AppBackup::from_bytes(&bare_as_layered),
        Err(AppError::InvalidData(_))
    ));
}

#[tokio::test]
async fn test_restore_layer_of_a_protocol_not_registered_is_refused() {
    let w = World::new();
    let protocol = JournalProtocol::new(Some(JOURNAL));
    // The app's own store, holding its state and journal: a refused restore leaves it as
    // it was.
    let store = Arc::new(MemoryStore::new());
    let (app, backup) = journaled(
        &w,
        &protocol,
        &store,
        b"at the backup",
        journal_layer(JOURNAL, b"at the backup"),
    )
    .await;
    let before = snapshot(&store, &app.app_id());
    assert!(!before.is_empty());
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    // A protocol with no backup name, and one of another name: the layer isn't theirs, and
    // the restore is refused rather than drop it.
    let others: [Arc<dyn Protocol>; 2] = [
        w.protocol.clone(),
        JournalProtocol::new(Some("another-protocol")),
    ];
    for other in others {
        let error = restore_on(&w, other, fault.clone() as Arc<dyn StateStore>, &backup)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, AppError::InvalidData(why) if why.contains("another protocol's")),
            "{error:?}"
        );
    }
    assert_eq!(fault.commits(), 0);
    assert_eq!(snapshot(&store, &app.app_id()), before);
}

#[tokio::test]
async fn test_restore_without_a_layer_by_a_protocol_that_takes_none() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    app.protocol_commit(&[LocalWrite::Put {
        key: JOURNAL_KEY.to_vec(),
        value: b"not in the backup".to_vec(),
    }])
    .await
    .unwrap();
    let backup = AppBackup::from_bytes(&app.backup().unwrap().to_bytes().unwrap()).unwrap();
    // The bytes of a backup without a layer carry no member for it.
    assert!(
        !String::from_utf8(backup.to_bytes().unwrap())
            .unwrap()
            .contains("\"protocol\"")
    );
    let store = Arc::new(MemoryStore::new());
    let restored = restore_on(
        &w,
        w.protocol.clone(),
        Arc::clone(&store) as Arc<dyn StateStore>,
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(restored.protocol_get(JOURNAL_KEY).await.unwrap(), None);
}

// -------------------------------------------------------------------------------------
// A receive step reads the local writes of the read's earlier entries

/// The local key of [`CounterProtocol`]'s count.
const COUNT: &[u8] = b"count";

/// [`SampleProtocol`], whose receive step counts the notes in its local state, reading the
/// count and writing it plus one, with no operation, so only the cursor moves. A note whose
/// text is [`FLAKY`] fails while `fails` is above zero, after writing a count of 99 through
/// the context, which must never be seen.
struct CounterProtocol {
    sample: SampleProtocol,
    fails: Mutex<u32>,
}

fn count_of(value: Option<Vec<u8>>) -> u64 {
    value
        .and_then(|v| String::from_utf8(v).ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

impl Protocol for CounterProtocol {
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
        let count = match cx.local_get(COUNT) {
            Ok(value) => count_of(value),
            Err(error) => {
                return match StoreFailure::try_from(error) {
                    Ok(failure) => Outcome::Retry(failure),
                    Err(error) => Outcome::Drop {
                        reason: error.to_string(),
                    },
                };
            }
        };
        let flaky = message.message.body.get("text").and_then(Value::as_str) == Some(FLAKY);
        let mut fails = self.fails.lock().unwrap();
        if flaky && *fails > 0 {
            *fails -= 1;
            cx.local(LocalWrite::Put {
                key: COUNT.to_vec(),
                value: b"99".to_vec(),
            });
            return Outcome::Retry(StoreError::Unavailable.into());
        }
        let scanned = cx.local_scan(COUNT).unwrap();
        assert_eq!(
            scanned
                .first()
                .map(|(_, v)| count_of(Some(v.clone())))
                .unwrap_or(0),
            count,
            "a scan reads what a get reads"
        );
        Outcome::Apply(Effect {
            ops: Vec::new(),
            local: vec![LocalWrite::Put {
                key: COUNT.to_vec(),
                value: (count + 1).to_string().into_bytes(),
            }],
        })
    }

    fn resend_needed(&self, needed: &ResendNeeded) -> Vec<LocalWrite> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Vec<LocalWrite> {
        self.sample.missed(missed)
    }
}

#[tokio::test]
async fn test_receive_context_reads_the_local_writes_of_earlier_entries_in_the_read() {
    let w = World::new();
    let protocol = Arc::new(CounterProtocol {
        sample: SampleProtocol::default(),
        fails: Mutex::new(1),
    });
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let mut app = App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap();
    w.note(app.app_id(), "one");
    w.note(app.app_id(), FLAKY);
    w.note(app.app_id(), "two");
    app.receive(None).await.unwrap();
    // Both notes counted in one read; the retried step's write stays unseen.
    assert_eq!(count_of(app.protocol_get(COUNT).await.unwrap()), 2);
    app.receive(None).await.unwrap();
    assert_eq!(count_of(app.protocol_get(COUNT).await.unwrap()), 3);
}

// -------------------------------------------------------------------------------------
// A backup is of committed state

/// The commit of the read below that commits its page, the second of the read: the test
/// checks that memory is ahead of the store after it fails.
const FAILING_COMMIT: u64 = 2;

#[tokio::test]
async fn test_backup_after_a_failed_commit_is_refused_until_the_store_is_read_again() {
    let w = World::new();
    let protocol = Arc::new(CounterProtocol {
        sample: SampleProtocol::default(),
        fails: Mutex::new(0),
    });
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let mut app = App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap();
    // A first read does what the join left due, so the next read's first commit is its
    // page's.
    app.receive(None).await.unwrap();
    let me = app.app_id();
    drop(app);
    // The page's commit fails: memory moves past the note, the store doesn't.
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::FailBefore(FAILING_COMMIT),
    ));
    let mut app = App::load(
        w.env_on(fault as Arc<dyn StateStore>),
        protocol.clone(),
        World::config(),
        me,
    )
    .await
    .unwrap();
    let (seq, _) = w.note(me, "one");
    let error = app.receive(None).await.unwrap_err();
    assert_eq!(error, AppError::Store(StoreError::Unavailable));
    assert!(app.cursor().seq >= seq, "memory is ahead");
    assert_eq!(
        app.protocol_get(COUNT).await.unwrap(),
        None,
        "the store isn't"
    );
    let error = app.backup().unwrap_err();
    assert!(
        matches!(error, AppError::Refused(crate::app::Refusal::NotNow(_))),
        "{error:?}"
    );
    // The next call reads the store again and processes the note; then it backs up.
    app.receive(None).await.unwrap();
    assert_eq!(count_of(app.protocol_get(COUNT).await.unwrap()), 1);
    let backup = app.backup().unwrap();
    let restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        protocol,
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert!(restored.cursor().seq >= seq);
}
