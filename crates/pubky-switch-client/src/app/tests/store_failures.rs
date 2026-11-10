//! A protocol whose store or host fails: a receive step that can't finish for now
//! ([`Outcome::Retry`]) leaves its entry unprocessed until a later read (Switch spec 8.2),
//! and a restore installs the protocol's backup layer with the app's state, in one commit,
//! or neither (Switch spec 12.4).

use std::sync::Mutex;

use super::*;
use crate::app::{
    AppBackup, AppError, AppEvent, Peeked, ProtocolLayer, RETRY_EVENT_READS, ReceiveContext,
    StoreFailure,
};
use crate::error::StoreError;
use crate::store::{Fault as StoreFault, FaultStore};

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
}

impl JournalProtocol {
    fn new(name: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            sample: SampleProtocol::default(),
            name: name.map(str::to_owned),
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
    let backup = app.backup().unwrap().with_protocol_layer(layer);
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
    let (app, backup) = journaled(
        &w,
        &protocol,
        &Arc::new(MemoryStore::new()),
        b"at the backup",
        journal_layer(JOURNAL, b""),
    )
    .await;
    let store = Arc::new(MemoryStore::new());
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    let error = restore_on(
        &w,
        protocol.clone(),
        fault.clone() as Arc<dyn StateStore>,
        &backup,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, AppError::InvalidData(why) if why.contains("the journal is empty")),
        "{error:?}"
    );
    assert_eq!(fault.commits(), 0);
    assert!(snapshot(&store, &app.app_id()).is_empty());
    // A backup without the layer the protocol needs is refused the same way.
    let bare = AppBackup::from_bytes(&app.backup().unwrap().to_bytes().unwrap()).unwrap();
    assert_eq!(bare.protocol_layer().unwrap(), None);
    let error = restore_on(&w, protocol, fault.clone() as Arc<dyn StateStore>, &bare)
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    assert_eq!(fault.commits(), 0);
    assert!(snapshot(&store, &app.app_id()).is_empty());
}

#[tokio::test]
async fn test_restore_layer_of_a_protocol_not_registered_is_refused() {
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
    assert!(snapshot(&store, &app.app_id()).is_empty());
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
