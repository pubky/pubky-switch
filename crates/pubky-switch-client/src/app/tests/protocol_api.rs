//! What a protocol does through the app's public API: effects that write their records in
//! the batch that moves the cursor, its own local state, messages signed before they are
//! queued, the attempt checks of its batches, counterparties' `identity.json`, the highest
//! service time, collections with a policy per sub-scope, and two identities messaging each
//! other, each on its own scripted switch.

use std::sync::{Arc, Mutex};

use pubky_switch_core::chain::TransitionProof;
use pubky_switch_core::claims::ClaimStatus;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ident::Policy;
use pubky_switch_core::message::{MessagePlaintext, Sender};
use pubky_switch_core::ops::{Condition, KeyBundlePut, OpKind, RecordVersion};
use pubky_switch_core::records::{
    CLOCK_TOLERANCE_MS, DAY_MS, IdentityDoc, Inbox, seal_bundle_parts,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Map, Value, json};

use super::shared_flows::{ItemsProtocol, ids, items, value};
use super::*;
use crate::app::{
    AppBackup, AppError, AppEvent, ClaimOp, Collection, DOC_CACHE_MS, Delivery,
    LISTS_TOO_LARGE_RETRY_MS, MAX_CURSOR_DEFER_MS, MAX_SEEN_MARK_BYTES, ObligationDeadline,
    OpBatch, OutgoingMessage, PolicyFamily, ReceiveContext, RecordJob, RecordTarget, Refusal,
    SENT_RETENTION_MS, SenderDisposition, SentMessage, SignedMessage, SwitchCopy, WontDeliver,
};
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::{Fault, Router, SWITCH_ORIGIN, ScriptedSwitch};
use crate::transport::Transport;

const MINUTE: u64 = 60_000;
pub(super) const BOB_ORIGIN: &str = "https://bob-switch.example";
const CAROL_ORIGIN: &str = "https://carol-switch.example";
const CLAIM: [u8; 32] = [5; 32];
const ATTEMPT: [u8; 16] = [6; 16];

/// What [`ApiProtocol`]'s receive step does with a note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// [`ItemsProtocol`]'s effect, through the plain `receive`.
    Plain,
    /// Add the note's `msg_id` to the record `inbox`, through the context.
    Record,
    /// The same, then write the record a second time in the batch.
    RecordTwice,
    /// The same, then drop the message.
    DropAfterWrite,
    /// An `attempt` on [`CLAIM`] through the context.
    Attempt,
    /// A write of a record whose policy names a write scope the app doesn't hold.
    OtherWriteScope,
    /// A write of `inbox` with a value that isn't JSON.
    NotJson,
}

/// What one call of the receive step saw.
#[derive(Clone, Debug)]
struct Seen {
    msg_id: String,
    /// The message hash of the signed plaintext it was handed.
    hash: [u8; 32],
    /// The version of `inbox` the app held.
    held: Option<RecordVersion>,
    conflict: bool,
    /// The context's answers to the writes, as text.
    writes: Vec<Result<(), String>>,
    context: Option<Value>,
    /// What the context knew of the sender's standing in the lists.
    disposition: Option<SenderDisposition>,
    /// The condition the context named on `inbox`, in the record modes.
    condition: Option<Condition>,
}

/// [`ItemsProtocol`], with a receive step that uses the [`ReceiveContext`].
struct ApiProtocol {
    items: ItemsProtocol,
    mode: Mutex<Mode>,
    collections: Mutex<Vec<Collection>>,
    seen: Mutex<Vec<Seen>>,
    /// How many of the next receive steps the store rejects for their entry, which is then
    /// stored locally ([`StoreFailure::of_entry`]).
    reject: Mutex<u32>,
    /// The body members it names opaque.
    opaque: Mutex<Vec<crate::app::OpaqueRule>>,
}

impl ApiProtocol {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            items: ItemsProtocol::default(),
            mode: Mutex::new(mode),
            collections: Mutex::new(vec![items()]),
            seen: Mutex::new(Vec::new()),
            reject: Mutex::new(0),
            opaque: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn inbox() -> RecordTarget {
    RecordTarget::new(items(), b"inbox")
}

fn text(result: Result<[u8; 32], AppError>) -> Result<(), String> {
    result.map(|_| ()).map_err(|e| e.to_string())
}

impl Protocol for ApiProtocol {
    fn has_keys(&self, scope: &str) -> bool {
        self.items.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.items.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.items.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.items.accepts(cert)
    }

    /// The plain mode receives as [`ItemsProtocol`] does; the others take any body.
    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        if *self.mode.lock().unwrap() == Mode::Plain {
            self.items.check_body(message)
        } else {
            Ok(())
        }
    }

    fn receive(&self, message: &ReceivedMessage) -> Outcome {
        self.items.receive(message)
    }

    fn receive_with(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        let mode = *self.mode.lock().unwrap();
        let msg_id = message.message.msg_id.clone();
        let mut seen = Seen {
            msg_id: msg_id.clone(),
            hash: message.plaintext.hash(),
            held: None,
            conflict: message.conflict.is_some(),
            writes: Vec::new(),
            context: message.context.clone(),
            disposition: cx.sender_disposition(&message.sender).ok(),
            condition: None,
        };
        {
            let mut reject = self.reject.lock().unwrap();
            if *reject > 0 {
                *reject -= 1;
                self.seen.lock().unwrap().push(seen);
                return Outcome::Retry(crate::app::StoreFailure::of_entry(
                    crate::error::StoreError::Corrupt,
                ));
            }
        }
        let outcome = match mode {
            Mode::Plain => self.receive(message),
            Mode::Record | Mode::RecordTwice | Mode::DropAfterWrite => {
                let held = cx.record(&inbox()).unwrap();
                seen.held = held.as_ref().map(|r| r.version);
                let key = cx.record_key(&inbox()).unwrap();
                seen.condition = Some(cx.record_condition(&key).unwrap());
                let mut all = ids(held.as_ref().and_then(|r| r.content.value()));
                if !all.contains(&msg_id) {
                    // A record that reflects the message already needs no write (Switch
                    // spec 8.2).
                    all.push(msg_id.clone());
                    let all: Vec<&str> = all.iter().map(String::as_str).collect();
                    seen.writes
                        .push(text(cx.put_record(&inbox(), &value(&all), vec![])));
                    if mode == Mode::RecordTwice {
                        seen.writes
                            .push(text(cx.put_record(&inbox(), &value(&all), vec![])));
                    }
                }
                cx.local(LocalWrite::Put {
                    key: format!("notes/{msg_id}").into_bytes(),
                    value: b"1".to_vec(),
                })
                .unwrap();
                if mode == Mode::DropAfterWrite {
                    Outcome::Drop {
                        reason: "sample: dropped after writing".into(),
                    }
                } else {
                    Outcome::Apply(Effect::default())
                }
            }
            Mode::OtherWriteScope => {
                let target = RecordTarget::new(
                    Collection::new("sample.other", Policy::new("scope-a", &["scope-b"])),
                    b"x",
                );
                seen.writes
                    .push(text(cx.put_record(&target, &value(&["x"]), vec![])));
                Outcome::Apply(Effect::default())
            }
            Mode::NotJson => {
                seen.writes
                    .push(text(cx.put_record(&inbox(), b"not json", vec![])));
                Outcome::Apply(Effect::default())
            }
            Mode::Attempt => {
                let step = cx.claim_view(&CLAIM).unwrap().map_or(0, |v| v.step);
                let result = cx.claim(
                    ClaimOp::attempt(CLAIM, step, ATTEMPT, 3600, None),
                    vec![cx.claim_condition(&CLAIM).unwrap()],
                    ObligationDeadline::NoDeadline,
                );
                seen.writes.push(result.map_err(|e| e.to_string()));
                Outcome::Apply(Effect::default())
            }
        };
        self.seen.lock().unwrap().push(seen);
        outcome
    }

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.items.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.items.missed(missed)
    }

    fn adds_conversation(&self, kind: &str) -> bool {
        self.items.adds_conversation(kind)
    }

    fn opaque_members(&self) -> Vec<crate::app::OpaqueRule> {
        self.opaque.lock().unwrap().clone()
    }

    fn collections(&self) -> Vec<Collection> {
        self.collections.lock().unwrap().clone()
    }

    fn record_seen(&self, c: &str, seen: Option<&[u8]>, value: Option<&[u8]>) -> Option<Vec<u8>> {
        self.items.record_seen(c, seen, value)
    }

    fn record_regression(&self, c: &str, seen: &[u8], value: Option<&[u8]>) -> Option<String> {
        self.items.record_regression(c, seen, value)
    }

    fn sent_record(
        &self,
        job: &RecordJob,
        sent: &SentMessage,
        current: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        self.items.sent_record(job, sent, current)
    }

    fn backup_name(&self) -> Option<String> {
        Some("sample.api".into())
    }
}

/// A cursor move that waits for the next batch as long as it may: one the switch holds came
/// with an effect.
pub(super) fn config() -> AppConfig {
    AppConfig {
        cursor_defer_ms: MAX_CURSOR_DEFER_MS,
        ..AppConfig::default()
    }
}

async fn join_on(
    w: &World,
    protocol: &Arc<ApiProtocol>,
    name: &str,
    scopes: &[&str],
    store: Arc<dyn StateStore>,
) -> App {
    let app = AppSpec::new(scopes).with_permissions(&Permission::ALL);
    let request = w.signer.approve(&app_keys(name), &app).unwrap();
    App::join(w.env_on(store), protocol.clone(), config(), request)
        .await
        .unwrap()
}

async fn join(w: &World, protocol: &Arc<ApiProtocol>, name: &str) -> App {
    join_on(
        w,
        protocol,
        name,
        &["scope-a"],
        Arc::new(MemoryStore::new()),
    )
    .await
}

fn record_puts(w: &World) -> usize {
    w.switch
        .applied()
        .iter()
        .filter(|op| matches!(op.body().kind, OpKind::RecordPut(_)))
        .count()
}

// -------------------------------------------------------------------------------------
// The receive context (Switch spec 8.2)

#[tokio::test]
async fn test_receive_context_writes_the_record_with_the_cursor_move() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Record);
    let mut app = join(&w, &protocol, "wallet").await;
    let (seq, note) = w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    // One batch: the record write, carrying the cursor past the entry.
    assert_eq!(record_puts(&w), 1);
    assert_eq!(w.switch.app(&app.app_id()).cursor, seq);
    assert_eq!(app.service_cursor().seq, seq);
    let key = app.record_key(&inbox()).unwrap();
    let record = app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()), vec![note.msg_id.clone()]);
    assert!(record.authenticated, "settled from the effect's proof");
    let local = format!("notes/{}", note.msg_id);
    assert!(app.protocol_get(local.as_bytes()).await.unwrap().is_some());
    // The message seen again writes nothing more.
    assert!(protocol.seen()[0].held.is_none());
}

#[tokio::test]
async fn test_receive_context_condition_names_zero_for_a_held_delete() {
    // The receive step's condition on a record: `{0, 0}` for one the app holds nothing of
    // and for one it holds as deleted, which `{0, 0}` matches as it matches a forgotten key
    // (Switch wire 6.3, spec 10.3); the held version for a live one.
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Record);
    let mut app = join(&w, &protocol, "wallet").await;
    let key = app.record_key(&inbox()).unwrap();
    let zero = Condition::RecordVersion {
        key,
        version: RecordVersion::NONE,
    };
    w.note(app.app_id(), "one");
    app.receive(None).await.unwrap();
    let live = app.shared_record(&key).await.unwrap().unwrap().version;
    w.note(app.app_id(), "two");
    app.receive(None).await.unwrap();
    app.delete_record(&inbox(), vec![]).await.unwrap();
    w.note(app.app_id(), "three");
    app.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(seen[0].condition, Some(zero), "absent");
    assert_eq!(
        seen[1].condition,
        Some(Condition::RecordVersion { key, version: live }),
        "live"
    );
    assert_eq!(seen[2].condition, Some(zero), "held as deleted");
}

#[tokio::test]
async fn test_receive_context_second_message_builds_on_the_first() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Record);
    let mut app = join(&w, &protocol, "wallet").await;
    let (_, first) = w.note(app.app_id(), "one");
    let (second_seq, second) = w.note(app.app_id(), "two");
    app.receive(None).await.unwrap();
    assert_eq!(record_puts(&w), 2);
    let seen = protocol.seen();
    assert_eq!(seen.len(), 2, "no conflict: {seen:?}");
    assert!(seen.iter().all(|s| !s.conflict));
    assert!(
        seen[1].held.is_some(),
        "the second effect built on the first"
    );
    let key = app.record_key(&inbox()).unwrap();
    let record = app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(
        ids(record.content.value()),
        vec![first.msg_id, second.msg_id]
    );
    assert_eq!(app.service_cursor().seq, second_seq);
}

#[tokio::test]
async fn test_receive_context_conflict_reads_again_and_builds_again() {
    conflict_reads_again_and_builds_again().await;
}

/// An entry whose effect, built on what the app holds, meets `409 conflict`: it reads the
/// record again and builds again. Also run on a small stack.
async fn conflict_reads_again_and_builds_again() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Record);
    let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
    let mut wallet = join_on(&w, &protocol, "wallet", &["scope-a"], store).await;
    let mut phone = join(&w, &protocol, "phone").await;
    wallet.receive(None).await.unwrap();
    let (_, note) = w.note(wallet.app_id(), "hello");
    // Another own app writes the record after the note: the wallet's effect, built on
    // what it holds, meets `409 conflict`.
    phone
        .put_record(&inbox(), &value(&["other"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let seen: Vec<Seen> = protocol
        .seen()
        .into_iter()
        .filter(|s| s.msg_id == note.msg_id)
        .collect();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(!seen[0].conflict && seen[0].held.is_none());
    assert!(
        seen[1].conflict && seen[1].held.is_some(),
        "read again first"
    );
    let key = wallet.record_key(&inbox()).unwrap();
    let record = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(
        ids(record.content.value()),
        vec!["other".to_owned(), note.msg_id]
    );
}

#[tokio::test]
async fn test_receive_context_without_the_current_key_waits_for_it() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Record);
    let mut app = join(&w, &protocol, "wallet").await;
    let cert = app.cert().clone();
    // A new data epoch whose keys haven't reached the app yet.
    w.next_doc(|body| body.data_epoch = 2);
    let (seq, note) = w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    assert_eq!(record_puts(&w), 0);
    // The entry waits for the key stored locally, with the cursor past it.
    assert_eq!(
        app.stored_at(seq).map(|stored| stored.reason),
        Some(crate::app::ParkReason::AwaitingKey { data_epoch: 2 })
    );
    assert!(app.cursor().seq >= seq, "the cursor passes the entry");
    // Once the bundle is there, the entry is handed over again and written.
    let has_keys = |scope: &str| SampleProtocol::default().has_keys(scope);
    for part in seal_bundle_parts(&w.alice, &cert, 1, 2, &has_keys).unwrap() {
        w.switch
            .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: app.app_id(),
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
    }
    app.receive(None).await.unwrap();
    assert_eq!(record_puts(&w), 1);
    assert!(app.stored_at(seq).is_none());
    let key = app.record_key(&inbox()).unwrap();
    let record = app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()), vec![note.msg_id]);
}

#[tokio::test]
async fn test_receive_context_refuses_a_second_write_of_one_record() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::RecordTwice);
    let mut app = join(&w, &protocol, "wallet").await;
    w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert!(seen[0].writes[0].is_ok());
    let second = seen[0].writes[1].as_ref().unwrap_err();
    assert!(second.contains("one write per record"), "{second}");
    assert_eq!(record_puts(&w), 1);
}

#[tokio::test]
async fn test_receive_context_without_a_write_scope_is_refused() {
    let w = World::new();
    // The record's policy writes under `scope-b`, which the app doesn't hold.
    let protocol = ApiProtocol::new(Mode::OtherWriteScope);
    let mut app = join(&w, &protocol, "wallet").await;
    let (seq, _) = w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    let seen = protocol.seen();
    let refused = seen[0].writes[0].as_ref().unwrap_err();
    assert!(refused.contains("write scopes"), "{refused}");
    assert_eq!(record_puts(&w), 0);
    // The effect without the write still applies: the cursor passes the entry.
    assert_eq!(app.cursor().seq, seq);
}

#[tokio::test]
async fn test_receive_context_write_whose_mark_wont_fit_is_refused() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Record);
    let mut app = join(&w, &protocol, "wallet").await;
    *protocol.items.pad.lock().unwrap() = MAX_SEEN_MARK_BYTES;
    let (seq, _) = w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    let refused = protocol.seen()[0].writes[0].clone().unwrap_err();
    assert!(refused.contains("mark"), "{refused}");
    assert_eq!(record_puts(&w), 0);
    assert_eq!(app.cursor().seq, seq);
}

#[tokio::test]
async fn test_receive_context_value_that_isnt_json_is_refused_before_the_mark() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::NotJson);
    let mut app = join(&w, &protocol, "wallet").await;
    // The mark queued for the next write is still there after the refusal: the protocol
    // was never asked to mark the value.
    protocol.items.pads.lock().unwrap().push_back(0);
    w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    let refused = protocol.seen()[0].writes[0].clone().unwrap_err();
    assert!(refused.contains("JSON"), "{refused}");
    assert_eq!(protocol.items.pads.lock().unwrap().len(), 1);
    assert_eq!(record_puts(&w), 0);
}

#[tokio::test]
async fn test_receive_context_writes_go_only_with_apply() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::DropAfterWrite);
    let mut app = join(&w, &protocol, "wallet").await;
    let (seq, note) = w.note(app.app_id(), "hello");
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::MessageDropped { seq: s, check: 10, .. } if *s == seq))
    );
    assert_eq!(record_puts(&w), 0);
    let local = format!("notes/{}", note.msg_id);
    assert!(app.protocol_get(local.as_bytes()).await.unwrap().is_none());
    assert_eq!(app.cursor().seq, seq);
}

#[tokio::test]
async fn test_receive_context_claim_goes_in_the_effect_and_is_checked() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Attempt);
    let mut app = join(&w, &protocol, "wallet").await;
    let (seq, _) = w.note(app.app_id(), "done");
    let report = app.receive(None).await.unwrap();
    assert!(protocol.seen()[0].writes[0].is_ok());
    assert!(
        !report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::AttemptNotHeld { .. })),
        "{:?}",
        report.events
    );
    let evidence = app.claim_evidence(&CLAIM).await.unwrap().unwrap();
    assert_eq!(evidence.view.status, ClaimStatus::Attempting);
    assert_eq!(evidence.own_deadline, ObligationDeadline::NoDeadline);
    assert_eq!(w.switch.app(&app.app_id()).cursor, seq);
}

#[tokio::test]
async fn test_receive_context_attempt_refused_in_reconcile_mode() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Attempt);
    let app = join(&w, &protocol, "wallet").await;
    let backup = app.backup().await.unwrap();
    drop(app);
    let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
    let mut app = App::restore(w.env_on(store), protocol.clone(), config(), &backup)
        .await
        .unwrap();
    assert!(app.reconcile_mode());
    w.note(app.app_id(), "done");
    app.receive(None).await.unwrap();
    let refused = protocol.seen()[0].writes[0].clone().unwrap_err();
    assert!(refused.contains("no attempt"), "{refused}");
    assert!(w.switch.claim(&CLAIM).is_none());
}

/// One run of the receiving scenario: join, two notes from bob, read them. Returns at the
/// first error, as a process that died.
async fn receive_scenario(
    w: &World,
    protocol: &Arc<ApiProtocol>,
    store: Arc<dyn StateStore>,
    sent: &mut Vec<(u64, String)>,
    approval: &mut Option<JoinRequest>,
) -> Result<(), AppError> {
    let keys = app_keys("wallet");
    let env = w.env_on(Arc::clone(&store));
    let mut app =
        match App::load(env.clone(), protocol.clone(), config(), keys.app_id_bytes()).await {
            Ok(app) => app,
            Err(AppError::Refused(Refusal::NotJoined)) => {
                let request = approval
                    .get_or_insert_with(|| w.approve(&keys, &["scope-a"]))
                    .clone();
                App::join(env, protocol.clone(), config(), request).await?
            }
            Err(error) => return Err(error),
        };
    app.receive(None).await?;
    while sent.len() < 2 {
        let (seq, note) = w.note(app.app_id(), &format!("note {}", sent.len()));
        sent.push((seq, note.msg_id));
    }
    app.receive(None).await?;
    app.receive(None).await?;
    Ok(())
}

#[tokio::test]
async fn test_receive_context_crash_at_each_commit_point_writes_each_effect_once() {
    let commits = {
        let w = World::new();
        let counting = Arc::new(FaultStore::new(
            Arc::new(MemoryStore::new()) as Arc<dyn StateStore>,
            StoreFault::None,
        ));
        receive_scenario(
            &w,
            &ApiProtocol::new(Mode::Record),
            Arc::clone(&counting) as Arc<dyn StateStore>,
            &mut Vec::new(),
            &mut None,
        )
        .await
        .unwrap();
        counting.commits()
    };
    assert!(commits > 6, "the scenario commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let w = World::new();
            let protocol = ApiProtocol::new(Mode::Record);
            let inner = Arc::new(MemoryStore::new());
            let fault = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let mut sent = Vec::new();
            let mut approval = None;
            let first = receive_scenario(
                &w,
                &protocol,
                Arc::clone(&fault) as Arc<dyn StateStore>,
                &mut sent,
                &mut approval,
            )
            .await;
            assert!(fault.stopped(), "commit {n} of {commits} is reached");
            assert!(first.is_err());
            receive_scenario(
                &w,
                &protocol,
                Arc::clone(&inner) as Arc<dyn StateStore>,
                &mut sent,
                &mut approval,
            )
            .await
            .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            let app = App::load(
                w.env_on(Arc::clone(&inner) as Arc<dyn StateStore>),
                protocol.clone(),
                config(),
                app_keys("wallet").app_id_bytes(),
            )
            .await
            .unwrap();
            // Each note's record write applied once, both in the record, the cursor past.
            assert_eq!(record_puts(&w), 2, "commit {n} ({stop_after})");
            let key = app.record_key(&inbox()).unwrap();
            let record = app.shared_record(&key).await.unwrap().unwrap();
            let expected: Vec<String> = sent.iter().map(|(_, id)| id.clone()).collect();
            assert_eq!(
                ids(record.content.value()),
                expected,
                "commit {n} ({stop_after})"
            );
            assert!(app.cursor().seq >= sent[1].0, "commit {n} ({stop_after})");
            for (_, msg_id) in &sent {
                let local = format!("notes/{msg_id}");
                assert!(app.protocol_get(local.as_bytes()).await.unwrap().is_some());
            }
        }
    }
}

// -------------------------------------------------------------------------------------
// The protocol's local state

#[tokio::test]
async fn test_protocol_commit_and_scan_in_key_order() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let put = |key: &str, value: &str| LocalWrite::Put {
        key: key.as_bytes().to_vec(),
        value: value.as_bytes().to_vec(),
    };
    app.protocol_commit(&[put("a/2", "two"), put("b/1", "x"), put("a/1", "one")])
        .await
        .unwrap();
    let scanned = app.protocol_scan(b"a/").await.unwrap();
    assert_eq!(
        scanned,
        vec![
            (b"a/1".to_vec(), b"one".to_vec()),
            (b"a/2".to_vec(), b"two".to_vec())
        ]
    );
    app.protocol_commit(&[LocalWrite::DeletePrefix {
        prefix: b"a/".to_vec(),
    }])
    .await
    .unwrap();
    assert!(app.protocol_scan(b"a/").await.unwrap().is_empty());
    assert_eq!(app.protocol_scan(b"").await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_protocol_commit_refused_once_the_keys_are_deleted() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    app.leave(crate::app::LeaveMode::Immediate(
        crate::app::UserConfirmed::new(),
    ))
    .await
    .unwrap();
    let error = app
        .protocol_commit(&[LocalWrite::Put {
            key: b"k".to_vec(),
            value: b"v".to_vec(),
        }])
        .await
        .unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::Left));
}

#[tokio::test]
async fn test_batch_local_writes_commit_with_the_answer_only() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let write = |key: &str| LocalWrite::Put {
        key: key.as_bytes().to_vec(),
        value: b"1".to_vec(),
    };
    app.submit_batch(
        OpBatch::new()
            .op(OpKind::DenyPut { pubky: [9; 32] })
            .local(write("applied")),
    )
    .await
    .unwrap();
    assert!(app.protocol_get(b"applied").await.unwrap().is_some());
    // A batch refused for good commits none of its local writes.
    let key = app.record_key(&inbox()).unwrap();
    let wrong = Condition::RecordVersion {
        key,
        version: RecordVersion::new(1, 99),
    };
    let entry = app
        .record_op(&inbox(), Some(&value(&["a"])), vec![wrong])
        .await
        .unwrap();
    let error = app
        .submit_batch(OpBatch::new().entry(entry).locals([write("refused")]))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    assert!(app.protocol_get(b"refused").await.unwrap().is_none());
}

// -------------------------------------------------------------------------------------
// The attempts of a protocol's own batches (Switch wire 6.5 "Binding")

#[tokio::test]
async fn test_submit_batch_checks_its_attempt_with_another_write() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let entry = app
        .record_op(&inbox(), Some(&value(&["working"])), vec![])
        .await
        .unwrap();
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None);
    let submitted = app
        .submit_batch(OpBatch::new().op(attempt.kind()).entry(entry))
        .await
        .unwrap();
    assert_eq!(submitted.proofs.len(), 2);
    let claim = w.switch.claim(&CLAIM).unwrap();
    assert_eq!(claim.step, 1);
}

/// An own attempt and a record write, signed by the app and sent apart from
/// [`App::submit_batch`]: the batch and its verified answer.
async fn send_apart(
    app: &mut App,
    orphan_after_s: u64,
) -> (crate::client::Batch, crate::client::Submitted) {
    let entry = app
        .record_op(&inbox(), Some(&value(&["working"])), vec![])
        .await
        .unwrap();
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, orphan_after_s, None);
    let batch = app
        .sign_ops(vec![(Vec::new(), attempt.kind()), entry], None)
        .unwrap();
    let submitted = app.submit(&batch).await.unwrap();
    (batch, submitted)
}

#[tokio::test]
async fn test_check_attempt_takes_the_proof_bound_to_its_operation() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let (batch, submitted) = send_apart(&mut app, 3600).await;
    let (op, proof) = (batch.ops()[0].signed(), submitted.proofs[0].signed());
    let view = app.check_attempt(op, proof).await.unwrap();
    assert_eq!(view.owner, Some(app.app_id()));
    assert_eq!(view.status, ClaimStatus::Attempting);
    // The record write's own proof, with the record write: not an attempt.
    let error = app
        .check_attempt(batch.ops()[1].signed(), submitted.proofs[1].signed())
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::Refused(Refusal::Usage(_))));
}

#[tokio::test]
async fn test_check_attempt_refuses_a_proof_of_another_operation() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let (batch, submitted) = send_apart(&mut app, 3600).await;
    let proof = submitted.proofs[0].signed();
    // The same attempt, orphaned after another time: another operation the switch never took.
    let other = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 1200, None);
    let unsent = app
        .sign_ops(vec![(Vec::new(), other.kind())], None)
        .unwrap();
    let error = app
        .check_attempt(unsent.ops()[0].signed(), proof)
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // The proof of the other operation in the same batch.
    let error = app
        .check_attempt(batch.ops()[0].signed(), submitted.proofs[1].signed())
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // Nothing was written: the attempt is still open, and its own proof still passes.
    assert_eq!(w.switch.claim(&CLAIM).unwrap().step, 1);
    app.check_attempt(batch.ops()[0].signed(), proof)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_check_attempt_refuses_a_proof_that_doesnt_verify() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let (batch, submitted) = send_apart(&mut app, 3600).await;
    let op = batch.ops()[0].signed();
    let genuine = &submitted.proofs[0];
    // A signature that doesn't verify.
    let mut sig = genuine.signed().sig_bytes().unwrap();
    sig[0] ^= 1;
    let tampered = SignedDoc::from_parts(&genuine.signed().body_bytes().unwrap(), &sig);
    let error = app.check_attempt(op, &tampered).await.unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // The same body, signed by another key.
    let other_key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let forged =
        TransitionProof::sign(&other_key, &w.alice.public(), genuine.body().clone()).unwrap();
    let error = app.check_attempt(op, forged.signed()).await.unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // An operation that isn't signed by the app's key.
    let mut op_sig = op.sig_bytes().unwrap();
    op_sig[0] ^= 1;
    let unsigned = SignedDoc::from_parts(&op.body_bytes().unwrap(), &op_sig);
    let error = app
        .check_attempt(&unsigned, genuine.signed())
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::Refused(Refusal::Usage(_))));
    // Nothing was written.
    assert_eq!(w.switch.claim(&CLAIM).unwrap().step, 1);
    app.check_attempt(op, genuine.signed()).await.unwrap();
}

#[tokio::test]
async fn test_check_attempt_writes_failed_for_a_bound_proof_of_another_state() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let (batch, submitted) = send_apart(&mut app, 3600).await;
    // A proof the service key signed that binds the attempt but shows the claim settled.
    let service = ed25519_dalek::SigningKey::from_bytes(&identity("alice").service_secret());
    assert_eq!(service.verifying_key().to_bytes(), w.switch.service_key());
    let mut body = submitted.proofs[0].body().clone();
    body.state["state"] = "SETTLED".into();
    let shown = TransitionProof::sign(&service, &w.alice.public(), body).unwrap();
    let error = app
        .check_attempt(batch.ops()[0].signed(), shown.signed())
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // Written failed after the attempt.
    let claim = w.switch.claim(&CLAIM).unwrap();
    assert_eq!(claim.step, 2);
}

/// Stop `app` on equivocation: another body at the version of its own `identity.json`.
async fn stop_on_equivocation(w: &World, app: &mut App) {
    let doc = w.next_doc(|_| {});
    app.receive(None).await.unwrap();
    let mut body = doc.body().clone();
    body.data_epoch += 1;
    w.switch
        .deliver_identity(&IdentityDoc::sign(&w.alice, body).unwrap())
        .unwrap();
    let error = app.receive(None).await.unwrap_err();
    assert!(matches!(error, AppError::Alarm(_)), "{error:?}");
    assert_eq!(app.may_attempt(false), Err(Refusal::Stopped));
}

#[tokio::test]
async fn test_check_attempt_refuses_a_stopped_app() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let (batch, submitted) = send_apart(&mut app, 3600).await;
    stop_on_equivocation(&w, &mut app).await;
    let op = batch.ops()[0].signed();
    // The genuine proof isn't taken.
    let error = app
        .check_attempt(op, submitted.proofs[0].signed())
        .await
        .unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::Stopped));
    // Nor is a proof of another state, and nothing is written failed.
    let service = ed25519_dalek::SigningKey::from_bytes(&identity("alice").service_secret());
    let mut body = submitted.proofs[0].body().clone();
    body.state["state"] = "SETTLED".into();
    let shown = TransitionProof::sign(&service, &w.alice.public(), body).unwrap();
    let error = app.check_attempt(op, shown.signed()).await.unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::Stopped));
    assert_eq!(w.switch.claim(&CLAIM).unwrap().step, 1);
}

#[tokio::test]
async fn test_record_op_and_key_fetch_refuse_a_stopped_app() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    app.record_op(&inbox(), Some(&value(&["a"])), vec![])
        .await
        .unwrap();
    app.fetch_key_bundle().await.unwrap();
    stop_on_equivocation(&w, &mut app).await;
    let error = app
        .record_op(&inbox(), Some(&value(&["a"])), vec![])
        .await
        .unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::Stopped));
    let error = app
        .put_record(&inbox(), &value(&["a"]), vec![])
        .await
        .unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::Stopped));
    assert_eq!(
        app.fetch_key_bundle().await.unwrap_err(),
        AppError::Refused(Refusal::Stopped)
    );
}

#[tokio::test]
async fn test_submit_batch_refuses_an_attempt_in_reconcile_mode() {
    let w = World::new();
    let app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    let backup = app.backup().await.unwrap();
    let mut app = App::restore(
        w.env_on(Arc::new(MemoryStore::new())),
        ApiProtocol::new(Mode::Plain),
        config(),
        &backup,
    )
    .await
    .unwrap();
    let attempt = ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None);
    let error = app
        .submit_batch(
            OpBatch::new()
                .op(OpKind::DenyPut { pubky: [9; 32] })
                .op(attempt.kind()),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::NotNow(_))),
        "{error:?}"
    );
    assert!(w.switch.claim(&CLAIM).is_none());
}

// -------------------------------------------------------------------------------------
// The highest verified service time (Switch spec 10.1)

#[tokio::test]
async fn test_highest_service_time_follows_verified_answers() {
    let w = World::new();
    let mut app = join(&w, &ApiProtocol::new(Mode::Plain), "wallet").await;
    assert_eq!(app.highest_service_time(), Some(START));
    w.clock.advance_ms(MINUTE);
    app.receive(None).await.unwrap();
    assert_eq!(app.highest_service_time(), Some(START + MINUTE));
    // A restored app has verified nothing yet.
    let backup = app.backup().await.unwrap();
    let restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new())),
        ApiProtocol::new(Mode::Plain),
        config(),
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(restored.highest_service_time(), None);
}

// -------------------------------------------------------------------------------------
// A policy per sub-scope (Switch spec 3.3, 10.3)

fn family() -> Collection {
    Collection::with_sub_scopes("sample.items", Policy::new("scope-a", &["scope-a"]))
}

#[tokio::test]
async fn test_policy_family_lists_and_takes_a_sub_scope_record() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    *protocol.collections.lock().unwrap() = vec![family()];
    let mut wallet = join(&w, &protocol, "wallet").await;
    let mut kiosk = join_on(
        &w,
        &protocol,
        "kiosk",
        &["scope-a:kiosk"],
        Arc::new(MemoryStore::new()),
    )
    .await;
    let target = RecordTarget::new(family().sub_scope("kiosk").unwrap(), b"k1");
    let written = kiosk
        .put_record(&target, &value(&["first"]), vec![])
        .await
        .unwrap();
    assert_eq!(written.policy, family().sub_scope_policy("kiosk").unwrap());
    // Listed by the name scope's holder, under the family.
    assert_eq!(wallet.list_collection(&family()).await.unwrap().records, 1);
    let held = wallet.records_of("sample.items").await.unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(ids(held[0].content.value()), vec!["first".to_owned()]);
    assert!(wallet.flagged_writes().await.unwrap().is_empty());
    // And from the feed, by a later write.
    kiosk
        .put_record(&target, &value(&["first", "second"]), vec![])
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let key = wallet.record_key(&target).unwrap();
    let record = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()).len(), 2);
}

#[tokio::test]
async fn test_policy_family_fixed_collection_flags_a_sub_scope_record() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = join(&w, &protocol, "wallet").await;
    let mut kiosk = join_on(
        &w,
        &protocol,
        "kiosk",
        &["scope-a:kiosk"],
        Arc::new(MemoryStore::new()),
    )
    .await;
    let target = RecordTarget::new(family().sub_scope("kiosk").unwrap(), b"k1");
    kiosk
        .put_record(&target, &value(&["first"]), vec![])
        .await
        .unwrap();
    // The fixed policy alone: the sub-scope's write isn't the collection's.
    assert_eq!(wallet.list_collection(&items()).await.unwrap().records, 1);
    assert!(wallet.records_of("sample.items").await.unwrap().is_empty());
    let flagged = wallet.flagged_writes().await.unwrap();
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].reason.contains("step 3"), "{flagged:?}");
}

#[test]
fn test_policy_family_members_follow_the_scope_rule() {
    let family = Collection {
        name: "c".into(),
        policy: Policy::new("name", &["name", "other"]),
        family: PolicyFamily::SubScopes,
    };
    let sub = family.sub_scope_policy("shop").unwrap();
    assert_eq!(sub, Policy::new("name:shop", &["name:shop", "other"]));
    assert_eq!(family.member(&sub), Some(Some("shop".into())));
    assert_eq!(family.member(&family.policy), Some(None));
    // Not members: another name's sub-scope, another write scope, a bad sub-scope.
    assert!(!family.admits(&Policy::new("else:shop", &["else:shop", "other"])));
    assert!(!family.admits(&Policy::new("name:shop", &["name:shop"])));
    assert!(family.sub_scope_policy("Bad Sub").is_err());
    // A fixed collection has no sub-scope policies.
    let fixed = Collection::new("c", Policy::new("name", &["name"]));
    assert!(fixed.sub_scope_policy("shop").is_err());
    assert!(!fixed.admits(&Policy::new("name:shop", &["name:shop"])));
    // Nor does a family whose fixed read scope is a sub-scope itself.
    let nested = Collection::with_sub_scopes("c", Policy::new("name:x", &["name:x"]));
    assert!(nested.sub_scope_policy("shop").is_err());
}

#[test]
fn test_policy_family_readable_by_a_sub_scope_holder() {
    let alice = identity("alice");
    let sub = cert_for(alice.key(), &app_keys("kiosk"), START, &["scope-a:kiosk"]);
    let other = cert_for(alice.key(), &app_keys("other"), START, &["scope-b"]);
    assert!(family().readable_by(&sub));
    assert!(!items().readable_by(&sub));
    assert!(!family().readable_by(&other));
}

// -------------------------------------------------------------------------------------
// Two identities, each on its own scripted switch (Switch spec 7; Switch wire 7.4.3)

/// Alice, bob and carol, each with a signer and a scripted switch at an origin of its own,
/// a router between them, and one Homeserver.
pub(super) struct Pair {
    pub(super) clock: Arc<crate::clock::TestClock>,
    pub(super) alice: TestSigner,
    pub(super) bob: TestSigner,
    pub(super) carol: TestSigner,
    pub(super) router: Arc<Router>,
}

impl Pair {
    pub(super) fn new() -> Self {
        let clock = Arc::new(crate::clock::TestClock::new(START));
        let homeserver = Arc::new(TestHomeserver::new());
        let signer = |name: &str, origin: &str| {
            TestSigner::at(
                identity(name),
                origin,
                Arc::clone(&clock),
                Arc::clone(&homeserver),
                sample_spec(),
            )
        };
        let alice = signer("alice", SWITCH_ORIGIN);
        let bob = signer("bob", BOB_ORIGIN);
        let carol = signer("carol", CAROL_ORIGIN);
        let router = Arc::new(Router::new());
        router.add_switch(SWITCH_ORIGIN, alice.switch());
        router.add_switch(BOB_ORIGIN, bob.switch());
        router.add_switch(CAROL_ORIGIN, carol.switch());
        Self {
            clock,
            alice,
            bob,
            carol,
            router,
        }
    }

    pub(super) async fn join_on(
        &self,
        signer: &TestSigner,
        name: &str,
        protocol: Arc<dyn Protocol>,
        store: Arc<dyn StateStore>,
    ) -> App {
        self.join_with(signer, name, protocol, store, &Permission::ALL)
            .await
    }

    /// `name` of `signer`'s identity on `store`, with `permissions`.
    async fn join_with(
        &self,
        signer: &TestSigner,
        name: &str,
        protocol: Arc<dyn Protocol>,
        store: Arc<dyn StateStore>,
        permissions: &[Permission],
    ) -> App {
        let keys = signer.identity().app_keys(name);
        let app = AppSpec::new(&["scope-a"]).with_permissions(permissions);
        let request = signer.approve(&keys, &app).unwrap();
        App::join(self.env(signer, store), protocol, config(), request)
            .await
            .unwrap()
    }

    fn env(&self, signer: &TestSigner, store: Arc<dyn StateStore>) -> AppEnv {
        signer.env_with(store, Arc::clone(&self.router) as Arc<dyn Transport>)
    }

    async fn join(&self, signer: &TestSigner, name: &str, protocol: &Arc<ApiProtocol>) -> App {
        self.join_on(signer, name, protocol.clone(), Arc::new(MemoryStore::new()))
            .await
    }

    pub(super) fn note(to: &TestSigner, text: &str) -> OutgoingMessage {
        let mut body = Map::new();
        body.insert("text".into(), json!(text));
        OutgoingMessage::new(to.identity().public(), "sample.note", body)
    }
}

fn queued_with(delivery: &Delivery, code: &str) -> bool {
    matches!(delivery, Delivery::Queued { last_error: Some(e), .. } if e.contains(code))
}

#[tokio::test]
async fn test_scripted_inbox_refuses_a_sender_not_admitted() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    let (_, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(queued_with(&delivery, "not_admitted"), "{delivery:?}");
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

#[tokio::test]
async fn test_outbox_try_too_large_for_the_store_gives_the_message_up() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()),
        StoreFault::None,
    ));
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::clone(&store) as Arc<dyn StateStore>,
        )
        .await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(queued_with(&delivery, "not_admitted"), "{delivery:?}");
    wallet.take_events();
    // Every write of the message is now over the store's sizes: no try can be kept.
    store.refuse_puts_as_too_large(Some(b"out/"));
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![msg_id.clone()]);
    assert!(
        wallet.take_events().iter().any(|e| matches!(
            e,
            AppEvent::MessageUndelivered { msg_id: m, resend: false, .. } if *m == msg_id
        )),
        "the protocol is told"
    );
    // Given up for good: later flushes go on, and don't try it again.
    let appends = p.bob.switch().entries_from(&p.alice.identity().public());
    let report = wallet.flush_outbox().await.unwrap();
    assert!(
        report.queued.is_empty() && report.undelivered.is_empty(),
        "{report:?}"
    );
    assert_eq!(wallet.delivery(&msg_id).await.unwrap(), None);
    assert_eq!(
        p.bob.switch().entries_from(&p.alice.identity().public()),
        appends
    );
}

#[tokio::test]
async fn test_outbox_message_too_large_for_the_store_holds_up_no_later_one() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()),
        StoreFault::None,
    ));
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::clone(&store) as Arc<dyn StateStore>,
        )
        .await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let (first, _) = wallet.send(Pair::note(&p.bob, "first")).await.unwrap();
    let (second, _) = wallet.send(Pair::note(&p.bob, "second")).await.unwrap();
    // Only the first message's own writes are over the store's sizes now.
    store.refuse_puts_as_too_large(Some(format!("out/{first}").as_bytes()));
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![first.clone()]);
    // The flush went on to the later message, which is delivered.
    assert_eq!(report.done, vec![second.clone()], "{report:?}");
    assert!(matches!(
        wallet.delivery(&second).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
}

#[tokio::test]
async fn test_send_to_a_directory_too_large_to_cache_goes_and_caches_its_stub() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()),
        StoreFault::None,
    ));
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::clone(&store) as Arc<dyn StateStore>,
        )
        .await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    // Bob's directory doesn't fit one value of the wallet's store; its stub does.
    store.refuse_puts_as_too_large_over(Some(b"dir/"), 1024);
    let reads = directory_reads(&p);
    for text in ["one", "two"] {
        let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, text)).await.unwrap();
        assert!(
            matches!(delivery, Delivery::Accepted { .. }),
            "{delivery:?}"
        );
        assert!(matches!(
            wallet.delivery(&msg_id).await.unwrap(),
            Some(Delivery::Accepted { .. })
        ));
    }
    // Only its stub cached, with no apps and stale: each send read it again.
    assert_eq!(directory_reads(&p), reads + 2);
    let ns = crate::store::client_namespace(&wallet.app_id());
    let kept = store.inner().scan(&ns, b"dir/", None, 10).unwrap();
    assert_eq!(kept.len(), 1);
    let stub: crate::app::directory::CachedDirectory =
        crate::app::state::decode(&kept[0].1).unwrap();
    assert!(stub.apps.is_empty() && stub.stale);
}

/// Alice's wallet on a [`FaultStore`] over a new store, and bob's shop admitting her.
async fn wallet_on_a_fault_store(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
) -> (App, App, Arc<FaultStore>) {
    let store = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()),
        StoreFault::None,
    ));
    let wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::clone(&store) as Arc<dyn StateStore>,
        )
        .await;
    let mut shop = p.join(&p.bob, "shop", protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    (wallet, shop, store)
}

#[tokio::test]
async fn test_outbox_give_up_of_an_accepted_message_keeps_its_owed_record_job() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target: target.clone(),
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    // Accepted, its record job failing for now (its batch, after the conversation entry's,
    // can't reach the switch): kept, the record job owed.
    let unreachable = |after| Fault::Unreachable {
        path: "ops".into(),
        after,
    };
    p.alice.switch().fail_next(unreachable(1));
    wallet.flush_outbox().await.unwrap();
    assert!(matches!(
        wallet.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
    // The next try's own write is too large: only the re-send is given up.
    p.alice.switch().lock().faults.clear();
    p.alice.switch().fail_next(unreachable(0));
    store.refuse_puts_as_too_large_once(format!("out/{msg_id}").as_bytes());
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![msg_id.clone()]);
    assert!(wallet.take_events().iter().any(|e| matches!(
        e,
        AppEvent::MessageUndelivered { msg_id: m, resend: true, .. } if *m == msg_id
    )));
    assert!(matches!(
        wallet.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Accepted { .. })
    ));
    // Its outbox record stays while the record job is owed, as `drop_undeliverable` keeps it.
    let ns = crate::store::client_namespace(&wallet.app_id());
    let out = format!("out/{msg_id}");
    assert!(store.inner().get(&ns, out.as_bytes()).unwrap().is_some());
    // Its record job is still made.
    p.alice.switch().lock().faults.clear();
    wallet.flush_outbox().await.unwrap();
    let key = wallet.record_key(&target).unwrap();
    let record = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()), vec![msg_id]);
}

/// A record job whose try left its batch kept, and that is given up at the sent retention,
/// names that batch in its duty event: it may still apply, and its end tells.
#[tokio::test]
async fn test_outbox_record_job_given_up_names_the_batch_it_left_kept() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, _store) = wallet_on_a_fault_store(&p, &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target,
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    // Accepted; the record job's batch, after the conversation entry's, is kept unsent.
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 1,
    });
    wallet.flush_outbox().await.unwrap();
    let Some(Delivery::Accepted { accepted_at_ms }) = wallet.delivery(&msg_id).await.unwrap()
    else {
        panic!("accepted");
    };
    let kept = wallet.kept_batches().await.unwrap();
    assert_eq!(kept.len(), 1);
    let batch_id = kept[0].0;
    // At the retention the kept batch is past its window, and the job is given up.
    p.alice.switch().lock().faults.clear();
    for _ in 0..8 {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
    }
    p.clock
        .set_ms(accepted_at_ms + crate::app::SENT_RETENTION_MS);
    wallet.flush_outbox().await.unwrap();
    // A flush sends no kept batch itself: the next read does, and past its window drops it.
    wallet.receive(None).await.unwrap();
    let events = wallet.unacknowledged_events().await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            e,
            AppEvent::RecordJobDropped { msg_id: m, batch_id: Some(b), .. }
                if *m == msg_id && *b == batch_id
        )),
        "{events:?}"
    );
    // Its end tells what became of it: sent once, then past the window a resend tells in.
    assert!(matches!(
        wallet.kept_batch(batch_id).await.unwrap(),
        Some(crate::app::KeptBatchStatus::Dropped {
            reason: crate::app::KeptBatchDrop::Uncertain,
            ..
        })
    ));
}

#[tokio::test]
async fn test_outbox_give_up_reads_state_again_before_going_on() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    // Queued: bob's switch can't be reached.
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    // Queued for the network, not for admission: no time of a first `403 not_admitted`.
    assert!(
        matches!(
            delivery,
            Delivery::Queued {
                undeliverable_since_ms: None,
                undeliverable_reason: None,
                ..
            }
        ),
        "{delivery:?}"
    );
    p.bob.switch().lock().faults.clear();
    // The next try's own write is refused as too large: given up.
    store.refuse_puts_as_too_large_once(format!("out/{msg_id}").as_bytes());
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![msg_id]);
    // The refused commit was read past: what the app holds is the store's again, so a
    // backup, only ever of committed state, is given at once.
    assert!(
        wallet.backup().await.is_ok(),
        "{:?}",
        wallet.backup().await.err()
    );
}

#[tokio::test]
async fn test_send_after_a_recipients_provider_loss_resends_with_a_directory_too_large_to_cache() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    // Bob's directory is over what the wallet's store keeps: only its stub is cached.
    store.refuse_puts_as_too_large_over(Some(b"dir/"), 1024);
    let (first, delivery) = wallet.send(Pair::note(&p.bob, "one")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    // Bob loses his provider and recovers at another.
    const RECOVERED: &str = "https://bob-recovered.example";
    let recovered =
        ScriptedSwitch::recovering(p.bob.identity().key(), [9; 32], Arc::clone(&p.clock), 2, 1)
            .unwrap();
    p.router.add_switch(RECOVERED, &recovered);
    let doc = p
        .bob
        .sign_next(|body| {
            body.generation = 2;
            body.inbox = Inbox::new(RECOVERED, recovered.service_key());
            body.recovery_from = Some(1);
        })
        .unwrap();
    recovered.deliver_identity(&doc).unwrap();
    // Bob's contacts came back with his recovery: alice is admitted there.
    recovered
        .lock()
        .shared
        .add_contact(p.alice.identity().public());
    p.clock.advance_ms(DOC_CACHE_MS + MINUTE);
    wallet.take_events();
    let _ = wallet.send(Pair::note(&p.bob, "two")).await;
    // The stub held the switch and generation the directory was read under: the loss is
    // found, and what bob's lost switch accepted is sent again.
    assert!(
        wallet.take_events().iter().any(|e| matches!(
            e,
            AppEvent::ResendAfterLoss { identity, messages: 1 } if *identity == p.bob.identity().public()
        )),
        "the re-send after the loss"
    );
    assert!(wallet.delivery(&first).await.unwrap().is_some());
}

#[tokio::test]
async fn test_scripted_inbox_admits_after_an_invite_and_delivers() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    let alice = p.alice.identity().public();
    assert_eq!(
        p.bob.switch().peer_copy(&alice).unwrap().version(),
        wallet.own_identity().version()
    );
    // A retry of the same bytes gets the original answer, and no second entry. The entry is
    // counted before its reader passes it, which is when the switch lets it go.
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    shop.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert_eq!(seen.last().unwrap().msg_id, msg_id);
}

#[tokio::test]
async fn test_scripted_inbox_invite_code_admits_once_with_its_context() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let code = shop
        .register_invite_code(START + DAY_MS, 1, json!({ "order": "o-1" }))
        .await
        .unwrap();
    let mut first = Pair::note(&p.bob, "order");
    first.invite_code = Some(code.code.clone());
    let (_, delivery) = wallet.send(first).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert_eq!(p.bob.switch().invite_uses_left(&code.code), Some(0));
    shop.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert_eq!(
        seen.last().unwrap().context,
        Some(json!({ "order": "o-1" }))
    );
    // The service's conversation entry admits the sender from then on, without the code.
    let (_, delivery) = wallet.send(Pair::note(&p.bob, "again")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    // A code used up admits nobody else.
    let mut carol_app = p.join(&p.carol, "phone", &protocol).await;
    let mut late = Pair::note(&p.bob, "late");
    late.invite_code = Some(code.code);
    let (_, delivery) = carol_app.send(late).await.unwrap();
    assert!(queued_with(&delivery, "not_admitted"), "{delivery:?}");
}

#[tokio::test]
async fn test_scripted_inbox_stale_key_names_an_app_added_since() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    wallet.send(Pair::note(&p.bob, "one")).await.unwrap();
    // Bob adds an app; alice's cached directory predates it.
    let mut kiosk = p.join(&p.bob, "kiosk", &protocol).await;
    let appends_before = inbox_appends(&p);
    let (second, delivery) = wallet.send(Pair::note(&p.bob, "two")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    // Refused with the app's records, sealed again, accepted.
    assert_eq!(inbox_appends(&p) - appends_before, 2);
    kiosk.receive(None).await.unwrap();
    assert!(protocol.seen().iter().any(|s| s.msg_id == second));
}

fn inbox_appends(p: &Pair) -> usize {
    p.router
        .log()
        .iter()
        .filter(|line| line.starts_with(&format!("POST {BOB_ORIGIN}")) && line.contains("/inbox"))
        .count()
}

fn directory_reads(p: &Pair) -> usize {
    p.router
        .log()
        .iter()
        .filter(|line| {
            line.starts_with(&format!("GET {BOB_ORIGIN}")) && line.contains("/directory")
        })
        .count()
}

#[tokio::test]
async fn test_stale_key_answer_missing_a_member_reads_the_directory_again() {
    let members = [
        "receive_keys",
        "not_current",
        "unknown_kids",
        "added_apps",
        "apps_version",
    ];
    for member in members {
        for null in [false, true] {
            let p = Pair::new();
            let protocol = ApiProtocol::new(Mode::Plain);
            let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
            let mut shop = p.join(&p.bob, "shop", &protocol).await;
            shop.invite(&p.alice.identity().public()).await.unwrap();
            wallet.send(Pair::note(&p.bob, "one")).await.unwrap();
            let mut current = json!({
                "receive_keys": [], "not_current": [], "unknown_kids": [], "added_apps": [],
                "apps_version": 1,
            });
            if null {
                current[member] = Value::Null;
            } else {
                current.as_object_mut().unwrap().remove(member);
            }
            p.bob.switch().fail_next(Fault::Error {
                path: "/inbox".into(),
                code: ErrorCode::StaleKey,
                current,
            });
            let reads = directory_reads(&p);
            let (_, delivery) = wallet.send(Pair::note(&p.bob, "two")).await.unwrap();
            assert!(
                matches!(delivery, Delivery::Accepted { .. }),
                "{member}, null {null}: {delivery:?}"
            );
            // Nothing taken from the answer: sealed again for the directory read again.
            assert_eq!(directory_reads(&p), reads + 1, "{member}, null {null}");
        }
    }
}

#[tokio::test]
async fn test_scripted_inbox_identity_needed_delivers_the_copy_again() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    wallet.send(Pair::note(&p.bob, "one")).await.unwrap();
    let alice = p.alice.identity().public();
    p.bob.switch().forget_peer_copy(&alice);
    let (_, delivery) = wallet.send(Pair::note(&p.bob, "two")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert!(p.bob.switch().peer_copy(&alice).is_some());
    assert_eq!(p.bob.switch().entries_from(&alice), 2);
}

#[tokio::test]
async fn test_scripted_inbox_connect_requests_follow_the_policy() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    let bob = p.bob.identity().public();
    let alice = p.alice.identity().public();
    // Off by default: a stranger can't ask.
    let error = wallet.ask_to_connect(&bob).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotAdmitted));
    assert!(p.bob.switch().connects().is_empty());
    // On: the stranger's document is taken and its request kept, once.
    p.bob
        .next_doc(|body| body.policy.connect_requests.enabled = true)
        .unwrap();
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert_eq!(p.bob.switch().connects(), vec![alice]);
    assert!(p.bob.switch().peer_copy(&alice).is_some());
}

#[tokio::test]
async fn test_scripted_inbox_connect_requests_full_refuse_before_the_deny_list() {
    // At `max_pending` 0 the list is always full: `429 quota_exceeded` naming connect
    // requests, the same for a denied sender, as at the service (Switch wire 7.4.7).
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let bob = p.bob.identity().public();
    let alice = p.alice.identity().public();
    p.bob
        .next_doc(|body| {
            body.policy.connect_requests.enabled = true;
            body.policy.connect_requests.max_pending = 0;
        })
        .unwrap();
    let error = wallet.ask_to_connect(&bob).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::QuotaExceeded));
    p.bob.switch().lock().shared.deny.insert(alice);
    let denied = wallet.ask_to_connect(&bob).await.unwrap_err();
    assert_eq!(denied.code(), Some(ErrorCode::QuotaExceeded));
    let list = shop.connect_requests().await.unwrap();
    assert_eq!((list.max_pending, list.full), (0, true));
    assert!(p.bob.switch().connects().is_empty());
}

#[tokio::test]
async fn test_scripted_inbox_connect_request_of_a_denied_sender_is_pending_and_not_kept() {
    // A denied sender is answered as anyone else, and its request isn't kept.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let bob = p.bob.identity().public();
    p.bob
        .next_doc(|body| body.policy.connect_requests.enabled = true)
        .unwrap();
    p.bob
        .switch()
        .lock()
        .shared
        .deny
        .insert(p.alice.identity().public());
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(p.bob.switch().connects().is_empty());
    let list = shop.connect_requests().await.unwrap();
    assert_eq!((list.max_pending, list.full), (50, false));
}

#[tokio::test]
async fn test_scripted_inbox_connect_requests_full_keep_the_one_waiting() {
    // At `max_pending` 1 the one waiting fills the list, stays, and asking again is
    // answered pending.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let bob = p.bob.identity().public();
    p.bob
        .next_doc(|body| {
            body.policy.connect_requests.enabled = true;
            body.policy.connect_requests.max_pending = 1;
        })
        .unwrap();
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(shop.connect_requests().await.unwrap().full);
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert_eq!(p.bob.switch().connects(), vec![p.alice.identity().public()]);
}

#[tokio::test]
async fn test_scripted_inbox_connect_request_is_answered_by_each_entry_and_a_decline() {
    // As at the service: a contact, a conversation entry, a deny list entry, a decline and
    // the conversation entry an invite code's first append writes each answer the request;
    // a sender the lists admit asks without a request kept.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let bob = p.bob.identity().public();
    let alice = p.alice.identity().public();
    p.bob
        .next_doc(|body| body.policy.connect_requests.enabled = true)
        .unwrap();
    let asked = |p: &Pair| p.bob.switch().connects() == vec![alice];
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(asked(&p));
    shop.add_contact(&alice).await.unwrap();
    assert!(p.bob.switch().connects().is_empty(), "a contact");
    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(
        p.bob.switch().connects().is_empty(),
        "admitted: nothing kept"
    );
    shop.remove_contact(&alice).await.unwrap();

    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(asked(&p));
    shop.invite(&alice).await.unwrap();
    assert!(p.bob.switch().connects().is_empty(), "a conversation entry");
    shop.remove_conversation(&alice).await.unwrap();

    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(asked(&p));
    shop.deny(&alice).await.unwrap();
    assert!(p.bob.switch().connects().is_empty(), "a deny list entry");
    shop.undeny(&alice).await.unwrap();

    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(asked(&p));
    shop.decline_connect(&alice).await.unwrap();
    assert!(p.bob.switch().connects().is_empty(), "a decline");

    assert!(wallet.ask_to_connect(&bob).await.unwrap());
    assert!(asked(&p));
    let code = shop
        .register_invite_code(START + DAY_MS, 1, json!({ "order": "o-1" }))
        .await
        .unwrap();
    let mut first = Pair::note(&p.bob, "order");
    first.invite_code = Some(code.code.clone());
    let (_, delivery) = wallet.send(first).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert!(
        p.bob.switch().connects().is_empty(),
        "an invite code's entry"
    );
}

#[tokio::test]
async fn test_scripted_inbox_takes_own_apps_kinds_between_them() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut phone = p.join(&p.alice, "phone", &protocol).await;
    let mut body = Map::new();
    body.insert("text".into(), json!("to my other app"));
    let notice = OutgoingMessage::new(p.alice.identity().public(), "sample.notice", body);
    // The wallet's own identity.json predates the phone: the own directory brings the newer
    // one, which lists it.
    assert!(wallet.own_identity().listed_cert(&phone.app_id()).is_none());
    let (msg_id, delivery) = wallet.send(notice).await.unwrap();
    assert!(wallet.own_identity().listed_cert(&phone.app_id()).is_some());
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    phone.receive(None).await.unwrap();
    assert!(protocol.seen().iter().any(|s| s.msg_id == msg_id));
    // The sending app isn't among the targets: its own copy isn't in its feed.
    let before = protocol.seen().len();
    wallet.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), before);
}

// -------------------------------------------------------------------------------------
// Messages signed before they are queued (Switch spec 8.2, 11)

#[tokio::test]
async fn test_signed_message_queued_with_the_record_built_from_its_hash() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    // Nothing is kept by signing.
    assert!(wallet.delivery(signed.msg_id()).await.unwrap().is_none());
    let target = RecordTarget::new(items(), &signed.hash());
    let entry = wallet
        .record_op(&target, Some(&value(&[signed.msg_id()])), vec![])
        .await
        .unwrap();
    wallet
        .submit_batch(OpBatch::new().entry(entry).queue(signed.clone()))
        .await
        .unwrap();
    // Queued with the batch's answer, the record written in it.
    assert!(matches!(
        wallet.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { tries: 0, .. })
    ));
    let key = wallet.record_key(&target).unwrap();
    assert!(wallet.shared_record(&key).await.unwrap().is_some());
    let delivery = wallet.flush_message(signed.msg_id()).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Accepted { .. })),
        "{delivery:?}"
    );
    shop.receive(None).await.unwrap();
    assert!(protocol.seen().iter().any(|s| s.msg_id == signed.msg_id()));
}

#[tokio::test]
async fn test_signed_message_not_queued_when_its_batch_is_refused() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let key = wallet.record_key(&target).unwrap();
    let wrong = Condition::RecordVersion {
        key,
        version: RecordVersion::new(1, 99),
    };
    let entry = wallet
        .record_op(&target, Some(&value(&["x"])), vec![wrong])
        .await
        .unwrap();
    let error = wallet
        .submit_batch(OpBatch::new().entry(entry).queue(signed.clone()))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    // Never queued: its batch was refused, at this time.
    let delivery = wallet.delivery(signed.msg_id()).await.unwrap();
    assert!(
        matches!(
            &delivery,
            Some(Delivery::Failed { reason, failed_at_ms })
                if reason.contains("conflict") && *failed_at_ms == p.clock.now_ms()
        ),
        "{delivery:?}"
    );
    // The same signed message goes in the batch built again.
    let entry = wallet
        .record_op(&target, Some(&value(&["x"])), vec![])
        .await
        .unwrap();
    wallet
        .submit_batch(OpBatch::new().entry(entry).queue(signed.clone()))
        .await
        .unwrap();
    assert!(matches!(
        wallet.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. } | Delivery::Accepted { .. })
    ));
}

#[tokio::test]
async fn test_signed_message_record_job_from_its_own_hash() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let signed = signed.with_record(RecordJob {
        target: target.clone(),
        tag: b"sent".to_vec(),
    });
    let msg_id = wallet.queue_signed(signed.clone()).await.unwrap();
    // Queued once: queueing it again changes nothing.
    assert_eq!(wallet.queue_signed(signed).await.unwrap(), msg_id);
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()]);
    let key = wallet.record_key(&target).unwrap();
    let record = wallet.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()), vec![msg_id]);
}

#[tokio::test]
async fn test_signed_message_of_another_app_is_refused() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut phone = p.join(&p.alice, "phone", &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let error = phone.queue_signed(signed).await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error:?}"
    );
}

/// The signed plaintext a record of [`items`] stores, as [`stored_value`] wrote it.
fn stored_plaintext(record: Option<&[u8]>) -> MessagePlaintext {
    let text = ids(record).pop().unwrap();
    MessagePlaintext::decode(&pubky_switch_core::enc::unb64(&text).unwrap()).unwrap()
}

/// A record value of [`items`] that stores the signed plaintext of `signed`.
fn stored_value(signed: &SignedMessage) -> Vec<u8> {
    value(&[&pubky_switch_core::enc::b64(&signed.plaintext().encode())])
}

/// Switch spec 11 "Queued again by its signer": a batch writing a record that stores a
/// message, and queueing it, is applied but its answer lost; a backup taken while it is
/// kept doesn't carry it, so the restored app's outbox doesn't hold the message though its
/// record does. Queued again from the record's plaintext, it is delivered once, with the
/// same `msg_id` and bytes.
#[tokio::test]
async fn test_queue_stored_restored_app_delivers_a_kept_batchs_message_once() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let target = RecordTarget::new(items(), &signed.hash());
    let entry = wallet
        .record_op(&target, Some(&stored_value(&signed)), vec![])
        .await
        .unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let error = wallet
        .submit_batch(OpBatch::new().entry(entry).queue(signed.clone()))
        .await
        .unwrap_err();
    assert!(error.kept_batch().is_some(), "{error:?}");
    assert!(matches!(
        wallet.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Kept { .. })
    ));
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let mut restored = App::restore(
        p.env(&p.alice, Arc::new(MemoryStore::new())),
        protocol.clone(),
        config(),
        &backup,
    )
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    // The record holds the message; no outbox does, and nothing delivered it.
    assert_eq!(restored.delivery(signed.msg_id()).await.unwrap(), None);
    let key = restored.record_key(&target).unwrap();
    let record = restored.shared_record(&key).await.unwrap().unwrap();
    let plaintext = stored_plaintext(record.content.value());
    assert_eq!(plaintext, *signed.plaintext());
    let alice = p.alice.identity().public();
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    let msg_id = restored.queue_stored(&plaintext).await.unwrap();
    assert_eq!(msg_id, signed.msg_id());
    let delivery = restored.flush_message(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Accepted { .. })),
        "{delivery:?}"
    );
    // Queued again, it is left as it is: sent, it goes once.
    assert_eq!(restored.queue_stored(&plaintext).await.unwrap(), msg_id);
    restored.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    shop.receive(None).await.unwrap();
    let seen: Vec<Seen> = protocol
        .seen()
        .into_iter()
        .filter(|s| s.msg_id == msg_id)
        .collect();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].hash, signed.hash());
}

/// Only a message this app signed is queued again: one another app of the identity
/// signed, one of another identity, one naming another App ID in its plaintext or another
/// app or identity in `from` though this app's key signed it, and one whose signature
/// isn't this app's are refused, and nothing is queued.
#[tokio::test]
async fn test_queue_stored_refuses_a_message_this_app_didnt_sign() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let phone = p.join(&p.alice, "phone", &protocol).await;
    let shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let other_app = phone
        .sign_message(Pair::note(&p.bob, "hello"))
        .unwrap()
        .plaintext()
        .clone();
    let other_identity = shop
        .sign_message(Pair::note(&p.alice, "hello"))
        .unwrap()
        .plaintext()
        .clone();
    let keys = p.alice.identity().app_keys("wallet");
    let mut body = Map::new();
    body.insert("text".into(), json!("hello"));
    let from_other = Message::new(
        "sample.note",
        Sender {
            identity: p.bob.identity().public(),
            app_id: keys.app_id_bytes(),
        },
        p.bob.identity().public(),
        p.clock.now_ms(),
        vec![],
        body,
    )
    .unwrap()
    .sign(&keys)
    .unwrap();
    let own = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let forged = MessagePlaintext::from_parts(
        own.plaintext().sender_app_id(),
        other_app.signature(),
        own.plaintext().json().to_vec(),
    )
    .unwrap();
    let other_app_id = MessagePlaintext::from_parts(
        phone.app_id(),
        own.plaintext().signature(),
        own.plaintext().json().to_vec(),
    )
    .unwrap();
    let mut body = Map::new();
    body.insert("text".into(), json!("hello"));
    let json = Message::new(
        "sample.note",
        Sender {
            identity: alice,
            app_id: phone.app_id(),
        },
        p.bob.identity().public(),
        p.clock.now_ms(),
        vec![],
        body,
    )
    .unwrap()
    .to_json()
    .unwrap();
    let bob = p.bob.identity().public();
    let signature = keys.sign(pubky_switch_core::labels::sig::MSG, &[&bob, &json]);
    let from_other_app =
        MessagePlaintext::from_parts(keys.app_id_bytes(), signature, json).unwrap();
    for (name, plaintext) in [
        ("another app", other_app),
        ("another identity", other_identity),
        ("another App ID in the plaintext", other_app_id),
        ("from another app", from_other_app),
        ("from another identity", from_other),
        ("another signature", forged),
    ] {
        let error = wallet.queue_stored(&plaintext).await.unwrap_err();
        assert!(
            matches!(error, AppError::Refused(Refusal::Usage(_))),
            "{name}: {error:?}"
        );
        let msg_id = Message::parse(plaintext.json(), &[]).unwrap().msg_id;
        assert_eq!(wallet.delivery(&msg_id).await.unwrap(), None, "{name}");
    }
    assert_eq!(
        wallet.flush_outbox().await.unwrap().done,
        Vec::<String>::new()
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
}

/// A message the outbox holds, or that was sent, is left as it is: queued again it isn't
/// queued twice, and goes once.
#[tokio::test]
async fn test_queue_stored_leaves_a_message_the_outbox_holds_or_sent() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    // Queued: the recipient doesn't admit the sender yet.
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let plaintext = signed.plaintext().clone();
    let msg_id = wallet.queue_signed(signed).await.unwrap();
    let delivery = wallet.flush_message(&msg_id).await.unwrap().unwrap();
    assert!(queued_with(&delivery, "not_admitted"), "{delivery:?}");
    assert_eq!(wallet.queue_stored(&plaintext).await.unwrap(), msg_id);
    assert_eq!(wallet.delivery(&msg_id).await.unwrap(), Some(delivery));
    shop.invite(&alice).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    // Sent: left as it is too.
    assert_eq!(wallet.queue_stored(&plaintext).await.unwrap(), msg_id);
    let report = wallet.flush_outbox().await.unwrap();
    assert!(
        report.done.is_empty() && report.queued.is_empty(),
        "{report:?}"
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    shop.receive(None).await.unwrap();
    assert_eq!(
        protocol
            .seen()
            .iter()
            .filter(|s| s.msg_id == msg_id)
            .count(),
        1
    );
}

/// A recipient keeps a processed pair only so long, so a message queued again goes only
/// until 30 days from its `created_at`, less the clock tolerance: past that it is given up
/// unsent, and the protocol told.
#[tokio::test]
async fn test_queue_stored_past_the_replay_window_is_refused_and_queues_nothing() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "old")).unwrap();
    p.clock
        .advance_ms(SENT_RETENTION_MS - CLOCK_TOLERANCE_MS + MINUTE);
    wallet.take_events();
    let error = wallet.queue_stored(signed.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::PastReplayWindow { .. }))
        ),
        "{error:?}"
    );
    assert!(wallet.take_events().is_empty());
    assert_eq!(wallet.delivery(signed.msg_id()).await.unwrap(), None);
    let report = wallet.flush_outbox().await.unwrap();
    assert!(report.undelivered.is_empty() && report.done.is_empty());
    assert!(wallet.unacknowledged_events().await.unwrap().is_empty());
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    // Within it, the same message goes.
    let fresh = wallet.sign_message(Pair::note(&p.bob, "fresh")).unwrap();
    p.clock
        .advance_ms(SENT_RETENTION_MS - CLOCK_TOLERANCE_MS - MINUTE);
    let msg_id = wallet.queue_stored(fresh.plaintext()).await.unwrap();
    let delivery = wallet.flush_message(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Accepted { .. })),
        "{delivery:?}"
    );
}

/// The `MessageUndelivered` events for `msg_id` among `events`, with their `resend`.
fn undelivered(events: &[AppEvent], msg_id: &str) -> Vec<bool> {
    events
        .iter()
        .filter_map(|e| match e {
            AppEvent::MessageUndelivered {
                msg_id: m, resend, ..
            } if m == msg_id => Some(*resend),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn test_queue_stored_given_up_once_is_refused_after() {
    // Queued within its window to a recipient that doesn't admit the sender, so it stays
    // queued until the deadline: given up once, the protocol told once; every later call is
    // refused, queues nothing and tells nothing.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let signed = wallet.sign_message(Pair::note(&p.bob, "old")).unwrap();
    p.clock.advance_ms(25 * DAY_MS);
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    p.clock.advance_ms(5 * DAY_MS);
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![msg_id.clone()]);
    assert_eq!(undelivered(&wallet.take_events(), &msg_id), vec![false]);
    for _ in 0..2 {
        let error = wallet.queue_stored(signed.plaintext()).await.unwrap_err();
        assert!(
            matches!(
                error,
                AppError::Refused(Refusal::WontDeliver(WontDeliver::GivenUp))
            ),
            "{error:?}"
        );
        let report = wallet.flush_outbox().await.unwrap();
        assert!(report.undelivered.is_empty(), "{report:?}");
    }
    assert!(wallet.take_events().is_empty());
    assert_eq!(
        undelivered(&wallet.unacknowledged_events().await.unwrap(), &msg_id),
        vec![false],
        "one duty event"
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    // Past the mark's month, the replay deadline refuses it.
    p.clock.advance_ms(SENT_RETENTION_MS + MINUTE);
    wallet.flush_outbox().await.unwrap();
    let error = wallet.queue_stored(signed.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::PastReplayWindow { .. }))
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_queue_stored_resend_past_the_deadline_is_given_up() {
    // The copy is accepted at day 25. Ten days later a re-send asked of it is past the
    // message's replay deadline: given up with `resend: true`, nothing delivered again.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    p.clock.advance_ms(25 * DAY_MS);
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    let delivery = wallet.flush_message(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Accepted { .. })),
        "{delivery:?}"
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    p.clock.advance_ms(10 * DAY_MS);
    wallet.take_events();
    wallet.resend(&msg_id).await.unwrap();
    assert_eq!(undelivered(&wallet.take_events(), &msg_id), vec![true]);
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "not delivered again"
    );
    // Within the deadline a re-send goes.
    let fresh = wallet.sign_message(Pair::note(&p.bob, "fresh")).unwrap();
    let msg_id = wallet.queue_stored(fresh.plaintext()).await.unwrap();
    wallet.flush_message(&msg_id).await.unwrap();
    p.clock.advance_ms(DAY_MS);
    let delivery = wallet.resend(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    assert_eq!(p.bob.switch().entries_from(&alice), 3);
}

#[tokio::test]
async fn test_queue_stored_after_the_sent_copy_is_forgotten_is_refused() {
    // The copy is accepted, and forgotten from the sent messages 30 days later: by then it
    // is past the replay deadline, so a later call is refused and tells nothing.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    let delivery = wallet.flush_message(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Accepted { .. })),
        "{delivery:?}"
    );
    p.clock.advance_ms(SENT_RETENTION_MS + MINUTE);
    wallet.flush_outbox().await.unwrap();
    assert_eq!(wallet.delivery(&msg_id).await.unwrap(), None);
    wallet.take_events();
    let error = wallet.queue_stored(signed.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::PastReplayWindow { .. }))
        ),
        "{error:?}"
    );
    wallet.flush_outbox().await.unwrap();
    assert!(undelivered(&wallet.take_events(), &msg_id).is_empty());
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
}

#[tokio::test]
async fn test_queue_stored_refuses_a_plaintext_that_isnt_a_message() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let keys = p.alice.identity().app_keys("wallet");
    let bob = p.bob.identity().public();
    let json = br#"{"v":1,"kind":"sample.note"}"#.to_vec();
    let signature = keys.sign(pubky_switch_core::labels::sig::MSG, &[&bob, &json]);
    let plaintext = MessagePlaintext::from_parts(wallet.app_id(), signature, json).unwrap();
    let error = wallet.queue_stored(&plaintext).await.unwrap_err();
    assert!(
        matches!(&error, AppError::Refused(Refusal::Usage(why)) if why.contains("isn't a message")),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_queue_stored_reads_the_protocols_opaque_members() {
    // A body member the protocol names opaque may hold any number, such as a fraction: the
    // stored message reads as the protocol signed it, and is queued.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    *protocol.opaque.lock().unwrap() = vec![crate::app::OpaqueRule {
        kind: None,
        member: "score".into(),
    }];
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut body = Map::new();
    body.insert("score".into(), json!(1.5));
    let message = OutgoingMessage::new(p.bob.identity().public(), "sample.note", body);
    let signed = wallet.sign_message(message).unwrap();
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    assert_eq!(msg_id, signed.msg_id());
    assert!(wallet.outbox_record(&msg_id).await.is_some());
}

#[tokio::test]
async fn test_queue_stored_copy_notifies_and_adds_the_conversation_entry() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    let item = wallet.outbox_record(&msg_id).await.unwrap();
    assert_eq!(item.notify_and_conversation(), (true, true));
    wallet.flush_message(&msg_id).await.unwrap();
    let entries = p
        .alice
        .switch()
        .applied()
        .iter()
        .filter(|op| {
            matches!(
                op.body().kind,
                OpKind::AllowPut { pubky, kind: pubky_switch_core::ops::AllowKind::Conversation }
                    if pubky == bob
            )
        })
        .count();
    assert_eq!(entries, 1, "the conversation entry its kind needs");
}

/// A copy given up within its window because its try is too large for the store is
/// refused by its mark, not queued again.
#[tokio::test]
async fn test_queue_stored_after_a_too_large_give_up_is_refused() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, _shop, store) = wallet_on_a_fault_store(&p, &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    store.refuse_puts_as_too_large_once(format!("out/{msg_id}").as_bytes());
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![msg_id.clone()], "{report:?}");
    assert_eq!(undelivered(&wallet.take_events(), &msg_id), vec![false]);
    let error = wallet.queue_stored(signed.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::GivenUp))
        ),
        "{error:?}"
    );
    // A message whose own record doesn't fit: refused, nothing written, nothing told.
    store.refuse_puts_as_too_large(Some(b"out/"));
    let fresh = wallet.sign_message(Pair::note(&p.bob, "fresh")).unwrap();
    let error = wallet.queue_stored(fresh.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::TooLarge))
        ),
        "{error:?}"
    );
    store.refuse_puts_as_too_large(None);
    assert_eq!(wallet.delivery(fresh.msg_id()).await.unwrap(), None);
    assert!(undelivered(&wallet.take_events(), fresh.msg_id()).is_empty());
}

/// A message a restore left out of its outbox is refused by its mark.
#[tokio::test]
async fn test_queue_stored_left_out_by_a_restore_is_refused() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let text = "x".repeat(40_000);
    let mut last = None;
    for _ in 0..260 {
        let signed = wallet.sign_message(Pair::note(&p.bob, &text)).unwrap();
        last = Some(signed.plaintext().clone());
        wallet.queue_signed(signed).await.unwrap();
        p.clock.advance_ms(1);
    }
    let last = last.unwrap();
    let msg_id = Message::parse(last.json(), &[]).unwrap().msg_id;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    assert_eq!(restored.delivery(&msg_id).await.unwrap(), None);
    let error = restored.queue_stored(&last).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::GivenUp))
        ),
        "{error:?}"
    );
}

/// On the device that keeps the batch, a copy given up at its deadline, then the kept batch
/// settling: the message isn't queued again, and doesn't go.
#[tokio::test]
async fn test_queue_stored_given_up_then_its_kept_batch_settles_queues_nothing() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let start = p.clock.now_ms();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    p.clock.advance_ms(120 * MINUTE);
    let target = RecordTarget::new(items(), &signed.hash());
    let entry = wallet
        .record_op(&target, Some(&stored_value(&signed)), vec![])
        .await
        .unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let error = wallet
        .submit_batch(OpBatch::new().entry(entry).queue(signed.clone()))
        .await
        .unwrap_err();
    assert!(error.kept_batch().is_some(), "{error:?}");
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    p.clock.set_ms(start + SENT_RETENTION_MS);
    for _ in 0..6 {
        p.alice.switch().fail_next(Fault::Unreachable {
            path: "ops".into(),
            after: 0,
        });
    }
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![msg_id.clone()], "{report:?}");
    assert_eq!(undelivered(&wallet.take_events(), &msg_id), vec![false]);
    p.alice.switch().lock().faults.clear();
    let mut shop = shop;
    shop.invite(&alice).await.unwrap();
    let report = wallet.flush_outbox().await.unwrap();
    let events = wallet.take_events();
    let accepted = events
        .iter()
        .any(|e| matches!(e, AppEvent::MessageAccepted { msg_id: m, .. } if *m == msg_id));
    assert!(
        !accepted && p.bob.switch().entries_from(&alice) == 0,
        "given up, and not delivered {} after the message was signed: {report:?}",
        p.clock.now_ms() - start
    );
}

/// A plain message's re-send queued 29 days after its first acceptance, and kept from going
/// by the network, is given up 30 days after it, not delivered at 40.
#[tokio::test]
async fn test_resend_past_30_days_from_first_acceptance_is_given_up() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    let Delivery::Accepted { accepted_at_ms } = delivery else {
        panic!("{delivery:?}");
    };
    p.clock.set_ms(accepted_at_ms + 29 * DAY_MS);
    for _ in 0..4 {
        p.bob.switch().fail_next(Fault::Unreachable {
            path: "inbox".into(),
            after: 0,
        });
    }
    let delivery = wallet.resend(&msg_id).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    p.bob.switch().lock().faults.clear();
    p.clock.set_ms(accepted_at_ms + 40 * DAY_MS);
    wallet.take_events();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "not re-sent 40 days after its first acceptance"
    );
    assert_eq!(undelivered(&wallet.take_events(), &msg_id), vec![true]);
}

#[tokio::test]
async fn test_queue_stored_give_up_mark_is_pruned_after_its_month() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "old")).unwrap();
    p.clock.advance_ms(25 * DAY_MS);
    wallet.queue_stored(signed.plaintext()).await.unwrap();
    p.clock.advance_ms(5 * DAY_MS);
    wallet.flush_outbox().await.unwrap();
    let marks = |app: &App| {
        let app = app.reader();
        async move { app.scan_raw("outgone/").await.unwrap().len() }
    };
    assert_eq!(marks(&wallet).await, 1);
    p.clock.advance_ms(SENT_RETENTION_MS - MINUTE);
    wallet.flush_outbox().await.unwrap();
    assert_eq!(marks(&wallet).await, 1, "kept its month");
    p.clock.advance_ms(2 * MINUTE);
    wallet.flush_outbox().await.unwrap();
    assert_eq!(marks(&wallet).await, 0, "pruned after it");
}

/// One run of the scenario of a message signed, its record written from its hash in the
/// batch that queues it, then delivered. Returns at the first error, as a process that
/// died.
async fn signed_scenario(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
    store: Arc<dyn StateStore>,
    approval: &mut Option<JoinRequest>,
    msg_id: &mut Option<String>,
) -> Result<(), AppError> {
    let keys = p.alice.identity().app_keys("wallet");
    let env = p.alice.env_with(
        Arc::clone(&store),
        Arc::clone(&p.router) as Arc<dyn Transport>,
    );
    let mut app =
        match App::load(env.clone(), protocol.clone(), config(), keys.app_id_bytes()).await {
            Ok(app) => app,
            Err(AppError::Refused(Refusal::NotJoined)) => {
                let app = AppSpec::new(&["scope-a"]).with_permissions(&Permission::ALL);
                let request = approval
                    .get_or_insert_with(|| p.alice.approve(&keys, &app).unwrap())
                    .clone();
                App::join(env, protocol.clone(), config(), request).await?
            }
            Err(error) => return Err(error),
        };
    app.receive(None).await?;
    // A kept batch is sent again, and what it queued delivered.
    app.flush_outbox().await?;
    let kept = match msg_id {
        Some(id) => app.delivery(id).await?.is_some(),
        None => false,
    };
    if !kept {
        let signed = app.sign_message(Pair::note(&p.bob, "hello"))?;
        *msg_id = Some(signed.msg_id().to_owned());
        let target = RecordTarget::new(items(), &signed.hash());
        let entry = app
            .record_op(&target, Some(&value(&[signed.msg_id()])), vec![])
            .await?;
        app.submit_batch(OpBatch::new().entry(entry).queue(signed))
            .await?;
        app.flush_outbox().await?;
    }
    Ok(())
}

#[tokio::test]
async fn test_signed_message_crash_at_each_commit_point_sends_and_writes_once() {
    let setup = || async {
        let p = Pair::new();
        let protocol = ApiProtocol::new(Mode::Plain);
        let mut shop = p.join(&p.bob, "shop", &protocol).await;
        shop.invite(&p.alice.identity().public()).await.unwrap();
        (p, protocol)
    };
    let commits = {
        let (p, protocol) = setup().await;
        let counting = Arc::new(FaultStore::new(
            Arc::new(MemoryStore::new()) as Arc<dyn StateStore>,
            StoreFault::None,
        ));
        signed_scenario(
            &p,
            &protocol,
            Arc::clone(&counting) as Arc<dyn StateStore>,
            &mut None,
            &mut None,
        )
        .await
        .unwrap();
        counting.commits()
    };
    assert!(commits > 6, "the scenario commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let (p, protocol) = setup().await;
            let inner = Arc::new(MemoryStore::new());
            let fault = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let mut approval = None;
            let mut msg_id = None;
            let first = signed_scenario(
                &p,
                &protocol,
                Arc::clone(&fault) as Arc<dyn StateStore>,
                &mut approval,
                &mut msg_id,
            )
            .await;
            assert!(fault.stopped(), "commit {n} of {commits} is reached");
            assert!(first.is_err());
            signed_scenario(
                &p,
                &protocol,
                Arc::clone(&inner) as Arc<dyn StateStore>,
                &mut approval,
                &mut msg_id,
            )
            .await
            .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            let alice = p.alice.identity().public();
            assert_eq!(
                p.bob.switch().entries_from(&alice),
                1,
                "commit {n} ({stop_after})"
            );
            let puts = p
                .alice
                .switch()
                .applied()
                .iter()
                .filter(|op| matches!(op.body().kind, OpKind::RecordPut(_)))
                .count();
            assert_eq!(puts, 1, "commit {n} ({stop_after})");
            let app = App::load(
                p.alice
                    .env_with(inner.clone(), Arc::clone(&p.router) as Arc<dyn Transport>),
                protocol.clone(),
                config(),
                p.alice.identity().app_keys("wallet").app_id_bytes(),
            )
            .await
            .unwrap();
            let msg_id = msg_id.clone().unwrap();
            assert!(matches!(
                app.delivery(&msg_id).await.unwrap(),
                Some(Delivery::Accepted { .. })
            ));
        }
    }
}

// -------------------------------------------------------------------------------------
// A counterparty's identity.json (Switch spec 4.3, "The switch's copy")

#[tokio::test]
async fn test_identity_of_takes_the_switch_copy_when_higher() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    // The switch holds a version the Homeserver doesn't publish yet.
    let mut body = p.bob.body();
    body.version += 1;
    let newer = IdentityDoc::sign(p.bob.identity().key(), body).unwrap();
    p.bob.switch().deliver_identity(&newer).unwrap();
    let bob = p.bob.identity().public();
    let found = wallet.identity_of(&bob, false).await.unwrap();
    assert_eq!(found.doc.version(), newer.version());
    assert_eq!(found.switch_copy, SwitchCopy::Read);
    assert_eq!(found.read_at_ms, START);
    // Within 10 minutes the copy held is used, nothing read.
    let reads = p.router.log().len();
    p.clock.advance_ms(9 * MINUTE);
    let cached = wallet.identity_of(&bob, false).await.unwrap();
    assert_eq!(cached.doc.version(), newer.version());
    assert_eq!(p.router.log().len(), reads);
    // After them, read again.
    p.clock.advance_ms(2 * MINUTE);
    wallet.identity_of(&bob, false).await.unwrap();
    assert!(p.router.log().len() > reads);
}

#[tokio::test]
async fn test_identity_of_without_the_switch_stands_on_the_homeserver() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    p.router.remove(BOB_ORIGIN);
    let bob = p.bob.identity().public();
    let found = wallet.identity_of(&bob, true).await.unwrap();
    assert_eq!(found.switch_copy, SwitchCopy::Unavailable);
    assert_eq!(found.doc.version(), p.bob.body().version);
    // The failed lookup counts until the copy is 10 minutes old.
    p.router.add_switch(BOB_ORIGIN, p.bob.switch());
    let again = wallet.identity_of(&bob, false).await.unwrap();
    assert_eq!(again.switch_copy, SwitchCopy::Unavailable);
    let refreshed = wallet.identity_of(&bob, true).await.unwrap();
    assert_eq!(refreshed.switch_copy, SwitchCopy::Read);
}

#[tokio::test]
async fn test_identity_of_refuses_an_equivocating_counterparty() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    // Another body at the version the Homeserver publishes.
    let mut body = p.bob.body();
    body.apps.clear();
    let other = IdentityDoc::sign(p.bob.identity().key(), body).unwrap();
    p.bob.switch().deliver_identity(&other).unwrap();
    let bob = p.bob.identity().public();
    let error = wallet.identity_of(&bob, false).await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::NotNow(_))),
        "{error:?}"
    );
    assert!(
        wallet
            .take_events()
            .iter()
            .any(|e| matches!(e, AppEvent::PeerEquivocation { .. }))
    );
    // From then on no copy of it is used.
    assert!(wallet.identity_of(&bob, true).await.is_err());
    // Nor is the own identity looked up so.
    let alice = p.alice.identity().public();
    let own = wallet.identity_of(&alice, false).await.unwrap_err();
    assert!(matches!(own, AppError::Refused(Refusal::Usage(_))));
}

// -------------------------------------------------------------------------------------
// A sender's standing in the lists, as a receive step reads it (Switch spec 7 "Spam")

/// The disposition the receive step saw for the last message.
fn last_disposition(protocol: &ApiProtocol) -> SenderDisposition {
    protocol.seen().last().unwrap().disposition.unwrap()
}

/// Bob's shop with alice invited, and a note from alice's wallet waiting in its inbox.
async fn shop_with_a_note(p: &Pair, protocol: &Arc<ApiProtocol>) -> App {
    let mut wallet = p.join(&p.alice, "wallet", protocol).await;
    let mut shop = p.join(&p.bob, "shop", protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let (_, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    shop
}

#[tokio::test]
async fn test_sender_disposition_neither_after_a_refresh() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    // Another sender is flagged and blocked; alice is neither.
    let carol = p.carol.identity().public();
    p.bob.switch().lock().shared.flagged.insert(carol, 3);
    shop.deny(&carol).await.unwrap();
    shop.allow_list().await.unwrap();
    let as_of = shop.highest_service_time();
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert!(!seen.blocked && !seen.flagged, "{seen:?}");
    assert!(as_of.is_some());
    assert_eq!(seen.lists_as_of_ms, as_of);
}

#[tokio::test]
async fn test_sender_disposition_blocked() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    // Denied after the inbox accepted the note.
    shop.deny(&p.alice.identity().public()).await.unwrap();
    shop.allow_list().await.unwrap();
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert!(seen.blocked && !seen.flagged, "{seen:?}");
}

#[tokio::test]
async fn test_sender_disposition_flagged() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    p.bob.switch().lock().shared.flagged.insert(alice, 4);
    let list = shop.allow_list().await.unwrap();
    assert_eq!(list.flagged.len(), 1);
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert!(seen.flagged && !seen.blocked, "{seen:?}");
    assert!(seen.lists_as_of_ms.is_some());
}

#[tokio::test]
async fn test_sender_disposition_refresh_clears_a_flag() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    p.bob.switch().lock().shared.flagged.insert(alice, 3);
    shop.allow_list().await.unwrap();
    let first = shop.highest_service_time().unwrap();
    // The service drops the flag; the next refresh replaces the copy.
    p.bob.switch().lock().shared.flagged.clear();
    p.clock.advance_ms(MINUTE);
    shop.allow_list().await.unwrap();
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert!(!seen.flagged && !seen.blocked, "{seen:?}");
    assert!(seen.lists_as_of_ms.unwrap() >= first + MINUTE, "{seen:?}");
}

#[tokio::test]
async fn test_sender_disposition_never_refreshed_shows_only_own_deny_changes() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    // Without `lists.read` the shop never reads its lists.
    let mut shop = p
        .join_with(
            &p.bob,
            "shop",
            protocol.clone(),
            Arc::new(MemoryStore::new()),
            &[Permission::ListsManage, Permission::ConversationAdd],
        )
        .await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    // The service flags alice; only the shop's own deny shows, and the copy is unknown.
    p.bob.switch().lock().shared.flagged.insert(alice, 3);
    shop.deny(&alice).await.unwrap();
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert_eq!(seen.lists_as_of_ms, None);
    assert!(seen.blocked && !seen.flagged, "{seen:?}");
}

#[tokio::test]
async fn test_sender_disposition_first_read_refreshes_a_copy_never_refreshed() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    p.bob.switch().lock().shared.flagged.insert(alice, 3);
    // No allow_list(): the read refreshes the copy before it hands the note over.
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert!(seen.flagged, "{seen:?}");
    assert!(seen.lists_as_of_ms.is_some());
}

#[tokio::test]
async fn test_sender_disposition_lists_as_of_is_service_time() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    // The shop's device clock runs two minutes ahead of the service, within the timestamp
    // tolerance.
    let keys = p.bob.identity().app_keys("shop");
    let request = p
        .bob
        .approve(
            &keys,
            &AppSpec::new(&["scope-a"]).with_permissions(&Permission::ALL),
        )
        .unwrap();
    let mut env = p.env(&p.bob, Arc::new(MemoryStore::new()));
    let device = Arc::new(crate::clock::TestClock::new(p.clock.now_ms() + 2 * MINUTE));
    env.clock = device.clone();
    let mut shop = App::join(env, protocol.clone(), config(), request)
        .await
        .unwrap();
    shop.invite(&p.alice.identity().public()).await.unwrap();
    wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    shop.allow_list().await.unwrap();
    shop.receive(None).await.unwrap();
    let as_of = last_disposition(&protocol).lists_as_of_ms.unwrap();
    assert_eq!(as_of, p.clock.now_ms());
    assert_ne!(as_of, device.now_ms());
}

#[tokio::test]
async fn test_sender_disposition_answer_without_flagged_replaces_nothing() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    p.bob.switch().lock().shared.flagged.insert(alice, 3);
    shop.allow_list().await.unwrap();
    let as_of = shop.highest_service_time();
    // A faulty answer leaves `flagged` out: malformed, so the copy stays as it was.
    p.clock.advance_ms(MINUTE);
    p.bob.switch().lock().allow = Some(json!({
        "contacts": [], "conversations": [], "deny": [], "invite_codes": []
    }));
    let error = shop.allow_list().await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Switch(crate::ClientError::InvalidResponse(_))
        ),
        "{error:?}"
    );
    shop.receive(None).await.unwrap();
    let seen = last_disposition(&protocol);
    assert!(seen.flagged, "{seen:?}");
    assert_eq!(seen.lists_as_of_ms, as_of);
}

/// A restore of bob's shop after it denied alice: her note, accepted before the deny, is
/// stored locally, and the shop's feed read has passed the deny. Returns the restored shop,
/// on the returned new store, with alice's note to be tried again.
async fn shop_restored_after_a_deny(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
    permissions: &[Permission],
) -> (App, Arc<MemoryStore>) {
    let mut wallet = p.join(&p.alice, "wallet", protocol).await;
    let mut shop = p
        .join_with(
            &p.bob,
            "shop",
            protocol.clone(),
            Arc::new(MemoryStore::new()),
            permissions,
        )
        .await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    // The store rejects the note: it is stored locally, and stays so at the next read.
    *protocol.reject.lock().unwrap() = 2;
    shop.receive(None).await.unwrap();
    shop.deny(&alice).await.unwrap();
    shop.receive(None).await.unwrap();
    let backup = shop.backup_layered().await.unwrap();
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    protocol.seen.lock().unwrap().clear();
    let store = Arc::new(MemoryStore::new());
    let restored = App::restore(
        p.env(&p.bob, Arc::clone(&store) as Arc<dyn StateStore>),
        protocol.clone(),
        config(),
        &backup,
    )
    .await
    .unwrap();
    (restored, store)
}

/// Whether `shop`'s copy of the lists holds a refresh time.
fn refreshed(store: &MemoryStore, shop: &App) -> bool {
    let ns = crate::store::client_namespace(&shop.app_id());
    store.get(&ns, b"lc/lists_at").unwrap().is_some()
}

/// The disposition the receive step saw for alice's note after the restore, read until it
/// is handed over.
async fn restored_disposition(shop: &mut App, protocol: &ApiProtocol) -> SenderDisposition {
    for _ in 0..3 {
        shop.receive(None).await.unwrap();
        if let Some(seen) = protocol.seen().last() {
            return seen.disposition.unwrap();
        }
    }
    panic!("the stored note was never tried again");
}

#[tokio::test]
async fn test_sender_disposition_after_a_restore_refreshes_before_a_stored_entry() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut shop, _) = shop_restored_after_a_deny(&p, &protocol, &Permission::ALL).await;
    let seen = restored_disposition(&mut shop, &protocol).await;
    assert!(seen.blocked, "{seen:?}");
    assert!(seen.lists_as_of_ms.is_some());
}

#[tokio::test]
async fn test_sender_disposition_after_a_restore_without_lists_read_is_unknown() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut shop, store) = shop_restored_after_a_deny(
        &p,
        &protocol,
        &[Permission::ListsManage, Permission::ConversationAdd],
    )
    .await;
    // The deny was made before the backup: nothing of it is known, and `None` says so.
    let seen = restored_disposition(&mut shop, &protocol).await;
    assert_eq!(seen.lists_as_of_ms, None);
    assert!(!seen.blocked, "{seen:?}");
    assert!(!refreshed(&store, &shop));
}

#[tokio::test]
async fn test_sender_disposition_failed_refresh_after_a_restore_holds_the_read() {
    // A restore with `lists.read` owes the protocol a deny list gap, told with the lists
    // read for it: while that read fails, the read holds and hands nothing, so no entry is
    // handed with the copy unknown. The next read tells the gap and takes the copy.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut shop, store) = shop_restored_after_a_deny(&p, &protocol, &Permission::ALL).await;
    p.bob.switch().fail_next(Fault::Error {
        path: "allow".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    let held = shop.receive(None).await.unwrap();
    assert!(held.stopped);
    assert!(protocol.seen().is_empty());
    assert!(!refreshed(&store, &shop));
    let seen = restored_disposition(&mut shop, &protocol).await;
    assert!(seen.blocked, "{seen:?}");
    assert!(seen.lists_as_of_ms.is_some());
    assert!(refreshed(&store, &shop));
}

#[tokio::test]
async fn test_sender_disposition_lists_too_large_for_one_commit_let_the_read_go_on() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = shop_with_a_note(&p, &protocol).await;
    // More flagged senders than one commit's batch size holds, as at raised limits.
    {
        let mut switch = p.bob.switch().lock();
        for n in 0..310_000u32 {
            let mut pubky = [9u8; 32];
            pubky[..4].copy_from_slice(&n.to_be_bytes());
            switch.shared.flagged.insert(pubky, 3);
        }
    }
    // The owed refresh fails the same way at every read, and the reads go on.
    for _ in 0..2 {
        let result = shop.receive(None).await;
        assert!(result.is_ok(), "the read goes on: {result:?}");
    }
    let seen = last_disposition(&protocol);
    assert_eq!(seen.lists_as_of_ms, None);
    // The host's own refresh gets the refusal.
    let error = shop.allow_list().await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Store(crate::error::StoreError::TooLarge { .. })
        ),
        "{error:?}"
    );
}

/// How many `GET /allow` calls the router carried.
fn allow_reads(p: &Pair) -> usize {
    p.router
        .log()
        .iter()
        .filter(|line| line.starts_with("GET ") && line.ends_with("/allow"))
        .count()
}

/// Whether the copy of the lists in `store` holds `key`.
fn lists_key(store: &MemoryStore, shop: &App, key: &[u8]) -> bool {
    let ns = crate::store::client_namespace(&shop.app_id());
    store.get(&ns, key).unwrap().is_some()
}

/// Bob's shop on `store`, with a note from alice waiting, whose first read found its lists
/// too large for one commit: the refusal is kept.
async fn shop_with_lists_too_large(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
    store: &Arc<MemoryStore>,
) -> App {
    let mut wallet = p.join(&p.alice, "wallet", protocol).await;
    let mut shop = p
        .join_on(
            &p.bob,
            "shop",
            protocol.clone(),
            Arc::clone(store) as Arc<dyn StateStore>,
        )
        .await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    {
        let mut switch = p.bob.switch().lock();
        for n in 0..310_000u32 {
            let mut pubky = [9u8; 32];
            pubky[..4].copy_from_slice(&n.to_be_bytes());
            switch.shared.flagged.insert(pubky, 3);
        }
    }
    let before = allow_reads(p);
    shop.receive(None).await.unwrap();
    assert_eq!(allow_reads(p), before + 1);
    assert!(lists_key(store, &shop, b"lc/too_large"));
    assert!(!lists_key(store, &shop, b"lc/lists_at"));
    shop
}

/// The service's flagged senders shrink to fit one commit.
fn lists_fit_again(p: &Pair) {
    p.bob.switch().lock().shared.flagged.clear();
}

#[tokio::test]
async fn test_lists_too_large_refresh_isnt_tried_again_by_the_next_read() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let mut shop = shop_with_lists_too_large(&p, &protocol, &store).await;
    let reads = allow_reads(&p);
    shop.receive(None).await.unwrap();
    assert_eq!(allow_reads(&p), reads);
    // Still nothing known, so still `None`.
    assert_eq!(last_disposition(&protocol).lists_as_of_ms, None);
}

#[tokio::test]
async fn test_lists_too_large_refresh_is_tried_again_after_a_day() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let mut shop = shop_with_lists_too_large(&p, &protocol, &store).await;
    lists_fit_again(&p);
    let reads = allow_reads(&p);
    p.clock.advance_ms(LISTS_TOO_LARGE_RETRY_MS - MINUTE);
    shop.receive(None).await.unwrap();
    assert_eq!(allow_reads(&p), reads, "not before a day");
    p.clock.advance_ms(2 * MINUTE);
    // The day is judged on the highest service time verified, which this read's page
    // moves on: the next read refreshes.
    shop.receive(None).await.unwrap();
    assert_eq!(
        allow_reads(&p),
        reads,
        "judged on the time before this read"
    );
    shop.receive(None).await.unwrap();
    assert_eq!(allow_reads(&p), reads + 1);
    assert!(lists_key(&store, &shop, b"lc/lists_at"));
    assert!(!lists_key(&store, &shop, b"lc/too_large"));
}

#[tokio::test]
async fn test_lists_too_large_explicit_refresh_is_always_tried() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let mut shop = shop_with_lists_too_large(&p, &protocol, &store).await;
    let reads = allow_reads(&p);
    let error = shop.allow_list().await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Store(crate::error::StoreError::TooLarge { .. })
        ),
        "{error:?}"
    );
    assert_eq!(allow_reads(&p), reads + 1);
    assert!(lists_key(&store, &shop, b"lc/too_large"));
    lists_fit_again(&p);
    shop.allow_list().await.unwrap();
    assert!(lists_key(&store, &shop, b"lc/lists_at"));
    assert!(!lists_key(&store, &shop, b"lc/too_large"));
}

#[tokio::test]
async fn test_lists_too_large_refresh_is_tried_again_after_a_restore() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let mut shop = shop_with_lists_too_large(&p, &protocol, &store).await;
    lists_fit_again(&p);
    // Held back at the app's own store.
    let reads = allow_reads(&p);
    shop.receive(None).await.unwrap();
    assert_eq!(allow_reads(&p), reads);
    let backup = shop.backup_layered().await.unwrap();
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    let restored_store = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        p.env(&p.bob, Arc::clone(&restored_store) as Arc<dyn StateStore>),
        protocol.clone(),
        config(),
        &backup,
    )
    .await
    .unwrap();
    let reads = allow_reads(&p);
    restored.receive(None).await.unwrap();
    assert_eq!(allow_reads(&p), reads + 1);
    assert!(lists_key(&restored_store, &restored, b"lc/lists_at"));
}

#[tokio::test]
async fn test_sender_disposition_sees_an_undeny_earlier_in_the_same_read() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let mut kiosk = p.join(&p.bob, "kiosk", &protocol).await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    shop.deny(&alice).await.unwrap();
    // Another of bob's apps lifts the block; alice writes again.
    kiosk.undeny(&alice).await.unwrap();
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    // The shop's copy still holds its own deny until the feed's undeny commits, which is in
    // the same read as the note.
    shop.receive(None).await.unwrap();
    let seen = protocol.seen();
    let seen = seen.iter().find(|s| s.msg_id == msg_id).unwrap();
    assert!(!seen.disposition.unwrap().blocked, "{seen:?}");
}

#[tokio::test]
async fn test_sender_disposition_flagged_list_is_kept_whole() {
    // `max_flags` at the default limits (Switch wire 9.2), and one more, as a service with a
    // raised limit may answer: every flagged sender is kept, as every entry of the other
    // lists is.
    const MAX_FLAGS: u32 = 1_000;
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let store = Arc::new(MemoryStore::new());
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p
        .join_on(
            &p.bob,
            "shop",
            protocol.clone(),
            Arc::clone(&store) as Arc<dyn StateStore>,
        )
        .await;
    let alice = p.alice.identity().public();
    shop.invite(&alice).await.unwrap();
    wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    {
        let mut switch = p.bob.switch().lock();
        for n in 0..MAX_FLAGS {
            let mut pubky = [7u8; 32];
            pubky[..4].copy_from_slice(&n.to_be_bytes());
            switch.shared.flagged.insert(pubky, 3);
        }
        switch.shared.flagged.insert(alice, 3);
    }
    let list = shop.allow_list().await.unwrap();
    assert_eq!(list.flagged.len(), 1_001);
    let ns = crate::store::client_namespace(&shop.app_id());
    let kept = store.scan(&ns, b"lc/flag/", None, 10_000).unwrap();
    assert_eq!(kept.len(), 1_001);
    shop.receive(None).await.unwrap();
    assert!(last_disposition(&protocol).flagged);
}

// -------------------------------------------------------------------------------------
// The futures of the app's calls (debug builds keep every call's state on the caller's
// stack unless it is boxed)

#[tokio::test]
async fn test_app_call_futures_are_boxed_at_the_boundary() {
    let w = World::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut app = join(&w, &protocol, "wallet").await;
    let bound = 256;
    let receive = std::mem::size_of_val(&app.receive(None));
    assert!(receive <= bound, "receive: {receive} bytes");
    let flush = std::mem::size_of_val(&app.flush_outbox());
    assert!(flush <= bound, "flush_outbox: {flush} bytes");
    let batch = std::mem::size_of_val(&app.submit_batch(OpBatch::new()));
    assert!(batch <= bound, "submit_batch: {batch} bytes");
    let read = std::mem::size_of_val(&app.read_record(&inbox()));
    assert!(read <= bound, "read_record: {read} bytes");
    let claim = std::mem::size_of_val(&app.read_claim(&CLAIM));
    assert!(claim <= bound, "read_claim: {claim} bytes");
    let message = Pair::note(&w.signer, "x");
    let queue = std::mem::size_of_val(&app.queue(message));
    assert!(queue <= 512, "queue: {queue} bytes");
}

#[tokio::test]
async fn test_scripted_feed_visibility_by_kind_and_currency() {
    // Switch wire 7.5: for each kind of chain item, readers shown it in full and readers
    // shown its stub; then items whose document is no longer current, a stub to their
    // readers too, the writer included (6.8 "Tombstones", 3.8).
    use pubky_switch_core::claims::Basis;
    use pubky_switch_core::records::{
        AppRecord, AppRecordBody, ListedApp, RenewedCert, seal_bundle_parts,
    };
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let switch = Arc::clone(p.bob.switch());
    let bob = p.bob.identity().clone();
    let register = |name: &str, scopes: &[&str], permissions: &[Permission]| {
        let keys = bob.app_keys(name);
        let spec = AppSpec::new(scopes).with_permissions(permissions);
        let cert = p.bob.register_app(&keys, &spec).unwrap();
        (keys, cert, switch.seq())
    };
    let (_, plain_cert, _) = register("plain", &["scope-a"], &[]);
    let (claims_keys, claims_cert, claims_put) =
        register("claims", &["scope-b"], &[Permission::ClaimsRead]);
    let (_, lists_cert, _) = register("lists", &["scope-b"], &[Permission::ListsRead]);
    let (adder_keys, adder_cert, _) =
        register("adder", &["scope-b"], &[Permission::ConversationAdd]);
    let (renewing_keys, renewing_cert, _) = register("renewing", &["scope-b"], &[]);
    let (plain, claims, lists, adder) = (
        plain_cert.app_id(),
        claims_cert.app_id(),
        lists_cert.app_id(),
        adder_cert.app_id(),
    );
    // (what, seq, item type, shown in full to, shown as a stub to)
    type Apps = Vec<[u8; 16]>;
    let mut rows: Vec<(&str, u64, &str, Apps, Apps)> = Vec::new();
    // A claim entry: `claims.read`.
    let attempt = |key: [u8; 32]| ClaimOp::attempt(key, 0, ATTEMPT, 3600, None);
    shop.write_claim(attempt(CLAIM), vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
    rows.push(("claim", switch.seq(), "op", vec![claims], vec![plain]));
    // A record write: the read scope (`scope-a`), not another scope.
    shop.put_record(&inbox(), &value(&["a"]), vec![])
        .await
        .unwrap();
    rows.push((
        "record.put",
        switch.seq(),
        "op",
        vec![plain, shop.app_id()],
        vec![claims],
    ));
    // An invite code: `lists.read` or `conversation.add`, each alone.
    let code = shop
        .register_invite_code(START + DAY_MS, 1, json!({}))
        .await
        .unwrap();
    rows.push((
        "invite_code.put",
        switch.seq(),
        "op",
        vec![lists, adder],
        vec![plain],
    ));
    // The service's conversation entry for a sender the code admitted: `lists.read` only.
    let before = switch.seq();
    let mut note = Pair::note(&p.bob, "hello");
    note.invite_code = Some(code.code);
    let (_, delivery) = wallet.send(note).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    let added = switch
        .shown(lists)
        .into_iter()
        .find(|i| i["seq"].as_u64().unwrap() > before && i["item_type"] == "service")
        .expect("the conversation.add")["seq"]
        .as_u64()
        .unwrap();
    rows.push((
        "conversation.add",
        added,
        "service",
        vec![lists],
        vec![adder],
    ));
    // A key bundle part: its target only.
    let part = |cert: &AppCert| {
        let sealed = seal_bundle_parts(bob.key(), cert, 1, 1, &|s: &str| s == "scope-a");
        OpKind::KeyBundlePut(KeyBundlePut {
            target_app_id: cert.app_id(),
            bundle: sealed.unwrap().remove(0).bundle,
            first_epoch: 1,
            last_epoch: 1,
        })
    };
    switch.signer_op(part(&plain_cert)).unwrap();
    let replaced_part = switch.seq();
    switch.signer_op(part(&plain_cert)).unwrap();
    rows.push((
        "key_bundle.put",
        switch.seq(),
        "op",
        vec![plain],
        vec![claims],
    ));
    rows.push((
        "key_bundle.put replaced",
        replaced_part,
        "op",
        vec![],
        vec![plain],
    ));
    // A superseded record write, to its writer too.
    let other = RecordTarget::new(items(), b"other");
    shop.put_record(&other, &value(&["a"]), vec![])
        .await
        .unwrap();
    let superseded = switch.seq();
    shop.put_record(&other, &value(&["a", "b"]), vec![])
        .await
        .unwrap();
    rows.push((
        "record.put superseded",
        superseded,
        "op",
        vec![],
        vec![plain, shop.app_id()],
    ));
    // A compacted claim's entries: stubs to every app, the claim's own writer included.
    let compacted = [9; 32];
    shop.write_claim(attempt(compacted), vec![], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
    let compacted_attempt = switch.seq();
    let condition = shop.claim_condition(&compacted).await.unwrap();
    let done = ClaimOp::done(compacted, 1, ATTEMPT, Basis::Owner, None).unwrap();
    shop.write_claim(done, vec![condition], ObligationDeadline::NoDeadline)
        .await
        .unwrap();
    rows.push((
        "claim compacted",
        compacted_attempt,
        "op",
        vec![],
        vec![claims, shop.app_id()],
    ));
    rows.push((
        "claim compacted, its last",
        switch.seq(),
        "op",
        vec![],
        vec![claims, shop.app_id()],
    ));
    // An app record: every app while it is held; a superseded one is a stub.
    p.clock.advance_ms(1000);
    let newer = AppRecord::sign(
        &claims_keys,
        AppRecordBody::new(&claims_cert, Vec::new(), p.clock.now_ms()),
    )
    .unwrap();
    let record = newer.signed().clone();
    switch
        .app_op(&claims_keys, OpKind::AppPut { record })
        .unwrap();
    rows.push(("app.put", switch.seq(), "op", vec![plain], vec![]));
    rows.push(("app.put superseded", claims_put, "op", vec![], vec![plain]));
    // A renewed certificate: every app while stored; one the app's record carries is a stub.
    let renew = |keys: &AppKeys| {
        let spec = AppSpec::new(&["scope-b"]);
        let renewed = issue_cert(bob.key(), keys, &spec, p.clock.now_ms()).unwrap();
        switch
            .signer_op(OpKind::CertPut {
                target_app_id: renewed.app_id(),
                cert: renewed.signed().clone(),
            })
            .unwrap();
        renewed
    };
    renew(&adder_keys);
    rows.push(("cert.put", switch.seq(), "op", vec![plain], vec![]));
    let renewed = renew(&renewing_keys);
    let carried = switch.seq();
    let renewing = renewing_cert.app_id();
    p.bob
        .next_doc(|body| {
            body.apps.retain(|a| a.app_id != renewing);
            body.apps.push(ListedApp {
                app_id: renewing,
                cert: renewed.hash(),
            });
            body.renewed.push(RenewedCert {
                app_id: renewing,
                cert: renewing_cert.hash(),
                until: None,
            });
        })
        .unwrap();
    p.clock.advance_ms(1000);
    let record = AppRecord::sign(
        &renewing_keys,
        AppRecordBody::new(&renewed, Vec::new(), p.clock.now_ms()),
    )
    .unwrap();
    switch
        .app_op(
            &renewing_keys,
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    rows.push((
        "cert.put carried by the record",
        carried,
        "op",
        vec![],
        vec![plain],
    ));
    for (what, seq, item_type, full, stub) in &rows {
        let shown = |app: &[u8; 16]| {
            switch
                .shown(*app)
                .into_iter()
                .find(|item| item["seq"] == *seq)
                .unwrap_or_else(|| panic!("{what}: no item at {seq}"))
        };
        for app in full {
            let item = shown(app);
            assert_eq!(item["type"], "chain", "{what}, in full: {item}");
            assert_eq!(item["item_type"], *item_type, "{what}: {item}");
        }
        for app in stub {
            let item = shown(app);
            assert_eq!(item["type"], "stub", "{what}, a stub: {item}");
        }
    }
}

// -------------------------------------------------------------------------------------
// The outbox across a backup and a restore

/// Alice's wallet, with a note to bob queued and refused `403 not_admitted`, bob's shop, and
/// that note as signed.
async fn wallet_with_a_queued_note(
    p: &Pair,
    protocol: &Arc<ApiProtocol>,
) -> (App, App, SignedMessage) {
    let mut wallet = p.join(&p.alice, "wallet", protocol).await;
    let shop = p.join(&p.bob, "shop", protocol).await;
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    wallet.queue_signed(signed.clone()).await.unwrap();
    let delivery = wallet
        .flush_message(signed.msg_id())
        .await
        .unwrap()
        .unwrap();
    assert!(queued_with(&delivery, "not_admitted"), "{delivery:?}");
    (wallet, shop, signed)
}

/// `backup` restored for alice's wallet onto a new store.
async fn restored_wallet(p: &Pair, protocol: &Arc<ApiProtocol>, backup: &AppBackup) -> App {
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    let env = p.env(&p.alice, Arc::new(MemoryStore::new()));
    App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap()
}

#[tokio::test]
async fn test_backup_outbox_queued_message_delivers_after_the_restore() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    let msg_id = signed.msg_id().to_owned();
    assert!(
        matches!(
            restored.delivery(&msg_id).await.unwrap(),
            Some(Delivery::Queued { .. })
        ),
        "the restore put the message back in the outbox"
    );
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()], "{report:?}");
    // The same signed plaintext, so the same `msg_id` and hash.
    let sent = restored
        .sent_to(&p.bob.identity().public(), 0, u64::MAX)
        .await
        .unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].plaintext.encode(), signed.plaintext().encode());
    shop.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].msg_id, msg_id);
}

#[tokio::test]
async fn test_backup_outbox_message_delivered_since_the_backup_is_a_harmless_duplicate() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup_layered().await.unwrap();
    // The wallet delivers the note after the backup, and bob's app processes it.
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![signed.msg_id().to_owned()]);
    shop.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), 1);
    // Read, the entry is gone from bob's inbox.
    let alice = p.alice.identity().public();
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    // The restore from before the delivery sends it again: bob's switch, which no longer
    // holds the entry, takes it as new, and bob's app drops it by its processed pair.
    drop(wallet);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![signed.msg_id().to_owned()]);
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    shop.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), 1, "applied once");
    assert!(
        protocol.seen().iter().all(|seen| !seen.conflict),
        "the second copy is a duplicate, not a conflict"
    );
}

/// Whether the events tell the protocol, once, that `msg_id` wasn't delivered, as a re-send
/// or not.
fn undelivered_once(events: &[AppEvent], msg_id: &str, resend: bool) -> bool {
    events
        .iter()
        .filter(|e| matches!(e, AppEvent::MessageUndelivered { msg_id: m, resend: r, .. } if m == msg_id && *r == resend))
        .count()
        == 1
}

#[tokio::test]
async fn test_backup_outbox_past_the_window_gives_the_delivery_up() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    // A first try more than 30 days after the backup: bob's app may hold the processed pair
    // of a delivery since no longer.
    p.clock.advance_ms(SENT_RETENTION_MS + MINUTE);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    let msg_id = signed.msg_id().to_owned();
    restored.take_events();
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![msg_id.clone()]);
    assert!(undelivered_once(&restored.take_events(), &msg_id, false));
    assert_eq!(restored.delivery(&msg_id).await.unwrap(), None);
    restored.flush_outbox().await.unwrap();
    assert!(restored.take_events().is_empty(), "told once");
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

/// The deadline is checked at every try, not at the restore: a message put back 29 days
/// after the backup, and first tried two days later, isn't sent.
#[tokio::test]
async fn test_backup_outbox_restored_in_time_and_tried_past_the_window_isnt_sent() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    shop.invite(&p.alice.identity().public()).await.unwrap();
    assert_eq!(wallet.flush_outbox().await.unwrap().done.len(), 1);
    shop.receive(None).await.unwrap();
    drop(wallet);
    p.clock.advance_ms(29 * DAY_MS);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    assert!(matches!(
        restored.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
    p.clock.advance_ms(2 * DAY_MS);
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![signed.msg_id().to_owned()]);
    shop.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), 1, "applied once");
}

/// A device clock behind doesn't hold the window open: the deadline is judged at the later
/// of the device clock and the service time the flush verifies.
#[tokio::test]
async fn test_backup_outbox_window_holds_on_a_device_clock_behind() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    p.clock.advance_ms(32 * DAY_MS);
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    let mut env = p.env(&p.alice, Arc::new(MemoryStore::new()));
    env.clock = Arc::new(crate::clock::TestClock::new(p.clock.now_ms() - 3 * DAY_MS))
        as Arc<dyn crate::clock::Clock>;
    let mut restored = App::restore(env, protocol.clone(), config(), &backup)
        .await
        .unwrap();
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![signed.msg_id().to_owned()]);
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

/// A restored note tried at `offset` from its replay deadline: whether it went.
async fn tried_at_the_deadline(offset: i64) -> bool {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    let deadline = restored
        .outbox_record(signed.msg_id())
        .await
        .unwrap()
        .replay_until_ms()
        .unwrap();
    p.clock.set_ms(deadline.saturating_add_signed(offset));
    let report = restored.flush_outbox().await.unwrap();
    report.done == vec![signed.msg_id().to_owned()]
}

#[tokio::test]
async fn test_backup_outbox_window_ends_at_its_deadline() {
    assert!(tried_at_the_deadline(0).await, "at the deadline, it goes");
    assert!(!tried_at_the_deadline(1).await, "past it, it doesn't");
}

/// The deadline is the backup's time less the clock tolerance, plus 30 days, and a later
/// backup and restore carry it, never moved on.
#[tokio::test]
async fn test_backup_outbox_deadline_survives_a_later_backup() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let first = restored_wallet(&p, &protocol, &backup).await;
    let deadline = first
        .outbox_record(signed.msg_id())
        .await
        .unwrap()
        .replay_until_ms()
        .unwrap();
    assert!(deadline <= START + SENT_RETENTION_MS - CLOCK_TOLERANCE_MS);
    p.clock.advance_ms(20 * DAY_MS);
    let later = first.backup().await.unwrap();
    drop(first);
    let mut second = restored_wallet(&p, &protocol, &later).await;
    assert_eq!(
        second
            .outbox_record(signed.msg_id())
            .await
            .unwrap()
            .replay_until_ms(),
        Some(deadline)
    );
    shop.invite(&p.alice.identity().public()).await.unwrap();
    p.clock.advance_ms(11 * DAY_MS);
    let report = second.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![signed.msg_id().to_owned()]);
}

/// A message a restore put back, accepted only after the restore: a re-send of it goes by
/// the deadline the restore gave it, not 30 days from that later acceptance.
#[tokio::test]
async fn test_backup_outbox_resend_after_its_deadline_is_given_up() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&alice).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    let deadline = restored
        .outbox_record(signed.msg_id())
        .await
        .unwrap()
        .replay_until_ms()
        .unwrap();
    p.clock.set_ms(deadline - 5 * DAY_MS);
    let report = restored.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![signed.msg_id().to_owned()]);
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    p.clock.set_ms(deadline + DAY_MS);
    restored.take_events();
    restored.resend(signed.msg_id()).await.unwrap();
    assert_eq!(
        undelivered(&restored.take_events(), signed.msg_id()),
        vec![true]
    );
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "not delivered again"
    );
}

/// A re-send queued from `sent/` and given up past the window is told as a re-send.
#[tokio::test]
async fn test_backup_outbox_resend_given_up_says_resend() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    p.bob.switch().fail_next(Fault::Unreachable {
        path: "inbox".into(),
        after: 0,
    });
    let delivery = wallet.resend(&msg_id).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    p.clock.advance_ms(SENT_RETENTION_MS + MINUTE);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    restored.take_events();
    restored.flush_outbox().await.unwrap();
    assert!(undelivered_once(&restored.take_events(), &msg_id, true));
}

/// A message refused for good is carried as it stands: the restored app reports it failed.
#[tokio::test]
async fn test_backup_outbox_carries_failed_messages() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    p.bob.switch().fail_next(Fault::Error {
        path: "/inbox".into(),
        code: ErrorCode::BadRequest,
        current: Value::Null,
    });
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(matches!(delivery, Delivery::Failed { .. }), "{delivery:?}");
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let restored = restored_wallet(&p, &protocol, &backup).await;
    assert!(matches!(
        restored.delivery(&msg_id).await.unwrap(),
        Some(Delivery::Failed { .. })
    ));
}

/// An outbox over the byte budget is carried oldest first; the rest are told to the
/// protocol as undelivered, and the restore fits one commit.
#[tokio::test]
async fn test_backup_outbox_over_its_budget_carries_the_oldest() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let text = "x".repeat(40_000);
    let mut queued = Vec::new();
    for _ in 0..260 {
        let signed = wallet.sign_message(Pair::note(&p.bob, &text)).unwrap();
        queued.push(wallet.queue_signed(signed).await.unwrap());
        p.clock.advance_ms(1);
    }
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    let first = queued.first().unwrap();
    let last = queued.last().unwrap();
    assert!(restored.delivery(first).await.unwrap().is_some());
    assert_eq!(restored.delivery(last).await.unwrap(), None);
    let events = restored.take_events();
    assert!(
        undelivered_once(&events, last, false),
        "{} events",
        events.len()
    );
    let mut carried = 0;
    for msg_id in &queued {
        if restored.delivery(msg_id).await.unwrap().is_some() {
            carried += 1;
        } else {
            assert!(undelivered_once(&events, msg_id, false));
        }
    }
    assert!(carried > 0 && carried < queued.len(), "{carried}");
}

/// The deadline's base is the service time the backup's app had verified, not its device
/// clock: a device clock ahead at the backup doesn't move the window on.
#[tokio::test]
async fn test_backup_outbox_deadline_starts_at_the_verified_service_time() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let _shop = p.join(&p.bob, "shop", &protocol).await;
    // The wallet's device clock runs four minutes ahead of its switch.
    let ahead = Arc::new(crate::clock::TestClock::new(START + 4 * MINUTE));
    let keys = p.alice.identity().app_keys("wallet");
    let request = p
        .alice
        .approve(
            &keys,
            &AppSpec::new(&["scope-a"]).with_permissions(&Permission::ALL),
        )
        .unwrap();
    let mut env = p.env(&p.alice, Arc::new(MemoryStore::new()));
    env.clock = Arc::clone(&ahead) as Arc<dyn crate::clock::Clock>;
    let mut wallet = App::join(env, protocol.clone(), config(), request)
        .await
        .unwrap();
    wallet.receive(None).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    wallet.queue_signed(signed.clone()).await.unwrap();
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    let restored = restored_wallet(&p, &protocol, &backup).await;
    let deadline = restored
        .outbox_record(signed.msg_id())
        .await
        .unwrap()
        .replay_until_ms()
        .unwrap();
    assert_eq!(deadline, START + SENT_RETENTION_MS - CLOCK_TOLERANCE_MS);
}

#[tokio::test]
async fn test_scripted_invite_codes_spent_or_expired_go_at_the_minutes_sweep() {
    // As at the service (Switch wire 9.1): once a minute of the switch's clock, at a
    // request, the codes that expired or ran out go; a live one stays, and a spent one
    // stays until the next sweep.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let spent = shop
        .register_invite_code(START + DAY_MS, 1, json!({ "order": "o-1" }))
        .await
        .unwrap();
    let expiring = shop
        .register_invite_code(START + 10 * MINUTE, 1, Value::Null)
        .await
        .unwrap();
    let live = shop
        .register_invite_code(START + DAY_MS, 2, Value::Null)
        .await
        .unwrap();
    let mut first = Pair::note(&p.bob, "order");
    first.invite_code = Some(spent.code.clone());
    let (_, delivery) = wallet.send(first).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    shop.receive(None).await.unwrap();
    assert_eq!(p.bob.switch().invite_uses_left(&spent.code), Some(0));
    // A code expiring at the very time of the sweep is expired then, as at the service.
    let at_the_sweep = shop
        .register_invite_code(p.clock.now_ms() + 11 * MINUTE, 1, Value::Null)
        .await
        .unwrap();
    p.clock.advance_ms(11 * MINUTE);
    shop.receive(None).await.unwrap();
    let left = |code: &str| p.bob.switch().invite_uses_left(code);
    assert_eq!(left(&spent.code), None);
    assert_eq!(left(&expiring.code), None);
    assert_eq!(left(&at_the_sweep.code), None);
    assert_eq!(left(&live.code), Some(2));
}

#[tokio::test]
async fn test_scripted_invite_codes_sweep_with_the_clock_behind_its_mark() {
    // A minute's mark ahead of the switch's clock, left before the clock stepped back, is
    // due at once, as at the service: an expired code goes at the next request.
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let code = shop
        .register_invite_code(START + MINUTE, 1, Value::Null)
        .await
        .unwrap();
    p.bob.switch().lock().shared.swept_at = Some(START + DAY_MS);
    p.clock.advance_ms(2 * MINUTE);
    shop.receive(None).await.unwrap();
    assert_eq!(p.bob.switch().invite_uses_left(&code.code), None);
}

// -------------------------------------------------------------------------------------
// Holding and withdrawing the messages queued to a counterparty

#[tokio::test]
async fn test_hold_queued_holds_a_message_until_released() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    wallet.hold_queued(&bob).await.unwrap();
    assert_eq!(wallet.held_counterparties().await.unwrap(), vec![bob]);
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(matches!(delivery, Delivery::Queued { .. }), "{delivery:?}");
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.queued, vec![msg_id.clone()]);
    assert_eq!(p.bob.switch().entries_from(&alice), 0, "held");
    wallet.release_queued(&bob).await.unwrap();
    assert!(wallet.held_counterparties().await.unwrap().is_empty());
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id]);
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "released, delivered once"
    );
}

/// A batch that queues a message to a held counterparty, its answer lost: once it settles
/// the message is in the outbox, held, while the batch's other operation is applied.
#[tokio::test]
async fn test_hold_queued_holds_what_a_kept_batch_queues() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let batch = OpBatch::new()
        .op(OpKind::AllowPut {
            pubky: [9; 32],
            kind: pubky_switch_core::ops::AllowKind::Conversation,
        })
        .queue(signed.clone());
    assert!(
        wallet
            .submit_batch(batch)
            .await
            .unwrap_err()
            .kept_batch()
            .is_some()
    );
    wallet.hold_queued(&bob).await.unwrap();
    wallet.receive(None).await.unwrap();
    assert!(wallet.kept_batches().await.unwrap().is_empty(), "settled");
    assert!(matches!(
        wallet.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0, "held");
    wallet.release_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
}

/// Withdrawing gives up the messages queued to the counterparty and those a kept batch
/// would queue, each told once; none is delivered or queued again.
#[tokio::test]
async fn test_withdraw_queued_gives_up_queued_and_kept_batch_messages() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    wallet.hold_queued(&bob).await.unwrap();
    let first = wallet.sign_message(Pair::note(&p.bob, "first")).unwrap();
    wallet.queue_signed(first.clone()).await.unwrap();
    let second = wallet.sign_message(Pair::note(&p.bob, "second")).unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let batch = OpBatch::new()
        .op(OpKind::AllowPut {
            pubky: [9; 32],
            kind: pubky_switch_core::ops::AllowKind::Conversation,
        })
        .queue(second.clone());
    assert!(
        wallet
            .submit_batch(batch)
            .await
            .unwrap_err()
            .kept_batch()
            .is_some()
    );
    wallet.take_events();
    let withdrawn = wallet.withdraw_queued(&bob).await.unwrap();
    assert_eq!(
        withdrawn,
        vec![first.msg_id().to_owned(), second.msg_id().to_owned()]
    );
    let events = wallet.take_events();
    assert_eq!(undelivered(&events, first.msg_id()), vec![false]);
    assert_eq!(undelivered(&events, second.msg_id()), vec![false]);
    // The kept batch settles; neither message goes, even released and admitted.
    shop.invite(&alice).await.unwrap();
    wallet.release_queued(&bob).await.unwrap();
    wallet.receive(None).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    assert!(
        wallet
            .take_events()
            .iter()
            .all(|e| !matches!(e, AppEvent::MessageUndelivered { .. })),
        "told once"
    );
    let error = wallet.queue_stored(first.plaintext()).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Refused(Refusal::WontDeliver(WontDeliver::GivenUp))
        ),
        "{error:?}"
    );
}

/// A backup carries the hold: the restored app holds the counterparty and delivers none of
/// its messages. A restore in place also keeps a hold the host set after the backup.
#[tokio::test]
async fn test_hold_queued_survives_a_restore() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, mut shop, signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    wallet.hold_queued(&bob).await.unwrap();
    let backup = wallet.backup().await.unwrap();
    drop(wallet);
    shop.invite(&alice).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    assert_eq!(restored.held_counterparties().await.unwrap(), vec![bob]);
    restored.flush_outbox().await.unwrap();
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        0,
        "held after the restore"
    );
    assert!(matches!(
        restored.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Queued { .. })
    ));
    // In place: a backup taken before the hold, restored over a store that holds it.
    restored.release_queued(&bob).await.unwrap();
    let before = restored.backup().await.unwrap();
    restored.hold_queued(&bob).await.unwrap();
    let store = Arc::new(MemoryStore::new());
    drop(restored);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let before = AppBackup::from_bytes(&before.to_bytes().unwrap()).unwrap();
    let mut first = App::restore(env, protocol.clone(), config(), &before)
        .await
        .unwrap();
    first.hold_queued(&bob).await.unwrap();
    drop(first);
    let env = p.env(&p.alice, Arc::clone(&store) as Arc<dyn StateStore>);
    let in_place = App::restore(env, protocol.clone(), config(), &before)
        .await
        .unwrap();
    assert_eq!(in_place.held_counterparties().await.unwrap(), vec![bob]);
}

/// A held copy's replay deadline still runs: past it the copy is given up, once, though
/// held.
#[tokio::test]
async fn test_hold_queued_copy_past_its_deadline_is_given_up_once() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "old")).unwrap();
    p.clock.advance_ms(25 * DAY_MS);
    let msg_id = wallet.queue_stored(signed.plaintext()).await.unwrap();
    wallet.hold_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    p.clock.advance_ms(6 * DAY_MS);
    wallet.take_events();
    let report = wallet.flush_outbox().await.unwrap();
    assert_eq!(report.undelivered, vec![msg_id.clone()]);
    assert_eq!(undelivered(&wallet.take_events(), &msg_id), vec![false]);
    wallet.release_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
}

/// A re-send asked while the counterparty is held isn't delivered until the release; then it
/// goes once.
#[tokio::test]
async fn test_hold_queued_holds_a_resend_until_released() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let (msg_id, delivery) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    let before = p.bob.switch().entries_from(&alice);
    wallet.hold_queued(&bob).await.unwrap();
    wallet.resend(&msg_id).await.unwrap();
    wallet.flush_message(&msg_id).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), before, "held");
    wallet.release_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        before + 1,
        "released, re-sent once"
    );
}

/// A held message's tries aren't counted, and the conversation entry it owes waits with its
/// delivery.
#[tokio::test]
async fn test_hold_queued_counts_no_try_and_writes_no_conversation_entry() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let entries = |w: &ScriptedSwitch| {
        w.applied()
            .iter()
            .filter(|op| {
                matches!(op.body().kind, OpKind::AllowPut { pubky, kind: pubky_switch_core::ops::AllowKind::Conversation } if pubky == bob)
            })
            .count()
    };
    wallet.hold_queued(&bob).await.unwrap();
    let (msg_id, _) = wallet.send(Pair::note(&p.bob, "hello")).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert!(
        matches!(
            wallet.delivery(&msg_id).await.unwrap(),
            Some(Delivery::Queued { tries: 0, .. })
        ),
        "{:?}",
        wallet.delivery(&msg_id).await.unwrap()
    );
    assert_eq!(
        entries(p.alice.switch()),
        0,
        "no conversation entry while held"
    );
    wallet.release_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    assert_eq!(
        entries(p.alice.switch()),
        1,
        "the conversation entry, with the delivery"
    );
}

/// A kept batch that a later write settles, not a read: its message goes into the outbox
/// held.
#[tokio::test]
async fn test_hold_queued_holds_what_a_kept_batch_queues_when_a_write_settles_it() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let signed = wallet.sign_message(Pair::note(&p.bob, "hello")).unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let batch = OpBatch::new()
        .op(OpKind::AllowPut {
            pubky: [9; 32],
            kind: pubky_switch_core::ops::AllowKind::Conversation,
        })
        .queue(signed.clone());
    assert!(
        wallet
            .submit_batch(batch)
            .await
            .unwrap_err()
            .kept_batch()
            .is_some()
    );
    wallet.hold_queued(&bob).await.unwrap();
    wallet
        .submit_batch(OpBatch::new().op(OpKind::AllowPut {
            pubky: [8; 32],
            kind: pubky_switch_core::ops::AllowKind::Conversation,
        }))
        .await
        .unwrap();
    assert!(wallet.kept_batches().await.unwrap().is_empty(), "settled");
    wallet.flush_message(signed.msg_id()).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 0, "held");
    wallet.release_queued(&bob).await.unwrap();
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
}

/// A backup taken before the hold doesn't carry it: restored on another store, the message
/// isn't held, and goes at the first flush unless the host holds again first.
#[tokio::test]
async fn test_hold_queued_set_after_a_backup_isnt_carried_to_another_store() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let (mut wallet, mut shop, _signed) = wallet_with_a_queued_note(&p, &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    let backup = wallet.backup().await.unwrap();
    wallet.hold_queued(&bob).await.unwrap();
    drop(wallet);
    shop.invite(&alice).await.unwrap();
    let mut restored = restored_wallet(&p, &protocol, &backup).await;
    assert!(restored.held_counterparties().await.unwrap().is_empty());
    restored.flush_outbox().await.unwrap();
    assert_eq!(
        p.bob.switch().entries_from(&alice),
        1,
        "not held on the new store"
    );
}

/// A re-send given up by `withdraw_queued` isn't queued again when a send later finds the
/// counterparty's provider loss (`resend_since`).
#[tokio::test]
async fn test_withdraw_queued_resend_isnt_queued_again_after_a_provider_loss() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    let (first, delivery) = wallet.send(Pair::note(&p.bob, "one")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    // A re-send asked while held, then withdrawn.
    wallet.hold_queued(&bob).await.unwrap();
    wallet.resend(&first).await.unwrap();
    wallet.take_events();
    let withdrawn = wallet.withdraw_queued(&bob).await.unwrap();
    assert_eq!(withdrawn, vec![first.clone()]);
    assert_eq!(undelivered(&wallet.take_events(), &first), vec![true]);
    wallet.release_queued(&bob).await.unwrap();
    // Bob loses his provider and recovers at another.
    const RECOVERED: &str = "https://bob-recovered.example";
    let recovered =
        ScriptedSwitch::recovering(p.bob.identity().key(), [9; 32], Arc::clone(&p.clock), 2, 1)
            .unwrap();
    p.router.add_switch(RECOVERED, &recovered);
    let doc = p
        .bob
        .sign_next(|body| {
            body.generation = 2;
            body.inbox = Inbox::new(RECOVERED, recovered.service_key());
            body.recovery_from = Some(1);
        })
        .unwrap();
    recovered.deliver_identity(&doc).unwrap();
    recovered
        .lock()
        .shared
        .add_contact(p.alice.identity().public());
    p.clock.advance_ms(DOC_CACHE_MS + MINUTE);
    let two = wallet.send(Pair::note(&p.bob, "two")).await;
    let report = wallet.flush_outbox().await.unwrap();
    let events = wallet.take_events();
    assert!(
        matches!(
            wallet.delivery(&first).await.unwrap(),
            Some(Delivery::Accepted { .. })
        ),
        "the withdrawn re-send is in the outbox again: {:?}; two: {two:?}; report: {report:?}; entries at the recovered switch: {}",
        wallet.delivery(&first).await.unwrap(),
        recovered.entries_from(&alice)
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, AppEvent::ResendAfterLoss { .. })),
        "the withdrawn re-send is queued again: {events:?}"
    );
}

/// A withdrawn re-send that keeps its record job stays in the outbox with a give-up mark, so
/// a send that later finds the counterparty's provider loss doesn't queue it again.
#[tokio::test]
async fn test_withdraw_queued_resend_with_a_record_job_isnt_queued_again_after_a_provider_loss() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let mut shop = p.join(&p.bob, "shop", &protocol).await;
    let alice = p.alice.identity().public();
    let bob = p.bob.identity().public();
    shop.invite(&alice).await.unwrap();
    wallet.send(Pair::note(&p.bob, "zero")).await.unwrap();
    // Accepted, its record write's answer lost: the record job stays owed.
    let signed = wallet
        .sign_message(Pair::note(&p.bob, "one"))
        .unwrap()
        .with_record(crate::app::RecordJob {
            target: inbox(),
            tag: b"sent".to_vec(),
        });
    let one = wallet.queue_signed(signed).await.unwrap();
    p.alice
        .switch()
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    let delivery = wallet.flush_message(&one).await.unwrap();
    assert!(
        matches!(delivery, Some(Delivery::Accepted { .. })),
        "{delivery:?}"
    );
    assert!(
        wallet.outbox_record(&one).await.is_some(),
        "the record job is owed"
    );
    wallet.hold_queued(&bob).await.unwrap();
    // The record write fails again at the re-send's try, so the job is still owed.
    p.alice.switch().fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    wallet.resend(&one).await.unwrap();
    wallet.take_events();
    assert_eq!(
        wallet.withdraw_queued(&bob).await.unwrap(),
        vec![one.clone()]
    );
    assert_eq!(undelivered(&wallet.take_events(), &one), vec![true]);
    assert!(
        wallet.outbox_record(&one).await.is_some(),
        "kept for its record job"
    );
    wallet.release_queued(&bob).await.unwrap();
    // Bob loses his provider and recovers at another.
    const RECOVERED: &str = "https://bob-recovered.example";
    let recovered =
        ScriptedSwitch::recovering(p.bob.identity().key(), [9; 32], Arc::clone(&p.clock), 2, 1)
            .unwrap();
    p.router.add_switch(RECOVERED, &recovered);
    let doc = p
        .bob
        .sign_next(|body| {
            body.generation = 2;
            body.inbox = Inbox::new(RECOVERED, recovered.service_key());
            body.recovery_from = Some(1);
        })
        .unwrap();
    recovered.deliver_identity(&doc).unwrap();
    recovered.lock().shared.add_contact(alice);
    p.clock.advance_ms(DOC_CACHE_MS + MINUTE);
    wallet.send(Pair::note(&p.bob, "two")).await.unwrap();
    let events = wallet.take_events();
    // Only the message not given up is sent again.
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AppEvent::ResendAfterLoss { messages: 1, .. })),
        "{events:?}"
    );
    assert!(
        wallet
            .outbox_record(&one)
            .await
            .is_none_or(|item| !item.delivery_owed()),
        "no re-send of the withdrawn message is owed"
    );
}

#[tokio::test]
async fn test_hold_queued_refuses_the_own_identity() {
    let p = Pair::new();
    let protocol = ApiProtocol::new(Mode::Plain);
    let mut wallet = p.join(&p.alice, "wallet", &protocol).await;
    let alice = p.alice.identity().public();
    let error = wallet.hold_queued(&alice).await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error:?}"
    );
    assert!(wallet.held_counterparties().await.unwrap().is_empty());
}

/// Run `body` on a thread with a stack of `bytes`, in a runtime of that thread alone, as a
/// host on small threads does.
fn on_a_small_stack<F>(bytes: usize, body: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    std::thread::Builder::new()
        .stack_size(bytes)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(body());
        })
        .unwrap()
        .join()
        .expect("the read runs within the stack");
}

#[test]
fn test_receive_runs_on_a_one_mebibyte_stack() {
    // In a debug build, on a 1 MiB stack: a read whose entry's effect writes a record
    // through the context, one whose effect makes an attempt, one whose effect meets `409
    // conflict` and builds again, and the read that follows a move and sends the writes
    // kept during the freeze.
    on_a_small_stack(1 << 20, conflict_reads_again_and_builds_again);
    on_a_small_stack(1 << 20, || {
        super::moves::writes_kept_during_a_freeze_reach_the_next_service()
    });
    for mode in [Mode::Record, Mode::Attempt] {
        on_a_small_stack(1 << 20, move || async move {
            let w = World::new();
            let protocol = ApiProtocol::new(mode);
            let mut app = join(&w, &protocol, "wallet").await;
            w.note(app.app_id(), "hello");
            app.receive(None).await.unwrap();
            assert!(!protocol.seen().is_empty());
        });
    }
}
