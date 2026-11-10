//! What a protocol reads through the app beyond its store: blinded inputs under the naming
//! key, a counterparty's `identity.json` with what each lookup read, claims from the switch
//! during a receive step, and its local state from its other callbacks; and its batches,
//! sealed again after the data epoch rises.

use std::sync::{Arc, Mutex};

use pubky_switch_core::claims::{Basis, ClaimStatus, EntryKind, Outcome as AttemptOutcome};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{Condition, KeyBundlePut, OpKind, RecordVersion, SignedOp};
use pubky_switch_core::records::{AppCert, AppRecord, IdentityDoc, seal_bundle_parts};
use pubky_switch_core::scopes::Permission;
use serde_json::json;

use super::protocol_api::{BOB_ORIGIN, Pair, config};
use super::shared_flows::{ItemsProtocol, ids, items, value};
use super::*;
use crate::app::{
    AppError, AppEvent, ClaimFetch, ClaimOp, Collection, DOC_CACHE_MS, Delivery, HomeserverCopy,
    Initiator, LocalView, MAX_CLAIM_READS, MayAct, Need, ObligationDeadline, OpBatch, ParkReason,
    PeerIdentity, ReceiveContext, RecordTarget, Refusal, SwitchCopy,
};
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::Fault;

const MINUTE: u64 = 60_000;
const ATTEMPT: [u8; 16] = [6; 16];
const GRACE: u64 = 500;

/// The input a note's obligation is named by, blinded into its claim key.
const OBLIGATION: &[u8] = b"sample obligation";

/// What [`ReadsProtocol`]'s receive step does with a note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Read the obligation's claim from the switch, then settle its open attempt with the
    /// note as evidence.
    Settle,
    /// Ask for the obligation's claim on every call.
    NeedAgain,
    /// Ask for more claims than one entry gets.
    NeedTooMany,
}

/// What one call of the receive step saw.
#[derive(Clone, Debug)]
struct Seen {
    /// The claim as the switch gave it, if read.
    fetched: Option<ClaimFetch>,
}

/// [`ItemsProtocol`], with a receive step that reads claims from the switch, and a sending
/// rule that reads the protocol's local state.
struct ReadsProtocol {
    items: ItemsProtocol,
    mode: Mutex<Mode>,
    seen: Mutex<Vec<Seen>>,
}

impl ReadsProtocol {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            items: ItemsProtocol::default(),
            mode: Mutex::new(mode),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn settle(cx: &mut ReceiveContext<'_>, claim_key: [u8; 32], evidence: [u8; 32]) {
        let Some(ClaimFetch::Read(read)) = cx.switch_claim(&claim_key).cloned() else {
            return;
        };
        if read.view.status == ClaimStatus::Settled {
            return;
        }
        let open = read.view.attempts.iter().find(|a| {
            matches!(
                a.outcome,
                AttemptOutcome::Open | AttemptOutcome::Unknown | AttemptOutcome::Failed
            )
        });
        let Some(attempt) = open else {
            return;
        };
        let Ok(op) = ClaimOp::done(
            claim_key,
            read.view.step,
            attempt.attempt_id,
            Basis::Evidence,
            Some(evidence),
        ) else {
            return;
        };
        let Ok(condition) = cx.claim_condition(&claim_key) else {
            return;
        };
        let _ = cx.claim(op, vec![condition], ObligationDeadline::NotKnown);
    }
}

impl Protocol for ReadsProtocol {
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

    fn receive_with(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        let mode = *self.mode.lock().unwrap();
        let claim_key = cx.blind(OBLIGATION);
        let fetched = cx.switch_claim(&claim_key).cloned();
        self.seen.lock().unwrap().push(Seen {
            fetched: fetched.clone(),
        });
        match mode {
            Mode::Settle => {
                if fetched.is_none() {
                    return Outcome::Need(vec![Need::Claim(claim_key)]);
                }
                let evidence = *blake3::hash(message.message.msg_id.as_bytes()).as_bytes();
                Self::settle(cx, claim_key, evidence);
                Outcome::Apply(Effect::default())
            }
            Mode::NeedAgain => Outcome::Need(vec![Need::Claim(claim_key)]),
            Mode::NeedTooMany => {
                let count = u8::try_from(MAX_CLAIM_READS + 1).unwrap();
                Outcome::Need((0..count).map(|i| Need::Claim([i; 32])).collect())
            }
        }
    }

    fn resend_needed(&self, needed: &ResendNeeded) -> Vec<LocalWrite> {
        self.items.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Vec<LocalWrite> {
        self.items.missed(missed)
    }

    fn collections(&self) -> Vec<Collection> {
        vec![items()]
    }

    /// No message goes while the protocol's local state holds `mute`.
    fn sends_to_with(
        &self,
        _message: &Message,
        _recipient: &AppRecord,
        view: &LocalView<'_>,
    ) -> bool {
        view.local_get(b"mute").unwrap().is_none()
    }
}

async fn join_on(
    w: &World,
    protocol: Arc<dyn Protocol>,
    name: &str,
    store: Arc<dyn StateStore>,
) -> App {
    let app = AppSpec::new(&["scope-a"]).with_permissions(&Permission::ALL);
    let request = w.signer.approve(&app_keys(name), &app).unwrap();
    App::join(w.env_on(store), protocol, config(), request)
        .await
        .unwrap()
}

async fn join(w: &World, protocol: Arc<dyn Protocol>, name: &str) -> App {
    join_on(w, protocol, name, Arc::new(MemoryStore::new())).await
}

fn inbox() -> RecordTarget {
    RecordTarget::new(items(), b"inbox")
}

// -------------------------------------------------------------------------------------
// Blinded inputs (Switch wire 1.5)

#[tokio::test]
async fn test_blind_is_the_naming_key_derivation_shared_by_own_apps() {
    let w = World::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let wallet = join(&w, protocol.clone(), "wallet").await;
    let phone = join(&w, protocol.clone(), "phone").await;
    assert_eq!(
        wallet.blind(OBLIGATION),
        wallet.naming_key().blind(OBLIGATION)
    );
    // Every app of the identity finds the same key.
    assert_eq!(wallet.blind(OBLIGATION), phone.blind(OBLIGATION));
}

#[tokio::test]
async fn test_blind_differs_by_input_and_by_identity() {
    let p = Pair::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::new(MemoryStore::new()),
        )
        .await;
    let shop = p
        .join_on(&p.bob, "shop", protocol, Arc::new(MemoryStore::new()))
        .await;
    assert_ne!(
        wallet.blind(OBLIGATION),
        wallet.blind(b"another obligation")
    );
    // Another identity's naming key: the stored keys name no counterparty's inputs.
    assert_ne!(wallet.blind(OBLIGATION), shop.blind(OBLIGATION));
}

// -------------------------------------------------------------------------------------
// Claims read from the switch in a receive step (Switch spec 10.2; Switch wire 7.4.8)

/// Another own app opens an attempt on the obligation's claim; returns the claim key.
async fn attempt_elsewhere(phone: &mut App) -> [u8; 32] {
    let claim_key = phone.blind(OBLIGATION);
    let attempt = ClaimOp::attempt(claim_key, 0, ATTEMPT, 3600, None);
    phone
        .submit_batch(OpBatch::new().op(attempt.kind()))
        .await
        .unwrap();
    claim_key
}

fn claim_gets(w: &World) -> usize {
    w.switch
        .applied()
        .iter()
        .filter(|op| matches!(op.body().kind, OpKind::Claim(_)))
        .count()
}

#[tokio::test]
async fn test_receive_need_reads_the_claim_and_settles_it_with_the_cursor() {
    let w = World::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let mut wallet = join(&w, protocol.clone(), "wallet").await;
    let mut phone = join(&w, protocol.clone(), "phone").await;
    let claim_key = attempt_elsewhere(&mut phone).await;
    let (seq, _) = w.note(wallet.app_id(), "receipt");
    wallet.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(seen[0].fetched.is_none(), "asked first");
    let Some(ClaimFetch::Read(read)) = &seen[1].fetched else {
        panic!("read: {seen:?}")
    };
    // The switch's answer carries the entries (Switch wire 7.4.8), checked.
    assert_eq!(read.entries.len(), 1);
    assert_eq!(read.entries[0].writer, Some(phone.app_id()));
    assert!(matches!(
        read.entries[0].entry.kind,
        EntryKind::Attempt { .. }
    ));
    // The settling entry went in the batch that moved the cursor.
    let claim = w.switch.claim(&claim_key).unwrap();
    assert_eq!(claim.step, 2);
    assert_eq!(claim_gets(&w), 2);
    assert_eq!(w.switch.app(&wallet.app_id()).cursor, seq);
    let evidence = wallet.claim_evidence(&claim_key).await.unwrap().unwrap();
    assert_eq!(evidence.view.status, ClaimStatus::Settled);
    // Every attempt done: compacted to a tombstone, which carries no entries.
    let read = wallet.read_claim(&claim_key).await.unwrap().unwrap();
    assert!(read.view.tombstone);
    assert!(read.entries.is_empty());
}

#[tokio::test]
async fn test_receive_need_of_an_absent_claim_applies_without_it() {
    let w = World::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let mut wallet = join(&w, protocol.clone(), "wallet").await;
    let (seq, _) = w.note(wallet.app_id(), "receipt");
    wallet.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].fetched, Some(ClaimFetch::Absent));
    assert_eq!(claim_gets(&w), 0);
    assert_eq!(wallet.cursor().seq, seq);
}

#[tokio::test]
async fn test_receive_need_refused_read_is_handed_over_with_its_code() {
    let w = World::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let mut wallet = join(&w, protocol.clone(), "wallet").await;
    let (seq, _) = w.note(wallet.app_id(), "receipt");
    w.switch.fail_next(Fault::Error {
        path: "claims/".into(),
        code: ErrorCode::PermissionMissing,
        current: json!(null),
    });
    wallet.receive(None).await.unwrap();
    let seen = protocol.seen();
    assert_eq!(
        seen[1].fetched,
        Some(ClaimFetch::Refused("permission_missing".into()))
    );
    assert_eq!(wallet.cursor().seq, seq);
}

#[tokio::test]
async fn test_receive_need_failing_for_now_holds_the_entry() {
    let w = World::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let mut wallet = join(&w, protocol.clone(), "wallet").await;
    let mut phone = join(&w, protocol.clone(), "phone").await;
    let claim_key = attempt_elsewhere(&mut phone).await;
    let (seq, _) = w.note(wallet.app_id(), "receipt");
    w.switch.fail_next(Fault::Error {
        path: "claims/".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    wallet.receive(None).await.unwrap();
    assert!(wallet.cursor().seq < seq, "the entry waits");
    assert_eq!(w.switch.claim(&claim_key).unwrap().step, 1);
    // Read again at the next read of the feed, and settled then.
    wallet.receive(None).await.unwrap();
    assert_eq!(wallet.cursor().seq, seq);
    assert_eq!(w.switch.claim(&claim_key).unwrap().step, 2);
}

#[tokio::test]
async fn test_receive_need_asked_again_parks_the_entry() {
    let w = World::new();
    let protocol = ReadsProtocol::new(Mode::NeedAgain);
    let mut wallet = join(&w, protocol.clone(), "wallet").await;
    let (seq, _) = w.note(wallet.app_id(), "receipt");
    let report = wallet.receive(None).await.unwrap();
    // One read, then the same need again: stored and passed, no loop.
    assert_eq!(protocol.seen().len(), 2);
    assert!(report.events.iter().any(|e| matches!(
        e,
        AppEvent::Parked { seq: s, reason: ParkReason::TooManyReads } if *s == seq
    )));
    assert_eq!(wallet.cursor().seq, seq);
    // Not tried again.
    wallet.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), 2);
}

#[tokio::test]
async fn test_receive_need_past_the_bound_reads_nothing() {
    let w = World::new();
    let protocol = ReadsProtocol::new(Mode::NeedTooMany);
    let mut wallet = join(&w, protocol.clone(), "wallet").await;
    let (seq, _) = w.note(wallet.app_id(), "receipt");
    let report = wallet.receive(None).await.unwrap();
    assert_eq!(protocol.seen().len(), 1);
    assert!(report.events.iter().any(|e| matches!(
        e,
        AppEvent::Parked {
            reason: ParkReason::TooManyReads,
            ..
        }
    )));
    assert_eq!(wallet.cursor().seq, seq);
}

/// One run of the settling scenario: join both apps, the phone's attempt, a note to the
/// wallet, the wallet's read. Returns at the first error, as a process that died.
async fn need_scenario(
    w: &World,
    protocol: &Arc<ReadsProtocol>,
    store: Arc<dyn StateStore>,
    phone: &mut Option<App>,
    sent: &mut Option<u64>,
    approval: &mut Option<JoinRequest>,
) -> Result<(), AppError> {
    let keys = app_keys("wallet");
    let env = w.env_on(Arc::clone(&store));
    let mut wallet =
        match App::load(env.clone(), protocol.clone(), config(), keys.app_id_bytes()).await {
            Ok(app) => app,
            Err(AppError::Refused(Refusal::NotJoined)) => {
                let app = AppSpec::new(&["scope-a"]).with_permissions(&Permission::ALL);
                let request = approval
                    .get_or_insert_with(|| w.signer.approve(&keys, &app).unwrap())
                    .clone();
                App::join(env, protocol.clone(), config(), request).await?
            }
            Err(error) => return Err(error),
        };
    wallet.receive(None).await?;
    if phone.is_none() {
        let mut other = join(w, protocol.clone(), "phone").await;
        attempt_elsewhere(&mut other).await;
        *phone = Some(other);
    }
    if sent.is_none() {
        *sent = Some(w.note(wallet.app_id(), "receipt").0);
    }
    wallet.receive(None).await?;
    wallet.receive(None).await?;
    Ok(())
}

#[tokio::test]
async fn test_receive_need_crash_at_each_commit_point_settles_once() {
    let commits = {
        let w = World::new();
        let counting = Arc::new(FaultStore::new(
            Arc::new(MemoryStore::new()) as Arc<dyn StateStore>,
            StoreFault::None,
        ));
        need_scenario(
            &w,
            &ReadsProtocol::new(Mode::Settle),
            Arc::clone(&counting) as Arc<dyn StateStore>,
            &mut None,
            &mut None,
            &mut None,
        )
        .await
        .unwrap();
        counting.commits()
    };
    assert!(commits > 4, "the scenario commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let w = World::new();
            let protocol = ReadsProtocol::new(Mode::Settle);
            let inner = Arc::new(MemoryStore::new());
            let fault = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let (mut phone, mut sent, mut approval) = (None, None, None);
            let first = need_scenario(
                &w,
                &protocol,
                Arc::clone(&fault) as Arc<dyn StateStore>,
                &mut phone,
                &mut sent,
                &mut approval,
            )
            .await;
            assert!(fault.stopped(), "commit {n} of {commits} is reached");
            assert!(first.is_err());
            need_scenario(
                &w,
                &protocol,
                Arc::clone(&inner) as Arc<dyn StateStore>,
                &mut phone,
                &mut sent,
                &mut approval,
            )
            .await
            .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            // The attempt and one settling entry: the effect applied once, the cursor past.
            let phone = phone.as_ref().unwrap();
            let claim = w.switch.claim(&phone.blind(OBLIGATION)).unwrap();
            assert_eq!(claim.step, 2, "commit {n} ({stop_after})");
            assert_eq!(claim_gets(&w), 2, "commit {n} ({stop_after})");
            let wallet = App::load(
                w.env_on(Arc::clone(&inner) as Arc<dyn StateStore>),
                protocol.clone(),
                config(),
                app_keys("wallet").app_id_bytes(),
            )
            .await
            .unwrap();
            assert!(
                wallet.cursor().seq >= sent.unwrap(),
                "commit {n} ({stop_after})"
            );
        }
    }
}

// -------------------------------------------------------------------------------------
// Batches sealed again after the data epoch rises (Switch spec 3.5, 13.4)

/// The signer raises the data epoch to 2 and stores the app's key bundle through it.
fn raise_epoch(w: &World, app: &App) {
    let cert = app.cert().clone();
    let has_keys = |scope: &str| SampleProtocol::default().has_keys(scope);
    w.next_doc(|body| body.data_epoch = 2);
    bundle_through(w, app.app_id(), &cert, 2, &has_keys);
}

fn bundle_through(
    w: &World,
    app_id: [u8; 16],
    cert: &AppCert,
    last: u64,
    has_keys: &dyn Fn(&str) -> bool,
) {
    for part in seal_bundle_parts(&w.alice, cert, 1, last, has_keys).unwrap() {
        w.switch
            .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: app_id,
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
    }
}

fn sealed_epoch(w: &World, key: &[u8; 32]) -> Option<u64> {
    let held = w.switch.record(key)?;
    match SignedOp::peek(&held.op).ok()?.body().kind.clone() {
        OpKind::RecordPut(put) => Some(put.value_sealed.data_epoch),
        _ => None,
    }
}

fn local(key: &str) -> LocalWrite {
    LocalWrite::Put {
        key: key.as_bytes().to_vec(),
        value: b"1".to_vec(),
    }
}

#[tokio::test]
async fn test_submit_batch_stale_epoch_seals_again_and_sends_once_more() {
    let w = World::new();
    let mut app = join(&w, ReadsProtocol::new(Mode::Settle), "wallet").await;
    // Built at epoch 1, before the app learns of epoch 2.
    let entry = app
        .record_op(&inbox(), Some(&value(&["a"])), vec![])
        .await
        .unwrap();
    let key = app.record_key(&inbox()).unwrap();
    raise_epoch(&w, &app);
    app.submit_batch(
        OpBatch::new()
            .entry(entry)
            .op(OpKind::DenyPut { pubky: [9; 32] })
            .local(local("written")),
    )
    .await
    .unwrap();
    assert_eq!(app.data_epoch(), 2);
    assert_eq!(sealed_epoch(&w, &key), Some(2));
    let record = app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(ids(record.content.value()), vec!["a"]);
    assert!(app.protocol_get(b"written").await.unwrap().is_some());
}

#[tokio::test]
async fn test_submit_batch_stale_epoch_keeps_the_conditions_and_version() {
    let w = World::new();
    let mut app = join(&w, ReadsProtocol::new(Mode::Settle), "wallet").await;
    let key = app.record_key(&inbox()).unwrap();
    let condition = app.record_condition(&key).await.unwrap();
    let entry = app
        .record_op(&inbox(), Some(&value(&["a"])), vec![condition])
        .await
        .unwrap();
    raise_epoch(&w, &app);
    app.submit_batch(OpBatch::new().entry(entry)).await.unwrap();
    // Sealed again: the same condition and expected version, at the new epoch.
    let held = w.switch.record(&key).unwrap();
    let op = SignedOp::peek(&held.op).unwrap();
    assert_eq!(op.body().conditions, vec![condition]);
    let OpKind::RecordPut(put) = &op.body().kind else {
        panic!("a record.put")
    };
    assert_eq!(put.expected_version, RecordVersion::NONE);
    assert_eq!(put.value_sealed.data_epoch, 2);
}

#[tokio::test]
async fn test_submit_batch_stale_epoch_behind_a_failing_condition_is_the_conflict() {
    let w = World::new();
    let mut app = join(&w, ReadsProtocol::new(Mode::Settle), "wallet").await;
    let key = app.record_key(&inbox()).unwrap();
    let wrong = Condition::RecordVersion {
        key,
        version: RecordVersion::new(1, 99),
    };
    let entry = app
        .record_op(&inbox(), Some(&value(&["a"])), vec![wrong])
        .await
        .unwrap();
    raise_epoch(&w, &app);
    let error = app
        .submit_batch(OpBatch::new().entry(entry).local(local("written")))
        .await
        .unwrap_err();
    // Conditions come before the operation's own rules (Switch wire 6.4 steps 8 and 9).
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    assert!(w.switch.record(&key).is_none());
    assert!(app.protocol_get(b"written").await.unwrap().is_none());
}

#[tokio::test]
async fn test_submit_batch_stale_epoch_without_the_new_key_is_not_now() {
    let w = World::new();
    let mut app = join(&w, ReadsProtocol::new(Mode::Settle), "wallet").await;
    let entry = app
        .record_op(&inbox(), Some(&value(&["a"])), vec![])
        .await
        .unwrap();
    w.next_doc(|body| body.data_epoch = 2);
    let error = app
        .submit_batch(OpBatch::new().entry(entry).local(local("written")))
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::NotNow(_))),
        "{error:?}"
    );
    let key = app.record_key(&inbox()).unwrap();
    assert!(w.switch.record(&key).is_none());
    assert!(app.protocol_get(b"written").await.unwrap().is_none());
}

#[tokio::test]
async fn test_submit_batch_stale_epoch_before_the_homeserver_has_it_is_returned() {
    let w = World::new();
    let mut app = join(&w, ReadsProtocol::new(Mode::Settle), "wallet").await;
    let entry = app
        .record_op(&inbox(), Some(&value(&["a"])), vec![])
        .await
        .unwrap();
    // The switch holds epoch 2; the Homeserver still publishes the version before.
    let published = w.switch.identity_doc().unwrap();
    let cert = app.cert().clone();
    let has_keys = |scope: &str| SampleProtocol::default().has_keys(scope);
    let newer = w.signer.sign_next(|body| body.data_epoch = 2).unwrap();
    w.switch.deliver_identity(&newer).unwrap();
    w.homeserver.publish(&published).unwrap();
    bundle_through(&w, app.app_id(), &cert, 2, &has_keys);
    let error = app
        .submit_batch(OpBatch::new().entry(entry))
        .await
        .unwrap_err();
    // The caller builds the batch again once the app holds the newer document.
    assert_eq!(error.code(), Some(ErrorCode::StaleEpoch));
    assert_eq!(app.data_epoch(), 1);
}

/// One run of the writing scenario: join, the epoch rises once, then a write built at the
/// epoch held and submitted. Returns at the first error, as a process that died.
async fn epoch_scenario(
    w: &World,
    protocol: &Arc<ReadsProtocol>,
    store: Arc<dyn StateStore>,
    raised: &mut bool,
    approval: &mut Option<JoinRequest>,
) -> Result<(), AppError> {
    let keys = app_keys("wallet");
    let env = w.env_on(Arc::clone(&store));
    let mut app =
        match App::load(env.clone(), protocol.clone(), config(), keys.app_id_bytes()).await {
            Ok(app) => app,
            Err(AppError::Refused(Refusal::NotJoined)) => {
                let spec = AppSpec::new(&["scope-a"]).with_permissions(&Permission::ALL);
                let request = approval
                    .get_or_insert_with(|| w.signer.approve(&keys, &spec).unwrap())
                    .clone();
                App::join(env, protocol.clone(), config(), request).await?
            }
            Err(error) => return Err(error),
        };
    app.receive(None).await?;
    let held = app.read_record(&inbox()).await?;
    if held.is_some_and(|r| ids(r.content.value()) == vec!["a"]) {
        return Ok(());
    }
    let entry = app
        .record_op(&inbox(), Some(&value(&["a"])), vec![])
        .await?;
    if !*raised {
        raise_epoch(w, &app);
        *raised = true;
    }
    match app.submit_batch(OpBatch::new().entry(entry)).await {
        Ok(_) => Ok(()),
        // A kept batch sent first created the record: this create meets it.
        Err(error) if error.code() == Some(ErrorCode::Conflict) => Ok(()),
        Err(error) => Err(error),
    }
}

#[tokio::test]
async fn test_submit_batch_stale_epoch_crash_at_each_commit_point_writes_once() {
    let commits = {
        let w = World::new();
        let counting = Arc::new(FaultStore::new(
            Arc::new(MemoryStore::new()) as Arc<dyn StateStore>,
            StoreFault::None,
        ));
        epoch_scenario(
            &w,
            &ReadsProtocol::new(Mode::Settle),
            Arc::clone(&counting) as Arc<dyn StateStore>,
            &mut false,
            &mut None,
        )
        .await
        .unwrap();
        counting.commits()
    };
    assert!(commits > 4, "the scenario commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let w = World::new();
            let protocol = ReadsProtocol::new(Mode::Settle);
            let inner = Arc::new(MemoryStore::new());
            let fault = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let (mut raised, mut approval) = (false, None);
            let first = epoch_scenario(
                &w,
                &protocol,
                Arc::clone(&fault) as Arc<dyn StateStore>,
                &mut raised,
                &mut approval,
            )
            .await;
            assert!(fault.stopped(), "commit {n} of {commits} is reached");
            assert!(first.is_err());
            // Twice: a batch kept at the crash goes with the next call.
            for _ in 0..2 {
                epoch_scenario(
                    &w,
                    &protocol,
                    Arc::clone(&inner) as Arc<dyn StateStore>,
                    &mut raised,
                    &mut approval,
                )
                .await
                .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            }
            let app = App::load(
                w.env_on(Arc::clone(&inner) as Arc<dyn StateStore>),
                protocol.clone(),
                config(),
                app_keys("wallet").app_id_bytes(),
            )
            .await
            .unwrap();
            let key = app.record_key(&inbox()).unwrap();
            let puts = w
                .switch
                .applied()
                .iter()
                .filter(|op| matches!(op.body().kind, OpKind::RecordPut(_)))
                .count();
            assert_eq!(puts, 1, "commit {n} ({stop_after})");
            assert_eq!(sealed_epoch(&w, &key), Some(2), "commit {n} ({stop_after})");
        }
    }
}

// -------------------------------------------------------------------------------------
// A counterparty's identity.json: what each lookup read (Switch spec 4.3)

#[tokio::test]
async fn test_identity_lookup_reports_each_source_and_its_time() {
    let p = Pair::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::new(MemoryStore::new()),
        )
        .await;
    let _shop = p
        .join_on(&p.bob, "shop", protocol, Arc::new(MemoryStore::new()))
        .await;
    let bob = p.bob.identity().public();
    let start = p.clock.now_ms();
    let found = wallet.identity_of(&bob, false).await.unwrap();
    assert_eq!(found.homeserver, HomeserverCopy::Read);
    assert_eq!(found.switch_copy, SwitchCopy::Read);
    assert_eq!(found.read_at_ms, start);
    assert_eq!(found.homeserver_read_ms, Some(start));
    assert_eq!(found.switch_read_ms, Some(start));
    assert_eq!(
        found.may_act(start, Initiator::Automatic, GRACE),
        MayAct::Now
    );
    // Within 10 minutes the copy held stands: nothing read now.
    p.clock.advance_ms(MINUTE);
    let held = wallet.identity_of(&bob, false).await.unwrap();
    assert_eq!(held.homeserver, HomeserverCopy::Held);
    assert_eq!(held.read_at_ms, start);
    assert_eq!(held.switch_lookup_ms, start);
    assert_eq!(held.fresh_until_ms(), start + DOC_CACHE_MS);
    // Past them, the copy must be looked up again before acting.
    let late = start + DOC_CACHE_MS;
    assert_eq!(
        held.may_act(late, Initiator::User, GRACE),
        MayAct::LookUpAgain
    );
}

#[tokio::test]
async fn test_identity_lookup_with_no_source_keeps_the_last_read_time() {
    let p = Pair::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::new(MemoryStore::new()),
        )
        .await;
    let _shop = p
        .join_on(&p.bob, "shop", protocol, Arc::new(MemoryStore::new()))
        .await;
    let bob = p.bob.identity().public();
    let start = p.clock.now_ms();
    wallet.identity_of(&bob, false).await.unwrap();
    p.clock.advance_ms(11 * MINUTE);
    p.alice.homeserver().set_down(true);
    p.router.remove(BOB_ORIGIN);
    let found = wallet.identity_of(&bob, false).await.unwrap();
    assert_eq!(found.homeserver, HomeserverCopy::Unavailable);
    assert_eq!(found.switch_copy, SwitchCopy::Unavailable);
    // The copy held was read at the start, not now.
    assert_eq!(found.read_at_ms, start);
    assert_eq!(found.homeserver_read_ms, Some(start));
    assert_eq!(found.switch_read_ms, Some(start));
    assert_eq!(found.switch_lookup_ms, start + 11 * MINUTE);
    assert_eq!(
        found.may_act(p.clock.now_ms(), Initiator::User, GRACE),
        MayAct::LookUpAgain
    );
}

#[tokio::test]
async fn test_identity_lookup_switch_alone_confirms_without_the_homeserver() {
    let p = Pair::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::new(MemoryStore::new()),
        )
        .await;
    let _shop = p
        .join_on(&p.bob, "shop", protocol, Arc::new(MemoryStore::new()))
        .await;
    let bob = p.bob.identity().public();
    let start = p.clock.now_ms();
    wallet.identity_of(&bob, false).await.unwrap();
    p.clock.advance_ms(11 * MINUTE);
    p.alice.homeserver().set_down(true);
    let found = wallet.identity_of(&bob, false).await.unwrap();
    let now = p.clock.now_ms();
    assert_eq!(found.homeserver, HomeserverCopy::Unavailable);
    assert_eq!(found.homeserver_read_ms, Some(start));
    assert_eq!(found.switch_copy, SwitchCopy::Read);
    assert_eq!(found.switch_read_ms, Some(now));
    assert_eq!(found.read_at_ms, now);
    assert_eq!(found.may_act(now, Initiator::Automatic, GRACE), MayAct::Now);
}

#[tokio::test]
async fn test_identity_lookup_split_waits_a_grace_then_takes_the_answer() {
    let p = Pair::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::new(MemoryStore::new()),
        )
        .await;
    let _shop = p
        .join_on(&p.bob, "shop", protocol, Arc::new(MemoryStore::new()))
        .await;
    // The switch holds a version the Homeserver doesn't publish yet.
    let mut body = p.bob.body();
    body.version += 1;
    let newer = IdentityDoc::sign(p.bob.identity().key(), body).unwrap();
    p.bob.switch().deliver_identity(&newer).unwrap();
    let bob = p.bob.identity().public();
    let lookup = wallet.begin_identity_lookup(&bob, false).await.unwrap();
    let begun = lookup.identity.clone();
    assert_eq!(begun.homeserver, HomeserverCopy::Read);
    assert_eq!(begun.switch_copy, SwitchCopy::Pending);
    assert!(begun.doc.version() < newer.version());
    let now = p.clock.now_ms();
    assert_eq!(
        begun.may_act(now, Initiator::User, GRACE),
        MayAct::WaitUntil(now + GRACE)
    );
    // The grace passes: a user's action goes on the user's word, an automatic one waits.
    let late = now + GRACE;
    assert_eq!(
        begun.may_act(late, Initiator::User, GRACE),
        MayAct::IfUserConfirms
    );
    assert_eq!(
        begun.may_act(late, Initiator::Automatic, GRACE),
        MayAct::WaitForLookup
    );
    // The answer arrives before the action takes effect: still used.
    let answer = lookup.switch.unwrap().await;
    assert!(answer.read());
    assert_eq!(answer.identity(), bob);
    let found = wallet.finish_identity_lookup(answer).await.unwrap();
    assert_eq!(found.switch_copy, SwitchCopy::Read);
    assert_eq!(found.doc.version(), newer.version());
    assert_eq!(
        found.may_act(late, Initiator::Automatic, GRACE),
        MayAct::Now
    );
    // Fresh now: the next lookup runs nothing.
    let again = wallet.begin_identity_lookup(&bob, false).await.unwrap();
    assert!(again.switch.is_none());
    assert_eq!(again.identity.homeserver, HomeserverCopy::Held);
}

#[tokio::test]
async fn test_identity_lookup_split_answer_held_past_ten_minutes_is_stale() {
    let p = Pair::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::new(MemoryStore::new()),
        )
        .await;
    let _shop = p
        .join_on(&p.bob, "shop", protocol, Arc::new(MemoryStore::new()))
        .await;
    let bob = p.bob.identity().public();
    let lookup = wallet.begin_identity_lookup(&bob, true).await.unwrap();
    let answer = lookup.switch.unwrap().await;
    let read_ms = p.clock.now_ms();
    assert!(answer.read());
    assert_eq!(answer.read_ms(), read_ms);
    // The answer is held past the 10 minutes before it is finished.
    p.clock.advance_ms(11 * MINUTE);
    let found = wallet.finish_identity_lookup(answer).await.unwrap();
    let now = p.clock.now_ms();
    assert_eq!(found.switch_copy, SwitchCopy::Read);
    assert_eq!(found.switch_lookup_ms, read_ms);
    assert_eq!(found.switch_read_ms, Some(read_ms));
    assert_eq!(found.read_at_ms, read_ms);
    assert_eq!(
        found.may_act(now, Initiator::Automatic, GRACE),
        MayAct::LookUpAgain
    );
    assert_eq!(
        found.may_act(now, Initiator::User, GRACE),
        MayAct::LookUpAgain
    );
    // The next lookup reads the switch again.
    let again = wallet.begin_identity_lookup(&bob, false).await.unwrap();
    assert!(again.switch.is_some());
    assert_eq!(again.identity.homeserver, HomeserverCopy::Read);
}

#[tokio::test]
async fn test_identity_lookup_split_failed_switch_needs_the_user() {
    let p = Pair::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::new(MemoryStore::new()),
        )
        .await;
    let _shop = p
        .join_on(&p.bob, "shop", protocol, Arc::new(MemoryStore::new()))
        .await;
    let bob = p.bob.identity().public();
    let lookup = wallet.begin_identity_lookup(&bob, true).await.unwrap();
    p.router.remove(BOB_ORIGIN);
    let answer = lookup.switch.unwrap().await;
    assert!(!answer.read());
    let found = wallet.finish_identity_lookup(answer).await.unwrap();
    let now = p.clock.now_ms();
    assert_eq!(found.switch_copy, SwitchCopy::Unavailable);
    assert_eq!(
        found.may_act(now, Initiator::User, GRACE),
        MayAct::IfUserConfirms
    );
    assert_eq!(found.may_act(now, Initiator::Automatic, GRACE), MayAct::No);
    // The failed lookup counts until the copy is 10 minutes old.
    let held = wallet.identity_of(&bob, false).await.unwrap();
    assert_eq!(held.switch_copy, SwitchCopy::Unavailable);
    assert_eq!(held.homeserver, HomeserverCopy::Held);
}

#[test]
fn test_may_act_follows_the_rule_of_the_switch_copy() {
    let doc = World::new().signer.switch().identity_doc();
    let doc = doc.unwrap_or_else(|| World::new().next_doc(|_| {}));
    let at = |switch_copy| PeerIdentity {
        doc: doc.clone(),
        read_at_ms: START,
        homeserver: HomeserverCopy::Read,
        homeserver_read_ms: Some(START),
        switch_copy,
        switch_lookup_ms: START,
        switch_read_ms: None,
    };
    let (user, auto) = (Initiator::User, Initiator::Automatic);
    let read = at(SwitchCopy::Read);
    assert_eq!(read.may_act(START + 1, auto, GRACE), MayAct::Now);
    assert_eq!(
        read.may_act(START + DOC_CACHE_MS, auto, GRACE),
        MayAct::LookUpAgain
    );
    let pending = at(SwitchCopy::Pending);
    assert_eq!(
        pending.may_act(START + 1, auto, GRACE),
        MayAct::WaitUntil(START + GRACE)
    );
    assert_eq!(
        pending.may_act(START + GRACE, user, GRACE),
        MayAct::IfUserConfirms
    );
    assert_eq!(
        pending.may_act(START + GRACE, auto, GRACE),
        MayAct::WaitForLookup
    );
    // A pending lookup on a copy past 10 minutes: every action waits for it.
    let mut stale = at(SwitchCopy::Pending);
    stale.read_at_ms = START - DOC_CACHE_MS;
    assert_eq!(
        stale.may_act(START + GRACE, user, GRACE),
        MayAct::WaitForLookup
    );
    let failed = at(SwitchCopy::Unavailable);
    assert_eq!(failed.may_act(START, user, 0), MayAct::IfUserConfirms);
    assert_eq!(failed.may_act(START, auto, 0), MayAct::No);
}

// -------------------------------------------------------------------------------------
// The protocol's other callbacks read its local state (`LocalView`)

#[tokio::test]
async fn test_sends_to_with_reads_the_local_state() {
    let p = Pair::new();
    let protocol = ReadsProtocol::new(Mode::Settle);
    let mut wallet = p
        .join_on(
            &p.alice,
            "wallet",
            protocol.clone(),
            Arc::new(MemoryStore::new()),
        )
        .await;
    let mut shop = p
        .join_on(&p.bob, "shop", protocol, Arc::new(MemoryStore::new()))
        .await;
    shop.invite(&p.alice.identity().public()).await.unwrap();
    let alice = p.alice.identity().public();
    // The rule refuses every recipient while `mute` is held: nothing reaches bob.
    wallet.protocol_commit(&[local("mute")]).await.unwrap();
    let (_, muted) = wallet.send(Pair::note(&p.bob, "one")).await.unwrap();
    assert!(!matches!(muted, Delivery::Accepted { .. }), "{muted:?}");
    assert_eq!(p.bob.switch().entries_from(&alice), 0);
    wallet
        .protocol_commit(&[LocalWrite::Delete {
            key: b"mute".to_vec(),
        }])
        .await
        .unwrap();
    let (_, sent) = wallet.send(Pair::note(&p.bob, "two")).await.unwrap();
    assert!(matches!(sent, Delivery::Accepted { .. }), "{sent:?}");
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
}
