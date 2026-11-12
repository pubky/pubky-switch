//! What became of a kept batch, read after a crash at every commit of the write, signing
//! again, dropping and applying it: one batch ID throughout, its end committed with the
//! change it records, and answered by the batch ID, its attempt and its queued message for
//! the retention after (Switch spec 6.4, 12.5 "Kept batches"; Switch wire 6.4 step 5).

use ed25519_dalek::SigningKey;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{Condition, RecordVersion};
use pubky_switch_core::records::{Freeze, FreezeBody, Inbox};
use pubky_switch_core::scopes::Permission;

use super::moves::{
    ATTEMPT, CLAIM, NEXT, Router, allow_ops_for, change_key, contact_batch, has, join_on, next_key,
    publish_at,
};
use super::*;
use crate::app::{
    AppError, AppEvent, ClaimAttempt, ClaimOp, Delivery, KeptBatch, KeptBatchDrop, KeptBatchStatus,
    OpBatch, OutgoingMessage, SENT_RETENTION_MS, SignedMessage,
};
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::Fault;

/// A third service's origin.
const THIRD: &str = "https://third.example";

fn carol() -> [u8; 32] {
    IdentityKey::from_secret(seed("carol/identity")).public()
}

fn attempt() -> ClaimAttempt {
    ClaimAttempt {
        claim_key: CLAIM,
        attempt_id: ATTEMPT,
    }
}

/// A batch with a contact, an attempt and a note to bob it queues, and the note.
fn batch_of(w: &World, app: &App) -> (OpBatch, SignedMessage) {
    let body = json!({ "text": "kept" }).as_object().unwrap().clone();
    let signed = app
        .sign_message(OutgoingMessage::new(w.bob.public(), "sample.note", body))
        .unwrap();
    let batch = contact_batch(carol())
        .op(ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None).kind())
        .queue(signed.clone());
    (batch, signed)
}

async fn join_app(w: &World, router: &Router) -> App {
    join_on(
        w,
        router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await
}

async fn load_on(
    w: &World,
    router: &Router,
    store: Arc<dyn StateStore>,
    app_id: [u8; 16],
) -> Result<App, AppError> {
    App::load(
        router.env(w, store),
        w.protocol.clone(),
        World::config(),
        app_id,
    )
    .await
}

/// A store over `w`'s that stops after its `n`th commit; `None` counts commits only.
fn stopping(w: &World, n: Option<u64>) -> Arc<FaultStore> {
    Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        n.map_or(StoreFault::None, StoreFault::StopAfter),
    ))
}

/// What the reads tell of the batch carrying [`attempt`] and the message `msg_id`, checked
/// against what the store keeps: the batch kept answers `Kept` under its ID, by its ID, its
/// attempt and its message; one no longer kept answers its end the same three ways.
async fn reads_agree(app: &App, msg_id: &str) -> Option<KeptBatch> {
    let kept = app.kept_batches().await.unwrap();
    let found = app.kept_attempt(attempt()).await.unwrap();
    let delivery = app.delivery(msg_id).await.unwrap();
    let Some(found) = found else {
        assert!(kept.is_empty(), "a kept batch its attempt doesn't find");
        assert_eq!(delivery, None, "a message no batch is known to carry");
        return None;
    };
    assert_eq!(
        app.kept_batch(found.batch_id).await.unwrap(),
        Some(found.status.clone())
    );
    match &found.status {
        KeptBatchStatus::Kept { .. } => {
            assert_eq!(kept.len(), 1);
            assert_eq!(kept[0].0, found.batch_id);
            assert_eq!(
                delivery,
                Some(Delivery::Kept {
                    batch_id: found.batch_id
                })
            );
        }
        KeptBatchStatus::Applied { .. } => {
            assert!(kept.is_empty());
            assert!(
                matches!(
                    delivery,
                    Some(Delivery::Queued { .. } | Delivery::Accepted { .. })
                ),
                "{delivery:?}"
            );
        }
        KeptBatchStatus::Dropped { dropped_at_ms, .. } => {
            assert!(kept.is_empty());
            assert!(
                matches!(
                    delivery,
                    Some(Delivery::Failed { failed_at_ms, .. }) if failed_at_ms == *dropped_at_ms
                ),
                "{delivery:?}"
            );
        }
    }
    Some(found)
}

/// A write stopped after each of its commits in turn: reloaded, the reads find the batch by
/// its attempt and its message, kept or applied, under the one ID, though the caller never
/// learned it; the next read settles it, applied once, under that ID.
#[tokio::test]
async fn test_kept_batch_status_answers_after_a_crash_at_each_commit_of_a_write() {
    let mut seen = (false, false);
    let mut commits = None;
    let mut n = 1;
    loop {
        let w = World::new();
        let router = Router::of(&w);
        let me = join_app(&w, &router).await.app_id();
        let store = stopping(&w, commits.map(|_| n));
        let mut app = load_on(&w, &router, Arc::clone(&store) as Arc<dyn StateStore>, me)
            .await
            .unwrap();
        let (batch, signed) = batch_of(&w, &app);
        let result = app.submit_batch(batch).await;
        drop(app);
        let Some(total) = commits else {
            result.unwrap();
            commits = Some(store.commits());
            continue;
        };
        let mut app = load_on(&w, &router, Arc::clone(&w.store) as Arc<dyn StateStore>, me)
            .await
            .unwrap();
        // The first commit keeps the batch: from it on, the reads find it.
        let before = reads_agree(&app, signed.msg_id()).await.unwrap();
        match &before.status {
            KeptBatchStatus::Kept { .. } => seen.0 = true,
            KeptBatchStatus::Applied { .. } => seen.1 = true,
            other => panic!("commit {n}: {other:?}"),
        }
        app.receive(None).await.unwrap();
        let after = reads_agree(&app, signed.msg_id()).await.unwrap();
        assert_eq!(after.batch_id, before.batch_id, "commit {n}");
        assert!(
            matches!(after.status, KeptBatchStatus::Applied { .. }),
            "commit {n}: {after:?}"
        );
        assert_eq!(allow_ops_for(&w.switch.applied(), carol()), 1);
        if n >= total {
            break;
        }
        n += 1;
    }
    assert_eq!(seen, (true, true), "both kept and applied were met");
}

/// A batch kept and never sent, `id` the ID it was kept under, then the account's key
/// changed in place, so the next read signs it again for generation 2. With `refused`, its
/// attempt carries a condition no state meets, so the switch refuses it for good.
async fn kept_before_a_key_change(
    w: &World,
    router: &Router,
    refused: bool,
) -> ([u8; 16], SignedMessage, Arc<ScriptedSwitch>, [u8; 16]) {
    let mut app = join_app(w, router).await;
    w.switch.fail_next(Fault::Unreachable {
        path: "feed".into(),
        after: 0,
    });
    w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let (mut batch, signed) = batch_of(w, &app);
    if refused {
        batch = batch.when(Condition::RecordVersion {
            key: [8; 32],
            version: RecordVersion::new(1, 99),
        });
    }
    let id = app
        .submit_batch(batch)
        .await
        .unwrap_err()
        .kept_batch()
        .unwrap();
    w.switch.lock().faults.clear();
    assert_eq!(app.kept_batches().await.unwrap()[0].1.kept_ms, None);
    let changed = change_key(w, router);
    (id, signed, changed, app.app_id())
}

/// Signing a kept batch again, stopped after each commit of the reads that follow the key
/// change and send it: the batch stays kept under the ID it was first kept under, its new
/// bytes under another, and ends applied under the first, whatever event a crash lost.
#[tokio::test]
async fn test_kept_batch_status_keeps_its_id_after_a_crash_at_each_commit_of_signing_again() {
    let mut signed_again = false;
    let mut commits = None;
    let mut n = 1;
    loop {
        let w = World::new();
        let router = Router::of(&w);
        let (id, signed, changed, me) = kept_before_a_key_change(&w, &router, false).await;
        let store = stopping(&w, commits.map(|_| n));
        let mut app = load_on(&w, &router, Arc::clone(&store) as Arc<dyn StateStore>, me)
            .await
            .unwrap();
        let first = app.receive(None).await;
        let second = app.receive(None).await;
        drop(app);
        let Some(total) = commits else {
            first.unwrap();
            second.unwrap();
            commits = Some(store.commits());
            continue;
        };
        let mut app = load_on(&w, &router, Arc::clone(&w.store) as Arc<dyn StateStore>, me)
            .await
            .unwrap();
        let found = reads_agree(&app, signed.msg_id()).await.unwrap();
        assert_eq!(found.batch_id, id, "commit {n}");
        if let KeptBatchStatus::Kept { wire_batch_id, .. } = found.status
            && wire_batch_id != id
        {
            signed_again = true;
        }
        app.receive(None).await.unwrap();
        app.receive(None).await.unwrap();
        let found = reads_agree(&app, signed.msg_id()).await.unwrap();
        assert_eq!(found.batch_id, id, "commit {n}");
        assert!(
            matches!(found.status, KeptBatchStatus::Applied { .. }),
            "commit {n}: {found:?}"
        );
        assert_eq!(allow_ops_for(&changed.applied(), carol()), 1);
        assert!(changed.applied().iter().all(|op| op.body().batch.id != id));
        if n >= total {
            break;
        }
        n += 1;
    }
    assert!(
        signed_again,
        "a crash met the batch signed again, still kept"
    );
}

/// [`kept_before_a_key_change`], then the read that follows the key change stopped right
/// after the commit that signs the batch again, before it is sent: the event telling of it
/// is lost. Returns the world as the reload finds it.
async fn signed_again_then_crash(
    refused: bool,
) -> (
    World,
    Router,
    [u8; 16],
    SignedMessage,
    Arc<ScriptedSwitch>,
    App,
) {
    for n in 1.. {
        let w = World::new();
        let router = Router::of(&w);
        let (id, signed, changed, me) = kept_before_a_key_change(&w, &router, refused).await;
        let store = stopping(&w, Some(n));
        let mut app = load_on(&w, &router, Arc::clone(&store) as Arc<dyn StateStore>, me)
            .await
            .unwrap();
        let _ = app.receive(None).await;
        drop(app);
        let app = load_on(&w, &router, Arc::clone(&w.store) as Arc<dyn StateStore>, me)
            .await
            .unwrap();
        match app.kept_batch(id).await.unwrap() {
            Some(KeptBatchStatus::Kept { wire_batch_id, .. }) if wire_batch_id != id => {
                return (w, router, id, signed, changed, app);
            }
            Some(KeptBatchStatus::Kept { .. }) => {}
            other => panic!("commit {n}: signed again and sent in one commit: {other:?}"),
        }
    }
    unreachable!()
}

/// A batch signed again, the event lost to a crash, then refused for good: the refusal
/// names the ID it was first kept under, and so do its end and its message.
#[tokio::test]
async fn test_kept_batch_status_refused_after_signing_again_names_the_first_id() {
    let (w, _router, id, signed, changed, mut app) = signed_again_then_crash(true).await;
    for _ in 0..2 {
        let _ = app.receive(None).await;
    }
    let events = app.unacknowledged_events().await.unwrap();
    assert!(
        has(&events, |e| matches!(
            e,
            AppEvent::BatchRefused { batch_id, code, .. } if *batch_id == id && code == "conflict"
        )),
        "{events:?}"
    );
    let found = reads_agree(&app, signed.msg_id()).await.unwrap();
    assert_eq!(
        found,
        KeptBatch {
            batch_id: id,
            status: KeptBatchStatus::Dropped {
                dropped_at_ms: w.clock.now_ms(),
                reason: KeptBatchDrop::Refused {
                    code: "conflict".into()
                },
            },
        }
    );
    assert_eq!(allow_ops_for(&changed.applied(), carol()), 0);
}

/// A batch sent once, its answer lost to the network, unapplied; then past the window in
/// which a resend tells.
async fn sent_past_the_window(w: &World, router: &Router) -> ([u8; 16], SignedMessage, [u8; 16]) {
    let mut app = join_app(w, router).await;
    w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let (batch, signed) = batch_of(w, &app);
    let id = app
        .submit_batch(batch)
        .await
        .unwrap_err()
        .kept_batch()
        .unwrap();
    assert!(app.kept_batches().await.unwrap()[0].1.kept_ms.is_some());
    w.clock
        .advance_ms(crate::app::provider::KEPT_BATCH_ANSWER_MS);
    (id, signed, app.app_id())
}

/// A drop past the window, stopped after each commit of the read that drops it: the batch
/// is kept, or dropped with its end, never neither; the end is uncertain, at the drop's
/// time, also for its attempt and its message.
#[tokio::test]
async fn test_kept_batch_status_dropped_after_a_crash_at_each_commit_of_a_drop() {
    let mut seen = (false, false);
    let mut commits = None;
    let mut n = 1;
    loop {
        let w = World::new();
        let router = Router::of(&w);
        let (id, signed, me) = sent_past_the_window(&w, &router).await;
        let store = stopping(&w, commits.map(|_| n));
        let mut app = load_on(&w, &router, Arc::clone(&store) as Arc<dyn StateStore>, me)
            .await
            .unwrap();
        let result = app.receive(None).await;
        drop(app);
        let Some(total) = commits else {
            result.unwrap();
            commits = Some(store.commits());
            continue;
        };
        let mut app = load_on(&w, &router, Arc::clone(&w.store) as Arc<dyn StateStore>, me)
            .await
            .unwrap();
        let found = reads_agree(&app, signed.msg_id()).await.unwrap();
        assert_eq!(found.batch_id, id);
        match found.status {
            KeptBatchStatus::Kept { .. } => seen.0 = true,
            _ => seen.1 = true,
        }
        app.receive(None).await.unwrap();
        let found = reads_agree(&app, signed.msg_id()).await.unwrap();
        assert_eq!(
            found.status,
            KeptBatchStatus::Dropped {
                dropped_at_ms: w.clock.now_ms(),
                reason: KeptBatchDrop::Uncertain,
            },
            "commit {n}"
        );
        assert!(has(
            &app.unacknowledged_events().await.unwrap(),
            |e| matches!(
                e,
                AppEvent::KeptBatchDropped { batch_id, .. } if *batch_id == id
            )
        ));
        assert_eq!(allow_ops_for(&w.switch.applied(), carol()), 0);
        if n >= total {
            break;
        }
        n += 1;
    }
    assert_eq!(seen, (true, true), "both kept and dropped were met");
}

/// The keys the ends of kept batches and their indexes take.
async fn end_keys(app: &App) -> usize {
    app.reader().scan_raw("kb").await.unwrap().len()
}

/// An end is answered until [`SENT_RETENTION_MS`] from its time, by every read, and at that
/// time no read answers it and the next flush forgets it with its indexes.
#[tokio::test]
async fn test_kept_batch_status_end_is_forgotten_at_its_retention() {
    let w = World::new();
    let router = Router::of(&w);
    let (id, signed, me) = sent_past_the_window(&w, &router).await;
    let mut app = load_on(&w, &router, Arc::clone(&w.store) as Arc<dyn StateStore>, me)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    let ended = w.clock.now_ms();
    let dropped = reads_agree(&app, signed.msg_id()).await.unwrap();
    assert!(
        matches!(dropped.status, KeptBatchStatus::Dropped { dropped_at_ms, .. } if dropped_at_ms == ended)
    );
    let keys = end_keys(&app).await;
    assert!(keys >= 4, "{keys}");
    w.clock.advance_ms(SENT_RETENTION_MS - 1);
    app.flush_outbox().await.unwrap();
    assert_eq!(reads_agree(&app, signed.msg_id()).await, Some(dropped));
    assert_eq!(end_keys(&app).await, keys);
    w.clock.advance_ms(1);
    assert_eq!(app.kept_batch(id).await.unwrap(), None);
    assert_eq!(reads_agree(&app, signed.msg_id()).await, None);
    app.flush_outbox().await.unwrap();
    assert_eq!(end_keys(&app).await, 0);
}

/// The signer's freeze naming `next` at `origin`, for `next_generation`.
fn freeze_to(w: &World, origin: &str, next: &SigningKey, next_generation: u64) -> Freeze {
    Freeze::sign(
        &w.alice,
        FreezeBody {
            identity: w.alice.public(),
            inbox: Inbox::new(origin, next.verifying_key().to_bytes()),
            next_generation,
            issued_at: w.clock.now_ms(),
            nonce: [next_generation as u8; 16],
        },
    )
    .unwrap()
}

/// The service an account moves to: its origin, its key and the generation it serves.
struct Hop<'a> {
    origin: &'a str,
    key: &'a SigningKey,
    generation: u64,
}

/// Follow a move of `from` to `to`: frozen, imported, published, `faults` set at the next
/// service, and `reads` reads after. Returns the next service and the reads' events.
async fn moved(
    w: &World,
    router: &Router,
    app: &mut App,
    from: &ScriptedSwitch,
    to: Hop<'_>,
    faults: Vec<Fault>,
    reads: usize,
) -> (Arc<ScriptedSwitch>, Vec<AppEvent>) {
    let Hop {
        origin,
        key,
        generation,
    } = to;
    from.freeze(&freeze_to(w, origin, key, generation)).unwrap();
    let next = from.import_into(key.to_bytes());
    router.add(origin, &next);
    let _ = app.receive(None).await;
    publish_at(
        w,
        &next,
        Inbox::new(origin, key.verifying_key().to_bytes()),
        generation,
        None,
    );
    for fault in faults {
        next.fail_next(fault);
    }
    let mut events = Vec::new();
    for _ in 0..reads {
        if let Ok(report) = app.receive(None).await {
            events.extend(report.events);
        }
    }
    if reads > 0 {
        assert_eq!(app.cursor().generation, generation);
    }
    (next, events)
}

/// How many times `switch` applied [`attempt`].
fn attempts_at(switch: &ScriptedSwitch) -> usize {
    switch
        .applied()
        .iter()
        .filter(|op| {
            matches!(&op.body().kind, OpKind::Claim(claim)
                if claim.check().is_ok_and(|entry| entry.attempt_id == ATTEMPT))
        })
        .count()
}

/// A batch signed again under a new wire ID at a move, applied at the next service with its
/// answer lost, then a move on from there before it is sent again: the old chain holds its
/// wire ID, so it is settled applied from the chain, under the ID it was kept under, and
/// never signed or applied again. The app follows without `lists.read`, so a follow sends no
/// kept batch of its own: a read sends it before its feed, and goes on when that fails.
#[tokio::test]
async fn test_kept_batch_status_signed_again_and_applied_is_found_in_the_old_chain() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[
            Permission::ClaimsRead,
            Permission::ClaimsWrite,
            Permission::ConversationAdd,
        ],
    )
    .await;
    w.switch.fail_next(Fault::Unreachable {
        path: "feed".into(),
        after: 0,
    });
    w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let body = json!({ "text": "kept" }).as_object().unwrap().clone();
    let signed = app
        .sign_message(OutgoingMessage::new(w.bob.public(), "sample.note", body))
        .unwrap();
    let batch = OpBatch::new()
        .op(ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None).kind())
        .queue(signed.clone());
    let id = app
        .submit_batch(batch)
        .await
        .unwrap_err()
        .kept_batch()
        .unwrap();
    w.switch.lock().faults.clear();
    // A move seen frozen signs it again for generation 2, never sent at 1; the read's own
    // send of it there loses its answer, applied.
    let (next, _) = moved(
        &w,
        &router,
        &mut app,
        &w.switch,
        Hop {
            origin: NEXT,
            key: &next_key(),
            generation: 2,
        },
        Vec::new(),
        0,
    )
    .await;
    // The read that follows it sends the registration, then the batch, whose answer is
    // lost; the read goes on to the feed, which shows the batch applied.
    next.fail_next(Fault::LoseAnswerAfter {
        path: "ops".into(),
        after: 1,
    });
    let report = app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::KeptBatchesWaiting { kept: 1, .. }
    )));
    let status = app.kept_batch(id).await.unwrap();
    let Some(KeptBatchStatus::Kept {
        wire_batch_id,
        sent_at_ms: Some(_),
    }) = status
    else {
        panic!("kept and sent: {status:?}");
    };
    assert_ne!(wire_batch_id, id);
    assert_eq!(attempts_at(&next), 1);
    // A move on from generation 2 before any read sends it again.
    let third = SigningKey::from_bytes(&seed("service/alice/third"));
    let (last, events) = moved(
        &w,
        &router,
        &mut app,
        &next,
        Hop {
            origin: THIRD,
            key: &third,
            generation: 3,
        },
        Vec::new(),
        3,
    )
    .await;
    assert!(
        has(
            &events,
            |e| matches!(e, AppEvent::KeptBatchApplied { batch_id } if *batch_id == id)
        ),
        "{events:?}"
    );
    let found = reads_agree(&app, signed.msg_id()).await.unwrap();
    assert!(
        matches!(found.status, KeptBatchStatus::Applied { .. }),
        "{found:?}"
    );
    assert_eq!(attempts_at(&last), 0);
}

/// A restore in place replaces the namespace with the backup: the end of a batch dropped
/// before it and its indexes go with it, and no read answers them after.
#[tokio::test]
async fn test_kept_batch_status_end_is_not_carried_by_a_restore() {
    let w = World::new();
    let router = Router::of(&w);
    let (id, signed, me) = sent_past_the_window(&w, &router).await;
    let mut app = load_on(&w, &router, Arc::clone(&w.store) as Arc<dyn StateStore>, me)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    assert!(reads_agree(&app, signed.msg_id()).await.is_some());
    let backup = app.backup().await.unwrap();
    drop(app);
    let app = App::restore(
        router.env(&w, Arc::clone(&w.store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(app.kept_batch(id).await.unwrap(), None);
    assert_eq!(reads_agree(&app, signed.msg_id()).await, None);
    assert_eq!(end_keys(&app).await, 0);
}

/// A batch kept by an earlier build, with no index of its message and attempt: the load
/// indexes it, in one commit, so neither reads as unknown while the batch is still to be
/// sent; a load with nothing to index commits nothing.
#[tokio::test]
async fn test_kept_batch_status_unindexed_batch_is_indexed_at_load() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_app(&w, &router).await;
    let me = app.app_id();
    w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let (batch, signed) = batch_of(&w, &app);
    let id = app
        .submit_batch(batch)
        .await
        .unwrap_err()
        .kept_batch()
        .unwrap();
    w.switch.lock().faults.clear();
    // As an earlier build left it: kept, with no index.
    let mut tx = app.tx().unwrap();
    tx.delete_prefix("kbm/").unwrap();
    tx.delete_prefix("kba/").unwrap();
    app.commit(tx).await.unwrap();
    drop(app);
    // A load whose index commit fails writes none of it.
    let failing = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::FailBefore(1),
    ));
    assert!(
        load_on(&w, &router, Arc::clone(&failing) as Arc<dyn StateStore>, me)
            .await
            .is_err()
    );
    let counting = stopping(&w, None);
    let app = load_on(
        &w,
        &router,
        Arc::clone(&counting) as Arc<dyn StateStore>,
        me,
    )
    .await
    .unwrap();
    assert_eq!(counting.commits(), 1, "indexed in one commit");
    let found = app.kept_attempt(attempt()).await.unwrap().unwrap();
    assert_eq!(found.batch_id, id);
    assert!(matches!(found.status, KeptBatchStatus::Kept { .. }));
    assert_eq!(
        app.delivery(signed.msg_id()).await.unwrap(),
        Some(Delivery::Kept { batch_id: id })
    );
    drop(app);
    let again = stopping(&w, None);
    load_on(&w, &router, Arc::clone(&again) as Arc<dyn StateStore>, me)
        .await
        .unwrap();
    assert_eq!(again.commits(), 0, "nothing to index");
}

/// A batch sent once, its answer lost to the network, unapplied, still inside its window.
async fn sent_unanswered(w: &World, router: &Router) -> ([u8; 16], SignedMessage, [u8; 16]) {
    let mut app = join_app(w, router).await;
    w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let (batch, signed) = batch_of(w, &app);
    let id = app
        .submit_batch(batch)
        .await
        .unwrap_err()
        .kept_batch()
        .unwrap();
    w.switch.lock().faults.clear();
    assert!(app.kept_batches().await.unwrap()[0].1.kept_ms.is_some());
    (id, signed, app.app_id())
}

/// A kept batch refused for good when sent again, stopped after each commit of the read:
/// its end and its `BatchRefused` duty event come in one commit, so no crash leaves the
/// one without the other.
#[tokio::test]
async fn test_kept_batch_status_refusal_and_its_duty_after_a_crash_at_each_commit() {
    let mut refused = false;
    let mut commits = None;
    let mut n = 1;
    loop {
        let w = World::new();
        let router = Router::of(&w);
        let (id, signed, me) = sent_unanswered(&w, &router).await;
        w.switch.fail_next(Fault::Error {
            path: "ops".into(),
            code: ErrorCode::Conflict,
            current: json!(null),
        });
        let store = stopping(&w, commits.map(|_| n));
        let mut app = load_on(&w, &router, Arc::clone(&store) as Arc<dyn StateStore>, me)
            .await
            .unwrap();
        let result = app.receive(None).await;
        drop(app);
        let Some(total) = commits else {
            result.unwrap();
            commits = Some(store.commits());
            continue;
        };
        let mut app = load_on(&w, &router, Arc::clone(&w.store) as Arc<dyn StateStore>, me)
            .await
            .unwrap();
        let found = reads_agree(&app, signed.msg_id()).await.unwrap();
        let duty = has(
            &app.unacknowledged_events().await.unwrap(),
            |e| matches!(e, AppEvent::BatchRefused { batch_id, .. } if *batch_id == id),
        );
        match found.status {
            KeptBatchStatus::Kept { .. } => assert!(!duty, "commit {n}"),
            KeptBatchStatus::Dropped {
                reason: KeptBatchDrop::Refused { .. },
                ..
            } => {
                assert!(duty, "commit {n}: ended without its duty event");
                refused = true;
            }
            other => panic!("commit {n}: {other:?}"),
        }
        if n >= total {
            break;
        }
        n += 1;
    }
    assert!(refused, "a crash met the batch refused");
}

/// A batch applied at generation 1 with its answer lost, then sent again unchanged after a
/// key change in place, stopped after each commit: its original proofs settle it, and its
/// end comes in the commit that settles it.
#[tokio::test]
async fn test_kept_batch_status_old_generation_resend_applied_after_a_crash_at_each_commit() {
    let mut applied = false;
    let mut commits = None;
    let mut n = 1;
    loop {
        let w = World::new();
        let router = Router::of(&w);
        let mut app = join_app(&w, &router).await;
        let me = app.app_id();
        w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
        let (batch, signed) = batch_of(&w, &app);
        let id = app
            .submit_batch(batch)
            .await
            .unwrap_err()
            .kept_batch()
            .unwrap();
        drop(app);
        change_key(&w, &router);
        let store = stopping(&w, commits.map(|_| n));
        let mut app = load_on(&w, &router, Arc::clone(&store) as Arc<dyn StateStore>, me)
            .await
            .unwrap();
        let result = app.receive(None).await;
        drop(app);
        let Some(total) = commits else {
            result.unwrap();
            commits = Some(store.commits());
            continue;
        };
        let mut app = load_on(&w, &router, Arc::clone(&w.store) as Arc<dyn StateStore>, me)
            .await
            .unwrap();
        let found = reads_agree(&app, signed.msg_id()).await.unwrap();
        assert_eq!(found.batch_id, id);
        if matches!(found.status, KeptBatchStatus::Applied { .. }) {
            applied = true;
        }
        app.receive(None).await.unwrap();
        let found = reads_agree(&app, signed.msg_id()).await.unwrap();
        assert!(
            matches!(found.status, KeptBatchStatus::Applied { .. }),
            "commit {n}: {found:?}"
        );
        assert_eq!(allow_ops_for(&w.switch.applied(), carol()), 1);
        if n >= total {
            break;
        }
        n += 1;
    }
    assert!(applied, "a crash met the batch settled");
}

/// The prune of an end leaves an index entry a later batch took over: the later batch's
/// attempt still finds it.
#[tokio::test]
async fn test_kept_batch_status_prune_keeps_an_index_a_later_batch_took_over() {
    let w = World::new();
    let router = Router::of(&w);
    let (first, _, me) = sent_past_the_window(&w, &router).await;
    let mut app = load_on(&w, &router, Arc::clone(&w.store) as Arc<dyn StateStore>, me)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    assert!(matches!(
        app.kept_batch(first).await.unwrap(),
        Some(KeptBatchStatus::Dropped { .. })
    ));
    // A later batch carries the same attempt, and takes over its index.
    w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let (batch, _) = batch_of(&w, &app);
    let later = app
        .submit_batch(batch)
        .await
        .unwrap_err()
        .kept_batch()
        .unwrap();
    w.switch.lock().faults.clear();
    assert_eq!(
        app.kept_attempt(attempt()).await.unwrap().unwrap().batch_id,
        later
    );
    // The first batch's end goes at its retention; the index stays the later batch's.
    w.clock.advance_ms(SENT_RETENTION_MS);
    app.flush_outbox().await.unwrap();
    assert_eq!(app.kept_batch(first).await.unwrap(), None);
    assert_eq!(
        app.kept_attempt(attempt())
            .await
            .unwrap()
            .map(|k| k.batch_id),
        Some(later)
    );
}

/// A leave deletes the ends of kept batches and their indexes with the keys: no flush of a
/// left app would prune them after.
#[tokio::test]
async fn test_kept_batch_status_ends_go_with_a_leave() {
    let w = World::new();
    let router = Router::of(&w);
    let (_, _, me) = sent_past_the_window(&w, &router).await;
    let mut app = load_on(&w, &router, Arc::clone(&w.store) as Arc<dyn StateStore>, me)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    assert!(end_keys(&app).await > 0);
    app.leave(crate::app::LeaveMode::Immediate(
        crate::app::UserConfirmed::new(),
    ))
    .await
    .unwrap();
    assert_eq!(end_keys(&app).await, 0);
}
