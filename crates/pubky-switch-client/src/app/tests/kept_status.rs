//! What became of a kept batch, read after a crash at every commit of the write, signing
//! again, dropping and applying it: one batch ID throughout, its end committed with the
//! change it records, and answered by the batch ID, its attempt and its queued message for
//! the retention after (Switch spec 6.4, 12.5 "Kept batches"; Switch wire 6.4 step 5).

use pubky_switch_core::ops::{Condition, RecordVersion};
use pubky_switch_core::records::Inbox;
use pubky_switch_core::scopes::Permission;

use super::moves::{
    ATTEMPT, CLAIM, NEXT, Router, allow_ops_for, change_key, contact_batch, freeze_for, has,
    join_on, next_key, publish_at,
};
use super::*;
use crate::app::{
    AppError, AppEvent, ClaimAttempt, ClaimOp, Delivery, KeptBatch, KeptBatchDrop, KeptBatchStatus,
    OpBatch, OutgoingMessage, SENT_RETENTION_MS, SignedMessage,
};
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::Fault;

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

/// A batch signed again under a new wire ID, applied by the service whose answer was lost,
/// then a move away from that service: the old chain holds its wire ID, so it is settled
/// applied, under the ID it was kept under, and never signed or applied again.
#[tokio::test]
async fn test_kept_batch_status_signed_again_and_applied_is_found_in_the_old_chain() {
    let (w, router, id, signed, changed, mut app) = signed_again_then_crash(false).await;
    // The batch's first send at generation 2 is cut off.
    changed.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 1,
    });
    let _ = app.receive(None).await;
    changed.lock().faults.clear();
    assert_eq!(allow_ops_for(&changed.applied(), carol()), 0);
    // Sent again, applied there, and its answer lost.
    changed.fail_next(Fault::LoseAnswer { path: "ops".into() });
    let _ = app.receive(None).await;
    assert_eq!(allow_ops_for(&changed.applied(), carol()), 1);
    let Some(KeptBatchStatus::Kept {
        wire_batch_id,
        sent_at_ms: Some(_),
    }) = app.kept_batch(id).await.unwrap()
    else {
        panic!("kept, sent");
    };
    assert_ne!(wire_batch_id, id);
    // The account moves on from generation 2 to the next service.
    let n_key = next_key();
    changed.freeze(&freeze_for(&w, &n_key, 3)).unwrap();
    let next = changed.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    let _ = app.receive(None).await;
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        3,
        None,
    );
    let mut events = Vec::new();
    for _ in 0..3 {
        if let Ok(report) = app.receive(None).await {
            events.extend(report.events);
        }
    }
    assert_eq!(app.cursor().generation, 3);
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
    app.submit_batch(contact_batch([7; 32])).await.unwrap();
    assert_eq!(allow_ops_for(&next.applied(), carol()), 0);
}
