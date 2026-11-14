//! The cursor the service holds, beside the app's own position (Switch spec 8.3, 12.4).

use std::sync::Arc;

use super::*;
use crate::app::{AppEvent, HeldCursor, UserConfirmed};

/// `app` restored from `backup` into a store of its own, its newest identity.json
/// confirmed.
async fn restored(w: &World, backup: &crate::app::AppBackup) -> App {
    let mut app = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        backup,
    )
    .await
    .unwrap();
    app.end_reconcile(UserConfirmed::new()).await.ok();
    // The newest identity.json, confirmed after the restore, as the host does before any
    // attempt: only then does a page settle the verdict.
    app.refresh_identity().await.unwrap();
    app
}

fn ahead_told(events: &[AppEvent]) -> Option<(u64, u64)> {
    events.iter().find_map(|event| match event {
        AppEvent::HeldCursorAhead { held, position } => Some((*held, *position)),
        _ => None,
    })
}

#[tokio::test]
async fn test_held_cursor_read_at_the_apps_position_is_clean() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    w.note(me, "one");
    let report = app.receive(None).await.unwrap();
    assert_eq!(report.held_cursor, Some(HeldCursor::Clean));
    assert_eq!(ahead_told(&report.events), None);
}

#[tokio::test]
async fn test_held_cursor_ahead_is_told_once_for_each_higher_report() {
    // Switch spec 8.3: ahead at a read other than a restore's, for an app whose devices
    // don't share its cursor: the app's state went back, or a copy of it reads first.
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    let position = app.cursor().seq;
    w.switch.set_held_cursor(&me, position + 5);
    let report = app.receive(None).await.unwrap();
    assert_eq!(
        report.held_cursor,
        Some(HeldCursor::Ahead {
            held: position + 5,
            position
        })
    );
    assert_eq!(ahead_told(&report.events), Some((position + 5, position)));
    // The same report again isn't told again; the read still says so.
    let report = app.receive(None).await.unwrap();
    assert!(matches!(report.held_cursor, Some(HeldCursor::Ahead { .. })));
    assert_eq!(ahead_told(&report.events), None);
    w.switch.set_held_cursor(&me, position + 9);
    let report = app.receive(None).await.unwrap();
    assert_eq!(ahead_told(&report.events), Some((position + 9, position)));
    assert!(app.alarm().is_none());
}

#[tokio::test]
async fn test_held_cursor_ahead_of_an_app_sharing_its_cursor_is_unknown() {
    // Switch spec 8.3: another device's move is ordinary for an app whose devices share
    // its cursor.
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    app.set_multi_device(true).await.unwrap();
    app.receive(None).await.unwrap();
    let position = app.cursor().seq;
    w.switch.set_held_cursor(&me, position + 5);
    let report = app.receive(None).await.unwrap();
    assert_eq!(report.held_cursor, Some(HeldCursor::Unknown));
    assert_eq!(ahead_told(&report.events), None);
}

#[tokio::test]
async fn test_held_cursor_restore_with_nothing_passed_since_is_clean() {
    // Switch spec 12.4 "The held cursor": the backup's position, the first page from the
    // current service read before any move, the restored key current.
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    w.note(me, "one");
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    w.note(me, "two");
    let mut restored = restored(&w, &backup).await;
    assert_eq!(restored.restore_held_cursor(), None);
    restored.receive(None).await.unwrap();
    assert_eq!(restored.restore_held_cursor(), Some(HeldCursor::Clean));
}

#[tokio::test]
async fn test_held_cursor_restore_after_progress_since_the_backup_is_ahead() {
    // The device read on past the backup and moved its cursor: entries after the backup's
    // position were passed, and the restore says so.
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    let position = backup.cursor.seq;
    w.note(me, "two");
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let held = w.switch.app(&me).cursor;
    assert!(held > position);
    let mut restored = restored(&w, &backup).await;
    let report = restored.receive(None).await.unwrap();
    assert_eq!(
        restored.restore_held_cursor(),
        Some(HeldCursor::Ahead { held, position })
    );
    // At a restore the host knows: no alert. The gap goes to the protocol as a missed item.
    assert_eq!(ahead_told(&report.events), None);
    let missed = w.protocol.missed.lock().unwrap().clone();
    assert!(
        missed.iter().any(|m| m.seq == held && m.entries == 0),
        "{missed:?}"
    );
}

#[tokio::test]
async fn test_held_cursor_restore_moving_its_cursor_before_a_page_is_unknown() {
    // Switch spec 12.4 condition 1: the page is read before any cursor move of the app.
    let w = World::new();
    let mut app = w.join("wallet").await;
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    let mut restored = restored(&w, &backup).await;
    restored.flush_cursor().await.unwrap();
    restored.receive(None).await.unwrap();
    assert_eq!(restored.restore_held_cursor(), Some(HeldCursor::Unknown));
}

#[tokio::test]
async fn test_held_cursor_restore_after_a_rotation_since_the_backup_is_unknown() {
    // Switch spec 12.4 condition 6: entries after the position may be sealed to a key the
    // restored app lacks.
    let w = World::new();
    let mut app = w.join("wallet").await;
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    assert!(app.rotate().await.unwrap());
    let mut restored = restored(&w, &backup).await;
    restored.receive(None).await.ok();
    restored.receive(None).await.ok();
    assert_eq!(restored.restore_held_cursor(), Some(HeldCursor::Unknown));
}

#[tokio::test]
async fn test_held_cursor_later_ahead_ends_a_clean_restore() {
    // Switch spec 12.4 condition 7: an app whose devices don't share its cursor goes on
    // comparing, and a later report ahead ends the clean verdict.
    let w = World::new();
    let mut app = w.join("wallet").await;
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    let mut restored = restored(&w, &backup).await;
    let me = restored.app_id();
    restored.receive(None).await.unwrap();
    assert_eq!(restored.restore_held_cursor(), Some(HeldCursor::Clean));
    let position = restored.cursor().seq;
    w.switch.set_held_cursor(&me, position + 3);
    restored.receive(None).await.unwrap();
    assert!(matches!(
        restored.restore_held_cursor(),
        Some(HeldCursor::Ahead { .. })
    ));
}

// -------------------------------------------------------------------------------------
// Further cases: a restore against the conditions of Switch spec 12.4 "The held cursor".

use super::moves::{self, Router};

/// `backup` restored into a store of its own, reached through `router`.
async fn restored_on(w: &World, router: &Router, backup: &crate::app::AppBackup) -> App {
    App::restore(
        router.env(w, Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        backup,
    )
    .await
    .unwrap()
}

/// A provider loss of generation 1, declared at a new service at `NEXT`; the old service
/// still answers.
fn declare_loss(w: &World, router: &Router) -> Arc<ScriptedSwitch> {
    let n_key = moves::next_key();
    let next =
        ScriptedSwitch::recovering(&w.alice, n_key.to_bytes(), Arc::clone(&w.clock), 2, 1).unwrap();
    router.add(moves::NEXT, &next);
    moves::publish_at(
        w,
        &next,
        Inbox::new(moves::NEXT, n_key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    next
}

#[tokio::test]
async fn test_held_cursor_restore_from_a_sequence_a_loss_ended_is_unknown() {
    // Switch spec 12.4 condition 2: no provider loss at or after the backup's generation.
    // The loss is declared after the backup; the old service still answers, and the
    // restored app holds the backup's identity.json, which names it.
    let w = World::new();
    let router = Router::of(&w);
    let mut app = moves::join(&w, &router).await;
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    declare_loss(&w, &router);
    let mut restored = restored_on(&w, &router, &backup).await;
    restored.receive(None).await.unwrap();
    let first = restored.restore_held_cursor();
    // The host then reads the newest identity.json, as before any attempt, and the app
    // follows the loss.
    restored.refresh_identity().await.unwrap();
    for _ in 0..3 {
        let _ = restored.receive(None).await;
    }
    assert_eq!(restored.own_identity().body().recovery_from, Some(1));
    let after = restored.restore_held_cursor();
    // Once the loss is followed, the verdict no longer reads clean.
    assert_ne!(
        after,
        Some(HeldCursor::Clean),
        "first {first:?}, after {after:?}"
    );
}

#[tokio::test]
async fn test_held_cursor_restore_before_following_the_newest_identity_isnt_clean() {
    // Switch spec 12.4 condition 1: the first page from the current service, once the app
    // has followed the newest identity.json. The restored app reads the old service, which
    // still answers, before it has read the Homeserver's newer document.
    let w = World::new();
    let router = Router::of(&w);
    let mut app = moves::join(&w, &router).await;
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    declare_loss(&w, &router);
    let mut restored = restored_on(&w, &router, &backup).await;
    restored.receive(None).await.unwrap();
    assert_ne!(restored.restore_held_cursor(), Some(HeldCursor::Clean));
}

#[tokio::test]
async fn test_held_cursor_clean_restore_followed_by_a_loss_reads_unknown() {
    // A restore found clean, then a provider loss of the backup's generation: the
    // backup's position no longer compares, and the loss's reconcile mode follows.
    let w = World::new();
    let router = Router::of(&w);
    let mut app = moves::join(&w, &router).await;
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    let mut restored = restored_on(&w, &router, &backup).await;
    restored.refresh_identity().await.unwrap();
    restored.receive(None).await.unwrap();
    assert_eq!(restored.restore_held_cursor(), Some(HeldCursor::Clean));
    restored.end_reconcile(UserConfirmed::new()).await.unwrap();
    declare_loss(&w, &router);
    w.switch.lock().erased = true;
    restored.refresh_identity().await.unwrap();
    for _ in 0..3 {
        let _ = restored.receive(None).await;
    }
    assert!(restored.reconcile_mode());
    assert_ne!(restored.restore_held_cursor(), Some(HeldCursor::Clean));
}

/// A cooperative move to `NEXT`, followed by `app`, which then reads a note there and
/// moves its cursor past `position`.
async fn move_and_read_on(w: &World, router: &Router, app: &mut App, position: u64) {
    let me = app.app_id();
    let n_key = moves::next_key();
    let freeze = moves::freeze_for(w, &n_key, 2);
    w.switch.freeze(&freeze).unwrap();
    let next = w.switch.import_into(n_key.to_bytes());
    router.add(moves::NEXT, &next);
    let _ = app.receive(None).await;
    moves::publish_at(
        w,
        &next,
        Inbox::new(moves::NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let _ = app.receive(None).await;
    assert_eq!(app.cursor().generation, 2);
    moves::note_at(w, &next, me, "at the next service");
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    assert!(next.app(&me).cursor > position);
}

#[tokio::test]
async fn test_held_cursor_restore_judged_at_a_frozen_service_waits_for_the_next() {
    // Switch spec 12.4 condition 1: the first page from the current service, once the app
    // has followed the newest identity.json. A frozen service isn't it.
    let w = World::new();
    let router = Router::of(&w);
    let mut app = moves::join(&w, &router).await;
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    move_and_read_on(&w, &router, &mut app, backup.cursor.seq).await;
    let mut restored = restored_on(&w, &router, &backup).await;
    let _ = restored.receive(None).await;
    // After the first read, which met the frozen service's page.
    assert_ne!(
        restored.restore_held_cursor(),
        Some(HeldCursor::Clean),
        "cursor {:?}",
        restored.cursor()
    );
}

#[tokio::test]
async fn test_held_cursor_restore_of_a_shared_cursor_judged_at_a_frozen_service_isnt_clean() {
    // As above, for an app whose devices share its cursor: ahead at the current service
    // is unknown, never clean.
    let w = World::new();
    let router = Router::of(&w);
    let mut app = moves::join(&w, &router).await;
    app.set_multi_device(true).await.unwrap();
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    move_and_read_on(&w, &router, &mut app, backup.cursor.seq).await;
    let mut restored = restored_on(&w, &router, &backup).await;
    restored.refresh_identity().await.unwrap();
    for _ in 0..4 {
        let _ = restored.receive(None).await;
    }
    assert_eq!(restored.cursor().generation, 2);
    assert_eq!(restored.restore_held_cursor(), Some(HeldCursor::Unknown));
}

#[tokio::test]
async fn test_held_cursor_restore_writing_before_a_page_is_unknown() {
    // Switch spec 12.4 condition 1: a batch of operations carries the restored, deferred
    // cursor move, so a write before the first page leaves the verdict unknown.
    let w = World::new();
    let mut app = w.join("wallet").await;
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    let mut restored = restored(&w, &backup).await;
    let target = crate::app::RecordTarget::new(super::shared_flows::items(), b"key");
    restored
        .put_record(&target, &super::shared_flows::value(&["a"]), vec![])
        .await
        .unwrap();
    restored.receive(None).await.unwrap();
    assert_eq!(restored.restore_held_cursor(), Some(HeldCursor::Unknown));
}

#[tokio::test]
async fn test_held_cursor_restore_verdict_survives_a_load() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.refresh_identity().await.unwrap();
    restored.receive(None).await.unwrap();
    assert_eq!(restored.restore_held_cursor(), Some(HeldCursor::Clean));
    drop(restored);
    let mut loaded = App::load(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        me,
    )
    .await
    .unwrap();
    assert_eq!(loaded.restore_held_cursor(), Some(HeldCursor::Clean));
    // A later report ahead, after the load, still ends it.
    let position = loaded.cursor().seq;
    w.switch.set_held_cursor(&me, position + 2);
    let report = loaded.receive(None).await.unwrap();
    assert!(matches!(
        loaded.restore_held_cursor(),
        Some(HeldCursor::Ahead { .. })
    ));
    assert_eq!(ahead_told(&report.events), Some((position + 2, position)));
}

#[tokio::test]
async fn test_held_cursor_restore_settles_only_once_its_identity_is_confirmed() {
    // Lead's rule for Switch spec 12.4 condition 1: until the app confirmed its newest
    // identity.json after the restore, no page settles the verdict, which reads None.
    let w = World::new();
    let mut app = w.join("wallet").await;
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let backup = app.backup().await.unwrap();
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.receive(None).await.unwrap();
    assert_eq!(restored.restore_held_cursor(), None);
    restored.refresh_identity().await.unwrap();
    restored.receive(None).await.unwrap();
    assert_eq!(restored.restore_held_cursor(), Some(HeldCursor::Clean));
}

#[tokio::test]
async fn test_held_cursor_ahead_hands_the_gap_to_the_protocol_once() {
    // Switch spec 8.3 "Ahead": the gap is handled as a `missed` item, from the cursor's
    // time less the clock tolerance, with no end; once for each higher report, across a
    // load, and a listing is owed.
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    w.note(me, "one");
    app.receive(None).await.unwrap();
    let position = app.cursor().seq;
    let gaps = || -> Vec<MissedEntries> {
        w.protocol
            .missed
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.entries == 0)
            .cloned()
            .collect()
    };
    w.switch.set_held_cursor(&me, position + 4);
    app.receive(None).await.unwrap();
    let handed = gaps();
    assert_eq!(handed.len(), 1, "{handed:?}");
    assert_eq!(handed[0].seq, position + 4);
    assert_eq!(handed[0].accepted_until_ms, u64::MAX);
    assert_eq!(
        handed[0].accepted_from_ms,
        app.state
            .cursor
            .time_ms
            .saturating_sub(pubky_switch_core::records::CLOCK_TOLERANCE_MS)
    );
    let mut app = w.load(me).await;
    app.receive(None).await.unwrap();
    assert_eq!(gaps().len(), 1);
    w.switch.set_held_cursor(&me, position + 6);
    app.receive(None).await.unwrap();
    assert_eq!(gaps().len(), 2);
}

#[tokio::test]
async fn test_held_cursor_gap_is_handed_once_across_a_key_change() {
    // A key change in place continues the sequence: the same gap ahead, shown again by the
    // service at the next generation, isn't handed again.
    use super::moves::{self, Router};
    let w = World::new();
    let router = Router::of(&w);
    let mut app = moves::join(&w, &router).await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    let position = app.cursor().seq;
    let gaps = || -> usize {
        w.protocol
            .missed
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.entries == 0)
            .count()
    };
    w.switch.set_held_cursor(&me, position + 4);
    app.receive(None).await.unwrap();
    assert_eq!(gaps(), 1);
    let pending = ed25519_dalek::SigningKey::from_bytes(&seed("service/alice/pending"));
    let changed = w.switch.import_into(pending.to_bytes());
    router.add(crate::testing::SWITCH_ORIGIN, &changed);
    moves::publish_at(
        &w,
        &changed,
        Inbox::new(
            crate::testing::SWITCH_ORIGIN,
            pending.verifying_key().to_bytes(),
        ),
        2,
        None,
    );
    for _ in 0..2 {
        app.receive(None).await.unwrap();
    }
    assert_eq!(app.cursor().generation, 2);
    assert_eq!(changed.app(&me).cursor, position + 4);
    assert_eq!(gaps(), 1);
}

#[tokio::test]
async fn test_held_cursor_gap_whose_call_fails_holds_the_page() {
    // Switch spec 8.3: the gap ahead goes to the protocol before anything after it. Its
    // call failing, it is owed at the compared position, and nothing of the page is handed
    // until the protocol takes it.
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    let position = app.cursor().seq;
    // Another instance passed the first note; the second comes after the gap.
    let (passed, _) = w.note(me, "passed elsewhere");
    let (note, _) = w.note(me, "after the gap");
    assert!(passed > position);
    w.switch.set_held_cursor(&me, passed);
    *w.protocol.failing.lock().unwrap() = 1;
    let held = app.receive(None).await.unwrap();
    assert!(held.stopped);
    let received = || -> Vec<u64> {
        w.protocol
            .received
            .lock()
            .unwrap()
            .iter()
            .map(|(seq, _, _)| *seq)
            .collect()
    };
    assert!(!received().contains(&note));
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 1);
    for _ in 0..2 {
        app.receive(None).await.unwrap();
    }
    let gaps = w
        .protocol
        .missed
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m.entries == 0)
        .count();
    assert_eq!(gaps, 1);
    assert!(received().contains(&note));
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 0);
}
