//! The cursor the service holds, beside the app's own position (Switch spec 8.3, 12.4).

use std::sync::Arc;

use super::*;
use crate::app::{AppEvent, HeldCursor, UserConfirmed};

/// `app` restored from `backup` into a store of its own.
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
    w.switch.lock().apps.get_mut(&me).unwrap().cursor = position + 5;
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
    w.switch.lock().apps.get_mut(&me).unwrap().cursor = position + 9;
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
    w.switch.lock().apps.get_mut(&me).unwrap().cursor = position + 5;
    let report = app.receive(None).await.unwrap();
    assert_eq!(report.held_cursor, Some(HeldCursor::Unknown));
    assert_eq!(ahead_told(&report.events), None);
}

#[tokio::test]
async fn test_held_cursor_not_reported_is_unknown() {
    // Switch wire 7.4.4: a page without `cursor`, from a service of an earlier version,
    // is no report.
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.switch.lock().omit_cursor = true;
    let report = app.receive(None).await.unwrap();
    assert_eq!(report.held_cursor, Some(HeldCursor::Unknown));
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
    assert_eq!(ahead_told(&report.events), Some((held, position)));
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
    w.switch.lock().apps.get_mut(&me).unwrap().cursor = position + 3;
    restored.receive(None).await.unwrap();
    assert!(matches!(
        restored.restore_held_cursor(),
        Some(HeldCursor::Ahead { .. })
    ));
}
