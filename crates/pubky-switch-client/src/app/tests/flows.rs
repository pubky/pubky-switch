//! App flows against the scripted switch.

use std::sync::Arc;

use pubky_switch_core::envelope::Recipient;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::ReceiveKey;
use pubky_switch_core::message::Sender;
use pubky_switch_core::ops::{KeyBundlePut, OpKind};
use pubky_switch_core::records::{
    CLOCK_TOLERANCE_MS, ListedApp, ReceiveKeyBody, ReceiveKeyRecord, RemovedApp, RenewedCert,
    seal_bundle_parts,
};
use serde_json::{Map, json};

use super::*;
use crate::app::{
    Alarm, AppBackup, AppError, AppEvent, EventId, IdentityRefresh, LeaveMode, LeaveReport,
    ParkReason, REVALIDATION_MS, Refusal, UserConfirmed,
};
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::Fault;

const HOUR: u64 = 3_600_000;

fn has(events: &[AppEvent], pred: impl Fn(&AppEvent) -> bool) -> bool {
    events.iter().any(pred)
}

fn received(events: &[AppEvent], seq: u64) -> bool {
    has(
        events,
        |e| matches!(e, AppEvent::MessageReceived { seq: s, .. } if *s == seq),
    )
}

#[tokio::test]
async fn test_app_join_registers_and_receives_a_note() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    assert!(w.switch.app(&me).receive_key.is_some());
    assert_eq!(app.receive_key_numbers(), vec![0]);
    let (seq, message) = w.note(me, "hello");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(w.effects(), 1);
    assert!(app.cursor().seq >= seq);
    let note = app
        .protocol_get(format!("notes/{}", message.msg_id).as_bytes())
        .await
        .unwrap();
    assert_eq!(note, Some(b"hello".to_vec()));
    // The effect's batch carried the cursor.
    assert!(w.switch.app(&me).cursor >= seq);
    // The app reloads from the store alone, where it left off.
    let loaded = w.load(me).await;
    assert_eq!(loaded.cursor(), app.cursor());
    assert_eq!(loaded.receive_key_numbers(), vec![0]);
}

#[tokio::test]
async fn test_app_join_refuses_an_approval_for_other_keys() {
    let w = World::new();
    let mut request = w.approve(&app_keys("wallet"), &["scope-a"]);
    request.keys = app_keys("phone");
    let error = App::join(w.env(), w.protocol.clone(), World::config(), request)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Approval(_))),
        "{error:?}"
    );
    // Nothing was kept.
    assert!(w.store.is_empty(&crate::store::client_namespace(
        &app_keys("phone").app_id_bytes()
    )));
}

#[tokio::test]
async fn test_app_load_refuses_an_unknown_app() {
    let w = World::new();
    let error = App::load(w.env(), w.protocol.clone(), World::config(), [9; 16])
        .await
        .unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::NotJoined));
}

/// One run of the scenario: join, two notes, a read, a rotation after a day and the reads
/// that delete the retired key. Returns at the first error, as a process that died.
async fn scenario(
    w: &World,
    store: Arc<dyn StateStore>,
    sent: &mut Vec<u64>,
    approval: &mut Option<JoinRequest>,
) -> Result<(), AppError> {
    let keys = app_keys("wallet");
    let env = w.env_on(Arc::clone(&store));
    let mut app = match App::load(
        env.clone(),
        w.protocol.clone(),
        World::config(),
        keys.app_id_bytes(),
    )
    .await
    {
        Ok(app) => app,
        Err(AppError::Refused(Refusal::NotJoined)) => {
            let request = approval
                .get_or_insert_with(|| w.approve(&keys, &["scope-a"]))
                .clone();
            App::join(env, w.protocol.clone(), World::config(), request).await?
        }
        Err(error) => return Err(error),
    };
    // The registration may still be owed: the first read finishes it.
    app.receive(None).await?;
    while sent.len() < 2 {
        let text = format!("note {}", sent.len());
        sent.push(w.note(app.app_id(), &text).0);
    }
    app.receive(None).await?;
    if app.receive_key_numbers().last() == Some(&0) {
        w.clock.advance_ms(25 * HOUR);
        app.receive(None).await?;
    }
    app.receive(None).await?;
    app.receive(None).await?;
    Ok(())
}

/// The commits of one uninterrupted run of the scenario.
async fn scenario_commits() -> u64 {
    let w = World::new();
    let counting = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()) as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    scenario(
        &w,
        Arc::clone(&counting) as Arc<dyn StateStore>,
        &mut Vec::new(),
        &mut None,
    )
    .await
    .unwrap();
    counting.commits()
}

#[tokio::test]
async fn test_app_crash_at_each_commit_point_resumes_without_loss_or_repeat() {
    let commits = scenario_commits().await;
    assert!(commits > 5, "the scenario commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let w = World::new();
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
            let first = scenario(
                &w,
                Arc::clone(&fault) as Arc<dyn StateStore>,
                &mut sent,
                &mut approval,
            )
            .await;
            assert!(fault.stopped(), "commit {n} of {commits} is reached");
            assert!(first.is_err());
            // Restart on what the store holds.
            scenario(
                &w,
                Arc::clone(&inner) as Arc<dyn StateStore>,
                &mut sent,
                &mut approval,
            )
            .await
            .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            let app = App::load(
                w.env_on(Arc::clone(&inner) as Arc<dyn StateStore>),
                w.protocol.clone(),
                World::config(),
                app_keys("wallet").app_id_bytes(),
            )
            .await
            .unwrap();
            // Nothing lost: both notes processed, the cursor past them.
            assert_eq!(sent.len(), 2);
            assert!(app.cursor().seq >= sent[1], "commit {n}");
            // Nothing done twice: each note's effect applied once.
            assert_eq!(w.effects(), 2, "commit {n} ({stop_after})");
            // The rotation happened and the retired key went once its successor was passed.
            assert_eq!(
                app.receive_key_numbers(),
                vec![1],
                "commit {n} ({stop_after})"
            );
            assert_eq!(w.switch.app(&app.app_id()).receive_n, Some(1));
        }
    }
}

#[tokio::test]
async fn test_app_rotation_registers_then_deletes_after_the_cursor_passes() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    // Nothing opened yet: no rotation, however long the wait.
    w.clock.advance_ms(30 * HOUR);
    app.receive(None).await.unwrap();
    assert_eq!(app.receive_key_numbers(), vec![0]);
    // An opened envelope, then a day: the read rotates.
    w.note(me, "one");
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(e, AppEvent::Rotated { n: 1 })),
        "{:?}",
        report.events
    );
    // Registered; the old key stays until the cursor passes the registration.
    assert_eq!(app.receive_key_numbers(), vec![0, 1]);
    let registration = w.switch.tip_seq();
    assert!(app.cursor().seq < registration);
    // A message sealed to the old key before the registration still opens: the order is
    // read, register, read past the registration, delete.
    let report = app.receive(None).await.unwrap();
    assert!(app.cursor().seq >= registration);
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::KeysDeleted { count: 1 }
    )));
    assert_eq!(app.receive_key_numbers(), vec![1]);
    // A note sealed to the new key opens.
    let (seq, _) = w.note(me, "two");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq));
}

#[tokio::test]
async fn test_app_rotation_waits_for_its_interval() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.note(app.app_id(), "one");
    w.clock.advance_ms(HOUR);
    app.receive(None).await.unwrap();
    assert_eq!(app.receive_key_numbers(), vec![0]);
}

#[tokio::test]
async fn test_app_unexpected_registration_stops_and_leaves() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    // Someone holding the signing key registers a key of their own.
    let thief = ReceiveKey::from_secret(1, [42; 32]);
    let record = ReceiveKeyRecord::sign(
        &app_keys("wallet"),
        app.cert(),
        ReceiveKeyBody::new(app.cert(), &thief),
    )
    .unwrap();
    let seq = w
        .switch
        .app_op(
            &app_keys("wallet"),
            OpKind::ReceiveKeyPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    let at = w.clock.now_ms();
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(error, AppError::Alarm(Alarm::Compromise { n: 1, .. })),
        "{error:?}"
    );
    assert_eq!(app.compromise_distrust_from(), Some(at));
    // The app left at once: the copy holding the same key is refused from now on.
    assert!(w.switch.app(&me).departed);
    assert!(app.cursor().seq < seq);
    // It stays stopped, also after a reload.
    assert_eq!(
        app.receive(None).await.unwrap_err(),
        AppError::Refused(Refusal::Stopped)
    );
    let mut reloaded = w.load(me).await;
    assert!(matches!(
        reloaded.alarm(),
        Some(Alarm::Compromise { n: 1, .. })
    ));
    assert!(reloaded.receive(None).await.is_err());
}

#[tokio::test]
async fn test_app_conflict_naming_a_foreign_key_is_a_compromise() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let joined = w.clock.now_ms();
    w.clock.advance_ms(HOUR);
    let thief = ReceiveKey::from_secret(1, [43; 32]);
    let record = ReceiveKeyRecord::sign(
        &app_keys("wallet"),
        app.cert(),
        ReceiveKeyBody::new(app.cert(), &thief),
    )
    .unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::ReceiveKeyPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    let registered = w.clock.now_ms();
    // The app rotates before reading the thief's registration: `409 conflict` names it.
    // Without its chain item, the app distrusts from its own registration, the latest
    // service time it holds, which lies before the thief's (Switch spec 3.6).
    let error = app.rotate().await.unwrap_err();
    assert!(
        matches!(error, AppError::Alarm(Alarm::Compromise { n: 1, .. })),
        "{error:?}"
    );
    let distrust_from = app.compromise_distrust_from().unwrap();
    assert!(
        (joined..=registered).contains(&distrust_from),
        "{distrust_from}"
    );
    assert!(w.switch.app(&app.app_id()).departed);
}

#[tokio::test]
async fn test_app_two_devices_rotating_at_once_one_discards_its_key() {
    let w = World::new();
    let mut a = w.join("wallet").await;
    let me = a.app_id();
    a.set_multi_device(true).await.unwrap();
    // A second device of the app, from the same state, in a store of its own.
    let backup = a.backup().unwrap();
    let store_b = Arc::new(MemoryStore::new());
    let mut b = App::restore(
        w.env_on(Arc::clone(&store_b) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    b.end_reconcile(UserConfirmed::new()).await.ok();
    // Device A rotates; B doesn't know A's key yet: it waits for device sync.
    assert!(a.rotate().await.unwrap());
    let error_free = b.rotate().await.unwrap();
    assert!(!error_free, "the second registration loses");
    assert_eq!(b.alarm(), None);
    // Device sync brings A's key and kids: B reads on.
    b.take_device_keys(a.device_keys()).await.unwrap();
    assert!(b.receive_key_numbers().contains(&1));
    let (seq, _) = w.note(me, "to both");
    let report = b.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
}

#[tokio::test]
async fn test_app_device_sync_with_a_bad_key_changes_nothing() {
    let w = World::new();
    let mut a = w.join("wallet").await;
    let backup = a.backup().unwrap();
    a.set_multi_device(true).await.unwrap();
    assert!(a.rotate().await.unwrap());
    w.clock.advance_ms(1000);
    assert!(a.rotate().await.unwrap());
    // A second device of the app, from before the rotations.
    let store_b = Arc::new(MemoryStore::new());
    let mut b = App::restore(
        w.env_on(Arc::clone(&store_b) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    let before = b.backup().unwrap().to_bytes().unwrap();
    let shared_before = b.device_keys();
    // The set's last key carries a record another app signed.
    let mut keys = a.device_keys();
    assert_eq!(keys.receive_keys.len(), 3);
    let lone = w.join("phone").await;
    let foreign = lone.device_keys();
    if let (Some(last), Some(bad)) = (keys.receive_keys.last_mut(), foreign.receive_keys.first()) {
        last.record = bad.record.clone();
    }
    let error = b.take_device_keys(keys).await.unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // Nothing of the set was taken, in memory or in a backup.
    assert_eq!(b.receive_key_numbers(), vec![0]);
    assert_eq!(b.device_keys(), shared_before);
    assert_eq!(b.backup().unwrap().to_bytes().unwrap(), before);
    assert!(!b.state.device.multi_device);
}

#[tokio::test]
async fn test_app_device_sync_without_the_key_is_a_compromise() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    app.set_multi_device(true).await.unwrap();
    let foreign = ReceiveKey::from_secret(1, [44; 32]);
    let record = ReceiveKeyRecord::sign(
        &app_keys("wallet"),
        app.cert(),
        ReceiveKeyBody::new(app.cert(), &foreign),
    )
    .unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::ReceiveKeyPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    // A newer key than every one held: the read stops and waits for device sync.
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::AwaitingDeviceSync { n: 1 }
    )));
    // The sync shows no device made it.
    let other = World::new();
    let mut lone = other.join("wallet").await;
    lone.set_multi_device(true).await.unwrap();
    let error = app.take_device_keys(lone.device_keys()).await.unwrap_err();
    assert!(matches!(
        error,
        AppError::Alarm(Alarm::Compromise { n: 1, .. })
    ));
}

#[tokio::test]
async fn test_app_equivocation_stops_the_app() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let doc = w.next_doc(|_| {});
    app.receive(None).await.unwrap();
    assert_eq!(app.own_identity().version(), doc.version());
    // Another body at the same version.
    let mut body = doc.body().clone();
    body.data_epoch += 1;
    let other = IdentityDoc::sign(&w.alice, body).unwrap();
    w.switch.deliver_identity(&other).unwrap();
    let error = app.receive(None).await.unwrap_err();
    assert_eq!(
        error,
        AppError::Alarm(Alarm::Equivocation {
            version: doc.version()
        })
    );
    assert_eq!(
        app.receive(None).await.unwrap_err(),
        AppError::Refused(Refusal::Stopped)
    );
    assert!(app.may_attempt(false).is_err());
}

#[tokio::test]
async fn test_app_newer_identity_is_taken_and_older_ignored() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let v_before = app.own_identity().version();
    w.next_doc(|_| {});
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::IdentityUpdated { .. }
    )));
    assert_eq!(app.own_identity().version(), v_before + 1);
    assert!(app.may_attempt(true).is_ok());
}

#[tokio::test]
async fn test_app_rollback_is_detected() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    w.note(me, "one");
    let before = w.switch.tip_seq();
    w.next_doc(|_| {});
    app.receive(None).await.unwrap();
    // The service loses its last item and serves on.
    w.switch.roll_back_to(before);
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(error, AppError::Alarm(Alarm::Rollback { .. })),
        "{error:?}"
    );
    assert!(app.may_attempt(false).is_err());
}

#[tokio::test]
async fn test_app_fork_is_detected() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let before = w.switch.tip_seq();
    w.next_doc(|_| {});
    app.receive(None).await.unwrap();
    // The service replaces its last item with another one at the same place.
    w.switch.roll_back_to(before);
    let mut body = w.signer.body();
    body.version += 1;
    let other = IdentityDoc::sign(&w.alice, body).unwrap();
    w.switch.deliver_identity(&other).unwrap();
    let error = app.receive(None).await.unwrap_err();
    assert!(matches!(error, AppError::Alarm(_)), "{error:?}");
}

#[tokio::test]
async fn test_app_duplicate_message_is_applied_once() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let (_, message) = w.note(me, "once");
    app.receive(None).await.unwrap();
    // The same signed plaintext again, as a re-send.
    let plaintext = message.sign(&w.bob_keys).unwrap();
    let again = w
        .switch
        .send_plaintext(w.bob.public(), &w.bob_cert, &plaintext, &[me])
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Duplicate { seq, conflicting: false } if *seq == again
    )));
    assert_eq!(w.effects(), 1);
    // Another message under the same `msg_id`: a conflict.
    let mut other = message.clone();
    other.body.insert("text".into(), json!("changed"));
    let plaintext = other.sign(&w.bob_keys).unwrap();
    let third = w
        .switch
        .send_plaintext(w.bob.public(), &w.bob_cert, &plaintext, &[me])
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Duplicate { seq, conflicting: true } if *seq == third
    )));
    assert_eq!(w.effects(), 1);
    assert!(app.cursor().seq >= third);
}

#[tokio::test]
async fn test_app_body_that_fails_check_10_is_dropped_and_passed() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let (seq, _) = w
        .switch
        .send(
            &w.bob,
            &w.bob_keys,
            &w.bob_cert,
            "sample.note",
            json!({ "other": 1 }),
            &[me],
        )
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::MessageDropped { check: 10, seq: s, .. } if *s == seq
    )));
    assert!(app.cursor().seq >= seq);
    assert_eq!(w.effects(), 0);
}

#[tokio::test]
async fn test_app_message_failing_a_scope_check_is_dropped() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let (seq, _) = w
        .switch
        .send(
            &w.bob,
            &w.bob_keys,
            &w.bob_cert,
            "sample.unknown",
            json!({ "text": "x" }),
            &[app.app_id()],
        )
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::MessageDropped { check: 8, seq: s, .. } if *s == seq
    )));
}

#[tokio::test]
async fn test_app_unopenable_entry_asks_a_resend_from_the_cursor_time_on() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    w.note(me, "first");
    app.receive(None).await.unwrap();
    // Sealed to a key the app doesn't hold.
    let stranger = ReceiveKey::from_secret(9, [45; 32]);
    let sealed = |w: &World| {
        let message = pubky_switch_core::message::Message::new(
            "sample.note",
            Sender::of_app(w.bob.public(), &w.bob_keys),
            w.alice.public(),
            w.clock.now_ms(),
            vec![],
            Map::new(),
        )
        .unwrap();
        message
            .sign(&w.bob_keys)
            .unwrap()
            .seal(&w.alice.public(), &[Recipient::new(stranger.public)], false)
            .unwrap()
    };
    let seq = w
        .switch
        .send_envelope(w.bob.public(), &w.bob_cert, sealed(&w), &[me]);
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Unopenable { seq: s, resend_asked: true } if *s == seq
    )));
    assert_eq!(w.protocol.resends.lock().unwrap().len(), 1);
    assert!(app.cursor().seq >= seq);
    // One accepted before the cursor's time, less the tolerance: passed, nothing asked.
    let now = w.clock.now_ms();
    w.clock.set_ms(now - 2 * CLOCK_TOLERANCE_MS);
    let old = w
        .switch
        .send_envelope(w.bob.public(), &w.bob_cert, sealed(&w), &[me]);
    w.clock.set_ms(now);
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Unopenable { seq: s, resend_asked: false } if *s == old
    )));
    assert_eq!(w.protocol.resends.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_app_unreadable_entry_asks_only_after_a_verified_departure() {
    let w = World::new();
    let mut wallet = w.join("wallet").await;
    let mut phone = w.join("phone").await;
    wallet.receive(None).await.unwrap();
    // No departure: the service's word alone isn't enough.
    let seq = w.switch.push_unreadable(w.bob.public(), w.clock.now_ms());
    let report = wallet.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Unreadable { seq: s, resend_asked: false } if *s == seq
    )));
    // The phone leaves; an entry accepted before its departure is asked again.
    let accepted = w.clock.now_ms();
    w.clock.advance_ms(1000);
    phone
        .leave(LeaveMode::Immediate(UserConfirmed::new()))
        .await
        .unwrap();
    let seq = w.switch.push_unreadable(w.bob.public(), accepted);
    let report = wallet.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::Unreadable { seq: s, resend_asked: true } if *s == seq
        )),
        "{:?}",
        report.events
    );
    assert_eq!(w.protocol.resends.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_app_missed_entries_go_to_the_protocol_from_the_cursor_time() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.note(app.app_id(), "first");
    app.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    let seq = w.switch.push_missed(3, now - 10 * HOUR, now);
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Missed { entries: 3, .. }
    )));
    let missed = w.protocol.missed.lock().unwrap().clone();
    assert_eq!(missed.len(), 1);
    assert_eq!(missed[0].seq, seq);
    // Never before the cursor's time, less the tolerance.
    assert_eq!(missed[0].accepted_from_ms, now - CLOCK_TOLERANCE_MS);
}

#[tokio::test]
async fn test_app_missed_call_the_protocol_fails_is_made_again() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    w.note(me, "first");
    app.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    let seq = w.switch.push_missed(3, now - 10 * HOUR, now);
    // The protocol can't read its state: the item is passed, its call kept.
    *w.protocol.failing.lock().unwrap() = 1;
    app.receive(None).await.unwrap();
    assert!(app.cursor().seq >= seq);
    assert!(w.protocol.missed.lock().unwrap().is_empty());
    let mark = format!("missed/{seq}");
    assert_eq!(app.protocol_get(mark.as_bytes()).await.unwrap(), None);
    // Made again by the next read, after a load too, with what the item gave.
    let mut app = w.load(me).await;
    app.receive(None).await.unwrap();
    let missed = w.protocol.missed.lock().unwrap().clone();
    assert_eq!(missed.len(), 1);
    assert_eq!(missed[0].seq, seq);
    assert_eq!(missed[0].entries, 3);
    assert_eq!(missed[0].accepted_from_ms, now - CLOCK_TOLERANCE_MS);
    assert_eq!(
        app.protocol_get(mark.as_bytes()).await.unwrap(),
        Some(b"1".to_vec())
    );
    // Once.
    app.receive(None).await.unwrap();
    assert_eq!(w.protocol.missed.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_app_owed_call_failing_for_good_starves_no_other() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.note(app.app_id(), "first");
    app.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    let stuck = w.switch.push_missed(1, now - HOUR, now);
    w.protocol.failing_missed.lock().unwrap().push(stuck);
    let later = w.switch.push_missed(2, now - HOUR, now);
    // Both calls fail at first: both owed, and counted.
    *w.protocol.failing.lock().unwrap() = 1;
    app.receive(None).await.unwrap();
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 2);
    // The next read makes each on its own: the later one is answered though the first
    // keeps failing.
    app.receive(None).await.unwrap();
    let missed = w.protocol.missed.lock().unwrap().clone();
    assert_eq!(missed.len(), 1, "{missed:?}");
    assert_eq!(missed[0].seq, later);
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 1);
}

#[tokio::test]
async fn test_app_unreadable_entry_whose_call_fails_isnt_reported_asked() {
    let w = World::new();
    let mut wallet = w.join("wallet").await;
    let mut phone = w.join("phone").await;
    wallet.receive(None).await.unwrap();
    let accepted = w.clock.now_ms();
    w.clock.advance_ms(1000);
    phone
        .leave(LeaveMode::Immediate(UserConfirmed::new()))
        .await
        .unwrap();
    let seq = w.switch.push_unreadable(w.bob.public(), accepted);
    *w.protocol.failing.lock().unwrap() = 1;
    let report = wallet.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::Unreadable { seq: s, resend_asked: false } if *s == seq
        )),
        "{:?}",
        report.events
    );
    assert_eq!(wallet.owed_protocol_calls().await.unwrap(), 1);
    wallet.receive(None).await.unwrap();
    assert_eq!(w.protocol.resends.lock().unwrap().len(), 1);
    assert_eq!(wallet.owed_protocol_calls().await.unwrap(), 0);
}

#[tokio::test]
async fn test_app_restore_in_place_over_a_store_that_cant_be_read_fails() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let backup = app.backup().unwrap();
    assert!(!refuse_next(&w, &mut app).await.is_empty());
    drop(app);
    // The store can't be read right now: the restore fails, to be tried again.
    let store = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    store.fail_scan(b"duty/", 0);
    let failed = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await;
    assert!(
        matches!(failed, Err(AppError::Store(crate::StoreError::Unavailable))),
        "{:?}",
        failed.map(|_| ())
    );
    // Tried again, it restores, the duty events kept.
    let mut restored = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert_eq!(restored.app_id(), me);
    assert_eq!(restored.unacknowledged_events().await.unwrap().len(), 2);
}

#[tokio::test]
async fn test_app_restore_in_place_leaves_behind_what_doesnt_read_and_says_so() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let backup = app.backup().unwrap();
    let duties = refuse_next(&w, &mut app).await;
    assert_eq!(duties.len(), 2);
    let now = w.clock.now_ms();
    w.switch.push_missed(1, now - HOUR, now);
    *w.protocol.failing.lock().unwrap() = 1;
    app.receive(None).await.unwrap();
    // One duty event's value and the owed call's don't read.
    let first = duties[0].id().unwrap().counter();
    let owed = app.reader().scan_raw("owed/").await.unwrap();
    assert_eq!(owed.len(), 1);
    let mut batch = crate::store::WriteBatch::new();
    batch
        .put(
            &app.ns,
            crate::app::state::key::duty(first).into_bytes(),
            b"not a value".to_vec(),
        )
        .unwrap();
    batch
        .put(
            &app.ns,
            format!("owed/{}", owed[0].0).into_bytes(),
            b"not a value".to_vec(),
        )
        .unwrap();
    app.env.store.commit(batch).await.unwrap();
    drop(app);
    let mut restored = App::restore(w.env(), w.protocol.clone(), World::config(), &backup)
        .await
        .unwrap();
    let events = restored.take_events();
    // The one that reads is carried with its ID; the protocol is told what was left.
    assert!(events.contains(&duties[1]), "{events:?}");
    assert!(!events.contains(&duties[0]), "{events:?}");
    assert!(
        has(&events, |e| e.is_duty()
            && matches!(
                e,
                AppEvent::RestoreLeftBehind {
                    duty_events: 1,
                    owed_calls: 1,
                    ..
                }
            )),
        "{events:?}"
    );
    assert_eq!(restored.owed_protocol_calls().await.unwrap(), 0);
}

#[tokio::test]
async fn test_app_restore_in_place_over_a_damaged_epoch_starts_a_new_one() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let backup = app.backup().unwrap();
    let duties = refuse_next(&w, &mut app).await;
    let old = last_id(&duties);
    // The store's event epoch doesn't read.
    let mut tx = app.tx().unwrap();
    tx.put(crate::app::state::key::DUTY_EPOCH, &"not an epoch")
        .unwrap();
    app.commit(tx).await.unwrap();
    drop(app);
    let mut restored = App::restore(w.env(), w.protocol.clone(), World::config(), &backup)
        .await
        .unwrap();
    // A new epoch: the kept duty events come again, under IDs of the new store.
    let events = restored.take_events();
    let ids: Vec<EventId> = events.iter().filter_map(AppEvent::id).collect();
    assert_eq!(ids.len(), duties.len(), "{events:?}");
    assert!(ids.iter().all(|id| !id.same_store(&old)), "{ids:?}");
}

#[tokio::test]
async fn test_app_resend_call_the_protocol_fails_is_made_again() {
    let w = World::new();
    let mut wallet = w.join("wallet").await;
    let mut phone = w.join("phone").await;
    wallet.receive(None).await.unwrap();
    let accepted = w.clock.now_ms();
    w.clock.advance_ms(1000);
    phone
        .leave(LeaveMode::Immediate(UserConfirmed::new()))
        .await
        .unwrap();
    let seq = w.switch.push_unreadable(w.bob.public(), accepted);
    // Twice in a row the protocol can't answer: the item is passed, its call kept.
    *w.protocol.failing.lock().unwrap() = 2;
    wallet.receive(None).await.unwrap();
    assert!(wallet.cursor().seq >= seq);
    wallet.receive(None).await.unwrap();
    assert!(w.protocol.resends.lock().unwrap().is_empty());
    let mark = format!("resend/{accepted}");
    assert_eq!(wallet.protocol_get(mark.as_bytes()).await.unwrap(), None);
    // Then it answers: the same request, once.
    wallet.receive(None).await.unwrap();
    wallet.receive(None).await.unwrap();
    let resends = w.protocol.resends.lock().unwrap().clone();
    assert_eq!(resends.len(), 1);
    assert_eq!(resends[0].sender, w.bob.public());
    assert_eq!(resends[0].accepted_from_ms, accepted);
    assert_eq!(resends[0].accepted_until_ms, accepted);
    assert_eq!(resends[0].reason, crate::app::ResendReason::Unreadable);
    assert_eq!(
        wallet.protocol_get(mark.as_bytes()).await.unwrap(),
        Some(b"1".to_vec())
    );
}

#[tokio::test]
async fn test_app_holds_then_parks_an_unverifiable_sender() {
    let w = World::new();
    let mut wallet = w.join("wallet").await;
    let phone = w.join("phone").await;
    let me = wallet.app_id();
    w.homeserver.set_down(true);
    let (held, _) = w.note(me, "held");
    // A message from an own app after it goes on.
    let (later, _) = w
        .switch
        .send(
            &w.alice,
            &app_keys("phone"),
            phone.cert(),
            "sample.notice",
            json!({ "text": "hi" }),
            &[me],
        )
        .unwrap();
    let report = wallet.receive(None).await.unwrap();
    assert!(has(
        &report.events,
        |e| matches!(e, AppEvent::Held { seq } if *seq == held)
    ));
    assert!(received(&report.events, later));
    // The cursor stays before the held entry, so the inbox keeps it.
    assert!(wallet.cursor().seq < held);
    // Read again: the held one is still held, the later one isn't processed twice.
    let report = wallet.receive(None).await.unwrap();
    assert!(!received(&report.events, later));
    // After the bounded wait it is stored locally and passed.
    w.clock.advance_ms(25 * HOUR);
    let report = wallet.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Parked { id: None, seq, reason: ParkReason::Unverifiable } if *seq == held
    )));
    assert!(wallet.cursor().seq >= later);
    assert_eq!(w.effects(), 0, "{:?}", report.events);
    // Once the sender can be checked, it is applied.
    w.homeserver.set_down(false);
    let report = wallet.receive(None).await.unwrap();
    assert!(has(
        &report.events,
        |e| matches!(e, AppEvent::Unparked { seq } if *seq == held)
    ));
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn test_app_quota_parks_the_entry_and_writes_later() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let (seq, _) = w.note(app.app_id(), "big");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::QuotaExceeded,
        current: json!({}),
    });
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Parked { id: None, seq: s, reason: ParkReason::Quota } if *s == seq
    )));
    assert!(app.cursor().seq >= seq, "the feed never stalls");
    assert_eq!(w.effects(), 0);
    app.receive(None).await.unwrap();
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn test_app_conflict_rebuilds_the_effect_once() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let (seq, _) = w.note(app.app_id(), "contended");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!({ "record": null }),
    });
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq));
    let calls = w.protocol.received.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert!(
        !calls[0].2 && calls[1].2,
        "the second call carries the conflict"
    );
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn test_app_lost_answer_resends_the_same_batch() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let (seq, _) = w.note(app.app_id(), "once");
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn test_scripted_switch_refuses_a_cursor_outside_the_sequence() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let newest = w.switch.seq();
    let before = w.switch.app(&me).cursor;
    let cursor = |generation, seq| {
        crate::client::Batch::cursor_only(pubky_switch_core::ops::Position { generation, seq })
    };
    for (generation, seq) in [(77, 10_000), (1, newest + 1), (2, 0)] {
        let error = app.submit(&cursor(generation, seq)).await.unwrap_err();
        assert_eq!(
            error.code(),
            Some(ErrorCode::BadRequest),
            "{generation}:{seq}"
        );
        assert_eq!(w.switch.app(&me).cursor, before);
    }
    app.submit(&cursor(1, newest)).await.unwrap();
    assert_eq!(w.switch.app(&me).cursor, newest);
}

#[tokio::test]
async fn test_scripted_switch_pages_the_feed_by_bytes_never_inside_a_batch() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let notes: Vec<u64> = (0..3).map(|i| w.note(me, &format!("note {i}")).0).collect();
    // A budget below one item: each page holds its first item or batch alone (Switch wire
    // 7.4.4).
    w.switch.lock().max_page_bytes = 1;
    let query = |seq| crate::client::answers::FeedQuery {
        after: Some(pubky_switch_core::ops::Position { generation: 1, seq }),
        limit: Some(100),
        wait: None,
    };
    // A batch comes whole, as the join's record and first receive key do.
    let batch_of = |item: &crate::client::answers::FeedItem| match item {
        crate::client::answers::FeedItem::Chain(chain) => chain
            .stub
            .open()
            .ok()
            .and_then(|env| env.batch)
            .map(|b| b.id),
        _ => None,
    };
    let mut after = 0;
    let mut whole_batch = false;
    loop {
        let page = app.client.feed(query(after)).await.unwrap();
        if page.items.len() > 1 {
            let first = batch_of(&page.items[0]);
            assert!(first.is_some(), "{:?}", page.items);
            assert!(page.items.iter().all(|item| batch_of(item) == first));
            whole_batch = true;
        }
        if !page.more {
            break;
        }
        assert!(!page.items.is_empty(), "a page holds at least one item");
        after = page.next.seq;
    }
    assert!(whole_batch);
    // The app reads them all, a page at a time.
    let report = app.receive(None).await.unwrap();
    for seq in notes {
        assert!(received(&report.events, seq), "{:?}", report.events);
    }
}

#[tokio::test]
async fn test_app_defers_a_cursor_only_move() {
    let w = World::new();
    let mut wallet = w.join("wallet").await;
    let phone = w.join("phone").await;
    let me = wallet.app_id();
    let (seq, _) = w
        .switch
        .send(
            &w.alice,
            &app_keys("phone"),
            phone.cert(),
            "sample.notice",
            json!({ "text": "no effect" }),
            &[me],
        )
        .unwrap();
    wallet.receive(None).await.unwrap();
    assert!(wallet.cursor().seq >= seq);
    assert!(w.switch.app(&me).cursor < seq, "deferred");
    w.clock.advance_ms(3_000);
    wallet.receive(None).await.unwrap();
    assert!(w.switch.app(&me).cursor >= seq);
    // A move before going to the background is sent at once.
    let (seq, _) = w
        .switch
        .send(
            &w.alice,
            &app_keys("phone"),
            phone.cert(),
            "sample.notice",
            json!({ "text": "again" }),
            &[me],
        )
        .unwrap();
    wallet.receive(None).await.unwrap();
    wallet.flush_cursor().await.unwrap();
    assert!(w.switch.app(&me).cursor >= seq);
}

#[tokio::test]
async fn test_app_renewal_is_picked_up_once_listed() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let old = app.cert().clone();
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms() + 1000,
        &["scope-a"],
    );
    w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: me,
            cert: renewed.signed().clone(),
        })
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(e, AppEvent::RenewalSeen)));
    assert_eq!(app.cert().hash(), old.hash(), "not listed yet");
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.apps.push(ListedApp {
            app_id: me,
            cert: renewed.hash(),
        });
        body.renewed.push(RenewedCert {
            app_id: me,
            cert: old.hash(),
            until: None,
        });
    });
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::CertificateTaken { .. }
        )),
        "{:?}",
        report.events
    );
    assert_eq!(app.cert().hash(), renewed.hash());
    // The record carrying it was delivered.
    assert_eq!(
        w.switch.app(&me).cert.map(|c| c.hash()),
        Some(renewed.hash())
    );
    // The app goes on with it: a note still arrives.
    let (seq, _) = w.note(me, "after");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq));
}

#[tokio::test]
async fn test_app_expired_certificate_is_renewed_by_the_signer_alone() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let old = app.cert().clone();
    // The certificate expires: the switch refuses the app everything, its feed read too.
    w.clock.set_ms(old.expires_at() + 1);
    let Err(AppError::Switch(crate::ClientError::Switch { code, .. })) = app.receive(None).await
    else {
        panic!("an expired app is refused");
    };
    assert_eq!(code, ErrorCode::CertExpired);
    // Step 1: the signer stores the renewed certificate with a full bundle made for it, in
    // one batch, while the document still lists the expired certificate.
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["scope-a"],
    );
    let has_keys = |s: &str| SampleProtocol::default().has_keys(s);
    let epoch = w.switch.identity_doc().unwrap().data_epoch();
    let mut batch = vec![OpKind::CertPut {
        target_app_id: me,
        cert: renewed.signed().clone(),
    }];
    for part in seal_bundle_parts(&w.alice, &renewed, 1, epoch, &has_keys).unwrap() {
        batch.push(OpKind::KeyBundlePut(KeyBundlePut {
            target_app_id: me,
            bundle: part.bundle,
            first_epoch: part.first_epoch,
            last_epoch: part.last_epoch,
        }));
    }
    w.switch.signer_batch(batch).unwrap();
    // Still expired until the document lists the renewal.
    assert!(app.receive(None).await.is_err());
    // Step 2: the delivery listing the new certificate. From it the switch checks the app
    // against the renewed certificate, so the app reads its feed again, takes the
    // certificate and delivers its record carrying it.
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.apps.push(ListedApp {
            app_id: me,
            cert: renewed.hash(),
        });
        body.renewed.push(RenewedCert {
            app_id: me,
            cert: old.hash(),
            until: None,
        });
    });
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::CertificateTaken { .. }
        )),
        "{:?}",
        report.events
    );
    assert_eq!(app.cert().hash(), renewed.hash());
    assert_eq!(
        w.switch.app(&me).cert.map(|c| c.hash()),
        Some(renewed.hash())
    );
    // The app goes on with it, and holds the keys the renewal's bundle gave.
    app.receive(None).await.unwrap();
    assert_eq!(
        app.scope_key(epoch, "scope-a"),
        Some(w.alice.scope_key(epoch, "scope-a"))
    );
}

/// An app of `w` whose device clock is its own, starting `offset_ms` from the service's.
async fn app_with_its_own_clock(w: &World, offset_ms: i64) -> (App, Arc<TestClock>) {
    let start = w.clock.now_ms().saturating_add_signed(offset_ms);
    let clock = Arc::new(TestClock::new(start));
    let mut env = w.env();
    env.clock = Arc::clone(&clock) as Arc<dyn Clock>;
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let app = App::join(env, w.protocol.clone(), World::config(), request)
        .await
        .unwrap();
    (app, clock)
}

#[tokio::test]
async fn test_kept_effect_window_holds_with_the_device_clock_ahead_at_the_keep() {
    let w = World::new();
    // The device clock reads two hours ahead; its requests still pass, a `401
    // stale_timestamp` being retried at the service's time.
    let (mut app, clock) = app_with_its_own_clock(&w, 2 * HOUR as i64).await;
    let me = app.app_id();
    let (seq, _) = w.note(me, "before");
    // Its effect is kept, the send not reaching the service, whichever of the read's
    // requests that send is.
    for after in 0..4 {
        w.switch.fail_next(Fault::Unreachable {
            path: "ops".into(),
            after,
        });
        let _ = app.receive(None).await;
        w.switch.lock().faults.clear();
        if app.state.pending_effect.is_some() {
            break;
        }
    }
    assert!(app.state.pending_effect.is_some());
    // Kept in service time, whatever the device read.
    let kept = app.state.pending_effect.as_ref().unwrap().kept_ms.unwrap();
    assert!(kept <= w.clock.now_ms(), "{kept}");
    // The clock is set right. 30 days and half an hour after the service applied it, its
    // proofs are gone and a retry would be answered `409 conflict`.
    w.clock.advance_ms(30 * 24 * HOUR + HOUR / 2);
    clock.set_ms(w.clock.now_ms());
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!(null),
    });
    let built = w.protocol.received.lock().unwrap().len();
    let report = app.receive(None).await.unwrap();
    // Past the window: not sent again, stored as uncertain, never built again.
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::EffectUncertain { seq: s, .. } if *s == seq
        )),
        "{:?}",
        report.events
    );
    assert_eq!(w.protocol.received.lock().unwrap().len(), built);
    assert_eq!(w.effects(), 0, "not sent");
}

#[tokio::test]
async fn test_kept_effect_window_holds_with_the_device_clock_behind_at_the_resend() {
    let w = World::new();
    let (mut app, clock) = app_with_its_own_clock(&w, 0).await;
    let me = app.app_id();
    let (seq, _) = w.note(me, "before");
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    // A fresh load, the service time it holds from before; 30 days and half an hour on,
    // the device clock reads two hours behind.
    let mut env = w.env();
    env.clock = Arc::clone(&clock) as Arc<dyn Clock>;
    drop(app);
    let mut app = App::load(env, w.protocol.clone(), World::config(), me)
        .await
        .unwrap();
    w.clock.advance_ms(30 * 24 * HOUR + HOUR / 2);
    clock.set_ms(w.clock.now_ms() - 2 * HOUR);
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!(null),
    });
    let built = w.protocol.received.lock().unwrap().len();
    let report = app.receive(None).await.unwrap();
    // A service time read first shows it past the window: not sent again.
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::EffectUncertain { seq: s, .. } if *s == seq
        )),
        "{:?}",
        report.events
    );
    assert_eq!(w.protocol.received.lock().unwrap().len(), built);
    assert_eq!(w.effects(), 1);
}

/// A kept effect refused with `403 cert_expired` stays kept, and goes again once the renewal
/// is listed. A service following Switch wire 7.2 checks an own app against the stored
/// renewed certificate as soon as the newest `identity.json` lists it, so the resend can
/// pass before the app adopts the certificate: this test passes whether or not the app
/// takes the renewal before it sends the kept effect again.
#[tokio::test]
async fn test_app_kept_effect_refused_for_an_expired_certificate_waits_for_the_renewal() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let old = app.cert().clone();
    // A day before the certificate expires, a note's effect is applied, its answer lost:
    // the effect is kept.
    w.clock.set_ms(old.expires_at() - 24 * HOUR);
    let (seq, _) = w.note(me, "before");
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    assert_eq!(w.effects(), 1);
    // The certificate expires: the resend is refused about the caller, so the effect stays.
    w.clock.set_ms(old.expires_at() + 1);
    let Err(AppError::Switch(crate::ClientError::Switch { code, .. })) = app.receive(None).await
    else {
        panic!("an expired app is refused");
    };
    assert_eq!(code, ErrorCode::CertExpired);
    assert!(app.state.pending_effect.is_some());
    // The signer renews it and lists the renewal.
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["scope-a"],
    );
    let has_keys = |s: &str| SampleProtocol::default().has_keys(s);
    let epoch = w.switch.identity_doc().unwrap().data_epoch();
    let mut batch = vec![OpKind::CertPut {
        target_app_id: me,
        cert: renewed.signed().clone(),
    }];
    for part in seal_bundle_parts(&w.alice, &renewed, 1, epoch, &has_keys).unwrap() {
        batch.push(OpKind::KeyBundlePut(KeyBundlePut {
            target_app_id: me,
            bundle: part.bundle,
            first_epoch: part.first_epoch,
            last_epoch: part.last_epoch,
        }));
    }
    w.switch.signer_batch(batch).unwrap();
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.apps.push(ListedApp {
            app_id: me,
            cert: renewed.hash(),
        });
        body.renewed.push(RenewedCert {
            app_id: me,
            cert: old.hash(),
            until: None,
        });
    });
    // The renewal is taken, the same bytes go again and show the effect applied: once.
    let mut events = Vec::new();
    for _ in 0..2 {
        if let Ok(report) = app.receive(None).await {
            events.extend(report.events);
        }
    }
    assert!(
        has(&events, |e| matches!(e, AppEvent::CertificateTaken { .. })),
        "{events:?}"
    );
    assert!(received(&events, seq), "{events:?}");
    assert_eq!(w.effects(), 1);
    assert!(app.state.pending_effect.is_none());
    assert_eq!(app.cert().hash(), renewed.hash());
}

#[tokio::test]
async fn test_app_ignores_a_cert_put_of_other_keys() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let other = cert_for(
        &w.alice,
        &app_keys("phone"),
        w.clock.now_ms() + 1000,
        &["scope-a"],
    );
    // A compliant switch refuses this cert.put; a faulty one chains it.
    w.switch
        .chain_unchecked(
            &w.alice,
            None,
            OpKind::CertPut {
                target_app_id: app.app_id(),
                cert: other.signed().clone(),
            },
        )
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(!has(&report.events, |e| matches!(e, AppEvent::RenewalSeen)));
}

#[tokio::test]
async fn test_app_key_bundle_with_a_missing_epoch_asks_for_a_full_bundle() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    assert_eq!(app.keys_through(), 1);
    let cert = app.cert().clone();
    let has_keys = |s: &str| SampleProtocol::default().has_keys(s);
    // The epoch rises to 3, but only epoch 3's part is stored.
    w.next_doc(|body| body.data_epoch = 3);
    for part in seal_bundle_parts(&w.alice, &cert, 3, 3, &has_keys).unwrap() {
        w.switch
            .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: me,
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
    }
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::FullBundleRequested
        )),
        "{:?}",
        report.events
    );
    assert!(app.scope_key(3, "scope-a").is_some());
    assert!(app.scope_key(2, "scope-a").is_none());
    assert_eq!(app.keys_through(), 1);
    assert!(w.switch.app(&me).full_requested.is_some());
    // The signer stores a full bundle: every epoch held, the request done.
    for part in seal_bundle_parts(&w.alice, &cert, 1, 3, &has_keys).unwrap() {
        w.switch
            .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: me,
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
    }
    app.receive(None).await.unwrap();
    assert_eq!(app.keys_through(), 3);
    assert_eq!(
        app.scope_key(2, "scope-a"),
        Some(w.alice.scope_key(2, "scope-a"))
    );
}

#[tokio::test]
async fn test_app_skips_a_bundle_part_with_another_naming_key() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    // Another identity's parts, sealed to the app's bundle key: they don't verify for
    // alice, so a compliant switch refuses them; a faulty one chains them, and the app skips
    // them and takes nothing.
    let mallory = IdentityKey::from_secret([46; 32]);
    let fake_cert = cert_for(
        &mallory,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["scope-a"],
    );
    let has_keys = |s: &str| SampleProtocol::default().has_keys(s);
    let part = seal_bundle_parts(&mallory, &fake_cert, 1, 1, &has_keys)
        .unwrap()
        .remove(0);
    w.switch
        .chain_unchecked(
            &w.alice,
            None,
            OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: me,
                bundle: part.bundle,
                first_epoch: 1,
                last_epoch: 1,
            }),
        )
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::BundlePartSkipped { .. }
    )));
    assert_eq!(
        app.scope_key(1, "scope-a"),
        Some(w.alice.scope_key(1, "scope-a"))
    );
}

/// Rotate the app once (an opened envelope, then a day), returning its backup taken before.
async fn backup_then_rotate(w: &World, app: &mut App) -> AppBackup {
    let backup = app.backup().unwrap();
    w.note(app.app_id(), "before the rotation");
    app.receive(None).await.unwrap();
    w.clock.advance_ms(25 * HOUR);
    app.receive(None).await.unwrap();
    assert_eq!(app.receive_key_numbers().last(), Some(&1));
    backup
}

async fn restored(w: &World, backup: &AppBackup) -> (App, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let app = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        backup,
    )
    .await
    .unwrap();
    (app, store)
}

#[tokio::test]
async fn test_app_restore_asks_about_registrations_since_the_backup() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let backup = backup_then_rotate(&w, &mut app).await;
    let backup = AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap();
    let (mut restored, _) = restored(&w, &backup).await;
    assert!(restored.reconcile_mode());
    let report = restored.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::RestoreQuestion { .. }
    )));
    assert_eq!(restored.restore_question(), vec![1]);
    // It registered a fresh key above the current one before reading on.
    assert_eq!(restored.receive_key_numbers().last(), Some(&2));
    assert_eq!(
        restored.may_attempt(false),
        Err(Refusal::RestoreQuestionOpen)
    );
    // The user confirms the app ran on this device after the backup.
    restored
        .confirm_restored_registrations(UserConfirmed::new())
        .await
        .unwrap();
    assert!(restored.restore_question().is_empty());
    restored.end_reconcile(UserConfirmed::new()).await.unwrap();
    assert!(restored.may_attempt(false).is_ok());
    // A note sealed to the new key arrives.
    let (seq, _) = w.note(restored.app_id(), "after the restore");
    let report = restored.receive(None).await.unwrap();
    assert!(received(&report.events, seq));
}

#[tokio::test]
async fn test_app_restore_refused_registration_is_a_compromise() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let backup = backup_then_rotate(&w, &mut app).await;
    let (mut restored, _) = restored(&w, &backup).await;
    restored.receive(None).await.unwrap();
    let error = restored.refuse_restored_registrations().await.unwrap_err();
    assert!(matches!(
        error,
        AppError::Alarm(Alarm::Compromise { n: 1, .. })
    ));
    assert!(w.switch.app(&restored.app_id()).departed);
}

#[tokio::test]
async fn test_app_restore_registration_after_its_own_key_is_a_compromise() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let backup = backup_then_rotate(&w, &mut app).await;
    let (mut restored, _) = restored(&w, &backup).await;
    restored.receive(None).await.unwrap();
    // The thief registers after the restored app's own new key.
    let thief = ReceiveKey::from_secret(3, [47; 32]);
    let cert = restored.cert().clone();
    let record = ReceiveKeyRecord::sign(
        &app_keys("wallet"),
        &cert,
        ReceiveKeyBody::new(&cert, &thief),
    )
    .unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::ReceiveKeyPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    let error = restored.receive(None).await.unwrap_err();
    assert!(
        matches!(error, AppError::Alarm(Alarm::Compromise { n: 3, .. })),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_app_restore_with_its_current_key_registers_nothing() {
    let w = World::new();
    let app = w.join("wallet").await;
    let backup = app.backup().unwrap();
    let (mut restored, _) = restored(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert!(restored.restore_question().is_empty());
    assert_eq!(restored.receive_key_numbers(), vec![0]);
}

#[tokio::test]
async fn test_app_leaves_in_two_steps() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    assert_eq!(
        app.leave(LeaveMode::TwoStep).await.unwrap(),
        LeaveReport::AwaitingRemoval
    );
    assert!(w.switch.app(&me).departed);
    // Calls that read or write are refused from now on.
    assert_eq!(
        app.receive(None).await.unwrap_err(),
        AppError::Refused(Refusal::Left)
    );
    // The signer publishes the app as removed.
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from: START,
        });
    });
    let report = app.finish_leave().await.unwrap();
    assert!(matches!(report, LeaveReport::Removed { .. }));
    w.clock.advance_ms(11 * 60_000);
    assert_eq!(app.finish_leave().await.unwrap(), LeaveReport::Done);
    // The keys are gone from the store.
    let error = App::load(w.env(), w.protocol.clone(), World::config(), me)
        .await
        .unwrap_err();
    assert_eq!(error, AppError::Refused(Refusal::Left));
}

#[tokio::test]
async fn test_app_leaving_deletes_the_duty_events_and_owed_calls() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    assert!(!refuse_next(&w, &mut app).await.is_empty());
    let now = w.clock.now_ms();
    w.switch.push_missed(1, now - HOUR, now);
    *w.protocol.failing.lock().unwrap() = 1;
    app.receive(None).await.unwrap();
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 1);
    assert!(!app.reader().scan_raw("duty/").await.unwrap().is_empty());
    app.leave(LeaveMode::TwoStep).await.unwrap();
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from: START,
        });
    });
    app.finish_leave().await.unwrap();
    w.clock.advance_ms(11 * 60_000);
    assert_eq!(app.finish_leave().await.unwrap(), LeaveReport::Done);
    // With the keys, what the app owed its protocol is gone from the store.
    assert!(app.reader().scan_raw("duty/").await.unwrap().is_empty());
    assert!(app.reader().scan_raw("owed/").await.unwrap().is_empty());
}

#[tokio::test]
async fn test_app_leave_retried_after_a_lost_answer() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.switch.fail_next(Fault::LoseAnswer {
        path: "leave".into(),
    });
    assert!(
        app.leave(LeaveMode::Immediate(UserConfirmed::new()))
            .await
            .is_err()
    );
    // The service counts the app as departed: `403 not_current` is the leave done.
    assert_eq!(
        app.leave(LeaveMode::Immediate(UserConfirmed::new()))
            .await
            .unwrap(),
        LeaveReport::Done
    );
}

#[tokio::test]
async fn test_app_removed_by_the_signer_stops_reading() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from: START,
        });
    });
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Removed)));
}

#[tokio::test]
async fn test_app_service_time_going_back_is_an_alarm() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.clock.advance_ms(HOUR);
    app.receive(None).await.unwrap();
    // The service signs an earlier time than one the app verified.
    w.clock.set_ms(START + HOUR / 2);
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(error, AppError::Alarm(Alarm::ServiceTimeBackwards { .. })),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_app_refresh_identity_takes_a_newer_homeserver_copy() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let before = app.own_identity().version();
    // Published on the Homeserver, not yet read in the feed.
    let mut body = w.signer.body();
    body.version += 1;
    let newer = IdentityDoc::sign(&w.alice, body.clone()).unwrap();
    w.homeserver.publish(&newer).unwrap();
    assert_eq!(
        app.refresh_identity().await.unwrap(),
        IdentityRefresh::Newer {
            version: before + 1,
            confirmed_at: START,
        }
    );
    assert_eq!(app.own_identity().version(), before + 1);
    assert_eq!(app.identity_confirmed_at(), Some(START));
    // The same copy again confirms it.
    w.clock.set_ms(START + 5_000);
    assert_eq!(
        app.refresh_identity().await.unwrap(),
        IdentityRefresh::Current {
            confirmed_at: START + 5_000
        }
    );
    assert_eq!(app.identity_confirmed_at(), Some(START + 5_000));
    // Another body at that version, from the switch: equivocation across sources.
    body.data_epoch += 1;
    let other = IdentityDoc::sign(&w.alice, body).unwrap();
    w.switch.deliver_identity(&other).unwrap();
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(error, AppError::Alarm(Alarm::Equivocation { .. })),
        "{error:?}"
    );
}

/// A store whose commits take `delay_ms` of the test clock.
struct SlowStore {
    inner: MemoryStore,
    clock: Arc<crate::clock::TestClock>,
    delay_ms: std::sync::atomic::AtomicU64,
}

impl StateStore for SlowStore {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, crate::error::StoreError> {
        self.inner.get(ns, key)
    }

    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<crate::store::KeyValue>, crate::error::StoreError> {
        self.inner.scan(ns, prefix, after, limit)
    }

    fn commit(&self, batch: crate::store::WriteBatch) -> Result<(), crate::error::StoreError> {
        self.clock
            .advance_ms(self.delay_ms.load(std::sync::atomic::Ordering::SeqCst));
        self.inner.commit(batch)
    }
}

#[tokio::test]
async fn test_app_refresh_identity_confirms_at_the_time_of_the_read() {
    let w = World::new();
    let store = Arc::new(SlowStore {
        inner: MemoryStore::new(),
        clock: Arc::clone(&w.clock),
        delay_ms: std::sync::atomic::AtomicU64::new(0),
    });
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let mut app = App::join(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        request,
    )
    .await
    .unwrap();
    let mut body = w.signer.body();
    body.version += 1;
    w.homeserver
        .publish(&IdentityDoc::sign(&w.alice, body).unwrap())
        .unwrap();
    // Taking the newer copy is slow: the read it confirms is past the window by the end.
    store
        .delay_ms
        .store(REVALIDATION_MS + 1, std::sync::atomic::Ordering::SeqCst);
    let read_at = w.clock.now_ms();
    let refreshed = app.refresh_identity().await.unwrap();
    assert!(
        matches!(refreshed, IdentityRefresh::Newer { .. }),
        "{refreshed:?}"
    );
    assert_eq!(refreshed.confirmed_at(), Some(read_at));
    assert_eq!(app.identity_confirmed_at(), Some(read_at));
    assert!(w.clock.now_ms() - read_at > REVALIDATION_MS);
}

#[tokio::test]
async fn test_app_refresh_identity_of_an_older_copy_confirms_nothing() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let first = app.own_identity().clone();
    assert!(
        app.refresh_identity()
            .await
            .unwrap()
            .confirmed_at()
            .is_some()
    );
    w.next_doc(|_| {});
    app.receive(None).await.unwrap();
    // The copy taken from the feed isn't the one the Homeserver confirmed.
    assert_eq!(app.identity_confirmed_at(), None);
    // A stale Homeserver serves the earlier version.
    w.homeserver.publish(&first).unwrap();
    assert_eq!(
        app.refresh_identity().await.unwrap(),
        IdentityRefresh::Older {
            served: first.version()
        }
    );
    assert_eq!(app.own_identity().version(), first.version() + 1);
    assert_eq!(app.identity_confirmed_at(), None);
}

#[tokio::test]
async fn test_app_refresh_identity_missing_or_unavailable_confirms_nothing() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    assert_eq!(app.identity_confirmed_at(), None);
    let confirmed = app.refresh_identity().await.unwrap();
    assert_eq!(
        confirmed,
        IdentityRefresh::Current {
            confirmed_at: START
        }
    );
    // The Homeserver stops serving the document: the last confirmation stays where it was,
    // so it ages past the window.
    w.homeserver
        .remove(w.alice.public(), pubky_switch_core::records::IDENTITY_PATH);
    w.clock.set_ms(START + REVALIDATION_MS);
    let missing = app.refresh_identity().await.unwrap();
    assert_eq!(missing, IdentityRefresh::Missing);
    assert_eq!(missing.confirmed_at(), None);
    assert_eq!(app.identity_confirmed_at(), Some(START));
    let fresh = |app: &App, now: u64| {
        app.identity_confirmed_at()
            .is_some_and(|at| now.saturating_sub(at) < REVALIDATION_MS)
    };
    assert!(!fresh(&app, START + REVALIDATION_MS));
    // A Homeserver that can't be read confirms nothing either.
    w.homeserver.set_down(true);
    let unavailable = app.refresh_identity().await.unwrap();
    assert_eq!(unavailable, IdentityRefresh::Unavailable);
    assert_eq!(unavailable.confirmed_at(), None);
    assert_eq!(app.identity_confirmed_at(), Some(START));
    // Served again, it confirms the copy held anew.
    w.homeserver.set_down(false);
    w.homeserver.publish(app.own_identity()).unwrap();
    let again = app.refresh_identity().await.unwrap();
    assert_eq!(again.confirmed_at(), Some(START + REVALIDATION_MS));
    assert!(fresh(&app, START + REVALIDATION_MS));
}

#[test]
fn test_app_config_keeps_the_spec_bounds() {
    let config = AppConfig {
        rotation_interval_ms: 1,
        cursor_defer_ms: 60_000,
        page_size: 0,
        ..AppConfig::default()
    };
    assert_eq!(config.rotation_ms(), crate::app::MIN_ROTATION_MS);
    assert_eq!(config.defer_ms(), crate::app::MAX_CURSOR_DEFER_MS);
    assert_eq!(config.page(), 1);
    let default = AppConfig::default();
    assert_eq!(default.rotation_ms(), crate::app::DEFAULT_ROTATION_MS);
    assert_eq!(default.page(), 100);
}

#[tokio::test]
async fn test_app_backup_refuses_another_schema_or_bytes() {
    let w = World::new();
    let app = w.join("wallet").await;
    let bytes = app.backup().unwrap().to_bytes().unwrap();
    assert!(AppBackup::from_bytes(&bytes).is_ok());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["v"] = json!(crate::app::SCHEMA_VERSION - 1);
    let other = serde_json::to_vec(&value).unwrap();
    assert!(matches!(
        AppBackup::from_bytes(&other),
        Err(AppError::InvalidData(_))
    ));
    assert!(AppBackup::from_bytes(b"{}").is_err());
    // Its Debug names the app only.
    let text = format!("{:?}", app.backup().unwrap());
    assert!(text.starts_with("AppBackup("));
}

// -------------------------------------------------------------------------------------
// Reading past held entries, duplicates on one page, effects refused for good

/// A notice from alice's phone to `to`.
fn notice(
    w: &World,
    phone: &App,
    to: [u8; 16],
    text: &str,
) -> (u64, pubky_switch_core::message::Message) {
    w.switch
        .send(
            &w.alice,
            &app_keys("phone"),
            phone.cert(),
            "sample.notice",
            json!({ "text": text }),
            &[to],
        )
        .unwrap()
}

#[tokio::test]
async fn test_app_held_entry_doesnt_hold_up_later_pages() {
    let w = World::new();
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let config = AppConfig {
        page_size: 2,
        ..World::config()
    };
    let mut wallet = App::join(w.env(), w.protocol.clone(), config, request)
        .await
        .unwrap();
    let phone = w.join("phone").await;
    let me = wallet.app_id();
    wallet.receive(None).await.unwrap();
    w.homeserver.set_down(true);
    let (held, _) = w.note(me, "held");
    let later: Vec<u64> = (0..5)
        .map(|n| notice(&w, &phone, me, &format!("later {n}")).0)
        .collect();
    // A read that went back to the cursor for every page would never end: the switch
    // answers `503` after a bound.
    {
        let mut inner = w.switch.lock();
        inner.feed_limit = Some(inner.feed_reads + 20);
    }
    let report = wallet.receive(None).await.unwrap();
    assert!(has(
        &report.events,
        |e| matches!(e, AppEvent::Held { seq } if *seq == held)
    ));
    for seq in &later {
        assert!(received(&report.events, *seq), "{seq}: {:?}", report.events);
    }
    // The cursor stays before the held entry, here and at the switch.
    assert!(wallet.cursor().seq < held);
    assert!(w.switch.app(&me).cursor < held);
    // The next read meets the held entry again and processes nothing twice.
    let report = wallet.receive(None).await.unwrap();
    for seq in &later {
        assert!(!received(&report.events, *seq), "{seq}");
    }
    assert_eq!(w.protocol.received.lock().unwrap().len(), 5);
}

#[tokio::test]
async fn test_app_same_pair_twice_on_one_page_is_applied_once() {
    let w = World::new();
    let mut wallet = w.join("wallet").await;
    let phone = w.join("phone").await;
    let me = wallet.app_id();
    wallet.receive(None).await.unwrap();
    // A notice has no operations: its processed pair is only in the read's writes when the
    // second copy comes.
    let (first, message) = notice(&w, &phone, me, "once");
    let plaintext = message.sign(&app_keys("phone")).unwrap();
    let again = w
        .switch
        .send_plaintext(w.alice.public(), phone.cert(), &plaintext, &[me])
        .unwrap();
    let mut other = message.clone();
    other.body.insert("text".into(), json!("changed"));
    let plaintext = other.sign(&app_keys("phone")).unwrap();
    let third = w
        .switch
        .send_plaintext(w.alice.public(), phone.cert(), &plaintext, &[me])
        .unwrap();
    let report = wallet.receive(None).await.unwrap();
    assert!(received(&report.events, first));
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Duplicate { seq, conflicting: false } if *seq == again
    )));
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Duplicate { seq, conflicting: true } if *seq == third
    )));
    assert_eq!(w.protocol.received.lock().unwrap().len(), 1);
    assert!(wallet.cursor().seq >= third);
}

#[tokio::test]
async fn test_app_effect_refused_for_good_is_parked_and_the_feed_goes_on() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let (refused, _) = w.note(me, "refused");
    let (after, _) = w.note(me, "after");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::PermissionMissing,
        current: json!(null),
    });
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Parked { id: Some(_), seq, reason: ParkReason::Refused } if *seq == refused
    )));
    // The protocol is told, with the code, so it may build the effect another way (Switch
    // spec 8.2).
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::EffectRefused { seq, code: Some(code), kind, .. }
                if *seq == refused && code == "permission_missing" && kind == "sample.note"
        )),
        "{:?}",
        report.events
    );
    assert!(received(&report.events, after), "{:?}", report.events);
    assert!(app.cursor().seq >= after);
    assert_eq!(w.effects(), 1);
    // It isn't tried again.
    let report = app.receive(None).await.unwrap();
    assert!(!has(&report.events, |e| matches!(
        e,
        AppEvent::Unparked { .. }
    )));
    assert_eq!(w.effects(), 1);
}

// -------------------------------------------------------------------------------------
// Duty events (`events` module, "Duty events")

fn refused_events(events: &[AppEvent], seq: u64) -> Vec<AppEvent> {
    events
        .iter()
        .filter(|e| matches!(e, AppEvent::EffectRefused { seq: s, .. } if *s == seq))
        .cloned()
        .collect()
}

/// A joined app with a note at the first `seq` whose effect the switch refuses for good,
/// and a note after it.
async fn refusing(w: &World) -> (App, u64, u64) {
    let app = w.join("wallet").await;
    let me = app.app_id();
    let (refused, _) = w.note(me, "refused");
    let (after, _) = w.note(me, "after");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::PermissionMissing,
        current: json!(null),
    });
    (app, refused, after)
}

/// `app`, loaded again on `w`'s store behind `fault`.
async fn load_behind(w: &World, app: App, fault: StoreFault) -> (App, Arc<FaultStore>) {
    let me = app.app_id();
    drop(app);
    let store = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        fault,
    ));
    let app = App::load(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        me,
    )
    .await
    .unwrap();
    (app, store)
}

#[tokio::test]
async fn test_duty_event_kept_through_a_crash_before_it_is_taken() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let (refused, _) = w.note(me, "refused");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::PermissionMissing,
        current: json!(null),
    });
    let report = app.receive(None).await.unwrap();
    let first = refused_events(&report.events, refused);
    assert_eq!(first.len(), 1, "{:?}", report.events);
    assert!(first.iter().all(AppEvent::is_duty));
    // The host stops before it acts on the report: the next load delivers it again, with
    // the same ID.
    drop(app);
    let mut app = w.load(me).await;
    let events = app.take_events();
    assert_eq!(refused_events(&events, refused), first, "{events:?}");
    assert!(has(&events, |e| matches!(
        e,
        AppEvent::Parked { id: Some(_), seq, reason: ParkReason::Refused } if *seq == refused
    )));
    assert_eq!(app.unacknowledged_events().await.unwrap(), events);
}

#[tokio::test]
async fn test_duty_event_delivered_again_until_acknowledged() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    w.note(me, "refused");
    let (after, _) = w.note(me, "after");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::PermissionMissing,
        current: json!(null),
    });
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, after));
    let duties: Vec<AppEvent> = report
        .events
        .iter()
        .filter(|e| e.is_duty())
        .cloned()
        .collect();
    assert_eq!(duties.len(), 2, "{:?}", report.events);
    // Not acknowledged: every load delivers them again; informational events aren't kept.
    for _ in 0..2 {
        let mut app = w.load(me).await;
        let events = app.take_events();
        assert_eq!(events, duties);
        assert!(!received(&events, after), "{events:?}");
    }
    // Acknowledged up to the last: gone, across a reload too.
    let last = last_id(&duties);
    app.ack_events(last).await.unwrap();
    assert!(app.unacknowledged_events().await.unwrap().is_empty());
    let mut app = w.load(me).await;
    assert!(app.take_events().is_empty());
    // The next duty event takes a new ID.
    let (again, _) = w.note(me, "again");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::PermissionMissing,
        current: json!(null),
    });
    let report = app.receive(None).await.unwrap();
    let next = refused_events(&report.events, again);
    assert!(
        next.iter()
            .filter_map(AppEvent::id)
            .all(|id| id.cmp_same_store(&last) == Some(std::cmp::Ordering::Greater)),
        "{next:?}"
    );
}

#[tokio::test]
async fn test_duty_event_acknowledged_in_part_keeps_the_later_ones() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let (refused, _) = w.note(me, "refused");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::PermissionMissing,
        current: json!(null),
    });
    let report = app.receive(None).await.unwrap();
    let ids: Vec<EventId> = report.events.iter().filter_map(AppEvent::id).collect();
    assert_eq!(ids.len(), 2, "{:?}", report.events);
    assert_eq!(
        ids[0].cmp_same_store(&ids[1]),
        Some(std::cmp::Ordering::Less)
    );
    app.ack_events(ids[0]).await.unwrap();
    let mut app = w.load(me).await;
    let events = app.take_events();
    assert_eq!(
        events.iter().filter_map(AppEvent::id).collect::<Vec<_>>(),
        vec![ids[1]]
    );
    assert_eq!(refused_events(&events, refused).len(), 1, "{events:?}");
}

/// Refuse the effect of the next note to `app` for good, and read it: the duty events.
async fn refuse_next(w: &World, app: &mut App) -> Vec<AppEvent> {
    w.note(app.app_id(), "refused");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::PermissionMissing,
        current: json!(null),
    });
    let report = app.receive(None).await.unwrap();
    report
        .events
        .into_iter()
        .filter(AppEvent::is_duty)
        .collect()
}

/// The duty event of the highest counter among `events`, all of one store.
fn last_id(events: &[AppEvent]) -> EventId {
    let ids: Vec<EventId> = events.iter().filter_map(AppEvent::id).collect();
    assert!(ids.iter().all(|id| ids[0].same_store(id)), "{ids:?}");
    ids.into_iter().max_by_key(EventId::counter).unwrap()
}

#[test]
fn test_duty_event_id_round_trips_its_stable_forms() {
    let id = EventId::new([7; 16], 42);
    assert_eq!(EventId::from_bytes(&id.to_bytes()), Ok(id));
    assert_eq!(id.to_string().parse::<EventId>(), Ok(id));
    assert_eq!(id.to_string(), format!("{}-42", "07".repeat(16)));
    for bad in [
        "",
        "07-1",
        &format!("{}-", "07".repeat(16)),
        &format!("{}-x", "07".repeat(16)),
    ] {
        assert!(bad.parse::<EventId>().is_err(), "{bad}");
    }
    assert!(EventId::from_bytes(&[0; 23]).is_err());
    // Ordered within one store only.
    let other = EventId::new([8; 16], 1);
    assert_eq!(id.cmp_same_store(&other), None);
    assert_eq!(
        id.cmp_same_store(&EventId::new([7; 16], 1)),
        Some(std::cmp::Ordering::Greater)
    );
}

#[tokio::test]
async fn test_duty_event_ids_after_a_restore_on_a_fresh_store_are_new() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let backup = app.backup().unwrap();
    let start = w.clock.now_ms();
    let before = refuse_next(&w, &mut app).await;
    let acked = last_id(&before);
    app.ack_events(acked).await.unwrap();
    // The device is lost; the backup, older than the IDs the host acknowledged, is
    // restored on a new one whose clock reads earlier.
    w.clock.set_ms(start);
    let store = Arc::new(MemoryStore::new());
    let mut restored = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert!(restored.take_events().is_empty());
    let after = refuse_next(&w, &mut restored).await;
    assert_eq!(after.len(), before.len(), "{after:?}");
    // The same counters, under a new epoch: no ID equals one from before.
    let counters = |events: &[AppEvent]| {
        events
            .iter()
            .filter_map(AppEvent::id)
            .map(|id| id.counter())
            .collect::<Vec<_>>()
    };
    assert_eq!(counters(&after), counters(&before));
    for id in after.iter().filter_map(AppEvent::id) {
        assert!(!id.same_store(&acked), "{id}");
        assert!(before.iter().filter_map(AppEvent::id).all(|old| old != id));
    }
    // An acknowledgement of the old store's ID removes nothing here, and says so.
    let error = restored.ack_events(acked).await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error:?}"
    );
    assert_eq!(restored.unacknowledged_events().await.unwrap(), after);
}

#[tokio::test]
async fn test_duty_events_and_owed_calls_carried_across_a_restore_in_place() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let backup = app.backup().unwrap();
    let duties = refuse_next(&w, &mut app).await;
    assert_eq!(duties.len(), 2, "{duties:?}");
    let now = w.clock.now_ms();
    let seq = w.switch.push_missed(3, now - HOUR, now);
    *w.protocol.failing.lock().unwrap() = 1;
    app.receive(None).await.unwrap();
    assert!(w.protocol.missed.lock().unwrap().is_empty());
    // Restored in place from the older backup: what the app still owes its protocol stays,
    // with its IDs, and is delivered again.
    drop(app);
    let mut restored = App::restore(w.env(), w.protocol.clone(), World::config(), &backup)
        .await
        .unwrap();
    assert_eq!(restored.take_events(), duties);
    assert_eq!(restored.unacknowledged_events().await.unwrap(), duties);
    // Its next duty events continue the store's epoch and counter.
    let last = last_id(&duties);
    let next = refuse_next(&w, &mut restored).await;
    assert!(!next.is_empty());
    for id in next.iter().filter_map(AppEvent::id) {
        assert_eq!(
            id.cmp_same_store(&last),
            Some(std::cmp::Ordering::Greater),
            "{id} after {last}"
        );
    }
    restored.receive(None).await.unwrap();
    assert!(
        w.protocol
            .missed
            .lock()
            .unwrap()
            .iter()
            .any(|missed| missed.seq == seq && missed.entries == 3),
        "the owed call is made"
    );
    // Restored on another device, nothing of this store is carried.
    let store = Arc::new(MemoryStore::new());
    let mut other = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    assert!(other.unacknowledged_events().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_duty_event_reported_only_with_its_commit() {
    let w = World::new();
    let (app, _, _) = refusing(&w).await;
    let (mut app, counting) = load_behind(&w, app, StoreFault::None).await;
    app.receive(None).await.unwrap();
    let commits = counting.commits();
    assert!(commits > 1, "the read commits {commits} times");
    // Each commit of the read fails once in turn, applying nothing or applied with an
    // answer that can't tell: a refusal is reported at most once in all, only as kept, and
    // every kept duty event is reported.
    for n in 1..=commits {
        for fault in [StoreFault::FailBefore(n), StoreFault::FailAfter(n)] {
            let w = World::new();
            let (app, refused, after) = refusing(&w).await;
            let me = app.app_id();
            let (mut app, _) = load_behind(&w, app, fault).await;
            let mut events = match app.receive(None).await {
                Ok(report) => report.events,
                Err(_) => app.take_events(),
            };
            events.extend(app.receive(None).await.unwrap().events);
            let reported = refused_events(&events, refused);
            assert!(reported.len() <= 1, "{fault:?}: {events:?}");
            let kept = app.unacknowledged_events().await.unwrap();
            for event in &reported {
                assert!(kept.contains(event), "{fault:?}: {event:?} isn't kept");
            }
            for event in &kept {
                assert!(
                    events.contains(event),
                    "{fault:?}: {event:?} kept, never reported"
                );
            }
            assert!(app.cursor().seq >= after, "{fault:?}");
            // A later duty event, acknowledged: nothing kept is removed unreported.
            let later = refuse_next(&w, &mut app).await;
            events.extend(later.iter().cloned());
            app.ack_events(last_id(&later)).await.unwrap();
            for event in app.unacknowledged_events().await.unwrap() {
                assert!(
                    !events.contains(&event),
                    "{fault:?}: {event:?} acknowledged, kept"
                );
            }
            assert_eq!(w.load(me).await.take_events(), Vec::new(), "{fault:?}");
        }
    }
}

#[tokio::test]
async fn test_duty_event_replay_whose_read_fails_is_made_again() {
    let mut found = false;
    for n in 1..=8 {
        let w = World::new();
        let (app, seq, _) = refusing(&w).await;
        let (mut app, store) = load_behind(&w, app, StoreFault::FailAfter(n)).await;
        if app.receive(None).await.is_ok() {
            continue;
        }
        if !refused_events(&app.take_events(), seq).is_empty()
            || refused_events(&app.unacknowledged_events().await.unwrap(), seq).is_empty()
        {
            continue;
        }
        found = true;
        // The refusal's commit was applied unreported. The reload's replay of the kept duty
        // events fails once: the next call makes it again.
        store.fail_scan(b"duty/", 1);
        assert!(app.receive(None).await.is_err(), "commit {n}");
        let mut events = app.take_events();
        let later = refuse_next(&w, &mut app).await;
        events.extend(later.iter().cloned());
        assert_eq!(
            refused_events(&events, seq).len(),
            1,
            "commit {n}: {events:?}"
        );
        // Acknowledged: nothing kept was removed unseen.
        app.ack_events(last_id(&later)).await.unwrap();
        for event in app.unacknowledged_events().await.unwrap() {
            assert!(!events.contains(&event), "commit {n}: {event:?}");
        }
        break;
    }
    assert!(
        found,
        "a commit keeping the refusal answers that it can't tell"
    );
}

#[tokio::test]
async fn test_duty_event_kept_but_not_taken_survives_an_acknowledgement() {
    // The commit that keeps the refusal is applied, but answers that it can't tell: the
    // read fails, and nothing reports the refusal yet.
    let mut found = false;
    for n in 1..=8 {
        let w = World::new();
        let (app, seq, _) = refusing(&w).await;
        let (mut app, _) = load_behind(&w, app, StoreFault::FailAfter(n)).await;
        if app.receive(None).await.is_ok() {
            continue;
        }
        if !refused_events(&app.take_events(), seq).is_empty()
            || refused_events(&app.kept_duties().await.unwrap(), seq).is_empty()
        {
            continue;
        }
        found = true;
        // An acknowledgement of its ID before the host was handed it leaves it kept.
        let kept = app.kept_duties().await.unwrap();
        app.ack_events(last_id(&kept)).await.unwrap();
        assert_eq!(
            refused_events(&app.kept_duties().await.unwrap(), seq).len(),
            1,
            "commit {n}"
        );
        // The reload queued it: taken, then acknowledged, it goes.
        let taken = app.take_events();
        assert_eq!(
            refused_events(&taken, seq).len(),
            1,
            "commit {n}: {taken:?}"
        );
        app.ack_events(last_id(&taken)).await.unwrap();
        assert!(app.kept_duties().await.unwrap().is_empty());
        break;
    }
    assert!(
        found,
        "a commit keeping the refusal answers that it can't tell"
    );
}

#[tokio::test]
async fn test_duty_event_listed_after_a_load_can_be_acknowledged() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    assert_eq!(refuse_next(&w, &mut app).await.len(), 2);
    drop(app);
    // A new session: the host reads what it still has to act on, acts, and acknowledges,
    // without taking the call's events.
    let mut app = w.load(me).await;
    let listed = app.unacknowledged_events().await.unwrap();
    assert_eq!(listed.len(), 2);
    app.ack_events(last_id(&listed)).await.unwrap();
    assert!(app.unacknowledged_events().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_app_effect_kept_on_a_retryable_refusal_and_sent_again() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let (seq, _) = w.note(app.app_id(), "busy");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    assert!(app.receive(None).await.is_err());
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(w.effects(), 1);
    // The protocol built the effect once: the kept batch went again, the same bytes.
    assert_eq!(w.protocol.received.lock().unwrap().len(), 1);
}

/// The sample protocol, whose note writes eight operations: more than one batch takes with
/// the cursor move.
struct WideProtocol(SampleProtocol);

impl Protocol for WideProtocol {
    fn has_keys(&self, scope: &str) -> bool {
        self.0.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.0.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &pubky_switch_core::message::Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.0.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.0.accepts(cert)
    }

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.0.check_body(message)
    }

    fn receive(&self, message: &ReceivedMessage) -> Outcome {
        let ops = (0..8u8)
            .map(|n| (Vec::new(), OpKind::DenyPut { pubky: [n; 32] }))
            .collect();
        self.0
            .received
            .lock()
            .unwrap()
            .push((message.seq, message.message.msg_id.clone(), false));
        Outcome::Apply(Effect {
            ops,
            local: Vec::new(),
        })
    }

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.0.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.0.missed(missed)
    }
}

#[tokio::test]
async fn test_app_effect_over_one_batch_is_parked_and_the_feed_goes_on() {
    let w = World::new();
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let protocol = Arc::new(WideProtocol(SampleProtocol::default()));
    let mut app = App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap();
    let (first, _) = w.note(app.app_id(), "wide");
    let (second, _) = w.note(app.app_id(), "wide again");
    let report = app.receive(None).await.unwrap();
    for seq in [first, second] {
        assert!(has(&report.events, |e| matches!(
            e,
            AppEvent::Parked { id: Some(_), seq: s, reason: ParkReason::TooManyOperations } if *s == seq
        )));
        assert!(has(&report.events, |e| matches!(
            e,
            AppEvent::EffectRefused { seq: s, code: None, .. } if *s == seq
        )));
    }
    assert!(app.cursor().seq >= second);
    assert!(
        w.switch
            .applied()
            .iter()
            .all(|op| !matches!(op.body().kind, OpKind::DenyPut { .. }))
    );
    app.receive(None).await.unwrap();
    assert_eq!(protocol.0.received.lock().unwrap().len(), 2);
}

/// The wallet joined, then loaded again on a device clock `offset_ms` ahead of the switch's.
async fn wallet_on_a_clock_ahead(w: &World, offset_ms: u64) -> App {
    let me = w.join("wallet").await.app_id();
    let clock = Arc::new(crate::clock::TestClock::new(w.clock.now_ms() + offset_ms));
    let env = AppEnv {
        clock: clock as Arc<dyn crate::clock::Clock>,
        ..w.env()
    };
    App::load(env, w.protocol.clone(), World::config(), me)
        .await
        .unwrap()
}

#[tokio::test]
async fn test_app_stale_timestamp_is_retried_once_at_the_service_time() {
    let w = World::new();
    let mut app = wallet_on_a_clock_ahead(&w, 60 * 60_000).await;
    // The switch refuses the timestamp, and the client signs the call again at the time
    // the refusal names.
    let (seq, _) = w.note(app.app_id(), "hello");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    // Only once: a retry whose timestamp the switch refuses again is the answer.
    w.switch.fail_next(Fault::Error {
        path: "feed".into(),
        code: ErrorCode::StaleTimestamp,
        current: json!({ "server_time": pubky_switch_core::time::rfc3339(w.clock.now_ms() + 3_600_000) }),
    });
    let Err(AppError::Switch(crate::ClientError::Switch { code, .. })) = app.receive(None).await
    else {
        panic!("a second stale timestamp is the answer");
    };
    assert_eq!(code, ErrorCode::StaleTimestamp);
}

#[tokio::test]
async fn test_app_refusal_before_the_lock_measures_no_service_time() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    app.receive(None).await.unwrap();
    app.take_events();
    let highest = app.highest_service_time();
    let skew = app.clock_skew_ms();
    assert!(highest.is_some());
    // The account idles for days; its last stamped time stays where it was.
    w.clock.advance_ms(3 * pubky_switch_core::records::DAY_MS);
    // A refusal answered before the request verified carries that old time.
    w.switch.fail_next(Fault::Error {
        path: "feed".into(),
        code: ErrorCode::BadSignature,
        current: json!(null),
    });
    assert!(app.receive(None).await.is_err());
    // So does a stale timestamp, whose retry at the time it names is refused again: that
    // time, far ahead, counts for nothing either.
    w.switch.fail_next(Fault::Error {
        path: "feed".into(),
        code: ErrorCode::StaleTimestamp,
        current: json!({ "server_time": pubky_switch_core::time::rfc3339(w.clock.now_ms() + 30 * pubky_switch_core::records::DAY_MS) }),
    });
    assert!(app.receive(None).await.is_err());
    let events = app.take_events();
    assert!(
        !has(&events, |e| matches!(e, AppEvent::ClockSkew { .. })),
        "{events:?}"
    );
    assert_eq!(app.highest_service_time(), highest);
    assert_eq!(app.clock_skew_ms(), skew);
    // The next answer stamped at the switch measures the clock again.
    app.receive(None).await.unwrap();
    assert_eq!(app.highest_service_time(), Some(w.clock.now_ms()));
    assert_eq!(app.clock_skew_ms(), Some(0));
}

#[tokio::test]
async fn test_switch_cursor_set_behind_the_cursor_changes_nothing() {
    use pubky_switch_core::ops::{OpsRequest, Position};
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    w.note(me, "one");
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let cursor = w.switch.app(&me).cursor;
    assert!(cursor > 1);
    let post = |seq: u64| {
        let generation = w.switch.identity_doc().unwrap().generation();
        let body = OpsRequest::new(&[], Some(Position { generation, seq })).to_json();
        w.switch
            .handle(&crate::transport::Request {
                method: "POST".into(),
                origin: crate::testing::SWITCH_ORIGIN.into(),
                path_and_query: format!("/v1/{}/ops", w.alice.id()),
                headers: vec![
                    crate::transport::Header::new(
                        pubky_switch_core::http::header::IDENTITY,
                        &w.alice.id(),
                    ),
                    crate::transport::Header::new(
                        pubky_switch_core::http::header::APP,
                        &pubky_switch_core::enc::zbase32_encode(&me),
                    ),
                ],
                body,
            })
            .unwrap()
            .status
    };
    // Behind it, or at it: answered, and the cursor stays.
    assert_eq!(post(cursor - 1), 200);
    assert_eq!(w.switch.app(&me).cursor, cursor);
    assert_eq!(post(cursor), 200);
    assert_eq!(w.switch.app(&me).cursor, cursor);
}
