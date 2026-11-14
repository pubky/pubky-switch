//! App flows against the scripted switch.

use std::sync::{Arc, Mutex};

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
    Alarm, AppBackup, AppError, AppEvent, EventId, IdentityRefresh, LOCAL_WRITE_OVERHEAD_BYTES,
    LeaveMode, LeaveReport, MAX_STEP_LOCAL_BYTES, ParkReason, REVALIDATION_MS, Refusal,
    RefusedCall, UserConfirmed,
};
use crate::error::ClientError;
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::Fault;

const HOUR: u64 = 3_600_000;
const MINUTE: u64 = 60_000;

fn has(events: &[AppEvent], pred: impl Fn(&AppEvent) -> bool) -> bool {
    events.iter().any(pred)
}

pub(crate) fn received(events: &[AppEvent], seq: u64) -> bool {
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
    let backup = a.backup().await.unwrap();
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
    let backup = a.backup().await.unwrap();
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
    let before = b.backup().await.unwrap().to_bytes().unwrap();
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
    assert_eq!(b.backup().await.unwrap().to_bytes().unwrap(), before);
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
    assert_eq!(missed[0].accepted_until_ms, now);
    assert_eq!(
        app.protocol_get(mark.as_bytes()).await.unwrap(),
        Some(b"1".to_vec())
    );
    // Once.
    app.receive(None).await.unwrap();
    assert_eq!(w.protocol.missed.lock().unwrap().len(), 1);
}

/// Switch wire 7.5: the protocol is given the item's last acceptance time as well as the
/// first, raised to the time it asks from when it is earlier.
#[tokio::test]
async fn test_missed_entries_carry_the_items_last_acceptance_time() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.note(app.app_id(), "first");
    app.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    let after = w.switch.push_missed(3, now + 10 * MINUTE, now + HOUR);
    let before = w.switch.push_missed(2, now - 10 * HOUR, now - 9 * HOUR);
    app.receive(None).await.unwrap();
    let missed = w.protocol.missed.lock().unwrap().clone();
    let of = |seq: u64| missed.iter().find(|m| m.seq == seq).unwrap().clone();
    let after = of(after);
    assert_eq!(
        (after.accepted_from_ms, after.accepted_until_ms),
        (now + 10 * MINUTE, now + HOUR)
    );
    // Missed before the cursor's time: from that time less the tolerance, to that time.
    let before = of(before);
    assert_eq!(before.accepted_from_ms, now - CLOCK_TOLERANCE_MS);
    assert_eq!(before.accepted_until_ms, before.accepted_from_ms);
}

/// An item whose last acceptance time doesn't parse asks for no re-send, as one whose first
/// doesn't, and still owes the listing (Switch wire 7.4.4).
#[tokio::test]
async fn test_missed_entries_last_time_unparsable_asks_for_nothing() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.note(app.app_id(), "first");
    app.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    let seq = w.switch.push_missed_until_unparsable(3, now - HOUR);
    let (behind, _) = w.note(app.app_id(), "behind it");
    app.receive(None).await.unwrap();
    assert!(w.protocol.missed.lock().unwrap().is_empty());
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 0);
    assert!(app.cursor().seq >= behind && behind > seq);
    // The listing it owes was made: none is owed any more, and the item behind was read.
    assert!(!app.listing_owed().await.unwrap());
}

/// A missed-entries call kept owed in the form written before, without the item's last
/// acceptance time, still reads and is made, with no end.
#[tokio::test]
async fn test_missed_entries_owed_call_of_the_earlier_form_is_made_without_an_end() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    // Owed at the cursor, as a call is when its item is passed.
    let at = app.cursor().seq;
    let mut tx = app.tx().unwrap();
    tx.put(
        &crate::app::state::key::owed(1, at),
        &json!({ "Missed": { "seq": at, "entries": 2, "accepted_from_ms": now } }),
    )
    .unwrap();
    app.commit(tx).await.unwrap();
    drop(app);
    let mut app = w.load(me).await;
    app.receive(None).await.unwrap();
    let missed = w.protocol.missed.lock().unwrap().clone();
    assert_eq!(missed.len(), 1);
    assert_eq!(
        (
            missed[0].seq,
            missed[0].accepted_from_ms,
            missed[0].accepted_until_ms
        ),
        (at, now, u64::MAX)
    );
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 0);
}

#[tokio::test]
async fn test_app_owed_call_failing_for_good_holds_the_later_ones() {
    // Switch spec 8.3: every notice the protocol can't take yet is kept in feed order, and
    // the read hands nothing after it. The host is told after a few reads.
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.note(app.app_id(), "first");
    app.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    let stuck = w.switch.push_missed(1, now - HOUR, now);
    w.protocol.failing_missed.lock().unwrap().push(stuck);
    let later = w.switch.push_missed(2, now - HOUR, now);
    // The first call fails: owed, and the page stops after it.
    assert!(app.receive(None).await.unwrap().stopped);
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 1);
    let mut events = Vec::new();
    for _ in 0..3 {
        let report = app.receive(None).await.unwrap();
        assert!(report.stopped);
        events.extend(report.events);
    }
    assert!(w.protocol.missed.lock().unwrap().is_empty());
    assert!(
        has(&events, |e| matches!(e, AppEvent::OwedCallHeld { .. })),
        "{events:?}"
    );
    // Once the protocol takes it, the later one goes too, in order.
    w.protocol.failing_missed.lock().unwrap().clear();
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    let seqs: Vec<u64> = w
        .protocol
        .missed
        .lock()
        .unwrap()
        .iter()
        .map(|m| m.seq)
        .collect();
    assert_eq!(seqs, vec![stuck, later]);
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 0);
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
    let backup = app.backup().await.unwrap();
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
    let backup = app.backup().await.unwrap();
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
async fn test_app_restore_in_place_leaves_behind_an_owed_call_that_isnt_whole() {
    // Owed calls that decode but fail the queue's own checks, a key naming no feed
    // position and a change not checked yet whose operation doesn't parse, would fail
    // every read: a restore in place doesn't carry them, says so, and the store reads.
    let w = World::new();
    let mut app = w.join("wallet").await;
    let backup = app.backup().await.unwrap();
    app.receive(None).await.unwrap();
    let missed = crate::app::feed::OwedCall::Missed {
        seq: 1,
        entries: 1,
        accepted_from_ms: 5,
        accepted_until_ms: 6,
    };
    let unchecked = crate::app::feed::OwedCall::DenyUnverified {
        generation: 1,
        seq: 1,
        pubky: [7; 32],
        added: true,
        at_ms: 5,
        op: pubky_switch_core::sig::SignedDoc {
            body: "not an operation".into(),
            sig: String::new(),
        },
    };
    let mut tx = app.tx().unwrap();
    tx.put(
        &format!("{}not-a-position", crate::app::state::key::OWED_PREFIX),
        &missed,
    )
    .unwrap();
    tx.put(&crate::app::state::key::owed(1, 1), &unchecked)
        .unwrap();
    app.commit(tx).await.unwrap();
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 2);
    drop(app);
    let mut restored = App::restore(w.env(), w.protocol.clone(), World::config(), &backup)
        .await
        .unwrap();
    let events = restored.take_events();
    assert!(
        has(&events, |e| e.is_duty()
            && matches!(
                e,
                AppEvent::RestoreLeftBehind { owed_calls: 2, .. }
            )),
        "{events:?}"
    );
    assert_eq!(restored.owed_protocol_calls().await.unwrap(), 0);
    restored.end_reconcile(UserConfirmed::new()).await.ok();
    restored.receive(None).await.unwrap();
    assert!(w.protocol.missed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_app_restore_in_place_over_a_damaged_epoch_starts_a_new_one() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let backup = app.backup().await.unwrap();
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
    let stored_id = report
        .events
        .iter()
        .find_map(|e| match e {
            AppEvent::Parked {
                id: None,
                seq,
                stored_id,
                reason: ParkReason::Unverifiable,
            } if *seq == held => Some(*stored_id),
            _ => None,
        })
        .unwrap();
    // The event names the entry by its local ID, the key it is stored under.
    assert_eq!(wallet.stored_id_at(held), Some(stored_id));
    assert!(wallet.cursor().seq >= later);
    assert_eq!(w.effects(), 0, "{:?}", report.events);
    // Once the sender can be checked, it is applied.
    w.homeserver.set_down(false);
    let report = wallet.receive(None).await.unwrap();
    assert!(has(
        &report.events,
        |e| matches!(e, AppEvent::Unparked { seq, stored_id: s } if *seq == held && *s == stored_id)
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
        AppEvent::Parked { id: None, seq: s, reason: ParkReason::Quota, .. } if *s == seq
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
async fn test_feed_page_without_items_is_refused_and_moves_nothing() {
    // Read as an empty page scanned through `next`, a page without `items` would pass over
    // an entry unseen, since entries aren't chained, and would stop the app on a rollback
    // alarm when it skips a chain item. So the page is refused, and nothing moves.
    let w = World::new();
    let mut app = w.join("wallet").await;
    app.receive(None).await.unwrap();
    let leave_out_items = || {
        w.switch.fail_next(Fault::LeaveOut {
            path: "feed".into(),
            member: "items".into(),
        });
    };
    let refused = |error: AppError| {
        assert!(
            matches!(error, AppError::Switch(ClientError::InvalidResponse(_))),
            "{error:?}"
        );
    };
    // An entry.
    let before = app.cursor();
    let (seq, _) = w.note(app.app_id(), "kept");
    leave_out_items();
    refused(app.receive(None).await.unwrap_err());
    assert_eq!(app.cursor(), before);
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    // A chain item.
    let before = app.cursor();
    w.next_doc(|_| {});
    leave_out_items();
    refused(app.receive(None).await.unwrap_err());
    assert_eq!(app.cursor(), before);
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().seq, w.switch.tip_seq());
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

/// A restore from a backup older than a renewal the other device of the app took and
/// delivered: the renewal's `cert.put` is a stub by then, carried by the app's record, and
/// the backup's `identity.json` lists the earlier certificate. The restored app learns the
/// listed one from the current `identity.json` and its own record in the directory, and
/// takes it at its first read (Switch spec 3.2 step 3, 12.4 step 1).
#[tokio::test]
async fn test_app_restore_takes_a_renewal_another_device_took() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let backup = app.backup().await.unwrap();
    let earlier = app.cert().clone();
    w.clock.advance_ms(HOUR);
    renew_listed(&w, &app);
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let renewed = app.cert().clone();
    assert_ne!(renewed.hash(), earlier.hash());
    assert_eq!(
        w.switch.app(&me).cert.map(|c| c.hash()),
        Some(renewed.hash())
    );
    drop(app);
    let (mut restored, _) = restored(&w, &backup).await;
    assert_eq!(restored.cert().hash(), earlier.hash());
    let report = restored.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::CertificateTaken { .. }
        )),
        "{:?}",
        report.events
    );
    assert_eq!(restored.cert().hash(), renewed.hash());
    assert_eq!(
        restored.own_identity().listed_cert(&me),
        Some(renewed.hash())
    );
}

/// The failure path: the current `identity.json` lists a newer renewal while the one the
/// other device took is still open, so the own record in the directory carries a
/// certificate that isn't the listed one, and the cert.put of the listed one never came.
/// The restored app takes neither: not the record's, which isn't listed, nor the listed
/// one, which nothing shows it.
#[tokio::test]
async fn test_app_restore_takes_no_listed_certificate_it_cant_verify() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let backup = app.backup().await.unwrap();
    let earlier = app.cert().clone();
    w.clock.advance_ms(HOUR);
    renew_listed(&w, &app);
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    let renewed = app.cert().clone();
    assert_ne!(renewed.hash(), earlier.hash());
    let unshown = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms() + 1000,
        &["scope-a"],
    );
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.apps.push(ListedApp {
            app_id: me,
            cert: unshown.hash(),
        });
        body.renewed.push(RenewedCert {
            app_id: me,
            cert: renewed.hash(),
            until: None,
        });
    });
    drop(app);
    let (mut restored, _) = restored(&w, &backup).await;
    let report = restored.receive(None).await.unwrap();
    assert!(
        !has(&report.events, |e| matches!(
            e,
            AppEvent::CertificateTaken { .. }
        )),
        "{:?}",
        report.events
    );
    assert_eq!(restored.cert().hash(), earlier.hash());
    assert_eq!(
        restored.own_identity().listed_cert(&me),
        Some(unshown.hash()),
        "the newest document was read"
    );
}

/// The directory's newer document removes the app: the restored read stops there, and
/// neither checks its receive key nor registers one at this switch.
#[tokio::test]
async fn test_app_restore_removed_by_a_newer_document_registers_nothing() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let backup = backup_then_rotate(&w, &mut app).await;
    drop(app);
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from: START,
        });
    });
    let applied = w.switch.applied().len();
    let (mut restored, _) = restored(&w, &backup).await;
    let report = restored.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(
        has(&report.events, |e| matches!(e, AppEvent::Removed)),
        "{:?}",
        report.events
    );
    assert_eq!(w.switch.applied().len(), applied, "nothing registered");
}

/// The restore's directory read brings a newer document naming the next generation:
/// `take_listed_cert` takes it and reports the app not current here, before the restore's
/// key check, which would register a key at the generation the app leaves. A read follows
/// the change at its start (`follow_provider_change`) before it gets here; this is the
/// guard for a document that arrives between the two.
#[tokio::test]
async fn test_app_restore_listed_cert_stops_at_a_newer_generation() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let backup = backup_then_rotate(&w, &mut app).await;
    drop(app);
    let mut body = w.switch.identity_doc().unwrap().body().clone();
    body.version += 1;
    body.generation += 1;
    let doc = IdentityDoc::sign(&w.alice, body).unwrap();
    w.switch.deliver_identity(&doc).unwrap();
    let (mut restored, _) = restored(&w, &backup).await;
    let applied = w.switch.applied().len();
    assert!(matches!(
        restored.take_listed_cert().await.unwrap(),
        crate::app::renewal::Listed::NotCurrentHere
    ));
    assert_eq!(restored.own_identity().generation(), 2);
    assert!(restored.not_current_here().is_some());
    assert_eq!(w.switch.applied().len(), applied, "nothing registered");
}

/// A listed certificate that isn't a renewal of the one held, an earlier one, isn't taken.
#[tokio::test]
async fn test_app_restore_takes_no_listed_certificate_older_than_its_own() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let first = app.cert().clone();
    let before = w.switch.app(&me);
    w.clock.advance_ms(HOUR);
    renew_listed(&w, &app);
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    let renewed = app.cert().clone();
    assert_ne!(renewed.hash(), first.hash());
    let backup = app.backup().await.unwrap();
    drop(app);
    // The switch holds the first certificate's record again, and a newer document lists it.
    {
        let mut inner = w.switch.lock();
        let held = inner.apps.get_mut(&me).unwrap();
        held.record = before.record.clone();
        held.cert = before.cert.clone();
        held.renewed = None;
    }
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.apps.push(ListedApp {
            app_id: me,
            cert: first.hash(),
        });
        body.renewed.clear();
    });
    let (mut restored, _) = restored(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(restored.own_identity().listed_cert(&me), Some(first.hash()));
    assert_eq!(restored.cert().hash(), renewed.hash());
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

/// A batch writing a conversation entry for `pubky`.
fn conversation(pubky: [u8; 32]) -> crate::app::OpBatch {
    crate::app::OpBatch::new().op(OpKind::AllowPut {
        pubky,
        kind: pubky_switch_core::ops::AllowKind::Conversation,
    })
}

#[tokio::test]
async fn test_kept_batch_window_holds_with_the_device_clock_ahead_after_a_restore() {
    let w = World::new();
    let a = w.join("wallet").await;
    let backup = a.backup().await.unwrap();
    drop(a);
    // Restored on a device whose clock reads two hours ahead: it holds no service time.
    let clock = Arc::new(TestClock::new(w.clock.now_ms() + 2 * HOUR));
    let store_b = Arc::new(MemoryStore::new());
    let mut env = w.env_on(Arc::clone(&store_b) as Arc<dyn StateStore>);
    env.clock = Arc::clone(&clock) as Arc<dyn Clock>;
    let mut b = App::restore(env, w.protocol.clone(), World::config(), &backup)
        .await
        .unwrap();
    // Its first call keeps a batch, which is applied and its answer lost. (A first try
    // may be answered `401 stale_timestamp`, the device clock ahead, before the lost one.)
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(b.submit_batch(conversation(w.bob.public())).await.is_err());
    w.switch.lock().faults.clear();
    let kept = b.kept_batches().await.unwrap();
    assert_eq!(kept.len(), 1);
    // Kept in service time, not at the device's.
    assert!(kept[0].1.kept_ms.unwrap() <= w.clock.now_ms());
    // 30 days and half an hour on, the clock set right: the proofs are gone, and a resend
    // would be answered `409 conflict`.
    w.clock.advance_ms(30 * 24 * HOUR + HOUR / 2);
    clock.set_ms(w.clock.now_ms());
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!(null),
    });
    let _ = b.submit_batch(conversation([7; 32])).await;
    let events = b.unacknowledged_events().await.unwrap();
    // Past the window: dropped unsent, never read as refused.
    assert!(
        has(&events, |e| matches!(e, AppEvent::KeptBatchDropped { .. })),
        "{events:?}"
    );
    assert!(
        !has(&events, |e| matches!(e, AppEvent::BatchRefused { .. })),
        "{events:?}"
    );
}

/// How many conversation entries for `pubky` the switch applied.
fn conversations_for(w: &World, pubky: [u8; 32]) -> usize {
    w.switch
        .applied()
        .iter()
        .filter(|op| matches!(op.body().kind, OpKind::AllowPut { pubky: p, .. } if p == pubky))
        .count()
}

/// A write while the service can't be reached: kept, never sent.
async fn write_offline(w: &World, app: &mut App) {
    w.switch.fail_next(Fault::Unreachable {
        path: "feed".into(),
        after: 0,
    });
    w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let error = app
        .submit_batch(conversation(w.bob.public()))
        .await
        .unwrap_err();
    assert!(
        matches!(error.unkept(), AppError::Transport(_)),
        "{error:?}"
    );
    w.switch.lock().faults.clear();
    let kept = app.kept_batches().await.unwrap();
    assert_eq!(kept.len(), 1, "a network failure keeps the batch");
    assert_eq!(
        error.kept_batch(),
        Some(kept[0].0),
        "the error names it kept"
    );
    assert_eq!(kept[0].1.kept_ms, None, "never sent, so not stamped");
    assert_eq!(conversations_for(w, w.bob.public()), 0);
}

#[tokio::test]
async fn test_submit_batch_lost_answer_says_the_batch_is_kept() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    let error = app
        .submit_batch(conversation(w.bob.public()))
        .await
        .unwrap_err();
    let kept = app.kept_batches().await.unwrap();
    assert_eq!(kept.len(), 1);
    let AppError::Kept {
        batch_id,
        error: inner,
    } = &error
    else {
        panic!("the call's own batch is kept: {error:?}");
    };
    assert_eq!(*batch_id, kept[0].0);
    assert!(matches!(**inner, AppError::Transport(_)), "{inner:?}");
    // A `503` answer keeps it the same way, and its code shows through.
    let mut app = w.join("phone").await;
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    let error = app.submit_batch(conversation([7; 32])).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Unavailable));
    assert_eq!(
        error.kept_batch(),
        Some(app.kept_batches().await.unwrap()[0].0)
    );
}

#[tokio::test]
async fn test_submit_batch_behind_an_unsent_kept_batch_keeps_nothing_of_its_own() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let first = app
        .submit_batch(conversation(w.bob.public()))
        .await
        .unwrap_err();
    let kept = app.kept_batches().await.unwrap();
    assert_eq!(first.kept_batch(), Some(kept[0].0));
    // The kept batch still can't be sent: the next call fails before its own batch is
    // signed, naming the kept batch ahead, with the bare error inside, and keeps nothing of
    // its own.
    w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let second = app.submit_batch(conversation([7; 32])).await.unwrap_err();
    assert!(
        matches!(&second, AppError::Ahead { ahead, .. } if ahead.batch_id == kept[0].0),
        "{second:?}"
    );
    assert!(
        matches!(second.unkept(), AppError::Transport(_)),
        "{second:?}"
    );
    assert_eq!(second.kept_batch(), None);
    let ids = |kept: &[([u8; 16], crate::app::batch::PendingBatch)]| {
        kept.iter().map(|(id, _)| *id).collect::<Vec<_>>()
    };
    assert_eq!(ids(&app.kept_batches().await.unwrap()), ids(&kept));
    // A refusal for good keeps nothing either, and says so.
    let mut phone = w.join("phone").await;
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!(null),
    });
    let refused = phone.submit_batch(conversation([8; 32])).await.unwrap_err();
    assert_eq!(refused.code(), Some(ErrorCode::Conflict));
    assert_eq!(refused.kept_batch(), None);
    assert!(phone.kept_batches().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_receive_sends_a_kept_batch_before_the_feed() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(
        app.submit_batch(conversation(w.bob.public()))
            .await
            .is_err()
    );
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
    // The feed can't be read past the service time the resend is judged at, but the kept
    // batch went first: its original proof came back and settled it, applied once.
    w.switch.fail_next(Fault::Unreachable {
        path: "feed".into(),
        after: 1,
    });
    assert!(app.receive(None).await.is_err());
    w.switch.lock().faults.clear();
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(conversations_for(&w, w.bob.public()), 1);
    let report = app.receive(None).await.unwrap();
    assert!(
        !has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchesWaiting { .. }
        )),
        "{:?}",
        report.events
    );
    assert_eq!(conversations_for(&w, w.bob.public()), 1);
}

#[tokio::test]
async fn test_receive_goes_on_when_a_kept_batch_still_cant_be_sent() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.submit_batch(conversation([6; 32])).await.is_err());
    let (seq, _) = w.note(app.app_id(), "after");
    // The resend doesn't reach the switch: the read goes on to the feed, reports the
    // batch waiting, and keeps it.
    w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    let report = app.receive(None).await.unwrap();
    w.switch.lock().faults.clear();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchesWaiting {
                kept: 1,
                code: None
            }
        )),
        "{:?}",
        report.events
    );
    assert!(report.cursor.seq >= seq, "the feed was read");
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
    // The feed showed the operation applied; the kept copy is cleared by the next read's
    // resend, which the switch answers with the original proof.
    let report = app.receive(None).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert!(
        !has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchesWaiting { .. }
        )),
        "{:?}",
        report.events
    );
    assert_eq!(conversations_for(&w, [6; 32]), 1);
    // A `503` on the resend is reported with its code.
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.submit_batch(conversation([7; 32])).await.is_err());
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Unavailable,
        current: json!(null),
    });
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchesWaiting { kept: 1, code: Some(code) } if code == "unavailable"
        )),
        "{:?}",
        report.events
    );
}

#[tokio::test]
async fn test_receive_sends_no_batch_refused_for_good() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!(null),
    });
    assert!(
        app.submit_batch(conversation(w.bob.public()))
            .await
            .is_err()
    );
    // Refused for good on its first send: not kept, so no read sends it.
    assert!(app.kept_batches().await.unwrap().is_empty());
    let report = app.receive(None).await.unwrap();
    assert!(!has(&report.events, |e| matches!(
        e,
        AppEvent::KeptBatchesWaiting { .. } | AppEvent::BatchRefused { .. }
    )));
    assert_eq!(conversations_for(&w, w.bob.public()), 0);
}

/// The signer renews the app's certificate and lists the renewal (Switch spec 3.2 steps 1
/// and 2).
pub(super) fn renew_listed(w: &World, app: &App) -> pubky_switch_core::records::AppCert {
    let me = app.app_id();
    let old = app.cert().clone();
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
    renewed
}

/// A write while the certificate is expired: the batch is signed and kept, then the
/// service time read before its first send is refused (`403 cert_expired`), so it was
/// never sent. It stays kept, and the error says so; after the renewal a read sends it.
#[tokio::test]
async fn test_kept_batch_refused_before_its_first_send_says_it_is_kept() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.clock.set_ms(app.cert().expires_at() + 1);
    let error = app
        .submit_batch(conversation(w.bob.public()))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::CertExpired), "{error:?}");
    let kept = app.kept_batches().await.unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].1.kept_ms, None, "never sent");
    assert_eq!(error.kept_batch(), Some(kept[0].0), "{error:?}");
    renew_listed(&w, &app);
    for _ in 0..2 {
        let _ = app.receive(None).await;
    }
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(conversations_for(&w, w.bob.public()), 1);
}

#[tokio::test]
async fn test_kept_batch_written_offline_goes_once_the_service_is_back() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    w.clock.advance_ms(20 * 60 * 1000);
    write_offline(&w, &mut app).await;
    // The next write sends it first, as its first send: applied once.
    app.submit_batch(conversation([7; 32])).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(conversations_for(&w, w.bob.public()), 1);
    assert_eq!(conversations_for(&w, [7; 32]), 1);
}

#[tokio::test]
async fn test_kept_batch_written_offline_survives_a_restart_unsent() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    w.clock.advance_ms(20 * 60 * 1000);
    write_offline(&w, &mut app).await;
    drop(app);
    // Loaded again a month on: still unsent, with no window, so not judged for age.
    w.clock.advance_ms(31 * 24 * HOUR);
    let mut app = w.load(me).await;
    assert_eq!(app.kept_batches().await.unwrap()[0].1.kept_ms, None);
    app.submit_batch(conversation([7; 32])).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(conversations_for(&w, w.bob.public()), 1);
    assert!(!has(
        &app.unacknowledged_events().await.unwrap(),
        |e| matches!(e, AppEvent::KeptBatchDropped { .. })
    ));
}

#[tokio::test]
async fn test_parked_retry_effect_is_kept_at_a_fresh_service_time() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let (seq, _) = w.note(app.app_id(), "note");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::QuotaExceeded,
        current: json!(null),
    });
    app.receive(None).await.unwrap();
    assert_eq!(
        app.stored_at(seq).map(|p| p.reason),
        Some(ParkReason::Quota)
    );
    // A month on, the stored entry is tried again before any feed read, and its effect
    // kept: at a service time read in this call, not the month-old one.
    w.clock.advance_ms(30 * 24 * HOUR);
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    let _ = app.receive(None).await;
    let pending = app.state.pending_effect.as_ref().unwrap();
    assert_eq!(pending.seq, seq);
    let age = w.clock.now_ms() - pending.kept_ms.unwrap();
    assert!(age < HOUR, "kept {age} ms before now");
}

#[tokio::test]
async fn test_kept_batch_window_holds_with_the_device_clock_behind_at_the_resend() {
    let w = World::new();
    let (mut app, clock) = app_with_its_own_clock(&w, 0).await;
    let me = app.app_id();
    // Applied, its answer lost: kept.
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(
        app.submit_batch(conversation(w.bob.public()))
            .await
            .is_err()
    );
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
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
    // The next write sends the kept batch again first: a service time read before it shows
    // it past the window, so it is dropped unsent, never read as refused.
    let _ = app.submit_batch(conversation([7; 32])).await;
    let events = app.unacknowledged_events().await.unwrap();
    assert!(
        has(&events, |e| matches!(e, AppEvent::KeptBatchDropped { .. })),
        "{events:?}"
    );
    assert!(
        !has(&events, |e| matches!(e, AppEvent::BatchRefused { .. })),
        "{events:?}"
    );
}

#[tokio::test]
async fn test_kept_batch_kept_after_an_idle_month_is_resent_after_a_lost_answer() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    // Idle for 30 days, the device clock and the service's agreeing: the service time the
    // app holds is a month old.
    w.clock.advance_ms(30 * 24 * HOUR);
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(
        app.submit_batch(conversation(w.bob.public()))
            .await
            .is_err()
    );
    let kept = app.kept_batches().await.unwrap();
    assert_eq!(kept.len(), 1);
    // Kept at the service time of this call, not the month-old one.
    assert!(w.clock.now_ms() - kept[0].1.kept_ms.unwrap() < HOUR);
    // A minute later the app writes again: the kept batch goes again, and its proofs show
    // it applied; it isn't dropped.
    w.clock.advance_ms(60_000);
    app.submit_batch(conversation([7; 32])).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    let events = app.unacknowledged_events().await.unwrap();
    assert!(
        !has(&events, |e| matches!(e, AppEvent::KeptBatchDropped { .. })),
        "{events:?}"
    );
}

#[tokio::test]
async fn test_kept_batch_past_the_window_by_the_device_clock_goes_without_a_read() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let (seq, _) = w.note(app.app_id(), "before");
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(
        app.submit_batch(conversation(w.bob.public()))
            .await
            .is_err()
    );
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
    // Past the window by the device clock alone, with no feed read to be had: the kept
    // effect and batch are judged without one.
    w.clock.advance_ms(31 * 24 * HOUR);
    for _ in 0..4 {
        w.switch.fail_next(Fault::Unreachable {
            path: "feed".into(),
            after: 0,
        });
    }
    let _ = app.receive(None).await;
    assert_eq!(
        app.stored_at(seq).map(|p| p.reason),
        Some(ParkReason::Uncertain)
    );
    let _ = app.submit_batch(conversation([7; 32])).await;
    w.switch.lock().faults.clear();
    assert!(has(&app.kept_duties().await.unwrap(), |e| matches!(
        e,
        AppEvent::KeptBatchDropped { .. }
    )));
}

#[tokio::test]
async fn test_fresh_service_time_is_read_again_once_it_has_aged() {
    let w = World::new();
    let (mut app, clock) = app_with_its_own_clock(&w, 0).await;
    app.receive(None).await.unwrap();
    let read_at = app.time_fresh_at.unwrap();
    // Within the bound, the time read in the call counts.
    clock.advance_ms(crate::app::provider::FRESH_SERVICE_TIME_MS);
    app.fresh_service_time().await.unwrap();
    assert_eq!(app.time_fresh_at, Some(read_at));
    // Past it, by the device clock, it is read again.
    clock.advance_ms(1);
    app.fresh_service_time().await.unwrap();
    assert_eq!(app.time_fresh_at, Some(clock.now_ms()));
    // A device clock gone back since counts as not fresh either.
    let again = clock.now_ms();
    clock.set_ms(again - 60_000);
    app.fresh_service_time().await.unwrap();
    assert_eq!(app.time_fresh_at, Some(again - 60_000));
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

/// The app layer's own lifecycle operations, and the signer's, for `app`.
fn lifecycle_ops(w: &World, app: &App) -> Vec<OpKind> {
    let has_keys = |s: &str| SampleProtocol::default().has_keys(s);
    let epoch = w.switch.identity_doc().unwrap().data_epoch();
    let part = seal_bundle_parts(&w.alice, app.cert(), 1, epoch, &has_keys)
        .unwrap()
        .remove(0);
    vec![
        OpKind::AppPut {
            record: app.record().clone(),
        },
        OpKind::ReceiveKeyPut {
            record: app
                .state
                .receive_keys
                .values()
                .next()
                .unwrap()
                .record
                .clone(),
        },
        OpKind::KeyBundlePut(KeyBundlePut {
            target_app_id: app.app_id(),
            bundle: part.bundle,
            first_epoch: part.first_epoch,
            last_epoch: part.last_epoch,
        }),
        OpKind::CertPut {
            target_app_id: app.app_id(),
            cert: app.cert().signed().clone(),
        },
    ]
}

#[tokio::test]
async fn test_app_refuses_lifecycle_operations_in_a_host_batch() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let applied = w.switch.applied().len();
    for kind in lifecycle_ops(&w, &app) {
        let error = app
            .submit_batch(crate::app::OpBatch::new().op(kind.clone()))
            .await
            .unwrap_err();
        assert!(
            matches!(error, AppError::Refused(Refusal::Usage(_))),
            "{kind:?}: {error:?}"
        );
        // Refused before anything is kept or sent.
        assert!(app.kept_batches().await.unwrap().is_empty());
        assert_eq!(w.switch.applied().len(), applied);
    }
    // A batch of the host's own writes still goes.
    app.submit_batch(crate::app::OpBatch::new().op(OpKind::AllowPut {
        pubky: w.bob.public(),
        kind: pubky_switch_core::ops::AllowKind::Conversation,
    }))
    .await
    .unwrap();
    assert_eq!(w.switch.applied().len(), applied + 1);
}

/// The sample protocol, whose effect for a note also carries `extra`, through the context
/// or in the effect itself, recording what the context answered.
struct LifecycleProtocol {
    sample: SampleProtocol,
    extra: OpKind,
    in_context: bool,
    answers: std::sync::Mutex<Vec<bool>>,
    /// Whether the effects carry `extra` yet.
    active: std::sync::atomic::AtomicBool,
}

impl Protocol for LifecycleProtocol {
    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &pubky_switch_core::message::Message,
        sender: &pubky_switch_core::records::AppCert,
        own: &pubky_switch_core::records::AppCert,
    ) -> Result<(), String> {
        self.sample.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &pubky_switch_core::records::AppCert) -> Vec<String> {
        self.sample.accepts(cert)
    }

    fn check_body(&self, message: &crate::app::ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(message)
    }

    fn receive_with(
        &self,
        message: &crate::app::ReceivedMessage,
        cx: &mut crate::app::ReceiveContext<'_>,
    ) -> crate::app::Outcome {
        if !self.active.load(std::sync::atomic::Ordering::SeqCst) {
            return self.sample.receive(message);
        }
        if self.in_context {
            let answer = cx.op(Vec::new(), self.extra.clone());
            self.answers.lock().unwrap().push(answer.is_ok());
            return self.sample.receive(message);
        }
        match self.sample.receive(message) {
            crate::app::Outcome::Apply(mut effect) => {
                effect.ops.push((Vec::new(), self.extra.clone()));
                crate::app::Outcome::Apply(effect)
            }
            other => other,
        }
    }

    fn resend_needed(
        &self,
        needed: &crate::app::ResendNeeded,
    ) -> Result<Vec<crate::app::LocalWrite>, crate::app::StoreFailure> {
        self.sample.resend_needed(needed)
    }

    fn missed(
        &self,
        missed: &crate::app::MissedEntries,
    ) -> Result<Vec<crate::app::LocalWrite>, crate::app::StoreFailure> {
        self.sample.missed(missed)
    }
}

/// The entry at `seq` stored for good for a lifecycle operation in its effect, and the
/// protocol told in `report`, durably.
async fn lifecycle_effect_refused(app: &mut App, report: &crate::app::ReceiveReport, seq: u64) {
    assert_eq!(
        app.stored_at(seq).map(|p| p.reason),
        Some(ParkReason::LifecycleOperation)
    );
    assert!(app.state.pending_effect.is_none());
    let refused =
        |e: &AppEvent| matches!(e, AppEvent::EffectRefused { seq: s, code: None, .. } if *s == seq);
    assert!(has(&report.events, refused), "{:?}", report.events);
    assert!(has(&app.unacknowledged_events().await.unwrap(), refused));
}

#[tokio::test]
async fn test_app_lifecycle_operation_in_an_effect_doesnt_stall_the_feed() {
    let w = World::new();
    let base = w.join("phone").await;
    let protocol = Arc::new(LifecycleProtocol {
        sample: SampleProtocol::default(),
        extra: lifecycle_ops(&w, &base)[0].clone(),
        in_context: false,
        answers: std::sync::Mutex::new(Vec::new()),
        active: std::sync::atomic::AtomicBool::new(true),
    });
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let mut app = App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap();
    let (first, _) = w.note(app.app_id(), "note");
    let report = app.receive(None).await.unwrap();
    lifecycle_effect_refused(&mut app, &report, first).await;
    // Later entries go on, and the stored one isn't tried again.
    let (second, _) = w.note(app.app_id(), "later note");
    let report = app.receive(None).await.unwrap();
    assert!(app.cursor().seq >= second);
    assert!(
        !has(&report.events, |e| matches!(e, AppEvent::Unparked { .. })),
        "{:?}",
        report.events
    );
}

#[tokio::test]
async fn test_app_lifecycle_operation_in_a_stored_entrys_effect_stores_it_for_good() {
    let w = World::new();
    let base = w.join("phone").await;
    let protocol = Arc::new(LifecycleProtocol {
        sample: SampleProtocol::default(),
        extra: lifecycle_ops(&w, &base)[1].clone(),
        in_context: false,
        answers: std::sync::Mutex::new(Vec::new()),
        active: std::sync::atomic::AtomicBool::new(false),
    });
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let mut app = App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap();
    // Stored for a quota, to be tried again.
    let (seq, _) = w.note(app.app_id(), "note");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::QuotaExceeded,
        current: json!(null),
    });
    app.receive(None).await.unwrap();
    assert_eq!(
        app.stored_at(seq).map(|p| p.reason),
        Some(ParkReason::Quota)
    );
    // Tried again, its effect now carries a lifecycle operation: stored for good, and the
    // protocol told; the read goes on.
    protocol
        .active
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let applied = w.switch.applied().len();
    let report = app.receive(None).await.unwrap();
    lifecycle_effect_refused(&mut app, &report, seq).await;
    assert_eq!(w.switch.applied().len(), applied);
}

#[tokio::test]
async fn test_app_entry_stored_for_good_drops_its_retry_count() {
    let w = World::new();
    let base = w.join("phone").await;
    let protocol = Arc::new(LifecycleProtocol {
        sample: SampleProtocol::default(),
        extra: lifecycle_ops(&w, &base)[0].clone(),
        in_context: false,
        answers: std::sync::Mutex::new(Vec::new()),
        active: std::sync::atomic::AtomicBool::new(true),
    });
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let mut app = App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap();
    let (seq, _) = w.note(app.app_id(), "note");
    // Its receive step had been retried for the store before.
    let retry = crate::app::state::RetryEntry {
        reads: 1,
        since_ms: w.clock.now_ms(),
    };
    let mut tx = app.tx().unwrap();
    tx.put(&crate::app::state::key::retry(seq), &retry).unwrap();
    app.commit(tx).await.unwrap();
    app.state.retries.insert(seq, retry);
    // Stored for good, its effect carrying a lifecycle operation: the count goes with it.
    let report = app.receive(None).await.unwrap();
    lifecycle_effect_refused(&mut app, &report, seq).await;
    assert!(app.no_retries(), "{:?}", app.state.retries);
    let loaded = w.load(app.app_id()).await;
    assert!(loaded.no_retries(), "and in the store");
}

#[tokio::test]
async fn test_app_refuses_lifecycle_operations_in_a_protocol_effect() {
    let probe = World::new();
    let probe_app = probe.join("wallet").await;
    let kinds = lifecycle_ops(&probe, &probe_app);
    for (index, _) in kinds.iter().enumerate() {
        for in_context in [true, false] {
            let w = World::new();
            let base = w.join("phone").await;
            let extra = lifecycle_ops(&w, &base)[index].clone();
            let protocol = Arc::new(LifecycleProtocol {
                sample: SampleProtocol::default(),
                extra,
                in_context,
                answers: std::sync::Mutex::new(Vec::new()),
                active: std::sync::atomic::AtomicBool::new(true),
            });
            let request = w.approve(&app_keys("wallet"), &["scope-a"]);
            let mut app = App::join(w.env(), protocol.clone(), World::config(), request)
                .await
                .unwrap();
            let (seq, _) = w.note(app.app_id(), "note");
            let applied = w.switch.applied().len();
            let report = app.receive(None).await.unwrap();
            if in_context {
                // The context refuses it; the effect goes without it.
                assert_eq!(*protocol.answers.lock().unwrap(), vec![false]);
                assert!(received(&report.events, seq), "{:?}", report.events);
            } else {
                // In the effect itself: never sent, the entry stored and passed, and the
                // protocol told, so the feed goes on (Switch spec 8.2).
                lifecycle_effect_refused(&mut app, &report, seq).await;
                assert_eq!(w.switch.applied().len(), applied, "{index}");
                assert!(app.cursor().seq >= seq);
            }
        }
    }
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

/// The signer stores `me`'s key bundle part over `first`..=`last` at the scripted switch,
/// through its batch path: the `seq` it takes.
fn store_part(w: &World, me: [u8; 16], cert: &AppCert, first: u64, last: u64) -> u64 {
    let has_keys = |s: &str| SampleProtocol::default().has_keys(s);
    let mut seq = 0;
    for part in seal_bundle_parts(&w.alice, cert, first, last, &has_keys).unwrap() {
        seq = w
            .switch
            .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: me,
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
    }
    seq
}

#[tokio::test]
async fn test_app_restore_asks_again_for_a_full_bundle_a_later_part_left_short() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    // A new epoch whose part isn't stored: the app asks for a full bundle, and is backed up
    // while it waits. Then its device is lost.
    w.next_doc(|body| body.data_epoch = 3);
    let report = app.receive(None).await.unwrap();
    let asked = |events: &[AppEvent]| has(events, |e| matches!(e, AppEvent::FullBundleRequested));
    assert!(asked(&report.events), "{:?}", report.events);
    let backup = app.backup().await.unwrap();
    drop(app);
    // The signer answers in two parts, the second completing the request; then the switch
    // drops the first.
    store_part(&w, me, &cert, 1, 2);
    let completing = store_part(&w, me, &cert, 3, 3);
    assert_eq!(w.switch.app(&me).full_completed, Some(completing));
    w.switch
        .lock()
        .bundles
        .entry(me)
        .or_default()
        .retain(|(part, _)| part.first_epoch != 1);
    assert_eq!(w.switch.bundles_of(&me), vec![(3, 3)]);
    // The restored app holds the backup's request, and reads the part stored after it: the
    // request is answered, and the keys still lacking are asked for again.
    let (mut restored, _) = restored(&w, &backup).await;
    let report = restored.receive(None).await.unwrap();
    assert!(asked(&report.events), "{:?}", report.events);
    assert!(w.switch.app(&me).full_requested.is_some());
    assert!(restored.scope_key(3, "scope-a").is_some());
    assert_eq!(restored.keys_through(), 1);
    // Once per part stored: a read without one asks nothing more.
    let report = restored.receive(None).await.unwrap();
    assert!(!asked(&report.events), "{:?}", report.events);
    // The signer answers again, and the keys arrive.
    store_part(&w, me, &cert, 1, 2);
    restored.receive(None).await.unwrap();
    assert_eq!(restored.keys_through(), 3);
    assert_eq!(
        restored.scope_key(2, "scope-a"),
        Some(w.alice.scope_key(2, "scope-a"))
    );
}

/// The answer to a full-bundle request the backup holds was read by the device the backup
/// came from, which moved its cursor past it, so the switch dropped the parts and the
/// restored app's feed shows only their stubs. The restore drops the request: the first read
/// asks once, and no later read asks again while no part arrives.
#[tokio::test]
async fn test_app_restore_asks_again_for_a_full_bundle_read_and_dropped() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    w.next_doc(|body| body.data_epoch = 3);
    let report = app.receive(None).await.unwrap();
    let asked = |events: &[AppEvent]| {
        events
            .iter()
            .filter(|e| matches!(e, AppEvent::FullBundleRequested))
            .count()
    };
    assert_eq!(asked(&report.events), 1, "{:?}", report.events);
    let backup = app.backup().await.unwrap();
    store_part(&w, me, &cert, 1, 3);
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    assert_eq!(app.keys_through(), 3);
    store_part(&w, me, &cert, 3, 3);
    app.receive(None).await.unwrap();
    app.flush_cursor().await.unwrap();
    assert!(!w.switch.bundles_of(&me).contains(&(1, 3)), "dropped");
    drop(app);
    let (mut restored, _) = restored(&w, &backup).await;
    let mut events = restored.receive(None).await.unwrap().events;
    assert_eq!(asked(&events), 1, "{events:?}");
    assert!(w.switch.app(&me).full_requested.is_some());
    for _ in 0..2 {
        events = restored.receive(None).await.unwrap().events;
        assert_eq!(asked(&events), 0, "{events:?}");
    }
    store_part(&w, me, &cert, 1, 3);
    restored.receive(None).await.unwrap();
    assert_eq!(restored.keys_through(), 3);
}

// The scripted switch drops key bundle parts by the core's rule, as the service does (Switch
// wire 6.2): these mirror the service's tests of the same names in
// `crates/pubky-switch/tests/endpoints_keys.rs`.

#[tokio::test]
async fn test_scripted_keys_passed_parts_go_when_the_next_part_is_stored() {
    let w = World::new();
    let app = w.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    w.next_doc(|body| body.data_epoch = 2);
    // Epoch 1's part, passed before the switch dropped parts at cursor moves.
    let first = store_part(&w, me, &cert, 1, 1);
    w.switch.set_cursor_unchecked(me, first);
    assert_eq!(w.switch.bundles_of(&me), vec![(1, 1)]);
    // The next part stored: the passed part goes there.
    store_part(&w, me, &cert, 2, 2);
    assert_eq!(w.switch.bundles_of(&me), vec![(2, 2)]);
    assert_eq!(w.switch.keys_through_of(&me), Some(1));
}

#[tokio::test]
async fn test_scripted_keys_a_request_stays_in_force_until_the_completing_part_is_passed() {
    let w = World::new();
    let app = w.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    w.next_doc(|body| body.data_epoch = 3);
    // Asked for, then epoch 1's part passed: kept. Epoch 2's part completes the request.
    w.switch.request_full_bundle(me);
    let first = store_part(&w, me, &cert, 1, 1);
    w.switch.move_cursor(me, first).unwrap();
    let second = store_part(&w, me, &cert, 2, 2);
    // Not covered through epoch 3 yet: the request is still pending. Epoch 3's part
    // completes it.
    let third = store_part(&w, me, &cert, 3, 3);
    assert!(w.switch.app(&me).full_requested.is_none(), "covered");
    assert_eq!(w.switch.bundles_of(&me), vec![(1, 1), (2, 2), (3, 3)]);
    // The next put comes before the cursor passes the part that completed it: the request
    // is still in force, and nothing goes.
    store_part(&w, me, &cert, 4, 4);
    let all = vec![(1, 1), (2, 2), (3, 3), (4, 4)];
    assert_eq!(w.switch.bundles_of(&me), all);
    // A move short of the completing part keeps them too; the move that passes it ends the
    // request's force and drops the parts it passed and holds.
    w.switch.move_cursor(me, second).unwrap();
    assert_eq!(w.switch.bundles_of(&me), all);
    w.switch.move_cursor(me, third).unwrap();
    assert_eq!(w.switch.bundles_of(&me), vec![(4, 4)]);
    assert_eq!(w.switch.keys_through_of(&me), Some(3));
}

#[tokio::test]
async fn test_scripted_keys_a_part_replacing_the_completing_one_carries_the_force() {
    let w = World::new();
    let app = w.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    w.next_doc(|body| body.data_epoch = 2);
    w.switch.request_full_bundle(me);
    let first = store_part(&w, me, &cert, 1, 1);
    w.switch.move_cursor(me, first).unwrap();
    // Epoch 2's part completes the request; a part over epochs 2 and 3 replaces it while
    // the request is in force.
    let completing = store_part(&w, me, &cert, 2, 2);
    let replacing = store_part(&w, me, &cert, 2, 3);
    assert_eq!(w.switch.bundles_of(&me), vec![(1, 1), (2, 3)]);
    // Passing the completing item, now a stub, drops nothing: the force runs on to the part
    // that replaced it.
    w.switch.move_cursor(me, completing).unwrap();
    assert_eq!(w.switch.bundles_of(&me), vec![(1, 1), (2, 3)]);
    store_part(&w, me, &cert, 4, 4);
    assert_eq!(w.switch.bundles_of(&me), vec![(1, 1), (2, 3), (4, 4)]);
    // Passing the replacing part ends the force.
    w.switch.move_cursor(me, replacing).unwrap();
    assert_eq!(w.switch.bundles_of(&me), vec![(4, 4)]);
    assert_eq!(w.switch.keys_through_of(&me), Some(3));
}

#[tokio::test]
async fn test_scripted_keys_replacing_another_part_while_in_force_keeps_the_force_where_it_is() {
    let w = World::new();
    let app = w.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    w.next_doc(|body| body.data_epoch = 2);
    w.switch.request_full_bundle(me);
    let first = store_part(&w, me, &cert, 1, 1);
    w.switch.move_cursor(me, first).unwrap();
    // Epoch 2's part completes the request; a put replaces epoch 1's part, not the
    // completing one, so the force stays where it was.
    let completing = store_part(&w, me, &cert, 2, 2);
    store_part(&w, me, &cert, 1, 1);
    // The move that passes the completing part ends the force: it goes, and epoch 1's new
    // part, unpassed, stays.
    w.switch.move_cursor(me, completing).unwrap();
    assert_eq!(w.switch.bundles_of(&me), vec![(1, 1)]);
    assert_eq!(w.switch.keys_through_of(&me), Some(2));
}

#[tokio::test]
async fn test_scripted_keys_a_replacement_after_the_force_ended_doesnt_restart_it() {
    let w = World::new();
    let app = w.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    w.next_doc(|body| body.data_epoch = 3);
    w.switch.request_full_bundle(me);
    store_part(&w, me, &cert, 1, 1);
    store_part(&w, me, &cert, 2, 2);
    let completing = store_part(&w, me, &cert, 3, 3);
    // Epoch 2's part is replaced while in force. The move that passes the completing part
    // ends the force; that part stays, passed above epoch 2's unpassed one.
    let second = store_part(&w, me, &cert, 2, 2);
    w.switch.move_cursor(me, completing).unwrap();
    assert_eq!(w.switch.bundles_of(&me), vec![(2, 2), (3, 3)]);
    // Replacing the completing part now doesn't put the request back in force: the move
    // that passes epoch 2's part drops it.
    store_part(&w, me, &cert, 3, 3);
    w.switch.move_cursor(me, second).unwrap();
    assert_eq!(w.switch.bundles_of(&me), vec![(3, 3)]);
}

#[tokio::test]
async fn test_scripted_keys_a_request_stays_in_force_for_the_rest_of_the_completing_batch() {
    let w = World::new();
    let app = w.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    w.next_doc(|body| body.data_epoch = 2);
    w.switch.request_full_bundle(me);
    let first = store_part(&w, me, &cert, 1, 1);
    w.switch.move_cursor(me, first).unwrap();
    // The completing part and the next one in one batch.
    let has_keys = |s: &str| SampleProtocol::default().has_keys(s);
    let mut kinds = Vec::new();
    for (first_epoch, last_epoch) in [(2, 2), (3, 3)] {
        for part in seal_bundle_parts(&w.alice, &cert, first_epoch, last_epoch, &has_keys).unwrap()
        {
            kinds.push(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: me,
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }));
        }
    }
    w.switch.signer_batch(kinds).unwrap();
    assert_eq!(w.switch.bundles_of(&me), vec![(1, 1), (2, 2), (3, 3)]);
}

#[tokio::test]
async fn test_scripted_keys_a_part_passed_before_its_gap_goes_once_the_gap_is_filled() {
    let w = World::new();
    let app = w.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    assert_eq!(w.switch.keys_through_of(&me), Some(1));
    w.next_doc(|body| body.data_epoch = 3);
    // Epoch 3's part, passed: not covered while epoch 2's keys are missing, so it stays.
    let third = store_part(&w, me, &cert, 3, 3);
    w.switch.move_cursor(me, third).unwrap();
    assert_eq!(w.switch.bundles_of(&me), vec![(3, 3)]);
    assert_eq!(w.switch.keys_through_of(&me), Some(1));
    // Epoch 2's part fills the gap; once the cursor passes it too, both go, and
    // keys_through stays at 3 without them.
    let second = store_part(&w, me, &cert, 2, 2);
    assert_eq!(w.switch.bundles_of(&me), vec![(2, 2), (3, 3)]);
    w.switch.move_cursor(me, second).unwrap();
    assert_eq!(w.switch.bundles_of(&me), Vec::<(u64, u64)>::new());
    assert_eq!(w.switch.keys_through_of(&me), Some(3));
}

#[tokio::test]
async fn test_scripted_keys_keys_through_keeps_its_height_at_the_next_generation() {
    let w = World::new();
    let app = w.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    w.next_doc(|body| body.data_epoch = 2);
    // Both parts passed and dropped: where keys_through starts carries its height.
    let first = store_part(&w, me, &cert, 1, 1);
    let second = store_part(&w, me, &cert, 2, 2);
    w.switch.move_cursor(me, second.max(first)).unwrap();
    assert_eq!(w.switch.bundles_of(&me), Vec::<(u64, u64)>::new());
    assert_eq!(w.switch.keys_through_of(&me), Some(2));
    // A key change in place and an import keep it.
    assert_eq!(
        w.switch.change_key_into([7; 32]).keys_through_of(&me),
        Some(2)
    );
    assert_eq!(w.switch.import_into([8; 32]).keys_through_of(&me), Some(2));
}

#[tokio::test]
async fn test_scripted_keys_a_cursor_move_keeps_parts_while_a_full_bundle_is_requested() {
    let w = World::new();
    let app = w.join("wallet").await;
    let me = app.app_id();
    let cert = app.cert().clone();
    // At data epoch 2, epoch 1's part doesn't complete the request.
    w.next_doc(|body| body.data_epoch = 2);
    w.switch.request_full_bundle(me);
    let first = store_part(&w, me, &cert, 1, 1);
    w.switch.move_cursor(me, first).unwrap();
    assert!(w.switch.app(&me).full_requested.is_some());
    assert_eq!(w.switch.bundles_of(&me), vec![(1, 1)]);
}

#[tokio::test]
async fn test_app_keys_calls_without_a_record_are_not_current() {
    // An app listed but holding no record at the switch isn't current: its `GET` and `POST
    // /apps/{app_id}/keys` are refused `403 not_current`, as the service refuses them, and no
    // request for a full bundle is kept for it (Switch wire 7.2, 7.4.11).
    let w = World::new();
    let keys = app_keys("phone");
    let cert = cert_for(&w.alice, &keys, START, &["scope-a"]);
    w.next_doc(|body| {
        body.apps.push(ListedApp {
            app_id: cert.app_id(),
            cert: cert.hash(),
        })
    });
    let env = w.env();
    let client = crate::client::SwitchClient::new(
        w.signer.origin(),
        w.alice.public(),
        crate::client::Credentials::App {
            identity: w.alice.public(),
            keys: keys.clone(),
            cert,
        },
        Some(w.switch.service_key()),
        Arc::clone(&env.transport),
        Arc::clone(&env.clock),
    )
    .unwrap();
    let not_current = |error: ClientError| error.code() == Some(ErrorCode::NotCurrent);
    assert!(not_current(client.request_full_bundle().await.unwrap_err()));
    assert!(not_current(client.keys().await.unwrap_err()));
    assert!(w.switch.app(&keys.app_id_bytes()).full_requested.is_none());
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
    let backup = app.backup().await.unwrap();
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

/// A thief's registration of key `n`, signed with the app's signing key, at the switch.
fn thief_registers(w: &World, cert: &AppCert, n: u64) {
    let thief = ReceiveKey::from_secret(n, [47; 32]);
    let record =
        ReceiveKeyRecord::sign(&app_keys("wallet"), cert, ReceiveKeyBody::new(cert, &thief))
            .unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::ReceiveKeyPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
}

/// A restore whose key was current at its check asks about nothing after it: a later
/// registration no device made, read in the feed, is a compromise.
#[tokio::test]
async fn test_app_restore_with_its_key_current_takes_a_later_unknown_key_for_a_compromise() {
    let w = World::new();
    let app = w.join("wallet").await;
    let backup = app.backup().await.unwrap();
    let (mut restored, _) = restored(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert!(restored.restore_question().is_empty());
    w.clock.advance_ms(30 * 24 * HOUR);
    thief_registers(&w, &restored.cert().clone(), 1);
    let error = restored.receive(None).await.unwrap_err();
    assert!(
        matches!(error, AppError::Alarm(Alarm::Compromise { n: 1, .. })),
        "{error:?}"
    );
    assert!(restored.restore_question().is_empty());
}

/// The same through a registration conflict: the restored app rotates onto the number a
/// thief took.
#[tokio::test]
async fn test_app_restore_with_its_key_current_takes_a_later_conflict_for_a_compromise() {
    let w = World::new();
    let app = w.join("wallet").await;
    let backup = app.backup().await.unwrap();
    let (mut restored, _) = restored(&w, &backup).await;
    restored.receive(None).await.unwrap();
    w.clock.advance_ms(30 * 24 * HOUR);
    thief_registers(&w, &restored.cert().clone(), 1);
    let error = restored.rotate().await.unwrap_err();
    assert!(
        matches!(error, AppError::Alarm(Alarm::Compromise { n: 1, .. })),
        "{error:?}"
    );
}

/// A restore whose check registered a fresh key asks about what came before it, and takes
/// an unknown key above it for a compromise.
#[tokio::test]
async fn test_app_restore_takes_an_unknown_key_above_its_own_for_a_compromise() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let backup = backup_then_rotate(&w, &mut app).await;
    drop(app);
    let (mut restored, _) = restored(&w, &backup).await;
    restored.receive(None).await.unwrap();
    assert_eq!(restored.restore_question(), vec![1]);
    assert_eq!(restored.receive_key_numbers().last(), Some(&2));
    thief_registers(&w, &restored.cert().clone(), 3);
    let error = restored.receive(None).await.unwrap_err();
    assert!(
        matches!(error, AppError::Alarm(Alarm::Compromise { n: 3, .. })),
        "{error:?}"
    );
}

/// Once reconciliation ends with nothing to ask, the restore is over: its record goes.
#[tokio::test]
async fn test_app_restore_record_goes_when_reconciliation_ends() {
    let w = World::new();
    let app = w.join("wallet").await;
    let backup = app.backup().await.unwrap();
    let (mut restored, store) = restored(&w, &backup).await;
    restored.receive(None).await.unwrap();
    restored.end_reconcile(UserConfirmed::new()).await.unwrap();
    assert!(!restored.reconcile_mode());
    let ns = crate::store::client_namespace(&restored.app_id());
    assert!(store.get(&ns, b"restore").unwrap().is_none());
}

#[tokio::test]
async fn test_app_restore_with_its_current_key_registers_nothing() {
    let w = World::new();
    let app = w.join("wallet").await;
    let backup = app.backup().await.unwrap();
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
async fn test_app_store_of_schema_1_fails_to_load_as_an_old_schema_and_stays() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let me = app.app_id();
    w.note(me, "one");
    app.receive(None).await.unwrap();
    let ns = app.ns.clone();
    // Every value of the app's own, as schema 1 wrote it.
    let mut batch = crate::store::WriteBatch::new();
    for (key, bytes) in app.reader().scan_raw("").await.unwrap() {
        if key.starts_with("p/") {
            continue;
        }
        let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if value.get("v") == Some(&json!(crate::app::SCHEMA_VERSION)) {
            value["v"] = json!(1);
            batch
                .put(
                    &ns,
                    key.as_bytes().to_vec(),
                    serde_json::to_vec(&value).unwrap(),
                )
                .unwrap();
        }
    }
    app.env.store.commit(batch).await.unwrap();
    let before = app.reader().scan_raw("").await.unwrap();
    let reader = app.reader();
    drop(app);
    let loaded = App::load(w.env(), w.protocol.clone(), World::config(), me).await;
    assert!(
        matches!(
            loaded,
            Err(AppError::Store(crate::StoreError::OldSchema { found: 1 }))
        ),
        "{:?}",
        loaded.map(|_| ())
    );
    // Refused, it writes nothing.
    assert_eq!(reader.scan_raw("").await.unwrap(), before);
}

#[tokio::test]
async fn test_app_backup_refuses_another_schema_or_bytes() {
    let w = World::new();
    let app = w.join("wallet").await;
    let bytes = app.backup().await.unwrap().to_bytes().unwrap();
    assert!(AppBackup::from_bytes(&bytes).is_ok());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // An earlier schema's backup is an old schema, as its store is; a later one doesn't
    // read.
    value["v"] = json!(1);
    let old = serde_json::to_vec(&value).unwrap();
    assert!(matches!(
        AppBackup::from_bytes(&old),
        Err(AppError::Store(crate::StoreError::OldSchema { found: 1 }))
    ));
    // A layered backup as schema 1 wrote it, at version 2.
    value["v"] = json!(2);
    value["protocol"] =
        json!({ "name": "x", "data": "", "seen": [], "parked": [], "processed": [] });
    let old_layered = serde_json::to_vec(&value).unwrap();
    assert!(matches!(
        AppBackup::from_bytes(&old_layered),
        Err(AppError::Store(crate::StoreError::OldSchema { found: 2 }))
    ));
    value["v"] = json!(9);
    value.as_object_mut().unwrap().remove("protocol");
    let other = serde_json::to_vec(&value).unwrap();
    assert!(matches!(
        AppBackup::from_bytes(&other),
        Err(AppError::InvalidData(_))
    ));
    assert!(AppBackup::from_bytes(b"{}").is_err());
    // Its Debug names the app only.
    let text = format!("{:?}", app.backup().await.unwrap());
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
        AppEvent::Parked { id: Some(_), seq, reason: ParkReason::Refused, .. } if *seq == refused
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
        AppEvent::Parked { id: Some(_), seq, reason: ParkReason::Refused, .. } if *seq == refused
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
    let backup = app.backup().await.unwrap();
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
    let backup = app.backup().await.unwrap();
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
            || refused_events(&app.kept_duties().await.unwrap(), seq).is_empty()
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
async fn test_duty_event_listed_after_a_failed_commit_comes_once() {
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
        // The refusal's commit was applied unreported. Listing it reloads first and hands
        // it over; the next report doesn't hand it over again.
        let listed = app.unacknowledged_events().await.unwrap();
        assert_eq!(refused_events(&listed, seq).len(), 1, "commit {n}");
        let report = app.receive(None).await.unwrap();
        let mut again = report.events;
        again.extend(app.take_events());
        assert!(
            refused_events(&again, seq).is_empty(),
            "commit {n}: {again:?}"
        );
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
            AppEvent::Parked { id: Some(_), seq: s, reason: ParkReason::TooManyOperations, .. } if *s == seq
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

/// The sample protocol, whose note `big` writes local values of `sizes` bytes of `0xff`,
/// with a conversation entry when `ops`; other notes as the sample protocol. With
/// `via_context`, the step adds the writes through its context instead, and keeps what
/// each add answered.
#[derive(Default)]
struct BigProtocol {
    sample: SampleProtocol,
    ops: bool,
    sizes: Vec<usize>,
    via_context: bool,
    added: Mutex<Vec<Result<(), String>>>,
}

impl BigProtocol {
    fn writes(&self) -> Vec<LocalWrite> {
        self.sizes
            .iter()
            .enumerate()
            .map(|(n, size)| LocalWrite::Put {
                key: format!("big/{n}").into_bytes(),
                value: vec![0xff; *size],
            })
            .collect()
    }
}

impl Protocol for BigProtocol {
    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &pubky_switch_core::message::Message,
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

    fn receive(&self, message: &ReceivedMessage) -> Outcome {
        if message.message.body.get("text").and_then(Value::as_str) != Some("big") {
            return self.sample.receive(message);
        }
        let ops = if self.ops {
            vec![(
                Vec::new(),
                OpKind::AllowPut {
                    pubky: message.sender,
                    kind: AllowKind::Conversation,
                },
            )]
        } else {
            Vec::new()
        };
        Outcome::Apply(Effect {
            ops,
            local: self.writes(),
        })
    }

    fn receive_with(
        &self,
        message: &ReceivedMessage,
        cx: &mut crate::app::ReceiveContext<'_>,
    ) -> Outcome {
        let big = message.message.body.get("text").and_then(Value::as_str) == Some("big");
        if !self.via_context || !big {
            return self.receive(message);
        }
        for write in self.writes() {
            let added = cx.local(write).map_err(|error| error.to_string());
            self.added.lock().unwrap().push(added);
        }
        Outcome::Apply(Effect::default())
    }

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.missed(missed)
    }
}

/// A note `big` to an app with [`BigProtocol`], then a plain one: the big one is stored
/// and passed as too large, the protocol told, and the plain one applied.
async fn big_effect_is_parked(ops: bool, sizes: Vec<usize>) {
    let protocol = Arc::new(BigProtocol {
        ops,
        sizes,
        ..BigProtocol::default()
    });
    big_effect_is_parked_with(protocol).await;
}

async fn big_effect_is_parked_with(protocol: Arc<BigProtocol>) {
    let w = World::new();
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let mut app = App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap();
    let (big, _) = w.note(app.app_id(), "big");
    let (plain, _) = w.note(app.app_id(), "plain");
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Parked { id: Some(_), seq: s, reason: ParkReason::EffectTooLarge, .. } if *s == big
    )));
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::EffectRefused { seq: s, code: None, .. } if *s == big
    )));
    assert!(received(&report.events, plain), "{:?}", report.events);
    assert!(app.cursor().seq >= plain);
    // Only the plain note's conversation entry went.
    assert_eq!(w.effects(), 1);
    assert!(app.protocol_get(b"big/0").await.unwrap().is_none());
    app.receive(None).await.unwrap();
}

/// The key `big/0` [`BigProtocol`] writes first.
const BIG_KEY_BYTES: usize = 5;

/// The value size that takes one write of [`BigProtocol`] exactly to the bound.
const AT_THE_BOUND: usize = MAX_STEP_LOCAL_BYTES - BIG_KEY_BYTES - LOCAL_WRITE_OVERHEAD_BYTES;

#[tokio::test]
async fn test_effect_at_the_bound_with_operations_is_kept_and_applied() {
    // Local writes at the bound, of the bytes that took the most room in the earlier kept
    // form (`255,` each, over 16 MiB): in base64 the kept effect fits one value.
    let w = World::new();
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let protocol = Arc::new(BigProtocol {
        ops: true,
        sizes: vec![AT_THE_BOUND],
        ..BigProtocol::default()
    });
    let mut app = App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap();
    let (seq, _) = w.note(app.app_id(), "big");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(w.effects(), 1);
    assert_eq!(
        app.protocol_get(b"big/0").await.unwrap().map(|v| v.len()),
        Some(AT_THE_BOUND)
    );
}

#[tokio::test]
async fn test_step_local_writes_at_the_bound_are_applied() {
    let w = World::new();
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let protocol = Arc::new(BigProtocol {
        sizes: vec![AT_THE_BOUND],
        ..BigProtocol::default()
    });
    let mut app = App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap();
    let (seq, _) = w.note(app.app_id(), "big");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(
        app.protocol_get(b"big/0").await.unwrap().map(|v| v.len()),
        Some(AT_THE_BOUND)
    );
}

#[tokio::test]
async fn test_step_local_writes_one_byte_over_the_bound_are_parked() {
    big_effect_is_parked(false, vec![AT_THE_BOUND + 1]).await;
}

#[tokio::test]
async fn test_step_local_through_the_context_past_the_bound_is_refused() {
    let protocol = Arc::new(BigProtocol {
        sizes: vec![AT_THE_BOUND, 1],
        via_context: true,
        ..BigProtocol::default()
    });
    big_effect_is_parked_with(protocol.clone()).await;
    let added = protocol.added.lock().unwrap().clone();
    assert_eq!(added.len(), 2);
    assert!(added[0].is_ok());
    assert!(
        added[1]
            .as_ref()
            .is_err_and(|why| why.contains(&MAX_STEP_LOCAL_BYTES.to_string())),
        "{added:?}"
    );
}

#[tokio::test]
async fn test_effect_local_writes_over_one_commit_are_stored_and_passed() {
    big_effect_is_parked(false, vec![12 << 20, 12 << 20, 12 << 20]).await;
}

#[tokio::test]
async fn test_effect_local_write_over_the_value_size_is_stored_and_passed() {
    big_effect_is_parked(false, vec![(16 << 20) + 1]).await;
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
                timeout: crate::transport::TimeoutClass::default(),
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

/// A kept batch stored without its stamp (`kept_ms: None`) was never sent: the stamp is
/// committed before the request leaves, so a crash before that commit leaves the batch
/// unsent, and its first send later goes under the same batch ID with nothing to settle.
#[tokio::test]
async fn test_kept_batch_unstamped_after_a_crash_was_never_sent() {
    let w = World::new();
    let app = w.join("wallet").await;
    let me = app.app_id();
    drop(app);
    w.clock.advance_ms(20 * 60 * 1000);
    // Reopened over a store that stops before its second commit from here: the first keeps
    // the batch, the second is its stamp.
    let fault = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::StopBefore(2),
    ));
    let mut app = App::load(
        w.env_on(fault.clone() as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        me,
    )
    .await
    .unwrap();
    assert!(
        app.submit_batch(conversation(w.bob.public()))
            .await
            .is_err()
    );
    drop(app);
    let mut app = w.load(me).await;
    let kept = app.kept_batches().await.unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].1.kept_ms, None);
    assert_eq!(
        conversations_for(&w, w.bob.public()),
        0,
        "stored unstamped, yet sent"
    );
    // Its first send applies it once.
    app.submit_batch(conversation([7; 32])).await.unwrap();
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(conversations_for(&w, w.bob.public()), 1);
}

// -------------------------------------------------------------------------------------
// The page's commit: effects and calls at the bound, and entries stored after them

/// The sample protocol, whose note `fill` writes local values at the bound, `huge…` writes
/// more than the bound (stored and passed), and whose missed-entries call answers with
/// `missed` bytes of local writes, after failing `missed_fails` times.
#[derive(Default)]
struct FillProtocol {
    sample: SampleProtocol,
    missed: usize,
    missed_fails: Mutex<u32>,
}

impl Protocol for FillProtocol {
    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &pubky_switch_core::message::Message,
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

    fn receive(&self, message: &ReceivedMessage) -> Outcome {
        let text = message
            .message
            .body
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("");
        let local = if text == "fill" {
            vec![LocalWrite::Put {
                key: format!("fill/{}", message.seq).into_bytes(),
                value: vec![0xff; MAX_STEP_LOCAL_BYTES - 64 - LOCAL_WRITE_OVERHEAD_BYTES],
            }]
        } else if text.starts_with("huge") {
            (0..3)
                .map(|n| LocalWrite::Put {
                    key: format!("huge/{n}").into_bytes(),
                    value: vec![0; 12 << 20],
                })
                .collect()
        } else {
            return self.sample.receive(message);
        };
        Outcome::Apply(Effect {
            ops: Vec::new(),
            local,
        })
    }

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        {
            let mut fails = self.missed_fails.lock().unwrap();
            if *fails > 0 {
                *fails -= 1;
                return Err(crate::error::StoreError::Unavailable.into());
            }
        }
        if self.missed == 0 {
            return self.sample.missed(missed);
        }
        let key = format!("missed/{}", missed.seq).into_bytes();
        // `usize::MAX` stands for exactly the bound.
        let size = if self.missed == usize::MAX {
            MAX_STEP_LOCAL_BYTES - LOCAL_WRITE_OVERHEAD_BYTES - key.len()
        } else {
            self.missed
        };
        Ok(vec![LocalWrite::Put {
            key,
            value: vec![0xff; size],
        }])
    }
}

async fn fill_app(w: &World, protocol: &Arc<FillProtocol>) -> App {
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    App::join(w.env(), protocol.clone(), World::config(), request)
        .await
        .unwrap()
}

/// Bytes of a missed-entries answer that take it to within its key of the bound.
const MISSED_NEAR_THE_BOUND: usize = MAX_STEP_LOCAL_BYTES - 64 - LOCAL_WRITE_OVERHEAD_BYTES;

#[tokio::test]
async fn test_page_full_of_effects_near_the_bound_and_entries_stored_goes_on() {
    let w = World::new();
    let protocol = Arc::new(FillProtocol::default());
    let mut app = fill_app(&w, &protocol).await;
    // Nine effects at the bound, 36 MiB of local writes in all, then entries stored for
    // effects over it, each with a large plaintext: one page, and more than one commit.
    let mut filled = Vec::new();
    for _ in 0..9 {
        filled.push(w.note(app.app_id(), "fill").0);
    }
    let pad = "x".repeat(40_000);
    let mut huge = Vec::new();
    for _ in 0..6 {
        huge.push(w.note(app.app_id(), &format!("huge{pad}")).0);
    }
    let (plain, _) = w.note(app.app_id(), "plain");
    let report = app.receive(None).await.unwrap();
    assert!(app.cursor().seq >= plain, "the feed goes on");
    for seq in &filled {
        let key = format!("fill/{seq}");
        assert!(app.protocol_get(key.as_bytes()).await.unwrap().is_some());
    }
    for seq in &huge {
        assert!(has(&report.events, |e| matches!(
            e,
            AppEvent::Parked { seq: s, reason: ParkReason::EffectTooLarge, .. } if s == seq
        )));
    }
    assert!(received(&report.events, plain));
}

#[tokio::test]
async fn test_missed_local_writes_near_the_bound_on_one_page_go_on() {
    let w = World::new();
    let protocol = Arc::new(FillProtocol {
        missed: MISSED_NEAR_THE_BOUND,
        ..FillProtocol::default()
    });
    let mut app = fill_app(&w, &protocol).await;
    w.note(app.app_id(), "first");
    app.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    let missed: Vec<u64> = (0..9)
        .map(|_| w.switch.push_missed(1, now - HOUR, now))
        .collect();
    let (plain, _) = w.note(app.app_id(), "plain");
    let report = app.receive(None).await.unwrap();
    assert!(app.cursor().seq >= plain, "the feed goes on");
    for seq in missed {
        let key = format!("missed/{seq}");
        assert!(app.protocol_get(key.as_bytes()).await.unwrap().is_some());
    }
    assert!(received(&report.events, plain));
}

#[tokio::test]
async fn test_page_of_effects_at_the_bound_between_entries_stored_goes_on() {
    let w = World::new();
    let protocol = Arc::new(FillProtocol::default());
    let mut app = fill_app(&w, &protocol).await;
    // Nine effects near the bound, each followed by three entries stored as too large.
    let pad = "x".repeat(40_000);
    for _ in 0..9 {
        w.note(app.app_id(), "fill");
        for _ in 0..3 {
            w.note(app.app_id(), &format!("huge{pad}"));
        }
    }
    let (plain, _) = w.note(app.app_id(), "plain");
    for _ in 0..3 {
        app.receive(None).await.unwrap();
    }
    assert!(app.cursor().seq >= plain, "the feed goes on");
}

#[tokio::test]
async fn test_missed_local_writes_at_the_bound_on_one_page_go_on() {
    let w = World::new();
    let protocol = Arc::new(FillProtocol {
        missed: usize::MAX,
        ..FillProtocol::default()
    });
    let mut app = fill_app(&w, &protocol).await;
    w.note(app.app_id(), "first");
    app.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    for _ in 0..9 {
        w.switch.push_missed(1, now - HOUR, now);
    }
    let (plain, _) = w.note(app.app_id(), "plain");
    app.receive(None).await.unwrap();
    assert!(app.cursor().seq >= plain, "the feed goes on");
    assert!(
        !app.kept_duties()
            .await
            .unwrap()
            .iter()
            .any(|e| matches!(e, AppEvent::LocalWritesRefused { .. })),
        "at the bound, the writes are taken"
    );
}

#[tokio::test]
async fn test_missed_local_writes_over_the_bound_are_refused_and_the_feed_goes_on() {
    let w = World::new();
    let protocol = Arc::new(FillProtocol {
        missed: MAX_STEP_LOCAL_BYTES,
        ..FillProtocol::default()
    });
    let mut app = fill_app(&w, &protocol).await;
    w.note(app.app_id(), "first");
    app.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    let seq = w.switch.push_missed(1, now - HOUR, now);
    let (plain, _) = w.note(app.app_id(), "plain");
    let report = app.receive(None).await.unwrap();
    assert!(app.cursor().seq >= plain, "the feed goes on");
    let key = format!("missed/{seq}");
    assert!(app.protocol_get(key.as_bytes()).await.unwrap().is_none());
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::LocalWritesRefused {
                call: RefusedCall::Missed(missed),
                ..
            } if missed.seq == seq && missed.accepted_until_ms == now
        )),
        "{:?}",
        report.events
    );
    // Not made again.
    app.receive(None).await.unwrap();
    assert!(
        app.kept_duties()
            .await
            .unwrap()
            .iter()
            .any(|e| matches!(e, AppEvent::LocalWritesRefused { .. }))
    );
}

#[tokio::test]
async fn test_owed_call_local_writes_over_the_bound_are_refused_once() {
    let w = World::new();
    let protocol = Arc::new(FillProtocol {
        missed: MAX_STEP_LOCAL_BYTES,
        missed_fails: Mutex::new(1),
        ..FillProtocol::default()
    });
    let mut app = fill_app(&w, &protocol).await;
    w.note(app.app_id(), "first");
    app.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    let seq = w.switch.push_missed(1, now - HOUR, now);
    // The call fails: owed, made again by the next read, whose answer is over the bound.
    app.receive(None).await.unwrap();
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 1);
    let (plain, _) = w.note(app.app_id(), "plain");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, plain), "{:?}", report.events);
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 0);
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::LocalWritesRefused {
            call: RefusedCall::Missed(missed),
            ..
        } if missed.seq == seq
    )));
    let key = format!("missed/{seq}");
    assert!(app.protocol_get(key.as_bytes()).await.unwrap().is_none());
}

#[tokio::test]
async fn test_submit_batch_local_writes_over_the_bound_are_refused_unkept() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let batch = conversation(w.bob.public()).local(LocalWrite::Put {
        key: b"big".to_vec(),
        value: vec![0; MAX_STEP_LOCAL_BYTES],
    });
    let error = app.submit_batch(batch).await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error:?}"
    );
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(conversations_for(&w, w.bob.public()), 0);
}

/// An own app of alice's, `name`, holding `permissions`, joined on its own store.
async fn join_holding(w: &World, name: &str, permissions: &[Permission]) -> App {
    let request = w
        .signer
        .approve(
            &app_keys(name),
            &AppSpec::new(&["scope-a"]).with_permissions(permissions),
        )
        .unwrap();
    App::join(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        request,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn test_scripted_feed_shows_an_allow_put_in_full_only_to_lists_read() {
    // Switch wire 7.5: `allow.*` is read in full by apps with `lists.read`. An app with
    // `lists.manage` alone writes a contact and is shown its own `allow.put` as a stub.
    let w = World::new();
    let mut manager = join_holding(&w, "manager", &[Permission::ListsManage]).await;
    let reader = join_holding(&w, "reader", &[Permission::ListsRead]).await;
    let before = w.switch.shown(manager.app_id()).len();
    manager.add_contact(&w.bob.public()).await.unwrap();
    let shown = w.switch.shown(manager.app_id());
    let put = shown[before..]
        .iter()
        .find(|item| item.get("stub").is_some())
        .expect("the allow.put's item");
    assert_eq!(put["type"], "stub", "{put}");
    let seq = put["seq"].clone();
    let full = w
        .switch
        .shown(reader.app_id())
        .into_iter()
        .find(|item| item["seq"] == seq)
        .unwrap();
    assert_eq!(full["type"], "chain", "{full}");
    assert_eq!(full["item_type"], "op");
}

#[tokio::test]
async fn test_scripted_feed_shows_a_compacted_claims_entries_as_stubs() {
    // Switch wire 6.8 "Tombstones", 7.5: a claim SETTLED with every attempt done or failed
    // is compacted at once, and its entries show as stubs, also to apps with `claims.read`.
    let w = World::new();
    let claim = [7; 32];
    let attempt = [8; 16];
    let mut writer = join_holding(&w, "writer", &Permission::ALL).await;
    let reader = join_holding(&w, "reader", &[Permission::ClaimsRead]).await;
    let before = w.switch.shown(reader.app_id()).len();
    writer
        .write_claim(
            crate::app::ClaimOp::attempt(claim, 0, attempt, 3600, None),
            vec![],
            crate::app::ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap();
    // While the attempt is open, its entry is read in full by `claims.read`.
    let open = w.switch.shown(reader.app_id());
    assert_eq!(open[before]["type"], "chain", "{}", open[before]);
    let condition = writer.claim_condition(&claim).await.unwrap();
    writer
        .write_claim(
            crate::app::ClaimOp::done(
                claim,
                1,
                attempt,
                pubky_switch_core::claims::Basis::Owner,
                None,
            )
            .unwrap(),
            vec![condition],
            crate::app::ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap();
    let shown = w.switch.shown(reader.app_id());
    let entries = &shown[before..];
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert!(
        entries.iter().all(|item| item["type"] == "stub"),
        "{entries:?}"
    );
}

#[tokio::test]
async fn test_scripted_feed_visibility_follows_a_listed_renewal() {
    // Switch wire 3.8, 7.5: an item's visibility is judged with the certificate the app is
    // checked against, a stored renewed one once the newest `identity.json` lists it. The
    // renewal adds `lists.read`, so the app reads an `allow.put` in full from then on.
    let w = World::new();
    let app = w.join("wallet").await;
    let me = app.app_id();
    let old = app.cert().clone();
    let renewed = crate::testing::issue_cert(
        &w.alice,
        &app_keys("wallet"),
        &AppSpec::new(&["scope-a"])
            .with_permissions(&[Permission::ListsRead, Permission::ConversationAdd]),
        w.clock.now_ms() + 1000,
    )
    .unwrap();
    w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: me,
            cert: renewed.signed().clone(),
        })
        .unwrap();
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
    let mut manager = join_holding(&w, "manager", &[Permission::ListsManage]).await;
    let before = w.switch.seq();
    manager.add_contact(&w.bob.public()).await.unwrap();
    let seq = w
        .switch
        .shown(manager.app_id())
        .into_iter()
        .find(|item| item["seq"].as_u64().unwrap() > before && item["type"] == "stub")
        .expect("the allow.put's item")["seq"]
        .clone();
    let item = w
        .switch
        .shown(me)
        .into_iter()
        .find(|item| item["seq"] == seq)
        .unwrap();
    assert_eq!(item["type"], "chain", "{item}");
}

/// The deny list changes `protocol` was handed, as (pubky, added) pairs.
fn denies(protocol: &SampleProtocol) -> Vec<([u8; 32], bool)> {
    protocol
        .denies
        .lock()
        .unwrap()
        .iter()
        .map(|change| (change.pubky, change.added))
        .collect()
}

/// A manager that changes the deny list, and a reader with `lists.read`.
async fn deny_list_apps(w: &World) -> (App, App) {
    // The manager has a protocol of its own, so what reaches `w.protocol` is the reader's.
    let manager = join_with(
        w,
        "manager",
        &[Permission::ListsManage],
        Arc::new(MemoryStore::new()),
        Arc::new(SampleProtocol::default()) as Arc<dyn Protocol>,
    )
    .await;
    let reader = join_holding(w, "reader", &[Permission::ListsRead]).await;
    (manager, reader)
}

#[tokio::test]
async fn test_deny_list_changes_reach_the_protocol_in_feed_order() {
    // Switch spec 8.3: the feed shows the deny list's changes to `lists.read`; each goes to
    // the protocol with its item's place and service time, its writes with the cursor.
    let w = World::new();
    let (mut manager, mut reader) = deny_list_apps(&w).await;
    let (a, b) = ([1; 32], [2; 32]);
    manager.deny(&a).await.unwrap();
    w.clock.advance_ms(1000);
    manager.deny(&b).await.unwrap();
    manager.undeny(&a).await.unwrap();
    reader.receive(None).await.unwrap();
    assert_eq!(denies(&w.protocol), vec![(a, true), (b, true), (a, false)]);
    let changes = w.protocol.denies.lock().unwrap().clone();
    assert!(changes.windows(2).all(|pair| pair[0].seq < pair[1].seq));
    assert!(changes[1].at_ms >= changes[0].at_ms + 1000);
    assert!(changes.iter().all(|change| change.generation == 1));
    let local = reader
        .protocol_get(format!("deny/{}", changes[2].seq).as_bytes())
        .await
        .unwrap();
    assert_eq!(local, Some(vec![0]));
    // Read again: nothing is handed over twice.
    reader.receive(None).await.unwrap();
    assert_eq!(w.protocol.denies.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn test_deny_list_changes_without_lists_read_reach_no_protocol() {
    // Switch wire 7.5: without `lists.read` the feed shows a deny list change as a stub.
    let w = World::new();
    let (mut manager, _) = deny_list_apps(&w).await;
    let mut wallet = w.join("wallet").await;
    manager.deny(&[1; 32]).await.unwrap();
    let before = w.protocol.denies.lock().unwrap().len();
    wallet.receive(None).await.unwrap();
    assert_eq!(w.protocol.denies.lock().unwrap().len(), before);
}

#[tokio::test]
async fn test_deny_list_change_owed_holds_the_later_ones_back() {
    // A change that fails is owed, and the read stops after it: nothing later is handed,
    // also while it fails again at the next read, which stops at its start. Once the
    // protocol takes it, the rest go in feed order. After RETRY_EVENT_READS reads held,
    // the host is told.
    let w = World::new();
    let (mut manager, mut reader) = deny_list_apps(&w).await;
    let (a, b) = ([1; 32], [2; 32]);
    manager.deny(&a).await.unwrap();
    manager.deny(&b).await.unwrap();
    manager.undeny(&a).await.unwrap();
    *w.protocol.failing_deny.lock().unwrap() = 3;
    let first = reader.receive(None).await.unwrap();
    assert!(first.stopped);
    assert!(denies(&w.protocol).is_empty());
    assert_eq!(reader.owed_protocol_calls().await.unwrap(), 1);
    let mut held = Vec::new();
    for _ in 0..2 {
        held.extend(reader.receive(None).await.unwrap().events);
    }
    assert!(denies(&w.protocol).is_empty());
    assert!(
        held.iter()
            .any(|e| matches!(e, AppEvent::OwedCallHeld { reads } if *reads >= 2)),
        "{held:?}"
    );
    reader.receive(None).await.unwrap();
    reader.receive(None).await.unwrap();
    assert_eq!(denies(&w.protocol), vec![(a, true), (b, true), (a, false)]);
    assert_eq!(reader.owed_protocol_calls().await.unwrap(), 0);
}

#[tokio::test]
async fn test_deny_list_changes_since_a_backup_reach_the_restored_protocol() {
    // A protocol restored from a backup gets each change made since the backup's cursor,
    // so it can rebuild who was denied.
    let w = World::new();
    let (mut manager, mut reader) = deny_list_apps(&w).await;
    let (a, b) = ([1; 32], [2; 32]);
    manager.deny(&a).await.unwrap();
    reader.receive(None).await.unwrap();
    let backup = reader.backup().await.unwrap();
    manager.deny(&b).await.unwrap();
    manager.undeny(&a).await.unwrap();
    let restored_protocol = Arc::new(SampleProtocol::default());
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        Arc::clone(&restored_protocol) as Arc<dyn Protocol>,
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.end_reconcile(UserConfirmed::new()).await.ok();
    restored.receive(None).await.unwrap();
    assert_eq!(denies(&restored_protocol), vec![(b, true), (a, false)]);
}

/// The sample protocol, logging the `seq` of each message and deny list change it takes,
/// in the order it takes them.
#[derive(Default)]
struct OrderedProtocol {
    sample: SampleProtocol,
    log: std::sync::Mutex<Vec<(&'static str, u64)>>,
}

impl Protocol for OrderedProtocol {
    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &pubky_switch_core::message::Message,
        sender: &pubky_switch_core::records::AppCert,
        own: &pubky_switch_core::records::AppCert,
    ) -> Result<(), String> {
        self.sample.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &pubky_switch_core::records::AppCert) -> Vec<String> {
        self.sample.accepts(cert)
    }

    fn check_body(&self, message: &crate::app::ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(message)
    }

    fn receive(&self, message: &crate::app::ReceivedMessage) -> crate::app::Outcome {
        self.log.lock().unwrap().push(("message", message.seq));
        self.sample.receive(message)
    }

    fn resend_needed(
        &self,
        needed: &crate::app::ResendNeeded,
    ) -> Result<Vec<crate::app::LocalWrite>, crate::app::StoreFailure> {
        self.sample.resend_needed(needed)
    }

    fn missed(
        &self,
        missed: &crate::app::MissedEntries,
    ) -> Result<Vec<crate::app::LocalWrite>, crate::app::StoreFailure> {
        self.sample.missed(missed)
    }

    fn deny_list_changed(
        &self,
        change: &crate::app::DenyListChange,
    ) -> Result<Vec<crate::app::LocalWrite>, crate::app::StoreFailure> {
        let writes = self.sample.deny_list_changed(change)?;
        self.log.lock().unwrap().push(("deny", change.seq));
        Ok(writes)
    }
}

/// An app `name` holding `permissions`, with `protocol`, in `store`.
async fn join_with(
    w: &World,
    name: &str,
    permissions: &[Permission],
    store: Arc<MemoryStore>,
    protocol: Arc<dyn Protocol>,
) -> App {
    let request = w
        .signer
        .approve(
            &app_keys(name),
            &AppSpec::new(&["scope-a"]).with_permissions(permissions),
        )
        .unwrap();
    App::join(
        w.env_on(store as Arc<dyn StateStore>),
        protocol,
        World::config(),
        request,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn test_deny_list_change_owed_comes_before_a_later_message() {
    // Feed order across the calls: a message accepted after a deny list change reaches the
    // protocol after it, also when the change was owed.
    let w = World::new();
    let mut manager = join_holding(&w, "manager", &[Permission::ListsManage]).await;
    let ordered = Arc::new(OrderedProtocol::default());
    let mut reader = join_with(
        &w,
        "reader",
        &[Permission::ListsRead, Permission::ConversationAdd],
        Arc::new(MemoryStore::new()),
        Arc::clone(&ordered) as Arc<dyn Protocol>,
    )
    .await;
    let bob = w.bob.public();
    manager.deny(&bob).await.unwrap();
    reader.receive(None).await.unwrap();
    manager.undeny(&bob).await.unwrap();
    w.note(reader.app_id(), "after the undeny");
    *ordered.sample.failing_deny.lock().unwrap() = 1;
    reader.receive(None).await.unwrap();
    reader.receive(None).await.unwrap();
    let log = ordered.log.lock().unwrap().clone();
    assert_eq!(log.len(), 3, "{log:?}");
    assert!(log.windows(2).all(|pair| pair[0].1 < pair[1].1), "{log:?}");
}

#[tokio::test]
async fn test_deny_list_change_of_the_apps_own_is_handed_once() {
    // An app that changes the deny list and reads it: its own change comes back by the
    // feed, and goes to its protocol once.
    let w = World::new();
    let protocol = Arc::new(SampleProtocol::default());
    let mut both = join_with(
        &w,
        "both",
        &[Permission::ListsRead, Permission::ListsManage],
        Arc::new(MemoryStore::new()),
        Arc::clone(&protocol) as Arc<dyn Protocol>,
    )
    .await;
    both.deny(&[5; 32]).await.unwrap();
    both.receive(None).await.unwrap();
    both.undeny(&[5; 32]).await.unwrap();
    both.receive(None).await.unwrap();
    both.receive(None).await.unwrap();
    assert_eq!(denies(&protocol), vec![([5; 32], true), ([5; 32], false)]);
}

#[tokio::test]
async fn test_deny_list_change_owed_at_a_restore_in_place_is_handed_once_in_order() {
    // A restore in place keeps the calls the protocol still owes, and reads the feed again
    // from the backup's cursor: each change still goes once, in feed order.
    let w = World::new();
    let mut manager = join_holding(&w, "manager", &[Permission::ListsManage]).await;
    let store = Arc::new(MemoryStore::new());
    let protocol = Arc::new(SampleProtocol::default());
    let mut reader = join_with(
        &w,
        "reader",
        &[Permission::ListsRead],
        Arc::clone(&store),
        Arc::clone(&protocol) as Arc<dyn Protocol>,
    )
    .await;
    reader.receive(None).await.unwrap();
    let backup = reader.backup().await.unwrap();
    let (x, a) = ([1; 32], [2; 32]);
    manager.deny(&x).await.unwrap();
    reader.receive(None).await.unwrap();
    manager.deny(&a).await.unwrap();
    *protocol.failing_deny.lock().unwrap() = 1;
    reader.receive(None).await.unwrap();
    assert_eq!(reader.owed_protocol_calls().await.unwrap(), 1);
    drop(reader);
    protocol.denies.lock().unwrap().clear();
    let mut restored = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&protocol) as Arc<dyn Protocol>,
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.end_reconcile(UserConfirmed::new()).await.ok();
    restored.receive(None).await.unwrap();
    restored.receive(None).await.unwrap();
    assert_eq!(denies(&protocol), vec![(x, true), (a, true)]);
}

#[tokio::test]
async fn test_deny_list_changes_dropped_behind_a_checkpoint_tell_the_restored_protocol() {
    // A backup older than the retained history: the changes behind the checkpoint can't
    // come from the feed, so the restored protocol is told the gap, with the list now
    // (Switch spec 12.4 "Older than the retained history").
    let w = World::new();
    w.switch.set_retention(Some(crate::testing::Retention {
        checkpoint_behind: 3,
        ..crate::testing::Retention::default()
    }));
    let mut wallet = join_with(
        &w,
        "wallet",
        &[Permission::ListsRead, Permission::ListsManage],
        Arc::new(MemoryStore::new()),
        w.protocol.clone(),
    )
    .await;
    wallet.receive(None).await.unwrap();
    let backup = wallet.backup().await.unwrap();
    for i in 1..=5u8 {
        wallet.deny(&[i; 32]).await.unwrap();
    }
    w.note(wallet.app_id(), "past");
    wallet.receive(None).await.unwrap();
    wallet.deny(&[0xee; 32]).await.unwrap();
    wallet.deny(&[0xef; 32]).await.unwrap();
    assert!(w.switch.retained().1 > 0, "nothing dropped");
    drop(wallet);
    let restored_protocol = Arc::new(SampleProtocol::default());
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        Arc::clone(&restored_protocol) as Arc<dyn Protocol>,
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    let mut events = Vec::new();
    for _ in 0..3 {
        events.extend(restored.receive(None).await.unwrap().events);
    }
    assert!(restored.reconcile_mode());
    // The protocol is told the gap, with the deny list as it stands now, before any
    // change after it.
    let gaps = restored_protocol.deny_gaps.lock().unwrap().clone();
    assert_eq!(gaps.len(), 1, "gaps {gaps:?}, events {events:?}");
    assert!(gaps[0].denied.contains(&[1; 32]), "{gaps:?}");
    assert!(gaps[0].denied.contains(&[0xef; 32]), "{gaps:?}");
    assert_eq!(gaps[0].generation, backup.cursor.generation);
}

// -------------------------------------------------------------------------------------
// Deny list changes: further cases.

/// The sample protocol, logging each message, missed-entries call and deny list change it
/// takes, by `seq`, in order; the first `retries` messages are answered
/// [`crate::app::Outcome::Retry`], so their entries are held.
#[derive(Default)]
struct KindsProtocol {
    sample: SampleProtocol,
    log: std::sync::Mutex<Vec<(&'static str, u64)>>,
    retries: std::sync::Mutex<u32>,
}

impl Protocol for KindsProtocol {
    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &pubky_switch_core::message::Message,
        sender: &pubky_switch_core::records::AppCert,
        own: &pubky_switch_core::records::AppCert,
    ) -> Result<(), String> {
        self.sample.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &pubky_switch_core::records::AppCert) -> Vec<String> {
        self.sample.accepts(cert)
    }

    fn check_body(&self, message: &crate::app::ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(message)
    }

    fn receive(&self, message: &crate::app::ReceivedMessage) -> crate::app::Outcome {
        {
            let mut retries = self.retries.lock().unwrap();
            if *retries > 0 {
                *retries -= 1;
                return crate::app::Outcome::Retry(crate::app::StoreFailure::unavailable(
                    crate::error::StoreError::Unavailable,
                ));
            }
        }
        self.log.lock().unwrap().push(("message", message.seq));
        self.sample.receive(message)
    }

    fn resend_needed(
        &self,
        needed: &crate::app::ResendNeeded,
    ) -> Result<Vec<crate::app::LocalWrite>, crate::app::StoreFailure> {
        self.sample.resend_needed(needed)
    }

    fn missed(
        &self,
        missed: &crate::app::MissedEntries,
    ) -> Result<Vec<crate::app::LocalWrite>, crate::app::StoreFailure> {
        let writes = self.sample.missed(missed)?;
        self.log.lock().unwrap().push(("missed", missed.seq));
        Ok(writes)
    }

    fn deny_list_changed(
        &self,
        change: &crate::app::DenyListChange,
    ) -> Result<Vec<crate::app::LocalWrite>, crate::app::StoreFailure> {
        let writes = self.sample.deny_list_changed(change)?;
        self.log.lock().unwrap().push(("deny", change.seq));
        Ok(writes)
    }

    fn deny_list_gap(
        &self,
        gap: &crate::app::DenyListGap,
    ) -> Result<Vec<crate::app::LocalWrite>, crate::app::StoreFailure> {
        let writes = self.sample.deny_list_gap(gap)?;
        self.log.lock().unwrap().push(("gap", gap.seq));
        Ok(writes)
    }
}

/// A manager with `lists.manage` and a protocol of its own.
async fn manager_of(w: &World) -> App {
    join_with(
        w,
        "manager",
        &[Permission::ListsManage],
        Arc::new(MemoryStore::new()),
        Arc::new(SampleProtocol::default()) as Arc<dyn Protocol>,
    )
    .await
}

#[tokio::test]
async fn test_deny_list_change_owed_inside_a_batch_goes_on_after_it() {
    // A batch of three changes, the first owed: the read stops after it, inside the
    // batch; the next reads hand all three, in order, and nothing is taken for a rollback.
    let w = World::new();
    let mut manager = manager_of(&w).await;
    let mut reader = join_holding(&w, "reader", &[Permission::ListsRead]).await;
    let (a, b, c) = ([1; 32], [2; 32], [3; 32]);
    manager
        .submit_batch(
            crate::app::OpBatch::new()
                .op(OpKind::DenyPut { pubky: a })
                .op(OpKind::DenyPut { pubky: b })
                .op(OpKind::DenyPut { pubky: c }),
        )
        .await
        .unwrap();
    *w.protocol.failing_deny.lock().unwrap() = 1;
    for _ in 0..3 {
        let _ = reader.receive(None).await;
    }
    assert!(reader.alarm().is_none(), "{:?}", reader.alarm());
    assert_eq!(denies(&w.protocol), vec![(a, true), (b, true), (c, true)]);
}

#[tokio::test]
async fn test_deny_list_change_past_a_held_entry_is_handed_once() {
    // A note held for two reads, then a deny list change after it: the reads that meet the
    // change again past the held note don't hand it again.
    let w = World::new();
    let mut manager = manager_of(&w).await;
    let kinds = Arc::new(KindsProtocol::default());
    let mut reader = join_with(
        &w,
        "reader",
        &[Permission::ListsRead, Permission::ConversationAdd],
        Arc::new(MemoryStore::new()),
        Arc::clone(&kinds) as Arc<dyn Protocol>,
    )
    .await;
    *kinds.retries.lock().unwrap() = 2;
    w.note(reader.app_id(), "held");
    manager.deny(&[7; 32]).await.unwrap();
    for _ in 0..4 {
        reader.receive(None).await.unwrap();
    }
    let log = kinds.log.lock().unwrap().clone();
    let deny_calls = log.iter().filter(|(kind, _)| *kind == "deny").count();
    assert_eq!(deny_calls, 1, "{log:?}");
}

#[tokio::test]
async fn test_deny_list_change_after_an_owed_missed_call_waits_for_it() {
    // Feed order across everything handed over: a missed-entries call the protocol
    // couldn't take comes before a deny list change after it.
    let w = World::new();
    let mut manager = manager_of(&w).await;
    let kinds = Arc::new(KindsProtocol::default());
    let mut reader = join_with(
        &w,
        "reader",
        &[Permission::ListsRead],
        Arc::new(MemoryStore::new()),
        Arc::clone(&kinds) as Arc<dyn Protocol>,
    )
    .await;
    reader.receive(None).await.unwrap();
    let now = w.clock.now_ms();
    w.switch.push_missed(2, now, now);
    manager.deny(&[7; 32]).await.unwrap();
    *kinds.sample.failing.lock().unwrap() = 1;
    for _ in 0..3 {
        let _ = reader.receive(None).await;
    }
    let log = kinds.log.lock().unwrap().clone();
    assert!(log.iter().any(|(kind, _)| *kind == "missed"), "{log:?}");
    assert!(log.windows(2).all(|pair| pair[0].1 <= pair[1].1), "{log:?}");
}

#[tokio::test]
async fn test_deny_list_owed_calls_at_a_restore_in_place_keep_feed_order() {
    // A restore in place carries a missed-entries call owed past the backup's cursor; the
    // feed hands a deny list change before it again: the order holds across both.
    let w = World::new();
    let mut manager = manager_of(&w).await;
    let store = Arc::new(MemoryStore::new());
    let kinds = Arc::new(KindsProtocol::default());
    let mut reader = join_with(
        &w,
        "reader",
        &[Permission::ListsRead],
        Arc::clone(&store),
        Arc::clone(&kinds) as Arc<dyn Protocol>,
    )
    .await;
    reader.receive(None).await.unwrap();
    let backup = reader.backup().await.unwrap();
    manager.deny(&[7; 32]).await.unwrap();
    let now = w.clock.now_ms();
    w.switch.push_missed(2, now, now);
    *kinds.sample.failing.lock().unwrap() = 1;
    reader.receive(None).await.unwrap();
    assert_eq!(reader.owed_protocol_calls().await.unwrap(), 1);
    drop(reader);
    kinds.log.lock().unwrap().clear();
    let mut restored = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&kinds) as Arc<dyn Protocol>,
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.end_reconcile(UserConfirmed::new()).await.ok();
    for _ in 0..2 {
        let _ = restored.receive(None).await;
    }
    let log = kinds.log.lock().unwrap().clone();
    assert!(log.windows(2).all(|pair| pair[0].1 <= pair[1].1), "{log:?}");
}

/// A reader, on `store`, whose last two deny list changes for `x` come after its backup,
/// the second owed: `x` denied, then undenied, or, with `denied_at_end`, undenied (denied
/// before the backup), then denied. It is restored in place from that backup, its
/// reconcile ended, not read yet. With the second change's seq.
async fn restored_with_a_carried_deny_change(
    w: &World,
    store: &Arc<MemoryStore>,
    kinds: &Arc<KindsProtocol>,
    x: [u8; 32],
    denied_at_end: bool,
) -> (App, u64) {
    let mut manager = manager_of(w).await;
    let mut reader = join_with(
        w,
        "reader",
        &[Permission::ListsRead],
        Arc::clone(store),
        Arc::clone(kinds) as Arc<dyn Protocol>,
    )
    .await;
    reader.receive(None).await.unwrap();
    if denied_at_end {
        manager.deny(&x).await.unwrap();
        reader.receive(None).await.unwrap();
    }
    let backup = reader.backup().await.unwrap();
    if denied_at_end {
        manager.undeny(&x).await.unwrap();
    } else {
        manager.deny(&x).await.unwrap();
    }
    reader.receive(None).await.unwrap();
    if denied_at_end {
        manager.deny(&x).await.unwrap();
    } else {
        manager.undeny(&x).await.unwrap();
    }
    *kinds.sample.failing_deny.lock().unwrap() = 1;
    reader.receive(None).await.unwrap();
    assert_eq!(reader.owed_protocol_calls().await.unwrap(), 1);
    assert_eq!(
        reader.lists_copy().await.unwrap().deny.contains(&x),
        denied_at_end
    );
    let seq = reader.cursor().seq;
    drop(reader);
    let mut restored = App::restore(
        w.env_on(Arc::clone(store) as Arc<dyn StateStore>),
        Arc::clone(kinds) as Arc<dyn Protocol>,
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.end_reconcile(UserConfirmed::new()).await.ok();
    (restored, seq)
}

/// After the restored reader's reads: nothing owed, the copy of the lists and the
/// protocol's state agree on `x`, and the protocol was handed the deny list changes in
/// feed order, the carried one at `seq` last.
async fn assert_carried_deny_change_taken(
    restored: &App,
    kinds: &KindsProtocol,
    x: [u8; 32],
    seq: u64,
    denied_at_end: bool,
) {
    assert_eq!(restored.owed_protocol_calls().await.unwrap(), 0);
    let log = kinds.log.lock().unwrap().clone();
    assert_eq!(
        restored.lists_copy().await.unwrap().deny.contains(&x),
        denied_at_end,
        "the copy of the lists; log {log:?}"
    );
    let handed = restored
        .protocol_get(format!("deny/{seq}").as_bytes())
        .await
        .unwrap();
    assert_eq!(handed, Some(vec![u8::from(denied_at_end)]), "{log:?}");
    let denies: Vec<u64> = log
        .iter()
        .filter(|(kind, _)| *kind == "deny")
        .map(|(_, seq)| *seq)
        .collect();
    assert!(denies.windows(2).all(|pair| pair[0] <= pair[1]), "{log:?}");
    assert_eq!(denies.last(), Some(&seq), "{log:?}");
}

#[tokio::test]
async fn test_deny_list_carried_change_keeps_the_copy_of_the_lists_right() {
    // Deny, then an undeny the protocol couldn't take, carried by a restore in place from
    // a backup before both: the feed hands the deny again and the queue the undeny, and the
    // copy of the lists, which admission works from, ends with the undeny too.
    let w = World::new();
    let store = Arc::new(MemoryStore::new());
    let kinds = Arc::new(KindsProtocol::default());
    let x = [7; 32];
    let (mut restored, seq) =
        restored_with_a_carried_deny_change(&w, &store, &kinds, x, false).await;
    for _ in 0..4 {
        restored.receive(None).await.unwrap();
    }
    assert_carried_deny_change_taken(&restored, &kinds, x, seq, false).await;
}

#[tokio::test]
async fn test_deny_list_carried_change_keeps_the_copy_of_the_lists_right_for_a_deny() {
    // The mirror case: an undeny, then a deny the protocol couldn't take. The copy ends
    // with the pubky denied, as the service and the protocol have it.
    let w = World::new();
    let store = Arc::new(MemoryStore::new());
    let kinds = Arc::new(KindsProtocol::default());
    let x = [7; 32];
    let (mut restored, seq) =
        restored_with_a_carried_deny_change(&w, &store, &kinds, x, true).await;
    for _ in 0..4 {
        restored.receive(None).await.unwrap();
    }
    assert_carried_deny_change_taken(&restored, &kinds, x, seq, true).await;
}

/// The restored reader's reads after a restore in place.
async fn carried_deny_change_reads(app: &mut App) -> Result<(), AppError> {
    for _ in 0..4 {
        app.receive(None).await?;
    }
    Ok(())
}

/// A reader, on `store`, restored in place from an older backup, where the deny list
/// change at seq b for `x` fails and is owed, then from a newer backup, taken after b and a
/// later change c for `x`: the newer backup's cursor is past both, and the owed call is
/// carried behind it. With `denied_at_end`, b undenies and c denies again; without, b
/// denies and c undenies. The restored app, its reconcile ended, not read yet; the
/// protocol's log is cleared.
async fn restored_from_a_newer_backup(
    w: &World,
    store: &Arc<MemoryStore>,
    kinds: &Arc<KindsProtocol>,
    x: [u8; 32],
    denied_at_end: bool,
) -> App {
    let mut manager = manager_of(w).await;
    let mut reader = join_with(
        w,
        "reader",
        &[Permission::ListsRead],
        Arc::clone(store),
        Arc::clone(kinds) as Arc<dyn Protocol>,
    )
    .await;
    reader.receive(None).await.unwrap();
    manager.deny(&x).await.unwrap();
    if !denied_at_end {
        manager.undeny(&x).await.unwrap();
    }
    reader.receive(None).await.unwrap();
    let older = reader.backup().await.unwrap();
    if denied_at_end {
        manager.undeny(&x).await.unwrap();
        manager.deny(&x).await.unwrap();
    } else {
        manager.deny(&x).await.unwrap();
        manager.undeny(&x).await.unwrap();
    }
    reader.receive(None).await.unwrap();
    assert_eq!(
        reader.lists_copy().await.unwrap().deny.contains(&x),
        denied_at_end
    );
    let newer = reader.backup().await.unwrap();
    drop(reader);
    let restore = async |backup: &crate::app::AppBackup| {
        let mut restored = App::restore(
            w.env_on(Arc::clone(store) as Arc<dyn StateStore>),
            Arc::clone(kinds) as Arc<dyn Protocol>,
            World::config(),
            backup,
        )
        .await
        .unwrap();
        restored.end_reconcile(UserConfirmed::new()).await.ok();
        restored
    };
    let mut restored = restore(&older).await;
    *kinds.sample.failing_deny.lock().unwrap() = 1;
    for _ in 0..4 {
        let _ = restored.receive(None).await;
        if restored.owed_protocol_calls().await.unwrap() == 1 {
            break;
        }
    }
    assert_eq!(restored.owed_protocol_calls().await.unwrap(), 1);
    drop(restored);
    kinds.log.lock().unwrap().clear();
    restore(&newer).await
}

/// After the reads of a reader restored from the newer backup: nothing owed, no deny list
/// change handed, the copy of the lists as the service has `x`, and the protocol's latest
/// deny list gap with the same.
async fn assert_behind_the_cursor_taken_as_a_gap(
    restored: &App,
    kinds: &KindsProtocol,
    x: [u8; 32],
    denied_at_end: bool,
) {
    assert_eq!(restored.owed_protocol_calls().await.unwrap(), 0);
    let log = kinds.log.lock().unwrap().clone();
    assert!(
        !log.iter().any(|(kind, _)| *kind == "deny"),
        "the older change is handed after the newer one: {log:?}"
    );
    assert_eq!(
        restored.lists_copy().await.unwrap().deny.contains(&x),
        denied_at_end,
        "the copy of the lists; log {log:?}"
    );
    let gaps = kinds.sample.deny_gaps.lock().unwrap().clone();
    assert_eq!(
        gaps.last().map(|gap| gap.denied.contains(&x)),
        Some(denied_at_end),
        "{log:?}"
    );
}

#[tokio::test]
async fn test_deny_list_owed_undeny_behind_a_newer_backup_keeps_the_copy_denied() {
    // The owed undeny is older than the deny the newer backup's cursor is past: the copy,
    // which admission works from, still denies, and the protocol learns the list by a
    // gap, never the older change after the newer one.
    let w = World::new();
    let store = Arc::new(MemoryStore::new());
    let kinds = Arc::new(KindsProtocol::default());
    let x = [7; 32];
    let mut restored = restored_from_a_newer_backup(&w, &store, &kinds, x, true).await;
    for _ in 0..4 {
        restored.receive(None).await.unwrap();
    }
    assert_behind_the_cursor_taken_as_a_gap(&restored, &kinds, x, true).await;
}

#[tokio::test]
async fn test_deny_list_owed_deny_behind_a_newer_backup_keeps_the_copy_undenied() {
    let w = World::new();
    let store = Arc::new(MemoryStore::new());
    let kinds = Arc::new(KindsProtocol::default());
    let x = [7; 32];
    let mut restored = restored_from_a_newer_backup(&w, &store, &kinds, x, false).await;
    for _ in 0..4 {
        restored.receive(None).await.unwrap();
    }
    assert_behind_the_cursor_taken_as_a_gap(&restored, &kinds, x, false).await;
}

#[tokio::test]
async fn test_deny_list_owed_change_behind_the_cursor_crash_at_each_commit_point_ends_right() {
    // A crash at each commit of the reads after the newer restore, before or after it,
    // then a restart on what the store holds: the change behind the cursor becomes the gap
    // once, and the copy and the protocol end as the service has it.
    let x = [7; 32];
    for denied_at_end in [false, true] {
        let commits = {
            let w = World::new();
            let store = Arc::new(MemoryStore::new());
            let kinds = Arc::new(KindsProtocol::default());
            let restored = restored_from_a_newer_backup(&w, &store, &kinds, x, denied_at_end).await;
            let id = restored.app_id();
            drop(restored);
            let counting = Arc::new(FaultStore::new(
                Arc::clone(&store) as Arc<dyn StateStore>,
                StoreFault::None,
            ));
            let mut app = App::load(
                w.env_on(Arc::clone(&counting) as Arc<dyn StateStore>),
                Arc::clone(&kinds) as Arc<dyn Protocol>,
                World::config(),
                id,
            )
            .await
            .unwrap();
            carried_deny_change_reads(&mut app).await.unwrap();
            counting.commits()
        };
        assert!(commits > 2, "the reads commit {commits} times");
        for stop_after in [false, true] {
            for n in 1..=commits {
                let w = World::new();
                let store = Arc::new(MemoryStore::new());
                let kinds = Arc::new(KindsProtocol::default());
                let restored =
                    restored_from_a_newer_backup(&w, &store, &kinds, x, denied_at_end).await;
                let id = restored.app_id();
                drop(restored);
                let fault = Arc::new(FaultStore::new(
                    Arc::clone(&store) as Arc<dyn StateStore>,
                    if stop_after {
                        StoreFault::StopAfter(n)
                    } else {
                        StoreFault::StopBefore(n)
                    },
                ));
                if let Ok(mut app) = App::load(
                    w.env_on(Arc::clone(&fault) as Arc<dyn StateStore>),
                    Arc::clone(&kinds) as Arc<dyn Protocol>,
                    World::config(),
                    id,
                )
                .await
                {
                    let _ = carried_deny_change_reads(&mut app).await;
                }
                assert!(fault.stopped(), "commit {n} of {commits} is reached");
                let mut app = App::load(
                    w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
                    Arc::clone(&kinds) as Arc<dyn Protocol>,
                    World::config(),
                    id,
                )
                .await
                .unwrap();
                carried_deny_change_reads(&mut app)
                    .await
                    .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
                assert_behind_the_cursor_taken_as_a_gap(&app, &kinds, x, denied_at_end).await;
            }
        }
    }
}

#[tokio::test]
async fn test_deny_list_carried_change_crash_at_each_commit_point_keeps_the_copy_right() {
    // A crash at each commit of the restored reader's reads, before or after it, then a
    // restart on what the store holds: the copy of the lists and the protocol's state end
    // the same, and nothing stays owed.
    let x = [7; 32];
    for denied_at_end in [false, true] {
        let commits = {
            let w = World::new();
            let store = Arc::new(MemoryStore::new());
            let kinds = Arc::new(KindsProtocol::default());
            let (restored, _) =
                restored_with_a_carried_deny_change(&w, &store, &kinds, x, denied_at_end).await;
            let id = restored.app_id();
            drop(restored);
            let counting = Arc::new(FaultStore::new(
                Arc::clone(&store) as Arc<dyn StateStore>,
                StoreFault::None,
            ));
            let mut app = App::load(
                w.env_on(Arc::clone(&counting) as Arc<dyn StateStore>),
                Arc::clone(&kinds) as Arc<dyn Protocol>,
                World::config(),
                id,
            )
            .await
            .unwrap();
            carried_deny_change_reads(&mut app).await.unwrap();
            counting.commits()
        };
        assert!(commits > 2, "the reads commit {commits} times");
        for stop_after in [false, true] {
            for n in 1..=commits {
                let w = World::new();
                let store = Arc::new(MemoryStore::new());
                let kinds = Arc::new(KindsProtocol::default());
                let (restored, seq) =
                    restored_with_a_carried_deny_change(&w, &store, &kinds, x, denied_at_end).await;
                let id = restored.app_id();
                drop(restored);
                let fault = Arc::new(FaultStore::new(
                    Arc::clone(&store) as Arc<dyn StateStore>,
                    if stop_after {
                        StoreFault::StopAfter(n)
                    } else {
                        StoreFault::StopBefore(n)
                    },
                ));
                if let Ok(mut app) = App::load(
                    w.env_on(Arc::clone(&fault) as Arc<dyn StateStore>),
                    Arc::clone(&kinds) as Arc<dyn Protocol>,
                    World::config(),
                    id,
                )
                .await
                {
                    let _ = carried_deny_change_reads(&mut app).await;
                }
                assert!(fault.stopped(), "commit {n} of {commits} is reached");
                let mut app = App::load(
                    w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
                    Arc::clone(&kinds) as Arc<dyn Protocol>,
                    World::config(),
                    id,
                )
                .await
                .unwrap();
                carried_deny_change_reads(&mut app)
                    .await
                    .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
                assert_carried_deny_change_taken(&app, &kinds, x, seq, denied_at_end).await;
            }
        }
    }
}

/// A reader that owes a missed-entries call past its backup's cursor, after a deny list
/// change it was handed, restored in place from that backup and then following `changes`
/// key changes in place, read after each; the first `failing_deny` deny list changes its
/// protocol is handed after the restore fail. The protocol's log since the restore.
async fn owed_across_a_restore_and_key_changes(
    changes: u64,
    failing_deny: u32,
) -> Vec<(&'static str, u64)> {
    let w = World::new();
    let router = super::moves::Router::of(&w);
    let mut manager = manager_of(&w).await;
    let store = Arc::new(MemoryStore::new());
    let kinds = Arc::new(KindsProtocol::default());
    let request = w
        .signer
        .approve(
            &app_keys("reader"),
            &AppSpec::new(&["scope-a"]).with_permissions(&[Permission::ListsRead]),
        )
        .unwrap();
    let mut reader = App::join(
        router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&kinds) as Arc<dyn Protocol>,
        World::config(),
        request,
    )
    .await
    .unwrap();
    reader.receive(None).await.unwrap();
    let backup = reader.backup().await.unwrap();
    manager.deny(&[7; 32]).await.unwrap();
    let now = w.clock.now_ms();
    w.switch.push_missed(2, now, now);
    *kinds.sample.failing.lock().unwrap() = 1;
    reader.receive(None).await.unwrap();
    assert_eq!(reader.owed_protocol_calls().await.unwrap(), 1);
    drop(reader);
    kinds.log.lock().unwrap().clear();
    let mut restored = App::restore(
        router.env(&w, Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&kinds) as Arc<dyn Protocol>,
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored.end_reconcile(UserConfirmed::new()).await.ok();
    *kinds.sample.failing_deny.lock().unwrap() = failing_deny;
    let mut switch = Arc::clone(&w.switch);
    for n in 0..changes {
        let generation = n + 2;
        let key = ed25519_dalek::SigningKey::from_bytes(&seed(&format!("service/change/{n}")));
        let changed = switch.change_key_into(key.to_bytes());
        router.add(crate::testing::SWITCH_ORIGIN, &changed);
        super::moves::publish_at(
            &w,
            &changed,
            Inbox::new(
                crate::testing::SWITCH_ORIGIN,
                key.verifying_key().to_bytes(),
            ),
            generation,
            None,
        );
        switch = changed;
        for _ in 0..3 {
            let _ = restored.receive(None).await;
        }
        assert_eq!(restored.cursor().generation, generation);
    }
    assert_eq!(restored.owed_protocol_calls().await.unwrap(), 0);
    kinds.log.lock().unwrap().clone()
}

#[tokio::test]
async fn test_deny_list_owed_calls_keep_feed_order_across_a_restore_and_a_key_change() {
    // A key change in place continues the sequence: the call carried past the backup's
    // cursor still waits for the feed to reach its item at the next generation.
    let log = owed_across_a_restore_and_key_changes(1, 0).await;
    assert_eq!(
        log.iter().map(|e| e.0).collect::<Vec<_>>(),
        ["deny", "missed"]
    );
    assert!(log.windows(2).all(|pair| pair[0].1 < pair[1].1), "{log:?}");
}

#[tokio::test]
async fn test_deny_list_owed_calls_keep_feed_order_across_a_restore_and_two_key_changes() {
    let log = owed_across_a_restore_and_key_changes(2, 0).await;
    assert_eq!(
        log.iter().map(|e| e.0).collect::<Vec<_>>(),
        ["deny", "missed"]
    );
    assert!(log.windows(2).all(|pair| pair[0].1 < pair[1].1), "{log:?}");
}

#[tokio::test]
async fn test_deny_list_owed_calls_of_two_generations_are_made_in_feed_order() {
    // The deny list change fails at the next generation and is owed there, before the call
    // carried from the earlier one: the queue makes them in feed order, not by generation.
    let log = owed_across_a_restore_and_key_changes(1, 1).await;
    assert_eq!(
        log.iter().map(|e| e.0).collect::<Vec<_>>(),
        ["deny", "missed"]
    );
    assert!(log.windows(2).all(|pair| pair[0].1 < pair[1].1), "{log:?}");
}

#[tokio::test]
async fn test_deny_list_owed_call_of_a_generation_not_followed_yet_waits() {
    // A call keyed at a generation past the newest identity.json the app holds, as a
    // restore in place may carry from a store that went further: its sequence isn't known
    // yet, so it isn't taken as behind the cursor and made early; it waits.
    let w = World::new();
    let store = Arc::new(MemoryStore::new());
    let kinds = Arc::new(KindsProtocol::default());
    let mut reader = join_with(
        &w,
        "reader",
        &[Permission::ListsRead],
        Arc::clone(&store),
        Arc::clone(&kinds) as Arc<dyn Protocol>,
    )
    .await;
    reader.receive(None).await.unwrap();
    assert!(reader.cursor().seq > 1);
    let call = crate::app::feed::OwedCall::Missed {
        seq: 1,
        entries: 1,
        accepted_from_ms: 5,
        accepted_until_ms: 6,
    };
    let mut tx = reader.tx().unwrap();
    tx.put(&crate::app::state::key::owed(5, 1), &call).unwrap();
    reader.commit(tx).await.unwrap();
    let _ = reader.receive(None).await;
    assert_eq!(reader.owed_protocol_calls().await.unwrap(), 1);
    assert!(kinds.log.lock().unwrap().is_empty());
}

/// A reader restored from `backup` into a store of its own, with `protocol`, read twice.
async fn restored_reader(
    w: &World,
    backup: &crate::app::AppBackup,
    protocol: Arc<SampleProtocol>,
) -> App {
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        protocol as Arc<dyn Protocol>,
        World::config(),
        backup,
    )
    .await
    .unwrap();
    restored.end_reconcile(UserConfirmed::new()).await.ok();
    for _ in 0..2 {
        let _ = restored.receive(None).await;
    }
    restored
}

/// Whether `protocol` learned that `pubky` is denied: by the change, or by a gap's list.
fn learned_denied(protocol: &SampleProtocol, pubky: [u8; 32]) -> bool {
    denies(protocol).contains(&(pubky, true))
        || protocol
            .deny_gaps
            .lock()
            .unwrap()
            .iter()
            .any(|gap| gap.denied.contains(&pubky))
}

#[tokio::test]
async fn test_deny_list_change_by_a_writer_revoked_since_is_not_lost() {
    // A genuine change by a manager revoked since: a restored reader holds no certificate
    // of it and the directory no longer lists it, so the change can't be verified. The
    // protocol still learns the pubky is denied, by the change or by a gap.
    let w = World::new();
    let mut manager = manager_of(&w).await;
    let mut reader = join_holding(&w, "reader", &[Permission::ListsRead]).await;
    reader.receive(None).await.unwrap();
    let backup = reader.backup().await.unwrap();
    let x = [7; 32];
    manager.deny(&x).await.unwrap();
    w.switch.revoke(manager.app_id()).unwrap();
    let protocol = Arc::new(SampleProtocol::default());
    let restored = restored_reader(&w, &backup, Arc::clone(&protocol)).await;
    assert!(
        restored.lists_copy().await.unwrap().deny.contains(&x),
        "the copy lacks it"
    );
    assert!(
        learned_denied(&protocol, x),
        "denies {:?}, gaps {:?}",
        denies(&protocol),
        protocol.deny_gaps.lock().unwrap()
    );
}

#[tokio::test]
async fn test_deny_list_change_whose_writer_lookup_fails_is_not_lost() {
    // The one directory read for an unknown writer fails for now: the change isn't lost.
    let w = World::new();
    let mut manager = manager_of(&w).await;
    let store = Arc::new(MemoryStore::new());
    let protocol = Arc::new(SampleProtocol::default());
    let mut reader = join_with(
        &w,
        "reader",
        &[Permission::ListsRead],
        Arc::clone(&store),
        Arc::clone(&protocol) as Arc<dyn Protocol>,
    )
    .await;
    reader.receive(None).await.unwrap();
    let x = [7; 32];
    manager.deny(&x).await.unwrap();
    // The reader holds no certificate of the manager.
    let ns = crate::store::client_namespace(&reader.app_id());
    let mut batch = crate::store::WriteBatch::new();
    batch.delete_prefix(&ns, b"ocert/".to_vec()).unwrap();
    store.commit(batch).unwrap();
    drop(reader);
    let mut reader = App::load(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&protocol) as Arc<dyn Protocol>,
        World::config(),
        app_keys("reader").app_id_bytes(),
    )
    .await
    .unwrap();
    w.switch.fail_next(Fault::Unreachable {
        path: "/directory".into(),
        after: 0,
    });
    let mut errors = Vec::new();
    for _ in 0..3 {
        if let Err(error) = reader.receive(None).await {
            errors.push(error.to_string());
        }
    }
    assert!(
        learned_denied(&protocol, x),
        "denies {:?}, errors {errors:?}, copy {:?}",
        denies(&protocol),
        reader.lists_copy().await.unwrap().deny
    );
}

/// A reader owing a deny list change for `x` not checked yet: it holds no certificate of
/// the manager, and the directory read for it failed. With its protocol.
async fn reader_owing_an_unchecked_deny_change(
    w: &World,
    x: [u8; 32],
) -> (App, Arc<SampleProtocol>) {
    let mut manager = manager_of(w).await;
    let store = Arc::new(MemoryStore::new());
    let protocol = Arc::new(SampleProtocol::default());
    let mut reader = join_with(
        w,
        "reader",
        &[Permission::ListsRead],
        Arc::clone(&store),
        Arc::clone(&protocol) as Arc<dyn Protocol>,
    )
    .await;
    reader.receive(None).await.unwrap();
    manager.deny(&x).await.unwrap();
    let ns = crate::store::client_namespace(&reader.app_id());
    let mut batch = crate::store::WriteBatch::new();
    batch.delete_prefix(&ns, b"ocert/".to_vec()).unwrap();
    store.commit(batch).unwrap();
    drop(reader);
    let mut reader = App::load(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&protocol) as Arc<dyn Protocol>,
        World::config(),
        app_keys("reader").app_id_bytes(),
    )
    .await
    .unwrap();
    w.switch.fail_next(Fault::Unreachable {
        path: "/directory".into(),
        after: 0,
    });
    let _ = reader.receive(None).await;
    let owed = reader
        .reader()
        .scan::<crate::app::feed::OwedCall>(crate::app::state::key::OWED_PREFIX)
        .await
        .unwrap();
    assert!(
        matches!(
            owed.as_slice(),
            [(_, crate::app::feed::OwedCall::DenyUnverified { .. })]
        ),
        "{owed:?}"
    );
    (reader, protocol)
}

/// The reader's owed deny list change not checked yet, rewritten by `edit`, then a read:
/// it fails closed, as a corrupt store, and nothing is handed, applied or dropped.
async fn assert_edited_unchecked_deny_change_fails_closed(
    edit: impl FnOnce(&mut crate::app::feed::OwedCall),
) {
    let w = World::new();
    let x = [7; 32];
    let (mut reader, protocol) = reader_owing_an_unchecked_deny_change(&w, x).await;
    let owed = reader
        .reader()
        .scan::<crate::app::feed::OwedCall>(crate::app::state::key::OWED_PREFIX)
        .await
        .unwrap();
    let [(rest, mut call)] = <[_; 1]>::try_from(owed).unwrap();
    edit(&mut call);
    let mut tx = reader.tx().unwrap();
    tx.put(
        &format!("{}{rest}", crate::app::state::key::OWED_PREFIX),
        &call,
    )
    .unwrap();
    reader.commit(tx).await.unwrap();
    let read = reader.receive(None).await;
    assert!(
        matches!(
            read,
            Err(AppError::Store(crate::error::StoreError::Corrupt))
        ),
        "{read:?}"
    );
    assert_eq!(reader.owed_protocol_calls().await.unwrap(), 1);
    assert!(denies(&protocol).is_empty());
    assert!(!reader.lists_copy().await.unwrap().deny.contains(&[8; 32]));
}

#[tokio::test]
async fn test_deny_list_owed_change_whose_operation_does_not_parse_fails_closed() {
    assert_edited_unchecked_deny_change_fails_closed(|call| {
        if let crate::app::feed::OwedCall::DenyUnverified { op, .. } = call {
            op.body = "not an operation".into();
        }
    })
    .await;
}

#[tokio::test]
async fn test_deny_list_owed_change_other_than_its_operation_fails_closed() {
    // The change kept beside the operation names another pubky than the operation does.
    assert_edited_unchecked_deny_change_fails_closed(|call| {
        if let crate::app::feed::OwedCall::DenyUnverified { pubky, .. } = call {
            *pubky = [8; 32];
        }
    })
    .await;
}

#[tokio::test]
async fn test_app_owed_call_whose_key_names_no_position_fails_closed() {
    // Every owed call is keyed by its feed position; one whose key names none has no place
    // in feed order: the read fails as on a corrupt store, and the call is neither made
    // nor dropped.
    let w = World::new();
    let mut app = w.join("wallet").await;
    app.receive(None).await.unwrap();
    let call = crate::app::feed::OwedCall::Missed {
        seq: 1,
        entries: 1,
        accepted_from_ms: 5,
        accepted_until_ms: 6,
    };
    let mut tx = app.tx().unwrap();
    tx.put(
        &format!("{}not-a-position", crate::app::state::key::OWED_PREFIX),
        &call,
    )
    .unwrap();
    app.commit(tx).await.unwrap();
    let read = app.receive(None).await;
    assert!(
        matches!(
            read,
            Err(AppError::Store(crate::error::StoreError::Corrupt))
        ),
        "{read:?}"
    );
    assert!(w.protocol.missed.lock().unwrap().is_empty());
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 1);
}

#[tokio::test]
async fn test_deny_list_gap_waits_no_longer_than_the_lists_refresh() {
    // A gap is told with the lists read after it. While the copy of the lists waits out
    // its day after one too large for a commit, the read stays held, the feed unread.
    let w = World::new();
    w.switch.set_retention(Some(crate::testing::Retention {
        checkpoint_behind: 3,
        ..crate::testing::Retention::default()
    }));
    let mut wallet = join_with(
        &w,
        "wallet",
        &[Permission::ListsRead, Permission::ListsManage],
        Arc::new(MemoryStore::new()),
        Arc::new(SampleProtocol::default()) as Arc<dyn Protocol>,
    )
    .await;
    wallet.receive(None).await.unwrap();
    let backup = wallet.backup().await.unwrap();
    for i in 1..=5u8 {
        wallet.deny(&[i; 32]).await.unwrap();
    }
    w.note(wallet.app_id(), "past");
    wallet.receive(None).await.unwrap();
    wallet.deny(&[0xee; 32]).await.unwrap();
    assert!(w.switch.retained().1 > 0, "nothing dropped");
    drop(wallet);
    let store = Arc::new(MemoryStore::new());
    let protocol = Arc::new(SampleProtocol::default());
    let mut restored = App::restore(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&protocol) as Arc<dyn Protocol>,
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    // The copy of the lists was refused as too large just now.
    let ns = crate::store::client_namespace(&restored.app_id());
    let mut batch = crate::store::WriteBatch::new();
    batch
        .put(
            &ns,
            b"lc/too_large".to_vec(),
            crate::app::state::encode(&w.clock.now_ms()).unwrap(),
        )
        .unwrap();
    store.commit(batch).unwrap();
    let after_note = w.note(restored.app_id(), "after the gap").0;
    let mut stopped = 0;
    for _ in 0..5 {
        if restored.receive(None).await.unwrap().stopped {
            stopped += 1;
        }
    }
    let received: Vec<u64> = protocol
        .received
        .lock()
        .unwrap()
        .iter()
        .map(|(seq, _, _)| *seq)
        .collect();
    assert!(
        received.contains(&after_note),
        "{stopped} of 5 reads stopped, received {received:?}, gaps {:?}",
        protocol.deny_gaps.lock().unwrap()
    );
}

#[tokio::test]
async fn test_deny_list_gap_told_after_an_older_owed_change() {
    // A deny list change owed from before a gap, behind the cursor, as a provider loss
    // leaves it once the cursor follows the next sequence (the loss notes the gap whatever
    // is owed): the gap's list is the newer state, so the older change is never handed
    // after it. Behind the cursor, it is covered by the gap and not handed at all.
    let w = World::new();
    let mut manager = manager_of(&w).await;
    let store = Arc::new(MemoryStore::new());
    let kinds = Arc::new(KindsProtocol::default());
    let mut reader = join_with(
        &w,
        "reader",
        &[Permission::ListsRead],
        Arc::clone(&store),
        Arc::clone(&kinds) as Arc<dyn Protocol>,
    )
    .await;
    let a = [7; 32];
    manager.deny(&a).await.unwrap();
    reader.receive(None).await.unwrap();
    let put_at = denies(&kinds.sample)[0];
    let change = kinds.sample.denies.lock().unwrap()[0].clone();
    assert_eq!(put_at, (a, true));
    manager.undeny(&a).await.unwrap();
    reader.receive(None).await.unwrap();
    let through = reader.cursor();
    drop(reader);
    kinds.log.lock().unwrap().clear();
    // The deny owed, and a gap after the undeny noted, in the store.
    let ns = crate::store::client_namespace(&app_keys("reader").app_id_bytes());
    let owed = crate::app::feed::OwedCall::Deny {
        generation: change.generation,
        seq: change.seq,
        pubky: a,
        added: true,
        at_ms: change.at_ms,
    };
    let mut batch = crate::store::WriteBatch::new();
    batch
        .put(
            &ns,
            crate::app::state::key::owed(change.generation, change.seq).into_bytes(),
            crate::app::state::encode(&owed).unwrap(),
        )
        .unwrap();
    batch
        .put(
            &ns,
            crate::app::feed::DENY_GAP.as_bytes().to_vec(),
            crate::app::state::encode(&(through.generation, through.seq)).unwrap(),
        )
        .unwrap();
    batch
        .delete(&ns, crate::app::admission::LISTS_AT.as_bytes().to_vec())
        .unwrap();
    store.commit(batch).unwrap();
    let mut reader = App::load(
        w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&kinds) as Arc<dyn Protocol>,
        World::config(),
        app_keys("reader").app_id_bytes(),
    )
    .await
    .unwrap();
    reader.receive(None).await.unwrap();
    let log = kinds.log.lock().unwrap().clone();
    assert_eq!(log, [("gap", through.seq)]);
    assert_eq!(reader.owed_protocol_calls().await.unwrap(), 0);
    assert!(!reader.lists_copy().await.unwrap().deny.contains(&a));
}

#[tokio::test]
async fn test_deny_list_owed_call_past_a_held_entry_keeps_the_entry() {
    // A note held for two reads, then a missed item whose call fails once: the call is owed
    // past the held note. The note is still handed once the protocol takes it, the cursor
    // never passing it before.
    let w = World::new();
    let kinds = Arc::new(KindsProtocol::default());
    let mut reader = join_with(
        &w,
        "reader",
        &[Permission::ListsRead, Permission::ConversationAdd],
        Arc::new(MemoryStore::new()),
        Arc::clone(&kinds) as Arc<dyn Protocol>,
    )
    .await;
    reader.receive(None).await.unwrap();
    *kinds.retries.lock().unwrap() = 2;
    let note = w.note(reader.app_id(), "held").0;
    let now = w.clock.now_ms();
    let missed = w.switch.push_missed(2, now, now);
    *kinds.sample.failing.lock().unwrap() = 1;
    for _ in 0..6 {
        let _ = reader.receive(None).await;
    }
    let log = kinds.log.lock().unwrap().clone();
    assert!(
        log.contains(&("message", note)),
        "note {note}, missed {missed}, cursor {:?}, log {log:?}",
        reader.cursor()
    );
}

#[tokio::test]
async fn test_deny_list_gap_answered_unavailable_waits_for_the_list() {
    // The lists read for a gap answered `503 unavailable` for now: the gap waits for an
    // answer that gives the list, rather than going without it.
    let w = World::new();
    w.switch.set_retention(Some(crate::testing::Retention {
        checkpoint_behind: 3,
        ..crate::testing::Retention::default()
    }));
    let mut wallet = join_with(
        &w,
        "wallet",
        &[Permission::ListsRead, Permission::ListsManage],
        Arc::new(MemoryStore::new()),
        Arc::new(SampleProtocol::default()) as Arc<dyn Protocol>,
    )
    .await;
    wallet.receive(None).await.unwrap();
    let backup = wallet.backup().await.unwrap();
    for i in 1..=5u8 {
        wallet.deny(&[i; 32]).await.unwrap();
    }
    w.note(wallet.app_id(), "past");
    wallet.receive(None).await.unwrap();
    wallet.deny(&[0xee; 32]).await.unwrap();
    assert!(w.switch.retained().1 > 0, "nothing dropped");
    drop(wallet);
    let protocol = Arc::new(SampleProtocol::default());
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        Arc::clone(&protocol) as Arc<dyn Protocol>,
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    // The first read meets the gap and notes it; the next reads the lists for it.
    let _ = restored.receive(None).await;
    w.switch.fail_next(Fault::Error {
        path: "/allow".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    for _ in 0..3 {
        let _ = restored.receive(None).await;
    }
    let gaps = protocol.deny_gaps.lock().unwrap().clone();
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    assert!(gaps[0].list_read, "{gaps:?}");
    assert!(gaps[0].denied.contains(&[1; 32]), "{gaps:?}");
}
