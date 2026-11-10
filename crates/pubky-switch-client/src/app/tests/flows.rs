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
    Alarm, AppBackup, AppError, AppEvent, IdentityRefresh, LeaveMode, LeaveReport, ParkReason,
    REVALIDATION_MS, Refusal, UserConfirmed,
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
    // The app rotates before reading the thief's registration: `409 conflict` names it.
    let error = app.rotate().await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Alarm(Alarm::Compromise {
                n: 1,
                distrust_from: None
            })
        ),
        "{error:?}"
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
        AppEvent::Parked { seq, reason: ParkReason::Unverifiable } if *seq == held
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
        AppEvent::Parked { seq: s, reason: ParkReason::Quota } if *s == seq
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
    value["v"] = json!(2);
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
        AppEvent::Parked { seq, reason: ParkReason::Refused } if *seq == refused
    )));
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

    fn resend_needed(&self, needed: &ResendNeeded) -> Vec<LocalWrite> {
        self.0.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Vec<LocalWrite> {
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
            AppEvent::Parked { seq: s, reason: ParkReason::TooManyOperations } if *s == seq
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
