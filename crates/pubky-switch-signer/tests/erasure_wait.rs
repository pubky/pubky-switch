//! The erasure's wait for the operator's `404` to hold, after a request in doubt (Switch wire
//! 7.4.16, spec 12.7 step 5): what counts, what ends it, and what the signer sends meanwhile.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use common::*;
use pubky_switch_client::clock::Clock;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::Fault as SwitchFault;
use pubky_switch_client::transport::{MockTransport, Response};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::app_record_path;
use pubky_switch_signer::{Alert, Refusal, Signer, SignerError, SignerStatus, UserConfirmed};

const H: u64 = 3_600_000;

fn confirmed() -> UserConfirmed {
    UserConfirmed::shown_and_confirmed()
}

async fn with_an_app(world: &World) -> (Signer, [u8; 16], Arc<MemoryStore>) {
    let (mut signer, store) = world.enrolled().await;
    let app = App::with_keys(
        AppKeys::from_secrets([3; 32], [4; 32]),
        &["notes"],
        None,
        [9; 32],
    );
    world.approve(&mut signer, &app).await;
    let id = app.keys.app_id_bytes();
    world
        .homeserver
        .set(&app_record_path(&id), b"the app's record".to_vec());
    (signer, id, store)
}

fn erase_requests(transport: &MockTransport) -> usize {
    transport
        .requests()
        .iter()
        .filter(|r| r.method == "POST" && r.path_and_query.ends_with("/erase"))
        .count()
}

/// A signer whose first erasure request never reached the switch (in doubt), behind an
/// intermediary that answers GET /apps with an unsigned 404 while the flag is set. The
/// first such 404 has been met: erased but unconfirmed since the returned time.
async fn waiting_behind_an_intermediary(
    world: &World,
) -> (Signer, [u8; 16], Arc<AtomicBool>, u64, Arc<MockTransport>) {
    let (signer, id, store) = with_an_app(world).await;
    drop(signer);
    let intermediary = Arc::new(AtomicBool::new(false));
    let answering = Arc::clone(&intermediary);
    let switch = Arc::clone(&world.switch);
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if answering.load(Ordering::SeqCst)
            && request.method == "GET"
            && request.path_and_query.ends_with("/apps")
        {
            return Ok(Response {
                status: 404,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            });
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport.clone();
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(!world.switch.erased());
    intermediary.store(true, Ordering::SeqCst);
    let t0 = world.clock.now_ms();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: t0 })
    );
    (signer, id, intermediary, t0, transport)
}

fn posts(transport: &MockTransport) -> Vec<String> {
    transport
        .requests()
        .iter()
        .filter(|r| r.method != "GET")
        .map(|r| format!("{} {}", r.method, r.path_and_query))
        .collect()
}

#[tokio::test]
async fn test_erasure_wait_signed_check_with_homeserver_down_ends_the_wait() {
    // T0: 404. T0+2h: the switch answers GET /apps signed (the account is there), but the
    // Homeserver is down, so the check fails after the signed read. An answer the pinned key
    // signs ends the wait (12.7 step 5). T0+24h: the intermediary's 404 again: the wait
    // starts again from then, and doesn't conclude.
    let world = World::new();
    let (mut signer, _, intermediary, t0, transport) = waiting_behind_an_intermediary(&world).await;
    world.clock.advance_ms(2 * H);
    intermediary.store(false, Ordering::SeqCst);
    *world.homeserver.down.lock().unwrap() = true;
    signer.resume().await.unwrap_err();
    let signed_get = transport
        .requests()
        .iter()
        .rev()
        .any(|r| r.method == "GET" && r.path_and_query.ends_with("/apps"));
    assert!(signed_get);
    let status_after_signed = signer.status();
    *world.homeserver.down.lock().unwrap() = false;
    intermediary.store(true, Ordering::SeqCst);
    world.clock.advance_ms(22 * H);
    let now = world.clock.now_ms();
    let result = signer.resume().await;
    assert_eq!(
        status_after_signed,
        SignerStatus::Erasing,
        "a signed answer ends the wait (since {t0})"
    );
    assert_eq!(
        result.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: now })
    );
}

#[tokio::test]
async fn test_erasure_wait_signed_error_to_the_check_ends_the_wait() {
    // T0: 404. T0+2h: the switch answers GET /apps with a signed 503, which ends the wait
    // (12.7 step 5). T0+24h: 404 again: the wait starts again, and doesn't conclude.
    let world = World::new();
    let (mut signer, _, intermediary, _t0, _) = waiting_behind_an_intermediary(&world).await;
    world.clock.advance_ms(2 * H);
    intermediary.store(false, Ordering::SeqCst);
    world.switch.fail_next(SwitchFault::Error {
        path: "/apps".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    signer.resume().await.unwrap_err();
    let status_after_signed = signer.status();
    intermediary.store(true, Ordering::SeqCst);
    world.clock.advance_ms(22 * H);
    let now = world.clock.now_ms();
    let result = signer.resume().await;
    assert_eq!(status_after_signed, SignerStatus::Erasing);
    assert_eq!(
        result.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: now })
    );
}

#[tokio::test]
async fn test_erasure_wait_signed_rollback_to_the_check_ends_the_wait() {
    // T0: 404. T0+2h: the switch answers GET /apps signed, with no copy: a rollback alarm,
    // the erasure kept. The answer was signed: the wait ends. T0+24h: 404 again.
    let world = World::new();
    let (mut signer, _, intermediary, _t0, _) = waiting_behind_an_intermediary(&world).await;
    world.clock.advance_ms(2 * H);
    intermediary.store(false, Ordering::SeqCst);
    world.switch.lose_identity();
    signer.resume().await.unwrap_err();
    let status_after_signed = signer.status();
    intermediary.store(true, Ordering::SeqCst);
    world.clock.advance_ms(22 * H);
    let now = world.clock.now_ms();
    let result = signer.resume().await;
    assert_eq!(status_after_signed, SignerStatus::Erasing);
    assert_eq!(
        result.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: now })
    );
}

#[tokio::test]
async fn test_erasure_wait_revoke_during_the_wait_with_a_signed_switch_sends_nothing() {
    // Erased but unconfirmed; the switch answers signed again; the user revokes. Revocations
    // are refused during any erasure, and the signer signs nothing else during the wait (12.7
    // step 5).
    let world = World::new();
    let (mut signer, id, intermediary, _t0, transport) =
        waiting_behind_an_intermediary(&world).await;
    intermediary.store(false, Ordering::SeqCst);
    let before = posts(&transport);
    let error = signer.revoke(id, None, confirmed()).await.unwrap_err();
    let after = posts(&transport);
    assert!(
        matches!(error, SignerError::Refused(Refusal::FlowInProgress)),
        "{error:?}"
    );
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|a| matches!(a, Alert::RevocationPending { .. })),
        "nothing kept"
    );
    assert_eq!(after.len(), before.len(), "nothing sent but reads");
}

#[tokio::test]
async fn test_erasure_wait_revoke_while_erasing_sends_nothing() {
    // Erasing after a signed 503 to the request (not in doubt): revocations are refused as
    // during any erasure (12.7 step 5).
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::Error {
        path: "/erase".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert_eq!(signer.status(), SignerStatus::Erasing);
    let before = posts(&world.transport);
    let error = signer.revoke(id, None, confirmed()).await.unwrap_err();
    let after = posts(&world.transport);
    assert!(
        matches!(error, SignerError::Refused(Refusal::FlowInProgress)),
        "{error:?}"
    );
    assert!(
        !signer
            .alerts()
            .iter()
            .any(|a| matches!(a, Alert::RevocationPending { .. })),
        "nothing kept"
    );
    assert_eq!(after.len(), before.len(), "nothing sent but reads");
}

#[tokio::test]
async fn test_erasure_wait_revocation_pending_from_before_isnt_sent_while_erasing() {
    // A revocation the switch refused before the erasure stays pending: a run during the
    // erasure doesn't send it, and it still shows (12.7 step 5).
    let world = World::new();
    let (mut signer, id, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::Error {
        path: "/revoke".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    signer.revoke(id, None, confirmed()).await.unwrap_err();
    let pending = |signer: &Signer| {
        signer
            .alerts()
            .iter()
            .any(|a| matches!(a, Alert::RevocationPending { .. }))
    };
    assert!(pending(&signer));
    let refused = || SwitchFault::Error {
        path: "/erase".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    };
    world.switch.fail_next(refused());
    signer.close_account(confirmed()).await.unwrap_err();
    assert_eq!(signer.status(), SignerStatus::Erasing);
    world.switch.fail_next(refused());
    let before = posts(&world.transport);
    signer.run_due().await.unwrap_err();
    let after = posts(&world.transport);
    assert!(
        !after[before.len()..].iter().any(|p| p.ends_with("/revoke")),
        "{:?}",
        &after[before.len()..]
    );
    assert_eq!(signer.status(), SignerStatus::Erasing);
    assert!(pending(&signer));
}

/// A clone of `signer`'s install delivers the next version at the switch and backs it up.
fn a_clone_delivers_and_backs_up(
    world: &World,
    signer: &Signer,
) -> pubky_switch_core::records::IdentityDoc {
    use pubky_switch_core::keys::IdentityKey;
    use pubky_switch_core::records::{SIGNER_BACKUP_PATH, SignerBackup, SignerRecords};
    let on = signer.identity_doc().unwrap().unwrap();
    let next = world.other_install_version(&on, signer.install_id());
    world.switch.deliver_identity(&next).unwrap();
    let held = world.backup();
    let records = SignerRecords::new(
        IdentityKey::from_secret(world.key.secret_bytes()),
        next.clone(),
        held.revoked_apps(),
        held.certs(),
        *held.limits(),
        held.bundle_parts(),
        Some(on.hash()),
    )
    .unwrap();
    let backup = SignerBackup::seal(&world.key, &records).unwrap();
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, serde_json::to_vec(&backup).unwrap());
    next
}

#[tokio::test]
async fn test_erasure_wait_records_behind_signed_reads_dont_end_the_wait() {
    // The design note's case: records behind (a clone delivered), request in doubt. T0: a
    // stray 404 starts the wait. T0+1h..T0+23h: every run reads the switch, signed, showing
    // the clone's version (the account lives). T0+24h: one more stray 404. The wait ended
    // at the first signed read, so this 404 starts it again: not Erased.
    let world = World::new();
    let (mut signer, _, intermediary, t0, _) = waiting_behind_an_intermediary(&world).await;
    intermediary.store(false, Ordering::SeqCst);
    a_clone_delivers_and_backs_up(&world, &signer);
    for _ in 0..3 {
        world.clock.advance_ms(H);
        signer.resume().await.unwrap_err();
    }
    let status_after_signed = signer.status();
    world.clock.set_ms(t0 + 24 * H);
    intermediary.store(true, Ordering::SeqCst);
    let now = world.clock.now_ms();
    let result = signer.resume().await;
    assert_eq!(status_after_signed, SignerStatus::Erasing);
    assert_eq!(
        result.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: now })
    );
}

#[tokio::test]
async fn test_erasure_wait_no_answer_neither_counts_nor_ends() {
    // T0: 404. T0+5h: switch unreachable at GET /apps. Wait unchanged. T0+24h: 404: Erased.
    let world = World::new();
    let (mut signer, _, intermediary, t0, transport) = waiting_behind_an_intermediary(&world).await;
    world.clock.advance_ms(5 * H);
    intermediary.store(false, Ordering::SeqCst);
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/apps".into(),
        after: 0,
    });
    signer.resume().await.unwrap_err();
    assert_eq!(
        signer.status(),
        SignerStatus::ErasedUnconfirmed { since_ms: t0 }
    );
    intermediary.store(true, Ordering::SeqCst);
    world.clock.advance_ms(19 * H);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    assert_eq!(erase_requests(&transport), 1);
}

#[tokio::test]
async fn test_erasure_wait_unsigned_503_neither_counts_nor_ends() {
    // T0: 404. T0+5h: an intermediary's unsigned 503 to GET /apps. Wait unchanged.
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let mode = Arc::new(std::sync::Mutex::new(0u16));
    let answering = Arc::clone(&mode);
    let switch = Arc::clone(&world.switch);
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        let m = *answering.lock().unwrap();
        if m != 0 && request.method == "GET" && request.path_and_query.ends_with("/apps") {
            return Ok(Response {
                status: m,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            });
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport.clone();
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    *mode.lock().unwrap() = 404;
    let t0 = world.clock.now_ms();
    signer.resume().await.unwrap_err();
    assert_eq!(
        signer.status(),
        SignerStatus::ErasedUnconfirmed { since_ms: t0 }
    );
    world.clock.advance_ms(5 * H);
    *mode.lock().unwrap() = 503;
    signer.resume().await.unwrap_err();
    assert_eq!(
        signer.status(),
        SignerStatus::ErasedUnconfirmed { since_ms: t0 }
    );
    assert_eq!(
        erase_requests(&transport),
        1,
        "no request goes out on an unsigned 503"
    );
    *mode.lock().unwrap() = 404;
    world.clock.advance_ms(19 * H);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_wait_signed_answer_then_404_restarts_from_the_later_404() {
    // T0: 404. T0+2h: signed check (wait ends), request unreachable again. T0+3h: 404
    // (since = T0+3h). T0+24h: still unconfirmed; T0+27h: Erased.
    let world = World::new();
    let (mut signer, _, intermediary, _t0, _) = waiting_behind_an_intermediary(&world).await;
    world.clock.advance_ms(2 * H);
    intermediary.store(false, Ordering::SeqCst);
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.resume().await.unwrap_err();
    assert_eq!(signer.status(), SignerStatus::Erasing);
    world.clock.advance_ms(H);
    intermediary.store(true, Ordering::SeqCst);
    let t1 = world.clock.now_ms();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: t1 })
    );
    world.clock.advance_ms(21 * H);
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: t1 })
    );
    world.clock.advance_ms(3 * H);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
    assert!(!world.switch.erased(), "the stated residual");
}

#[tokio::test]
async fn test_erasure_wait_backup_of_another_install_on_the_concluding_run_ends_without_erasing() {
    // T0: 404. Another device restores and takes over (straight to the switch). T0+24h: the
    // intermediary's 404 again, but the backup names the other install: the erasure ends
    // without erasing (managed_by), not Erased.
    let world = World::new();
    let (mut signer, _, _intermediary, _t0, _) = waiting_behind_an_intermediary(&world).await;
    let other = Signer::restore_new(
        world.env(Arc::new(MemoryStore::new())),
        world.keyring(),
        confirmed(),
    )
    .await
    .unwrap();
    world.clock.advance_ms(24 * H);
    let error = signer.resume().await.unwrap_err();
    assert_eq!(
        error,
        SignerError::NotNamed {
            install: other.install_id()
        }
    );
    assert!(matches!(signer.status(), SignerStatus::ManagedBy { .. }));
}

#[tokio::test]
async fn test_erasure_wait_clock_back_then_max() {
    // Clock set back below since: restart from now. Clock at u64::MAX: no overflow, Erased.
    let world = World::new();
    let (mut signer, _, _i, t0, _) = waiting_behind_an_intermediary(&world).await;
    world.clock.set_ms(t0 - 1);
    let now = world.clock.now_ms();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: now })
    );
    world.clock.set_ms(u64::MAX);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_wait_older_stored_flow_without_the_field_loads_as_no_404_yet() {
    // A Flow::Erase stored by an older build, in doubt, without `first_404_ms`: it loads,
    // shows Erasing, and the next 404 starts the wait (doesn't conclude at once).
    use pubky_switch_client::store::{StoreHandle, WriteBatch};
    use pubky_switch_core::keys::IdentityKey;
    use pubky_switch_signer::state::signer_namespace;
    let world = World::new();
    let (mut signer, _, store) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
    assert!(world.switch.erased());
    drop(signer);
    let handle = StoreHandle::inline(store.clone());
    let ns = signer_namespace(&IdentityKey::from_secret(SECRET).public());
    let bytes = handle.get(&ns, b"flow").await.unwrap().unwrap();
    let mut flow: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let erase = flow.get_mut("Erase").unwrap().as_object_mut().unwrap();
    assert!(erase.remove("first_404_ms").is_some());
    assert_eq!(
        erase.get("unanswered"),
        Some(&serde_json::Value::Bool(true))
    );
    let mut batch = WriteBatch::new();
    batch
        .put(&ns, b"flow", serde_json::to_vec(&flow).unwrap())
        .unwrap();
    handle.commit(batch).await.unwrap();
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert_eq!(signer.status(), SignerStatus::Erasing);
    let now = world.clock.now_ms();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: now })
    );
}

#[tokio::test]
async fn test_erasure_wait_crash_before_the_wait_commit_starts_again() {
    // The store fails the commit that records the first 404: nothing is lost, the next run
    // records it then, and the erasure isn't concluded early.
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let flaky = FlakyStore::new(store.clone());
    let mut signer = Signer::open(world.env(flaky.clone()), world.keyring())
        .await
        .unwrap();
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
    flaky.fail(true);
    signer.resume().await.unwrap_err();
    flaky.fail(false);
    drop(signer);
    world.clock.advance_ms(24 * H);
    let mut signer = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert_eq!(signer.status(), SignerStatus::Erasing);
    let now = world.clock.now_ms();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: now })
    );
}

#[tokio::test]
async fn test_erasure_wait_alarm_during_the_wait_keeps_since_and_concludes() {
    // The wait runs; an equivocation on the Homeserver raises the alarm on the in-doubt
    // path (the erasure and `since` kept); the user clears it; a run 24 h after T0 ends it.
    let world = World::new();
    let (mut signer, _, _) = with_an_app(&world).await;
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/erase".into(),
    });
    signer.close_account(confirmed()).await.unwrap_err();
    let t0 = world.clock.now_ms();
    signer.resume().await.unwrap_err();
    assert_eq!(
        signer.status(),
        SignerStatus::ErasedUnconfirmed { since_ms: t0 }
    );
    let mark = signer.identity_doc().unwrap().unwrap();
    let mut body = mark.body().clone();
    body.record_max_age = Some(12_345);
    let other = pubky_switch_core::records::IdentityDoc::sign(&world.key, body).unwrap();
    world.homeserver.set(
        pubky_switch_core::records::IDENTITY_PATH,
        serde_json::to_vec(other.signed()).unwrap(),
    );
    world.clock.advance_ms(H);
    let error = signer.resume().await.unwrap_err();
    assert!(matches!(error, SignerError::Alarm(_)));
    assert_eq!(
        signer.status(),
        SignerStatus::ErasedUnconfirmed { since_ms: t0 }
    );
    world.clock.advance_ms(23 * H);
    // Alarm held, uncleared: the in-doubt path raises it again (the Homeserver's other body).
    signer.resume().await.unwrap_err();
    let alert = signer
        .alerts()
        .iter()
        .find(|a| matches!(a, pubky_switch_signer::Alert::Equivocation { .. }))
        .cloned()
        .unwrap();
    signer.clear_alert(&alert).await.unwrap();
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_wait_retry_404_after_a_signed_check_starts_a_fresh_wait() {
    // T0: the intermediary's 404 to the check. T0+23h: the check is signed (the wait ends),
    // and the retry meets an unsigned 404: a fresh wait from now, not from T0.
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let get404 = Arc::new(AtomicBool::new(false));
    let post404 = Arc::new(AtomicBool::new(false));
    let (g, p) = (Arc::clone(&get404), Arc::clone(&post404));
    let switch = Arc::clone(&world.switch);
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        let get = request.method == "GET" && request.path_and_query.ends_with("/apps");
        let post = request.method == "POST" && request.path_and_query.ends_with("/erase");
        if (get && g.load(Ordering::SeqCst)) || (post && p.load(Ordering::SeqCst)) {
            return Ok(Response {
                status: 404,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            });
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport;
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    get404.store(true, Ordering::SeqCst);
    let t0 = world.clock.now_ms();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: t0 })
    );
    world.clock.advance_ms(23 * H);
    get404.store(false, Ordering::SeqCst);
    post404.store(true, Ordering::SeqCst);
    let t1 = world.clock.now_ms();
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: t1 })
    );
    assert_eq!(
        signer.status(),
        SignerStatus::ErasedUnconfirmed { since_ms: t1 }
    );
    get404.store(true, Ordering::SeqCst);
    world.clock.advance_ms(2 * H);
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnconfirmed { since_ms: t1 })
    );
    world.clock.advance_ms(22 * H);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Erased);
}

#[tokio::test]
async fn test_erasure_wait_signed_error_to_the_retry_ends_the_wait() {
    // T0: 404. T0+2h: signed check, the retry gets a signed 503: the wait is over, the
    // mark cleared. T0+24h: 404 again: a fresh wait.
    let world = World::new();
    let (mut signer, _, intermediary, _t0, _) = waiting_behind_an_intermediary(&world).await;
    world.clock.advance_ms(2 * H);
    intermediary.store(false, Ordering::SeqCst);
    world.switch.fail_next(SwitchFault::Error {
        path: "/erase".into(),
        code: ErrorCode::Unavailable,
        current: serde_json::Value::Null,
    });
    signer.resume().await.unwrap_err();
    assert_eq!(signer.status(), SignerStatus::Erasing);
    intermediary.store(true, Ordering::SeqCst);
    world.clock.advance_ms(22 * H);
    // No request in doubt now: the 404 to the check is an error, not the wait.
    signer.resume().await.unwrap_err();
    assert!(!matches!(
        signer.status(),
        SignerStatus::Erased | SignerStatus::ErasedUnconfirmed { .. }
    ));
}

#[tokio::test]
async fn test_erasure_wait_unsigned_503_to_the_retry_doesnt_count() {
    // Every POST /erase gets an intermediary's unsigned 503: in doubt, but never the 404's
    // wait; the checks are signed.
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let switch = Arc::clone(&world.switch);
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "POST" && request.path_and_query.ends_with("/erase") {
            return Ok(Response {
                status: 503,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            });
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport;
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.close_account(confirmed()).await.unwrap_err();
    for _ in 0..2 {
        let error = signer.resume().await.unwrap_err();
        assert_eq!(
            error,
            SignerError::Switch(pubky_switch_client::ClientError::BadServiceSignature {
                status: 503
            })
        );
        assert_eq!(signer.status(), SignerStatus::Erasing);
        world.clock.advance_ms(24 * H);
    }
    assert_eq!(
        signer.abort_erasure().await.unwrap_err(),
        SignerError::Refused(Refusal::ErasureUnanswered)
    );
}

#[tokio::test]
async fn test_erasure_wait_unsigned_503_to_the_check_doesnt_start_the_wait() {
    // A request in doubt, no 404 yet: an intermediary's unsigned 503 to the check neither
    // starts the wait nor sends anything.
    let world = World::new();
    let (signer, _, store) = with_an_app(&world).await;
    drop(signer);
    let on = Arc::new(AtomicBool::new(false));
    let answering = Arc::clone(&on);
    let switch = Arc::clone(&world.switch);
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if answering.load(Ordering::SeqCst)
            && request.method == "GET"
            && request.path_and_query.ends_with("/apps")
        {
            return Ok(Response {
                status: 503,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            });
        }
        switch.handle(request)
    }));
    let mut env = world.env(store);
    env.transport = transport.clone();
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/erase".into(),
        after: 0,
    });
    signer.close_account(confirmed()).await.unwrap_err();
    on.store(true, Ordering::SeqCst);
    for _ in 0..2 {
        assert_eq!(
            signer.resume().await.unwrap_err(),
            SignerError::Switch(pubky_switch_client::ClientError::BadServiceSignature {
                status: 503
            })
        );
        assert_eq!(signer.status(), SignerStatus::Erasing);
        world.clock.advance_ms(24 * H);
    }
    assert_eq!(erase_requests(&transport), 1);
}
