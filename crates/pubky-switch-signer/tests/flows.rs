//! The signer's enrollment and `identity.json` deliveries against the scripted switch
//! (Switch spec 4.3, 12.8; Switch wire 3.3, 3.7, 3.13, 7.4.1, 7.4.2), with crash tests over
//! every commit.
//!
//! The scripted switch judges each delivery by the core's `check_delivery`, the rule the
//! service applies; the same flows run against the service once it serves enrollment and
//! `PUT /identity`.

// The helpers outside `#[test]` functions build fixed fixtures, where a failure is a test
// failure: the workspace's no-panic lints don't apply to them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use std::sync::Arc;

use pubky_switch_client::StoreError;
use pubky_switch_client::store::{Fault, FaultStore, MemoryStore, StateStore};
use pubky_switch_client::testing::SWITCH_ORIGIN;
use pubky_switch_core::keys::IdentityKey;
use pubky_switch_core::records::{
    IdentityDoc, Limits, SIGNER_BACKUP_PATH, SignerBackup, SignerRecords,
};
use pubky_switch_signer::{Alert, Refusal, Signer, SignerError, SignerStatus, Source};

#[tokio::test]
async fn test_signer_enrollment_delivers_then_publishes_the_first_version() {
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    assert_eq!(signer.status(), SignerStatus::Signing);
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(
        (doc.version(), doc.generation(), doc.data_epoch()),
        (1, 1, 1)
    );
    // The first version names this switch, its key and this install (Switch spec 4.3).
    assert_eq!(doc.inbox().url, SWITCH_ORIGIN);
    assert_eq!(doc.inbox().service_key, world.switch.service_key());
    assert_eq!(doc.body().signer, signer.install_id());
    // Delivered, then published: both copies are the signer's high-water mark.
    let high = signer.high_water().unwrap();
    assert_eq!((high.version, high.doc_hash), (1, doc.hash()));
    assert_eq!(world.switch.identity_doc().unwrap().signed(), doc.signed());
    assert_eq!(world.published().unwrap().signed(), doc.signed());
    // The backup holds that version, for this identity (Switch wire 3.13).
    let records = world.backup();
    assert_eq!(records.identity_doc().signed(), doc.signed());
    assert_eq!(records.prev(), None);
    assert!(signer.alerts().is_empty());
}

#[tokio::test]
async fn test_signer_create_refuses_an_identity_already_set_up() {
    let world = World::new();
    let (_, store) = world.enrolled().await;
    let error = Signer::create(world.env(store), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap_err();
    assert_eq!(error, SignerError::Refused(Refusal::AlreadySetUp));
}

#[tokio::test]
async fn test_signer_open_refuses_an_empty_store() {
    let world = World::new();
    let error = Signer::open(world.env(Arc::new(MemoryStore::new())), world.keyring())
        .await
        .unwrap_err();
    assert_eq!(error, SignerError::Refused(Refusal::NotSetUp));
}

#[tokio::test]
async fn test_signer_create_refuses_an_origin_that_isnt_a_switch_origin() {
    let world = World::new();
    for origin in ["http://switch.example", "https://switch.example/v1"] {
        let error = Signer::create(
            world.env(Arc::new(MemoryStore::new())),
            world.keyring(),
            origin,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, SignerError::InvalidData(_)),
            "{origin}: {error:?}"
        );
    }
}

#[tokio::test]
async fn test_signer_open_keeps_the_install_and_the_high_water_mark() {
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    let opened = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert_eq!(opened.install_id(), signer.install_id());
    assert_eq!(opened.high_water(), signer.high_water());
    assert_eq!(opened.status(), SignerStatus::Signing);
}

#[tokio::test]
async fn test_signer_new_version_builds_on_the_newest() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let second = signer.set_record_max_age(Some(2_592_000)).await.unwrap();
    assert_eq!(second.version(), 2);
    assert_eq!(second.body().record_max_age, Some(2_592_000));
    assert_eq!(second.body().signer, signer.install_id());
    assert_eq!(signer.high_water().unwrap().doc_hash, second.hash());
    assert_eq!(
        world.switch.identity_doc().unwrap().signed(),
        second.signed()
    );
    assert_eq!(world.published().unwrap().signed(), second.signed());
    // The backup was written before the delivery, holding the version and its `prev`.
    let records = world.backup();
    assert_eq!(records.identity_doc().signed(), second.signed());
    assert_eq!(records.prev(), Some(first.hash()));
}

#[tokio::test]
async fn test_signer_a_backup_write_that_fails_stops_the_delivery() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    // Reads still answer, so the backup check passes and only the write fails.
    *world.homeserver.failing_puts.lock().unwrap() = true;
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    // Nothing reached the switch: the backup comes first (Switch wire 3.13).
    assert_eq!(world.switch.identity_doc().unwrap().version(), 1);
    assert_eq!(world.distinct_requests("PUT", "/identity"), 1);
    assert_eq!(signer.high_water().unwrap().version, 1);
    // Once the Homeserver takes writes again, the same version goes out.
    *world.homeserver.failing_puts.lock().unwrap() = false;
    signer.resume().await.unwrap();
    assert_eq!(world.switch.identity_doc().unwrap().version(), 2);
    assert_eq!(world.distinct_requests("PUT", "/identity"), 2);
}

#[tokio::test]
async fn test_signer_refuses_a_new_version_while_a_flow_is_in_progress() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    *world.homeserver.failing_puts.lock().unwrap() = true;
    signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    let error = signer.set_record_max_age(Some(3_600)).await.unwrap_err();
    assert_eq!(error, SignerError::Refused(Refusal::FlowInProgress));
}

#[tokio::test]
async fn test_signer_a_newer_version_by_another_install_stops_signing() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let other = [9; 16];
    world
        .switch
        .deliver_identity(&world.other_install_version(&first, other))
        .unwrap();
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: other });
    assert_eq!(signer.status(), SignerStatus::ManagedBy { install: other });
    assert!(
        signer
            .alerts()
            .contains(&Alert::ManagedByOtherInstall { install: other })
    );
    // The newer copy is adopted as the high-water mark, and this install signs nothing more.
    assert_eq!(signer.high_water().unwrap().version, 2);
    let error = signer
        .set_connect_requests(Default::default())
        .await
        .unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: other });
    // It never publishes another install's version (Switch spec 4.3).
    assert_eq!(world.published().unwrap().version(), 1);
}

#[tokio::test]
async fn test_signer_another_installs_backup_stops_signing_before_the_delivery() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let other = [7; 16];
    let theirs = world.other_install_version(&first, other);
    let records = SignerRecords::new(
        IdentityKey::from_secret(SECRET),
        theirs,
        &[],
        &[],
        Limits::default(),
        &[],
        Some(first.hash()),
    )
    .unwrap();
    let backup = SignerBackup::seal(&world.key, &records).unwrap();
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, serde_json::to_vec(&backup).unwrap());
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: other });
    // Nothing was written or delivered (Switch wire 3.13 "Another install's backup").
    assert_eq!(world.switch.identity_doc().unwrap().version(), 1);
    assert_eq!(world.backup().identity_doc().body().signer, other);
}

#[tokio::test]
async fn test_signer_own_earlier_backup_doesnt_stop_signing() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    // The backup of version 1 names this install: the next version goes out.
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    signer.set_record_max_age(None).await.unwrap();
    assert_eq!(signer.high_water().unwrap().version, 3);
}

#[tokio::test]
async fn test_signer_an_unreadable_backup_is_replaced_with_an_alert() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    world.homeserver.set(
        SIGNER_BACKUP_PATH,
        b"{\"envelopes\":[],\"sig\":\"x\"}".to_vec(),
    );
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    assert!(signer.alerts().contains(&Alert::BackupUnreadable));
    assert_eq!(world.backup().identity_doc().version(), 2);
}

#[tokio::test]
async fn test_signer_an_older_copy_at_the_switch_is_a_rollback_alarm() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    // The switch goes back to version 1.
    world.switch.deliver_identity(&first).unwrap();
    let error = signer.set_record_max_age(None).await.unwrap_err();
    let alert = Alert::Rollback {
        source: Source::Switch,
        version: Some(1),
        generation: Some(1),
        high_water_version: 2,
    };
    assert_eq!(error, SignerError::Alarm(alert.clone()));
    assert!(signer.alerts().contains(&alert));
    // The high-water mark doesn't go back.
    assert_eq!(signer.high_water().unwrap().version, 2);
}

#[tokio::test]
async fn test_signer_another_body_at_the_high_water_version_is_equivocation() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let second = signer.set_record_max_age(Some(86_400)).await.unwrap();
    // Another version 2, built on the same first version.
    let mut body = first.body().clone();
    body.version = 2;
    body.record_max_age = Some(3_600);
    let forked = IdentityDoc::sign(&world.key, body).unwrap();
    assert_ne!(forked.body_hash(), second.body_hash());
    world.switch.deliver_identity(&forked).unwrap();
    let error = signer.set_record_max_age(None).await.unwrap_err();
    let alert = Alert::Equivocation {
        source: Source::Switch,
        version: 2,
    };
    assert_eq!(error, SignerError::Alarm(alert.clone()));
    assert_eq!(signer.high_water().unwrap().doc_hash, second.hash());
}

#[tokio::test]
async fn test_signer_a_lost_answer_is_resent_with_the_same_bytes() {
    use pubky_switch_client::testing::Fault as SwitchFault;
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/v1/enroll".into(),
    });
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/identity".into(),
    });
    assert!(signer.resume().await.is_err());
    assert!(signer.resume().await.is_err());
    signer.resume().await.unwrap();
    // The enrollment and the delivery each went out twice, the same bytes both times, and
    // the switch took the retry (Switch wire 2.1, 7.4.2).
    assert_eq!(world.distinct_requests("POST", "/v1/enroll"), 1);
    assert_eq!(world.distinct_requests("PUT", "/identity"), 1);
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(world.switch.identity_doc().unwrap().signed(), doc.signed());
}

/// Run the enrollment with the store stopping before or after commit `n`, then reopen the
/// store as a restarted process would and finish.
async fn crash_at(fault: Fault) -> (World, Signer) {
    let world = World::new();
    let memory: Arc<dyn StateStore> = Arc::new(MemoryStore::new());
    let faulty = Arc::new(FaultStore::new(Arc::clone(&memory), fault));
    let created = Signer::create(world.env(faulty.clone()), world.keyring(), SWITCH_ORIGIN).await;
    if let Ok(mut signer) = created {
        let _ = signer.resume().await;
    }
    let env = world.env(memory);
    let mut signer = match Signer::open(env.clone(), world.keyring()).await {
        Ok(signer) => signer,
        Err(SignerError::Refused(Refusal::NotSetUp)) => {
            Signer::create(env, world.keyring(), SWITCH_ORIGIN)
                .await
                .unwrap()
        }
        Err(error) => panic!("{fault:?}: {error:?}"),
    };
    signer
        .resume()
        .await
        .unwrap_or_else(|e| panic!("{fault:?}: {e:?}"));
    (world, signer)
}

#[tokio::test]
async fn test_signer_enrollment_survives_a_crash_at_every_commit() {
    // Set up, enrolled, backup sealed, backup written, delivered, published: six commits.
    let world = World::new();
    let counting = Arc::new(FaultStore::new(Arc::new(MemoryStore::new()), Fault::None));
    let mut signer = Signer::create(world.env(counting.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    assert_eq!(counting.commits(), 6);
    for n in 1..=7 {
        for fault in [Fault::StopBefore(n), Fault::StopAfter(n)] {
            let (world, signer) = crash_at(fault).await;
            let doc = signer.identity_doc().unwrap().unwrap();
            assert_eq!(doc.version(), 1, "{fault:?}");
            assert_eq!(world.switch.identity_doc().unwrap().signed(), doc.signed());
            assert_eq!(world.published().unwrap().signed(), doc.signed());
            assert_eq!(world.backup().identity_doc().signed(), doc.signed());
            // Nothing signed twice: one enrollment, one document and one backup went out,
            // however often each was sent.
            assert_eq!(
                world.distinct_requests("POST", "/v1/enroll"),
                1,
                "{fault:?}"
            );
            assert_eq!(world.distinct_requests("PUT", "/identity"), 1, "{fault:?}");
            assert_eq!(
                world.homeserver.distinct_writes(SIGNER_BACKUP_PATH),
                1,
                "{fault:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_signer_a_failed_commit_sends_nothing_it_didnt_commit() {
    let world = World::new();
    let memory = Arc::new(MemoryStore::new());
    let flaky = FlakyStore::new(memory.clone());
    let mut signer = Signer::create(world.env(flaky.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    flaky.fail(true);
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(error, SignerError::Store(StoreError::Unavailable));
    for _ in 0..3 {
        let _ = signer.resume().await;
    }
    // Nothing that wasn't committed reached the switch or the Homeserver.
    assert_eq!(world.switch.identity_doc().unwrap().version(), 1);
    assert_eq!(world.backup().identity_doc().version(), 1);
    // A restart finds the store as committed, and the next change is signed once.
    flaky.fail(false);
    let mut restarted = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    restarted.set_record_max_age(Some(3_600)).await.unwrap();
    assert_eq!(
        world.switch.identity_doc().unwrap().body().record_max_age,
        Some(3_600)
    );
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_signer_a_store_that_cant_tell_is_read_again() {
    // The commit of the signed version is applied but answers `Unknown`: the signer reads its
    // state again, so it goes on from what the store holds (Switch wire 2.1).
    let world = World::new();
    // The enrollment takes six commits; the seventh is the new version's first.
    let faulty = Arc::new(FaultStore::new(
        Arc::new(MemoryStore::new()),
        Fault::FailAfter(7),
    ));
    let mut signer = Signer::create(world.env(faulty), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(error, SignerError::Store(StoreError::Unknown));
    signer.resume().await.unwrap();
    assert_eq!(world.switch.identity_doc().unwrap().version(), 2);
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_signer_never_signs_a_version_twice_after_a_dropped_flow() {
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    world.switch.deliver_identity(&first).unwrap();
    // Two changes, each refused with a rollback alarm after its document went out.
    for seconds in [3_600, 7_200] {
        let error = signer.set_record_max_age(Some(seconds)).await.unwrap_err();
        assert!(
            matches!(error, SignerError::Alarm(Alert::Rollback { .. })),
            "{error:?}"
        );
    }
    // And once more after a restart.
    let mut restarted = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    restarted.set_record_max_age(Some(60)).await.unwrap_err();
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_signer_an_unreadable_backup_after_a_take_over_isnt_overwritten() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let other = [5; 16];
    world
        .switch
        .deliver_identity(&world.other_install_version(&first, other))
        .unwrap();
    let garbage = b"not a backup".to_vec();
    world.homeserver.set(SIGNER_BACKUP_PATH, garbage.clone());
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: other });
    // Nothing written over the other install's backup, nothing delivered (Switch wire 3.13).
    assert_eq!(world.homeserver.file(SIGNER_BACKUP_PATH), Some(garbage));
    assert!(world.sent_docs().iter().all(|d| d.version() == 1));
}

#[tokio::test]
async fn test_signer_a_missing_backup_after_a_take_over_isnt_written() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let other = [6; 16];
    world
        .switch
        .deliver_identity(&world.other_install_version(&first, other))
        .unwrap();
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: other });
    assert_eq!(world.homeserver.file(SIGNER_BACKUP_PATH), None);
}

#[tokio::test]
async fn test_signer_a_missing_backup_at_its_own_mark_is_written_again() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    assert!(signer.alerts().contains(&Alert::BackupMissing));
    assert_eq!(world.backup().identity_doc().version(), 2);
}

#[tokio::test]
async fn test_signer_a_switch_holding_nothing_under_a_mark_is_a_rollback() {
    use pubky_switch_client::testing::Fault as SwitchFault;
    use pubky_switch_core::http::ErrorCode;
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::StaleIdentity,
        current: serde_json::Value::Null,
    });
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    let alert = Alert::Rollback {
        source: Source::Switch,
        version: None,
        generation: None,
        high_water_version: 1,
    };
    assert_eq!(error, SignerError::Alarm(alert.clone()));
    assert!(signer.alerts().contains(&alert));
}

#[tokio::test]
async fn test_signer_a_new_version_survives_a_crash_at_every_commit() {
    // Signed, backup sealed, backup written, delivered, published: five commits. Under each
    // fault the signer is asked again on the failing store, then restarted and asked for a
    // different change: no version may go out with two bodies (Switch wire 2.1, spec 4.3).
    for n in 1..=6 {
        for fault in [
            Fault::StopBefore(n),
            Fault::StopAfter(n),
            Fault::FailBefore(n),
            Fault::FailAfter(n),
        ] {
            let world = World::new();
            let memory = Arc::new(MemoryStore::new());
            let mut signer =
                Signer::create(world.env(memory.clone()), world.keyring(), SWITCH_ORIGIN)
                    .await
                    .unwrap();
            signer.resume().await.unwrap();
            let faulty = Arc::new(FaultStore::new(memory.clone(), fault));
            let mut signer = Signer::open(world.env(faulty), world.keyring())
                .await
                .unwrap();
            let _ = signer.set_record_max_age(Some(86_400)).await;
            for _ in 0..3 {
                let _ = signer.resume().await;
            }
            let mut restarted = Signer::open(world.env(memory), world.keyring())
                .await
                .unwrap();
            restarted
                .resume()
                .await
                .unwrap_or_else(|e| panic!("{fault:?}: {e:?}"));
            let last = restarted.set_record_max_age(Some(3_600)).await.unwrap();
            world.assert_no_version_sent_twice();
            assert_eq!(
                world.switch.identity_doc().unwrap().signed(),
                last.signed(),
                "{fault:?}"
            );
            assert_eq!(
                world.published().unwrap().signed(),
                last.signed(),
                "{fault:?}"
            );
            assert_eq!(
                world.backup().identity_doc().signed(),
                last.signed(),
                "{fault:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_signer_an_unreadable_backup_before_the_first_version_is_refused_with_an_alert() {
    let world = World::new();
    let garbage = b"not a backup".to_vec();
    world.homeserver.set(SIGNER_BACKUP_PATH, garbage.clone());
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    // Every attempt is the same typed refusal, never the staged switch's `503`.
    for _ in 0..2 {
        let error = signer.resume().await.unwrap_err();
        assert_eq!(error, SignerError::Refused(Refusal::UnreadableBackup));
    }
    assert!(
        signer
            .alerts()
            .contains(&Alert::UnreadableBackupBeforeEnrollment)
    );
    assert_eq!(signer.status(), SignerStatus::Enrolling);
    // Nothing written over the backup, nothing delivered.
    assert_eq!(world.homeserver.file(SIGNER_BACKUP_PATH), Some(garbage));
    assert!(world.sent_docs().is_empty());
    // Once the user removes it, the enrollment goes on from where it stopped.
    world
        .homeserver
        .files
        .lock()
        .unwrap()
        .remove(SIGNER_BACKUP_PATH);
    signer.resume().await.unwrap();
    assert_eq!(signer.status(), SignerStatus::Signing);
    assert_eq!(world.backup().identity_doc().version(), 1);
    assert_eq!(world.distinct_requests("POST", "/v1/enroll"), 1);
}

#[tokio::test]
async fn test_signer_a_resumed_publication_never_overwrites_a_newer_identity() {
    // The signer stops after publishing version 2 but before keeping that, another install
    // then delivers and publishes version 3, and the restarted signer resumes: it doesn't
    // publish version 2 again over version 3 (Switch spec 4.3).
    let world = World::new();
    let memory = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(memory.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    // A new version takes five commits: signed, backup sealed and written, delivered,
    // published. The store stops before the fifth.
    let faulty = Arc::new(FaultStore::new(memory.clone(), Fault::StopBefore(5)));
    let mut signer = Signer::open(world.env(faulty), world.keyring())
        .await
        .unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(world.published().unwrap().version(), 2);
    let second = world.switch.identity_doc().unwrap();
    let theirs = world.other_install_version(&second, [7; 16]);
    world.switch.deliver_identity(&theirs).unwrap();
    world.homeserver.set(
        pubky_switch_core::records::IDENTITY_PATH,
        serde_json::to_vec(theirs.signed()).unwrap(),
    );
    let mut restarted = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    let error = restarted.resume().await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: [7; 16] });
    assert_eq!(world.published().unwrap().signed(), theirs.signed());
}

/// Another body at `doc`'s version, signed with the identity key.
fn other_body(world: &World, doc: &IdentityDoc) -> IdentityDoc {
    let mut body = doc.body().clone();
    body.record_max_age = Some(7);
    IdentityDoc::sign(&world.key, body).unwrap()
}

/// Publish `doc` on the Homeserver, as someone holding the identity key could.
fn plant(world: &World, doc: &IdentityDoc) {
    world.homeserver.set(
        pubky_switch_core::records::IDENTITY_PATH,
        serde_json::to_vec(doc.signed()).unwrap(),
    );
}

#[tokio::test]
async fn test_signer_another_body_on_the_homeserver_is_an_alarm_then_republished_over() {
    // Version 2 reaches the switch but not the Homeserver, which then shows another body at
    // version 2. The user is told, claims are held and nothing is signed on top. Once the
    // alert is cleared, the switch's copy, this signer's own, is published over it (Switch
    // wire 3.3 "Deliver, then publish"), and signing goes on.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    *world.homeserver.failing_path.lock().unwrap() =
        Some(pubky_switch_core::records::IDENTITY_PATH.into());
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    *world.homeserver.failing_path.lock().unwrap() = None;
    let two = world.switch.identity_doc().unwrap();
    let other = other_body(&world, &two);
    plant(&world, &other);
    let alert = Alert::Equivocation {
        source: Source::Homeserver,
        version: 2,
    };
    assert_eq!(
        signer.resume().await.unwrap_err(),
        SignerError::Alarm(alert.clone())
    );
    // While the alert is held: kept as it is, and nothing signed on top.
    assert_eq!(signer.status(), SignerStatus::Alarm);
    let sent = world.sent_docs().len();
    for seconds in [3_600, 60] {
        let error = signer.set_record_max_age(Some(seconds)).await.unwrap_err();
        assert_eq!(error, SignerError::Alarm(alert.clone()));
    }
    assert_eq!(world.sent_docs().len(), sent);
    assert!(signer.alerts().contains(&alert));
    assert_eq!(world.published().unwrap().signed(), other.signed());
    // Cleared: the switch's copy goes over it, and signing goes on.
    signer.clear_alert(&alert).await.unwrap();
    assert!(!signer.alerts().contains(&alert));
    assert_eq!(world.published().unwrap().signed(), two.signed());
    assert_eq!(signer.status(), SignerStatus::Signing);
    let three = signer.set_record_max_age(Some(3_600)).await.unwrap();
    assert_eq!(world.published().unwrap().signed(), three.signed());
    // A third body planted after the clear is another equivocation: the alarm again, and
    // it is kept.
    let third = other_body(&world, &three);
    plant(&world, &third);
    let alert = Alert::Equivocation {
        source: Source::Homeserver,
        version: 3,
    };
    assert_eq!(
        signer.set_record_max_age(Some(60)).await.unwrap_err(),
        SignerError::Alarm(alert.clone())
    );
    assert!(signer.alerts().contains(&alert));
    assert_eq!(world.published().unwrap().signed(), third.signed());
}

#[tokio::test]
async fn test_signer_another_body_replacing_a_published_version_is_republished_over_once_seen() {
    // The Homeserver held this signer's version 2, and another body at version 2 replaced
    // it: the next signing call raises the alarm before signing anything.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let two = signer.set_record_max_age(Some(86_400)).await.unwrap();
    let other = other_body(&world, &two);
    plant(&world, &other);
    let SignerError::Alarm(alert) = signer.set_record_max_age(Some(60)).await.unwrap_err() else {
        panic!("no alarm")
    };
    assert_eq!(world.switch.identity_doc().unwrap().signed(), two.signed());
    signer.clear_alert(&alert).await.unwrap();
    assert_eq!(world.published().unwrap().signed(), two.signed());
    signer.set_record_max_age(Some(60)).await.unwrap();
}

#[tokio::test]
async fn test_signer_another_body_on_the_homeserver_stays_once_another_install_signs() {
    // Cleared, the alarm leads to publication only when the switch holds this signer's
    // newest version: here another install's newer one stops it instead.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let two = signer.set_record_max_age(Some(86_400)).await.unwrap();
    let other = other_body(&world, &two);
    plant(&world, &other);
    let SignerError::Alarm(alert) = signer.set_record_max_age(Some(60)).await.unwrap_err() else {
        panic!("no alarm")
    };
    world
        .switch
        .deliver_identity(&world.other_install_version(&two, [7; 16]))
        .unwrap();
    let error = signer.clear_alert(&alert).await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: [7; 16] });
    assert_eq!(world.published().unwrap().signed(), other.signed());
}

#[tokio::test]
async fn test_signer_a_newer_homeserver_version_of_its_own_stops_signing() {
    // The Homeserver holds a version 9 this install signed, at data epoch 2, as after its
    // records went back. Signing above it with the older records would roll the identity's
    // state back, so the change is refused, and nothing more is signed (Switch spec 4.3).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let mut body = first.body().clone();
    body.version = 9;
    body.data_epoch = 2;
    let nine = IdentityDoc::sign(&world.key, body).unwrap();
    world.homeserver.set(
        pubky_switch_core::records::IDENTITY_PATH,
        serde_json::to_vec(nine.signed()).unwrap(),
    );
    let behind = SignerError::Refused(Refusal::RecordsBehind { version: 9 });
    let sent = world.sent_docs().len();
    let error = signer.set_record_max_age(Some(3_600)).await.unwrap_err();
    assert_eq!(error, behind);
    // Found before anything was signed: nothing was sent.
    assert_eq!(world.sent_docs().len(), sent);
    let alert = Alert::RecordsBehind {
        source: Source::Homeserver,
        version: 9,
        high_water_version: 1,
    };
    assert!(signer.alerts().contains(&alert));
    assert_eq!(signer.status(), SignerStatus::RecordsBehind { version: 9 });
    // It stays so, cleared alert or not, and the Homeserver keeps version 9.
    signer.clear_alert(&alert).await.unwrap();
    assert!(signer.alerts().contains(&alert));
    for seconds in [60, 120] {
        let error = signer.set_record_max_age(Some(seconds)).await.unwrap_err();
        assert_eq!(error, behind);
    }
    assert_eq!(world.sent_docs().len(), sent);
    assert!(world.sent_docs().iter().all(|d| d.version() < 9));
    assert_eq!(world.published().unwrap().signed(), nine.signed());
}

/// A version `version` of this install's own above `doc`, at data epoch 2, and its signer
/// backup, as the install wrote them before its records went back.
fn own_newer(world: &World, doc: &IdentityDoc, version: u64) -> (IdentityDoc, Vec<u8>) {
    let mut body = doc.body().clone();
    body.version = version;
    body.data_epoch = 2;
    let newer = IdentityDoc::sign(&world.key, body).unwrap();
    let records = SignerRecords::new(
        IdentityKey::from_secret(SECRET),
        newer.clone(),
        &[],
        &[],
        Limits::default(),
        &[],
        None,
    )
    .unwrap();
    let backup = SignerBackup::seal(&world.key, &records).unwrap();
    (newer, serde_json::to_vec(&backup).unwrap())
}

#[tokio::test]
async fn test_signer_records_behind_keep_the_backup_to_restore_from() {
    // The switch and the signer backup hold this install's own version 9, and the store,
    // reopened, holds its records at version 1, as after a restore of an old device backup.
    // A change is refused before anything is signed: no version 2 is backed up or sent, so
    // the backup still holds version 9 to restore from (Switch wire 3.13).
    let world = World::new();
    let (signer, memory) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    drop(signer);
    let (nine, backup) = own_newer(&world, &first, 9);
    world.switch.deliver_identity(&nine).unwrap();
    world.homeserver.set(SIGNER_BACKUP_PATH, backup);
    let sent = world.sent_docs().len();
    let mut signer = Signer::open(world.env(memory.clone()), world.keyring())
        .await
        .unwrap();
    let behind = SignerError::Refused(Refusal::RecordsBehind { version: 9 });
    assert_eq!(
        signer.set_record_max_age(Some(3_600)).await.unwrap_err(),
        behind
    );
    assert_eq!(world.backup().identity_doc().signed(), nine.signed());
    assert_eq!(world.sent_docs().len(), sent);
    assert_eq!(world.switch.identity_doc().unwrap().signed(), nine.signed());
    // Reopened again, it stays behind.
    drop(signer);
    let mut signer = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    assert_eq!(signer.status(), SignerStatus::RecordsBehind { version: 9 });
    assert_eq!(
        signer.set_record_max_age(Some(60)).await.unwrap_err(),
        behind
    );
    assert_eq!(world.backup().identity_doc().signed(), nine.signed());
    assert_eq!(world.sent_docs().len(), sent);
}

#[tokio::test]
async fn test_signer_a_newer_own_backup_alone_shows_the_records_behind() {
    // Only the backup holds the newer version: the switch is still at version 1.
    let world = World::new();
    let (signer, memory) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    drop(signer);
    let (nine, backup) = own_newer(&world, &first, 9);
    world.homeserver.set(SIGNER_BACKUP_PATH, backup);
    let mut signer = Signer::open(world.env(memory), world.keyring())
        .await
        .unwrap();
    let error = signer.set_record_max_age(Some(3_600)).await.unwrap_err();
    assert_eq!(
        error,
        SignerError::Refused(Refusal::RecordsBehind { version: 9 })
    );
    assert!(signer.alerts().contains(&Alert::RecordsBehind {
        source: Source::Backup,
        version: 9,
        high_water_version: 1,
    }));
    assert_eq!(world.backup().identity_doc().signed(), nine.signed());
    assert_eq!(world.switch.identity_doc().unwrap().version(), 1);
}

#[tokio::test]
async fn test_signer_a_resumed_backup_write_never_overwrites_a_newer_own_backup() {
    // A version 2 was signed and its backup write failed. Meanwhile the Homeserver shows a
    // backup of this install's own version 9: the resumed write stops there, so the backup
    // to restore from stays, and version 2 is never sent.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    *world.homeserver.failing_path.lock().unwrap() = Some(SIGNER_BACKUP_PATH.into());
    let error = signer.set_record_max_age(Some(3_600)).await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    *world.homeserver.failing_path.lock().unwrap() = None;
    let (nine, backup) = own_newer(&world, &first, 9);
    world.homeserver.set(SIGNER_BACKUP_PATH, backup);
    let error = signer.resume().await.unwrap_err();
    assert_eq!(
        error,
        SignerError::Refused(Refusal::RecordsBehind { version: 9 })
    );
    assert_eq!(world.backup().identity_doc().signed(), nine.signed());
    assert!(world.sent_docs().iter().all(|d| d.version() < 2));
}

#[tokio::test]
async fn test_signer_a_newer_switch_version_of_its_own_isnt_adopted() {
    // The switch holds a version 2 this install signed, listing an app and a renewal its
    // records don't hold. It isn't adopted, nor built on: this install's records are behind
    // (Switch spec 4.3).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let mut body = first.body().clone();
    body.version = 2;
    body.apps.push(pubky_switch_core::records::ListedApp {
        app_id: [3; 16],
        cert: [4; 32],
    });
    body.renewed.push(pubky_switch_core::records::RenewedCert {
        app_id: [3; 16],
        cert: [5; 32],
        until: None,
    });
    let two = IdentityDoc::sign(&world.key, body).unwrap();
    world.switch.deliver_identity(&two).unwrap();
    let error = signer.set_record_max_age(Some(3_600)).await.unwrap_err();
    assert_eq!(
        error,
        SignerError::Refused(Refusal::RecordsBehind { version: 2 })
    );
    assert_eq!(
        signer.identity_doc().unwrap().unwrap().signed(),
        first.signed()
    );
    assert!(signer.alerts().contains(&Alert::RecordsBehind {
        source: Source::Switch,
        version: 2,
        high_water_version: 1,
    }));
    assert_eq!(world.switch.identity_doc().unwrap().signed(), two.signed());
    assert!(world.sent_docs().iter().all(|d| d.version() <= 2));
}

#[tokio::test]
async fn test_signer_a_homeserver_copy_at_a_higher_generation_but_lower_version_isnt_adopted() {
    // Only a higher version at no lower generation is newer (Switch spec 4.3): a copy that
    // raises the generation but lowers the version, which an honest key never signs, doesn't
    // move the mark back. The newest version is published over it.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let mut body = first.body().clone();
    body.generation += 1;
    body.signer = [7; 16];
    let odd = IdentityDoc::sign(&world.key, body).unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    world.homeserver.set(
        pubky_switch_core::records::IDENTITY_PATH,
        serde_json::to_vec(odd.signed()).unwrap(),
    );
    let changed = signer.set_record_max_age(Some(3_600)).await.unwrap();
    assert_eq!(changed.version(), 3);
    assert_eq!(signer.high_water().unwrap().version, 3);
    assert_eq!(signer.status(), pubky_switch_signer::SignerStatus::Signing);
    assert_eq!(world.published().unwrap().signed(), changed.signed());
}

#[tokio::test]
async fn test_signer_a_newer_homeserver_version_by_another_install_stops_signing() {
    // The reviewer's sequence: the Homeserver holds a verified version 4 that another install
    // signed, the switch is at this signer's version 1. The signer stops at the first
    // publication, so it never signs a version 4 of its own (Switch spec 4.3).
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let mut body = first.body().clone();
    body.version = 4;
    body.signer = [7; 16];
    let theirs = IdentityDoc::sign(&world.key, body).unwrap();
    world.homeserver.set(
        pubky_switch_core::records::IDENTITY_PATH,
        serde_json::to_vec(theirs.signed()).unwrap(),
    );
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: [7; 16] });
    assert_eq!(
        signer.status(),
        pubky_switch_signer::SignerStatus::ManagedBy { install: [7; 16] }
    );
    for seconds in [3_600, 60] {
        let error = signer.set_record_max_age(Some(seconds)).await.unwrap_err();
        assert_eq!(error, SignerError::NotNamed { install: [7; 16] });
    }
    // Nothing of this install's at version 4, and the other install's copy stays published.
    assert!(world.sent_docs().iter().all(|d| d.version() < 4));
    assert_eq!(world.published().unwrap().signed(), theirs.signed());
}

#[tokio::test]
async fn test_signer_clearing_an_alarm_once_another_install_signs_delivers_nothing() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    world.switch.deliver_identity(&first).unwrap();
    let SignerError::Alarm(alert) = signer.set_record_max_age(Some(60)).await.unwrap_err() else {
        panic!("no alarm")
    };
    // Another install then takes over.
    let second = signer.identity_doc().unwrap().unwrap();
    world
        .switch
        .deliver_identity(&world.other_install_version(&second, [7; 16]))
        .unwrap();
    signer.set_record_max_age(Some(120)).await.unwrap_err();
    assert_eq!(
        signer.status(),
        pubky_switch_signer::SignerStatus::ManagedBy { install: [7; 16] }
    );
    let sent = world.sent_docs().len();
    signer.clear_alert(&alert).await.unwrap();
    assert_eq!(world.sent_docs().len(), sent);
    // No flow is left behind: resuming has nothing to do.
    signer.resume().await.unwrap();
}

#[tokio::test]
async fn test_signer_a_single_answer_without_a_copy_is_cleared_by_the_switchs_copy() {
    // One `409 stale_identity` answers that the switch holds no copy: a rollback alarm.
    // Nothing is delivered again for it, since a switch that lost the account's state must
    // not start it afresh (Switch spec 6.5). Cleared, the switch's copy is read instead: it
    // is the mark, so the switch is confirmed and signing goes on.
    use pubky_switch_client::testing::Fault as SwitchFault;
    use pubky_switch_core::http::ErrorCode;
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::StaleIdentity,
        current: serde_json::Value::Null,
    });
    let SignerError::Alarm(alert) = signer.set_record_max_age(Some(86_400)).await.unwrap_err()
    else {
        panic!("no alarm")
    };
    assert!(matches!(alert, Alert::Rollback { version: None, .. }));
    let sent = world.sent_docs().len();
    signer.clear_alert(&alert).await.unwrap();
    assert_eq!(world.sent_docs().len(), sent);
    assert!(signer.alerts().is_empty());
    assert_eq!(signer.status(), SignerStatus::Signing);
    signer.set_record_max_age(Some(3_600)).await.unwrap();
}

#[tokio::test]
async fn test_signer_a_switch_that_lost_its_copy_stays_unconfirmed_after_the_clear() {
    // The switch really holds nothing: clearing the alert reads its copy, finds none, and
    // raises the alarm again. Nothing is signed; the way out is a provider loss.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    world.switch.lose_identity();
    let SignerError::Alarm(alert) = signer.set_record_max_age(Some(86_400)).await.unwrap_err()
    else {
        panic!("no alarm")
    };
    assert!(matches!(alert, Alert::Rollback { version: None, .. }));
    assert_eq!(
        signer.clear_alert(&alert).await.unwrap_err(),
        SignerError::Alarm(alert.clone())
    );
    assert!(signer.alerts().contains(&alert));
    assert_eq!(signer.status(), SignerStatus::Alarm);
    let sent = world.sent_docs().len();
    signer.set_record_max_age(Some(60)).await.unwrap_err();
    assert_eq!(world.sent_docs().len(), sent);
    assert!(world.switch.identity_doc().is_none());
}
