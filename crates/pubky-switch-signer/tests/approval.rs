//! Approving an app against the scripted switch (Switch spec 3.2, 12.1; Switch wire 3.9,
//! 3.10): the review's checks, the certificate and the version that lists it, and the
//! companion claim as the app reads it.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{AppRequest, Approval, ApprovalClaim, app_record_path};
use pubky_switch_core::scopes::Permission;
use pubky_switch_signer::{Refusal, SignerError};

fn refusal(error: SignerError) -> Refusal {
    match error {
        SignerError::Refused(refusal) => refusal,
        other => panic!("not a refusal: {other:?}"),
    }
}

#[tokio::test]
async fn test_approval_lists_the_app_and_the_app_reads_its_claim() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "notes_tags"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    assert_eq!(review.app_id, app.keys.app_id_bytes());
    // The permissions are the protocol's table for the scopes, in the fixed order.
    assert_eq!(
        review.permissions,
        [Permission::ClaimsRead, Permission::ListsRead]
    );
    assert_eq!(review.keyed, ["notes"]);
    assert_eq!(review.grant_paths.len(), 1);
    assert_eq!(review.grant_paths[0].path, TAGS_PATH);

    let approved = signer.approve(review).await.unwrap();
    assert_eq!(approved.app_id, app.keys.app_id_bytes());
    assert_eq!(approved.caps, app.auth.caps);
    // The version listing the certificate is delivered, published and backed up.
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.version(), 2);
    let cert_hash = doc.listed_cert(&app.keys.app_id_bytes()).unwrap();
    assert_eq!(world.switch.identity_doc().unwrap().signed(), doc.signed());
    assert_eq!(world.published().unwrap().signed(), doc.signed());
    let records = world.backup();
    assert_eq!(records.identity_doc().signed(), doc.signed());
    assert!(records.certs().iter().any(|c| c.hash() == cert_hash));

    // The app checks the claim and reads the approval, opening its key bundle (Switch wire
    // 3.10).
    let identity = world.key.public();
    let claim = ApprovalClaim::from_plaintext(&approved.claim).unwrap();
    let json = claim.verify(&identity, &app.auth).unwrap();
    let request = AppRequest::verify(&app.request).unwrap();
    let has_keys = |scope: &str| scope == "notes";
    let read = Approval::read(
        json,
        &request,
        &identity,
        &app.keys.bundle_secret(),
        &has_keys,
    )
    .unwrap();
    assert_eq!(read.cert.hash(), cert_hash);
    assert_eq!(read.cert.scopes(), ["notes", "notes_tags"]);
    assert_eq!(
        read.cert.permissions(),
        [Permission::ClaimsRead, Permission::ListsRead]
    );
    assert_eq!(read.identity.signed(), doc.signed());
    assert_eq!(read.naming_key, world.key.naming_key());
    assert_eq!(
        read.keys.get(1, "notes"),
        Some(world.key.scope_key(1, "notes"))
    );
    assert_eq!(read.keys.get(1, "notes_tags"), None);

    // The host reports it delivered: the claim is dropped.
    assert!(signer.approved(&approved.request).unwrap().is_some());
    signer.claim_delivered(&approved.request).await.unwrap();
    assert!(signer.approved(&approved.request).unwrap().is_none());
}

#[tokio::test]
async fn test_approval_of_a_listed_app_is_refused() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    signer.approve(review).await.unwrap();
    let error = signer.review(&app.request, &app.auth).unwrap_err();
    assert_eq!(refusal(error), Refusal::AlreadyListed);
}

#[tokio::test]
async fn test_review_refuses_a_scope_no_protocol_owns() {
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    let app = App::new(&["notes", "photos"], None, [9; 32]);
    let error = signer.review(&app.request, &app.auth).unwrap_err();
    assert_eq!(
        refusal(error),
        Refusal::UnknownScopes {
            scopes: vec!["photos".into()]
        }
    );
}

#[tokio::test]
async fn test_review_refuses_capabilities_that_arent_the_apps_own() {
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    let record = format!(
        "{}:rw",
        app_record_path(&AppKeys::from_secrets([3; 32], [4; 32]).app_id_bytes())
    );
    for caps in [
        // A path the app's protocols don't add for its scopes.
        format!("{record},{TAGS_PATH}:rw"),
        // No record path.
        format!("{TAGS_PATH}:rw"),
    ] {
        let app = App::new(&["notes"], Some(caps.clone()), [9; 32]);
        let error = signer.review(&app.request, &app.auth).unwrap_err();
        assert!(
            matches!(refusal(error), Refusal::AppRequest(ref why) if why.contains("step 3")),
            "{caps}"
        );
    }
}

#[tokio::test]
async fn test_review_refuses_a_request_bound_to_another_auth_request() {
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let mut other = app.auth.clone();
    other.secret = [10; 32];
    let error = signer.review(&app.request, &other).unwrap_err();
    assert!(matches!(refusal(error), Refusal::AppRequest(ref why) if why.contains("step 2")),);
}

#[tokio::test]
async fn test_review_needs_a_first_version() {
    let world = World::new();
    let signer = pubky_switch_signer::Signer::create(
        world.env(std::sync::Arc::new(
            pubky_switch_client::store::MemoryStore::new(),
        )),
        world.keyring(),
        pubky_switch_client::testing::SWITCH_ORIGIN,
    )
    .await
    .unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    let error = signer.review(&app.request, &app.auth).unwrap_err();
    assert_eq!(refusal(error), Refusal::NotSetUp);
}

#[tokio::test]
async fn test_approval_claim_waits_for_its_delivery() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let request = review.request_hash();
    *world.homeserver.failing_puts.lock().unwrap() = true;
    let error = signer.approve(review).await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    // Not delivered, so not released.
    assert!(signer.approved(&request).unwrap().is_none());
    assert_eq!(world.switch.identity_doc().unwrap().version(), 1);
    *world.homeserver.failing_puts.lock().unwrap() = false;
    signer.resume().await.unwrap();
    let approved = signer.approved(&request).unwrap().unwrap();
    let claim = ApprovalClaim::from_plaintext(&approved.claim).unwrap();
    claim.verify(&world.key.public(), &app.auth).unwrap();
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_approval_claim_of_a_refused_delivery_is_never_released() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    world.switch.deliver_identity(&first).unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let request = review.request_hash();
    let error = signer.approve(review).await.unwrap_err();
    assert!(matches!(error, SignerError::Alarm(_)), "{error:?}");
    assert!(signer.approved(&request).unwrap().is_none());
}

#[tokio::test]
async fn test_review_refuses_a_grant_that_covers_identity_json() {
    // Only the covers check refuses this: the reason names it (Switch wire 3.9 step 3).
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    let record = format!(
        "{}:rw",
        app_record_path(&AppKeys::from_secrets([3; 32], [4; 32]).app_id_bytes())
    );
    for covering in [
        "/pub/pubky-switch/",
        "/pub/",
        "/pub/pubky-switch/v1/signer-backup.json",
    ] {
        let app = App::new(&["notes"], Some(format!("{record},{covering}:rw")), [9; 32]);
        let error = signer.review(&app.request, &app.auth).unwrap_err();
        assert!(
            matches!(refusal(error), Refusal::AppRequest(ref why) if why.contains("covers")),
            "{covering}"
        );
    }
}

#[tokio::test]
async fn test_review_refuses_an_app_id_the_newest_version_lists_as_removed() {
    // Wire 3.9 step 4. The revocations PR writes the signer's own tombstones; here the
    // newest version, adopted from the switch, another install's, lists the app in `removed`.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let newest = signer.identity_doc().unwrap().unwrap();
    let mut body = newest.body().clone();
    body.version += 1;
    body.signer = [7; 16];
    body.removed.push(pubky_switch_core::records::RemovedApp {
        app_id: app.keys.app_id_bytes(),
        distrust_from: START_MS,
    });
    let removing = pubky_switch_core::records::IdentityDoc::sign(&world.key, body).unwrap();
    world.switch.deliver_identity(&removing).unwrap();
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: [7; 16] });
    let error = signer.review(&app.request, &app.auth).unwrap_err();
    assert!(matches!(refusal(error), Refusal::AppRequest(ref why) if why.contains("step 4")),);
}

#[tokio::test]
async fn test_review_refuses_an_app_past_the_app_limit() {
    // Wire 3.9 step 6, at the limit the switch announced at enrollment.
    let world = World::new();
    world
        .switch
        .set_enroll_limits(pubky_switch_core::records::Limits {
            app_limit: 1,
            ..Default::default()
        });
    let (mut signer, _) = world.enrolled().await;
    let first = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&first.request, &first.auth).unwrap();
    signer.approve(review).await.unwrap();
    let second = App::with_keys(
        AppKeys::from_secrets([5; 32], [6; 32]),
        &["notes"],
        None,
        [10; 32],
    );
    let error = signer.review(&second.request, &second.auth).unwrap_err();
    assert!(matches!(refusal(error), Refusal::AppRequest(ref why) if why.contains("step 6")),);
}

#[tokio::test]
async fn test_approval_claim_waits_for_the_publish_and_for_alarms() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let request = review.request_hash();
    // Delivered, but the publish fails: no claim yet (Switch wire 3.9).
    *world.homeserver.failing_path.lock().unwrap() =
        Some(pubky_switch_core::records::IDENTITY_PATH.into());
    let error = signer.approve(review).await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    assert_eq!(world.switch.identity_doc().unwrap().version(), 2);
    assert!(signer.approved(&request).unwrap().is_none());
    *world.homeserver.failing_path.lock().unwrap() = None;
    signer.resume().await.unwrap();
    assert!(signer.approved(&request).unwrap().is_some());
    // The switch rolls back: the alarm holds the claim back until the user clears it.
    world.switch.deliver_identity(&first).unwrap();
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    let SignerError::Alarm(alert) = error else {
        panic!("{error:?}")
    };
    assert!(signer.approved(&request).unwrap().is_none());
    // Clearing it delivers the newest version again; the switch, back at version 1, takes it,
    // and only then is the claim released.
    signer.clear_alert(&alert).await.unwrap();
    let at_switch = world.switch.identity_doc().unwrap();
    assert_eq!(at_switch.version(), 2);
    assert!(at_switch.listed_cert(&app.keys.app_id_bytes()).is_some());
    assert!(signer.approved(&request).unwrap().is_some());
    world.assert_no_version_sent_twice();
}

#[tokio::test]
async fn test_approval_clearing_an_alarm_the_switch_still_shows_keeps_the_claim_held() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    // The switch holds another version 2: equivocation.
    let mut body = first.body().clone();
    body.version = 2;
    body.record_max_age = Some(60);
    let forked = pubky_switch_core::records::IdentityDoc::sign(&world.key, body).unwrap();
    world.switch.deliver_identity(&forked).unwrap();
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    let SignerError::Alarm(alert) = error else {
        panic!("{error:?}")
    };
    // Clearing it delivers version 2 again, which the switch refuses: the alarm comes back.
    let error = signer.clear_alert(&alert).await.unwrap_err();
    assert_eq!(error, SignerError::Alarm(alert));
    assert!(signer.approved(&approved.request).unwrap().is_none());
}

#[tokio::test]
async fn test_approval_after_an_old_alarm_waits_for_the_alert_to_be_cleared() {
    // The switch went back and is put back as it was: nothing is signed while the alert is
    // held. Once the user clears it, the re-delivery confirms the switch, and the approval and
    // its claim go through.
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    world.switch.deliver_identity(&first).unwrap();
    let SignerError::Alarm(alert) = signer.set_record_max_age(Some(3_600)).await.unwrap_err()
    else {
        panic!("no alarm")
    };
    let second = signer.identity_doc().unwrap().unwrap();
    world.switch.deliver_identity(&second).unwrap();
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let sent = world.sent_docs().len();
    assert_eq!(
        signer.approve(review.clone()).await.unwrap_err(),
        SignerError::Alarm(alert.clone())
    );
    assert_eq!(world.sent_docs().len(), sent);
    signer.clear_alert(&alert).await.unwrap();
    let approved = signer.approve(review).await.unwrap();
    assert_eq!(signer.approved(&approved.request).unwrap(), Some(approved));
}

#[tokio::test]
async fn test_approval_claim_is_held_while_another_install_signs() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    let newest = signer.identity_doc().unwrap().unwrap();
    world
        .switch
        .deliver_identity(&world.other_install_version(&newest, [7; 16]))
        .unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert!(signer.approved(&approved.request).unwrap().is_none());
}

#[tokio::test]
async fn test_approval_claim_is_held_while_the_records_are_behind() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    assert!(signer.approved(&approved.request).unwrap().is_some());
    // The switch then shows a newer version of this install's own.
    let newest = signer.identity_doc().unwrap().unwrap();
    world
        .switch
        .deliver_identity(&world.other_install_version(&newest, signer.install_id()))
        .unwrap();
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert!(
        matches!(error, SignerError::Refused(Refusal::RecordsBehind { .. })),
        "{error:?}"
    );
    assert!(signer.approved(&approved.request).unwrap().is_none());
}

#[tokio::test]
async fn test_approval_a_refused_delivery_leaves_no_certificate() {
    use pubky_switch_client::testing::Fault as SwitchFault;
    use pubky_switch_core::http::ErrorCode;
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    world.switch.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    let review = signer.review(&app.request, &app.auth).unwrap();
    signer.approve(review).await.unwrap_err();
    assert!(signer.certificates().unwrap().is_empty());
    // Approving the same request again holds one certificate for the App ID.
    let review = signer.review(&app.request, &app.auth).unwrap();
    signer.approve(review).await.unwrap();
    let id = app.keys.app_id_bytes();
    let held = signer.certificates().unwrap();
    assert_eq!(held.iter().filter(|c| c.app_id() == id).count(), 1);
}

#[tokio::test]
async fn test_approval_a_reopened_signer_releases_the_same_claim_bytes() {
    // The bytes `approve` returned are the bytes a reopened signer gives: signed once, never
    // again (the approval seals its bundle with fresh randomness, so a second signing would
    // differ).
    let world = World::new();
    let (mut signer, store) = world.enrolled().await;
    let app = App::new(&["notes"], None, [9; 32]);
    let review = signer.review(&app.request, &app.auth).unwrap();
    let request = review.request_hash();
    let before = signer.approve(review).await.unwrap();
    drop(signer);
    let mut reopened = pubky_switch_signer::Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    reopened.resume().await.unwrap();
    let first = reopened.approved(&request).unwrap().unwrap();
    assert_eq!(first.claim, before.claim);
    ApprovalClaim::from_plaintext(&first.claim)
        .unwrap()
        .verify(&world.key.public(), &app.auth)
        .unwrap();
}
