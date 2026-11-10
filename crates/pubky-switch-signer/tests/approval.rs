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
    let app = App::new(&["notes", "tags"], None, [9; 32]);
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
    assert_eq!(read.cert.scopes(), ["notes", "tags"]);
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
    assert_eq!(read.keys.get(1, "tags"), None);

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
        // A grant that covers identity.json.
        format!("{record},/pub/pubky-switch/:rw"),
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
