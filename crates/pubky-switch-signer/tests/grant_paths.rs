//! Grant paths the user declines at an approval (Switch spec 3.4, 12.1 step 1; Switch wire
//! 3.9, 3.10): the capabilities to grant leave them out, in the asked order, whichever way
//! the approval goes, and the certificate is the one asked for.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::SWITCH_ORIGIN;
use pubky_switch_core::records::{app_backup_path, app_record_path};
use pubky_switch_core::scopes::Permission;
use pubky_switch_signer::{GrantPath, Protocol, Protocols, Refusal, ScopeDef, Signer, SignerError};

const PROFILE: &str = "/pub/media/profile.json";
const FILES: &str = "/pub/media/files/";
const FEED: &str = "/pub/media/feed.json";

/// A protocol adding three grant paths, of which the profile and its files go only together.
struct Media;

impl Protocol for Media {
    fn name(&self) -> &str {
        "media"
    }
    fn scopes(&self) -> Vec<ScopeDef> {
        vec![ScopeDef::keyed("media")]
    }
    fn check_scopes(&self, _: &[&str]) -> Result<(), String> {
        Ok(())
    }
    fn permissions(&self, _: &[&str]) -> Vec<Permission> {
        vec![Permission::ListsRead]
    }
    fn grant_paths(&self, _: &[u8; 16], _: &[&str]) -> Vec<GrantPath> {
        [PROFILE, FILES, FEED]
            .iter()
            .map(|path| GrantPath {
                path: (*path).into(),
                purpose: "a media file".into(),
            })
            .collect()
    }
    fn check_grant_paths(&self, allowed: &[&str]) -> Result<(), String> {
        if allowed.iter().any(|p| ![PROFILE, FILES, FEED].contains(p)) {
            return Err("a path media didn't add".into());
        }
        if allowed.contains(&PROFILE) != allowed.contains(&FILES) {
            return Err("the profile and its files go together".into());
        }
        Ok(())
    }
}

fn protocols() -> Protocols {
    Protocols::new(vec![Arc::new(Notes), Arc::new(Media)]).unwrap()
}

/// A signer of `world`'s identity with [`Notes`] and [`Media`] registered, enrolled and
/// serving.
async fn enrolled(world: &World) -> (Signer, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let env = world.env_with(store.clone(), protocols());
    let mut signer = Signer::create(env, world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    (signer, store)
}

/// The capabilities naming the app's record, then `paths`, in that order.
fn caps(app: &[u8; 16], paths: &[&str]) -> String {
    std::iter::once(app_record_path(app))
        .chain(paths.iter().map(|p| (*p).to_owned()))
        .map(|p| format!("{p}:rw"))
        .collect::<Vec<_>>()
        .join(",")
}

/// An app asking for `scopes` and for the record and `paths` as its capabilities.
fn app(scopes: &[&str], paths: &[&str], secret: [u8; 32]) -> App {
    let id = App::new(&["media"], None, secret).keys.app_id_bytes();
    App::new(scopes, Some(caps(&id, paths)), secret)
}

fn refusal(error: SignerError) -> Refusal {
    match error {
        SignerError::Refused(refusal) => refusal,
        other => panic!("not a refusal: {other:?}"),
    }
}

#[tokio::test]
async fn test_grant_paths_declined_are_left_out_of_the_caps() {
    let world = World::new();
    let (mut signer, _) = enrolled(&world).await;
    let app = app(&["media"], &[PROFILE, FILES, FEED], [9; 32]);
    let id = app.keys.app_id_bytes();
    let mut review = signer.review(&app.request, &app.auth).unwrap();
    let shown: Vec<&str> = review.grant_paths.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(shown, [PROFILE, FILES, FEED]);
    assert_eq!(review.asked_caps, app.auth.caps);
    review.decline(&[FEED]).unwrap();
    assert_eq!(review.declined(), [FEED]);
    // A review of the same request declines nothing: the declines are the user's, on this
    // review.
    assert!(
        signer
            .review(&app.request, &app.auth)
            .unwrap()
            .declined()
            .is_empty()
    );

    let approved = signer.approve(review).await.unwrap();
    assert_eq!(approved.caps, caps(&id, &[PROFILE, FILES]));
    // The certificate is the one asked for: a decline changes only the grant.
    let cert = world.join(&app, &approved);
    assert_eq!(cert.scopes(), ["media"]);
    assert_eq!(cert.permissions(), [Permission::ListsRead]);
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.listed_cert(&id), Some(cert.hash()));
}

#[tokio::test]
async fn test_grant_paths_declined_from_the_middle_keep_the_order_of_the_rest() {
    let world = World::new();
    let (mut signer, _) = enrolled(&world).await;
    let app = app(&["media"], &[FEED, PROFILE, FILES], [9; 32]);
    let id = app.keys.app_id_bytes();
    let mut review = signer.review(&app.request, &app.auth).unwrap();
    review.decline(&[FILES, PROFILE]).unwrap();
    let approved = signer.approve(review).await.unwrap();
    assert_eq!(approved.caps, caps(&id, &[FEED]));
    signer.claim_delivered(&approved.request).await.unwrap();
    world.join(&app, &approved);

    let other = app_with_backup(&id, [10; 32]);
    let mut review = signer.review(&other.request, &other.auth).unwrap();
    review.decline(&[PROFILE, FILES]).unwrap();
    let approved = signer.approve(review).await.unwrap();
    let record = format!("{}:rw", app_record_path(&id));
    let backup = format!("{}:rw", app_backup_path(&id));
    assert_eq!(approved.caps, format!("{backup},{record},{FEED}:rw"));
}

/// The app of [`app`], asking again for its backup folder first, then its record, the
/// profile, its files and the feed.
fn app_with_backup(id: &[u8; 16], secret: [u8; 32]) -> App {
    let caps = [
        app_backup_path(id),
        app_record_path(id),
        PROFILE.into(),
        FILES.into(),
        FEED.into(),
    ]
    .map(|p| format!("{p}:rw"))
    .join(",");
    App::new(&["media"], Some(caps), secret)
}

#[tokio::test]
async fn test_grant_paths_that_go_together_are_declined_together() {
    let world = World::new();
    let (mut signer, _) = enrolled(&world).await;
    let app = app(&["media"], &[PROFILE, FILES, FEED], [9; 32]);
    let id = app.keys.app_id_bytes();
    let mut review = signer.review(&app.request, &app.auth).unwrap();
    review.decline(&[FEED]).unwrap();
    // Declining the profile alone breaks the protocol's rule: the host learns it at once,
    // with the rule, and the set stays as it was.
    match refusal(review.decline(&[PROFILE]).unwrap_err()) {
        Refusal::ProtocolRule { protocol, reason } => {
            assert_eq!(protocol, "media");
            assert_eq!(reason, "the profile and its files go together");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(review.declined(), [FEED]);
    review.decline(&[PROFILE, FILES]).unwrap();
    let approved = signer.approve(review).await.unwrap();
    assert_eq!(approved.caps, caps(&id, &[FEED]));
}

#[tokio::test]
async fn test_grant_paths_a_request_breaking_the_rule_is_refused_at_its_review() {
    let world = World::new();
    let (signer, _) = enrolled(&world).await;
    let app = app(&["media"], &[PROFILE, FEED], [9; 32]);
    let error = signer.review(&app.request, &app.auth).unwrap_err();
    assert!(
        matches!(refusal(error), Refusal::ProtocolRule { ref protocol, .. } if protocol == "media")
    );
}

#[tokio::test]
async fn test_grant_paths_only_the_added_ones_asked_for_are_declinable() {
    let world = World::new();
    let (signer, _) = enrolled(&world).await;
    let id = app(&["media"], &[], [9; 32]).keys.app_id_bytes();
    let asking = app_with_backup(&id, [9; 32]);
    let mut review = signer.review(&asking.request, &asking.auth).unwrap();
    let record = app_record_path(&id);
    let backup = app_backup_path(&id);
    for path in [record.as_str(), backup.as_str(), "/pub/other.json"] {
        match refusal(review.decline(&[path]).unwrap_err()) {
            Refusal::NotDeclinable { path: refused } => assert_eq!(refused, path),
            other => panic!("{other:?}"),
        }
    }
    // A path the protocol adds but the app didn't ask for isn't shown, and isn't declinable.
    let few = app(&["media"], &[FEED], [10; 32]);
    let mut review = signer.review(&few.request, &few.auth).unwrap();
    assert_eq!(review.grant_paths.len(), 1);
    assert!(matches!(
        refusal(review.decline(&[PROFILE, FILES]).unwrap_err()),
        Refusal::NotDeclinable { .. }
    ));
    assert!(review.declined().is_empty());
}

#[tokio::test]
async fn test_grant_paths_each_protocol_judges_its_own_paths() {
    // Media's rule refuses any path it didn't add: it is given only its own, so declining
    // the notes protocol's path leaves it to judge the profile, its files and the feed.
    let world = World::new();
    let (mut signer, _) = enrolled(&world).await;
    let app = app(
        &["media", "notes_tags"],
        &[TAGS_PATH, PROFILE, FILES, FEED],
        [9; 32],
    );
    let id = app.keys.app_id_bytes();
    let mut review = signer.review(&app.request, &app.auth).unwrap();
    assert_eq!(review.grant_paths.len(), 4);
    review.decline(&[TAGS_PATH, FEED]).unwrap();
    let approved = signer.approve(review).await.unwrap();
    assert_eq!(approved.caps, caps(&id, &[PROFILE, FILES]));
}

#[tokio::test]
async fn test_grant_paths_a_decline_replaces_the_one_before() {
    let world = World::new();
    let (mut signer, _) = enrolled(&world).await;
    let app = app(&["media"], &[PROFILE, FILES, FEED], [9; 32]);
    let mut review = signer.review(&app.request, &app.auth).unwrap();
    review.decline(&[FEED, FEED]).unwrap();
    assert_eq!(review.declined(), [FEED]);
    review.decline(&[]).unwrap();
    assert!(review.declined().is_empty());
    let approved = signer.approve(review).await.unwrap();
    assert_eq!(approved.caps, app.auth.caps);
}

#[tokio::test]
async fn test_grant_paths_declined_at_a_renewing_request_are_left_out() {
    // The app asks again with its listed keys: a renewal (Switch wire 3.9 step 5), whose
    // grant leaves out what the user declines there.
    let world = World::new();
    let (mut signer, _) = enrolled(&world).await;
    let first = app(&["media"], &[PROFILE, FILES, FEED], [9; 32]);
    let id = first.keys.app_id_bytes();
    let review = signer.review(&first.request, &first.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    world.join(&first, &approved);
    let before = signer.identity_doc().unwrap().unwrap().listed_cert(&id);

    let again = app(&["media"], &[PROFILE, FILES, FEED], [10; 32]);
    let mut review = signer.review(&again.request, &again.auth).unwrap();
    assert!(review.renews);
    review.decline(&[PROFILE, FILES]).unwrap();
    let approved = signer.approve(review).await.unwrap();
    assert_eq!(approved.caps, caps(&id, &[FEED]));
    let after = signer.identity_doc().unwrap().unwrap().listed_cert(&id);
    assert_ne!(after, before);
    let cert = signer
        .certificates()
        .unwrap()
        .into_iter()
        .find(|c| Some(c.hash()) == after)
        .unwrap();
    assert_eq!(cert.scopes(), ["media"]);
}

#[tokio::test]
async fn test_grant_paths_a_later_request_leaving_a_path_out_declines_nothing() {
    // The app asks again without the feed: that isn't the user declining it, and nothing is
    // declined; the grant covers only what the request names.
    let world = World::new();
    let (mut signer, _) = enrolled(&world).await;
    let first = app(&["media"], &[PROFILE, FILES, FEED], [9; 32]);
    let id = first.keys.app_id_bytes();
    world.approve(&mut signer, &first).await;
    let again = app(&["media"], &[PROFILE, FILES], [10; 32]);
    let review = signer.review(&again.request, &again.auth).unwrap();
    assert!(review.renews);
    let shown: Vec<&str> = review.grant_paths.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(shown, [PROFILE, FILES]);
    assert!(review.declined().is_empty());
    let approved = signer.approve(review).await.unwrap();
    assert_eq!(approved.caps, caps(&id, &[PROFILE, FILES]));
}

#[tokio::test]
async fn test_grant_paths_declined_stay_out_after_a_crash_before_the_claim() {
    // The approval was committed but its version wasn't published: a reopened signer gives
    // the claim with the capabilities the user allowed, not the ones asked for.
    let world = World::new();
    let (mut signer, store) = enrolled(&world).await;
    let app = app(&["media"], &[PROFILE, FILES, FEED], [9; 32]);
    let id = app.keys.app_id_bytes();
    let mut review = signer.review(&app.request, &app.auth).unwrap();
    review.decline(&[FEED]).unwrap();
    let request = review.request_hash();
    *world.homeserver.failing_puts.lock().unwrap() = true;
    signer.approve(review).await.unwrap_err();
    drop(signer);
    *world.homeserver.failing_puts.lock().unwrap() = false;
    let env = world.env_with(store, protocols());
    let mut reopened = Signer::open(env, world.keyring()).await.unwrap();
    reopened.resume().await.unwrap();
    let approved = reopened.approved(&request).unwrap().unwrap();
    assert_eq!(approved.caps, caps(&id, &[PROFILE, FILES]));
}

#[tokio::test]
async fn test_grant_paths_declined_stay_out_of_a_renewal_after_a_crash() {
    let world = World::new();
    let (mut signer, store) = enrolled(&world).await;
    let first = app(&["media"], &[PROFILE, FILES, FEED], [9; 32]);
    let id = first.keys.app_id_bytes();
    world.approve(&mut signer, &first).await;
    let again = app(&["media"], &[PROFILE, FILES, FEED], [10; 32]);
    let mut review = signer.review(&again.request, &again.auth).unwrap();
    review.decline(&[PROFILE, FILES]).unwrap();
    let request = review.request_hash();
    *world.homeserver.failing_puts.lock().unwrap() = true;
    signer.approve(review).await.unwrap_err();
    drop(signer);
    *world.homeserver.failing_puts.lock().unwrap() = false;
    let env = world.env_with(store, protocols());
    let mut reopened = Signer::open(env, world.keyring()).await.unwrap();
    reopened.resume().await.unwrap();
    let approved = reopened.approved(&request).unwrap().unwrap();
    assert_eq!(approved.caps, caps(&id, &[FEED]));
}
