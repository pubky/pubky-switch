//! The paths a protocol adds to an app's grant, which the user may decline (Switch spec 3.4,
//! Switch wire 3.9): an app approved with the paths declined, the paths allowed at a later
//! request, and a decline the protocol's rule refuses.
//!
//! The grant is the Homeserver's matter. The switch sees the app's certificate, which
//! carries every scope whatever was declined, so a decline changes nothing the switch is
//! sent.

use std::sync::Arc;

use pubky_switch_client::app::{App, AppConfig};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_core::records::app_record_path;
use pubky_switch_signer::{Refusal, Signer, SignerError};
use serde_json::json;

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, NOTES, NOTES_PROFILE, NOTES_PROFILE_FILES, notes_protocol};
use crate::{FlowResult, World, compare};

/// The paths the test protocol adds to a grant: both or neither.
const PATHS: [&str; 2] = [NOTES_PROFILE, NOTES_PROFILE_FILES];

/// Whether the capabilities `caps` name each of [`PATHS`].
fn names_the_paths(caps: &str) -> bool {
    PATHS
        .iter()
        .all(|path| caps.split(',').any(|cap| cap == format!("{path}:rw")))
}

/// alice enrolls at a switch of `world` and her wallet asks for its record's path and for
/// [`PATHS`]. Her signer approves it, with the paths declined when `decline`, and the wallet
/// joins. Gives the signer, the wallet and the capabilities the approval granted. Every
/// outcome noted is one a decline doesn't change.
async fn approved(
    world: &World,
    decline: bool,
) -> Result<(Signer, App, String), Box<dyn std::error::Error>> {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let asking = Asking::for_scopes_with_paths(
        world.app_keys(&alice, "wallet")?,
        &[NOTES],
        &PATHS,
        [9; 32],
    )?;
    let mut review = signer.review(asking.request.signed(), &asking.auth)?;
    if decline {
        review.decline(&PATHS)?;
    }
    let approved = signer.approve(review).await?;
    signer.claim_delivered(&approved.request).await?;
    world.advance_ms(STEP_MS);
    let mut wallet = App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        notes_protocol(),
        AppConfig::default(),
        asking.join_request(alice.public(), &approved)?,
    )
    .await?;
    wallet.receive(None).await?;
    world.outcome("joined", &app_status(&mut wallet));
    world.advance_ms(STEP_MS);
    Ok((signer, wallet, approved.caps))
}

/// An app approved with its grant paths declined, and the paths allowed later (Switch spec
/// 3.4, Switch wire 3.9). alice's wallet asks for its record's path and for the two paths
/// its protocol adds. She approves the app and declines both: the grant is the record's
/// path alone, and the certificate carries every scope asked for. The switch is sent
/// exactly what it is sent when she allows them, which the flow checks against a second
/// run of the same steps with nothing declined. The wallet then asks again with the same
/// keys, and she allows the paths: the request renews the wallet's certificate, and the
/// grant names the paths.
///
/// Calls: `PUT /v1/{id}/identity` with the version that lists an app whose grant paths
/// were declined, and with the renewing version a second request of the same app brings.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the grant holds a declined
/// path or the certificate lacks a scope, the switch is sent something else than in a run
/// with the paths allowed, or the second request doesn't renew the app with the paths
/// granted.
pub async fn grant_paths_declined(world: &World) -> FlowResult {
    let (mut signer, mut wallet, caps) = approved(world, true).await?;
    let alice = world.identity("alice")?;
    let record = format!("{}:rw", app_record_path(&wallet.app_id()));
    let scopes = wallet.cert().body().scopes.clone();
    if caps != record || scopes != [NOTES] {
        return Err(format!(
            "with both paths declined the grant is {caps:?} and the certificate's scopes \
             are {scopes:?}"
        )
        .into());
    }

    // The same steps in a world of their own, with the paths allowed: every request and
    // every answer is the same.
    let allowing = World::start(world.backend())?.ok_or("the second world didn't start")?;
    let (other_signer, other_wallet, allowed) = approved(&allowing, false).await?;
    let differences = compare::differences(&world.trace(), &allowing.trace());
    let lines = (world.trace().lines.len(), allowing.trace().lines.len());
    drop((other_signer, other_wallet));
    allowing.close().await?;
    if !names_the_paths(&allowed) || !differences.is_empty() || lines.0 != lines.1 {
        return Err(format!(
            "a run with the paths allowed granted {allowed:?} and showed {} and {} lines, \
             differing in {differences:?}",
            lines.0, lines.1
        )
        .into());
    }
    world.outcome(
        "the wallet was approved with both grant paths declined",
        &json!({
            "grant_is_the_record_alone": caps == record,
            "scopes": scopes,
            "alike_with_the_paths_allowed": differences.is_empty(),
        }),
    );
    world.advance_ms(STEP_MS);

    // The wallet asks again, as with a new auth request, and the paths are allowed.
    let first = wallet.cert().hash();
    let again = Asking::for_scopes_with_paths(
        world.app_keys(&alice, "wallet")?,
        &[NOTES],
        &PATHS,
        [10; 32],
    )?;
    let review = signer.review(again.request.signed(), &again.auth)?;
    let renews = review.renews;
    let renewing = signer.approve(review).await?;
    signer.claim_delivered(&renewing.request).await?;
    let newest = signer
        .identity_doc()?
        .ok_or("the signer holds no document")?;
    world.outcome(
        "the wallet asked again and the paths were allowed",
        &json!({
            "renews": renews,
            "grant_names_the_paths": names_the_paths(&renewing.caps),
            "renewed": newest.body().renewed.len(),
            "signer": status(&signer)?,
        }),
    );
    if !renews || !names_the_paths(&renewing.caps) || newest.body().renewed.len() != 1 {
        return Err(format!(
            "the second request renews: {renews}, was granted {:?}, and the version renews \
             {} apps",
            renewing.caps,
            newest.body().renewed.len()
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    // The wallet takes the renewed certificate from its feed, and the signer's run closes
    // the renewal.
    let report = wallet.receive(None).await?;
    world.outcome(
        "the wallet received after the renewal",
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "app": app_status(&mut wallet),
        }),
    );
    world.advance_ms(STEP_MS);
    signer.run_due().await?;
    world.outcome(
        "the signer ran what is due",
        &json!({ "app": app_status(&mut wallet), "signer": status(&signer)? }),
    );
    let renewed = wallet.cert();
    if renewed.hash() == first || renewed.body().scopes != [NOTES] {
        return Err("the wallet didn't take a renewed certificate with its scope".into());
    }
    Ok(())
}

/// A decline the protocol refuses (Switch spec 3.4). The two paths go together, by the
/// protocol's own rule. alice declines one of them: the signer refuses that set at the
/// review, where nothing is signed yet and no call is made, and the set of declined paths
/// stays empty. She then approves the request as it stands, and the grant names both
/// paths.
///
/// Calls: `PUT /v1/{id}/identity` with the version that lists the app once it is
/// approved. A decline is the signer's own step and makes no call.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the decline of one path is
/// taken, or the approval that follows grants other than both paths.
pub async fn grant_paths_decline_refused(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let asking = Asking::for_scopes_with_paths(
        world.app_keys(&alice, "wallet")?,
        &[NOTES],
        &PATHS,
        [9; 32],
    )?;
    let mut review = signer.review(asking.request.signed(), &asking.auth)?;
    let offered: Vec<String> = review
        .grant_paths
        .iter()
        .map(|path| path.path.clone())
        .collect();
    let refused = review.decline(&[NOTES_PROFILE]);
    let by_rule = matches!(
        &refused,
        Err(SignerError::Refused(Refusal::ProtocolRule { .. }))
    );
    world.outcome(
        "the user declined one path of the two",
        &json!({
            "offered": offered,
            "refused_by_the_protocols_rule": by_rule,
            "declined": review.declined(),
        }),
    );
    if offered != PATHS || !by_rule || !review.declined().is_empty() {
        return Err(format!(
            "of the paths {offered:?}, declining one ended {refused:?} with {:?} declined",
            review.declined()
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    let approved = signer.approve(review).await?;
    signer.claim_delivered(&approved.request).await?;
    world.advance_ms(STEP_MS);
    let mut wallet = App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        notes_protocol(),
        AppConfig::default(),
        asking.join_request(alice.public(), &approved)?,
    )
    .await?;
    wallet.receive(None).await?;
    world.outcome(
        "the request was approved as it stood, and the wallet joined",
        &json!({
            "grant_names_the_paths": names_the_paths(&approved.caps),
            "app": app_status(&mut wallet),
        }),
    );
    if !names_the_paths(&approved.caps) {
        return Err(format!("the approval granted {:?}", approved.caps).into());
    }
    Ok(())
}
