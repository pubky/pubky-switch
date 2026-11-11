//! Removing an app: a revocation by the signer, and a departure by the app itself, each
//! with the rotation that follows (Switch spec 12.2, 12.3, 3.5, Switch wire 7.4.11, 7.4.12).

use pubky_switch_client::app::{App, AppError, LeaveMode};
use pubky_switch_signer::UserConfirmed;
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// The signer revokes one of two apps: at the switch, then with the rotation and the version
/// that removes it. The app that stays follows its feed and fetches the new epoch's keys;
/// the revoked app is refused. An app approved after the rotation joins at the new epoch,
/// with every key it needs in its approval.
///
/// Calls, beyond the join's: `POST /v1/{id}/apps/{app_id}/revoke`, the signer's `POST
/// /v1/{id}/ops` (`key_bundle.put` for the rotation), `PUT /v1/{id}/identity` (the removing
/// version), `GET /v1/{id}/apps/{app_id}/keys` with parts, and a revoked app's refused `GET
/// /v1/{id}/feed` and `GET /v1/{id}/apps/{app_id}/keys`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn revocation(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (mut phone, _) = joined(world, &alice, &mut signer, "phone").await?;

    let removing = signer
        .revoke(phone.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "revoked",
        &json!({
            "version": removing.version(),
            "data_epoch": removing.body().data_epoch,
            "removed": removing.body().removed.len(),
            "signer": status(&signer)?,
        }),
    );
    world.advance_ms(STEP_MS);

    follow(world, &mut wallet, "the wallet after the revocation").await?;
    let refused = phone.receive(None).await;
    world.outcome("the revoked phone reads its feed", &result(&refused));
    world.advance_ms(STEP_MS);

    // An app approved now joins at the new epoch.
    let (mut tablet, _) = joined(world, &alice, &mut signer, "tablet").await?;
    follow(world, &mut tablet, "the tablet").await?;
    signer.run_due().await?;
    world.outcome("signer ran what is due", &status(&signer)?);
    world.advance_ms(STEP_MS);
    follow(world, &mut wallet, "the wallet at the end").await?;
    Ok(())
}

/// One of two apps leaves in two steps: `leave` at the switch, then, once the signer's
/// routine run rotated and published it as removed, the wait and the deletion of its keys.
/// The app that stays follows its feed and fetches the new epoch's keys.
///
/// Calls, beyond the join's: `POST /v1/{id}/apps/{app_id}/leave`, the signer's `GET
/// /v1/{id}/apps` showing the departure, its `POST /v1/{id}/ops` (`key_bundle.put`) and `PUT
/// /v1/{id}/identity` (the removing version).
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn departure(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (mut phone, _) = joined(world, &alice, &mut signer, "phone").await?;

    let left = phone.leave(LeaveMode::TwoStep).await?;
    world.outcome("the phone left", &json!({ "report": format!("{left:?}") }));
    world.advance_ms(STEP_MS);

    signer.run_due().await?;
    world.outcome("signer ran what is due", &status(&signer)?);
    world.advance_ms(STEP_MS);

    let waiting = phone.finish_leave().await?;
    world.outcome(
        "the phone sees its removal",
        &json!({ "report": format!("{waiting:?}").split(' ').next() }),
    );
    world.advance_ms(pubky_switch_client::app::LEAVE_CACHE_MS + STEP_MS);
    let done = phone.finish_leave().await?;
    world.outcome(
        "the phone deleted its keys",
        &json!({ "report": format!("{done:?}") }),
    );

    follow(world, &mut wallet, "the wallet after the departure").await?;
    Ok(())
}

/// `app` follows its feed and fetches its key bundle, with what it shows after each.
pub(crate) async fn follow(world: &World, app: &mut App, name: &str) -> FlowResult {
    let report = app.receive(None).await?;
    world.outcome(
        &format!("{name}: received"),
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "app": app_status(app),
        }),
    );
    world.advance_ms(STEP_MS);
    app.fetch_key_bundle().await?;
    world.outcome(&format!("{name}: keys fetched"), &app_status(app));
    world.advance_ms(STEP_MS);
    Ok(())
}

/// How a call ended, for the trace: the error's kind and its code at the switch, never its
/// text.
fn result<T>(result: &Result<T, AppError>) -> Value {
    match result {
        Ok(_) => json!({ "ok": true }),
        Err(error) => {
            let shown = format!("{error:?}");
            let kind = shown.split(|c: char| !c.is_ascii_alphanumeric()).next();
            json!({
                "ok": false,
                "error": kind,
                "code": error.code().map(|code| code.as_str().to_owned()),
            })
        }
    }
}
