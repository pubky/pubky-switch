//! An app restored from a backup older than a rotation (Switch spec 12.4, 3.5, Switch wire
//! 7.4.10, 7.4.11): it reads its own directory and the lists, follows its feed from the
//! backup's cursor, and catches up on the keys of the epoch it missed.

use std::sync::Arc;

use pubky_switch_client::app::{App, AppConfig};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_signer::UserConfirmed;
use serde_json::json;

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::parties::notes_protocol;
use crate::{FlowResult, World};

/// The wallet takes a backup. The signer then revokes the identity's other app and rotates;
/// the wallet follows its feed, fetches the new epoch's keys and moves its cursor. Then the
/// wallet's device is lost, and the wallet is restored from the backup on a new one: it
/// reads its own directory and the lists, follows its feed from the backup's cursor, and
/// fetches the new epoch's keys again.
///
/// The restored wallet asks for a full bundle: the bundle part of the new epoch went once the
/// wallet's cursor passed it before the loss (Switch wire 6.2), so the restored wallet,
/// behind it again, lacks that epoch's keys.
///
/// Calls, beyond a revocation's: an own app's `GET /v1/{id}/directory`, `GET /v1/{id}/allow`
/// after a restore, `GET /v1/{id}/feed` from an earlier cursor, `GET
/// /v1/{id}/apps/{app_id}/keys` once its part is gone, and `POST
/// /v1/{id}/apps/{app_id}/keys`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn restore(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (phone, _) = joined(world, &alice, &mut signer, "phone").await?;
    wallet.receive(None).await?;
    wallet.flush_cursor().await?;
    let backup = wallet.backup().await?;
    world.outcome("backed up", &app_status(&mut wallet));
    world.advance_ms(STEP_MS);

    signer
        .revoke(phone.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome("revoked", &status(&signer)?);
    world.advance_ms(STEP_MS);
    follow(world, &mut wallet, "the wallet after the rotation").await?;
    // The device is lost with everything the wallet learned since the backup.
    drop(wallet);

    let mut restored = App::restore(
        world.app_env(Arc::new(MemoryStore::new())),
        notes_protocol(),
        AppConfig::default(),
        &backup,
    )
    .await?;
    world.outcome("restored", &app_status(&mut restored));
    world.advance_ms(STEP_MS);
    follow(world, &mut restored, "the restored wallet").await?;

    signer.run_due().await?;
    world.outcome("signer ran what is due", &status(&signer)?);
    world.advance_ms(STEP_MS);
    follow(
        world,
        &mut restored,
        "the restored wallet after the signer's run",
    )
    .await?;
    Ok(())
}

/// `app` follows its feed, moves its cursor and fetches its key bundle, with what it raised
/// and where it stands after each.
async fn follow(world: &World, app: &mut App, name: &str) -> FlowResult {
    let report = app.receive(None).await?;
    app.flush_cursor().await?;
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
