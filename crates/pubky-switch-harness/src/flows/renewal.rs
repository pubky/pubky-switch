//! A certificate's renewal, with its key bundle (Switch spec 3.2, 3.5, Switch wire 3.8,
//! 7.4.11).

use pubky_switch_client::app::App;
use pubky_switch_signer::{CertChange, Signer};
use serde_json::json;

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// A day in milliseconds.
const DAY_MS: u64 = 24 * 3_600_000;

/// A day after an app joined, the signer renews its certificate: it delivers the renewing
/// `identity.json` and writes the new certificate and the app's key bundle to the switch.
/// The app follows its feed, takes the new certificate, fetches its key bundle and delivers
/// its record again; the signer's next routine run closes the renewal, and the app follows
/// its feed once more.
///
/// Calls, beyond the join's: `PUT /v1/{id}/identity` (the renewing and the closing
/// versions), the signer's `POST /v1/{id}/ops` (`cert.put`, `key_bundle.put`), `GET
/// /v1/{id}/apps/{app_id}/keys` with parts, and the app's `POST /v1/{id}/ops` (`app.put`
/// with the renewed certificate).
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn renewal(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    world.advance_ms(DAY_MS);

    renew_and_close(world, &mut signer, &mut wallet, "").await
}

/// The signer renews `wallet`'s certificate, the wallet takes the new one and its keys,
/// and the signer's routine run closes the renewal. `round` goes before each step's name.
async fn renew_and_close(
    world: &World,
    signer: &mut Signer,
    wallet: &mut App,
    round: &str,
) -> FlowResult {
    let renewing = signer.renew(wallet.app_id(), CertChange::default()).await?;
    world.outcome(
        &format!("{round}renewed"),
        &json!({
            "version": renewing.version(),
            "renewed": renewing.body().renewed.len(),
            "signer": status(signer)?,
        }),
    );
    world.advance_ms(STEP_MS);

    // The app learns of it from its feed, and fetches the bundle stored for it.
    for step in ["received after the renewal", "received again"] {
        let step = format!("{round}{step}");
        let report = wallet.receive(None).await?;
        world.outcome(
            &step,
            &json!({
                "events": events(&report.events),
                "stopped": report.stopped,
                "cert_expires_at": wallet.cert().body().expires_at,
                "app": app_status(wallet),
            }),
        );
        world.advance_ms(STEP_MS);
        wallet.fetch_key_bundle().await?;
        world.outcome(&format!("keys fetched, {step}"), &app_status(wallet));
        world.advance_ms(STEP_MS);
    }

    // The signer's routine run closes the renewal once the app's record carries the new
    // certificate.
    signer.run_due().await?;
    world.outcome(&format!("{round}signer ran what is due"), &status(signer)?);
    world.advance_ms(STEP_MS);

    let report = wallet.receive(None).await?;
    world.outcome(
        &format!("{round}received after the closing"),
        &json!({
            "events": events(&report.events),
            "app": app_status(wallet),
        }),
    );
    Ok(())
}

/// A certificate renewed a second time, a day after the first renewal closed: the newest
/// `identity.json` then names two earlier certificates of the app, and the app takes each
/// new one in turn.
///
/// Calls: those of [`renewal`], twice over, the second with an earlier renewal on record.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn renewed_twice(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    for round in ["first: ", "second: "] {
        world.advance_ms(DAY_MS);
        renew_and_close(world, &mut signer, &mut wallet, round).await?;
        world.advance_ms(STEP_MS);
    }
    Ok(())
}
