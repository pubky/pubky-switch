//! The signer's hand-over to another install (Switch spec 12.8, Switch wire 3.12, 7.4.17):
//! stored at the switch for one of the identity's apps, fetched by it, and dropped by the
//! next version of `identity.json`.

use std::sync::Arc;

use pubky_switch_client::app::App;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::TestIdentity;
use pubky_switch_signer::{ReceivingApp, Signer, UserConfirmed};
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// How a signer's call ended, for the trace: nothing of an error but its kinds.
fn ended<T, E: std::fmt::Debug>(result: &Result<T, E>) -> Value {
    match result {
        Ok(_) => json!({ "ok": true }),
        Err(error) => {
            let shown = format!("{error:?}");
            let kinds: Vec<&str> = shown
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| word.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
                .take(4)
                .collect();
            json!({ "ok": false, "error": kinds.join(" ") })
        }
    }
}

/// What the install taking the identity over presents: the receiving app's keys and
/// certificate, and the switch its `identity.json` names.
fn receiving(
    world: &World,
    identity: &TestIdentity,
    name: &str,
    app: &App,
) -> Result<ReceivingApp, crate::HarnessError> {
    Ok(ReceivingApp {
        keys: world.app_keys(identity, name)?,
        cert: app.cert().clone(),
        origin: ORIGIN.to_owned(),
        service_key: app.own_identity().inbox().service_key,
    })
}

/// The signer hands the identity over to the install of one of its apps. The first try's
/// answer is lost, so the hand-over is stored twice. The new install fetches it as that
/// app, takes the identity over with its first `identity.json` version, and the switch
/// drops the stored hand-over. The old install then finds itself succeeded; the new one
/// runs what is due, and the app follows its feed.
///
/// Calls: `PUT /v1/{id}/handover` (twice, the same hand-over), `GET /v1/{id}/handover` by
/// the target app, `PUT /v1/{id}/identity` by the new install, and the old install's reads
/// after it.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn hand_over(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut old = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut old, "wallet").await?;
    let (mut phone, _) = joined(world, &alice, &mut old, "phone").await?;

    world.lose_answer("PUT", "/handover");
    let lost = old
        .hand_over_to(wallet.app_id(), UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the hand-over was stored, and the answer lost",
        &json!({ "ended": ended(&lost), "signer": status(&old)? }),
    );
    world.advance_ms(STEP_MS);
    let again = old.resume().await;
    world.outcome(
        "the hand-over stored again",
        &json!({ "ended": ended(&again), "signer": status(&old)? }),
    );
    world.advance_ms(STEP_MS);

    // The new install, with the wallet's keys and an empty vault, takes the identity over.
    let app = receiving(world, &alice, "wallet", &wallet)?;
    let vault = world.empty_vault();
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let mut new = Signer::receive_hand_over(env, &app, vault).await?;
    world.outcome("the new install took the identity over", &status(&new)?);
    world.advance_ms(STEP_MS);

    // The old install finds it has been succeeded.
    let after = old.resume().await;
    world.outcome(
        "the old install after the take-over",
        &json!({ "ended": ended(&after), "signer": status(&old)? }),
    );
    world.advance_ms(STEP_MS);

    new.run_due().await?;
    world.outcome("the new install ran what is due", &status(&new)?);
    for (app, name) in [(&mut wallet, "the wallet"), (&mut phone, "the phone")] {
        let report = app.receive(None).await?;
        world.outcome(
            &format!("{name} after the hand-over"),
            &json!({ "events": events(&report.events), "app": app_status(app) }),
        );
    }
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}

/// The signer hands the identity over and then aborts: the version it delivers drops the
/// stored hand-over, and an install that then tries to take the identity over finds none.
///
/// Calls: `PUT /v1/{id}/handover`, `PUT /v1/{id}/identity` (the abort's version), and `GET
/// /v1/{id}/handover` by the target app once nothing is stored (`404`).
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn hand_over_aborted(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut old = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut old, "wallet").await?;

    old.hand_over_to(wallet.app_id(), UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome("the hand-over was stored", &status(&old)?);
    world.advance_ms(STEP_MS);

    let aborted = old
        .abort_hand_over(UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the hand-over was aborted",
        &json!({
            "ended": ended(&aborted),
            "outcome": aborted.as_ref().ok().map(|outcome| format!("{outcome:?}")
                .split(|c: char| !c.is_ascii_alphanumeric())
                .next()
                .map(str::to_owned)),
            "signer": status(&old)?,
        }),
    );
    world.advance_ms(STEP_MS);

    // An install that tries to take over now finds no hand-over stored.
    let app = receiving(world, &alice, "wallet", &wallet)?;
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let late = Signer::receive_hand_over(env, &app, world.empty_vault()).await;
    world.outcome("a take-over after the abort", &ended(&late.map(|_| ())));
    world.advance_ms(STEP_MS);

    old.run_due().await?;
    world.outcome("the signer ran what is due", &status(&old)?);
    let report = wallet.receive(None).await?;
    world.outcome(
        "the wallet after the abort",
        &json!({ "events": events(&report.events), "app": app_status(&mut wallet) }),
    );
    Ok(())
}
