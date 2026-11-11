//! The account's erasure, when the user stops using the Switch (Switch spec 12.7, Switch
//! wire 7.4.16).

use pubky_switch_client::app::App;
use pubky_switch_signer::{Signer, UserConfirmed};
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// How a call ended, for the trace: nothing of an error but its kinds.
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

/// What the world shows of the identity once its signer closed the account, or tried to:
/// the signer's own state, whether its `identity.json` is still on the Homeserver, what an
/// app of the identity meets at its next read, and what anyone reading the public
/// `identity.json` from the switch gets.
async fn afterwards(
    world: &World,
    name: &str,
    signer: &mut Signer,
    app: &mut App,
    public_path: &str,
    identity: &[u8; 32],
) -> FlowResult {
    world.outcome(
        &format!("{name}: the signer"),
        &json!({
            "signer": status(signer)?,
            "published": world.files().identity_doc(identity).is_some(),
        }),
    );
    let read = app.receive(None).await;
    world.outcome(
        &format!("{name}: an app's next read"),
        &json!({
            "ended": ended(&read),
            "events": events(&app.take_events()),
            "app": app_status(app),
        }),
    );
    let public = world.request("GET", ORIGIN, public_path).await?;
    world.outcome(
        &format!("{name}: the public read"),
        &json!({ "status": public.status }),
    );
    world.advance_ms(STEP_MS);
    let again = signer.resume().await;
    world.outcome(
        &format!("{name}: the signer's next run"),
        &json!({ "ended": ended(&again), "signer": status(signer)? }),
    );
    Ok(())
}

/// The signer closes the identity's account: `identity.json` leaves the Homeserver, the
/// switch erases the account, and every later call is answered by the operator's `404`.
///
/// Calls: `POST /v1/{id}/erase` (`200`), then an own app's `GET /v1/{id}/feed` and the
/// public `GET /v1/{id}/identity`, each answered `404` with the operator key. The signer,
/// holding the account as erased, sends nothing at its next run.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn erasure(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let public_path = format!("/v1/{}/identity", alice.key().id());

    let closed = signer
        .close_account(UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome("the account was closed", &ended(&closed));
    world.advance_ms(STEP_MS);
    afterwards(
        world,
        "after the erasure",
        &mut signer,
        &mut wallet,
        &public_path,
        &alice.public(),
    )
    .await
}

/// The erasure's answer is lost: the signer's call fails with the erasure in doubt, and its
/// next run, whose check meets the operator's `404`, concludes the account is erased
/// without sending the erasure again.
///
/// Calls: `POST /v1/{id}/erase` with its answer lost; the signer's next read, answered
/// `404` with the operator key.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn erasure_answer_lost(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let public_path = format!("/v1/{}/identity", alice.key().id());

    world.lose_answer("POST", "/erase");
    let lost = signer
        .close_account(UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the erasure's answer was lost",
        &json!({ "ended": ended(&lost), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);
    let again = signer.resume().await;
    world.outcome(
        "the signer's next run meets the erased account",
        &json!({ "ended": ended(&again), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);
    afterwards(
        world,
        "after the erasure",
        &mut signer,
        &mut wallet,
        &public_path,
        &alice.public(),
    )
    .await?;
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}
