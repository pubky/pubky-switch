//! The account's erasure, when the user stops using the Switch (Switch spec 12.7, Switch
//! wire 7.4.16).

use pubky_switch_client::app::App;
use pubky_switch_signer::{Signer, SignerStatus, UserConfirmed};
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// How long the operator's `404` must hold, after an erasure in doubt, before the signer
/// takes the erasure as done (Switch wire 7.4.16, Switch spec 12.7 step 5).
const CONFIRMATION_MS: u64 = 24 * 3_600_000;

/// Where the signer stands in an erasure in doubt, for the trace: how its run ended, its
/// state, since when it holds the account as erased but unconfirmed, as far into the flow
/// as the world's clock was then, and whether its `identity.json` is on the Homeserver.
fn in_doubt<T, E: std::fmt::Debug>(
    world: &World,
    started_ms: u64,
    signer: &Signer,
    run: &Result<T, E>,
    identity: &[u8; 32],
) -> Result<Value, Box<dyn std::error::Error>> {
    let unconfirmed_since = match signer.status() {
        SignerStatus::ErasedUnconfirmed { since_ms } => Some(since_ms.saturating_sub(started_ms)),
        _ => None,
    };
    Ok(json!({
        "ended": ended(run),
        "signer": status(signer)?,
        "unconfirmed_since_ms_into_the_flow": unconfirmed_since,
        "published": world.files().identity_doc(identity).is_some(),
    }))
}

/// Fail the flow when the signer doesn't stand where the step says: the steps of the wait
/// are named for what the signer holds at each, on either switch.
fn standing(signer: &Signer, expected: &str, holds: bool) -> FlowResult {
    if holds {
        Ok(())
    } else {
        Err(format!("the signer is {:?}, not {expected}", signer.status()).into())
    }
}

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

/// The erasure's answer is lost: the signer's call fails with the erasure in doubt. Its
/// next run meets the operator's `404`, which nobody can authenticate, and holds the account
/// as erased but unconfirmed; a run short of 24 hours later still does; the first run 24
/// hours after that first `404` concludes the account is erased (Switch wire 7.4.16, Switch
/// spec 12.7 step 5). The erasure is never sent again.
///
/// Calls: `POST /v1/{id}/erase` with its answer lost; then the signer's read at each of
/// its three runs, answered `404` with the operator key.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn erasure_answer_lost(world: &World) -> FlowResult {
    let started_ms = world.now_ms();
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
        &in_doubt(world, started_ms, &signer, &lost, &alice.public())?,
    );
    standing(
        &signer,
        "erasing",
        matches!(signer.status(), SignerStatus::Erasing),
    )?;
    world.advance_ms(STEP_MS);
    let first = signer.resume().await;
    world.outcome(
        "the signer's next run meets the operator's 404: erased, unconfirmed",
        &in_doubt(world, started_ms, &signer, &first, &alice.public())?,
    );
    standing(
        &signer,
        "erased, unconfirmed",
        matches!(signer.status(), SignerStatus::ErasedUnconfirmed { .. }),
    )?;
    // One step short of 24 hours after that first `404`.
    world.advance_ms(CONFIRMATION_MS - STEP_MS);
    let early = signer.resume().await;
    world.outcome(
        "a run short of 24 hours later: still unconfirmed",
        &in_doubt(world, started_ms, &signer, &early, &alice.public())?,
    );
    standing(
        &signer,
        "erased, unconfirmed",
        matches!(signer.status(), SignerStatus::ErasedUnconfirmed { .. }),
    )?;
    // 24 hours after it.
    world.advance_ms(STEP_MS);
    let done = signer.resume().await;
    world.outcome(
        "the run 24 hours after the first 404: erased",
        &in_doubt(world, started_ms, &signer, &done, &alice.public())?,
    );
    standing(
        &signer,
        "erased",
        matches!(signer.status(), SignerStatus::Erased),
    )?;
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
