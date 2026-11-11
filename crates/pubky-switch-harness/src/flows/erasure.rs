//! The account's erasure, when the user stops using the Switch (Switch spec 12.7, Switch
//! wire 7.4.16).

use pubky_switch_client::app::{App, AppEvent};
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

/// How long an app must meet the operator's `404` and a missing `identity.json`, at reads
/// spread over that time, before it takes its account as erased: the same 24 hours (Switch
/// spec 12.7 step 5).
const APP_WAIT_MS: u64 = CONFIRMATION_MS;

/// The least time between two reads the app's wait counts: it takes five, so four of these.
const APP_SPACING_MS: u64 = APP_WAIT_MS / 4;

/// One read of an app whose account was erased, for the trace: how it ended, the events it
/// raised, where the app stands with its service, and whether the identity's
/// `identity.json` is on the Homeserver. Returns whether the read raised `AccountGone`.
async fn read_once_erased(
    world: &World,
    name: &str,
    app: &mut App,
    identity: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error>> {
    let read = app.receive(None).await;
    let (stopped, raised) = match &read {
        Ok(report) => (Some(report.stopped), report.events.clone()),
        Err(_) => (None, app.take_events()),
    };
    // Where the app stands with its service, asked apart from the read, with the events
    // the asking itself raised.
    let provider = app.follow_provider().await;
    let provider_events = app.take_events();
    world.outcome(
        name,
        &json!({
            "ended": ended(&read),
            "stopped": stopped,
            "events": events(&raised),
            "provider": match &provider {
                Ok(status) => ended_word(&format!("{status:?}")),
                Err(error) => ended_word(&format!("{error:?}")),
            },
            "provider_events": events(&provider_events),
            "app": app_status(app),
            "published": world.files().identity_doc(identity).is_some(),
        }),
    );
    Ok(raised
        .iter()
        .any(|event| matches!(event, AppEvent::AccountGone)))
}

/// The first word of a `Debug` text: a status's or an error's name.
fn ended_word(shown: &str) -> String {
    shown
        .split(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Fail the flow when a read of the app's wait raised `AccountGone` or not, against what
/// the step says.
fn gone(raised: bool, expected: bool, step: &str) -> FlowResult {
    if raised == expected {
        Ok(())
    } else if expected {
        Err(format!("{step}: the app didn't take its account as gone").into())
    } else {
        Err(format!("{step}: the app took its account as gone already").into())
    }
}

/// What the world shows of the identity once its signer closed the account: the signer's
/// own state, whether its `identity.json` is still on the Homeserver, what anyone reading
/// the public `identity.json` from the switch gets, an app's wait, and the signer's next
/// run.
///
/// The app's wait (Switch spec 12.7 step 5): nothing authenticates an erasure, so the app
/// takes its account as gone only once the operator's `404` and a missing `identity.json`
/// have both held at five reads at least 6 hours apart, over 24 hours. The flow deletes
/// nothing itself: the file is missing because the signer's erasure took it off the
/// Homeserver. Four reads 6 hours apart raise nothing, nor does one a step short of 24
/// hours; the read 24 hours after the first raises `AccountGone`, and a read after that
/// asks the switch nothing.
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
    let public = world.request("GET", ORIGIN, public_path).await?;
    world.outcome(
        &format!("{name}: the public read"),
        &json!({ "status": public.status }),
    );

    let step = format!("{name}: an app's next read, the first of its wait");
    let raised = read_once_erased(world, &step, app, identity).await?;
    gone(raised, false, &step)?;
    // A check for a move in between asks the public `identity.json` of the switch: it meets
    // the `404` too.
    let check = app.check_for_move().await;
    world.outcome(
        &format!("{name}: the app's check for a move"),
        &json!({ "ended": ended(&check), "events": events(&app.take_events()) }),
    );
    for hours in [6, 12, 18] {
        world.advance_ms(APP_SPACING_MS);
        let step = format!("{name}: the app's read {hours} hours on");
        let raised = read_once_erased(world, &step, app, identity).await?;
        gone(raised, false, &step)?;
    }
    world.advance_ms(APP_SPACING_MS - STEP_MS);
    let step = format!("{name}: the app's read short of 24 hours on");
    let raised = read_once_erased(world, &step, app, identity).await?;
    gone(raised, false, &step)?;
    world.advance_ms(STEP_MS);
    let step = format!("{name}: the app's read 24 hours on, the account is gone");
    let raised = read_once_erased(world, &step, app, identity).await?;
    gone(raised, true, &step)?;
    world.advance_ms(STEP_MS);
    let step = format!("{name}: the app's read once the account is gone");
    read_once_erased(world, &step, app, identity).await?;

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
/// An app of the identity then waits its own 24 hours before it takes the account as gone.
///
/// Calls: `POST /v1/{id}/erase` (`200`), then the public `GET /v1/{id}/identity` and an
/// own app's `GET /v1/{id}/feed` at each read of its wait, each answered `404` with the
/// operator key. The signer, holding the account as erased, sends nothing at its next run,
/// nor does the app once it took the account as gone.
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
/// spec 12.7 step 5). The erasure is never sent again. An app of the identity then waits
/// its own 24 hours, as in [`erasure`].
///
/// Calls: `POST /v1/{id}/erase` with its answer lost; then the signer's read at each of
/// its three runs, answered `404` with the operator key; then the calls of [`erasure`]
/// after its `200`.
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
