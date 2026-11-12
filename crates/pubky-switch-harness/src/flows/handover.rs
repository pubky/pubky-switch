//! The signer's hand-over to another install (Switch spec 12.8, Switch wire 3.12, 7.4.17):
//! stored at the switch for one of the identity's apps, fetched by it, and dropped by the
//! next version of `identity.json`.

use std::sync::Arc;
use std::time::Duration;

use pubky_switch_client::app::App;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::TestIdentity;
use pubky_switch_signer::{AbortOutcome, ReceivingApp, Signer, SignerStatus, UserConfirmed};
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

/// How long two racing calls may take together.
const RACE_TIMEOUT: Duration = Duration::from_secs(15);

/// A signer's delivery of `identity.json`, whichever install sends it.
const DELIVERY: &str = "{alice} PUT /v1/{alice}/identity";

/// Fail the flow unless the last delivery, the one that arrived second, was refused `409
/// stale_identity`: the switch takes a version only when it builds on the one it holds (Switch
/// wire 7.4.2).
pub(super) fn expect_delivery_refused(world: &World) -> FlowResult {
    let answered = world
        .last_answer(DELIVERY)
        .map(|[status, code, _]| (status, code));
    let refused = ("409".to_owned(), "text stale_identity".to_owned());
    if answered.as_ref() == Some(&refused) {
        Ok(())
    } else {
        Err(format!("the delivery that arrived second was answered {answered:?}").into())
    }
}

/// An abort that arrives after the take-over (Switch wire 3.12, 7.4.2). alice's signer
/// hands the identity over and then aborts; the abort's version, signed two past the one
/// handed over and built on it, is held back on its way. Meanwhile the new install fetches
/// the hand-over and takes the identity over with the next version, which the switch
/// takes. The abort then arrives: it builds on a version the switch no longer holds as its
/// newest, and is refused. The old install finds the hand-over took effect.
///
/// Calls: `PUT /v1/{id}/identity` with a version that doesn't build on the held one
/// (`409 stale_identity`), from an install that was succeeded meanwhile.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the abort isn't refused, or
/// the old install doesn't find itself succeeded by the new one.
pub async fn hand_over_abort_late(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut old = enroll(world, &alice, ORIGIN).await?;
    let (wallet, _) = joined(world, &alice, &mut old, "wallet").await?;
    old.hand_over_to(wallet.app_id(), UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome("the hand-over was stored", &status(&old)?);
    world.advance_ms(STEP_MS);

    let app = receiving(world, &alice, "wallet", &wallet)?;
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    world.hold_back_next("PUT", "/identity");
    let abort = old.abort_hand_over(UserConfirmed::shown_and_confirmed());
    let take_over = async {
        // Once the abort's delivery is on its way and held.
        while world.held_back_now() == 0 {
            tokio::task::yield_now().await;
        }
        let new = Signer::receive_hand_over(env, &app, world.empty_vault()).await;
        world.let_go();
        new
    };
    let both = tokio::time::timeout(RACE_TIMEOUT, futures_util::future::join(abort, take_over));
    let raced = both.await;
    world.let_go();
    let Ok((aborted, new)) = raced else {
        return Err("the abort and the take-over didn't both end".into());
    };
    let new = new?;
    world.outcome(
        "the take-over arrived first, and the abort after it",
        &json!({
            "abort": ended(&aborted),
            "outcome": aborted.as_ref().ok().map(|outcome| format!("{outcome:?}")
                .split(|c: char| !c.is_ascii_alphanumeric())
                .next()
                .map(str::to_owned)),
            "old": status(&old)?,
            "new": status(&new)?,
        }),
    );
    expect_delivery_refused(world)?;
    let succeeded = matches!(
        &aborted,
        Ok(AbortOutcome::SucceededBy { install }) if *install == new.install_id()
    );
    if !succeeded || new.status() != SignerStatus::Signing {
        return Err(format!(
            "the abort ended {}, and the new install is {:?}",
            ended(&aborted),
            new.status()
        )
        .into());
    }
    Ok(())
}

/// A take-over that arrives after the abort (Switch wire 3.12, 7.4.2). alice's signer
/// hands the identity over. The new install fetches the hand-over and signs the next
/// version, whose delivery is held back on its way. Meanwhile the old install aborts: its
/// version, two past the one handed over, is taken, and drops the stored hand-over. The
/// take-over then arrives: it is a version below the one the switch holds, and is refused.
/// The old install signs on.
///
/// Calls: `PUT /v1/{id}/identity` with a version below the held one (`409 stale_identity`),
/// from an install whose take-over an abort overtook.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the take-over isn't
/// refused, or the abort doesn't win.
pub async fn hand_over_take_over_late(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut old = enroll(world, &alice, ORIGIN).await?;
    let (wallet, _) = joined(world, &alice, &mut old, "wallet").await?;
    old.hand_over_to(wallet.app_id(), UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome("the hand-over was stored", &status(&old)?);
    world.advance_ms(STEP_MS);

    let app = receiving(world, &alice, "wallet", &wallet)?;
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    world.hold_back_next("PUT", "/identity");
    let take_over = Signer::receive_hand_over(env, &app, world.empty_vault());
    let abort = async {
        // Once the take-over's delivery is on its way and held.
        while world.held_back_now() == 0 {
            tokio::task::yield_now().await;
        }
        let aborted = old
            .abort_hand_over(UserConfirmed::shown_and_confirmed())
            .await;
        world.let_go();
        aborted
    };
    let both = tokio::time::timeout(RACE_TIMEOUT, futures_util::future::join(take_over, abort));
    let raced = both.await;
    world.let_go();
    let Ok((taken, aborted)) = raced else {
        return Err("the take-over and the abort didn't both end".into());
    };
    world.outcome(
        "the abort arrived first, and the take-over after it",
        &json!({
            "take_over": ended(&taken.as_ref().map(|_| ())),
            "abort": ended(&aborted),
            "old": status(&old)?,
        }),
    );
    expect_delivery_refused(world)?;
    if taken.is_ok()
        || !matches!(aborted, Ok(AbortOutcome::Aborted { .. }))
        || old.status() != SignerStatus::Signing
    {
        return Err(format!(
            "the take-over ended ok: {}, the abort {}, and the old install is {:?}",
            taken.is_ok(),
            ended(&aborted),
            old.status()
        )
        .into());
    }
    world.advance_ms(STEP_MS);
    let next = old.set_record_max_age(Some(86_400)).await?;
    world.outcome(
        "the old install signed on",
        &json!({ "version": next.version(), "signer": status(&old)? }),
    );
    Ok(())
}
