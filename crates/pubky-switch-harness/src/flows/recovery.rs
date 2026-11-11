//! A provider loss and the recovery after it (Switch spec 12.6 steps 1 and 2, Switch wire
//! 3.3, 3.7, 7.4.1, 7.4.2, 7.4.14): the signer declares the service it is enrolled at lost,
//! enrolls at a service, delivers the next generation's first document there, and ends the
//! staged admission the recovery starts.

use std::sync::Arc;

use pubky_switch::limits::Limits;
use pubky_switch_client::app::{App, OutgoingMessage};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_core::records::IdentityDoc;
use pubky_switch_signer::{Signer, UserConfirmed};
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::events;
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::parties::NOTE_KIND;
use crate::{FlowResult, World};

/// Where the sender's identity is enrolled: a service that isn't lost.
const SENDERS_ORIGIN: &str = "https://senders.example";

/// The service the identity recovers at.
const RECOVERY_ORIGIN: &str = "https://recovery.example";

/// What a recovery's version shows, for the trace.
fn recovered(doc: &IdentityDoc, signer: &Signer) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json!({
        "version": doc.version(),
        "generation": doc.generation(),
        "recovery_from": doc.body().recovery_from,
        "data_epoch": doc.data_epoch(),
        "apps": doc.body().apps.len(),
        "removed": doc.body().removed.len(),
        "inbox": doc.inbox().url,
        "signer": status(signer)?,
    }))
}

/// How a signer's call ended, for the trace: the error's kinds, never its text.
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

/// `shop` sends alice a note, or tries its queued ones again, and the flow notes how each
/// stands.
async fn send(world: &World, name: &str, shop: &mut App, to: Option<[u8; 32]>) -> FlowResult {
    let outcome = match to {
        Some(to) => {
            let mut body = serde_json::Map::new();
            body.insert("text".into(), json!("hello"));
            let sent = shop.send(OutgoingMessage::new(to, NOTE_KIND, body)).await;
            json!({
                "delivery": sent.as_ref().ok().map(|(_, delivery)| {
                    format!("{delivery:?}").split(' ').next().map(str::to_owned)
                }),
                "ok": sent.is_ok(),
            })
        }
        None => {
            let flushed = shop.flush_outbox().await?;
            json!({
                "done": flushed.done.len(),
                "queued": flushed.queued.len(),
                "failed": flushed.failed.len(),
                "undelivered": flushed.undelivered.len(),
            })
        }
    };
    world.outcome(
        name,
        &json!({ "sent": outcome, "events": events(&shop.take_events()) }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

/// alice's service is lost. Her signer declares the loss and recovers at another service:
/// it enrolls there, delivers the next generation's first document, which lists her wallet,
/// and publishes it. The wallet manages the lists, so the recovery leaves admission staged
/// for its upload; here the signer ends it on the user's word. bob's shop writes to alice:
/// with `during`, first while admission is staged, where the new service holds every
/// sender back, and in any case once it has ended, where the service judges him by its
/// lists, which are empty until alice's apps bring them.
async fn recovery_elsewhere(world: &World, during: bool) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    world.add_switch(SENDERS_ORIGIN, &[&bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, SENDERS_ORIGIN).await?;
    let (_wallet, _) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;

    // The service is gone, and another stands ready.
    world.lose_switch(ORIGIN);
    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    let doc = alice_signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss and recovered elsewhere",
        &recovered(&doc, &alice_signer)?,
    );
    world.advance_ms(STEP_MS);

    if during {
        send(
            world,
            "bob's shop wrote to alice while admission was staged",
            &mut shop,
            Some(alice.public()),
        )
        .await?;
    }
    let ending = alice_signer.end_staged_admission().await;
    world.outcome(
        "the signer ended the staged admission",
        &json!({ "ended": ended(&ending), "signer": status(&alice_signer)? }),
    );
    world.advance_ms(STEP_MS);
    if during {
        send(
            world,
            "bob's shop tried again once admission had ended",
            &mut shop,
            None,
        )
        .await?;
    } else {
        send(
            world,
            "bob's shop wrote to alice once admission had ended",
            &mut shop,
            Some(alice.public()),
        )
        .await?;
    }

    alice_signer.run_due().await?;
    world.outcome("alice's signer ran what is due", &status(&alice_signer)?);
    Ok(())
}

/// A provider loss, a recovery at another service, and a sender who writes once the staged
/// admission has ended.
///
/// Calls: `POST /v1/enroll` at the new service, `PUT /v1/{id}/identity` with a recovery's
/// first document, `GET /v1/{id}/apps` with `recovery`, `POST /v1/{id}/recovery/admission`,
/// and a sender's `PUT /v1/{id}/peers` at an account recovered and not yet rebuilt.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn provider_loss(world: &World) -> FlowResult {
    recovery_elsewhere(world, false).await
}

/// As [`provider_loss`], with the sender writing first while admission is staged: he is
/// held back with `503 staged`, and tries again once it has ended.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn provider_loss_sender_staged(world: &World) -> FlowResult {
    recovery_elsewhere(world, true).await
}

/// A recovery in place: alice's service still serves, and her signer declares its
/// generation lost there. The enrollment is answered with a pending key for the next
/// generation, and the version naming it starts the account afresh under that key. The
/// first enrollment of the run, whose answer named the key now retired, is then sent again
/// as a retry still on its way: the switch answers it `409 conflict`. The signer signs on at
/// the service, and ends the staged admission.
///
/// Calls: `POST /v1/enroll` at a serving account, `PUT /v1/{id}/identity` with a recovery's
/// first document under a pending key, `POST /v1/enroll` with an enrollment a generation
/// change retired, and `POST /v1/{id}/recovery/admission`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn provider_loss_in_place(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (_wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;

    let doc = signer
        .declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss and recovered in place",
        &recovered(&doc, &signer)?,
    );
    world.advance_ms(STEP_MS);

    let retried = world.enroll_again(0).await?;
    world.outcome(
        "the first enrollment, sent again",
        &json!({ "status": retried.status }),
    );
    world.advance_ms(STEP_MS);

    let ending = signer.end_staged_admission().await;
    world.outcome(
        "the signer ended the staged admission",
        &json!({ "ended": ended(&ending), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);
    let next = signer.set_record_max_age(Some(60)).await?;
    world.outcome("the signer signed on", &recovered(&next, &signer)?);
    Ok(())
}

/// Where a recovery is refused: a service whose app limit is below the apps alice lists.
const SMALL_ORIGIN: &str = "https://small.example";

/// A recovery refused, then declared again elsewhere. alice lists two apps; the service
/// her signer first recovers at takes one. It refuses the recovery's first document for
/// good, and the signer shows the recovery as refused there, signing nothing else. The
/// user declares the loss again at another service, which takes it, at a higher version of
/// the same generation.
///
/// Calls: `POST /v1/enroll` at two services, and `PUT /v1/{id}/identity` with a first
/// document over the service's app limit, refused.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn provider_loss_refused(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (_wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (_phone, _) = joined(world, &alice, &mut signer, "phone").await?;

    world.lose_switch(ORIGIN);
    let one_app = Limits {
        app_limit: 1,
        ..Limits::default()
    };
    world
        .add_switch_with(SMALL_ORIGIN, &[&alice], one_app)
        .await?;
    let refused = signer
        .declare_provider_loss(SMALL_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the service refused the recovery",
        &json!({ "ended": ended(&refused), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);
    // Refused, the recovery waits to be declared again: a run sends nothing.
    let waiting = signer.resume().await;
    world.outcome(
        "the signer's next run, the recovery refused",
        &json!({ "ended": ended(&waiting), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);

    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    let doc = signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss again, elsewhere",
        &recovered(&doc, &signer)?,
    );
    Ok(())
}

/// An enrollment that takes three sends. The first is answered `400` and the second `409
/// conflict`, each in the service's place by something that holds none of its keys: the
/// signer takes neither for the service's word. After the `400` it sends the same
/// enrollment again; after the `409` it signs a new one, which the service answers, and the
/// recovery completes.
///
/// Calls: `POST /v1/enroll` three times, the first two never reaching the service.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or a fault met no request.
pub async fn provider_loss_enrollment_resent(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (_wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;

    world.lose_switch(ORIGIN);
    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    world.refuse("POST", "/v1/enroll", 400, "bad_request");
    world.refuse("POST", "/v1/enroll", 409, "conflict");
    let doc = signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer recovered at its third enrollment",
        &recovered(&doc, &signer)?,
    );
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}

/// A restore in the middle of a recovery. alice's service is lost with a revocation of her
/// wallet still pending, which it never took. Her signer declares the loss, and the
/// recovery's first document doesn't reach the new service. The install is gone then; a new
/// one is restored from the signer backup on the Homeserver. It completes the recovery at
/// the new service, revokes the wallet there, and delivers the version that removes it.
///
/// Calls: `POST /v1/enroll` and `PUT /v1/{id}/identity` of a recovery by a restored
/// install, `POST /v1/{id}/apps/{app_id}/revoke` and the removal at the new service.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or a fault met no request.
pub async fn provider_loss_restored(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;

    world.lose_switch(ORIGIN);
    let revoking = signer
        .revoke(wallet.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the signer asked to revoke the wallet, the service lost",
        &json!({ "ended": ended(&revoking), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);

    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    world.unreachable("PUT", "/identity");
    let declared = signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the signer declared the loss, and its document didn't arrive",
        &json!({ "ended": ended(&declared), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);
    drop(signer);

    // A new install, from the backup on the Homeserver.
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let mut restored = Signer::restore_new(
        env,
        world.keyring(&alice)?,
        UserConfirmed::shown_and_confirmed(),
    )
    .await?;
    world.outcome("a new install was restored", &status(&restored)?);
    world.advance_ms(STEP_MS);
    let resumed = restored.resume().await;
    world.outcome(
        "the restored install completed the recovery",
        &json!({ "ended": ended(&resumed), "signer": status(&restored)? }),
    );
    world.advance_ms(STEP_MS);
    let removed = restored.complete_removals().await?;
    let newest = restored.identity_doc()?;
    world.outcome(
        "the restored install carried out the revocation",
        &json!({
            "all_removed": removed,
            "apps": newest.as_ref().map(|doc| doc.body().apps.len()),
            "removed": newest.as_ref().map(|doc| doc.body().removed.len()),
            "signer": status(&restored)?,
        }),
    );
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}
