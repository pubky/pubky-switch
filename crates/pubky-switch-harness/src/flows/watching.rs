//! A second app of the identity follows its feed while the first acts (Switch spec 6, 10.2,
//! Switch wire 7.4.4, 7.5): what the other app learns, and when.

use pubky_switch_client::app::{App, ClaimOp, ObligationDeadline};
use pubky_switch_core::claims::Basis;
use serde_json::json;

use super::enrollment::enroll;
use super::join::{app_status, events};
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// The claim's key and its attempt's ID: any bytes, the same in every world.
const CLAIM_KEY: [u8; 32] = [0x6b; 32];
const ATTEMPT: [u8; 16] = [3; 16];

/// The wallet attempts a claim, reports it done and saves a contact. After each step the
/// phone, which did none of it, follows its feed and moves its cursor; at the end it reads
/// the claim.
///
/// A shared record the wallet writes belongs here too. An app whose protocol has
/// collections reads `GET /v1/{id}/records` when it joins, which the service doesn't serve
/// yet, so that step waits for it.
///
/// Calls, beyond the joins': the wallet's `POST /v1/{id}/ops` (`claim`, `allow.put`) and the
/// phone's `GET /v1/{id}/feed` after each, with items another app wrote, and its cursor
/// moves; the phone's `GET /v1/{id}/claims/{claim_key}`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn watching(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (mut phone, _) = joined(world, &alice, &mut signer, "phone").await?;
    // Each app sees what happened before it acts or watches: the other's join.
    look(world, &mut wallet, "the wallet before it acts").await?;
    look(world, &mut phone, "the phone before the wallet acts").await?;

    wallet
        .write_claim(
            ClaimOp::attempt(CLAIM_KEY, 0, ATTEMPT, 3_600, None),
            Vec::new(),
            ObligationDeadline::NotKnown,
        )
        .await?;
    acted(world, &mut wallet, "the wallet attempted");
    look(world, &mut phone, "the phone after the attempt").await?;
    held_claim(world, &phone, "the claim the phone holds after the attempt").await?;

    wallet
        .write_claim(
            ClaimOp::done(CLAIM_KEY, 1, ATTEMPT, Basis::Owner, None)?,
            Vec::new(),
            ObligationDeadline::NotKnown,
        )
        .await?;
    acted(world, &mut wallet, "the wallet reported done");
    look(world, &mut phone, "the phone after the outcome").await?;
    held_claim(world, &phone, "the claim the phone holds after the outcome").await?;

    wallet.add_contact(&bob.public()).await?;
    acted(world, &mut wallet, "the wallet saved a contact");
    look(world, &mut phone, "the phone after the contact").await?;
    world.outcome(
        "the contact the phone holds",
        &json!({ "admits": phone.admits(&bob.public()).await? }),
    );

    // What the switch tells the phone when it asks.
    let read = phone.read_claim(&CLAIM_KEY).await?;
    world.outcome(
        "the claim the phone reads",
        &json!({
            "status": read.as_ref().map(|read| format!("{:?}", read.view.status)),
            "step": read.as_ref().map(|read| read.view.step),
            "tombstone": read.as_ref().map(|read| read.view.tombstone),
            "entries": read.as_ref().map(|read| read.entries.len()),
            "events": events(&phone.take_events()),
        }),
    );
    held_claim(world, &phone, "the claim the phone holds after reading it").await?;
    world.advance_ms(STEP_MS);
    look(world, &mut wallet, "the wallet at the end").await?;
    Ok(())
}

/// Note what `app` raised by acting, and let time pass.
fn acted(world: &World, app: &mut App, name: &str) {
    world.outcome(name, &json!({ "events": events(&app.take_events()) }));
    world.advance_ms(STEP_MS);
}

/// `app` follows its feed and moves its cursor: the events it raises at this read, and
/// where it stands.
async fn look(world: &World, app: &mut App, name: &str) -> FlowResult {
    let report = app.receive(None).await?;
    app.flush_cursor().await?;
    world.outcome(
        name,
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "app": app_status(app),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

/// What `app` holds of the claim without asking the switch: the newest view it kept, and
/// whether it holds the proof that shows the claim settled.
async fn held_claim(world: &World, app: &App, name: &str) -> FlowResult {
    let evidence = app.claim_evidence(&CLAIM_KEY).await?;
    world.outcome(
        name,
        &json!({
            "held": evidence.is_some(),
            "status": evidence.as_ref().map(|held| format!("{:?}", held.view.status)),
            "step": evidence.as_ref().map(|held| held.view.step),
            "tombstone": evidence.as_ref().map(|held| held.view.tombstone),
            "settled_proof": evidence.as_ref().map(|held| held.settled_proof.is_some()),
        }),
    );
    Ok(())
}
