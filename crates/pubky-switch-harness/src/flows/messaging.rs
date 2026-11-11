//! Two identities at one switch: one saves the other as a contact, the other sends it a
//! message, and the recipient reads and applies it (Switch spec 7, 8, Switch wire 7.4.3 to
//! 7.4.5, 7.4.10).

use std::sync::Arc;

use pubky_switch_client::app::{App, AppConfig, OutgoingMessage};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::{TestIdentity, TestProtocol};
use pubky_switch_signer::Signer;
use serde_json::json;

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, NOTE_KIND, notes_protocol};
use crate::{FlowResult, World};

/// alice's wallet saves bob as a contact; bob's shop looks alice up, delivers bob's
/// `identity.json` to her switch and appends a message to her inbox; alice's wallet reads it
/// from its feed, applies it and moves its cursor.
///
/// Calls, beyond the join's: `POST /v1/{id}/ops` (`allow.put`, the cursor move), `GET
/// /v1/{id}/directory`, `PUT /v1/{id}/peers`, `POST /v1/{id}/inbox`, `GET /v1/{id}/feed`
/// with an entry.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn messaging(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let (mut wallet, wallet_protocol) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;

    // alice admits bob.
    wallet.add_contact(&bob.public()).await?;
    world.outcome("contact saved", &app_status(&mut wallet));
    world.advance_ms(STEP_MS);

    // bob's shop sends alice a note.
    let mut body = serde_json::Map::new();
    body.insert("text".into(), json!("hello"));
    let (_, delivery) = shop
        .send(OutgoingMessage::new(alice.public(), NOTE_KIND, body))
        .await?;
    world.outcome(
        "sent",
        &json!({
            "delivery": format!("{delivery:?}").split(' ').next(),
            "app": app_status(&mut shop),
        }),
    );
    world.advance_ms(STEP_MS);

    // alice's wallet reads its feed, applies the message and moves its cursor.
    let report = wallet.receive(None).await?;
    wallet.flush_cursor().await?;
    let received = wallet_protocol.received();
    world.outcome(
        "received",
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "messages": received.len(),
            "kinds": received.iter().map(|message| message.message.kind.clone()).collect::<Vec<_>>(),
            "app": app_status(&mut wallet),
        }),
    );
    world.advance_ms(STEP_MS);

    // Both signers' routine runs: each sees its app, and alice's the entry read.
    alice_signer.run_due().await?;
    world.outcome("alice's signer ran what is due", &status(&alice_signer)?);
    bob_signer.run_due().await?;
    world.outcome("bob's signer ran what is due", &status(&bob_signer)?);
    Ok(())
}

/// `identity`'s app `name`, approved by `signer` for the [`NOTES`](crate::parties::NOTES)
/// scope and joined, with its protocol.
pub(crate) async fn joined(
    world: &World,
    identity: &TestIdentity,
    signer: &mut Signer,
    name: &str,
) -> Result<(App, Arc<TestProtocol>), Box<dyn std::error::Error>> {
    let asking = Asking::new(world.app_keys(identity, name)?)?;
    joined_as(world, identity, signer, asking, notes_protocol()).await
}

/// The app that asks with `asking`, approved by `identity`'s `signer` and joined with
/// `protocol`.
pub(crate) async fn joined_as(
    world: &World,
    identity: &TestIdentity,
    signer: &mut Signer,
    asking: Asking,
    protocol: Arc<TestProtocol>,
) -> Result<(App, Arc<TestProtocol>), Box<dyn std::error::Error>> {
    let review = signer.review(asking.request.signed(), &asking.auth)?;
    let approved = signer.approve(review).await?;
    signer.claim_delivered(&approved.request).await?;
    world.advance_ms(STEP_MS);
    let mut app = App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        protocol.clone(),
        AppConfig::default(),
        asking.join_request(identity.public(), &approved)?,
    )
    .await?;
    app.receive(None).await?;
    world.outcome("joined", &app_status(&mut app));
    world.advance_ms(STEP_MS);
    Ok((app, protocol))
}
