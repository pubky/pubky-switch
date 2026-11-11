//! Enrollment and the first `identity.json` (Switch spec 12.1, Switch wire 3.7, 7.4.1,
//! 7.4.2).

use std::sync::Arc;

use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::TestIdentity;
use pubky_switch_core::records::IDENTITY_PATH;
use pubky_switch_signer::Signer;
use serde_json::json;

use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// A new identity's signer enrolls at its switch, delivers the first `identity.json` and
/// publishes it; then the same install opens its records again and finds nothing owed.
///
/// Calls: `POST /v1/enroll`, `PUT /v1/{id}/identity`, `GET /v1/{id}/apps`, and the public
/// `GET /v1/{id}/identity`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn enrollment(world: &World) -> FlowResult {
    let alice = world.identity("alice");
    world.add_switch(ORIGIN, &[&alice]).await?;
    let store = Arc::new(MemoryStore::new());

    let env = world.signer_env(&alice, store.clone())?;
    let mut signer = Signer::create(env, world.keyring(&alice)?, ORIGIN).await?;
    world.outcome("created", &status(&signer)?);
    world.advance_ms(STEP_MS);
    signer.resume().await?;
    world.outcome("enrolled", &status(&signer)?);
    drop(signer);
    world.advance_ms(STEP_MS);
    let published = world.files().identity_doc(&alice.public());
    world.outcome(
        "published",
        &json!({
            "path": IDENTITY_PATH,
            "version": published.as_ref().map(pubky_switch_core::records::IdentityDoc::version),
        }),
    );

    // Anyone reads the newest `identity.json` from the switch (Switch wire 7.4.2). Neither
    // the client nor the signer makes this call: a reader without keys does.
    let path = format!("/v1/{}/identity", alice.key().id());
    world.request("GET", ORIGIN, &path).await?;
    world.advance_ms(STEP_MS);

    // The same install after a restart: nothing is owed, and nothing changes.
    let env = world.signer_env(&alice, store)?;
    let mut signer = Signer::open(env, world.keyring(&alice)?).await?;
    signer.resume().await?;
    world.outcome("reopened", &status(&signer)?);
    Ok(())
}

/// A signer of `identity`, enrolled at the switch at `origin` and serving, on a store of its
/// own.
pub(crate) async fn enroll(
    world: &World,
    identity: &TestIdentity,
    origin: &str,
) -> Result<Signer, Box<dyn std::error::Error>> {
    let env = world.signer_env(identity, Arc::new(MemoryStore::new()))?;
    let mut signer = Signer::create(env, world.keyring(identity)?, origin).await?;
    signer.resume().await?;
    world.outcome("enrolled", &status(&signer)?);
    world.advance_ms(STEP_MS);
    Ok(signer)
}

/// What a signer shows of itself, for the trace.
pub(crate) fn status(signer: &Signer) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let doc = signer.identity_doc()?;
    let high_water = signer.high_water();
    Ok(json!({
        "status": format!("{:?}", signer.status()),
        "version": doc.as_ref().map(pubky_switch_core::records::IdentityDoc::version),
        "generation": doc.as_ref().map(pubky_switch_core::records::IdentityDoc::generation),
        "apps": doc.as_ref().map(|doc| doc.body().apps.len()),
        "high_water_version": high_water.map(|mark| mark.version),
        "high_water_generation": high_water.map(|mark| mark.generation),
        "alerts": signer.alerts().iter().map(|alert| format!("{alert:?}")).collect::<Vec<_>>(),
    }))
}
