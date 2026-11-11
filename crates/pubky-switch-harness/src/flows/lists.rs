//! An app that changes the lists and can't read them (Switch spec 3.2, Switch wire 7.5).

use serde_json::json;

use super::enrollment::enroll;
use super::join::{app_status, events};
use super::messaging::joined_as;
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, NOTES_LISTS};
use crate::{FlowResult, World};

/// alice's app `pad` holds `lists.manage` and not `lists.read`. It saves bob as a contact,
/// then follows its feed, where its own `allow.put` is an item it may not read.
///
/// Calls: those of a join without `GET /allow`, `POST /v1/{id}/ops` (`allow.put`), and `GET
/// /v1/{id}/feed` with a list operation shown to an app without `lists.read`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn lists_without_read(world: &World) -> FlowResult {
    let alice = world.identity("alice");
    let bob = world.identity("bob");
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let asking = Asking::for_scope(world.app_keys(&alice, "pad"), NOTES_LISTS)?;
    let (mut pad, _) = joined_as(world, &alice, &mut signer, asking).await?;

    pad.add_contact(&bob.public()).await?;
    world.outcome("contact saved", &app_status(&mut pad));
    world.advance_ms(STEP_MS);

    let report = pad.receive(None).await?;
    pad.flush_cursor().await?;
    world.outcome(
        "received",
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "app": app_status(&mut pad),
        }),
    );
    Ok(())
}
