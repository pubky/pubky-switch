//! Approving an app, and its join (Switch spec 12.1, Switch wire 3.9, 3.10).

use std::sync::Arc;

use pubky_switch_client::app::{App, AppConfig, AppEvent};
use pubky_switch_client::store::MemoryStore;
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, notes_protocol};
use crate::{FlowResult, World};

/// An enrolled identity's signer approves an app, which joins: it delivers its record and
/// registers its first receive key, reads the lists, follows its feed and asks for its key
/// bundle (none is stored: the approval carried its keys); the signer's routine run then
/// sees it among the account's apps.
///
/// Calls, beyond the enrollment's: `PUT /v1/{id}/identity` (the listing version), `POST
/// /v1/{id}/ops` (`app.put`, `receive_key.put`), `GET /v1/{id}/allow`, `GET /v1/{id}/feed`,
/// `GET /v1/{id}/apps/{app_id}/keys`, `GET /v1/{id}/apps`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn join(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;

    let asking = Asking::new(world.app_keys(&alice, "wallet")?)?;
    let review = signer.review(asking.request.signed(), &asking.auth)?;
    let approved = signer.approve(review).await?;
    world.outcome("approved", &status(&signer)?);
    signer.claim_delivered(&approved.request).await?;
    world.advance_ms(STEP_MS);

    let request = asking.join_request(alice.public(), &approved)?;
    let store = Arc::new(MemoryStore::new());
    let mut app = App::join(
        world.app_env(store),
        notes_protocol(),
        AppConfig::default(),
        request,
    )
    .await?;
    world.outcome("joined", &app_status(&mut app));
    world.advance_ms(STEP_MS);

    let report = app.receive(None).await?;
    world.outcome(
        "received",
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "app": app_status(&mut app),
        }),
    );
    world.advance_ms(STEP_MS);
    app.fetch_key_bundle().await?;
    world.outcome("keys fetched", &app_status(&mut app));
    world.advance_ms(STEP_MS);

    // The signer's routine run: it reads the account's apps, the new one among them with
    // its record, and finds nothing due.
    signer.run_due().await?;
    world.outcome("signer ran what is due", &status(&signer)?);
    Ok(())
}

/// What an app shows of itself, for the trace.
pub(crate) fn app_status(app: &mut App) -> Value {
    let raised = events(&app.take_events());
    json!({
        "data_epoch": app.data_epoch(),
        "keys_through": app.keys_through(),
        "cursor_generation": app.cursor().generation,
        "cursor_seq": app.cursor().seq,
        "service_cursor_seq": app.service_cursor().seq,
        "receive_keys": app.receive_key_numbers(),
        "identity_version": app.own_identity().version(),
        "alarm": app.alarm().is_some(),
        "reconcile_mode": app.reconcile_mode(),
        "events": raised,
    })
}

/// The events' names, in order: what they carry differs from run to run.
pub(crate) fn events(events: &[AppEvent]) -> Vec<String> {
    events
        .iter()
        .map(|event| {
            let shown = format!("{event:?}");
            shown
                .split(|c: char| !c.is_ascii_alphanumeric())
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}
