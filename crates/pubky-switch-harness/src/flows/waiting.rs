//! A feed read that waits (Switch wire 7.4.4 `wait`): an app with nothing to read asks the
//! switch to hold its read, and a write of another app answers it.
//!
//! This flow isn't among [`super::FLOWS`], whose runs are compared. The service holds a
//! read with `wait` until its account changes. The scripted switch doesn't read `wait`: it
//! answers at once, with nothing, and the app finds the write at its next read. The two
//! runs make their calls in different orders then, which the comparison can't set side by
//! side. The flow's test runs it against each and holds what each does; once the scripted
//! switch holds a waiting read, the flow belongs in `FLOWS`.

use std::time::{Duration, Instant};

use pubky_switch_client::app::{App, AppConfig, RecordTarget};
use serde_json::json;

use super::enrollment::enroll;
use super::join::{app_status, events};
use super::messaging::joined_with;
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, notes_collection, notes_protocol_with_records};
use crate::{FlowResult, World};

/// How long the watch asks the switch to hold its read, in seconds.
const WAIT_S: u32 = 10;

/// How long after the read was sent the wallet writes: time for the read to reach its wait.
const BEFORE_THE_WRITE: Duration = Duration::from_millis(300);

/// The longest the waiting read may take when a write answers it: well short of the wait.
const ANSWERED_WITHIN: Duration = Duration::from_secs(5);

/// alice's watch has read its feed to the end. It reads again and asks the switch to wait;
/// while the read is held, her wallet writes a record. At a switch that holds the read,
/// the write answers it: the watch gets the record without asking again, and a read after
/// that finds nothing new.
///
/// The two calls are in flight at once, the read sent first. The delay before the write
/// is of the real clock, not the world's.
///
/// Calls: `GET /v1/{id}/feed` with `wait`, answered by another app's `POST /v1/{id}/ops`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or when the waiting read
/// takes about as long as its wait: the write didn't answer it.
pub async fn waiting_read(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let asking = |name: &str| -> Result<Asking, crate::HarnessError> {
        Asking::new(world.app_keys(&alice, name)?)
    };
    let (mut wallet, _) = joined_with(
        world,
        &alice,
        &mut signer,
        asking("wallet")?,
        notes_protocol_with_records(),
        AppConfig::default(),
    )
    .await?;
    let (mut watch, _) = joined_with(
        world,
        &alice,
        &mut signer,
        asking("watch")?,
        notes_protocol_with_records(),
        AppConfig::default(),
    )
    .await?;
    look(world, &mut wallet, "the wallet before the wait").await?;
    look(world, &mut watch, "the watch before the wait").await?;

    let target = RecordTarget::new(notes_collection(), b"shopping list");
    let started = Instant::now();
    let write = async {
        tokio::time::sleep(BEFORE_THE_WRITE).await;
        wallet
            .put_record(&target, br#"{"items":["milk"]}"#, Vec::new())
            .await
    };
    let (read, written) = futures_util::future::join(watch.receive(Some(WAIT_S)), write).await;
    let took = started.elapsed();
    written?;
    let report = read?;
    world.outcome(
        "the watch's waiting read, answered by the wallet's write",
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "app": app_status(&mut watch),
        }),
    );
    if took >= ANSWERED_WITHIN {
        return Err(format!(
            "the waiting read took {} ms: the write didn't answer it",
            took.as_millis()
        )
        .into());
    }
    world.advance_ms(STEP_MS);
    look(world, &mut watch, "the watch's next read").await?;
    look(world, &mut wallet, "the wallet after its write").await?;
    Ok(())
}

/// `app` follows its feed to the end and moves its cursor: the events it raises at this
/// read, and where it stands.
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
