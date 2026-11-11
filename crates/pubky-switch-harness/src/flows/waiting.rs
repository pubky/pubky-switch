//! A feed read that waits (Switch wire 7.4.4 `wait`): an app with nothing to read asks the
//! switch to hold its read, and a write of another app answers it.

use std::cell::Cell;
use std::time::Duration;

use pubky_switch_client::app::{App, AppConfig, RecordTarget};
use serde_json::json;

use super::enrollment::enroll;
use super::join::{app_status, events};
use super::messaging::joined_with;
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, notes_collection, notes_protocol_with_records};
use crate::{FlowResult, World};

/// How long the watch asks the switch to hold its read, in seconds: the most a read may
/// ask for.
const WAIT_S: u32 = 25;

/// How long the read and the write may take together. It is well short of the wait, so a
/// read that is held and then answered within it was answered by the write, not by its
/// wait running out; and long enough for one write at any runner's pace.
const STEP_TIMEOUT: Duration = Duration::from_secs(15);

/// alice's watch has read its feed to the end. It reads again and asks the switch to wait;
/// while the read is held, her wallet writes a record. The write answers the read: the
/// watch gets the record without asking again, and a read after that finds nothing new.
///
/// The two calls are in flight at once. The write starts when the switch holds the read
/// ([`World::held_reads`]): it waits on that state, not for a time. A read answered before
/// the write started wasn't held, and fails the flow.
///
/// Calls: `GET /v1/{id}/feed` with `wait`, answered by another app's `POST /v1/{id}/ops`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails; when the switch answers the
/// read without holding it; or when the read and the write together take 15 seconds, well
/// short of the wait: the write didn't answer the read.
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
    let answered = Cell::new(false);
    let held_at_the_write = Cell::new(false);
    let read = async {
        let report = watch.receive(Some(WAIT_S)).await;
        answered.set(true);
        report
    };
    let write = async {
        // Until the switch holds the read, or answered it without holding it.
        while world.held_reads() == 0 && !answered.get() {
            tokio::task::yield_now().await;
        }
        held_at_the_write.set(world.held_reads() > 0);
        wallet
            .put_record(&target, br#"{"items":["milk"]}"#, Vec::new())
            .await
    };
    let both = futures_util::future::join(read, write);
    let Ok((read, written)) = tokio::time::timeout(STEP_TIMEOUT, both).await else {
        return Err("the write didn't answer the waiting read: the read is still held".into());
    };
    written?;
    let report = read?;
    if !held_at_the_write.get() {
        return Err("the switch answered the waiting read without holding it".into());
    }
    world.outcome(
        "the watch's waiting read, answered by the wallet's write",
        &json!({
            "held_when_the_wallet_wrote": held_at_the_write.get(),
            "events": events(&report.events),
            "stopped": report.stopped,
            "app": app_status(&mut watch),
        }),
    );
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
