//! Chain stub retention (Switch wire 7.4.4 "Checkpoints", 9.1; Switch spec 8.3): an app more
//! than 30 days behind finds the stubs after its position dropped behind a checkpoint, and
//! continues from it in reconcile mode, while an app whose cursor passed them goes on.

use pubky_switch::limits::Limits;
use pubky_switch_client::app::App;
use pubky_switch_core::keys::IdentityKey;
use serde_json::json;

use super::enrollment::enroll;
use super::join::app_status;
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// The switch's limits here: a checkpoint once three stubs may go, eight a request.
fn small_retention() -> Limits {
    Limits {
        checkpoint_behind: 3,
        retention_per_request: 8,
        ..Limits::default()
    }
}

/// `app` reads its feed to the end and moves its cursor; the flow notes where it stands.
async fn read(world: &World, name: &str, app: &mut App) -> FlowResult {
    app.receive(None).await?;
    app.flush_cursor().await?;
    world.outcome(name, &json!({ "app": app_status(app) }));
    world.advance_ms(STEP_MS);
    Ok(())
}

/// alice's wallet adds contact number `n`, one chain item.
async fn add(world: &World, wallet: &mut App, n: u8) -> FlowResult {
    let contact = IdentityKey::from_secret([n; 32]).public();
    wallet.add_contact(&contact).await?;
    world.advance_ms(STEP_MS);
    Ok(())
}

/// alice's wallet and phone read; the phone stops while the wallet writes and reads on.
/// Thirty-one days later the wallet writes again, and the switch, whose cursors no longer
/// hold the stubs after the phone, drops them behind a checkpoint. The wallet goes on; the
/// phone, reading at last, continues from the checkpoint in reconcile mode.
///
/// The switch signs a checkpoint once three stubs may go here ([`World::add_switch_with`]).
///
/// Calls: `GET /v1/{id}/feed` across a checkpoint, by an app whose cursor passed the stubs
/// and by one more than 30 days behind them.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or an app is in reconcile
/// mode where it shouldn't be, or isn't where it should.
pub async fn behind_a_checkpoint(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world
        .add_switch_with(ORIGIN, &[&alice], small_retention())
        .await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (mut phone, _) = joined(world, &alice, &mut signer, "phone").await?;
    read(world, "the wallet before the contacts", &mut wallet).await?;
    read(world, "the phone before the contacts", &mut phone).await?;
    for n in 1..=6 {
        add(world, &mut wallet, n).await?;
        read(world, &format!("the wallet after contact {n}"), &mut wallet).await?;
    }
    world.advance_ms(31 * DAY_MS);
    add(world, &mut wallet, 7).await?;
    read(world, "the wallet 31 days on", &mut wallet).await?;
    read(world, "the phone 31 days on", &mut phone).await?;
    if wallet.reconcile_mode() {
        return Err("the wallet, whose cursor passed the stubs, is in reconcile mode".into());
    }
    if !phone.reconcile_mode() {
        return Err("the phone, more than 30 days behind a checkpoint, isn't reconciling".into());
    }
    Ok(())
}
