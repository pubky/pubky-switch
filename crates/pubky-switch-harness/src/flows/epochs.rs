//! A data epoch past the second (Switch spec 3.5, Switch wire 7.4.11): two rotations, a
//! record sealed at each epoch, and what an app that joins at the third epoch reads of
//! them.

use pubky_switch_client::app::{App, RecordTarget};
use pubky_switch_signer::{Signer, UserConfirmed};
use serde_json::json;

use super::enrollment::{enroll, status};
use super::join::app_status;
use super::messaging::joined_as;
use super::records::shown;
use super::removal::follow;
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, notes_collection, notes_protocol_with_records};
use crate::{FlowResult, World};

/// The wallet writes the record `name`, sealed at the data epoch it is at.
async fn write(world: &World, wallet: &mut App, name: &str) -> FlowResult {
    let target = RecordTarget::new(notes_collection(), name.as_bytes());
    let value = format!(r#"{{"note":"{name}"}}"#);
    let written = wallet
        .put_record(&target, value.as_bytes(), Vec::new())
        .await?;
    world.outcome(
        &format!("the wallet wrote {name}"),
        &json!({ "record": shown(Some(&written)), "app": app_status(wallet) }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

/// The signer revokes `app`, which rotates the data keys, and the wallet follows.
async fn rotate_by_revoking(
    world: &World,
    signer: &mut Signer,
    app: &App,
    wallet: &mut App,
    name: &str,
) -> FlowResult {
    let removing = signer
        .revoke(app.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        &format!("the signer revoked {name}"),
        &json!({
            "version": removing.version(),
            "data_epoch": removing.body().data_epoch,
            "removed": removing.body().removed.len(),
            "signer": status(signer)?,
        }),
    );
    world.advance_ms(STEP_MS);
    follow(world, wallet, &format!("the wallet after {name} went")).await
}

/// alice's wallet writes a record at the first data epoch. The signer revokes her phone,
/// and the wallet writes a second record at the second epoch; it revokes her tablet, and
/// the wallet writes a third at the third. A desk then joins at the third epoch, lists
/// the collection and reads each record: what it can open of the earlier epochs' records
/// is what its approval gave it keys for.
///
/// Calls, beyond a revocation's and the records flow's: `PUT /v1/{id}/identity` and
/// `key_bundle.put` for a second rotation, `GET /v1/{id}/apps/{app_id}/keys` with the
/// third epoch's part, and `GET /v1/{id}/records` and `GET /v1/{id}/records/{key}` with
/// records sealed at three data epochs.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn third_epoch(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let join = async |signer: &mut Signer, name: &str| {
        joined_as(
            world,
            &alice,
            signer,
            Asking::new(world.app_keys(&alice, name)?)?,
            notes_protocol_with_records(),
        )
        .await
    };
    let (mut wallet, _) = join(&mut signer, "wallet").await?;
    let (phone, _) = join(&mut signer, "phone").await?;
    let (tablet, _) = join(&mut signer, "tablet").await?;
    follow(world, &mut wallet, "the wallet at the first epoch").await?;

    write(world, &mut wallet, "first").await?;
    rotate_by_revoking(world, &mut signer, &phone, &mut wallet, "the phone").await?;
    write(world, &mut wallet, "second").await?;
    rotate_by_revoking(world, &mut signer, &tablet, &mut wallet, "the tablet").await?;
    write(world, &mut wallet, "third").await?;

    // An app that joins at the third epoch.
    let (mut desk, _) = join(&mut signer, "desk").await?;
    let listed = desk.records_of(&notes_collection().name).await?;
    world.outcome(
        "the desk joined at the third epoch and listed the collection",
        &json!({ "listed": listed.len(), "app": app_status(&mut desk) }),
    );
    for name in ["first", "second", "third"] {
        let target = RecordTarget::new(notes_collection(), name.as_bytes());
        let held = desk.shared_record(&desk.record_key(&target)?).await?;
        let read = desk.read_record(&target).await?;
        world.outcome(
            &format!("what the desk holds and reads of {name}"),
            &json!({ "held": shown(held.as_ref()), "read": shown(read.as_ref()) }),
        );
        world.advance_ms(STEP_MS);
    }
    signer.run_due().await?;
    world.outcome("signer ran what is due", &status(&signer)?);
    Ok(())
}
