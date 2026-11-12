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

/// Which of the three records `app` opens when it reads them from the switch.
async fn opens(
    world: &World,
    app: &mut App,
    name: &str,
) -> Result<[bool; 3], Box<dyn std::error::Error>> {
    let mut opened = [false; 3];
    for (at, record) in ["first", "second", "third"].into_iter().enumerate() {
        let target = RecordTarget::new(notes_collection(), record.as_bytes());
        let read = app.read_record(&target).await?;
        opened[at] = read.is_some_and(|read| read.content.value().is_some());
        world.advance_ms(STEP_MS);
    }
    world.outcome(
        &format!("what {name} opens of the three records"),
        &json!({ "opened": opened, "app": app_status(app) }),
    );
    Ok(opened)
}

/// Two rotations with three apps that stay (Switch spec 3.5, Switch wire 7.4.11). alice's
/// wallet, phone and tablet share a collection; her desk and her pad are revoked in turn,
/// and each revocation rotates the data keys for the three that stay. The wallet follows
/// each rotation and writes a record at each epoch. The tablet reads the three records
/// before it has followed anything: it opens the first, and the other two, sealed at
/// epochs it holds no key for, it can't. The phone and the tablet then follow, two epochs
/// behind: one fetch brings each the parts of both epochs. At the end each of the three
/// holds keys through the third epoch and opens all three records.
///
/// Calls: the signer's `POST /v1/{id}/ops` with `key_bundle.put` for three apps, twice;
/// `GET /v1/{id}/apps/{app_id}/keys` by an app two epochs behind; `GET
/// /v1/{id}/records/{key}` by an app that holds no key for the record's epoch.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or an app that stays ends
/// without the third epoch's keys or can't open a record.
pub async fn epochs_three_readers(world: &World) -> FlowResult {
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
    let (mut phone, _) = join(&mut signer, "phone").await?;
    let (mut tablet, _) = join(&mut signer, "tablet").await?;
    let (desk, _) = join(&mut signer, "desk").await?;
    let (pad, _) = join(&mut signer, "pad").await?;
    follow(world, &mut wallet, "the wallet at the first epoch").await?;

    write(world, &mut wallet, "first").await?;
    rotate_by_revoking(world, &mut signer, &desk, &mut wallet, "the desk").await?;
    write(world, &mut wallet, "second").await?;
    rotate_by_revoking(world, &mut signer, &pad, &mut wallet, "the pad").await?;
    write(world, &mut wallet, "third").await?;

    // The tablet reads before it has followed anything: it holds the first epoch's keys
    // only, and a read fetches none.
    let behind = opens(world, &mut tablet, "the tablet, two epochs behind,").await?;
    if behind != [true, false, false] {
        return Err(format!("two epochs behind, the tablet opens {behind:?}").into());
    }
    // The phone and the tablet follow now, two epochs behind.
    follow(world, &mut phone, "the phone after both rotations").await?;
    follow(world, &mut tablet, "the tablet after both rotations").await?;
    for (name, app) in [
        ("wallet", &mut wallet),
        ("phone", &mut phone),
        ("tablet", &mut tablet),
    ] {
        let opened = opens(world, app, &format!("the {name}")).await?;
        if opened != [true, true, true] || app.keys_through() != 3 {
            return Err(format!(
                "the {name} opens {opened:?} and holds keys through epoch {}",
                app.keys_through()
            )
            .into());
        }
    }
    signer.run_due().await?;
    world.outcome("signer ran what is due", &status(&signer)?);
    Ok(())
}
