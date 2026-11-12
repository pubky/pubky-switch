//! A data epoch past the second (Switch spec 3.5, Switch wire 7.4.11): two rotations, a
//! record sealed at each epoch, and what an app that joins at the third epoch reads of
//! them.

use pubky_switch_client::app::{App, LeaveMode, RecordTarget};
use pubky_switch_signer::{CertChange, Signer, UserConfirmed};
use serde_json::json;

use super::enrollment::{enroll, status};
use super::join::app_status;
use super::messaging::joined_as;
use super::records::shown;
use super::removal::follow;
use super::{ORIGIN, STEP_MS};
use crate::parties::{
    Asking, NOTES, NOTES_JOURNAL, notes_collection, notes_protocol_with_both_collections,
    notes_protocol_with_records,
};
use crate::{FlowResult, World};

/// A day in milliseconds.
const DAY_MS: u64 = 24 * 3_600_000;

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

/// The apps that hold the keyed scope beside the wallet, in the order they are approved:
/// eight of them, so that a rotation's key bundles don't fit one batch of eight operations
/// with the wallet's own (Switch wire 6.4). The last one is the last the document lists.
const OTHERS: [&str; 8] = [
    "phone", "tablet", "desk", "pad", "watch", "console", "reader", "radio",
];

/// A rotation given up, and its epoch completed (Switch spec 3.2, 3.5). alice has nine
/// apps. Her signer renews the wallet's certificate without one of its keyed scopes, which
/// rotates the data keys: the renewal's operations take two batches. The first is taken;
/// the second never arrives. Before the signer sends it again, the radio, whose key bundle
/// is in that batch, leaves. The batch, sent again byte for byte, is refused `403
/// not_current`, since it holds a bundle for an app that departed (Switch wire 6.2
/// `key_bundle.put`), and the signer gives the renewal up: the second epoch's keys are
/// stored for some apps, and no version raised the epoch.
///
/// The signer's next run completes the second epoch for every current app in a version of
/// its own, then removes the radio with a rotation to the third. The wallet, whose
/// reduction was given up, keeps both its scopes and follows through both epochs.
///
/// Calls: the signer's `POST /v1/{id}/ops` with a rotation's second batch after its
/// target left (`403 not_current`); `PUT /v1/{id}/identity` with a version that only
/// raises the data epoch; the removing version after it; `GET
/// /v1/{id}/apps/{app_id}/keys` by apps two epochs behind.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the second batch is taken or
/// refused otherwise, or the epochs don't end at the third with the radio removed and the
/// wallet's scopes kept.
pub async fn rotation_given_up(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let scopes = [NOTES, NOTES_JOURNAL];
    let (mut wallet, _) = joined_as(
        world,
        &alice,
        &mut signer,
        Asking::for_scopes(world.app_keys(&alice, "wallet")?, &scopes)?,
        notes_protocol_with_both_collections(&scopes),
    )
    .await?;
    let mut others = Vec::new();
    for name in OTHERS {
        let (app, _) = joined_as(
            world,
            &alice,
            &mut signer,
            Asking::new(world.app_keys(&alice, name)?)?,
            notes_protocol_with_both_collections(&[NOTES]),
        )
        .await?;
        others.push(app);
    }
    world.advance_ms(DAY_MS);

    // The reduction's second batch doesn't arrive.
    world.unreachable_after("POST", "/ops", 1);
    let change = CertChange {
        scopes: Some(vec![NOTES.to_owned()]),
        expires_at: None,
    };
    let renewing = signer.renew(wallet.app_id(), change).await;
    world.outcome(
        "the signer renewed the wallet without a keyed scope, its second batch not arriving",
        &json!({ "ok": renewing.is_ok(), "signer": status(&signer)? }),
    );
    if renewing.is_ok() || world.faults_left() != 0 {
        return Err("the renewal's second batch wasn't cut off".into());
    }
    world.advance_ms(STEP_MS);

    // The radio, the last app listed, leaves meanwhile.
    let radio = others.last_mut().ok_or("no app was approved")?;
    let left = radio.leave(LeaveMode::TwoStep).await?;
    world.outcome("the radio left", &json!({ "report": format!("{left:?}") }));
    world.advance_ms(STEP_MS);

    let resumed = signer.resume().await;
    let held = signer.identity_doc()?;
    world.outcome(
        "the signer sent the second batch again and gave the renewal up",
        &json!({
            "ok": resumed.is_ok(),
            "data_epoch": held.as_ref().map(|doc| doc.data_epoch()),
            "signer": status(&signer)?,
        }),
    );
    let batch = "{alice} POST /v1/{alice}/ops";
    let refused = (
        world.last_fact(batch, "status"),
        world.last_fact(batch, "body.code"),
    );
    let not_current = (Some("403".to_owned()), Some("text not_current".to_owned()));
    if refused != not_current || held.as_ref().map(|doc| doc.data_epoch()) != Some(1) {
        return Err(format!(
            "the second batch was answered {refused:?}, and the signer's version is at \
             epoch {:?}",
            held.as_ref().map(|doc| doc.data_epoch())
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    signer.run_due().await?;
    let newest = signer
        .identity_doc()?
        .ok_or("the signer holds no document")?;
    world.outcome(
        "the signer's run completed the second epoch and removed the radio at the third",
        &json!({
            "version_steps": newest.version() - held.as_ref().map_or(0, |doc| doc.version()),
            "data_epoch": newest.data_epoch(),
            "apps": newest.body().apps.len(),
            "removed": newest.body().removed.len(),
            "signer": status(&signer)?,
        }),
    );
    if newest.data_epoch() != 3 || newest.body().apps.len() != 8 || newest.body().removed.len() != 1
    {
        return Err(format!(
            "the run ended at epoch {} with {} apps listed and {} removed",
            newest.data_epoch(),
            newest.body().apps.len(),
            newest.body().removed.len()
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    // Two apps follow, two epochs behind: the wallet, whose reduction was given up, and
    // the phone.
    follow(world, &mut wallet, "the wallet after the run").await?;
    let phone = others.first_mut().ok_or("no app was approved")?;
    follow(world, phone, "the phone after the run").await?;
    let kept = wallet.cert().body().scopes.len();
    if wallet.keys_through() != 3 || phone.keys_through() != 3 || kept != 2 {
        return Err(format!(
            "the wallet holds keys through epoch {} with {kept} scopes, the phone through {}",
            wallet.keys_through(),
            phone.keys_through()
        )
        .into());
    }
    Ok(())
}
