//! More of removing an app (Switch spec 12.2, 12.3, Switch wire 3.3, 7.4.11, 7.4.12): the
//! time a removal counts from, the cleanup after it, the purge of its entry, and a
//! revocation that goes out although the signer can't read the switch first.

use std::collections::BTreeMap;

use pubky_switch_client::app::LeaveMode;
use pubky_switch_core::records::{IdentityDoc, app_record_path};
use pubky_switch_signer::{Signer, UserConfirmed};
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::messaging::joined;
use super::recovery::expect_answer;
use super::removal::follow;
use super::{ORIGIN, STEP_MS};
use crate::parties::Asking;
use crate::{FlowResult, World};
use pubky_switch_client::testing::START_MS;

/// A day, in milliseconds.
const DAY_MS: u64 = 86_400_000;

/// An hour, in milliseconds.
const HOUR_MS: u64 = 3_600_000;

/// What a version says of the apps, for the trace: how many it lists, and when each one it
/// removed is distrusted from, after the world's start.
fn removals(doc: &IdentityDoc, signer: &Signer) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json!({
        "version": doc.version(),
        "data_epoch": doc.data_epoch(),
        "apps": doc.body().apps.len(),
        "distrust_from_ms_after_start": doc
            .body()
            .removed
            .iter()
            .map(|removed| removed.distrust_from.saturating_sub(START_MS))
            .collect::<Vec<_>>(),
        "signer": status(signer)?,
    }))
}

/// When the app `app_id` is distrusted from in `doc`.
fn distrust_from(doc: &IdentityDoc, app_id: [u8; 16]) -> Option<u64> {
    doc.body()
        .removed
        .iter()
        .find(|removed| removed.app_id == app_id)
        .map(|removed| removed.distrust_from)
}

/// What the signer's last read of the apps (`GET /v1/{id}/apps`) reports of alice's app
/// `name`: each member of its status, by name, as the trace keeps it (Switch wire 7.4.12).
/// Empty when the read doesn't report the app.
fn reported(world: &World, name: &str) -> Result<BTreeMap<String, String>, String> {
    let trace = world.trace();
    let line = trace
        .lines
        .iter()
        .rev()
        .find(|line| line.label == "{alice} GET /v1/{alice}/apps")
        .ok_or("the signer read no apps")?;
    let app = format!("id {{alice/{name}}}");
    let Some(index) = line.facts.iter().find_map(|(fact, value)| {
        let index = fact.strip_prefix("body.apps[")?.strip_suffix("].app_id")?;
        (*value == app).then_some(index)
    }) else {
        return Ok(BTreeMap::new());
    };
    let member = format!("body.apps[{index}].");
    Ok(line
        .facts
        .iter()
        .filter_map(|(fact, value)| Some((fact.strip_prefix(&member)?.to_owned(), value.clone())))
        .collect())
}

/// Fail the flow unless the signer's last read of the apps (`GET /v1/{id}/apps`) reports
/// alice's app `name` as revoked at `at` (Switch wire 7.4.12 `revoked_at`).
fn expect_revoked_at(world: &World, name: &str, at: u64) -> FlowResult {
    let status = reported(world, name)?;
    let reported = status.get("revoked_at");
    let expected = format!("time {}", pubky_switch_core::time::rfc3339(at));
    if reported == Some(&expected) {
        Ok(())
    } else {
        Err(
            format!("the apps read reports the {name} revoked at {reported:?}, not {expected}")
                .into(),
        )
    }
}

/// What a status shows of a purged app, freed down to its App ID and the time it was
/// revoked: a kept App ID that isn't current (Switch wire 7.4.12), and no last-seen time,
/// record, certificate from that record or key bundle part (Switch wire 9.1 "Departure,
/// revoked app").
const FREED: [(&str, &str); 6] = [
    ("current", "bool false"),
    ("last_seen", "null"),
    ("record_cert", "null"),
    ("record_at", "null"),
    ("cert_expires_at", "null"),
    ("bundle_ranges", "array of 0"),
];

/// Fail the flow unless the signer's last read of the apps reports alice's app `name` as
/// [`FREED`] (`freed`), or as still holding its record and certificate (`!freed`).
fn expect_freed(world: &World, name: &str, freed: bool) -> FlowResult {
    let status = reported(world, name)?;
    if status.is_empty() {
        return Err(format!("the apps read doesn't report the {name}").into());
    }
    let shows = |member: &str, value: &str| status.get(member).is_some_and(|held| held == value);
    let held = ["record_cert", "record_at", "cert_expires_at", "last_seen"]
        .iter()
        .all(|member| status.get(*member).is_some_and(|value| value != "null"));
    let all_freed = FREED.iter().all(|(member, value)| shows(member, value));
    if (freed && all_freed) || (!freed && held) {
        Ok(())
    } else {
        Err(format!("the apps read reports the {name} as {status:?}").into())
    }
}

/// The time a revocation counts from (Switch spec 12.2 step 3). A day after alice's three
/// apps joined, her signer revokes the phone and names a time an hour earlier, as after a
/// compromise the user dates: the version that removes the phone distrusts it from that
/// time. It revokes the tablet and names a time a day later: a later time counts as the
/// revocation's own, the switch's time of it.
///
/// Calls: `POST /v1/{id}/apps/{app_id}/revoke` twice, and `PUT /v1/{id}/identity` with a
/// `removed` entry dated before the revocation and one dated at it.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or a removal is dated other
/// than its step says.
pub async fn revocation_times(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (phone, _) = joined(world, &alice, &mut signer, "phone").await?;
    let (tablet, _) = joined(world, &alice, &mut signer, "tablet").await?;
    world.advance_ms(DAY_MS);

    let earlier = world.now_ms() - HOUR_MS;
    let phone_revoked_at = world.now_ms();
    let removing = signer
        .revoke(
            phone.app_id(),
            Some(earlier),
            UserConfirmed::shown_and_confirmed(),
        )
        .await?;
    world.outcome(
        "the signer revoked the phone, distrusted from an hour before",
        &removals(&removing, &signer)?,
    );
    let dated = distrust_from(&removing, phone.app_id());
    if dated != Some(earlier) {
        return Err(format!("the phone is distrusted from {dated:?}, not {earlier}").into());
    }
    // The switch's own time of the revocation is when it took it, whatever the user named.
    expect_revoked_at(world, "phone", phone_revoked_at)?;
    world.advance_ms(STEP_MS);

    let revoked_at = world.now_ms();
    let removing = signer
        .revoke(
            tablet.app_id(),
            Some(revoked_at + DAY_MS),
            UserConfirmed::shown_and_confirmed(),
        )
        .await?;
    world.outcome(
        "the signer revoked the tablet, naming a time a day later",
        &removals(&removing, &signer)?,
    );
    let dated = distrust_from(&removing, tablet.app_id());
    if dated != Some(revoked_at) {
        return Err(format!("the tablet is distrusted from {dated:?}, not {revoked_at}").into());
    }
    expect_revoked_at(world, "tablet", revoked_at)?;
    world.advance_ms(STEP_MS);

    follow(world, &mut wallet, "the wallet after both revocations").await?;
    Ok(())
}

/// A departure keeps its time. alice's phone leaves. A day later, before her signer's
/// routine run has seen the departure, the signer delivers a version for another reason,
/// which still lists the phone, as the switch allows while a departure awaits its rotation
/// (Switch wire 3.3). The run that follows removes the phone, distrusted from the time it
/// left, not from the later delivery.
///
/// Calls: `POST /v1/{id}/apps/{app_id}/leave`, `PUT /v1/{id}/identity` with a version that
/// lists a departed app, and the removing version dated at the departure.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or the removal is dated
/// other than at the departure.
pub async fn departure_time(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (mut phone, _) = joined(world, &alice, &mut signer, "phone").await?;

    let left_at = world.now_ms();
    let left = phone.leave(LeaveMode::TwoStep).await?;
    world.outcome("the phone left", &json!({ "report": format!("{left:?}") }));
    world.advance_ms(DAY_MS);

    let listing = signer.set_record_max_age(Some(86_400)).await?;
    world.outcome(
        "the signer delivered a version that still lists the phone",
        &removals(&listing, &signer)?,
    );
    if listing.listed_cert(&phone.app_id()).is_none() || !listing.body().removed.is_empty() {
        return Err("the version delivered meanwhile doesn't list the departed phone".into());
    }
    world.advance_ms(STEP_MS);

    signer.run_due().await?;
    let removing = signer
        .identity_doc()?
        .ok_or("the signer holds no document")?;
    world.outcome(
        "the signer's run removed the phone",
        &removals(&removing, &signer)?,
    );
    let dated = distrust_from(&removing, phone.app_id());
    if dated != Some(left_at) {
        return Err(format!("the phone is distrusted from {dated:?}, not {left_at}").into());
    }
    world.advance_ms(STEP_MS);
    follow(world, &mut wallet, "the wallet after the departure").await?;
    Ok(())
}

/// The cleanup after a removal, and the purge of its entry (Switch spec 12.2 step 4,
/// Switch wire 3.3 "Purging"). The phone's app record is a file on alice's Homeserver, as
/// its host wrote it. Her signer revokes the phone; the Homeserver fails the record's
/// deletion once. The removal stands, delivered and published, and the record stays until
/// the signer's next run deletes it. The signer then purges the phone's `removed` entry in
/// a new version, and the switch frees what it held of the phone: its record and
/// certificate, its last-seen time and its key bundle parts (Switch wire 9.1). The phone's
/// App ID stays refused: asked again with the same keys, the signer doesn't approve it,
/// the switch refuses the phone's call, and the apps the switch reports still hold the
/// phone with the time it was revoked.
///
/// Calls: `POST /v1/{id}/apps/{app_id}/revoke`, `PUT /v1/{id}/identity` with the removing
/// version and with the version that purges the entry, and `GET /v1/{id}/apps` showing the
/// phone's status before and after it.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the record is deleted or
/// kept against what its step says, the switch frees the phone's record before the purge
/// or keeps it after, the purged App ID is approved again or served, or the switch no
/// longer reports it as revoked.
pub async fn revocation_cleanup(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (mut phone, _) = joined(world, &alice, &mut signer, "phone").await?;

    let record = app_record_path(&phone.app_id());
    world
        .files()
        .put(alice.public(), &record, b"the phone's record".to_vec());
    let held = |world: &World| world.files().file(alice.public(), &record).is_some();
    let published = |world: &World| {
        world
            .files()
            .identity_doc(&alice.public())
            .map(|doc| doc.version())
    };

    world.fail_homeserver_deletion(&alice, &record);
    let revoked_at = world.now_ms();
    let removing = signer
        .revoke(phone.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await;
    let removing_version = signer.identity_doc()?.map(|doc| doc.version());
    world.outcome(
        "the signer revoked the phone, its record's deletion failing",
        &json!({
            "ok": removing.is_ok(),
            "record_held": held(world),
            "published_is_newest": published(world) == removing_version,
            "signer": status(&signer)?,
        }),
    );
    let removed = signer
        .identity_doc()?
        .is_some_and(|doc| distrust_from(&doc, phone.app_id()).is_some());
    if !removed || !held(world) || published(world) != removing_version {
        return Err("the removal doesn't stand with its record still held".into());
    }
    if world.homeserver_faults_left() != 0 {
        return Err("the record's deletion was never tried".into());
    }
    world.advance_ms(STEP_MS);

    signer.run_due().await?;
    world.outcome(
        "the signer's next run deleted the record",
        &json!({ "record_held": held(world), "signer": status(&signer)? }),
    );
    if held(world) {
        return Err("the removed app's record is still on the Homeserver".into());
    }
    // Listed in `removed`, the phone is kept whole at the switch.
    expect_freed(world, "phone", false)?;
    world.advance_ms(STEP_MS);

    let purged = signer.purge_removed(phone.app_id()).await?;
    world.outcome(
        "the signer purged the phone's entry",
        &removals(&purged, &signer)?,
    );
    if !purged.body().removed.is_empty() || published(world) != Some(purged.version()) {
        return Err("the purged version still removes an app, or isn't published".into());
    }
    // The delivery that lists it in neither list frees it (Switch wire 9.1 "Sweeps"); the
    // signer's read after the delivery shows it so.
    expect_freed(world, "phone", true)?;
    world.advance_ms(STEP_MS);

    // The App ID is kept for good: the same keys are never approved again.
    let again = Asking::new(world.app_keys(&alice, "phone")?)?;
    let reviewed = signer.review(again.request.signed(), &again.auth);
    world.outcome(
        "the phone's keys asked to be approved again",
        &json!({ "refused": reviewed.is_err() }),
    );
    if reviewed.is_ok() {
        return Err("the signer would approve a purged App ID again".into());
    }
    // And the switch keeps it too: purged from the document, the phone is still refused
    // (Switch wire 3.3 "Purging", 7.2).
    let refused = phone.receive(None).await;
    world.outcome(
        "the purged phone read its feed",
        &json!({ "refused": refused.is_err() }),
    );
    world.advance_ms(STEP_MS);
    expect_answer(
        world,
        "{alice/phone} GET /v1/{alice}/feed",
        403,
        "not_current",
    )?;
    // Any app the document doesn't list is refused so. That the switch still knows this
    // one shows in the apps it reports: the phone, with the time it was revoked.
    signer.run_due().await?;
    world.outcome(
        "the signer's run after the purge",
        &json!({ "signer": status(&signer)? }),
    );
    expect_revoked_at(world, "phone", revoked_at)?;
    expect_freed(world, "phone", true)?;
    world.advance_ms(STEP_MS);
    follow(world, &mut wallet, "the wallet at the end").await?;
    Ok(())
}

/// A revocation that goes out although the signer can't read the switch first (Switch
/// spec 12.2). Before a revocation the signer reads the switch's copy of the document; a
/// read that fails adds nothing and holds nothing back, since the revocation may answer a
/// compromise. The read before the phone's revocation never arrives; the one before the
/// tablet's is refused on its way, with no signature. Each revocation goes to the switch in
/// the same call, and the version that removes the app follows the next read.
///
/// Calls: `POST /v1/{id}/apps/{app_id}/revoke` after a `GET /v1/{id}/apps` that failed,
/// and the removing versions.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, a fault met no request, or
/// an app isn't revoked and removed in the call that asked for it.
pub async fn revocation_unread(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (phone, _) = joined(world, &alice, &mut signer, "phone").await?;
    let (tablet, _) = joined(world, &alice, &mut signer, "tablet").await?;

    for (name, app_id, unanswered) in [
        ("phone", phone.app_id(), true),
        ("tablet", tablet.app_id(), false),
    ] {
        if unanswered {
            world.unreachable("GET", "/apps");
        } else {
            world.refuse("GET", "/apps", 503, "unavailable");
        }
        let revoked_at = world.now_ms();
        let removing = signer
            .revoke(app_id, None, UserConfirmed::shown_and_confirmed())
            .await?;
        world.outcome(
            &format!("the signer revoked the {name} past a read that failed"),
            &removals(&removing, &signer)?,
        );
        let revocation = format!("{{alice}} POST /v1/{{alice}}/apps/{{alice/{name}}}/revoke");
        let answered = world.last_fact(&revocation, "status");
        if answered.as_deref() != Some("200")
            || distrust_from(&removing, app_id) != Some(revoked_at)
            || world.faults_left() != 0
        {
            return Err(format!(
                "the {name}'s revocation was answered {answered:?}, and its removal is \
                 dated {:?}, not {revoked_at}",
                distrust_from(&removing, app_id)
            )
            .into());
        }
        world.advance_ms(STEP_MS);
    }
    follow(world, &mut wallet, "the wallet after both revocations").await?;
    Ok(())
}
