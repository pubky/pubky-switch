//! What an app's upload brings to the service an identity recovered at (Switch spec 12.6
//! step 3, Switch wire 7.4.14): records and claims the lost service held, merged into what
//! the new one holds, and the refusals of an upload.

use pubky_switch_client::app::{App, AppEvent, RecordTarget};
use pubky_switch_client::testing::TestIdentity;
use pubky_switch_signer::{Signer, UserConfirmed};
use serde_json::json;

use super::enrollment::enroll;
use super::join::events;
use super::messaging::joined_as;
use super::records::{look, shown};
use super::recovery::{RECOVERY_ORIGIN, follow_recovery, recovered, upload_of};
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, notes_collection, notes_protocol_with_records};
use crate::{FlowResult, World};

/// alice's service is lost, and her signer recovers at another.
async fn lose_and_recover(world: &World, alice: &TestIdentity, signer: &mut Signer) -> FlowResult {
    world.lose_switch(ORIGIN);
    world.add_switch(RECOVERY_ORIGIN, &[alice]).await?;
    let doc = signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss and recovered elsewhere",
        &recovered(&doc, signer)?,
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

/// Fail the flow unless the evidence upload of alice's app `name`, the first of the two
/// its follow sends, changed `records` records and made `divergent` divergent.
fn expect_records(world: &World, name: &str, records: usize, divergent: usize) -> FlowResult {
    let upload = upload_of(name);
    let trace = world.trace();
    let line = trace
        .lines
        .iter()
        .rev()
        .filter(|line| line.label == upload)
        .nth(1)
        .ok_or_else(|| format!("the {name} sent no evidence upload"))?;
    let fact = |name: &str| line.facts.get(name).cloned();
    let shown = (
        fact("status"),
        fact("body.result.records"),
        fact("body.result.divergent"),
    );
    let expected = (
        Some("200".to_owned()),
        Some(format!("array of {records}")),
        Some(format!("array of {divergent}")),
    );
    if shown == expected {
        Ok(())
    } else {
        Err(format!("the {name}'s evidence upload shows {shown:?}, not {expected:?}").into())
    }
}

/// What `app` reads of the record at `target` from the switch, and whether the read told
/// it the record is divergent.
async fn read(
    world: &World,
    name: &str,
    app: &mut App,
    target: &RecordTarget,
) -> Result<bool, Box<dyn std::error::Error>> {
    let read = app.read_record(target).await?;
    let raised = app.take_events();
    world.outcome(
        name,
        &json!({ "record": shown(read.as_ref()), "events": events(&raised) }),
    );
    world.advance_ms(STEP_MS);
    Ok(raised
        .iter()
        .any(|event| matches!(event, AppEvent::RecordDivergent { .. })))
}

/// Records brought to the new service by uploads. alice's wallet and phone share a
/// collection. At the service that is lost, the wallet writes two records, the phone
/// follows, and the wallet changes the first, which the phone never sees. After the
/// recovery the phone follows first: its upload fills in both records as it holds them,
/// and it changes the first at the new service. The wallet follows next: its upload of the
/// second record is the operation the service holds, and changes nothing; its upload of
/// the first is newer than the version the phone's write built on, so it conflicts with a
/// write at the new service. The write stands, the upload is kept as divergent, and the
/// record's view says so until the wallet writes a newer version there.
///
/// Calls: `POST /v1/{id}/recovery/upload` with `records` (taken, the same again, and kept
/// divergent); `GET /v1/{id}/records/{key}` for a record taken from an upload, for one
/// with a divergent upload, and after a write cleared it; `GET /v1/{id}/feed` with
/// `upload` transitions; `POST /v1/{id}/ops` (`record.put`) on a record taken from an
/// upload and on a divergent one.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or an upload changes other
/// records than its step says.
pub async fn recovery_upload_records(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let asking = |name: &str| -> Result<Asking, crate::HarnessError> {
        Asking::new(world.app_keys(&alice, name)?)
    };
    let (mut wallet, _) = joined_as(
        world,
        &alice,
        &mut signer,
        asking("wallet")?,
        notes_protocol_with_records(),
    )
    .await?;
    let (mut phone, _) = joined_as(
        world,
        &alice,
        &mut signer,
        asking("phone")?,
        notes_protocol_with_records(),
    )
    .await?;

    let list = RecordTarget::new(notes_collection(), b"shopping list");
    let book = RecordTarget::new(notes_collection(), b"address book");
    wallet
        .put_record(&list, br#"{"items":["milk"]}"#, Vec::new())
        .await?;
    world.advance_ms(STEP_MS);
    wallet
        .put_record(&book, br#"{"names":["bob"]}"#, Vec::new())
        .await?;
    world.outcome(
        "the wallet wrote two records",
        &json!({ "events": events(&wallet.take_events()) }),
    );
    world.advance_ms(STEP_MS);
    look(world, &mut phone, "the phone followed both records").await?;
    let changed = wallet
        .put_record(&list, br#"{"items":["milk","bread"]}"#, Vec::new())
        .await?;
    world.outcome(
        "the wallet changed the first record, unseen by the phone",
        &shown(Some(&changed)),
    );
    world.advance_ms(STEP_MS);

    lose_and_recover(world, &alice, &mut signer).await?;

    // The phone first: both records as it holds them.
    follow_recovery(world, &mut phone, "phone", 1).await?;
    expect_records(world, "phone", 2, 0)?;
    look(
        world,
        &mut phone,
        "the phone read its feed at the new service",
    )
    .await?;
    read(
        world,
        "the phone read the first record, taken from its upload",
        &mut phone,
        &list,
    )
    .await?;
    let written = phone
        .put_record(&list, br#"{"items":["milk","eggs"]}"#, Vec::new())
        .await?;
    world.outcome(
        "the phone changed the first record at the new service",
        &json!({
            "record": shown(Some(&written)),
            "events": events(&phone.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);

    // The wallet next: the second record is the one held; the first conflicts with the
    // phone's write, which stands.
    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    expect_records(world, "wallet", 0, 1)?;
    look(
        world,
        &mut wallet,
        "the wallet read its feed at the new service",
    )
    .await?;
    let told = read(
        world,
        "the wallet read the first record, with a divergent upload",
        &mut wallet,
        &list,
    )
    .await?;
    let divergent = last_record_read(world, "wallet");
    if divergent.as_deref() != Some("bool true") || !told {
        return Err(format!(
            "the record with a divergent upload reads divergent {divergent:?}, and the \
             wallet was told so: {told}"
        )
        .into());
    }
    read(
        world,
        "the wallet read the second record",
        &mut wallet,
        &book,
    )
    .await?;

    // A newer version written at the new service clears the divergent upload.
    let settled = wallet
        .put_record(&list, br#"{"items":["milk","bread","eggs"]}"#, Vec::new())
        .await?;
    world.outcome(
        "the wallet wrote a newer version at the new service",
        &json!({
            "record": shown(Some(&settled)),
            "events": events(&wallet.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);
    look(world, &mut phone, "the phone followed the wallet's write").await?;
    let told = read(
        world,
        "the phone read the first record, the divergent upload cleared",
        &mut phone,
        &list,
    )
    .await?;
    let divergent = last_record_read(world, "phone");
    if divergent.as_deref() != Some("bool false") || told {
        return Err(format!(
            "after a newer write the record reads divergent {divergent:?}, and the phone \
             was told it is: {told}"
        )
        .into());
    }
    Ok(())
}

/// The `divergent` member of the last record view alice's app `name` read by key.
fn last_record_read(world: &World, name: &str) -> Option<String> {
    let prefix = format!("{{alice/{name}}} GET /v1/{{alice}}/records/");
    let trace = world.trace();
    let line = trace
        .lines
        .iter()
        .rev()
        .find(|line| line.label.starts_with(&prefix))?;
    line.facts.get("body.divergent").cloned()
}
