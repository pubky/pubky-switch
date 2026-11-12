//! What an app's upload brings to the service an identity recovered at (Switch spec 12.6
//! step 3, Switch wire 7.4.14): records and claims the lost service held, merged into what
//! the new one holds, and the refusals of an upload.

use pubky_switch::limits::Limits;
use pubky_switch_client::app::DOC_CACHE_MS;
use pubky_switch_client::app::{App, ClaimOp, ObligationDeadline, RecordTarget};
use pubky_switch_client::client::{Credentials, SwitchClient};
use pubky_switch_client::clock::Clock;
use pubky_switch_client::testing::TestIdentity;
use pubky_switch_core::claims::{Basis, ClaimView};
use pubky_switch_signer::{Signer, UserConfirmed};
use serde_json::json;
use std::sync::Arc;

use super::claim::view;
use super::enrollment::enroll;
use super::join::events;
use super::messaging::{joined, joined_as};
use super::records::{look, shown};
use super::recovery::{
    BOBS_FIRST_CALL, RECOVERY_ORIGIN, SENDERS_ORIGIN, ended, expect_answer, expect_staged,
    expect_upload, follow_recovery, recovered, send, upload_of,
};
use super::{ORIGIN, STEP_MS};
use crate::parties::{
    Asking, NOTES_READER, notes_collection, notes_protocol, notes_protocol_with_records,
};
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

/// What `app` reads of the record at `target` from the switch, and whether it then holds
/// the record divergent.
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
    // Whether the app holds the record divergent: it was told when a view first showed it
    // so (`RecordDivergent`), at this read or at the feed read that met the upload.
    Ok(read.as_ref().is_some_and(|record| record.divergent))
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

/// The claim's key: any 32 bytes, the same in every world.
const CLAIM_KEY: [u8; 32] = [0x5a; 32];

/// The attempts' IDs.
const FIRST_ATTEMPT: [u8; 16] = [1; 16];
const SECOND_ATTEMPT: [u8; 16] = [2; 16];
const THIRD_ATTEMPT: [u8; 16] = [3; 16];

/// `app` reads the claim from the switch; the flow notes its view and how many entries
/// the switch lists, and returns the view.
async fn read_claim(
    world: &World,
    name: &str,
    app: &mut App,
) -> Result<ClaimView, Box<dyn std::error::Error>> {
    let read = app
        .read_claim(&CLAIM_KEY)
        .await?
        .ok_or_else(|| format!("{name}: the switch holds no such claim"))?;
    world.outcome(
        name,
        &json!({
            "view": view(&read.view),
            "entries": read.entries.len(),
            "events": events(&app.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok(read.view)
}

/// `app` writes `entry`; the flow notes the view the switch answered, and returns it.
async fn write_entry(
    world: &World,
    name: &str,
    app: &mut App,
    entry: ClaimOp,
) -> Result<ClaimView, Box<dyn std::error::Error>> {
    let written = app
        .write_claim(entry, Vec::new(), ObligationDeadline::NotKnown)
        .await?;
    world.outcome(
        name,
        &json!({
            "view": view(&written.view),
            "events": events(&app.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok(written.view)
}

/// `app` reads the claim from the switch: the step it reads at, and the step of each
/// entry the switch lists.
async fn app_read(
    world: &World,
    name: &str,
    app: &mut App,
) -> Result<(u64, Vec<u64>), Box<dyn std::error::Error>> {
    let read = app
        .read_claim(&CLAIM_KEY)
        .await?
        .ok_or_else(|| format!("{name}: the switch holds no such claim"))?;
    world.outcome(
        name,
        &json!({
            "view": view(&read.view),
            "entries": read.entries.len(),
            "steps": read.entries.iter().map(|entry| entry.step).collect::<Vec<_>>(),
            "events": events(&app.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok((
        read.view.step,
        read.entries.iter().map(|entry| entry.step).collect(),
    ))
}

/// Fail the flow unless the evidence upload of alice's app `name` changed one claim.
fn expect_claim(world: &World, name: &str) -> FlowResult {
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
        fact("body.result.claims"),
        fact("body.result.divergent_claims"),
        fact("body.result.refused"),
        fact("body.result.unverified"),
    );
    let expected = (
        Some("200".to_owned()),
        Some("array of 1".to_owned()),
        Some("array of 0".to_owned()),
        Some("number 0".to_owned()),
        Some("number 0".to_owned()),
    );
    if shown == expected {
        Ok(())
    } else {
        Err(format!("the {name}'s evidence upload shows {shown:?}, not {expected:?}").into())
    }
}

/// A claim rebuilt from uploads. At the service that is lost, alice's wallet attempts a
/// claim and reports the attempt failed; her phone follows. The wallet attempts again,
/// which the phone never sees. After the recovery the phone follows first: its upload
/// brings the first attempt and its outcome, and the new service rebuilds the claim, free
/// again. The wallet follows next: its upload adds the attempt the phone lacked. Each read
/// of the claim shows it as rebuilt. The wallet then reports that attempt failed at the
/// new service: the claim lists that one entry, at the step the uploads left it at, and
/// none for the steps before. The wallet attempts once more and reports it done, which
/// settles the claim, and the phone reads it.
///
/// Calls: `POST /v1/{id}/recovery/upload` with `claims` (a claim the service holds
/// nothing for, and an attempt it lacks on a free claim); `GET /v1/{id}/claims/{claim_key}`
/// for a claim rebuilt from uploads, free, attempting and settled; `POST /v1/{id}/ops`
/// (`claim` with `failed`, `attempt` and `done`) on a rebuilt claim; `GET /v1/{id}/feed` with `upload` transitions
/// that list a claim.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, an upload changes other
/// claims than its step says, or a read doesn't show the claim as rebuilt.
pub async fn recovery_upload_claim(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    // The phone first: it then sees the wallet join, and keeps the wallet's certificate,
    // without which it couldn't upload the wallet's entries.
    let (mut phone, _) = joined(world, &alice, &mut signer, "phone").await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    look(world, &mut phone, "the phone saw the wallet join").await?;

    let entries = [
        (
            "attempted",
            ClaimOp::attempt(CLAIM_KEY, 0, FIRST_ATTEMPT, 3_600, None),
            true,
        ),
        ("failed", ClaimOp::failed(CLAIM_KEY, 1, FIRST_ATTEMPT), true),
        (
            "attempted again, unseen by the phone",
            ClaimOp::attempt(CLAIM_KEY, 2, SECOND_ATTEMPT, 3_600, None),
            false,
        ),
    ];
    for (name, entry, seen) in entries {
        let written = wallet
            .write_claim(entry, Vec::new(), ObligationDeadline::NotKnown)
            .await?;
        world.outcome(
            &format!("the wallet {name}"),
            &json!({
                "view": view(&written.view),
                "events": events(&wallet.take_events()),
            }),
        );
        world.advance_ms(STEP_MS);
        if seen {
            look(world, &mut phone, &format!("the phone followed: {name}")).await?;
        }
    }

    lose_and_recover(world, &alice, &mut signer).await?;

    follow_recovery(world, &mut phone, "phone", 1).await?;
    expect_claim(world, "phone")?;
    let rebuilt = read_claim(
        world,
        "the phone read the claim, rebuilt from its upload",
        &mut phone,
    )
    .await?;
    if !rebuilt.rebuilt || rebuilt.attempt_id.is_some() {
        return Err("the claim the phone's upload rebuilt isn't rebuilt and free".into());
    }

    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    expect_claim(world, "wallet")?;
    let attempting = read_claim(
        world,
        "the wallet read the claim, its second attempt added",
        &mut wallet,
    )
    .await?;
    if !attempting.rebuilt || attempting.attempt_id != Some(SECOND_ATTEMPT) {
        return Err("the claim doesn't hold the wallet's uploaded attempt as current".into());
    }

    // Entries written at the new service: the claim then lists them, from the step the
    // uploads left it at, with none for the steps before.
    let failed = write_entry(
        world,
        "the wallet reported its uploaded attempt failed, at the new service",
        &mut wallet,
        ClaimOp::failed(CLAIM_KEY, attempting.step, SECOND_ATTEMPT),
    )
    .await?;
    let read = app_read(
        world,
        "the wallet read the claim, with one entry",
        &mut wallet,
    )
    .await?;
    // One entry, at the step it was written at: the steps before it, which the uploads
    // made, have none.
    if read != (failed.step, vec![attempting.step]) {
        return Err(format!(
            "the rebuilt claim reads at step {} with entries at {:?}, not at {} with one \
             at {}",
            read.0, read.1, failed.step, attempting.step
        )
        .into());
    }
    // After a loss an app attempts nothing until its reconciliation is over (Switch spec
    // 12.6 steps 5 and 6): here the user confirms it is.
    wallet
        .end_reconcile(pubky_switch_client::app::UserConfirmed::new())
        .await?;
    world.outcome(
        "the wallet's reconciliation ended",
        &json!({ "reconcile_mode": wallet.reconcile_mode() }),
    );
    let again = write_entry(
        world,
        "the wallet attempted again at the new service",
        &mut wallet,
        ClaimOp::attempt(CLAIM_KEY, failed.step, THIRD_ATTEMPT, 3_600, None),
    )
    .await?;
    write_entry(
        world,
        "the wallet reported that attempt done",
        &mut wallet,
        ClaimOp::done(CLAIM_KEY, again.step, THIRD_ATTEMPT, Basis::Owner, None)?,
    )
    .await?;
    look(world, &mut phone, "the phone followed the claim's end").await?;
    let read = read_claim(world, "the phone read the settled claim", &mut phone).await?;
    if !read.rebuilt {
        return Err("the settled claim no longer reads as rebuilt".into());
    }
    Ok(())
}

/// An upload by an app that reads the lists and can't manage them. alice's wallet saved
/// bob and carol as contacts and then blocked carol; her reader, an app holding
/// `lists.read` alone, read the lists. After the recovery the reader follows first: its
/// upload brings the deny list, which only restricts admission, and doesn't end the staged
/// admission. The lists it then reads at the new service hold carol on the deny list and
/// no contact. bob and carol each write to alice and are held back alike, so the staging
/// tells carol nothing. The wallet follows: its upload brings the contacts, carol among
/// them, and ends the staged admission. bob tries again and is admitted; carol tries again
/// and is refused, a contact the deny list keeps out.
///
/// Calls: `POST /v1/{id}/recovery/upload` with `lists.deny` alone, from an app holding
/// `lists.read`; `GET /v1/{id}/allow` with an uploaded deny entry; `GET /v1/{id}/apps`
/// with `admission_staged` still true after it; `PUT
/// /v1/{id}/peers` from a contact and from a denied sender while staged (`503 staged`)
/// and after the upload that ended it (admitted, `403 not_admitted`).
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the reader's upload ends
/// the staged admission or leaves carol off the deny list, or a sender is admitted or
/// refused against what its step says.
pub async fn recovery_upload_deny_only(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    let carol = world.identity("carol")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    world.add_switch(SENDERS_ORIGIN, &[&bob, &carol]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, SENDERS_ORIGIN).await?;
    let mut carol_signer = enroll(world, &carol, SENDERS_ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let asking = Asking::for_scope(world.app_keys(&alice, "reader")?, NOTES_READER)?;
    let (mut reader, _) = joined_as(world, &alice, &mut signer, asking, notes_protocol()).await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    let (mut stall, _) = joined(world, &carol, &mut carol_signer, "stall").await?;

    wallet.add_contact(&bob.public()).await?;
    world.advance_ms(STEP_MS);
    wallet.add_contact(&carol.public()).await?;
    world.advance_ms(STEP_MS);
    wallet.deny(&carol.public()).await?;
    world.outcome(
        "the wallet saved bob and carol as contacts and blocked carol",
        &json!({ "events": events(&wallet.take_events()) }),
    );
    world.advance_ms(STEP_MS);
    look(world, &mut reader, "the reader followed the lists").await?;

    lose_and_recover(world, &alice, &mut signer).await?;

    // The reader first: a deny list, and no contacts.
    follow_recovery(world, &mut reader, "reader", 1).await?;
    expect_upload(world, "reader", true)?;
    signer.run_due().await?;
    world.outcome(
        "alice's signer ran what is due, admission still staged",
        &json!({ "requests": world.requests_sent() }),
    );
    expect_staged(world, true)?;
    // The deny entry is in force at the new service from the reader's upload on, before
    // any contact is there: the lists the reader reads say so.
    expect_lists(
        world,
        "the lists after the reader's upload",
        &mut reader,
        &[],
        &[&carol],
    )
    .await?;

    // The senders' copies of alice's `identity.json` are ten minutes old by now, so each
    // reads it again and finds the new service (Switch spec 4.3).
    world.advance_ms(DOC_CACHE_MS);
    for (name, app, first_call) in [
        ("bob's shop", &mut shop, BOBS_FIRST_CALL),
        ("carol's stall", &mut stall, CAROLS_FIRST_CALL),
    ] {
        send(
            world,
            &format!("{name} wrote to alice while admission was staged"),
            app,
            Some(alice.public()),
        )
        .await?;
        expect_answer(world, first_call, 503, "staged")?;
    }

    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    expect_upload(world, "wallet", true)?;
    signer.run_due().await?;
    world.outcome(
        "alice's signer ran what is due, the admission ended by the wallet's upload",
        &json!({ "requests": world.requests_sent() }),
    );
    expect_staged(world, false)?;

    send(
        world,
        "bob's shop tried again once the wallet had uploaded",
        &mut shop,
        None,
    )
    .await?;
    let admitted = world.last_fact("{bob/shop} POST /v1/{alice}/inbox", "status");
    if admitted.as_deref() != Some("200") {
        return Err(format!("bob's note was answered {admitted:?}").into());
    }
    send(
        world,
        "carol's stall tried again once the wallet had uploaded",
        &mut stall,
        None,
    )
    .await?;
    // carol is a contact at the new service now, and refused all the same: the deny list
    // is what keeps her out.
    expect_answer(world, CAROLS_FIRST_CALL, 403, "not_admitted")?;
    expect_lists(
        world,
        "the lists at the end",
        &mut wallet,
        &[&bob, &carol],
        &[&carol],
    )
    .await?;
    Ok(())
}

/// `app` reads the lists from the switch (`GET /v1/{id}/allow`); the flow fails unless the
/// contacts are exactly `contacts` and the deny list exactly `deny`.
pub(super) async fn expect_lists(
    world: &World,
    name: &str,
    app: &mut App,
    contacts: &[&TestIdentity],
    deny: &[&TestIdentity],
) -> FlowResult {
    let list = app.allow_list().await?;
    world.outcome(
        name,
        &json!({ "contacts": list.contacts.len(), "deny": list.deny.len() }),
    );
    world.advance_ms(STEP_MS);
    let same = |held: &[[u8; 32]], expected: &[&TestIdentity]| {
        held.len() == expected.len()
            && expected
                .iter()
                .all(|identity| held.contains(&identity.public()))
    };
    if same(&list.contacts, contacts) && same(&list.deny, deny) {
        Ok(())
    } else {
        Err(format!(
            "{name}: {} contacts and {} denied, not the {} and {} expected",
            list.contacts.len(),
            list.deny.len(),
            contacts.len(),
            deny.len()
        )
        .into())
    }
}

/// carol's delivery of her `identity.json` to alice's switch, her first call when she
/// writes to her.
pub(super) const CAROLS_FIRST_CALL: &str = "{carol/stall} PUT /v1/{alice}/peers";

/// A client that sends requests as alice's app `name`, signed with the app's key, to the
/// service `origin` whose key for her account is `service_key`: for an upload no app of
/// the client crate would send.
fn client_of(
    world: &World,
    alice: &TestIdentity,
    name: &str,
    app: &App,
    origin: &str,
    service_key: [u8; 32],
) -> Result<SwitchClient, Box<dyn std::error::Error>> {
    let credentials = Credentials::App {
        identity: alice.public(),
        keys: world.app_keys(alice, name)?,
        cert: app.cert().clone(),
    };
    Ok(SwitchClient::new(
        origin,
        alice.public(),
        credentials,
        Some(service_key),
        world.transport(),
        world.clock().clone() as Arc<dyn Clock>,
    )?)
}

/// A body that doesn't read as an upload: `records` isn't an array. It also carries
/// contacts, which its sender may not send.
const UNREADABLE: &str = r#"{"records":1,"lists":{"contacts":[]}}"#;

/// An upload of contacts, none of them.
const CONTACTS: &str = r#"{"lists":{"contacts":[]}}"#;

/// An upload of nothing.
const NOTHING: &str = "{}";

/// `client` uploads `body`; the flow fails unless the switch answers `status`, with the
/// error `code` when it refuses.
async fn upload(
    world: &World,
    name: &str,
    client: &SwitchClient,
    app: &str,
    body: &str,
    status: u16,
    code: Option<&str>,
) -> FlowResult {
    let path = format!(
        "/v1/{}/recovery/upload",
        pubky_switch_core::enc::pubky_id(&client.account())
    );
    let signed = client.sign_request("POST", &path, body.as_bytes().to_vec(), None)?;
    let answered = client.send(signed).await;
    world.outcome(
        name,
        &json!({
            "status": answered.as_ref().ok().map(|answer| answer.status),
            "ended": ended(&answered),
        }),
    );
    world.advance_ms(STEP_MS);
    match code {
        Some(code) => expect_answer(world, &upload_of(app), status, code),
        None => {
            let was = world.last_fact(&upload_of(app), "status");
            if was == Some(status.to_string()) {
                Ok(())
            } else {
                Err(format!("{name}: answered {was:?}, not {status}").into())
            }
        }
    }
}

/// The uploads the new service takes from one app in an hour, in [`recovery_upload_refused`].
const UPLOADS_AN_HOUR: u32 = 3;

/// An hour, the window of the upload limit.
const HOUR_MS: u64 = 3_600_000;

/// The refusals of an upload, in their order, and the hourly limit (Switch wire 7.4.14,
/// 9.4). alice's reader holds `lists.read` alone. Its client sends uploads its app never
/// would:
///
/// - at the service alice is enrolled at, before any loss: `404`, for a body that doesn't
///   read too, since the account is in neither stage;
/// - at the service she recovered at, once the reader has registered there and uploaded
///   what it holds, a body that doesn't read and carries contacts: `400`, before the
///   permission is looked at; contacts, which need `lists.manage`: `403
///   permission_missing`;
/// - the service takes three uploads an hour from one app, and each of those two took a
///   slot, as the reader's own did: an upload of nothing, which the service would take, is
///   `429 rate_limited`. Past the limit the refusals keep their order: the body that
///   doesn't read is still `400`, the contacts still `403`;
/// - in the next hour the upload of nothing is taken.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or an upload is answered
/// other than its step says.
pub async fn recovery_upload_refused(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let asking = Asking::for_scope(world.app_keys(&alice, "reader")?, NOTES_READER)?;
    let (mut reader, _) = joined_as(world, &alice, &mut signer, asking, notes_protocol()).await?;

    let service_key = |signer: &Signer| -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let doc = signer
            .identity_doc()?
            .ok_or("the signer holds no document")?;
        Ok(doc.inbox().service_key)
    };
    let before = client_of(
        world,
        &alice,
        "reader",
        &reader,
        ORIGIN,
        service_key(&signer)?,
    )?;
    upload(
        world,
        "an upload that doesn't read, at an account that lost no provider",
        &before,
        "reader",
        UNREADABLE,
        404,
        Some("not_found"),
    )
    .await?;

    world.lose_switch(ORIGIN);
    let limits = Limits {
        uploads_per_app_per_hour: UPLOADS_AN_HOUR,
        ..Limits::default()
    };
    world
        .add_switch_with(RECOVERY_ORIGIN, &[&alice], limits)
        .await?;
    let doc = signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss and recovered elsewhere",
        &recovered(&doc, &signer)?,
    );
    // The start of an hour of the service's clock, so that every upload up to the limit
    // falls in one window.
    world.advance_ms(HOUR_MS - world.now_ms() % HOUR_MS);

    let after = client_of(
        world,
        &alice,
        "reader",
        &reader,
        RECOVERY_ORIGIN,
        service_key(&signer)?,
    )?;
    // The reader registers, and uploads what it holds: the lost service's newest head.
    let sent = uploads(world);
    follow_recovery(world, &mut reader, "reader", 1).await?;
    let own = uploads(world) - sent;
    if own != 1 {
        return Err(format!("the reader's follow sent {own} uploads, not 1").into());
    }

    let refusals: [(&str, &str, u16, &str); 5] = [
        (
            "an upload that doesn't read, with contacts",
            UNREADABLE,
            400,
            "bad_request",
        ),
        (
            "contacts from an app without lists.manage",
            CONTACTS,
            403,
            "permission_missing",
        ),
        (
            "an upload of nothing, the hour's uploads used up",
            NOTHING,
            429,
            "rate_limited",
        ),
        (
            "an upload that doesn't read, past the limit",
            UNREADABLE,
            400,
            "bad_request",
        ),
        (
            "contacts, past the limit",
            CONTACTS,
            403,
            "permission_missing",
        ),
    ];
    for (name, body, status, code) in refusals {
        upload(world, name, &after, "reader", body, status, Some(code)).await?;
    }

    world.advance_ms(HOUR_MS);
    upload(
        world,
        "an upload of nothing, in the next hour",
        &after,
        "reader",
        NOTHING,
        200,
        None,
    )
    .await?;
    Ok(())
}

/// Uploads from before a loss count against the hour of the uploads after it (Switch wire
/// 7.4.14, 9.4). alice's service takes three uploads an hour from one app. Her reader's
/// client sends three uploads while the account has lost no provider: each is `404`, and
/// each takes a slot, since the service takes it once the request verifies, before it
/// looks at the stage. In the same hour her signer recovers in place. The reader follows
/// the recovery: it registers again, and its own upload is `429 rate_limited`, which the
/// app takes as a refusal the service may lift. In the next hour it follows again, and
/// the upload is taken.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or an upload is answered
/// other than its step says.
pub async fn recovery_upload_slots_before_the_loss(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let limits = Limits {
        uploads_per_app_per_hour: UPLOADS_AN_HOUR,
        ..Limits::default()
    };
    world.add_switch_with(ORIGIN, &[&alice], limits).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let asking = Asking::for_scope(world.app_keys(&alice, "reader")?, NOTES_READER)?;
    let (mut reader, _) = joined_as(world, &alice, &mut signer, asking, notes_protocol()).await?;

    // The start of an hour of the service's clock: the uploads before the loss and the
    // one after it fall in one window.
    world.advance_ms(HOUR_MS - world.now_ms() % HOUR_MS);
    let doc = signer
        .identity_doc()?
        .ok_or("the signer holds no document")?;
    let before = client_of(
        world,
        &alice,
        "reader",
        &reader,
        ORIGIN,
        doc.inbox().service_key,
    )?;
    for nth in ["first", "second", "third"] {
        upload(
            world,
            &format!("the {nth} upload at an account that lost no provider"),
            &before,
            "reader",
            NOTHING,
            404,
            Some("not_found"),
        )
        .await?;
    }

    let doc = signer
        .declare_provider_loss(ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss and recovered in place",
        &recovered(&doc, &signer)?,
    );
    world.advance_ms(STEP_MS);

    for (name, status, taken) in [
        ("in the hour of the uploads before the loss", "429", false),
        ("in the next hour", "200", true),
    ] {
        let refreshed = reader.refresh_identity().await;
        let followed = reader.follow_provider().await;
        world.outcome(
            &format!("the reader followed the recovery {name}"),
            &json!({
                "refreshed": ended(&refreshed),
                "ended": ended(&followed),
                "events": events(&reader.take_events()),
            }),
        );
        let answered = world.last_fact(&upload_of("reader"), "status");
        let code = world.last_fact(&upload_of("reader"), "body.code");
        let limited = code.as_deref() == Some("text rate_limited");
        if answered.as_deref() != Some(status) || followed.is_ok() != taken || limited == taken {
            return Err(format!(
                "{name}, the reader's upload was answered {answered:?} {code:?} and its \
                 follow ended {}",
                ended(&followed)
            )
            .into());
        }
        world.advance_ms(HOUR_MS);
    }
    Ok(())
}

/// How many uploads the run has sent so far.
fn uploads(world: &World) -> usize {
    let trace = world.trace();
    trace
        .lines
        .iter()
        .filter(|line| line.label.ends_with("/recovery/upload"))
        .count()
}
