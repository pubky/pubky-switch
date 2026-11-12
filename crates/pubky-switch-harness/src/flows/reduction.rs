//! A renewal that takes a scope from an app (Switch spec 3.2, 3.5, Switch wire 3.8, 6.2
//! "Accepting a write", 7.4.9): what becomes of a record the app wrote under the scope it
//! lost, for the readers that held it and for one that joins afterwards.

use pubky_switch_client::app::{App, AppError, AppEvent, RecordTarget};
use pubky_switch_core::records::IDENTITY_PATH;
use pubky_switch_signer::CertChange;
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined_as;
use super::records::{look, shown};
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, NOTES, NOTES_LISTS, notes_collection, notes_protocol_with_records};
use crate::{FlowResult, World};

/// A day in milliseconds.
const DAY_MS: u64 = 24 * 3_600_000;

/// How a call ended, for the trace: the error's kind and its code at the switch, never its
/// text.
fn ended<T>(result: &Result<T, AppError>) -> Value {
    match result {
        Ok(_) => json!({ "ok": true }),
        Err(error) => {
            let shown = format!("{error:?}");
            let kinds: Vec<&str> = shown
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| word.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
                .take(3)
                .collect();
            json!({
                "ok": false,
                "error": kinds.join(" "),
                "code": error.code().map(|code| code.as_str().to_owned()),
            })
        }
    }
}

/// The events' names, and of a flagged write the rule that flagged it, which is what this
/// flow is about.
fn raised(raised: &[AppEvent]) -> Vec<String> {
    raised
        .iter()
        .zip(events(raised))
        .map(|(event, name)| match event {
            AppEvent::WriteFlagged { reason, .. } => format!("{name}: {reason}"),
            _ => name,
        })
        .collect()
}

/// What `app` holds of the record at `target` and what the switch gives it when it asks,
/// for the trace.
async fn record_at(world: &World, name: &str, app: &mut App, target: &RecordTarget) -> FlowResult {
    let key = app.record_key(target)?;
    let held = app.shared_record(&key).await?;
    world.outcome(
        &format!("what {name} holds of the record"),
        &shown(held.as_ref()),
    );
    let read = app.read_record(target).await;
    world.outcome(
        &format!("what {name} reads of the record"),
        &json!({
            "ended": ended(&read),
            "record": shown(read.as_ref().ok().and_then(Option::as_ref)),
            "events": raised(&app.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

/// alice's wallet holds two scopes, one of them the collection's write scope, and writes a
/// record; her phone reads it. A day later the signer renews the wallet's certificate
/// without that scope: the data keys rotate, and the wallet can write the collection no
/// more. The record stays the wallet's write, made while it held the scope (Switch wire
/// 7.4.9: a record view carries the certificate the write was checked against, and an
/// earlier certificate counts for a write dated before its end). The flow notes what each
/// reader makes of it: the phone, which held the record and has since seen the wallet's
/// new certificate, and a tablet that joins after the renewal.
///
/// Calls, beyond a renewal's and the records flow's: `PUT /v1/{id}/identity` with a
/// certificate that lost a scope, `GET /v1/{id}/records` and `GET /v1/{id}/records/{key}`
/// with a record whose writer's certificate was renewed since, and the wallet's `POST
/// /v1/{id}/ops` (`record.put`) once it lacks the write scope.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn renewal_drops_scope(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let both = Asking::for_scopes(world.app_keys(&alice, "wallet")?, &[NOTES, NOTES_LISTS])?;
    let (mut wallet, _) = joined_as(
        world,
        &alice,
        &mut signer,
        both,
        notes_protocol_with_records(),
    )
    .await?;
    let (mut phone, _) = joined_as(
        world,
        &alice,
        &mut signer,
        Asking::new(world.app_keys(&alice, "phone")?)?,
        notes_protocol_with_records(),
    )
    .await?;
    look(world, &mut wallet, "the wallet before the record").await?;
    look(world, &mut phone, "the phone before the record").await?;

    let target = RecordTarget::new(notes_collection(), b"shopping list");
    let written = wallet
        .put_record(&target, br#"{"items":["milk"]}"#, Vec::new())
        .await?;
    world.outcome("the wallet wrote the record", &shown(Some(&written)));
    world.advance_ms(STEP_MS);
    look(world, &mut phone, "the phone after the write").await?;
    record_at(world, "the phone, before the renewal,", &mut phone, &target).await?;

    // The renewal takes the collection's scope from the wallet.
    world.advance_ms(DAY_MS);
    let change = CertChange {
        scopes: Some(vec![NOTES_LISTS.to_owned()]),
        expires_at: None,
    };
    let renewing = signer.renew(wallet.app_id(), change).await?;
    let newest = signer.identity_doc()?;
    world.outcome(
        "the signer renewed the wallet without the scope",
        &json!({
            "renewing_version": renewing.version(),
            "renewed": renewing.body().renewed.len(),
            "data_epoch": newest.as_ref().map(|doc| doc.body().data_epoch),
            "signer": status(&signer)?,
        }),
    );
    world.advance_ms(STEP_MS);

    // The wallet learns of it, and tries to write the record again.
    let read = wallet.receive(None).await;
    world.outcome(
        "the wallet after the renewal",
        &json!({
            "ended": ended(&read),
            "events": events(&read.as_ref().map_or_else(|_| wallet.take_events(), |report| report.events.clone())),
            "scopes": wallet.cert().body().scopes.clone(),
            "app": app_status(&mut wallet),
        }),
    );
    world.advance_ms(STEP_MS);
    let again = wallet
        .put_record(&target, br#"{"items":["milk","bread"]}"#, Vec::new())
        .await;
    world.outcome(
        "the wallet tried to write the record without the scope",
        &json!({ "ended": ended(&again), "events": events(&wallet.take_events()) }),
    );
    world.advance_ms(STEP_MS);

    signer.run_due().await?;
    world.outcome("signer ran what is due", &status(&signer)?);
    world.advance_ms(STEP_MS);

    // The reader that held the record.
    look(world, &mut phone, "the phone after the renewal").await?;
    let fetched = phone.fetch_key_bundle().await;
    world.outcome(
        "the phone fetched its keys",
        &json!({ "ended": ended(&fetched), "app": app_status(&mut phone) }),
    );
    world.advance_ms(STEP_MS);
    record_at(world, "the phone, after the renewal,", &mut phone, &target).await?;

    // A reader that joins afterwards.
    let (mut tablet, _) = joined_as(
        world,
        &alice,
        &mut signer,
        Asking::new(world.app_keys(&alice, "tablet")?)?,
        notes_protocol_with_records(),
    )
    .await?;
    let listed = tablet.records_of(&notes_collection().name).await?;
    world.outcome(
        "the tablet joined after the renewal and listed the collection",
        &json!({ "listed": listed.len(), "app": app_status(&mut tablet) }),
    );
    record_at(world, "the tablet", &mut tablet, &target).await?;
    Ok(())
}

/// A reduction whose publication fails (Switch wire 3.8 "A closing delivery owed"). alice's
/// wallet holds two scopes. A day later her signer renews its certificate without the one
/// that has no keys, a reduction that rotates nothing; her Homeserver fails the write of
/// `identity.json` once. The switch takes the renewing version and then the closing one,
/// which gives the earlier certificate its end: a Homeserver that refuses writes doesn't
/// hold the closing back. Only publication waits, and the signer's next run publishes the
/// closing version.
///
/// The flow holds that both versions reach the switch and when each is published. The
/// scope dropped here gates no call at the switch, so no refusal follows from it; what a
/// switch refuses once a certificate has lost a scope it enforces is in
/// [`renewal_drops_scope`].
///
/// Calls: `PUT /v1/{id}/identity` with a renewing version and with the version that closes
/// the earlier certificate, neither published yet.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the closing version doesn't
/// reach the switch while the publication fails, or it isn't published by the next run.
pub async fn reduction_unpublished(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let both = Asking::for_scopes(world.app_keys(&alice, "wallet")?, &[NOTES, NOTES_LISTS])?;
    let (mut wallet, _) = joined_as(
        world,
        &alice,
        &mut signer,
        both,
        notes_protocol_with_records(),
    )
    .await?;
    look(world, &mut wallet, "the wallet before the renewal").await?;
    world.advance_ms(DAY_MS);

    let published = |world: &World| {
        world
            .files()
            .identity_doc(&alice.public())
            .map(|doc| doc.version())
    };
    let before = published(world);
    let deliveries = |world: &World| {
        let trace = world.trace();
        trace
            .lines
            .iter()
            .filter(|line| line.label == "{alice} PUT /v1/{alice}/identity")
            .filter(|line| line.facts.get("status").map(String::as_str) == Some("200"))
            .count()
    };
    let delivered = deliveries(world);
    world.fail_homeserver_write(&alice, IDENTITY_PATH);
    let change = CertChange {
        scopes: Some(vec![NOTES.to_owned()]),
        expires_at: None,
    };
    let renewing = signer.renew(wallet.app_id(), change).await;
    let newest = signer.identity_doc()?;
    let closes = |doc: &pubky_switch_core::records::IdentityDoc| {
        doc.body()
            .renewed
            .iter()
            .filter(|renewed| renewed.until.is_some())
            .count()
    };
    world.outcome(
        "the signer renewed the wallet without the scope, the publication failing",
        &json!({
            "ok": renewing.is_ok(),
            "versions_delivered": deliveries(world) - delivered,
            "newest_version": newest.as_ref().map(|doc| doc.version()),
            "closed": newest.as_ref().map(closes),
            "published_moved": published(world) != before,
            "signer": status(&signer)?,
        }),
    );
    // Both versions reached the switch, the closing one included; neither is published.
    if renewing.is_ok()
        || deliveries(world) - delivered != 2
        || newest.as_ref().map(closes) != Some(1)
        || published(world) != before
        || world.homeserver_faults_left() != 0
    {
        return Err(format!(
            "with the publication failing, the renewal ended ok: {}, {} versions were \
             delivered, the newest closes {:?} certificates, and the published version \
             went from {before:?} to {:?}",
            renewing.is_ok(),
            deliveries(world) - delivered,
            newest.as_ref().map(closes),
            published(world)
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    signer.resume().await?;
    let newest = signer.identity_doc()?.map(|doc| doc.version());
    world.outcome(
        "the signer's next run published the closing version",
        &json!({ "published_is_newest": published(world) == newest, "signer": status(&signer)? }),
    );
    if published(world) != newest {
        return Err("the closing version isn't published after the next run".into());
    }
    world.advance_ms(STEP_MS);

    let read = wallet.receive(None).await;
    world.outcome(
        "the wallet after the renewal",
        &json!({
            "ended": ended(&read),
            "scopes": wallet.cert().body().scopes.clone(),
            "app": app_status(&mut wallet),
        }),
    );
    Ok(())
}
