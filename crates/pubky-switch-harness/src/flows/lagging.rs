//! An inbox under pressure and an app that left (Switch spec 6.3, 8.2, Switch wire 7.4.4,
//! 7.5): an app marked lagging, the `missed` item that tells it what went unread, and the
//! `unreadable` item an entry becomes when its only reader is revoked.

use pubky_switch::limits::Limits;
use pubky_switch_client::app::{App, OutgoingMessage};
use pubky_switch_client::testing::TestProtocol;
use pubky_switch_signer::{Signer, UserConfirmed};
use serde_json::json;

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::{joined, joined_as};
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, NOTE_KIND, notes_protocol_with_records};
use crate::{FlowResult, World};

/// The inbox quota the lagging flows give the service: small enough that a handful of
/// notes passes an app's share of it, which is the quota divided among the current apps.
const SMALL_QUOTA_BYTES: u64 = 8 * 1024;

/// The service's limits for the lagging flows: a small inbox quota, and no share of it per
/// sender, so one sender's notes can fill an app's share.
fn small_inbox() -> Limits {
    Limits {
        quota_bytes: SMALL_QUOTA_BYTES,
        sender_share_percent: 100,
        ..Limits::default()
    }
}

/// `shop` sends alice note number `number`, and the flow notes how the send ended.
async fn send_note(world: &World, shop: &mut App, to: [u8; 32], number: usize) -> FlowResult {
    let mut body = serde_json::Map::new();
    body.insert("text".into(), json!(format!("note {number}")));
    let sent = shop.send(OutgoingMessage::new(to, NOTE_KIND, body)).await;
    world.outcome(
        &format!("bob's shop sent note {number}"),
        &json!({
            "delivery": sent.as_ref().ok().map(|(_, delivery)| {
                format!("{delivery:?}").split(' ').next().map(str::to_owned)
            }),
            "ok": sent.is_ok(),
            "events": events(&shop.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

/// `app` follows its feed to the end and moves its cursor: the events it raises, the notes
/// its protocol took so far, and where it stands.
async fn look(world: &World, name: &str, app: &mut App, protocol: &TestProtocol) -> FlowResult {
    let report = app.receive(None).await?;
    app.flush_cursor().await?;
    world.outcome(
        name,
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "notes": protocol.received().len(),
            "app": app_status(app),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

/// The signer's routine run, which reads the account's apps: the trace's `GET
/// /v1/{id}/apps` line holds each app's `lagging`.
async fn signer_looks(world: &World, signer: &mut Signer, name: &str) -> FlowResult {
    signer.run_due().await?;
    world.outcome(name, &status(signer)?);
    world.advance_ms(STEP_MS);
    Ok(())
}

/// alice's wallet reads every note as it comes; her phone reads none. Once the phone's
/// unread notes pass its share of a small inbox quota, the service marks it lagging and
/// stops keeping notes for it: bob is never refused for a full inbox. The signer's routine
/// run sees the mark. When the phone reads at last, the mark ends.
///
/// The service runs with a small inbox quota here ([`World::add_switch_with`]). The
/// scripted switch marks no app lagging, so this flow isn't among [`super::FLOWS`]: its
/// test runs it against each switch and holds what each does.
///
/// Calls: `POST /v1/{id}/inbox` under pressure; `GET /v1/{id}/apps` with `lagging: true`
/// and `false` again; `GET /v1/{id}/feed` by a lagging app.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn lagging_app(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world
        .add_switch_with(ORIGIN, &[&alice, &bob], small_inbox())
        .await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let (mut wallet, wallet_notes) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut phone, phone_notes) = joined(world, &alice, &mut alice_signer, "phone").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    wallet.add_contact(&bob.public()).await?;
    look(
        world,
        "the wallet before the notes",
        &mut wallet,
        &wallet_notes,
    )
    .await?;
    look(
        world,
        "the phone before the notes",
        &mut phone,
        &phone_notes,
    )
    .await?;

    for number in 1..=6 {
        send_note(world, &mut shop, alice.public(), number).await?;
        look(
            world,
            &format!("the wallet reads note {number}"),
            &mut wallet,
            &wallet_notes,
        )
        .await?;
    }
    signer_looks(world, &mut alice_signer, "alice's signer looks at her apps").await?;

    look(world, "the phone reads at last", &mut phone, &phone_notes).await?;
    signer_looks(
        world,
        &mut alice_signer,
        "alice's signer looks again, after the phone read",
    )
    .await?;
    look(world, "the phone reads once more", &mut phone, &phone_notes).await?;
    Ok(())
}

/// As [`lagging_app`], with apps that keep shared records: the phone, lagging, finds a
/// `missed` item in its feed for the notes that went unread, then more notes go the same
/// way before it reads. Its one read finds one item covering both rounds; it lists its
/// collections again, as an app does that may have missed a forgotten key.
///
/// Not among [`super::FLOWS`], as [`lagging_app`] isn't.
///
/// Calls: `GET /v1/{id}/feed` with a `missed` item; `GET /v1/{id}/records` again after it.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn missed_item(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world
        .add_switch_with(ORIGIN, &[&alice, &bob], small_inbox())
        .await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let with_records = |name: &str| -> Result<Asking, crate::HarnessError> {
        Asking::new(world.app_keys(&alice, name)?)
    };
    let (mut wallet, wallet_notes) = joined_as(
        world,
        &alice,
        &mut alice_signer,
        with_records("wallet")?,
        notes_protocol_with_records(),
    )
    .await?;
    let (mut phone, phone_notes) = joined_as(
        world,
        &alice,
        &mut alice_signer,
        with_records("phone")?,
        notes_protocol_with_records(),
    )
    .await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    wallet.add_contact(&bob.public()).await?;
    look(
        world,
        "the wallet before the notes",
        &mut wallet,
        &wallet_notes,
    )
    .await?;
    look(
        world,
        "the phone before the notes",
        &mut phone,
        &phone_notes,
    )
    .await?;

    // Two rounds of notes the phone doesn't read, the signer looking in between.
    let mut number = 0;
    for round in ["the first round", "the second round"] {
        for _ in 0..4 {
            number += 1;
            send_note(world, &mut shop, alice.public(), number).await?;
            look(
                world,
                &format!("the wallet reads note {number}"),
                &mut wallet,
                &wallet_notes,
            )
            .await?;
        }
        signer_looks(
            world,
            &mut alice_signer,
            &format!("alice's signer looks at her apps after {round}"),
        )
        .await?;
    }

    look(world, "the phone reads at last", &mut phone, &phone_notes).await?;
    look(world, "the phone reads once more", &mut phone, &phone_notes).await?;
    Ok(())
}

/// bob's note reaches alice while her phone is her only app. She adds a wallet; then the
/// signer revokes the phone, which never read the note. No current app can open it any
/// more: it becomes an `unreadable` item, which the wallet finds in its feed.
///
/// The scripted switch writes no `unreadable` item, and an item of the service takes a
/// `seq`, so every later `seq` of the two runs differs: this flow isn't among
/// [`super::FLOWS`] either, and its test holds what each switch does.
///
/// Calls: `POST /v1/{id}/apps/{app_id}/revoke` with an entry left without a reader; `GET
/// /v1/{id}/apps` with an app's unread entries; `GET /v1/{id}/feed` with an `unreadable`
/// item.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn unreadable_after_revoke(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let (mut phone, phone_notes) = joined(world, &alice, &mut alice_signer, "phone").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    phone.add_contact(&bob.public()).await?;
    look(world, "the phone before the note", &mut phone, &phone_notes).await?;

    // The note's only target is the phone.
    send_note(world, &mut shop, alice.public(), 1).await?;
    let (mut wallet, wallet_notes) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    look(
        world,
        "the wallet, joined after the note",
        &mut wallet,
        &wallet_notes,
    )
    .await?;

    let removing = alice_signer
        .revoke(phone.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer revoked the phone, which hadn't read the note",
        &json!({
            "version": removing.version(),
            "removed": removing.body().removed.len(),
            "signer": status(&alice_signer)?,
        }),
    );
    world.advance_ms(STEP_MS);

    look(
        world,
        "the wallet after the revocation",
        &mut wallet,
        &wallet_notes,
    )
    .await?;
    wallet.fetch_key_bundle().await?;
    world.outcome("the wallet fetched its keys", &app_status(&mut wallet));
    world.advance_ms(STEP_MS);
    look(
        world,
        "the wallet reads once more",
        &mut wallet,
        &wallet_notes,
    )
    .await?;
    signer_looks(world, &mut alice_signer, "alice's signer ran what is due").await?;
    Ok(())
}
