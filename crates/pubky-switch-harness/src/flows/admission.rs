//! The lists in use (Switch spec 7, Switch wire 6.2, 7.4.2, 7.4.6): an invite code that
//! admits a stranger once, and a deny list entry that refuses a contact.

use pubky_switch_client::app::{App, AppError, Delivery, OutgoingMessage};
use pubky_switch_client::testing::TestProtocol;
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::parties::NOTE_KIND;
use crate::{FlowResult, World};

/// An hour in milliseconds.
const HOUR_MS: u64 = 3_600_000;

/// A note for `to` with `text`, presenting `code` if one is given.
fn note(to: [u8; 32], text: &str, code: Option<&str>) -> OutgoingMessage {
    let mut body = serde_json::Map::new();
    body.insert("text".into(), json!(text));
    let mut message = OutgoingMessage::new(to, NOTE_KIND, body);
    message.invite_code = code.map(str::to_owned);
    message
}

/// How a send ended, for the trace: the delivery's state, or the error's kind and its code
/// at the switch, never its text.
fn sent<T>(result: &Result<(T, Delivery), AppError>) -> Value {
    let first_word = |shown: String| {
        shown
            .split(|c: char| !c.is_ascii_alphanumeric())
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    match result {
        Ok((_, delivery)) => json!({ "ok": true, "delivery": first_word(format!("{delivery:?}")) }),
        Err(error) => json!({
            "ok": false,
            "error": first_word(format!("{error:?}")),
            "code": error.code().map(|code| code.as_str().to_owned()),
        }),
    }
}

/// `sender` sends `message`, and the flow notes how that ended. Fails the flow when the
/// send was admitted or refused against what the step says.
async fn send(
    world: &World,
    name: &str,
    sender: &mut App,
    message: OutgoingMessage,
    admitted: bool,
) -> FlowResult {
    let result = sender.send(message).await;
    world.outcome(
        name,
        &json!({
            "sent": sent(&result),
            "events": events(&sender.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);
    let accepted = matches!(&result, Ok((_, Delivery::Accepted { .. })));
    if accepted == admitted {
        Ok(())
    } else if admitted {
        Err(format!("{name}: the message wasn't accepted").into())
    } else {
        Err(format!("{name}: the message was accepted").into())
    }
}

/// What an app with `lists.read` reads of the lists (`GET /v1/{id}/allow`), for the trace:
/// how many entries each list holds, who wrote each conversation entry and whether a code
/// made it, and each live code's uses. The answer's own facts hold the rest, such as an
/// entry's `context` and `last_used`.
async fn lists(world: &World, name: &str, app: &mut App) -> FlowResult {
    let list = app.allow_list().await?;
    world.outcome(
        name,
        &json!({
            "contacts": list.contacts.len(),
            "deny": list.deny.len(),
            "flagged": list.flagged.len(),
            "conversations": list.conversations.iter().map(|entry| json!({
                "written_by": format!("{:?}", entry.written_by).split('(').next(),
                "by_a_code": entry.code_hash.is_some(),
            })).collect::<Vec<_>>(),
            "invite_codes": list.invite_codes.iter().map(|code| json!({
                "max_uses": code.max_uses,
                "uses": code.uses,
            })).collect::<Vec<_>>(),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

/// `app` follows its feed and moves its cursor: the events it raises at this read, the
/// messages its protocol took so far, and where it stands.
async fn look(world: &World, name: &str, app: &mut App, protocol: &TestProtocol) -> FlowResult {
    let report = app.receive(None).await?;
    app.flush_cursor().await?;
    world.outcome(
        name,
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "messages": protocol.received().len(),
            "app": app_status(app),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}

/// alice's wallet registers an invite code for one use. bob, a stranger to alice, sends
/// her a note with the code: it admits him and is used up, and the switch writes a
/// conversation entry for him, so his next note needs no code. carol presents the same
/// code and is refused. A second code runs out by time before anyone uses it.
///
/// Calls: `POST /v1/{id}/ops` (`invite_code.put`), `GET /v1/{id}/directory`, `PUT
/// /v1/{id}/peers` and `POST /v1/{id}/inbox` with `Switch-Invite-Code`, admitted and
/// refused (`403 not_admitted`); `GET /v1/{id}/feed` with the entry the switch wrote; `GET
/// /v1/{id}/allow` with a code's uses and a conversation entry a code made.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or a send is admitted or
/// refused against what its step says.
pub async fn invite_code(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    let carol = world.identity("carol")?;
    world.add_switch(ORIGIN, &[&alice, &bob, &carol]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let mut carol_signer = enroll(world, &carol, ORIGIN).await?;
    let (mut wallet, wallet_protocol) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    let (mut stall, _) = joined(world, &carol, &mut carol_signer, "stall").await?;

    // One use, good for an hour.
    let code = wallet
        .register_invite_code(world.now_ms() + HOUR_MS, 1, json!({ "order": "A-17" }))
        .await?;
    world.outcome(
        "the wallet registered a code for one use",
        &json!({
            "held": wallet.invite_codes().await?.len(),
            "max_uses": code.max_uses,
            "events": events(&wallet.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);
    lists(world, "the lists with the code registered", &mut wallet).await?;

    // bob uses it.
    send(
        world,
        "bob's shop sent a note with the code",
        &mut shop,
        note(alice.public(), "hello", Some(&code.code)),
        true,
    )
    .await?;
    look(
        world,
        "the wallet reads bob's note and the entry the switch wrote",
        &mut wallet,
        &wallet_protocol,
    )
    .await?;
    lists(world, "the lists with the code used up", &mut wallet).await?;

    // From then on bob needs no code.
    send(
        world,
        "bob's shop sent a second note, without a code",
        &mut shop,
        note(alice.public(), "hello again", None),
        true,
    )
    .await?;

    // carol comes too late.
    send(
        world,
        "carol's stall sent a note with the used-up code",
        &mut stall,
        note(alice.public(), "me too", Some(&code.code)),
        false,
    )
    .await?;

    // A code nobody uses in time.
    let late = wallet
        .register_invite_code(world.now_ms() + HOUR_MS, 1, json!({ "order": "A-18" }))
        .await?;
    world.outcome(
        "the wallet registered a second code",
        &json!({ "held": wallet.invite_codes().await?.len() }),
    );
    world.advance_ms(HOUR_MS + STEP_MS);
    send(
        world,
        "carol's stall sent a note with the second code, an hour late",
        &mut stall,
        note(alice.public(), "still me", Some(&late.code)),
        false,
    )
    .await?;

    look(
        world,
        "the wallet reads bob's second note, and nothing of carol",
        &mut wallet,
        &wallet_protocol,
    )
    .await?;
    lists(world, "the lists at the end", &mut wallet).await?;
    alice_signer.run_due().await?;
    world.outcome("alice's signer ran what is due", &status(&alice_signer)?);
    Ok(())
}

/// bob is alice's contact, and his note arrives. alice's wallet blocks him: his next note
/// is refused, as a stranger's would be, though he is still a contact, and stays in his
/// shop's outbox. The wallet unblocks him: the queued note goes through at its next try,
/// and so does a new one.
///
/// Calls: `POST /v1/{id}/ops` (`allow.put`, `deny.put`, `deny.delete`); `GET
/// /v1/{id}/directory`, `PUT /v1/{id}/peers` and `POST /v1/{id}/inbox` from a denied
/// sender (`403 not_admitted`) and from the same sender before and after; `GET
/// /v1/{id}/feed` with the list operations; `GET /v1/{id}/allow` with a deny list entry.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or a send is admitted or
/// refused against what its step says.
pub async fn deny_list(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let (mut wallet, wallet_protocol) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut shop, shop_protocol) = joined(world, &bob, &mut bob_signer, "shop").await?;

    wallet.add_contact(&bob.public()).await?;
    world.outcome(
        "the wallet saved bob as a contact",
        &app_status(&mut wallet),
    );
    world.advance_ms(STEP_MS);
    send(
        world,
        "bob's shop sent a note, as a contact",
        &mut shop,
        note(alice.public(), "hello", None),
        true,
    )
    .await?;
    look(
        world,
        "the wallet reads bob's note",
        &mut wallet,
        &wallet_protocol,
    )
    .await?;

    wallet.deny(&bob.public()).await?;
    world.outcome("the wallet blocked bob", &app_status(&mut wallet));
    world.advance_ms(STEP_MS);
    lists(world, "the lists with bob blocked", &mut wallet).await?;
    send(
        world,
        "bob's shop sent a note while blocked",
        &mut shop,
        note(alice.public(), "are you there", None),
        false,
    )
    .await?;
    look(
        world,
        "the wallet reads nothing of the blocked note",
        &mut wallet,
        &wallet_protocol,
    )
    .await?;
    look(
        world,
        "bob's shop reads its own feed",
        &mut shop,
        &shop_protocol,
    )
    .await?;

    wallet.undeny(&bob.public()).await?;
    world.outcome("the wallet unblocked bob", &app_status(&mut wallet));
    world.advance_ms(STEP_MS);
    // The refused note stayed in the shop's outbox: its next try goes through.
    let flushed = shop.flush_outbox().await?;
    world.outcome(
        "bob's shop tried its queued note again",
        &json!({
            "done": flushed.done.len(),
            "queued": flushed.queued.len(),
            "failed": flushed.failed.len(),
            "undelivered": flushed.undelivered.len(),
            "events": events(&shop.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);
    send(
        world,
        "bob's shop sent a note once unblocked",
        &mut shop,
        note(alice.public(), "hello once more", None),
        true,
    )
    .await?;
    look(
        world,
        "the wallet reads bob's notes again",
        &mut wallet,
        &wallet_protocol,
    )
    .await?;
    lists(world, "the lists at the end", &mut wallet).await?;
    alice_signer.run_due().await?;
    world.outcome("alice's signer ran what is due", &status(&alice_signer)?);
    Ok(())
}
