//! Connect requests (Switch spec 7, Switch wire 7.4.7): a stranger asks to be invited, and
//! the user's app allows or declines.

use pubky_switch_client::app::{App, AppError};
use pubky_switch_client::client::answers::ConnectList;
use pubky_switch_core::records::ConnectRequests;
use serde_json::{Value, json};

use super::admission::{lists, note, send};
use super::enrollment::{enroll, status};
use super::messaging::joined;
use super::recovery::expect_answer;
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// The policy that takes connect requests, at most `max_pending` of them pending.
fn taking(max_pending: u64) -> ConnectRequests {
    ConnectRequests {
        enabled: true,
        max_pending,
        push: false,
    }
}

/// How a request to connect ended, for the trace: whether it is pending, or the error's
/// kind and its code at the switch.
fn asked(result: &Result<bool, AppError>) -> Value {
    match result {
        Ok(pending) => json!({ "ok": true, "pending": pending }),
        Err(error) => json!({
            "ok": false,
            "code": error.code().map(|code| code.as_str().to_owned()),
        }),
    }
}

/// The app `asker` of `name` asks `to`'s switch to be invited, and the flow notes how that
/// ended.
async fn ask(
    world: &World,
    name: &str,
    asker: &mut App,
    to: [u8; 32],
) -> Result<Result<bool, AppError>, Box<dyn std::error::Error>> {
    let result = asker.ask_to_connect(&to).await;
    world.outcome(name, &json!({ "asked": asked(&result) }));
    world.advance_ms(STEP_MS);
    Ok(result)
}

/// The connect requests alice's app reads (`GET /v1/{id}/connect`), noted by their number,
/// the cap and whether the list is full. Fails the flow unless the senders are exactly
/// `from`, oldest first, with the list full or not as `full` says.
async fn pending(
    world: &World,
    name: &str,
    app: &mut App,
    from: &[[u8; 32]],
    full: bool,
) -> Result<ConnectList, Box<dyn std::error::Error>> {
    let list = app.connect_requests().await?;
    world.outcome(
        name,
        &json!({
            "requests": list.requests.len(),
            "max_pending": list.max_pending,
            "full": list.full,
        }),
    );
    world.advance_ms(STEP_MS);
    let senders: Vec<[u8; 32]> = list.requests.iter().map(|request| request.pubky).collect();
    let in_order = list
        .requests
        .windows(2)
        .all(|pair| pair[0].at <= pair[1].at);
    if senders != from || list.full != full || !in_order {
        return Err(format!(
            "{name}: {} requests are pending, full: {}, where {} were expected, full: {full}",
            senders.len(),
            list.full,
            from.len()
        )
        .into());
    }
    Ok(list)
}

/// A connect request, allowed and declined (Switch spec 7, Switch wire 7.4.7). alice's
/// policy takes no connect requests, and bob's shop, a stranger, is refused. Her signer
/// turns them on. bob asks: alice's switch holds no copy of his `identity.json`, so the
/// shop delivers it and asks again, and the request is pending. Asked a second time, the
/// switch answers the same and keeps nothing more. carol's stall asks too. alice's wallet
/// reads the two requests, oldest first, allows bob's with an invite, which removes it, and
/// declines carol's. bob's note is then taken and carol's refused, and a second decline
/// finds nothing.
///
/// Calls: `POST /v1/{id}/connect` refused by the policy (`403 not_admitted`), refused for
/// the sender's document (`409 identity_needed`), kept, and answered for a sender already
/// pending; `GET /v1/{id}/connect`; `DELETE /v1/{id}/connect/{pubky}`, taken and `404`; an
/// invite that answers a request.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, a request is answered or
/// kept against what its step says, or a note is admitted or refused against it.
pub async fn connect_request(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    let carol = world.identity("carol")?;
    world.add_switch(ORIGIN, &[&alice, &bob, &carol]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let mut carol_signer = enroll(world, &carol, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    let (mut stall, _) = joined(world, &carol, &mut carol_signer, "stall").await?;
    let connect = "{bob/shop} POST /v1/{alice}/connect";

    // Off by default.
    let refused = ask(
        world,
        "bob's shop asked while alice takes no requests",
        &mut shop,
        alice.public(),
    )
    .await?;
    expect_answer(world, connect, 403, "not_admitted")?;
    if refused.is_ok() {
        return Err("a request was taken with the policy off".into());
    }

    let doc = alice_signer.set_connect_requests(taking(50)).await?;
    world.outcome(
        "alice's signer turned connect requests on",
        &json!({
            "enabled": doc.body().policy.connect_requests.enabled,
            "signer": status(&alice_signer)?,
        }),
    );
    world.advance_ms(STEP_MS);

    // The first call is refused for bob's document; the shop delivers it and asks again.
    let sent = world.trace().lines.len();
    let first = ask(world, "bob's shop asked", &mut shop, alice.public()).await?;
    let answers: Vec<Option<String>> = world.trace().lines[sent..]
        .iter()
        .filter(|line| line.label == connect)
        .map(|line| line.facts.get("status").cloned())
        .collect();
    if first.as_ref().ok() != Some(&true)
        || answers != [Some("409".to_owned()), Some("200".to_owned())]
    {
        return Err(format!(
            "bob's request ended {} after the answers {answers:?}",
            asked(&first)
        )
        .into());
    }
    pending(
        world,
        "the wallet read one request",
        &mut wallet,
        &[bob.public()],
        false,
    )
    .await?;

    // Asked again, the same answer, and nothing more kept.
    let again = ask(world, "bob's shop asked again", &mut shop, alice.public()).await?;
    let third = ask(world, "carol's stall asked", &mut stall, alice.public()).await?;
    if again.as_ref().ok() != Some(&true) || third.as_ref().ok() != Some(&true) {
        return Err("a request that should be pending wasn't answered so".into());
    }
    pending(
        world,
        "the wallet read two requests, bob's first",
        &mut wallet,
        &[bob.public(), carol.public()],
        false,
    )
    .await?;

    // An invite answers bob's request; a decline answers carol's.
    wallet.allow_connect(&bob.public()).await?;
    world.outcome("the wallet allowed bob's request", &json!({}));
    world.advance_ms(STEP_MS);
    pending(
        world,
        "the wallet read carol's request alone",
        &mut wallet,
        &[carol.public()],
        false,
    )
    .await?;
    wallet.decline_connect(&carol.public()).await?;
    world.outcome("the wallet declined carol's request", &json!({}));
    world.advance_ms(STEP_MS);
    pending(world, "the wallet read no request", &mut wallet, &[], false).await?;
    lists(world, "the lists after both answers", &mut wallet).await?;

    send(
        world,
        "bob's shop sent a note",
        &mut shop,
        note(alice.public(), "hello", None),
        true,
    )
    .await?;
    send(
        world,
        "carol's stall sent a note",
        &mut stall,
        note(alice.public(), "me too", None),
        false,
    )
    .await?;

    // Nothing is pending from carol any more.
    let gone = wallet.decline_connect(&carol.public()).await;
    world.outcome(
        "the wallet declined carol's request again",
        &json!({ "ok": gone.is_ok() }),
    );
    expect_answer(
        world,
        "{alice/wallet} DELETE /v1/{alice}/connect/{carol}",
        404,
        "not_found",
    )?;
    Ok(())
}
