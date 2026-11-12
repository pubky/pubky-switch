//! Connect requests (Switch spec 7, Switch wire 7.4.7): a stranger asks to be invited, and
//! the user's app allows or declines.

use pubky_switch_client::app::{App, AppError, DOC_CACHE_MS};
use pubky_switch_client::client::answers::ConnectList;
use pubky_switch_client::error::ClientError;
use pubky_switch_core::records::ConnectRequests;
use pubky_switch_signer::UserConfirmed;
use serde_json::{Value, json};

use super::admission::{lists, note, send};
use super::enrollment::{enroll, status};
use super::messaging::joined;
use super::recovery::{
    RECOVERY_ORIGIN, SENDERS_ORIGIN, ended, expect_answer, expect_staged, expect_upload,
    follow_recovery, recovered,
};
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

/// Fail the flow unless `asker`'s request to connect to alice, which ended `result`, was
/// refused `429 quota_exceeded` for the limit on pending connect requests (Switch wire
/// 7.4.7 step 8).
fn expect_full(world: &World, asker: &str, result: &Result<bool, AppError>) -> FlowResult {
    let connect = format!("{{{asker}}} POST /v1/{{alice}}/connect");
    expect_answer(world, &connect, 429, "quota_exceeded")?;
    let limit = match result.as_ref().map_err(AppError::unkept) {
        Err(AppError::Switch(ClientError::Switch { current, .. })) => {
            current.get("limit").and_then(Value::as_str)
        }
        _ => None,
    };
    if limit == Some("connect_requests") {
        Ok(())
    } else {
        Err(format!("{asker}'s request was refused for the limit {limit:?}").into())
    }
}

/// A full list, and a denied sender (Switch wire 7.4.7 steps 7 to 9). alice takes one
/// pending request at most, and has carol on her deny list. carol asks: she is answered as
/// pending, and nothing is kept, so the answer doesn't tell her she is denied. bob asks and
/// his request is kept, which fills the list. Now carol and dave are both refused for the
/// full list, the denied sender like the stranger; bob, already pending, is still answered
/// as pending. alice's wallet declines bob's request, and dave's is kept. She then puts
/// dave on the deny list, which removes his request, and his next one is answered as
/// pending and not kept.
///
/// Calls: `POST /v1/{id}/connect` from a denied sender, with room and with the list full
/// (`429 quota_exceeded`, `current.limit` `connect_requests`), and from a sender already
/// pending while the list is full; `GET /v1/{id}/connect` with `full`; a `deny.put` that
/// answers a request.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or a request is answered or
/// kept against what its step says.
pub async fn connect_request_full(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    let carol = world.identity("carol")?;
    let dave = world.identity("dave")?;
    world
        .add_switch(ORIGIN, &[&alice, &bob, &carol, &dave])
        .await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let mut carol_signer = enroll(world, &carol, ORIGIN).await?;
    let mut dave_signer = enroll(world, &dave, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    let (mut stall, _) = joined(world, &carol, &mut carol_signer, "stall").await?;
    let (mut kiosk, _) = joined(world, &dave, &mut dave_signer, "kiosk").await?;

    alice_signer.set_connect_requests(taking(1)).await?;
    wallet.deny(&carol.public()).await?;
    world.outcome(
        "alice takes one request at most, and denies carol",
        &json!({ "signer": status(&alice_signer)? }),
    );
    world.advance_ms(STEP_MS);

    // A denied sender is answered as pending, and nothing is kept.
    let denied = ask(world, "carol's stall asked", &mut stall, alice.public()).await?;
    if denied.as_ref().ok() != Some(&true) {
        return Err(format!("the denied sender was answered {}", asked(&denied)).into());
    }
    pending(world, "the wallet read no request", &mut wallet, &[], false).await?;

    let kept = ask(world, "bob's shop asked", &mut shop, alice.public()).await?;
    if kept.as_ref().ok() != Some(&true) {
        return Err(format!("bob's request ended {}", asked(&kept)).into());
    }
    pending(
        world,
        "the wallet read bob's request, the list full",
        &mut wallet,
        &[bob.public()],
        true,
    )
    .await?;

    // Full: the denied sender and the stranger get the same refusal, and the sender
    // already pending the same answer as before.
    let denied = ask(
        world,
        "carol's stall asked with the list full",
        &mut stall,
        alice.public(),
    )
    .await?;
    expect_full(world, "carol/stall", &denied)?;
    let stranger = ask(
        world,
        "dave's kiosk asked with the list full",
        &mut kiosk,
        alice.public(),
    )
    .await?;
    expect_full(world, "dave/kiosk", &stranger)?;
    let again = ask(
        world,
        "bob's shop asked again with the list full",
        &mut shop,
        alice.public(),
    )
    .await?;
    if denied.is_ok() || stranger.is_ok() || again.as_ref().ok() != Some(&true) {
        return Err(format!(
            "with the list full carol was answered {}, dave {} and bob {}",
            asked(&denied),
            asked(&stranger),
            asked(&again)
        )
        .into());
    }

    // A decline makes room.
    wallet.decline_connect(&bob.public()).await?;
    world.outcome("the wallet declined bob's request", &json!({}));
    world.advance_ms(STEP_MS);
    let kept = ask(
        world,
        "dave's kiosk asked again",
        &mut kiosk,
        alice.public(),
    )
    .await?;
    if kept.as_ref().ok() != Some(&true) {
        return Err(format!("dave's request ended {}", asked(&kept)).into());
    }
    pending(
        world,
        "the wallet read dave's request",
        &mut wallet,
        &[dave.public()],
        true,
    )
    .await?;

    // A deny list entry answers a request, and the next one from him isn't kept.
    wallet.deny(&dave.public()).await?;
    world.outcome("the wallet denied dave", &json!({}));
    world.advance_ms(STEP_MS);
    pending(
        world,
        "the wallet read no request after the denial",
        &mut wallet,
        &[],
        false,
    )
    .await?;
    let unkept = ask(
        world,
        "dave's kiosk asked once denied",
        &mut kiosk,
        alice.public(),
    )
    .await?;
    if unkept.as_ref().ok() != Some(&true) {
        return Err(format!("dave, denied, was answered {}", asked(&unkept)).into());
    }
    pending(
        world,
        "the wallet read no request at the end",
        &mut wallet,
        &[],
        false,
    )
    .await?;
    lists(world, "the lists at the end", &mut wallet).await?;
    Ok(())
}

/// Connect requests turned off with one pending (Switch wire 7.4.7 "Answering"). alice
/// takes connect requests and bob's is pending. Her signer turns them off: carol is
/// refused, and bob's request stays, still read by alice's wallet. The wallet makes bob a
/// contact, which answers his request. Turned on again, the policy shows no request, and
/// carol's is kept.
///
/// Calls: `POST /v1/{id}/connect` refused by a policy turned off with a request pending
/// (`403 not_admitted`); `GET /v1/{id}/connect` while it is off; a contact entry that
/// answers a request.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or a request is answered or
/// kept against what its step says.
pub async fn connect_request_turned_off(world: &World) -> FlowResult {
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

    alice_signer.set_connect_requests(taking(50)).await?;
    world.advance_ms(STEP_MS);
    let kept = ask(world, "bob's shop asked", &mut shop, alice.public()).await?;
    if kept.as_ref().ok() != Some(&true) {
        return Err(format!("bob's request ended {}", asked(&kept)).into());
    }

    let off = alice_signer
        .set_connect_requests(ConnectRequests::default())
        .await?;
    world.outcome(
        "alice's signer turned connect requests off",
        &json!({
            "enabled": off.body().policy.connect_requests.enabled,
            "signer": status(&alice_signer)?,
        }),
    );
    world.advance_ms(STEP_MS);
    let refused = ask(
        world,
        "carol's stall asked while they are off",
        &mut stall,
        alice.public(),
    )
    .await?;
    expect_answer(
        world,
        "{carol/stall} POST /v1/{alice}/connect",
        403,
        "not_admitted",
    )?;
    if refused.is_ok() {
        return Err("a request was taken with the policy turned off".into());
    }
    pending(
        world,
        "the wallet still read bob's request",
        &mut wallet,
        &[bob.public()],
        false,
    )
    .await?;

    // A contact entry answers it, with the policy off.
    wallet.add_contact(&bob.public()).await?;
    world.outcome("the wallet made bob a contact", &json!({}));
    world.advance_ms(STEP_MS);
    pending(world, "the wallet read no request", &mut wallet, &[], false).await?;

    alice_signer.set_connect_requests(taking(50)).await?;
    world.advance_ms(STEP_MS);
    pending(
        world,
        "the wallet read no request once they are on again",
        &mut wallet,
        &[],
        false,
    )
    .await?;
    let kept = ask(
        world,
        "carol's stall asked again",
        &mut stall,
        alice.public(),
    )
    .await?;
    if kept.as_ref().ok() != Some(&true) {
        return Err(format!("carol's request ended {}", asked(&kept)).into());
    }
    pending(
        world,
        "the wallet read carol's request",
        &mut wallet,
        &[carol.public()],
        false,
    )
    .await?;
    Ok(())
}

/// Connect requests across a provider loss (Switch wire 7.4.7 step 3 and "Answering",
/// 7.4.14, Switch spec 12.6). alice takes connect requests; carol is a contact in her
/// wallet's lists, and bob's request is pending. Her service is lost and her signer
/// recovers at another. While the recovery stages admission bob is refused like every
/// sender. The signer ends the staged admission, and carol, whom the new service doesn't
/// know yet, asks: her request is kept. The wallet then follows the recovery and uploads
/// its lists. The merge writes carol's contact entry, which answers her request, and bob's
/// request of before the loss isn't there: the account started afresh. bob asks again and
/// his request is kept.
///
/// Calls: `POST /v1/{id}/connect` while admission is staged (`503 staged`); `POST
/// /v1/{id}/recovery/upload` whose list merge answers a pending request; `GET
/// /v1/{id}/connect` at the service recovered at.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, or a request is answered or
/// kept against what its step says.
pub async fn connect_request_recovered(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    let carol = world.identity("carol")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    world.add_switch(SENDERS_ORIGIN, &[&bob, &carol]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, SENDERS_ORIGIN).await?;
    let mut carol_signer = enroll(world, &carol, SENDERS_ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    let (mut stall, _) = joined(world, &carol, &mut carol_signer, "stall").await?;

    alice_signer.set_connect_requests(taking(50)).await?;
    world.advance_ms(STEP_MS);
    wallet.add_contact(&carol.public()).await?;
    world.advance_ms(STEP_MS);
    let kept = ask(world, "bob's shop asked", &mut shop, alice.public()).await?;
    if kept.as_ref().ok() != Some(&true) {
        return Err(format!("bob's request ended {}", asked(&kept)).into());
    }
    pending(
        world,
        "the wallet read bob's request",
        &mut wallet,
        &[bob.public()],
        false,
    )
    .await?;

    world.lose_switch(ORIGIN);
    world.add_switch(RECOVERY_ORIGIN, &[&alice]).await?;
    let doc = alice_signer
        .declare_provider_loss(RECOVERY_ORIGIN, UserConfirmed::shown_and_confirmed())
        .await?;
    world.outcome(
        "the signer declared the loss and recovered elsewhere",
        &recovered(&doc, &alice_signer)?,
    );
    // The senders use their copy of alice's `identity.json` for ten minutes (Switch spec
    // 4.3): until then they would ask the service that is gone.
    world.advance_ms(DOC_CACHE_MS);

    let staged = ask(
        world,
        "bob's shop asked while admission was staged",
        &mut shop,
        alice.public(),
    )
    .await?;
    expect_answer(world, "{bob/shop} POST /v1/{alice}/connect", 503, "staged")?;
    if staged.is_ok() {
        return Err("a request was taken while admission was staged".into());
    }

    let ending = alice_signer.end_staged_admission().await;
    world.outcome(
        "the signer ended the staged admission",
        &json!({ "ended": ended(&ending), "signer": status(&alice_signer)? }),
    );
    expect_staged(world, false)?;
    world.advance_ms(STEP_MS);

    // The new service's lists are empty: carol asks as a stranger.
    let kept = ask(world, "carol's stall asked", &mut stall, alice.public()).await?;
    if kept.as_ref().ok() != Some(&true) {
        return Err(format!("carol's request ended {}", asked(&kept)).into());
    }

    // The wallet's upload brings carol's contact entry, which answers her request. bob's
    // request stayed with the service that was lost.
    follow_recovery(world, &mut wallet, "wallet", 1).await?;
    expect_upload(world, "wallet", true)?;
    pending(
        world,
        "the wallet read no request at the new service",
        &mut wallet,
        &[],
        false,
    )
    .await?;

    let kept = ask(world, "bob's shop asked again", &mut shop, alice.public()).await?;
    if kept.as_ref().ok() != Some(&true) {
        return Err(format!("bob's second request ended {}", asked(&kept)).into());
    }
    pending(
        world,
        "the wallet read bob's request at the new service",
        &mut wallet,
        &[bob.public()],
        false,
    )
    .await?;
    lists(world, "the lists at the new service", &mut wallet).await?;
    Ok(())
}
