//! Retries: a call whose answer was lost, or that never reached the switch, made again
//! (Switch wire 6.4 step 5, 7.4.1, 7.4.2, 7.4.3). The faults are the transport's
//! ([`World::lose_answer`], [`World::unreachable`]), so each retry meets the switch as it
//! really is after the first try.

use std::sync::Arc;

use pubky_switch_client::app::{
    App, AppConfig, ClaimOp, LeaveMode, ObligationDeadline, OutgoingMessage,
};
use pubky_switch_client::store::MemoryStore;
use pubky_switch_signer::{CertChange, Signer, UserConfirmed};
use serde_json::{Value, json};

use super::enrollment::{enroll, status};
use super::join::{app_status, events};
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, NOTE_KIND, notes_protocol};
use crate::{FlowResult, World};

/// How a call ended, for the trace: nothing of an error but its kind, which names no key
/// and no time.
fn ended<T, E: std::fmt::Debug>(result: &Result<T, E>) -> Value {
    match result {
        Ok(_) => json!({ "ok": true }),
        Err(error) => {
            let shown = format!("{error:?}");
            // The variants' names, without what they carry.
            let kinds: Vec<&str> = shown
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| word.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
                .take(4)
                .collect();
            json!({ "ok": false, "error": kinds.join(" ") })
        }
    }
}

/// The signer's calls, each failed once and made again: the enrollment's answer is lost;
/// the first `identity.json` never reaches the switch; an approval's delivery is answered
/// and the answer lost; a renewal's batch is answered and the answer lost.
///
/// Calls: `POST /v1/enroll` twice with the same enrollment; `PUT /v1/{id}/identity` again
/// after a failed connection, and again with the same bytes after a lost answer; the
/// signer's `POST /v1/{id}/ops` again with the same batch.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn signer_retries(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let env = world.signer_env(&alice, Arc::new(MemoryStore::new()))?;
    let mut signer = Signer::create(env, world.keyring(&alice)?, ORIGIN).await?;

    world.lose_answer("POST", "/v1/enroll");
    let lost = signer.resume().await;
    world.outcome("the enrollment's answer was lost", &ended(&lost));
    world.advance_ms(STEP_MS);
    world.unreachable("PUT", "/identity");
    let unreached = signer.resume().await;
    world.outcome(
        "enrolled again, the first delivery didn't arrive",
        &ended(&unreached),
    );
    world.advance_ms(STEP_MS);
    signer.resume().await?;
    world.outcome("enrolled and delivered", &status(&signer)?);
    world.advance_ms(STEP_MS);

    // An approval whose delivery the switch took, and whose answer was lost.
    let asking = Asking::new(world.app_keys(&alice, "wallet")?)?;
    let review = signer.review(asking.request.signed(), &asking.auth)?;
    let request = review.request_hash();
    world.lose_answer("PUT", "/identity");
    let lost = signer.approve(review).await;
    world.outcome(
        "the approval's delivery was answered and the answer lost",
        &ended(&lost),
    );
    world.advance_ms(STEP_MS);
    signer.resume().await?;
    world.outcome("the approval's delivery sent again", &status(&signer)?);
    let approved = signer
        .approved(&request)?
        .ok_or("the approval isn't kept after its delivery")?;
    signer.claim_delivered(&request).await?;
    let mut wallet = App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        notes_protocol(),
        AppConfig::default(),
        asking.join_request(alice.public(), &approved)?,
    )
    .await?;
    wallet.receive(None).await?;
    world.outcome("joined", &app_status(&mut wallet));
    world.advance_ms(STEP_MS);

    // A renewal whose first batch the switch took, and whose answer was lost.
    world.lose_answer("POST", "/ops");
    let lost = signer.renew(wallet.app_id(), CertChange::default()).await;
    world.outcome(
        "the renewal's batch was answered and the answer lost",
        &ended(&lost),
    );
    world.advance_ms(STEP_MS);
    signer.resume().await?;
    world.outcome("the renewal finished", &status(&signer)?);
    let report = wallet.receive(None).await?;
    world.outcome(
        "the wallet after the renewal",
        &json!({ "events": events(&report.events), "app": app_status(&mut wallet) }),
    );
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}

/// An app's batches, each failed once: its registration when it joins, a contact it saves,
/// a cursor move alone, and a batch that never reaches the switch.
///
/// After a lost answer the app keeps the batch. The registration is sent again when the
/// app is loaded and reads. A later batch is not sent again by a read: the app finds its
/// own operation applied in its feed, and sends the kept batch again, as it was, before its
/// next write, where the switch answers with the original proofs (Switch wire 6.4 step 5).
///
/// Calls: `POST /v1/{id}/ops` again with the same batch after a lost answer (the
/// registration; an `allow.put` the feed already showed applied; a `cursor.set` alone), and
/// again after a failed connection.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn app_retries(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    let carol = world.identity("carol")?;
    let dave = world.identity("dave")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;

    // The registration's answer is lost: the join fails, and the app is loaded from its
    // store and sends the registration again at its next read.
    let asking = Asking::new(world.app_keys(&alice, "wallet")?)?;
    let review = signer.review(asking.request.signed(), &asking.auth)?;
    let approved = signer.approve(review).await?;
    signer.claim_delivered(&approved.request).await?;
    world.advance_ms(STEP_MS);
    let store = Arc::new(MemoryStore::new());
    world.lose_answer("POST", "/ops");
    let lost = App::join(
        world.app_env(store.clone()),
        notes_protocol(),
        AppConfig::default(),
        asking.join_request(alice.public(), &approved)?,
    )
    .await;
    world.outcome("the registration's answer was lost", &ended(&lost));
    drop(lost);
    world.advance_ms(STEP_MS);
    let mut wallet = App::load(
        world.app_env(store),
        notes_protocol(),
        AppConfig::default(),
        asking.keys.app_id_bytes(),
    )
    .await?;
    let report = wallet.receive(None).await?;
    world.outcome(
        "loaded, and the registration sent again",
        &json!({ "events": events(&report.events), "app": app_status(&mut wallet) }),
    );
    world.advance_ms(STEP_MS);

    // A contact whose batch the switch took, and whose answer was lost. The next read finds
    // the contact in the feed.
    world.lose_answer("POST", "/ops");
    let lost = wallet.add_contact(&bob.public()).await;
    world.outcome(
        "the contact's batch was answered and the answer lost",
        &json!({ "ended": ended(&lost), "admits": wallet.admits(&bob.public()).await? }),
    );
    world.advance_ms(STEP_MS);
    let report = wallet.receive(None).await?;
    world.outcome(
        "the wallet finds its contact in its feed",
        &json!({
            "events": events(&report.events),
            "admits": wallet.admits(&bob.public()).await?,
            "app": app_status(&mut wallet),
        }),
    );
    world.advance_ms(STEP_MS);

    // The next write first sends the kept batch again, as it was, and gets the original
    // proof; then its own.
    wallet.add_contact(&carol.public()).await?;
    world.outcome(
        "the next write, after the kept batch again",
        &json!({
            "admits": wallet.admits(&carol.public()).await?,
            "app": app_status(&mut wallet),
        }),
    );
    world.advance_ms(STEP_MS);

    // A cursor move alone, answered and the answer lost. The signer delivers a version the
    // wallet reads from its feed, which leaves the wallet's cursor to move.
    signer.set_record_max_age(Some(7 * 24 * 3_600)).await?;
    world.advance_ms(STEP_MS);
    let report = wallet.receive(None).await?;
    world.outcome(
        "the wallet read a new version",
        &json!({ "events": events(&report.events), "app": app_status(&mut wallet) }),
    );
    world.lose_answer("POST", "/ops");
    let lost = wallet.flush_cursor().await;
    world.outcome(
        "the cursor move was answered and the answer lost",
        &ended(&lost),
    );
    world.advance_ms(STEP_MS);
    let again = wallet.flush_cursor().await;
    world.outcome(
        "the cursor move sent again",
        &json!({ "ended": ended(&again), "app": app_status(&mut wallet) }),
    );
    world.advance_ms(STEP_MS);

    // A contact whose batch never reached the switch, saved again.
    world.unreachable("POST", "/ops");
    let unreached = wallet.add_contact(&dave.public()).await;
    world.outcome(
        "a contact's batch didn't arrive",
        &json!({ "ended": ended(&unreached), "admits": wallet.admits(&dave.public()).await? }),
    );
    world.advance_ms(STEP_MS);
    let again = wallet.add_contact(&dave.public()).await;
    world.outcome(
        "the contact saved again",
        &json!({
            "ended": ended(&again),
            "admits": wallet.admits(&dave.public()).await?,
            "app": app_status(&mut wallet),
        }),
    );
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}

/// A message whose append the recipient's switch took, and whose answer was lost: the
/// sender sends the same envelope again, and the recipient gets the message once.
///
/// Calls: `POST /v1/{id}/inbox` twice with the same envelope (the retry by content of
/// Switch wire 7.4.3), and the recipient's `GET /v1/{id}/feed`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn append_retry(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let (mut wallet, wallet_protocol) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;
    wallet.add_contact(&bob.public()).await?;
    world.advance_ms(STEP_MS);

    let mut body = serde_json::Map::new();
    body.insert("text".into(), json!("hello"));
    world.lose_answer("POST", "/inbox");
    let (msg_id, delivery) = shop
        .send(OutgoingMessage::new(alice.public(), NOTE_KIND, body))
        .await?;
    world.outcome(
        "the append was answered and the answer lost",
        &json!({
            "delivery": format!("{delivery:?}").split(' ').next(),
            "events": events(&shop.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);
    let flushed = shop.flush_outbox().await?;
    let delivery = shop.delivery(&msg_id).await?;
    world.outcome(
        "the append sent again",
        &json!({
            "done": flushed.done.len(),
            "delivery": delivery.map(|delivery| format!("{delivery:?}").split(' ').next().map(str::to_owned)),
            "events": events(&shop.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);

    let report = wallet.receive(None).await?;
    wallet.flush_cursor().await?;
    world.outcome(
        "the recipient reads its feed",
        &json!({
            "events": events(&report.events),
            "messages": wallet_protocol.received().len(),
            "app": app_status(&mut wallet),
        }),
    );
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}

/// A revocation and a departure whose answers were lost.
///
/// The signer doesn't send a revocation again: in the same call it reads the account's
/// apps, finds the app revoked, and goes on to the rotation and the removing version. The
/// app sends its leave again; the switch refuses it as no longer current, and the app takes
/// that as having left.
///
/// Calls: `POST /v1/{id}/apps/{app_id}/revoke` with its answer lost, then `GET
/// /v1/{id}/apps` showing the revocation; `POST /v1/{id}/apps/{app_id}/leave` with its
/// answer lost, then again by an app already departed (`403 not_current`).
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn removal_retries(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;
    let (phone, _) = joined(world, &alice, &mut signer, "phone").await?;
    let (mut tablet, _) = joined(world, &alice, &mut signer, "tablet").await?;

    // The revocation reaches the switch, and its answer is lost.
    world.lose_answer("POST", "/revoke");
    let lost = signer
        .revoke(phone.app_id(), None, UserConfirmed::shown_and_confirmed())
        .await;
    world.outcome(
        "the revocation's answer was lost, and the signer went on",
        &json!({ "ended": ended(&lost), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);
    let again = signer.run_due().await;
    world.outcome(
        "the signer's next run",
        &json!({ "ended": ended(&again), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);

    // The leave reaches the switch, and its answer is lost.
    world.lose_answer("POST", "/leave");
    let lost = tablet.leave(LeaveMode::TwoStep).await;
    world.outcome("the leave's answer was lost", &ended(&lost));
    world.advance_ms(STEP_MS);
    let again = tablet.leave(LeaveMode::TwoStep).await;
    world.outcome(
        "the app leaves again",
        &json!({
            "ended": ended(&again),
            "report": again.as_ref().ok().map(|report| format!("{report:?}")),
        }),
    );
    world.advance_ms(STEP_MS);
    let run = signer.run_due().await;
    world.outcome(
        "the signer's run after the departure",
        &json!({ "ended": ended(&run), "signer": status(&signer)? }),
    );
    world.advance_ms(STEP_MS);

    let report = wallet.receive(None).await?;
    wallet.fetch_key_bundle().await?;
    world.outcome(
        "the app that stays",
        &json!({ "events": events(&report.events), "app": app_status(&mut wallet) }),
    );
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}

/// A claim attempt whose answer was lost, and the caller attempting again; a peer delivery
/// whose answer was lost; a feed read whose answer was lost.
///
/// The caller's second attempt first sends the kept batch again, which gets the original
/// proof, and then its own, which the switch refuses with `409 conflict` and the claim in
/// `current`: the first attempt holds it.
///
/// Calls: `POST /v1/{id}/ops` (`claim`) again as it was; a second `attempt` at the step the
/// first one took (`409 conflict`); `PUT /v1/{id}/peers` again; `GET /v1/{id}/feed` again.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn claim_and_read_retries(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice, &bob]).await?;
    let mut alice_signer = enroll(world, &alice, ORIGIN).await?;
    let mut bob_signer = enroll(world, &bob, ORIGIN).await?;
    let (mut wallet, wallet_protocol) = joined(world, &alice, &mut alice_signer, "wallet").await?;
    let (mut shop, _) = joined(world, &bob, &mut bob_signer, "shop").await?;

    // An attempt the switch took, and whose answer was lost. The caller, who only saw the
    // failure, attempts again.
    let attempt = || ClaimOp::attempt(RETRIED_CLAIM, 0, [4; 16], 3_600, None);
    world.lose_answer("POST", "/ops");
    let lost = wallet
        .write_claim(attempt(), Vec::new(), ObligationDeadline::NotKnown)
        .await;
    world.outcome(
        "the attempt's answer was lost",
        &json!({ "ended": ended(&lost), "events": events(&wallet.take_events()) }),
    );
    world.advance_ms(STEP_MS);
    let again = wallet
        .write_claim(attempt(), Vec::new(), ObligationDeadline::NotKnown)
        .await;
    world.outcome(
        "the caller attempts again",
        &json!({
            "ended": ended(&again),
            "code": again.as_ref().err().and_then(pubky_switch_client::app::AppError::code).map(|code| code.as_str().to_owned()),
            "status": again.as_ref().ok().map(|written| format!("{:?}", written.view.status)),
            "events": events(&wallet.take_events()),
        }),
    );
    let read = wallet.read_claim(&RETRIED_CLAIM).await?;
    world.outcome(
        "the claim after both tries",
        &json!({
            "status": read.as_ref().map(|read| format!("{:?}", read.view.status)),
            "step": read.as_ref().map(|read| read.view.step),
            "attempts": read.as_ref().map(|read| read.view.attempts.len()),
            "entries": read.as_ref().map(|read| read.entries.len()),
            "events": events(&wallet.take_events()),
        }),
    );
    world.advance_ms(STEP_MS);

    // A message whose peer delivery was answered and the answer lost.
    wallet.add_contact(&bob.public()).await?;
    world.advance_ms(STEP_MS);
    let mut body = serde_json::Map::new();
    body.insert("text".into(), json!("hello"));
    world.lose_answer("PUT", "/peers");
    let (msg_id, delivery) = shop
        .send(OutgoingMessage::new(alice.public(), NOTE_KIND, body))
        .await?;
    world.outcome(
        "the peer delivery's answer was lost",
        &json!({ "delivery": format!("{delivery:?}").split(' ').next() }),
    );
    world.advance_ms(STEP_MS);
    let flushed = shop.flush_outbox().await?;
    let delivery = shop.delivery(&msg_id).await?;
    world.outcome(
        "the message sent again",
        &json!({
            "done": flushed.done.len(),
            "delivery": delivery.map(|delivery| format!("{delivery:?}").split(' ').next().map(str::to_owned)),
        }),
    );
    world.advance_ms(STEP_MS);

    // A feed read whose answer was lost.
    world.lose_answer("GET", "/feed");
    let lost = wallet.receive(None).await;
    world.outcome("the feed read's answer was lost", &ended(&lost));
    let report = wallet.receive(None).await?;
    wallet.flush_cursor().await?;
    world.outcome(
        "the feed read again",
        &json!({
            "events": events(&report.events),
            "messages": wallet_protocol.received().len(),
            "app": app_status(&mut wallet),
        }),
    );
    if world.faults_left() != 0 {
        return Err("a fault met no request".into());
    }
    Ok(())
}

/// The key of the claim attempted twice.
const RETRIED_CLAIM: [u8; 32] = [0x7c; 32];
