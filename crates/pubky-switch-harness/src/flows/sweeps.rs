//! The sweeps (Switch wire 9.1, 7.3 step 4; Switch spec 10.3): a switch forgets a deleted
//! key once every listed app has read past its delete, and drops an invite code that ran
//! out or expired, each no sooner than the first request a minute on.
//!
//! The two switches sweep at different requests. The service sweeps before the endpoint of
//! the first request a minute after the last sweep, from a caller that has verified. The
//! scripted switch forgets keys at a cursor move and drops codes at the first request of
//! any caller a minute on (`testing/FAKES.md`). The flows look only where both have swept:
//! a step of the flow's clock, which is longer than a minute, after what frees the key or
//! spends the code.

use pubky_switch_client::app::{App, Delivery, OutgoingMessage, RecordTarget};
use serde_json::json;

use super::admission::note;
use super::enrollment::enroll;
use super::messaging::{joined, joined_as};
use super::records::{look, shown};
use super::recovery::expect_answer;
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, notes_collection, notes_protocol_with_records};
use crate::{FlowResult, World};

const HOUR_MS: u64 = 3_600_000;

/// What the phone's last read of a record from the switch was answered: its status, and
/// the body's `deleted`.
fn record_read(world: &World) -> (Option<String>, Option<String>) {
    let trace = world.trace();
    let read = trace.lines.iter().rev().find(|line| {
        line.label
            .starts_with("{alice/phone} GET /v1/{alice}/records/")
    });
    let fact = |name: &str| read.and_then(|line| line.facts.get(name).cloned());
    (fact("status"), fact("body.deleted"))
}

/// alice's wallet, phone and desk hold a collection's read scope. The wallet writes a
/// record and deletes it. The wallet and the phone read past the delete; the desk doesn't,
/// so the switch keeps the key: the phone's read of the record is answered with the
/// delete. Then the desk reads too. A step later every listed app has passed the delete
/// and the minute's sweep has run: the key is forgotten, and the phone's read is `404`, as
/// for a key that never was.
///
/// The wallet writes at the key again. It holds the delete, so it writes as for a new key,
/// and the write is taken at a version past every one the key had. The phone takes it from
/// its feed, and a tablet that joins lists one record.
///
/// Calls: `GET /v1/{id}/records/{key}` for a deleted key the switch still holds and for
/// one it forgot; `POST /v1/{id}/ops` (`record.put`) creating a forgotten key again.
///
/// # Errors
///
/// When a step that should succeed against any switch fails; when the key isn't held
/// while an app is short of its delete, or isn't forgotten once all have passed; or when
/// the write at the forgotten key isn't taken as a newer one.
pub async fn deleted_key_forgotten(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let mut join = async |name: &str| -> Result<App, Box<dyn std::error::Error>> {
        let asking = Asking::new(world.app_keys(&alice, name)?)?;
        let protocol = notes_protocol_with_records();
        let (app, _) = joined_as(world, &alice, &mut signer, asking, protocol).await?;
        Ok(app)
    };
    let mut wallet = join("wallet").await?;
    let mut phone = join("phone").await?;
    let mut desk = join("desk").await?;
    for (app, name) in [
        (&mut wallet, "wallet"),
        (&mut phone, "phone"),
        (&mut desk, "desk"),
    ] {
        look(world, app, &format!("the {name} before any record")).await?;
    }
    world.advance_ms(STEP_MS);

    let list = RecordTarget::new(notes_collection(), b"shopping list");
    wallet
        .put_record(&list, br#"{"items":["milk"]}"#, Vec::new())
        .await?;
    world.advance_ms(STEP_MS);
    let deleted = wallet.delete_record(&list, Vec::new()).await?;
    world.outcome("the wallet deleted the record", &shown(Some(&deleted)));
    world.advance_ms(STEP_MS);

    // Two of the three apps pass the delete.
    look(world, &mut wallet, "the wallet read past its delete").await?;
    look(world, &mut phone, "the phone read past the delete").await?;
    world.advance_ms(STEP_MS);
    phone.read_record(&list).await?;
    let held = record_read(world);
    if held != (Some("200".into()), Some("bool true".into())) {
        return Err(format!(
            "with the desk short of the delete, the phone's read was answered {held:?}, not \
             the delete the switch still holds"
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    // The third passes it. A step on, both switches have forgotten the key.
    look(world, &mut desk, "the desk read past the delete").await?;
    world.advance_ms(STEP_MS);
    let kept = phone.read_record(&list).await?;
    world.outcome(
        "what the phone holds of the forgotten key",
        &shown(kept.as_ref()),
    );
    let forgotten = record_read(world);
    if forgotten.0.as_deref() != Some("404") {
        return Err(format!(
            "with every app past the delete, the phone's read was answered {forgotten:?}, not \
             404: the key isn't forgotten"
        )
        .into());
    }
    world.advance_ms(STEP_MS);

    // The key again, as a new one.
    let again = wallet
        .put_record(&list, br#"{"items":["tea"]}"#, Vec::new())
        .await?;
    world.outcome(
        "the wallet wrote at the forgotten key",
        &shown(Some(&again)),
    );
    let newer = (again.version.generation, again.version.version)
        > (deleted.version.generation, deleted.version.version);
    if !newer {
        return Err(format!(
            "the write at the forgotten key has version {:?}, not past the delete's {:?}",
            again.version, deleted.version
        )
        .into());
    }
    world.advance_ms(STEP_MS);
    look(world, &mut phone, "the phone read the new write").await?;
    let key = phone.record_key(&list)?;
    let taken = phone.shared_record(&key).await?;
    world.outcome("what the phone holds then", &shown(taken.as_ref()));
    let value = taken.as_ref().and_then(|record| record.content.value());
    if value != Some(br#"{"items":["tea"]}"#.as_slice()) {
        return Err("the phone doesn't hold the write at the forgotten key".into());
    }

    let tablet = join("tablet").await?;
    let listed = tablet.records_of(&notes_collection().name).await?;
    world.outcome(
        "the tablet joined and listed",
        &json!({ "listed": listed.len() }),
    );
    if listed.len() != 1 {
        return Err(format!("the tablet lists {} records, not the one", listed.len()).into());
    }
    Ok(())
}

/// `sender` sends `message`, which must be accepted. The clock stays where it is, so the
/// steps around it fall in one minute.
async fn accepted(
    world: &World,
    name: &str,
    sender: &mut App,
    message: OutgoingMessage,
) -> FlowResult {
    let (_, delivery) = sender.send(message).await?;
    let accepted = matches!(delivery, Delivery::Accepted { .. });
    world.outcome(name, &json!({ "accepted": accepted }));
    if accepted {
        Ok(())
    } else {
        Err(format!("{name}: the message wasn't accepted").into())
    }
}

/// How many invite codes the switch lists for `app`'s account, noted as `name` with each
/// code's uses.
async fn codes(
    world: &World,
    name: &str,
    app: &mut App,
) -> Result<usize, Box<dyn std::error::Error>> {
    let list = app.allow_list().await?;
    world.outcome(
        name,
        &json!({
            "invite_codes": list.invite_codes.iter().map(|code| json!({
                "uses": code.uses,
                "max_uses": code.max_uses,
            })).collect::<Vec<_>>(),
            "conversations": list.conversations.len(),
        }),
    );
    Ok(list.invite_codes.len())
}

/// alice's wallet registers three invite codes: two for a single use each, one good for an
/// hour. bob's shop and carol's stall each send a note with a single-use code, which admits
/// them and uses the codes up. A used-up code is no longer listed, but until the minute's
/// sweep the switch still holds it: within the same minute the wallet withdraws carol's,
/// and the withdrawal is taken. A step later the sweep has dropped bob's: withdrawing it
/// finds nothing. Past the hour the third code is dropped the same way. bob, admitted by a
/// code that is gone, is still admitted.
///
/// Calls: `POST /v1/{id}/ops` (`invite_code.delete`) for a used-up code before the sweep
/// (`200`) and for codes the sweep dropped (`404 not_found`); `GET /v1/{id}/allow` around
/// them.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, the list doesn't hold
/// exactly the codes each step names, or a withdrawal isn't answered as its step says.
pub async fn invite_codes_swept(world: &World) -> FlowResult {
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
    let expect = |held: usize, wanted: usize, when: &str| -> FlowResult {
        if held == wanted {
            Ok(())
        } else {
            Err(format!("{when} the switch lists {held} invite codes, not {wanted}").into())
        }
    };
    let withdrawal = "{alice/wallet} POST /v1/{alice}/ops";
    let later = world.now_ms() + 3 * HOUR_MS;

    let for_bob = wallet
        .register_invite_code(later, 1, json!({ "order": "A-17" }))
        .await?;
    let for_carol = wallet
        .register_invite_code(later, 1, json!({ "order": "A-18" }))
        .await?;
    let hour = wallet
        .register_invite_code(world.now_ms() + HOUR_MS, 5, json!({ "order": "A-19" }))
        .await?;
    world.advance_ms(STEP_MS);

    // Both single-use codes are used up in one minute.
    let hello = note(alice.public(), "hello", Some(&for_bob.code));
    accepted(
        world,
        "bob's shop sent a note with its code",
        &mut shop,
        hello,
    )
    .await?;
    let hello = note(alice.public(), "hello", Some(&for_carol.code));
    accepted(
        world,
        "carol's stall sent a note with its code",
        &mut stall,
        hello,
    )
    .await?;
    let held = codes(world, "the codes within the minute", &mut wallet).await?;
    expect(held, 1, "with two codes used up")?;
    // No sweep since: the switch still holds carol's, and takes its withdrawal.
    wallet.withdraw_invite_code(&for_carol.code_hash).await?;
    let taken = world.last_fact(withdrawal, "status");
    if taken.as_deref() != Some("200") {
        return Err(format!("the withdrawal before the sweep was answered {taken:?}").into());
    }
    world.advance_ms(STEP_MS);

    // A step on, the sweep has dropped bob's.
    let held = codes(world, "the codes a step later", &mut wallet).await?;
    expect(held, 1, "a step after the codes were used up")?;
    let gone = wallet.withdraw_invite_code(&for_bob.code_hash).await;
    world.outcome(
        "the wallet withdrew the used-up code the sweep dropped",
        &json!({ "ok": gone.is_ok() }),
    );
    expect_answer(world, withdrawal, 404, "not_found")?;
    world.advance_ms(HOUR_MS);

    // The third ran out by time.
    let held = codes(world, "the codes past the hour", &mut wallet).await?;
    expect(held, 0, "past the third code's hour")?;
    let gone = wallet.withdraw_invite_code(&hour.code_hash).await;
    world.outcome(
        "the wallet withdrew the expired code",
        &json!({ "ok": gone.is_ok() }),
    );
    expect_answer(world, withdrawal, 404, "not_found")?;

    // The entry bob's code made stays without it.
    let again = note(alice.public(), "hello again", None);
    accepted(
        world,
        "bob's shop sent a second note, without a code",
        &mut shop,
        again,
    )
    .await
}
