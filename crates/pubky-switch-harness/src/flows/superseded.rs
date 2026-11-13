//! Superseded writes, read late (Switch wire 7.5): a write that a later one replaced shows
//! as its stub to every app, wherever the reader's cursor stands, and a switch may keep its
//! document no longer.

use pubky_switch_client::app::{App, RecordTarget};
use serde_json::json;

use super::enrollment::enroll;
use super::messaging::joined_as;
use super::records::{look, shown};
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, notes_collection, notes_protocol_with_records};
use crate::{FlowResult, World};

/// What the last feed page `reader` was answered shows of each item, in order: `stub`, or
/// the operation of an item shown in full.
fn page(world: &World, reader: &str) -> Vec<String> {
    let label = format!("{{alice/{reader}}} GET /v1/{{alice}}/feed");
    let fact = |index: usize, member: &str| {
        world
            .last_fact(&label, &format!("body.items[{index}].{member}"))
            .map(|value| value.trim_start_matches("text ").to_owned())
    };
    (0..)
        .map_while(|index| {
            let kind = fact(index, "type")?;
            Some(fact(index, "item.body~.op").unwrap_or(kind))
        })
        .collect()
}

/// `reader` follows its feed in one read: the page must show `expected`, item by item.
async fn read_late(world: &World, app: &mut App, reader: &str, expected: &[&str]) -> FlowResult {
    look(world, app, &format!("the {reader} read its feed, late")).await?;
    let shown = page(world, reader);
    if shown != expected {
        return Err(format!("the {reader}'s page shows {shown:?}, not {expected:?}").into());
    }
    Ok(())
}

/// alice's wallet, phone and desk hold the collection's read scope. The phone and the desk
/// read their feeds to the end and then stop. The wallet writes a record and changes it,
/// writes a second record and deletes it, and saves a contact.
///
/// The phone reads then. The first record's first write and the second record's write were
/// each replaced, so the page shows their stubs; the writes that stand, the deletion and
/// the contact show in full. The wallet changes the first record once more, and the desk
/// reads from where the phone started: the write the phone was shown in full is a stub to
/// the desk. What an item shows follows from the account's state at the read, never from
/// where a reader stands, so a switch may drop a replaced write's document at once and no
/// answer changes.
///
/// Calls: `GET /v1/{id}/feed` by an app whose cursor stands before writes that were
/// replaced since, at two times.
///
/// # Errors
///
/// When a step that should succeed against any switch fails, a page doesn't show exactly
/// the stubs and the full items above, or a reader ends holding another value than the
/// record's last.
pub async fn superseded_writes_read_late(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    let bob = world.identity("bob")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let mut join = async |name: &str| -> Result<App, Box<dyn std::error::Error>> {
        let asking = Asking::new(world.app_keys(&alice, name)?)?;
        let (app, _) = joined_as(
            world,
            &alice,
            &mut signer,
            asking,
            notes_protocol_with_records(),
        )
        .await?;
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

    let list = RecordTarget::new(notes_collection(), b"shopping list");
    let book = RecordTarget::new(notes_collection(), b"address book");
    wallet
        .put_record(&list, br#"{"items":["milk"]}"#, Vec::new())
        .await?;
    world.advance_ms(STEP_MS);
    wallet
        .put_record(&list, br#"{"items":["milk","bread"]}"#, Vec::new())
        .await?;
    world.advance_ms(STEP_MS);
    wallet
        .put_record(&book, br#"{"names":["bob"]}"#, Vec::new())
        .await?;
    world.advance_ms(STEP_MS);
    wallet.delete_record(&book, Vec::new()).await?;
    world.advance_ms(STEP_MS);
    wallet.add_contact(&bob.public()).await?;
    world.outcome("the wallet wrote, changed and deleted", &json!({}));
    world.advance_ms(STEP_MS);

    // Each record's replaced write is a stub; what stands shows in full.
    read_late(
        world,
        &mut phone,
        "phone",
        &["stub", "record.put", "stub", "record.put", "allow.put"],
    )
    .await?;
    let list_key = phone.record_key(&list)?;
    let book_key = phone.record_key(&book)?;
    world.outcome(
        "what the phone holds",
        &json!({
            "the changed record": shown(phone.shared_record(&list_key).await?.as_ref()),
            "the deleted record": shown(phone.shared_record(&book_key).await?.as_ref()),
        }),
    );
    world.advance_ms(STEP_MS);

    // One more change: the write the phone was shown in full is replaced now.
    wallet
        .put_record(&list, br#"{"items":["milk","bread","tea"]}"#, Vec::new())
        .await?;
    world.advance_ms(STEP_MS);
    read_late(
        world,
        &mut desk,
        "desk",
        &[
            "stub",
            "stub",
            "stub",
            "record.put",
            "allow.put",
            "record.put",
        ],
    )
    .await?;
    let held = desk.shared_record(&list_key).await?;
    let value = held
        .as_ref()
        .and_then(|record| record.content.value())
        .map(|value| String::from_utf8_lossy(value).into_owned());
    world.outcome(
        "what the desk holds",
        &json!({
            "the changed record": shown(held.as_ref()),
            "the deleted record": shown(desk.shared_record(&book_key).await?.as_ref()),
        }),
    );
    if value.as_deref() != Some(r#"{"items":["milk","bread","tea"]}"#) {
        return Err(format!("the desk holds {value:?} of the record changed three times").into());
    }
    Ok(())
}
