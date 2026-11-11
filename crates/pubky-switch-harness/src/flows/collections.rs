//! Two collections under different scopes (Switch spec 10.3, Switch wire 6.2, 7.4.9, 7.5):
//! one app writes both, and each reader gets the one its scope covers.

use pubky_switch_client::app::{App, AppError, Collection, RecordTarget};
use serde_json::{Value, json};

use super::enrollment::enroll;
use super::join::{app_status, events};
use super::messaging::joined_as;
use super::records::{look, shown};
use super::{ORIGIN, STEP_MS};
use crate::parties::{
    Asking, NOTES, NOTES_JOURNAL, journal_collection, notes_collection,
    notes_protocol_with_both_collections,
};
use crate::{FlowResult, World};

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

/// What `app` holds of each collection, and what the switch gives it when it asks for the
/// record its scope covers and for the one outside it, for the trace.
async fn holdings(
    world: &World,
    name: &str,
    app: &mut App,
    covered: (&str, &RecordTarget),
    outside: (&str, &RecordTarget),
) -> FlowResult {
    let mut of = serde_json::Map::new();
    for collection in [notes_collection(), journal_collection()] {
        let listed = app.records_of(&collection.name).await?;
        of.insert(collection.name.clone(), json!(listed.len()));
    }
    world.outcome(
        &format!("what {name} holds of each collection"),
        &Value::Object(of),
    );
    for ((record, target), standing) in [
        (covered, "which its scope covers"),
        (outside, "outside its scope"),
    ] {
        let read = app.read_record(target).await;
        world.outcome(
            &format!("what {name} reads of {record}, {standing}"),
            &json!({
                "ended": ended(&read),
                "record": shown(read.as_ref().ok().and_then(Option::as_ref)),
                "events": events(&app.take_events()),
            }),
        );
        world.advance_ms(STEP_MS);
    }
    Ok(())
}

/// alice's wallet holds two scopes with keys, each the scope of a collection, and writes a
/// record in each. Her phone holds the first scope and her desk the second: each learns of
/// its own collection's write from its feed and may not read the other's, in the feed or
/// when it asks for it by its key (`403 permission_missing`, Switch wire 7.4.9). A tablet
/// that joins with the first scope lists that collection alone.
///
/// Calls: `POST /v1/{id}/ops` (`record.put`) in two collections; `GET /v1/{id}/feed` with a
/// write the reader's scope covers beside one it doesn't; `GET /v1/{id}/records/{key}`
/// allowed and refused by the record's read scope; `GET /v1/{id}/records`, one collection
/// at a time, by apps that may read both, one, or the other.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn two_collections(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let wallet_scopes = [NOTES, NOTES_JOURNAL];
    let (mut wallet, _) = joined_as(
        world,
        &alice,
        &mut signer,
        Asking::for_scopes(world.app_keys(&alice, "wallet")?, &wallet_scopes)?,
        notes_protocol_with_both_collections(&wallet_scopes),
    )
    .await?;
    let (mut phone, _) = joined_as(
        world,
        &alice,
        &mut signer,
        Asking::for_scope(world.app_keys(&alice, "phone")?, NOTES)?,
        notes_protocol_with_both_collections(&[NOTES]),
    )
    .await?;
    let (mut desk, _) = joined_as(
        world,
        &alice,
        &mut signer,
        Asking::for_scope(world.app_keys(&alice, "desk")?, NOTES_JOURNAL)?,
        notes_protocol_with_both_collections(&[NOTES_JOURNAL]),
    )
    .await?;
    for (app, name) in [
        (&mut wallet, "the wallet before any record"),
        (&mut phone, "the phone before any record"),
        (&mut desk, "the desk before any record"),
    ] {
        look(world, app, name).await?;
    }

    let item = RecordTarget::new(notes_collection(), b"shopping list");
    let entry = RecordTarget::new(journal_collection(), b"monday");
    let writes: [(&str, &RecordTarget, &Collection, &str); 2] = [
        ("an item", &item, &item.collection, r#"{"items":["milk"]}"#),
        (
            "a journal entry",
            &entry,
            &entry.collection,
            r#"{"text":"rain"}"#,
        ),
    ];
    for (name, target, collection, value) in writes {
        let written = wallet
            .put_record(target, value.as_bytes(), Vec::new())
            .await?;
        world.outcome(
            &format!("the wallet wrote {name}"),
            &json!({
                "record": shown(Some(&written)),
                "read_scope": collection.policy.read_scope,
            }),
        );
        world.advance_ms(STEP_MS);
    }

    let (the_item, the_entry) = (("the item", &item), ("the journal entry", &entry));
    look(world, &mut phone, "the phone after the writes").await?;
    holdings(world, "the phone", &mut phone, the_item, the_entry).await?;
    look(world, &mut desk, "the desk after the writes").await?;
    holdings(world, "the desk", &mut desk, the_entry, the_item).await?;

    // An app that joins with the first scope lists what it may read.
    let (mut tablet, _) = joined_as(
        world,
        &alice,
        &mut signer,
        Asking::for_scope(world.app_keys(&alice, "tablet")?, NOTES)?,
        notes_protocol_with_both_collections(&[NOTES]),
    )
    .await?;
    world.outcome("the tablet after it joined", &app_status(&mut tablet));
    holdings(world, "the tablet", &mut tablet, the_item, the_entry).await?;
    Ok(())
}
