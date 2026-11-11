//! Pages past the first (Switch wire 7.4.4, 7.4.9, 9.2): a feed read in pages its `limit`
//! ends, a feed read in pages the byte budget ends, and a collection listed in pages the
//! byte budget ends.

use pubky_switch_client::app::{App, AppConfig, RecordTarget};
use serde_json::json;

use super::enrollment::enroll;
use super::join::{app_status, events};
use super::messaging::joined_with;
use super::{ORIGIN, STEP_MS};
use crate::parties::{Asking, notes_collection, notes_protocol_with_records};
use crate::{FlowResult, World};

/// The items the phone asks for per feed page.
const SMALL_PAGE: u32 = 2;

/// The size of a large record's value: a few of them fill a page's byte budget of 8 MiB
/// (Switch wire 9.2 `max_page_bytes`), each within what one sealed value holds.
const LARGE_VALUE_BYTES: usize = 250_000;

/// How many large records the wallet writes: more than one page holds, of the feed and of
/// the collection's listing alike.
const LARGE_RECORDS: usize = 19;

/// The wallet writes records; the identity's other apps read them in pages.
///
/// - The phone asks for two items per page. After four writes its read takes the pages of
///   an even count, after three more those of an odd one: `more` and `next` at a page that
///   `limit` ends, and at the feed's end.
/// - The wallet then writes large records, more than a page's byte budget holds. The desk,
///   which asks for a hundred items per page, reads all the writes: its pages end at the
///   byte budget, short of `limit`.
/// - A tablet joins and lists the collection: the listing's pages end at the byte budget
///   too, with `next` to pass as `after`. It then holds every record.
///
/// Calls: `GET /v1/{id}/feed` with `more: true` and from a page's `next`, by `limit` and by
/// the byte budget; `GET /v1/{id}/records` with `next` and `after`.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn pages(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let asking = |name: &str| -> Result<Asking, crate::HarnessError> {
        Asking::new(world.app_keys(&alice, name)?)
    };
    let small_pages = AppConfig {
        page_size: SMALL_PAGE,
        ..AppConfig::default()
    };
    let (mut wallet, _) = joined_with(
        world,
        &alice,
        &mut signer,
        asking("wallet")?,
        notes_protocol_with_records(),
        AppConfig::default(),
    )
    .await?;
    let (mut phone, _) = joined_with(
        world,
        &alice,
        &mut signer,
        asking("phone")?,
        notes_protocol_with_records(),
        small_pages,
    )
    .await?;
    let (mut desk, _) = joined_with(
        world,
        &alice,
        &mut signer,
        asking("desk")?,
        notes_protocol_with_records(),
        AppConfig::default(),
    )
    .await?;
    look(world, &mut phone, "the phone before any record").await?;
    look(world, &mut desk, "the desk before any record").await?;

    // Pages that `limit` ends: an even count of items, then an odd one.
    let mut written = 0_usize;
    for (count, step) in [
        (4, "the phone reads four writes in pages of two"),
        (3, "the phone reads three more in pages of two"),
    ] {
        for _ in 0..count {
            written += 1;
            let target =
                RecordTarget::new(notes_collection(), format!("note {written}").as_bytes());
            let value = format!(r#"{{"note":{written}}}"#);
            wallet
                .put_record(&target, value.as_bytes(), Vec::new())
                .await?;
            world.advance_ms(STEP_MS);
        }
        world.outcome(
            &format!("the wallet wrote {count} small records"),
            &json!({ "events": events(&wallet.take_events()) }),
        );
        look(world, &mut phone, step).await?;
    }

    // Pages that the byte budget ends.
    let filler = "a".repeat(LARGE_VALUE_BYTES);
    for number in 1..=LARGE_RECORDS {
        written += 1;
        let target = RecordTarget::new(notes_collection(), format!("large {number}").as_bytes());
        let value = format!(r#"{{"large":{number},"text":"{filler}"}}"#);
        wallet
            .put_record(&target, value.as_bytes(), Vec::new())
            .await?;
        world.advance_ms(STEP_MS);
    }
    world.outcome(
        &format!("the wallet wrote {LARGE_RECORDS} large records"),
        &json!({ "events": events(&wallet.take_events()) }),
    );
    look(
        world,
        &mut desk,
        "the desk reads every write in pages the byte budget ends",
    )
    .await?;

    // A listing in pages the byte budget ends.
    let (mut tablet, _) = joined_with(
        world,
        &alice,
        &mut signer,
        asking("tablet")?,
        notes_protocol_with_records(),
        AppConfig::default(),
    )
    .await?;
    let listed = tablet.records_of(&notes_collection().name).await?;
    world.outcome(
        "what the tablet holds after it joined and listed the collection",
        &json!({
            "listed": listed.len(),
            "written": written,
            "app": app_status(&mut tablet),
        }),
    );
    if listed.len() != written {
        return Err(format!(
            "the tablet holds {} of the {written} records written",
            listed.len()
        )
        .into());
    }
    Ok(())
}

/// `app` follows its feed to the end and moves its cursor: the events it raises at this
/// read, and where it stands.
async fn look(world: &World, app: &mut App, name: &str) -> FlowResult {
    let report = app.receive(None).await?;
    app.flush_cursor().await?;
    world.outcome(
        name,
        &json!({
            "events": events(&report.events),
            "stopped": report.stopped,
            "app": app_status(app),
        }),
    );
    world.advance_ms(STEP_MS);
    Ok(())
}
