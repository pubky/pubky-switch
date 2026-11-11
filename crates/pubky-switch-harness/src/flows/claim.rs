//! A claim: an attempt, its outcome, and the read (Switch spec 6.3, 10.2, Switch wire 6.2
//! `claim`, 6.5, 7.4.8).

use pubky_switch_client::app::{ClaimOp, ObligationDeadline};
use pubky_switch_core::claims::{Basis, ClaimView};
use serde_json::{Value, json};

use super::enrollment::enroll;
use super::join::{app_status, events};
use super::messaging::joined;
use super::{ORIGIN, STEP_MS};
use crate::{FlowResult, World};

/// The claim's key: any 32 bytes, the same in every world.
const CLAIM_KEY: [u8; 32] = [0x5a; 32];

/// The attempts' IDs.
const FIRST_ATTEMPT: [u8; 16] = [1; 16];
const SECOND_ATTEMPT: [u8; 16] = [2; 16];

/// An app reads a claim nobody wrote, attempts it, reports the attempt failed, attempts it
/// again and reports that one done. After each entry it reads the claim and follows its
/// feed, which shows the entry.
///
/// Calls, beyond the join's: `GET /v1/{id}/claims/{claim_key}` (none, attempting, free
/// again, settled), `POST /v1/{id}/ops` (`claim` with `attempt`, `failed`, `attempt`,
/// `done`), `GET /v1/{id}/feed` with claim entries.
///
/// # Errors
///
/// When a step that should succeed against any switch fails.
pub async fn claim(world: &World) -> FlowResult {
    let alice = world.identity("alice")?;
    world.add_switch(ORIGIN, &[&alice]).await?;
    let mut signer = enroll(world, &alice, ORIGIN).await?;
    let (mut wallet, _) = joined(world, &alice, &mut signer, "wallet").await?;

    let nothing = wallet.read_claim(&CLAIM_KEY).await?;
    world.outcome(
        "read before any entry",
        &json!({ "found": nothing.is_some() }),
    );
    world.advance_ms(STEP_MS);

    let entries = [
        (
            "attempted",
            ClaimOp::attempt(CLAIM_KEY, 0, FIRST_ATTEMPT, 3_600, None),
        ),
        ("failed", ClaimOp::failed(CLAIM_KEY, 1, FIRST_ATTEMPT)),
        (
            "attempted again",
            ClaimOp::attempt(CLAIM_KEY, 2, SECOND_ATTEMPT, 3_600, None),
        ),
        (
            "done",
            ClaimOp::done(CLAIM_KEY, 3, SECOND_ATTEMPT, Basis::Owner, None)?,
        ),
    ];
    for (name, entry) in entries {
        // What the app raises at each step is taken at once, so each outcome shows the
        // events of its own step: the write, the read of the claim, the read of the feed.
        let written = wallet
            .write_claim(entry, Vec::new(), ObligationDeadline::NotKnown)
            .await?;
        world.outcome(
            name,
            &json!({
                "view": view(&written.view),
                "events": events(&wallet.take_events()),
            }),
        );
        world.advance_ms(STEP_MS);
        let read = wallet.read_claim(&CLAIM_KEY).await?;
        world.outcome(
            &format!("read after {name}"),
            &json!({
                "view": read.as_ref().map(|read| view(&read.view)),
                "entries": read.as_ref().map(|read| read.entries.len()),
                "events": events(&wallet.take_events()),
            }),
        );
        world.advance_ms(STEP_MS);
        let report = wallet.receive(None).await?;
        world.outcome(
            &format!("received after {name}"),
            &json!({ "events": events(&report.events) }),
        );
    }

    let doubt = wallet.claim_doubt(&CLAIM_KEY).await?;
    world.outcome(
        "at the end",
        &json!({
            "doubtful": format!("{doubt:?}"),
            "app": app_status(&mut wallet),
        }),
    );
    Ok(())
}

/// What a claim view says, for the trace.
fn view(view: &ClaimView) -> Value {
    json!({
        "status": format!("{:?}", view.status),
        "step": view.step,
        "owned": view.owner.is_some(),
        "attempting": view.attempt_id.is_some(),
        "attempts": view.attempts.len(),
        "tombstone": view.tombstone,
        "deadline": view.deadline,
        "divergent": view.divergent,
        "next_possibly_duplicate": view.next_possibly_duplicate,
    })
}
