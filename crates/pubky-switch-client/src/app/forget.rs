//! Forgetting a processed pair (Switch spec 11).
//!
//! The app keeps the (sender, `msg_id`) pair of every message it processed for the
//! retention, so a re-sent copy is dropped as a duplicate (check 9, Switch wire 5.1). A
//! protocol that keeps what a message brought, and later gives it up, may want a re-sent copy
//! delivered again instead. Forgetting the pair does that and nothing more: it deletes the
//! pair and its time index, in the commit that carries the protocol's own writes of the same
//! decision, and it makes the app deliver nothing, moves no cursor, and leaves every entry
//! stored locally and every kept effect as they are. A forgotten pair is simply gone, with
//! nothing left for the retention to prune, and no later backup carries it, since a backup
//! carries the pairs the store holds when it is taken.
//!
//! What the caller takes on: from the commit on, a re-sent copy of the message is a new
//! entry, delivered to the protocol again, and the protocol itself must not apply it twice.
//! The message's sender can replay it at will, every copy delivered (Switch spec 11).

use pubky_switch_core::message::MessagePlaintext;
use serde_json::Value;

use super::protocol::LocalWrite;
use super::state::{Processed, key};
use super::{App, AppError, AppState, Refusal};

/// The keys of the pair of `msg_id` from `sender`, if it is held (`processed`, read as the
/// caller sees the store): the pair and its time index.
///
/// # Errors
///
/// [`Refusal::NotNow`] while the message's effect is kept to be sent, or an entry stored
/// locally holds the message, whose pair keeps it from being applied twice (Switch spec 8.2,
/// 12.5 "Kept batches"); a store failure or a pair that doesn't read.
pub(crate) fn held_pair(
    state: &AppState,
    sender: &[u8; 32],
    msg_id: &str,
    processed: Option<Processed>,
) -> Result<Option<[String; 2]>, AppError> {
    if state
        .pending_effect
        .as_ref()
        .is_some_and(|pending| &pending.sender == sender && pending.msg_id == msg_id)
    {
        return Err(Refusal::NotNow("the message's effect is kept to be sent".into()).into());
    }
    if state.parked.values().any(|stored| {
        &stored.sender == sender && stored_msg_id(&stored.plaintext) == Some(msg_id.to_owned())
    }) {
        return Err(Refusal::NotNow("an entry stored locally holds the message".into()).into());
    }
    Ok(processed.map(|processed| {
        [
            key::processed(sender, msg_id),
            key::processed_at(processed.at_ms, sender, msg_id),
        ]
    }))
}

/// What forgetting the pairs under `keys` counts against
/// [`super::MAX_STEP_LOCAL_BYTES`]: each key as a delete of it would
/// ([`super::local_writes_bytes`]).
pub(crate) fn forget_bytes<'a>(keys: impl IntoIterator<Item = &'a String>) -> usize {
    keys.into_iter().fold(0usize, |total, key| {
        total.saturating_add(
            key.len()
                .saturating_add(super::protocol::LOCAL_WRITE_OVERHEAD_BYTES),
        )
    })
}

/// The `msg_id` of a stored entry's signed plaintext.
fn stored_msg_id(plaintext: &[u8]) -> Option<String> {
    let plaintext = MessagePlaintext::decode(plaintext).ok()?;
    let json: Value = serde_json::from_slice(plaintext.json()).ok()?;
    Some(json.get("msg_id")?.as_str()?.to_owned())
}

impl App {
    /// Forget the processed pair of `msg_id` from `sender`, and commit `local`, the
    /// protocol's own writes that give up what the message brought, in the same commit.
    /// Returns whether a pair was held; forgetting one that isn't, another sender's or an
    /// unknown `msg_id`, changes nothing but `local`.
    ///
    /// From then on a re-sent copy of the message is delivered as a new entry, and the
    /// protocol must not apply it twice itself: the message's sender can replay it at will,
    /// as often as it likes, and nothing in the app drops a copy as a duplicate any more,
    /// nor shows one with other bytes as a conflict (Switch spec 11). Nothing is delivered
    /// again by this call, and
    /// no cursor moves. Inside a receive step, use [`super::ReceiveContext::forget_processed`],
    /// which commits with the step. A caller that commits its own writes apart from this
    /// call forgets first: a crash between the two leaves the protocol still keeping what
    /// it recognises, so a re-sent copy is never applied twice.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] while the message's effect is kept to be sent, or an entry stored
    /// locally holds it; [`Refusal::Stopped`] or [`Refusal::Left`]; a store failure, after
    /// which nothing was written.
    pub async fn forget_processed(
        &mut self,
        protocol: &str,
        sender: [u8; 32],
        msg_id: &str,
        local: &[LocalWrite],
    ) -> Result<bool, AppError> {
        let msg_id = msg_id.to_owned();
        let local = super::protocols::qualify(protocol, local.iter().cloned());
        let protocol = protocol.to_owned();
        Box::pin(async move {
            if !self.protocols.contains(&protocol) {
                return Err(
                    Refusal::Usage(format!("no protocol `{protocol}` is registered")).into(),
                );
            }
            self.ready_local().await?;
            self.refuse_when_halted()?;
            let processed = self
                .reader()
                .get::<Processed>(&key::processed(&sender, &msg_id))
                .await?;
            let keys = held_pair(&self.state, &sender, &msg_id, processed)?;
            let mut tx = self.tx()?;
            for key in keys.iter().flatten() {
                tx.delete(key)?;
            }
            tx.local(&local)?;
            self.commit(tx).await?;
            Ok(keys.is_some())
        })
        .await
    }
}
