//! The entries stored locally, as a host sees and settles them (Switch spec 8.2).
//!
//! An entry the app stored locally and passed is tried again by later reads, or, for a
//! reason that isn't tried again ([`ParkReason::tried_again`]), kept until the host acts on
//! it. The host lists them ([`App::parked_entries`]), views one ([`App::parked_entry`]),
//! and either forgets one that isn't tried again ([`App::forget_parked`]), keeping its
//! message a duplicate, or releases one whose effect was uncertain to be tried once more
//! ([`App::release_parked`]). Each change is one commit.

use pubky_switch_core::enc::pubky_id;
use pubky_switch_core::json::OpaqueMember;
use pubky_switch_core::message::{Message, MessagePlaintext};
use pubky_switch_core::sig::SignedDoc;
use serde_json::Value;

use super::error::Refusal;
use super::events::ParkReason;
use super::feed::processed_writes;
use super::state::{ParkedEntry, Processed, key};
use super::{App, AppError};
use crate::error::StoreError;

/// An entry stored locally (Switch spec 8.2), as [`App::parked_entry`] shows it: why, the
/// message as the protocol is handed it, and the reads in a row its receive step couldn't
/// finish. Sensitive: its `Debug` shows neither the plaintext nor the body.
#[derive(Clone)]
#[non_exhaustive]
pub struct ParkedMessage {
    /// The entry's `seq`, in the generation it was read at, renumbered after a provider
    /// loss (`STATE.md`).
    pub seq: u64,
    /// The sender identity.
    pub sender: [u8; 32],
    /// When the inbox accepted it, service time in Unix milliseconds.
    pub accepted_at_ms: u64,
    /// Why it was stored.
    pub reason: ParkReason,
    /// The signed plaintext.
    pub plaintext: MessagePlaintext,
    /// The message, read with the protocol's opaque members; `None` when its JSON doesn't
    /// read as a message, as for an entry stored before its checks ran.
    pub message: Option<Message>,
    /// The sender's certificate, as the entry carried it.
    pub cert: SignedDoc,
    /// The invite code's context, if one admitted the entry; opaque.
    pub context: Option<Value>,
    /// The reads in a row that ended with the protocol's store or the host keeping the
    /// receive step from finishing ([`super::Outcome::Retry`]); 0 for none.
    pub retry_reads: u32,
    /// Since when those reads ended so, app clock; `None` for none.
    pub retrying_since_ms: Option<u64>,
}

impl std::fmt::Debug for ParkedMessage {
    // The plaintext and body are message content: only what names the entry is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = f.debug_struct("ParkedMessage");
        out.field("seq", &self.seq)
            .field("sender", &pubky_id(&self.sender))
            .field("accepted_at_ms", &self.accepted_at_ms)
            .field("reason", &self.reason);
        if let Some(message) = &self.message {
            out.field("kind", &message.kind)
                .field("msg_id", &message.msg_id);
        }
        out.field("retry_reads", &self.retry_reads).finish()
    }
}

fn no_entry(seq: u64) -> AppError {
    Refusal::Usage(format!("no entry is stored locally at seq {seq}")).into()
}

impl App {
    /// The entries stored locally, with why each was stored, in `seq` order.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn parked_entries(&mut self) -> Result<Vec<(u64, ParkReason)>, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            Ok(self
                .state
                .parked
                .iter()
                .map(|(seq, stored)| (*seq, stored.reason))
                .collect())
        })
        .await
    }

    /// The entry stored locally at `seq`, `None` when there is none.
    ///
    /// # Errors
    ///
    /// A store failure; [`StoreError::Corrupt`] for a stored plaintext that doesn't decode.
    pub async fn parked_entry(&mut self, seq: u64) -> Result<Option<ParkedMessage>, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let Some(stored) = self.state.parked.get(&seq).cloned() else {
                return Ok(None);
            };
            let plaintext = MessagePlaintext::decode(&stored.plaintext)
                .map_err(|_| AppError::Store(StoreError::Corrupt))?;
            let rules = self.protocol.opaque_members();
            let opaque: Vec<OpaqueMember<'_>> = rules
                .iter()
                .map(|rule| OpaqueMember {
                    kind: rule.kind.as_deref(),
                    member: rule.member.as_str(),
                })
                .collect();
            let message = Message::parse(plaintext.json(), &opaque).ok();
            let retry = self.state.retries.get(&seq).copied();
            Ok(Some(ParkedMessage {
                seq,
                sender: stored.sender,
                accepted_at_ms: stored.accepted_at_ms,
                reason: stored.reason,
                plaintext,
                message,
                cert: stored.cert,
                context: stored.context,
                retry_reads: retry.map_or(0, |r| r.reads),
                retrying_since_ms: retry.map(|r| r.since_ms),
            }))
        })
        .await
    }

    /// Forget the entry stored locally at `seq`, one that isn't tried again
    /// ([`ParkReason::tried_again`] is `false`), once the host and its protocol are done
    /// with it. In one commit: the entry and the count of the store's retries at it go, and
    /// its message stays processed, so a re-send of it is a duplicate, not applied (Switch
    /// spec 8.2, 11). The processed pair is written if the entry had none, and goes with
    /// the other processed pairs after their retention.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a `seq` with no entry stored, or one that is tried again;
    /// [`StoreError::Corrupt`] for a stored plaintext that doesn't decode; a store failure,
    /// after which nothing was written.
    pub async fn forget_parked(&mut self, seq: u64) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let stored = self.stored(seq)?;
            if stored.reason.tried_again() {
                return Err(Refusal::Usage(format!(
                    "the entry at seq {seq} is tried again ({:?}): it can't be forgotten",
                    stored.reason
                ))
                .into());
            }
            let plaintext = MessagePlaintext::decode(&stored.plaintext)
                .map_err(|_| AppError::Store(StoreError::Corrupt))?;
            let msg_id = self.msg_id_of(&plaintext)?;
            let mut tx = self.tx()?;
            tx.delete(&key::parked(seq))?;
            tx.delete(&key::retry(seq))?;
            let pair = key::processed(&stored.sender, &msg_id);
            if !self.reader().exists(&pair).await? {
                let now = self.now();
                processed_writes(&mut tx, &stored.sender, &msg_id, plaintext.hash(), now)?;
            }
            self.commit(tx).await?;
            self.state.parked.remove(&seq);
            self.state.retries.remove(&seq);
            Ok(())
        })
        .await
    }

    /// Release the entry stored locally at `seq` whose effect was uncertain
    /// ([`ParkReason::Uncertain`]), to be tried once more: in one commit its processed pair
    /// goes and it is stored as [`ParkReason::Released`], which a later read tries again as
    /// a fresh receive, building its effect again. The host releases it only once it knows
    /// the effect wasn't applied, such as from the shared state; a re-send of the message
    /// arriving before the run is applied as new, and the released entry is then a
    /// duplicate.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a `seq` with no entry stored, or one stored for another
    /// reason; [`StoreError::Corrupt`] for a stored plaintext that doesn't decode; a store
    /// failure, after which nothing was written.
    pub async fn release_parked(&mut self, seq: u64) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let stored = self.stored(seq)?;
            if stored.reason != ParkReason::Uncertain {
                return Err(Refusal::Usage(format!(
                    "the entry at seq {seq} is stored as {:?}, not Uncertain: it can't be \
                     released",
                    stored.reason
                ))
                .into());
            }
            let plaintext = MessagePlaintext::decode(&stored.plaintext)
                .map_err(|_| AppError::Store(StoreError::Corrupt))?;
            let msg_id = self.msg_id_of(&plaintext)?;
            let released = ParkedEntry {
                reason: ParkReason::Released,
                ..stored.clone()
            };
            let mut tx = self.tx()?;
            let pair = key::processed(&stored.sender, &msg_id);
            if let Some(processed) = self.reader().get::<Processed>(&pair).await? {
                tx.delete(&pair)?;
                tx.delete(&key::processed_at(processed.at_ms, &stored.sender, &msg_id))?;
            }
            tx.put(&key::parked(seq), &released)?;
            self.commit(tx).await?;
            self.state.parked.insert(seq, released);
            Ok(())
        })
        .await
    }

    fn stored(&self, seq: u64) -> Result<ParkedEntry, AppError> {
        self.state
            .parked
            .get(&seq)
            .cloned()
            .ok_or_else(|| no_entry(seq))
    }

    /// The `msg_id` of a stored plaintext, which its processed pair is keyed by.
    fn msg_id_of(&self, plaintext: &MessagePlaintext) -> Result<String, AppError> {
        let json: Value = serde_json::from_slice(plaintext.json())
            .map_err(|_| AppError::Store(StoreError::Corrupt))?;
        json.get("msg_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(AppError::Store(StoreError::Corrupt))
    }
}
