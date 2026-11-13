//! The entries stored locally, as a host sees and settles them (Switch spec 8.2).
//!
//! An entry the app stored locally and passed is tried again by later reads, or, for a
//! reason that isn't tried again ([`ParkReason::tried_again`]), kept until the host acts on
//! it. The host lists them ([`App::parked_entries`]), views one ([`App::parked_entry`]),
//! and either forgets one ([`App::forget_parked`]), being done with its message, or
//! releases one whose effect was uncertain to be tried once more
//! ([`App::release_parked`]). Each change is one commit.
//!
//! An entry is named by its local ID, which never changes, and the hash the listing gives
//! for it: a call whose hash doesn't match is refused, so a host never settles an entry it
//! didn't mean.

use pubky_switch_core::enc::pubky_id;
use pubky_switch_core::json::OpaqueMember;
use pubky_switch_core::message::{Message, MessagePlaintext, message_hash};
use pubky_switch_core::sig::SignedDoc;
use serde_json::Value;

use super::error::Refusal;
use super::events::Duty;
use super::events::{AppEvent, ParkReason};
use super::feed::processed_writes;
use super::state::{ParkedEntry, Processed, Tx, key};
use super::{App, AppError, AppState};
use crate::error::StoreError;

/// An entry stored locally, as [`App::parked_entries`] lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParkedSummary {
    /// The entry's local ID, its handle: it never changes, across provider changes too.
    pub stored_id: u64,
    /// The `seq` the entry was read at, in [`ParkedSummary::generation`].
    pub seq: u64,
    /// The generation it was read at.
    pub generation: u64,
    /// Why it was stored.
    pub reason: ParkReason,
    /// What [`App::forget_parked`] and [`App::release_parked`] check the entry by: the
    /// message hash (Switch wire 5.1), or, for a stored plaintext that doesn't read as a
    /// message ([`ParkedSummary::readable`] `false`), the same hash of the bytes as stored.
    pub hash: [u8; 32],
    /// Whether the stored plaintext reads as a signed message with a `msg_id`. One that
    /// doesn't reads as corrupt: it can't run again, and can only be forgotten.
    pub readable: bool,
}

/// An entry stored locally (Switch spec 8.2), as [`App::parked_entry`] shows it: why, the
/// message as the protocol is handed it, and the reads in a row its receive step couldn't
/// finish. Sensitive: its `Debug` shows neither the plaintext nor the body.
#[derive(Clone)]
#[non_exhaustive]
pub struct ParkedMessage {
    /// The entry's local ID, which never changes.
    pub stored_id: u64,
    /// The `seq` the entry was read at, in [`ParkedMessage::generation`].
    pub seq: u64,
    /// The generation it was read at. Two stored entries can share a `seq` from different
    /// generations, since a provider loss starts a new sequence; the pair names the feed
    /// position, and [`ParkedMessage::stored_id`] the entry.
    pub generation: u64,
    /// The sender identity.
    pub sender: [u8; 32],
    /// Whether the app checked the sender's standing before the entry was stored: `false`
    /// for an entry stored as [`ParkReason::Unverifiable`], whose signing app wasn't
    /// checked against the sender identity's `identity.json`. A host doesn't show such
    /// content as from a verified sender. Every other entry passed the app's checks of
    /// the sender before it was stored: one stored as [`ParkReason::StoreUnavailable`] was
    /// stored because the protocol's receive step couldn't finish, after those checks.
    pub sender_verified: bool,
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
        out.field("stored_id", &self.stored_id)
            .field("seq", &self.seq)
            .field("sender", &pubky_id(&self.sender))
            .field("sender_verified", &self.sender_verified)
            .field("accepted_at_ms", &self.accepted_at_ms)
            .field("reason", &self.reason);
        if let Some(message) = &self.message {
            out.field("kind", &message.kind)
                .field("msg_id", &message.msg_id);
        }
        out.field("retry_reads", &self.retry_reads).finish()
    }
}

/// A stored entry's plaintext as a message: its plaintext and its `msg_id`.
struct Opened {
    plaintext: MessagePlaintext,
    msg_id: String,
}

/// `None` for stored bytes that don't read as a message with a `msg_id`.
fn opened(stored: &ParkedEntry) -> Option<Opened> {
    let plaintext = MessagePlaintext::decode(&stored.plaintext).ok()?;
    let json: Value = serde_json::from_slice(plaintext.json()).ok()?;
    let msg_id = json.get("msg_id")?.as_str()?.to_owned();
    Some(Opened { plaintext, msg_id })
}

/// The `msg_id` of the message an entry stored locally holds; `None` for stored bytes that
/// don't read as a message with one.
pub(crate) fn stored_msg_id(stored: &ParkedEntry) -> Option<String> {
    opened(stored).map(|opened| opened.msg_id)
}

fn summary(id: u64, stored: &ParkedEntry) -> ParkedSummary {
    let opened = opened(stored);
    ParkedSummary {
        stored_id: id,
        seq: stored.seq,
        generation: stored.generation,
        reason: stored.reason,
        hash: opened.as_ref().map_or_else(
            || message_hash(&stored.plaintext),
            |opened| opened.plaintext.hash(),
        ),
        readable: opened.is_some(),
    }
}

/// The local ID a kept duty event names, for those that name an entry stored locally.
fn names_stored(event: &AppEvent) -> Option<u64> {
    match event {
        AppEvent::Parked {
            id: Some(_),
            stored_id,
            ..
        }
        | AppEvent::EffectRefused { stored_id, .. }
        | AppEvent::EffectUncertain { stored_id, .. } => Some(*stored_id),
        _ => None,
    }
}

impl App {
    /// The entries stored locally, in local ID order, which is the order they were stored
    /// in.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn parked_entries(&mut self) -> Result<Vec<ParkedSummary>, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            Ok(self
                .state
                .parked
                .iter()
                .map(|(id, stored)| summary(*id, stored))
                .collect())
        })
        .await
    }

    /// The entry stored locally at local ID `id`, `None` when there is none.
    ///
    /// # Errors
    ///
    /// A store failure; [`StoreError::Corrupt`] for a stored plaintext that doesn't decode
    /// ([`ParkedSummary::readable`]).
    pub async fn parked_entry(&mut self, id: u64) -> Result<Option<ParkedMessage>, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let Some(stored) = self.state.parked.get(&id).cloned() else {
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
            let retry = self.state.stored_retries.get(&id).copied();
            Ok(Some(ParkedMessage {
                stored_id: id,
                seq: stored.seq,
                generation: stored.generation,
                sender: stored.sender,
                sender_verified: stored.reason != ParkReason::Unverifiable,
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

    /// Forget the entry stored locally at local ID `id`, whose [`ParkedSummary::hash`] is
    /// `hash`: the host and its protocol are done with its message (Switch spec 8.2). Any
    /// stored entry may be forgotten, whatever it was stored for, tried again or not.
    /// Returns how many entries went: forgetting is being done with the message, so every
    /// entry stored for it goes in the same commit. Nothing brings a forgotten entry back:
    /// a host that might want the message later, for example once the cause of a refusal
    /// is fixed, doesn't forget it.
    ///
    /// **The entries stored for the message.** For a named entry whose sender's standing
    /// was checked and that reads as a message, those with the same sender identity and
    /// `msg_id`, as the app's processed pairs name a message. For one stored as
    /// [`ParkReason::Unverifiable`], only those with the same message hash: the identity
    /// signed it, but whether the signing app is current in its `identity.json` wasn't
    /// checked, so its `msg_id` alone doesn't say which message of that identity it is. For
    /// one that doesn't read as a message ([`ParkedSummary::readable`] `false`), only those
    /// whose stored bytes have the same hash.
    ///
    /// **The message stays processed,** so a re-send of it is a duplicate, not applied
    /// (Switch spec 8.2, 11), unless none of the entries that go had its sender's standing
    /// checked and read as a message. The processed pair is written if none is kept, from
    /// such an entry, and goes with the other processed pairs after their retention.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`], with nothing written, while the effect a retry of an entry that
    /// would go built is kept unanswered (Switch spec 12.5 "Kept batches"): it may still
    /// apply, so the read that settles it decides, and the host tries again once one has.
    /// The entry is then processed, gone, or stored again for what its effect came to.
    ///
    /// [`Refusal::Usage`], with nothing written:
    /// - for an ID with no entry stored, or a `hash` that isn't the entry's;
    /// - while a duty event the host hasn't acknowledged ([`App::ack_events`]) names an
    ///   entry that would go ([`AppEvent::Parked`], [`AppEvent::EffectRefused`],
    ///   [`AppEvent::EffectUncertain`]): those carry no content, so a protocol that hasn't
    ///   acted on one yet would lose the message.
    ///
    /// A store failure, after which nothing was written.
    pub async fn forget_parked(&mut self, id: u64, hash: &[u8; 32]) -> Result<u64, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let stored = self.stored(id, hash)?;
            let named = opened(&stored);
            let named_checked = stored.reason != ParkReason::Unverifiable;
            // Every entry stored for the message, the named one first.
            let mut going = vec![id];
            for (other, copy) in &self.state.parked {
                if *other == id || copy.sender != stored.sender {
                    continue;
                }
                let same = match (&named, opened(copy)) {
                    (Some(this), Some(copy)) if named_checked => copy.msg_id == this.msg_id,
                    (Some(this), Some(copy)) => copy.plaintext.hash() == this.plaintext.hash(),
                    (None, None) => copy.plaintext == stored.plaintext,
                    _ => false,
                };
                if same {
                    going.push(*other);
                }
            }
            // An effect a retry of one of them built and kept, unanswered, may still apply:
            // the read that settles it decides, not the forget.
            if let Some(kept) = self
                .state
                .pending_effect
                .as_ref()
                .and_then(|pending| pending.stored)
                .filter(|kept| going.contains(kept))
            {
                return Err(Refusal::NotNow(format!(
                    "the effect of the entry at local ID {kept} is kept unanswered: try again \
                     once a read has settled it"
                ))
                .into());
            }
            let kept = self.kept_duties().await?;
            if let Some(named) = kept
                .iter()
                .filter_map(names_stored)
                .find(|named| going.contains(named))
            {
                return Err(Refusal::Usage(format!(
                    "a duty event not acknowledged yet names the entry at local ID {named}: \
                     it can't be forgotten before the protocol acts on it"
                ))
                .into());
            }
            // The message stays processed if one of the entries had its sender's standing
            // checked and reads as a message.
            let checked = going.iter().find_map(|gone| {
                let entry = self.state.parked.get(gone)?;
                if entry.reason == ParkReason::Unverifiable {
                    return None;
                }
                opened(entry).map(|opened| (entry.sender, opened))
            });
            let mut tx = self.tx()?;
            for gone in &going {
                tx.delete(&key::parked(*gone))?;
                tx.delete(&key::stored_retry(*gone))?;
            }
            if let Some((sender, this)) = checked {
                let pair = key::processed(&sender, &this.msg_id);
                if !self.reader().exists(&pair).await? {
                    let now = self.now();
                    let hash = this.plaintext.hash();
                    processed_writes(&mut tx, &sender, &this.msg_id, hash, now)?;
                }
            }
            self.commit(tx).await?;
            for gone in &going {
                self.state.parked.remove(gone);
                self.state.stored_retries.remove(gone);
            }
            Ok(u64::try_from(going.len()).unwrap_or(u64::MAX))
        })
        .await
    }

    /// Release the entry stored locally at local ID `id`, whose [`ParkedSummary::hash`] is
    /// `hash`, after its effect was uncertain ([`ParkReason::Uncertain`]), to be tried once
    /// more: in one commit its processed pair goes and it is stored as
    /// [`ParkReason::Released`], which a later read tries again as a fresh receive,
    /// building its effect again, with [`super::ReceivedMessage::released`] set so the
    /// protocol may decline. The service refuses the effect again where an operation
    /// depends on what its first application changed, such as a record write's expected
    /// version or a claim's step; otherwise its operations, and its local writes, may apply
    /// twice (Switch spec 8.2).
    ///
    /// The host releases it only once it knows the effect wasn't applied, such as from the
    /// shared state. A re-send of the message arriving before the run is applied as new,
    /// and the released entry is then a duplicate, reported with
    /// [`AppEvent::ReleasedDuplicate`], a duty event.
    ///
    /// A release can repeat: a released run whose effect is kept unanswered past the window
    /// again is stored as [`ParkReason::Uncertain`] again, and may be released again. Each
    /// run is bounded by that window, not by a count of releases.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an ID with no entry stored, a `hash` that isn't the entry's,
    /// or an entry stored for another reason; [`StoreError::Corrupt`] for a stored
    /// plaintext that doesn't read as a message; a store failure, after which nothing was
    /// written.
    pub async fn release_parked(&mut self, id: u64, hash: &[u8; 32]) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let stored = self.stored(id, hash)?;
            if stored.reason != ParkReason::Uncertain {
                return Err(Refusal::Usage(format!(
                    "the entry at local ID {id} is stored as {:?}, not Uncertain: it can't \
                     be released",
                    stored.reason
                ))
                .into());
            }
            let msg_id = opened(&stored)
                .ok_or(AppError::Store(StoreError::Corrupt))?
                .msg_id;
            let released = ParkedEntry {
                reason: ParkReason::Released,
                released: true,
                ..stored.clone()
            };
            let mut tx = self.tx()?;
            let pair = key::processed(&stored.sender, &msg_id);
            if let Some(processed) = self.reader().get::<Processed>(&pair).await? {
                tx.delete(&pair)?;
                tx.delete(&key::processed_at(processed.at_ms, &stored.sender, &msg_id))?;
            }
            tx.put(&key::parked(id), &released)?;
            self.commit(tx).await?;
            self.state.parked.insert(id, released);
            Ok(())
        })
        .await
    }

    /// The entry stored at `id`, if `hash` is its [`ParkedSummary::hash`].
    fn stored(&self, id: u64, hash: &[u8; 32]) -> Result<ParkedEntry, AppError> {
        let stored = self.state.parked.get(&id).ok_or_else(|| {
            AppError::from(Refusal::Usage(format!(
                "no entry is stored locally at local ID {id}"
            )))
        })?;
        if summary(id, stored).hash != *hash {
            return Err(Refusal::Usage(format!(
                "the entry stored at local ID {id} has another hash: it isn't the one named"
            ))
            .into());
        }
        Ok(stored.clone())
    }
}

/// How many entries a restore brought back one commit tells the protocol of again.
const RETELL_PER_COMMIT: usize = 64;

/// `retell`: telling the protocol again of the entries stored for good that a restore
/// brought back (Switch spec 12.4), from local ID `next` up to `until`, the IDs the
/// restore installed. Each step keeps a [`AppEvent::Parked`] duty event for at most
/// [`RETELL_PER_COMMIT`] of them and moves `next` past them in the same commit, so a crash
/// between steps tells none twice and none not at all; the last step deletes it. An entry a
/// duty event already kept in the store names isn't told again, as after a restore in place
/// that carried it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Retell {
    next: u64,
    until: u64,
}

impl Retell {
    /// Start telling, in the restore's commit, if it brings back an entry stored for good.
    pub(crate) fn start(state: &AppState, tx: &mut Tx) -> Result<(), AppError> {
        if state
            .parked
            .values()
            .any(|stored| !stored.reason.tried_again())
        {
            let retell = Retell {
                next: 0,
                until: state.next_stored_id,
            };
            tx.put(key::RETELL, &retell)?;
        }
        Ok(())
    }
}

impl App {
    /// Tell the protocol again of the entries stored for good a restore brought back, in
    /// steps ([`Retell`]).
    pub(crate) async fn retell_restored(&mut self) -> Result<(), AppError> {
        loop {
            let Some(mut retell) = self.reader().get::<Retell>(key::RETELL).await? else {
                return Ok(());
            };
            let named: std::collections::BTreeSet<u64> = self
                .kept_duties()
                .await?
                .iter()
                .filter_map(names_stored)
                .collect();
            let step: Vec<(u64, ParkedEntry)> = self
                .state
                .parked
                .range(retell.next..retell.until)
                .filter(|(_, stored)| !stored.reason.tried_again())
                .take(RETELL_PER_COMMIT)
                .map(|(id, stored)| (*id, stored.clone()))
                .collect();
            let mut tx = self.tx()?;
            for (id, stored) in &step {
                if named.contains(id) {
                    continue;
                }
                self.keep_duty(
                    &mut tx,
                    Duty::Parked {
                        seq: stored.seq,
                        stored_id: *id,
                        reason: stored.reason,
                    },
                )?;
            }
            match step.last() {
                Some((last, _)) if step.len() == RETELL_PER_COMMIT => {
                    retell.next = last.saturating_add(1);
                    tx.put(key::RETELL, &retell)?;
                }
                _ => tx.delete(key::RETELL)?,
            }
            self.commit(tx).await?;
        }
    }
}
