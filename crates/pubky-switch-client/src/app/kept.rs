//! What became of a batch the app kept (`opq/`), read from the store after any restart
//! (Switch spec 6.4, 12.5 "Kept batches"; Switch wire 6.4 step 5).
//!
//! A kept batch has one ID for its whole life: the batch ID it was first signed and kept
//! under. Signing it again, for a later generation or after a provider change, changes the
//! batch ID its signed bytes carry on the wire, never the ID it is kept under, so every
//! error, event and read names the same one ([`App::kept_batch`]).
//!
//! The commit that applies or drops a kept batch also writes its end (`kb/<batch_id>`): when,
//! by the app's clock, and whether it was applied or dropped and why. The end is answered
//! for [`SENT_RETENTION_MS`] from that time, as a failed outbox message is, and forgotten at
//! the flush after ([`App::flush_outbox`]). The commit that keeps a batch indexes the
//! messages it queues (`kbm/<msg_id>`) and the attempts it carries (`kba/`) by its ID, so
//! [`App::delivery`] and [`App::kept_attempt`] answer them without a mapping of the
//! caller's own.

use pubky_switch_core::enc::{b64, serde_b64};
use serde::{Deserialize, Serialize};

use super::batch::{PendingBatch, pending_key};
use super::events::ClaimAttempt;
use super::provider::attempts_in;
use super::send::{Delivery, SENT_RETENTION_MS};
use super::state::{Tx, key};
use super::{App, AppError};
use crate::client::Batch;

/// The prefix of the ends of kept batches, by batch ID.
const END_PREFIX: &str = "kb/";
/// The prefix of the time index of those ends.
const END_TIME_PREFIX: &str = "kbt/";
/// The prefix of the messages kept batches queue, by `msg_id`.
const MESSAGE_PREFIX: &str = "kbm/";
/// The prefix of the attempts kept batches carry, by claim key and attempt ID.
const ATTEMPT_PREFIX: &str = "kba/";

fn end_key(batch_id: &[u8; 16]) -> String {
    format!("{END_PREFIX}{}", b64(batch_id))
}

fn end_time_key(at_ms: u64, batch_id: &[u8; 16]) -> String {
    format!("{END_TIME_PREFIX}{}/{}", key::num(at_ms), b64(batch_id))
}

fn message_key(msg_id: &str) -> String {
    format!("{MESSAGE_PREFIX}{msg_id}")
}

fn attempt_key(attempt: &ClaimAttempt) -> String {
    format!(
        "{ATTEMPT_PREFIX}{}/{}",
        b64(&attempt.claim_key),
        b64(&attempt.attempt_id)
    )
}

/// What became of a kept batch ([`App::kept_batch`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeptBatchStatus {
    /// Still kept, to be sent again, the same bytes, by the next call that writes and the
    /// next read (Switch wire 6.4 step 5).
    Kept {
        /// The batch ID its signed bytes carry now: the one it is kept under, or another
        /// once it was signed again ([`super::AppEvent::KeptBatchSignedAgain`]).
        wire_batch_id: [u8; 16],
        /// When the first send of its current bytes left, at a verified service time;
        /// `None` while they were never sent. Bytes signed again at a provider change start
        /// unsent, though earlier bytes may have been sent: after a move that read the old
        /// chain to its end, they weren't applied; after a provider loss, a batch without
        /// an `attempt` is signed again even if it was sent at the lost service, so whether
        /// those earlier bytes applied there can't be told.
        sent_at_ms: Option<u64>,
    },
    /// Applied: what it settles is committed.
    Applied {
        /// When the app committed it, app clock.
        applied_at_ms: u64,
    },
    /// Dropped, never to be sent again, with the local writes and outbox messages it
    /// carried.
    Dropped {
        /// When the app dropped it, app clock.
        dropped_at_ms: u64,
        /// Why.
        reason: KeptBatchDrop,
    },
}

/// Why a kept batch was dropped ([`KeptBatchStatus::Dropped`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeptBatchDrop {
    /// Refused for good with this error code at or after the service's batch ID lookup
    /// (Switch wire 6.4): never applied ([`super::AppEvent::BatchRefused`]).
    Refused {
        /// The error code.
        code: String,
    },
    /// Dropped before it was ever sent: never applied
    /// ([`super::AppEvent::KeptBatchDropped`]).
    Unsent,
    /// Dropped after a send whose answer can't tell whether it was applied, such as one
    /// past the window in which a resend tells (Switch spec 12.5 "Kept batches"): the
    /// protocol treats its attempts as uncertain ([`super::AppEvent::KeptBatchDropped`]).
    Uncertain,
}

impl KeptBatchDrop {
    /// Why a message the batch would have queued failed ([`Delivery::Failed`]).
    fn message_reason(&self) -> String {
        match self {
            Self::Refused { code } => format!("the batch carrying it was refused: {code}"),
            Self::Unsent | Self::Uncertain => "the batch carrying it was dropped".into(),
        }
    }
}

/// A kept batch named by one of its attempts ([`App::kept_attempt`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptBatch {
    /// The batch ID it is kept under.
    pub batch_id: [u8; 16],
    /// What became of it.
    pub status: KeptBatchStatus,
}

/// How a kept batch ended, as `kb/<batch_id>` keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Ended {
    Applied,
    Dropped(KeptBatchDrop),
}

/// `kb/<batch_id>`: the end of a kept batch, and what it named, to forget with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct KeptBatchEnd {
    at_ms: u64,
    ended: Ended,
    msg_ids: Vec<String>,
    attempts: Vec<ClaimAttempt>,
}

/// `kbm/<msg_id>` and `kba/<claim_key>/<attempt_id>`: the kept batch that names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct KeptIndex {
    #[serde(with = "serde_b64")]
    batch_id: [u8; 16],
}

/// Index the messages `pending` queues and the attempts `batch` carries by `batch_id`, in
/// `tx`, the commit that keeps it. A later kept batch naming one takes it over.
pub(crate) fn index_kept(
    tx: &mut Tx,
    batch_id: &[u8; 16],
    pending: &PendingBatch,
    batch: &Batch,
) -> Result<(), AppError> {
    let index = KeptIndex {
        batch_id: *batch_id,
    };
    for item in &pending.queued {
        tx.put(&message_key(item.msg_id()), &index)?;
    }
    for attempt in attempts_in(batch) {
        tx.put(&attempt_key(&attempt), &index)?;
    }
    Ok(())
}

impl App {
    /// Index the messages and attempts of every kept batch that names one with no index
    /// entry, as a batch an earlier build kept does, in one commit at load: so
    /// [`App::kept_attempt`] and [`App::delivery`] find a batch the store keeps, and a
    /// caller never reads one still to be sent as unknown. An entry a later batch took over
    /// is left as it is. The kept batches are at most [`super::MAX_KEPT_BATCHES_BYTES`], so
    /// the commit is bounded; a store with nothing to index commits nothing.
    pub(crate) async fn index_kept_batches(&mut self) -> Result<(), AppError> {
        let kept = self.kept_batches().await?;
        if kept.is_empty() {
            return Ok(());
        }
        let reader = self.reader();
        let mut tx = self.tx()?;
        let mut indexed = std::collections::BTreeSet::new();
        for (batch_id, pending) in kept {
            let batch = Batch::from_body(pending.body.clone())?;
            let index = KeptIndex { batch_id };
            let attempts = attempts_in(&batch);
            let keys = pending
                .queued
                .iter()
                .map(|item| message_key(item.msg_id()))
                .chain(attempts.iter().map(attempt_key));
            for key in keys {
                if !indexed.contains(&key) && !reader.exists(&key).await? {
                    tx.put(&key, &index)?;
                    indexed.insert(key);
                }
            }
        }
        if !tx.is_empty() {
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// End the batch kept under `batch_id` in `tx`: it is no longer kept, and its end is
    /// written in the same commit, at the app's clock.
    pub(crate) fn end_kept_batch(
        &self,
        batch_id: &[u8; 16],
        pending: &PendingBatch,
        ended: Ended,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let at_ms = self.now();
        let batch = Batch::from_body(pending.body.clone())?;
        let end = KeptBatchEnd {
            at_ms,
            ended,
            msg_ids: pending
                .queued
                .iter()
                .map(|item| item.msg_id().to_owned())
                .collect(),
            attempts: attempts_in(&batch),
        };
        tx.delete(&pending_key(batch_id))?;
        tx.put(&end_key(batch_id), &end)?;
        tx.put(&end_time_key(at_ms, batch_id), &())
    }

    /// Whether an end at `at_ms` is past its retention, as a failed outbox message is.
    fn past_retention(&self, at_ms: u64) -> bool {
        at_ms <= self.now().saturating_sub(SENT_RETENTION_MS)
    }

    /// What became of the batch kept under `batch_id`, the ID [`super::AppError::Kept`],
    /// [`super::AppEvent::BatchRefused`], [`super::AppEvent::KeptBatchDropped`],
    /// [`super::AppEvent::KeptBatchApplied`] and [`super::AppEvent::KeptBatchSignedAgain`]
    /// name: still kept, or applied or dropped, with when and why, for
    /// [`SENT_RETENTION_MS`] after. `None` for a batch this store keeps nothing of: never
    /// kept here, ended longer ago, or kept before a restore or a leave.
    ///
    /// # Errors
    ///
    /// A store failure, or a kept batch that doesn't read.
    pub async fn kept_batch(
        &self,
        batch_id: [u8; 16],
    ) -> Result<Option<KeptBatchStatus>, AppError> {
        let reader = self.reader();
        if let Some(pending) = reader.get::<PendingBatch>(&pending_key(&batch_id)).await? {
            let wire_batch_id = Batch::from_body(pending.body)?
                .id()
                .ok_or_else(|| AppError::InvalidData("a batch of operations has an ID".into()))?;
            return Ok(Some(KeptBatchStatus::Kept {
                wire_batch_id,
                sent_at_ms: pending.kept_ms,
            }));
        }
        let Some(end) = reader.get::<KeptBatchEnd>(&end_key(&batch_id)).await? else {
            return Ok(None);
        };
        if self.past_retention(end.at_ms) {
            return Ok(None);
        }
        Ok(Some(match end.ended {
            Ended::Applied => KeptBatchStatus::Applied {
                applied_at_ms: end.at_ms,
            },
            Ended::Dropped(reason) => KeptBatchStatus::Dropped {
                dropped_at_ms: end.at_ms,
                reason,
            },
        }))
    }

    /// The kept batch that carries `attempt`, and what became of it, as
    /// [`App::kept_batch`] answers: whether the attempt may still be applied by a resend,
    /// was applied, or was dropped. The latest batch kept with it answers. `None` for an
    /// attempt no batch this store keeps, or ended within [`SENT_RETENTION_MS`], carries.
    /// `None` never says the attempt was never sent: a batch ended longer ago, or kept
    /// before a restore, isn't known here, and an attempt written another way never was.
    /// The protocol reads the claim then ([`App::read_claim`]).
    ///
    /// # Errors
    ///
    /// A store failure, or a kept batch that doesn't read.
    pub async fn kept_attempt(&self, attempt: ClaimAttempt) -> Result<Option<KeptBatch>, AppError> {
        let Some(index) = self
            .reader()
            .get::<KeptIndex>(&attempt_key(&attempt))
            .await?
        else {
            return Ok(None);
        };
        Ok(self
            .kept_batch(index.batch_id)
            .await?
            .map(|status| KeptBatch {
                batch_id: index.batch_id,
                status,
            }))
    }

    /// Where a message a kept batch queues is, when the outbox and the sent messages hold
    /// nothing of it: [`Delivery::Kept`] while the batch is kept, [`Delivery::Failed`] with
    /// the drop's time once it is dropped; `None` otherwise.
    pub(crate) async fn kept_delivery(&self, msg_id: &str) -> Result<Option<Delivery>, AppError> {
        let Some(index) = self.reader().get::<KeptIndex>(&message_key(msg_id)).await? else {
            return Ok(None);
        };
        Ok(match self.kept_batch(index.batch_id).await? {
            Some(KeptBatchStatus::Kept { .. }) => Some(Delivery::Kept {
                batch_id: index.batch_id,
            }),
            Some(KeptBatchStatus::Dropped {
                dropped_at_ms,
                reason,
            }) => Some(Delivery::Failed {
                reason: reason.message_reason(),
                failed_at_ms: dropped_at_ms,
            }),
            Some(KeptBatchStatus::Applied { .. }) | None => None,
        })
    }

    /// Forget the ends of kept batches past their retention, oldest first, with the index
    /// entries that still name them, in one commit.
    pub(crate) async fn prune_kept_ends(&mut self) -> Result<(), AppError> {
        let cutoff = self.now().saturating_sub(SENT_RETENTION_MS);
        let reader = self.reader();
        let mut tx = self.tx()?;
        for (rest, ()) in reader.scan::<()>(END_TIME_PREFIX).await? {
            let Some((at, id)) = rest.split_once('/') else {
                continue;
            };
            let Ok(at_ms) = super::state::parse_num(at) else {
                continue;
            };
            if at_ms > cutoff {
                break;
            }
            let Ok(batch_id) = pubky_switch_core::enc::unb64_array::<16>(id) else {
                continue;
            };
            if let Some(end) = reader.get::<KeptBatchEnd>(&end_key(&batch_id)).await? {
                let names = |index: Option<KeptIndex>| {
                    index.is_some_and(|index| index.batch_id == batch_id)
                };
                for msg_id in &end.msg_ids {
                    let key = message_key(msg_id);
                    if names(reader.get(&key).await?) {
                        tx.delete(&key)?;
                    }
                }
                for attempt in &end.attempts {
                    let key = attempt_key(attempt);
                    if names(reader.get(&key).await?) {
                        tx.delete(&key)?;
                    }
                }
                tx.delete(&end_key(&batch_id))?;
            }
            tx.delete(&end_time_key(at_ms, &batch_id))?;
        }
        if !tx.is_empty() {
            self.commit(tx).await?;
        }
        Ok(())
    }
}
