//! Batches of operations with conditions (Switch spec 10.1, 13.5; Switch wire 6.3, 6.4), as
//! the app writes them for its own calls and for the protocol's effects.
//!
//! [`OpBatch`] is a small builder over the core's operations: each operation with the
//! conditions checked atomically with it. [`App::submit_batch`] signs a batch once, carries
//! the app's deferred cursor move in it when there is room (Switch spec 8.2), keeps the exact
//! body under `opq/<batch_id>` before it is first sent, sends those bytes until the switch
//! answers, and commits what the answer settles with the cursor:
//!
//! - a shared record write is cached at the version its transition proof gives (Switch wire
//!   6.2), with its sealed value opened by the app's own keys;
//! - a claim entry's proof and view are kept as evidence (Switch spec 6.3, 10.2);
//! - allowlist, deny list and invite code changes update what the app keeps of them.
//!
//! A batch the switch refuses for good is dropped: it was not applied, and the caller decides
//! what to write instead, except after `409 stale_epoch`, when the app seals its record
//! writes again at the new data epoch and sends it once more ([`App::submit_batch`]); one
//! sent again from an earlier call is reported as
//! [`AppEvent::BatchRefused`]. A batch whose answer didn't come back, or may pass unchanged
//! later (`429`, `503`, `401 stale_timestamp`, an answer that doesn't verify), stays kept,
//! and the next call that writes, and the next read before its feed, sends it again, the
//! same bytes, so the service answers it as a retry (Switch spec 6.4; Switch wire 2.1, 6.4
//! step 5).

use pubky_switch_core::chain::TransitionProof;
use pubky_switch_core::claims::{ClaimEntry, ClaimType, ClaimView, EntryKind};
use pubky_switch_core::enc::{b64, serde_b64_vec};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{Condition, MAX_BATCH_ENTRIES, OpKind, RecordVersion, SignedOp};
use pubky_switch_core::sealed::{RecordValue, SealedValue};
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};

use super::claims::ObligationDeadline;
use super::error::{KeptAhead, Refusal, RefusalPlace, refused_at, refused_for_good};
use super::events::AppEvent;
use super::kept::{Ended, KeptBatchDrop, index_kept};
use super::protocol::{LocalWrite, MAX_STEP_LOCAL_BYTES, local_writes_bytes};
use super::recovery::LossStep;
use super::send::{OutboxItem, SignedMessage};
use super::state::{Tx, key};
use super::{App, AppError};
use crate::client::{Batch, Submitted};
use crate::error::ClientError;

/// The prefix of the kept batches.
const PENDING_PREFIX: &str = "opq/";

/// The most bytes the batches kept unanswered (`opq/`) take together, as stored:
/// [`App::submit_batch`] keeps no batch past it. A provider change carries every kept batch
/// in its one commit, signed again or settled (Switch spec 12.5 "Kept batches"), so this
/// bounds that commit: the change's own records (under 2 MiB: `meta`, the cursor and chain
/// view, the move or loss record with its re-registration batch, the receive keys), the
/// kept effect's outcome (its local writes, at most 4 MiB, `MAX_STEP_LOCAL_BYTES`; a
/// settle without proofs caches no record), and the kept batches, each either signed again
/// at about its own size or settled into its local writes and queued messages, both under
/// its stored size plus 80 bytes, a fifth of the smallest batch: at most 1.2 x 12 MiB =
/// 14.4 MiB. Under 21 MiB in all, below the 32 MiB batch size. One batch at the largest it
/// can be, under 10.9 MiB kept (`MAX_STEP_LOCAL_BYTES`), always fits on its own.
pub const MAX_KEPT_BATCHES_BYTES: usize = 12 * 1024 * 1024;

// A batch's answer is settled in one commit: its local writes and queued messages (under
// its stored size, itself under `MAX_KEPT_BATCHES_BYTES`), a cached record write with its
// mark for each of its 8 operations at most, and the cursor, the chain view and the kept
// batch removed (under 1 MiB).
const _: () = assert!(
    MAX_KEPT_BATCHES_BYTES as u64
        + MAX_BATCH_ENTRIES as u64
            * (super::feed::CACHED_RECORD_BYTES + super::feed::KEPT_MARK_BYTES)
        + (1 << 20)
        <= crate::store::MAX_BATCH_BYTES
);

/// Refuse the app's own lifecycle operations, and the signer's, in a batch a host or a
/// protocol builds: `app.put`, `receive_key.put`, `key_bundle.put` and `cert.put`. The app
/// layer builds and sends these itself, in batches of their own (joining, the record's
/// delivery, a registration, a move's or a loss's re-registration), and a kept effect or
/// batch carrying one could be refused at step 9 in a way that reads as about the caller
/// ([`RefusalPlace::Caller`]).
///
/// # Errors
///
/// [`Refusal::Usage`] for such an operation.
pub(crate) fn refuse_lifecycle_ops<'a>(
    mut kinds: impl Iterator<Item = &'a OpKind>,
) -> Result<(), AppError> {
    if kinds.any(|kind| {
        matches!(
            kind,
            OpKind::AppPut { .. }
                | OpKind::ReceiveKeyPut { .. }
                | OpKind::KeyBundlePut(_)
                | OpKind::CertPut { .. }
        )
    }) {
        return Err(Refusal::Usage(
            "app.put, receive_key.put, key_bundle.put and cert.put are the app layer's own".into(),
        )
        .into());
    }
    Ok(())
}

/// Whether `error` refuses a batch for good before the service's batch ID lookup, about the
/// caller or about these bytes ([`RefusalPlace`]).
fn refused_before_lookup(error: &AppError) -> bool {
    matches!(
        refused_at(error),
        Some(RefusalPlace::Caller | RefusalPlace::Bytes)
    )
}

/// The most kept batches one read of the feed sends again before the feed
/// ([`App::receive`]), oldest first: the rest go at the next read, in the same order, and
/// the read says so ([`super::ReceiveReport::more`]).
pub const KEPT_RESENDS_PER_READ: usize = 4;

/// The most batches kept from earlier calls that a write sends again before its own
/// ([`App::submit_batch`]): with more kept, its own batch is kept behind them.
pub const KEPT_RESENDS_PER_WRITE: usize = 1;

/// The next creation number of a kept batch ([`PendingBatch::queued_n`]).
const KEPT_NEXT: &str = "keptn";

/// The order kept batches go in, so no write overtakes an earlier one: the order the calls
/// kept them in, by their creation number ([`PendingBatch::queued_n`]), whether or not they
/// were sent before. A batch's creation number never changes, so its place holds through a
/// first send, a signing again and a provider change. Batches an earlier build kept carry
/// none, and go first: before any numbered batch, which was kept after them, and among
/// themselves those sent before by their first send's time, then those never sent, each
/// group by ID.
fn kept_order(
    (id, pending): &([u8; 16], PendingBatch),
) -> (bool, Option<u64>, bool, Option<u64>, [u8; 16]) {
    (
        pending.queued_n.is_some(),
        pending.queued_n,
        pending.kept_ms.is_none(),
        pending.kept_ms,
        *id,
    )
}

/// `opq/<batch_id>`: a kept batch, under the batch ID it was first kept under, whatever ID
/// its bytes carry once signed again (`kept.rs`).
pub(crate) fn pending_key(batch_id: &[u8; 16]) -> String {
    format!("{PENDING_PREFIX}{}", b64(batch_id))
}

/// A batch of operations, each with its conditions (Switch wire 6.3, 6.4): at most 8 entries,
/// a carried cursor move counting toward them.
#[derive(Clone, Debug, Default)]
pub struct OpBatch {
    ops: Vec<(Vec<Condition>, OpKind)>,
    invites: Vec<InviteNote>,
    deadlines: Vec<([u8; 32], ObligationDeadline)>,
    local: Vec<LocalWrite>,
    queued: Vec<SignedMessage>,
}

/// An invite code registered in a batch, kept by the app once the switch takes it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InviteNote {
    pub(crate) code_hash: String,
    pub(crate) code: String,
}

impl std::fmt::Debug for InviteNote {
    // The code is a bearer secret (Switch spec 7).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InviteNote({})", self.code_hash)
    }
}

impl OpBatch {
    /// An empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an operation without conditions.
    pub fn op(self, kind: OpKind) -> Self {
        self.op_if(kind, Vec::new())
    }

    /// Add an operation with its conditions, checked against the state before the batch
    /// (Switch wire 6.3).
    pub fn op_if(mut self, kind: OpKind, conditions: Vec<Condition>) -> Self {
        self.ops.push((conditions, kind));
        self
    }

    /// Add an operation as built elsewhere, such as by [`App::record_op`].
    pub fn entry(mut self, entry: (Vec<Condition>, OpKind)) -> Self {
        self.ops.push(entry);
        self
    }

    /// Add a condition to the last operation; nothing without one.
    pub fn when(mut self, condition: Condition) -> Self {
        if let Some((conditions, _)) = self.ops.last_mut() {
            conditions.push(condition);
        }
        self
    }

    /// The deadline the app computes itself for the obligation of `claim_key`, kept with
    /// the claim's evidence once the switch takes the batch (Switch wire 6.8).
    pub fn obligation_deadline(
        mut self,
        claim_key: [u8; 32],
        deadline: ObligationDeadline,
    ) -> Self {
        self.deadlines.push((claim_key, deadline));
        self
    }

    /// A write of the protocol's own local state, committed once the switch applies the
    /// batch, with what its answer settles; never if the batch is refused (`STATE.md`).
    pub fn local(mut self, write: LocalWrite) -> Self {
        self.local.push(write);
        self
    }

    /// Writes of the protocol's own local state, as [`OpBatch::local`].
    pub fn locals(mut self, writes: impl IntoIterator<Item = LocalWrite>) -> Self {
        self.local.extend(writes);
        self
    }

    /// A message signed by [`App::sign_message`], put in the outbox once the switch applies
    /// the batch, with what its answer settles (Switch spec 8.2, 11). The batch is kept with
    /// it before it is first sent, so a crash never loses the message once the batch may
    /// have been applied; a batch refused for good queues nothing, and the caller may put
    /// the same signed message in the batch it builds again. The outbox then delivers it
    /// ([`App::flush_outbox`], [`App::flush_message`]).
    pub fn queue(mut self, message: SignedMessage) -> Self {
        self.queued.push(message);
        self
    }

    pub(crate) fn invite(mut self, code_hash: &[u8; 32], code: &str) -> Self {
        self.invites.push(InviteNote {
            code_hash: b64(code_hash),
            code: code.to_owned(),
        });
        self
    }

    /// The number of signed operations.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the batch holds no operation.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// The operations, as a protocol's [`super::Effect`] carries them.
    pub fn into_ops(self) -> Vec<(Vec<Condition>, OpKind)> {
        self.ops
    }

    /// The operations, in order.
    pub fn ops(&self) -> &[(Vec<Condition>, OpKind)] {
        &self.ops
    }
}

/// A batch signed and kept before it is first sent: its exact body and what its answer
/// settles. Its `Debug` shows no content.
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct PendingBatch {
    #[serde(with = "serde_b64_vec")]
    pub(crate) body: Vec<u8>,
    pub(crate) invites: Vec<InviteNote>,
    pub(crate) deadlines: Vec<(String, ObligationDeadline)>,
    /// The protocol's local writes, committed with the answer, kept in base64
    /// ([`super::state::kept_local`]).
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "super::state::kept_local"
    )]
    pub(crate) local: Vec<LocalWrite>,
    /// The messages put in the outbox with the answer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) queued: Vec<OutboxItem>,
    /// When its first send left, at a service time verified in that call
    /// ([`App::kept_stamp`]), committed before the request; `None` while it was never sent,
    /// which can't be ambiguous and so has no window yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kept_ms: Option<u64>,
    /// Its creation number among the app's kept batches, in the commit that keeps it: the
    /// order kept batches go in (`kept_order`). `None` for one an earlier build kept, which
    /// goes first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) queued_n: Option<u64>,
}

impl std::fmt::Debug for PendingBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PendingBatch({} body bytes)", self.body.len())
    }
}

impl App {
    /// Sign `batch` once, keep it, send it, and commit what its answer settles (module
    /// docs). The app's deferred cursor move rides along when there is room for it (Switch
    /// spec 8.2). The batches kept from earlier calls are sent first. Each own `attempt` in
    /// the batch gets the checks of its proof once the switch applied it (Switch wire 6.5
    /// "Binding", 6.8 "Deadline"), as [`App::check_attempt`] gives them: only an attempt
    /// that passes them may be carried out.
    ///
    /// On `409 stale_epoch` for a batch with record writes, the app takes the newer own
    /// `identity.json` and its key bundle, seals the record writes again at the new data
    /// epoch, and signs and sends the batch once more, under a new batch ID: the batch
    /// refused was refused for good, so nothing of it was applied or kept. Sealing again
    /// keeps every value, condition and expected version the caller built. When it can't be
    /// done (the newer document isn't on the Homeserver yet, or a write was sealed under a
    /// key the app doesn't hold), the call returns the `409 stale_epoch`, and the caller
    /// builds the batch again ([`App::record_op`] seals at the epoch the app holds then).
    ///
    /// **Kept batches ahead, and the worst case.** A batch kept from an earlier call goes
    /// before any later write, in the order the calls kept them, and no later write of the
    /// host overtakes it; this is the client's rule, the switch orders only what reaches it.
    /// A write sends at most one of them again ([`KEPT_RESENDS_PER_WRITE`]) before its own.
    /// With more kept, its own batch is kept unsent behind them and the call fails with
    /// [`AppError::Kept`] around [`Refusal::KeptBatchesAhead`], which names the oldest and
    /// when it was first sent: the host reads ([`App::receive`]), which sends them again in
    /// order. When the one sent again is answered `410 moved`, its own batch is kept unsent
    /// behind it too, and the call fails with [`AppError::Kept`] around that `410 moved`. A
    /// kept batch whose resend fails otherwise blocks the ones behind it until its answer
    /// window ends ([`super::KEPT_BATCH_ANSWER_MS`], 30 days less an hour from its first
    /// send), and is then dropped and reported; the write fails meanwhile with
    /// [`AppError::Ahead`], keeping nothing of its own.
    ///
    /// So a write sends at most three requests to the switch: a time sample, the kept batch
    /// and its own batch. The time sample has the short timeout (10 s by default), and each
    /// batch the short timeout and a share of the long one in proportion to its body
    /// ([`crate::transport::HttpConfig`]): a write of batches of a few KiB ends within about
    /// 30 s at the default timeouts, one of batches near a mebibyte within about 90 s. A
    /// kept batch signed for a generation before a move and answered `409 stale_generation`
    /// is signed again and sent once more, a fourth request; a `409 stale_epoch` of the own
    /// batch adds the newer `identity.json`, the key bundle and one more send.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an empty batch, one over 8 entries, or one whose local writes
    /// are over [`super::MAX_STEP_LOCAL_BYTES`], before anything is signed or kept;
    /// [`Refusal::Stopped`] or [`Refusal::Left`]; [`Refusal::NotNow`] while a provider loss
    /// is followed and the app's evidence isn't uploaded yet (Switch spec 12.6 step 3),
    /// after `409 stale_epoch` while the app lacks a read scope's key at the new data
    /// epoch, or when keeping the batch would take the batches kept unanswered past
    /// [`MAX_KEPT_BATCHES_BYTES`]: it is then neither kept nor sent, and may be submitted
    /// again once they are answered. Batches an earlier build kept count toward the cap but
    /// were kept without it, so they may already be past it; an
    /// `attempt` while the app may not attempt ([`App::may_attempt`]); the switch's refusal
    /// for good, such as `409 conflict` with its `current`, after which nothing is kept;
    /// [`AppError::Kept`] with the batch's ID, wrapping the cause, for any failure that leaves
    /// the batch kept, as the store shows it when the call returns (the network, `429`,
    /// `503`, an answer that doesn't verify, a refusal about the caller before its first
    /// send, an alarm, a failed commit, and the two cases above where it is kept unsent
    /// behind the batches from earlier calls, [`Refusal::KeptBatchesAhead`] and `410
    /// moved`): the batch is sent again, the same bytes, by the next call that writes and by
    /// the next read ([`App::receive`]) before its feed. A batch kept from an earlier call
    /// whose resend fails on the network or the switch, other than `410 moved`, fails the
    /// call with [`AppError::Ahead`] around that error before the new batch is signed, so
    /// nothing of this call is kept. [`AppError::InvalidData`] when an attempt's proof
    /// shows another state: the batch was applied and its outcome committed, and the
    /// attempt is written `failed`; a rollback for an attempt stamped at or after its
    /// deadline.
    pub async fn submit_batch(&mut self, batch: OpBatch) -> Result<Submitted, AppError> {
        Box::pin(async move { Ok(self.submit_checked(batch, false).await?.0) }).await
    }

    /// [`App::submit_batch`], with the claim view each own `attempt`'s proof shows, in the
    /// batch's order.
    ///
    /// `again` for a further try within one call ([`App::update_record`]): the service time
    /// the first try took still counts, and no kept batch is sent again, so the call takes
    /// one time sample and resends at most one kept batch in all. With batches kept, this
    /// one is kept behind them.
    pub(crate) async fn submit_checked(
        &mut self,
        batch: OpBatch,
        again: bool,
    ) -> Result<(Submitted, Vec<ClaimView>), AppError> {
        let fresh = self.time_fresh_at;
        self.ready_local().await?;
        if again {
            self.time_fresh_at = fresh;
        }
        self.refuse_when_stopped()?;
        refuse_lifecycle_ops(batch.ops.iter().map(|(_, kind)| kind))?;
        self.refuse_before_upload().await?;
        // At most one batch kept from an earlier call goes first; with more kept, this
        // one is kept behind them, so the call sends at most two batches.
        let resent = if again {
            Ok(self.kept_ahead().await?.is_some())
        } else {
            self.resume_kept(KEPT_RESENDS_PER_WRITE, None).await
        };
        let behind = match resent {
            Ok(false) => None,
            Ok(true) => self
                .kept_ahead()
                .await?
                .map(|ahead| AppError::Refused(Refusal::KeptBatchesAhead(ahead))),
            // A frozen account takes no write, but the app queues its writes for the next
            // service (Switch spec 12.5 step 2): the new batch is kept too, unsent behind
            // the kept batch the freeze refused, and the call reports that `410 moved`. Sent
            // now, it would overtake that batch should the freeze be called off meanwhile.
            Err(
                error @ AppError::Switch(ClientError::Switch {
                    code: ErrorCode::Moved,
                    ..
                }),
            ) => self.kept_ahead().await?.map(|_| error),
            Err(error @ (AppError::Transport(_) | AppError::Switch(_))) => {
                return Err(match self.kept_ahead().await? {
                    Some(ahead) => AppError::Ahead {
                        ahead,
                        error: Box::new(error),
                    },
                    None => error,
                });
            }
            Err(error) => return Err(error),
        };
        let attempts: Vec<(usize, ClaimEntry)> = batch
            .ops
            .iter()
            .enumerate()
            .filter_map(|(index, (_, kind))| match kind {
                OpKind::Claim(c) if c.kind == ClaimType::Attempt => {
                    c.check().ok().map(|entry| (index, entry))
                }
                _ => None,
            })
            .collect();
        if !attempts.is_empty() {
            self.may_attempt(false)?;
        }
        // A batch with sealed record writes is kept unsigned too, to be sealed again after
        // `409 stale_epoch` (below).
        let unsigned = batch
            .ops
            .iter()
            .any(|(_, kind)| matches!(kind, OpKind::RecordPut(_)))
            .then(|| batch.clone());
        let submitted = match (self.submit_new_behind(batch, behind).await, unsigned) {
            (Ok(submitted), _) => submitted,
            (Err(stale), Some(unsigned)) if stale.code() == Some(ErrorCode::StaleEpoch) => {
                self.submit_resealed(unsigned, stale).await?
            }
            (Err(error), _) => return Err(error),
        };
        let mut views = Vec::new();
        let mut refused = Vec::new();
        for (index, entry) in &attempts {
            let proof = submitted.proofs.get(*index).ok_or_else(|| {
                AppError::InvalidData(
                    "Switch wire 6.5: an attempt answered without its proof".into(),
                )
            })?;
            match self.check_own_attempt(entry, proof).await? {
                Ok(view) => views.push(view),
                Err(reason) => refused.push(reason),
            }
        }
        if let Some(reason) = refused.first() {
            return Err(AppError::InvalidData(format!(
                "the attempt's proof shows another state; written failed: {reason}"
            )));
        }
        Ok((submitted, views))
    }

    /// The checks of an own `attempt` the protocol sent another way (Switch wire 6.5
    /// "Binding", 6.8 "Deadline"), from the exact bytes of the signed operation and of its
    /// transition proof ([`SignedOp::signed`], [`TransitionProof::signed`]). The operation
    /// verifies with the app's own key; the proof verifies with the service key of the
    /// operation's generation and binds the operation; and it is of the generation the own
    /// `identity.json` names, stamped before the attempt's deadline, showing the app's own
    /// open attempt. Only then may the protocol carry the attempt out.
    /// [`App::submit_batch`] and [`App::write_claim`] give these checks to their own
    /// attempts.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`] for a stopped or departed app, with nothing
    /// checked or written; [`Refusal::Usage`] for an operation that isn't an own `attempt`
    /// signed by the app's key; [`AppError::InvalidData`] for a proof that doesn't verify with the service key or
    /// doesn't bind the operation, with nothing changed; once it binds, a rollback for a
    /// proof stamped at or after the deadline, and [`AppError::InvalidData`] for one that
    /// shows another state, after which the attempt is written `failed`.
    pub async fn check_attempt(
        &mut self,
        op: &SignedDoc,
        proof: &SignedDoc,
    ) -> Result<ClaimView, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            let identity = self.state.meta.identity;
            let app_id = self.state.meta.app_id;
            let op = SignedOp::verify(
                op,
                &self.state.keys.signing_public(),
                &identity,
                Some(&app_id),
            )
            .map_err(|_| {
                Refusal::Usage("Switch wire 6.1: the operation isn't the app's own".into())
            })?;
            let entry = match &op.body().kind {
                OpKind::Claim(fields) => fields.check().ok(),
                _ => None,
            }
            .filter(|entry| matches!(entry.kind, EntryKind::Attempt { .. }))
            .ok_or_else(|| Refusal::Usage("only an attempt's proof is checked so".into()))?;
            let unbound = || {
                AppError::InvalidData(
                    "Switch wire 6.5: the proof isn't the service's proof of the operation".into(),
                )
            };
            let service_key = self
                .service_key_of(op.body().generation)
                .await?
                .ok_or_else(unbound)?;
            let proof =
                TransitionProof::verify(proof, &service_key, &identity).map_err(|_| unbound())?;
            proof.check_binds(&op).map_err(|_| unbound())?;
            match self.check_own_attempt(&entry, &proof).await? {
                Ok(view) => Ok(view),
                Err(reason) => Err(AppError::InvalidData(format!(
                    "the attempt's proof shows another state; written failed: {reason}"
                ))),
            }
        })
        .await
    }

    /// Sign `batch` once, keep it, send it and commit its outcome, without sending the
    /// batches kept from earlier calls first.
    pub(crate) async fn submit_new(&mut self, batch: OpBatch) -> Result<Submitted, AppError> {
        self.submit_new_behind(batch, None).await
    }

    /// [`App::submit_new`], keeping the batch unsent when batches kept from earlier calls
    /// are ahead of it: `behind` is then the error the call returns around the kept batch
    /// ([`Refusal::KeptBatchesAhead`], or the `410 moved` the oldest kept batch got).
    async fn submit_new_behind(
        &mut self,
        batch: OpBatch,
        behind: Option<AppError>,
    ) -> Result<Submitted, AppError> {
        if batch.ops.is_empty() || batch.ops.len() > MAX_BATCH_ENTRIES {
            return Err(
                Refusal::Usage("Switch wire 6.4: a batch has 1 to 8 entries".into()).into(),
            );
        }
        // Local writes over the bound are refused at hand-over, before anything is signed
        // or kept (`Protocol`, "Limits a receive step plans for").
        if local_writes_bytes(&batch.local) > MAX_STEP_LOCAL_BYTES {
            return Err(Refusal::Usage(format!(
                "a batch's local writes are at most {MAX_STEP_LOCAL_BYTES} bytes"
            ))
            .into());
        }
        let carry = (batch.ops.len() < MAX_BATCH_ENTRIES)
            .then_some(self.state.cursor.seq)
            .filter(|_| self.state.cursor.deferred_since_ms.is_some());
        let queued = batch
            .queued
            .iter()
            .map(|message| self.outbox_item(message))
            .collect::<Result<Vec<_>, _>>()?;
        let signed = self.sign_ops(batch.ops, carry)?;
        let id = signed
            .id()
            .ok_or_else(|| AppError::InvalidData("a batch of operations has an ID".into()))?;
        let pending = PendingBatch {
            body: signed.body().to_vec(),
            invites: batch.invites,
            deadlines: batch
                .deadlines
                .iter()
                .map(|(claim_key, deadline)| (b64(claim_key), *deadline))
                .collect(),
            local: batch.local,
            queued,
            // Stamped at its first send ([`App::run_pending`]): kept now, it goes out with
            // the next call that writes when this one can't reach the service.
            kept_ms: None,
            queued_n: None,
        };
        // The kept batches together stay within what a provider change carries in its one
        // commit ([`MAX_KEPT_BATCHES_BYTES`]).
        let kept: usize = self
            .reader()
            .scan_raw(PENDING_PREFIX)
            .await?
            .iter()
            .map(|(_, value)| value.len())
            .sum();
        let this = super::state::encode(&pending)?.len();
        if kept.saturating_add(this) > MAX_KEPT_BATCHES_BYTES {
            return Err(Refusal::NotNow(format!(
                "the batches kept unanswered take {kept} bytes, and this one {this} more, over \
                 {MAX_KEPT_BATCHES_BYTES}: it is not kept, nor sent, until they are answered"
            ))
            .into());
        }
        let queued_n: u64 = self.reader().get(KEPT_NEXT).await?.unwrap_or(0);
        let pending = PendingBatch {
            queued_n: Some(queued_n),
            ..pending
        };
        let mut tx = self.tx()?;
        tx.put(KEPT_NEXT, &queued_n.saturating_add(1))?;
        tx.put(&pending_key(&id), &pending)?;
        index_kept(&mut tx, &id, &pending, &signed)?;
        if let Some(error) = behind {
            // Kept behind the batches from earlier calls: it goes after them, by the reads
            // and writes that send them again.
            self.commit(tx).await?;
            return Err(AppError::Kept {
                batch_id: id,
                error: Box::new(error),
            });
        }
        // From the commit that keeps it, a failure that leaves the batch kept says so, so
        // the caller can tell its own batch kept from an earlier one that couldn't be sent:
        // a commit answered `StoreError::Unknown` may have kept it too.
        let result = match self.commit(tx).await {
            Ok(()) => self.run_pending(&id, &pending, &signed, false).await,
            Err(error) => Err(error),
        };
        match result {
            Ok(submitted) => Ok(submitted),
            Err(error) => Err(self.kept_or_dropped(id, error).await),
        }
    }

    /// `error` of a call whose own batch `id` was kept, as the store shows it now: wrapped
    /// as [`AppError::Kept`] when the batch is still under `opq/`, bare when it is gone
    /// (settled, or dropped after a refusal for good). The store decides, not the step that
    /// failed, so no failure after the batch was kept, before its send included, returns a
    /// bare error for a batch that stays kept. A store that can't be read to tell gives its
    /// own error, bare, unless `error` is already a store failure, which is kept as it is.
    pub(crate) async fn kept_or_dropped(&self, id: [u8; 16], error: AppError) -> AppError {
        match self.reader().exists(&pending_key(&id)).await {
            Ok(still_kept) => AppError::kept_or(id, error, still_kept),
            Err(_) if matches!(error, AppError::Store(_)) => error,
            Err(unread) => unread,
        }
    }

    /// After `409 stale_epoch` on `batch` (Switch spec 3.5, 6.4): the switch refused it for
    /// good, and nothing of it is kept. The app takes the newer own `identity.json` and its
    /// key bundle, seals each record write again at the new data epoch, and signs and sends
    /// the batch once more, under a new batch ID. Sealing again changes only the ciphertext:
    /// each value is the one the caller built, opened with the app's key of the epoch it was
    /// sealed at, and the record key, policy, expected version and conditions stay as they
    /// were, so the switch still applies the batch only on the state it was built on.
    ///
    /// Returns `stale`, the switch's refusal, when nothing can be sealed again: the newer
    /// document isn't on the Homeserver yet (the data epoch didn't change), a record write
    /// was sealed under a key the app doesn't hold, or reading the newer document or key
    /// bundle failed. The caller then builds the batch again, as for any refusal for good.
    async fn submit_resealed(
        &mut self,
        batch: OpBatch,
        stale: AppError,
    ) -> Result<Submitted, AppError> {
        let refreshed = match self.refresh_identity().await {
            Ok(_) => self.fetch_key_bundle().await,
            Err(error) => Err(error),
        };
        match refreshed {
            Ok(()) => {}
            Err(error @ AppError::Alarm(_)) => return Err(error),
            Err(_) => return Err(stale),
        }
        match self.reseal(batch)? {
            Some(resealed) => self.submit_new(resealed).await,
            None => Err(stale),
        }
    }

    /// `batch` with every record write sealed at the current data epoch (Switch spec 13.4),
    /// or `None` when no write changes, or one can't be opened with the app's keys.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotNow`] while the app lacks the read scope's key at the current data
    /// epoch, as [`App::record_op`]; a value that doesn't seal.
    fn reseal(&self, mut batch: OpBatch) -> Result<Option<OpBatch>, AppError> {
        let epoch = self.state.own_doc.data_epoch();
        let identity = self.state.meta.identity;
        let mut changed = false;
        for (_, kind) in &mut batch.ops {
            let OpKind::RecordPut(put) = kind else {
                continue;
            };
            let sealed = &put.value_sealed;
            if sealed.data_epoch == epoch {
                continue;
            }
            let Some(old_key) = self.state.scope_keys.get(sealed.data_epoch, &sealed.scope) else {
                return Ok(None);
            };
            let Ok(value) = sealed.open(&old_key, &identity, &put.key) else {
                return Ok(None);
            };
            let read_scope = &put.policy.read_scope;
            let new_key = self
                .state
                .scope_keys
                .get(epoch, read_scope)
                .ok_or_else(|| {
                    AppError::Refused(Refusal::NotNow(
                        "Switch spec 3.5: no key of the read scope at the current data epoch yet"
                            .into(),
                    ))
                })?;
            let json: &[u8] = match &value {
                RecordValue::Delete => b"",
                RecordValue::Json(json) => json,
            };
            put.value_sealed =
                SealedValue::seal(&new_key, &identity, epoch, read_scope, &put.key, json)?;
            changed = true;
        }
        Ok(changed.then_some(batch))
    }

    /// While a provider loss is followed and the app's evidence isn't uploaded yet, it
    /// writes nothing at the new service: it uploads before its first write there (Switch
    /// spec 12.6 step 3, Switch wire 7.4.14).
    pub(crate) async fn refuse_before_upload(&self) -> Result<(), AppError> {
        self.refuse_before_upload_of(None).await
    }

    /// [`App::refuse_before_upload`] for one batch: only the loss's own registration batch
    /// (Switch spec 12.6 step 1) goes before the upload. Every other write waits, a received
    /// message's effect, a cursor move, a receive key rotation and the record of a renewal
    /// included.
    pub(crate) async fn refuse_before_upload_of(
        &self,
        batch: Option<&Batch>,
    ) -> Result<(), AppError> {
        if let Some(loss) = self.loss_record().await?
            && loss.step <= LossStep::Upload
            && batch.is_none_or(|batch| batch.body() != loss.batch.as_slice())
        {
            return Err(Refusal::NotNow(
                "Switch spec 12.6 step 3: the app uploads its evidence before it writes at the \
                 new service"
                    .into(),
            )
            .into());
        }
        Ok(())
    }

    /// Send the batches kept from earlier calls, oldest first, and commit their answers: in
    /// the order the calls kept them, whether sent before or not (`kept_order`). One
    /// refused for good is dropped and reported ([`AppEvent::BatchRefused`]); any other
    /// failure stops here, the batch still kept, and is the caller's error, so later writes
    /// don't overtake it. Nothing is sent while the evidence of a provider loss
    /// isn't uploaded yet. A batch never sent that holds an `attempt` is a new attempt, so
    /// it goes only while the app may attempt ([`App::may_attempt`]), as the call that kept
    /// it checked; otherwise, in reconcile mode begun since (Switch spec 8.3, 12.4), it is
    /// dropped unsent, never applied, and reported with its attempts
    /// ([`AppEvent::KeptBatchDropped`]).
    pub(crate) async fn resume_batches(&mut self) -> Result<(), AppError> {
        self.resume_kept(usize::MAX, None).await.map(|_| ())
    }

    /// The batch kept from an earlier call that goes first, and how many are kept; `None`
    /// with none kept.
    pub(crate) async fn kept_ahead(&self) -> Result<Option<KeptAhead>, AppError> {
        let mut kept = self.kept_batches().await?;
        kept.sort_by_key(kept_order);
        let count = u64::try_from(kept.len()).unwrap_or(u64::MAX);
        Ok(kept.first().map(|(id, pending)| KeptAhead {
            batch_id: *id,
            kept_since_ms: pending.kept_ms,
            answer_until_ms: pending
                .kept_ms
                .map(|at| at.saturating_add(super::KEPT_BATCH_ANSWER_MS)),
            kept: count,
        }))
    }

    /// [`App::resume_batches`], for at most `limit` kept batches: returns whether more are
    /// kept that this call didn't reach, left for the next one in the same order.
    async fn resume_kept(
        &mut self,
        limit: usize,
        budget: Option<&super::CallBudget>,
    ) -> Result<bool, AppError> {
        if self.refuse_before_upload().await.is_err() {
            return Ok(false);
        }
        let mut kept = self.kept_batches().await?;
        kept.sort_by_key(kept_order);
        let mut left = kept.len() > limit;
        for (index, (id, pending)) in kept.into_iter().take(limit).enumerate() {
            // Past the call's time budget no further batch is sent: those left go at the
            // next call, in the same order.
            if index > 0 && budget.is_some_and(|budget| self.spent(budget)) {
                left = true;
                break;
            }
            let batch = self.without_stale_cursor(Batch::from_body(pending.body.clone())?)?;
            // Never sent, as its record shows: no answer of it can be ambiguous, so it has
            // no window, and goes out as a first send would, an attempt in it only while the
            // app may attempt (Switch spec 12.4).
            if pending.kept_ms.is_none() {
                if !super::provider::attempts_in(&batch).is_empty()
                    && self.may_attempt(false).is_err()
                {
                    let mut tx = self.tx()?;
                    self.kept_batch_dropped(&id, &pending, &batch, &mut tx)?;
                    self.commit(tx).await?;
                    continue;
                }
                self.send_unsent(&id, &pending, &batch).await?;
                continue;
            }
            // Past the window no answer tells whether it was applied, at any generation: it
            // isn't sent again, and goes, reported with its attempts (Switch wire 6.4 step
            // 5, Switch spec 12.5 "Kept batches"). Past it by the clocks at hand is past it;
            // only a "still inside" needs a fresh service time, taken again before each
            // batch, should the sends before it have taken long.
            let mut past = !self.answer_decides(pending.kept_ms);
            if !past {
                self.fresh_service_time().await?;
                past = !self.answer_decides(pending.kept_ms);
            }
            if past {
                let mut tx = self.tx()?;
                self.kept_batch_dropped(&id, &pending, &batch, &mut tx)?;
                self.commit(tx).await?;
                continue;
            }
            if super::batch_generation(&batch).is_some_and(|g| g < self.state.meta.generation) {
                self.resend_earlier(&id, &pending, &batch).await?;
                continue;
            }
            match self.run_pending(&id, &pending, &batch, true).await {
                Ok(submitted) => self.check_attempts_of(&batch, &submitted).await?,
                Err(error) if refused_before_lookup(&error) => {
                    self.kept_refused_before_lookup(&id, &pending, &batch, error)
                        .await?;
                }
                Err(error) => match refused_for_good(&error) {
                    Some(code) => self.kept_batch_refused(&id, &pending, code).await?,
                    None => return Err(error),
                },
            }
        }
        Ok(left)
    }

    /// The own attempts of a batch sent again, or of a received message's effect: their
    /// proofs get the checks [`App::submit_batch`] gives its own (Switch wire 6.5
    /// "Binding", 6.8 "Deadline"); one that fails them is written `failed` and reported.
    pub(crate) async fn check_attempts_of(
        &mut self,
        batch: &Batch,
        submitted: &Submitted,
    ) -> Result<(), AppError> {
        for (index, op) in batch.ops().iter().enumerate() {
            let OpKind::Claim(fields) = &op.body().kind else {
                continue;
            };
            let Ok(entry) = fields.check() else {
                continue;
            };
            let (EntryKind::Attempt { .. }, Some(proof)) =
                (&entry.kind, submitted.proofs.get(index))
            else {
                continue;
            };
            if self.check_own_attempt(&entry, proof).await?.is_err() {
                self.events.push(AppEvent::AttemptNotHeld {
                    claim_key: entry.claim_key,
                    attempt_id: entry.attempt_id,
                });
            }
        }
        Ok(())
    }

    /// At the start of a read, before the feed: the batches kept from earlier calls are
    /// sent again ([`App::resume_batches`]), so an answer that was lost is settled by the
    /// next read, not only by the next write. The switch answers a batch it applied with
    /// its original proofs (Switch wire 6.4 step 5), so a batch whose operations the feed
    /// already shows applied is settled and cleared by that answer, its proofs kept as an
    /// answer of its first send would have been. A resend that fails on the network or the
    /// switch doesn't fail the read: the batch stays kept, and the read reports it
    /// ([`AppEvent::KeptBatchesWaiting`], returned for the read's own report) and goes on to
    /// the feed. After a kept batch was answered `429 rate_limited`, no read sends the kept
    /// batches again until the `retry_after` it asked has passed by the device clock: each
    /// read until then reports them waiting with that code, and sends nothing (Switch wire
    /// 7.6). An alarm, a store failure or a refusal of the app's own rules fails the read,
    /// as any of its steps does; so does a kept batch whose record under `opq/` doesn't
    /// read, at every read until the store is repaired or restored, since corruption must
    /// not pass silently, and a write would meet it as well.
    ///
    /// At most [`KEPT_RESENDS_PER_READ`] kept batches go in one read, oldest first; the
    /// second value says more are kept, for the next read.
    pub(crate) async fn resume_batches_before_feed(
        &mut self,
        budget: Option<&super::CallBudget>,
    ) -> Result<(Option<AppEvent>, bool), AppError> {
        let now = self.now();
        let waiting = |kept: usize, code: Option<ErrorCode>| AppEvent::KeptBatchesWaiting {
            kept: u64::try_from(kept).unwrap_or(u64::MAX),
            code: code.map(|code| code.as_str().to_owned()),
        };
        if self
            .kept_rate_limited
            .is_some_and(|(from, until)| from <= now && now < until)
        {
            let kept = self.reader().scan_raw(PENDING_PREFIX).await?.len();
            if kept > 0 {
                return Ok((Some(waiting(kept, Some(ErrorCode::RateLimited))), false));
            }
        }
        match self.resume_kept(KEPT_RESENDS_PER_READ, budget).await {
            Ok(left) => Ok((None, left)),
            Err(error @ (AppError::Transport(_) | AppError::Switch(_))) => {
                let kept = self.reader().scan_raw(PENDING_PREFIX).await?.len();
                Ok((Some(waiting(kept, error.code())), false))
            }
            Err(error) => Err(error),
        }
    }

    /// Note a kept batch's send answered `429 rate_limited`: the wait its `retry_after`
    /// asks, from now by the device clock ([`App::resume_batches_before_feed`]).
    fn note_kept_rate_limited(&mut self, error: &AppError) {
        if let AppError::Switch(ClientError::Switch {
            code: ErrorCode::RateLimited,
            retry_after: Some(seconds),
            ..
        }) = error
        {
            let now = self.now();
            let until = now.saturating_add(seconds.saturating_mul(1000));
            self.kept_rate_limited = Some((now, until));
        }
    }

    /// A kept batch never sent ([`PendingBatch::kept_ms`]), sent now: signed again first for
    /// the generation followed if it was signed for an earlier one, since no old bytes need
    /// an answer, still kept under `id`. A refusal for good, other than one about the caller, which keeps it, drops
    /// it with what it carried and tells the protocol in that commit ([`AppEvent::BatchRefused`]);
    /// it was never applied.
    async fn send_unsent(
        &mut self,
        id: &[u8; 16],
        pending: &PendingBatch,
        batch: &Batch,
    ) -> Result<(), AppError> {
        let (pending, batch) =
            if super::batch_generation(batch).is_some_and(|g| g < self.state.meta.generation) {
                let signed = self.sign_ops(super::provider::ops_of(batch), None)?;
                let wire_batch_id = signed.id().ok_or_else(|| {
                    AppError::InvalidData("a batch of operations has an ID".into())
                })?;
                let renewed = PendingBatch {
                    body: signed.body().to_vec(),
                    ..pending.clone()
                };
                let mut tx = self.tx()?;
                Self::keep_signed_again(id, &renewed, &mut tx)?;
                self.commit(tx).await?;
                self.events.push(AppEvent::KeptBatchSignedAgain {
                    batch_id: *id,
                    wire_batch_id,
                });
                (renewed, signed)
            } else {
                (pending.clone(), batch.clone())
            };
        match self.run_pending(id, &pending, &batch, true).await {
            Ok(submitted) => self.check_attempts_of(&batch, &submitted).await,
            Err(error) if refused_at(&error) == Some(RefusalPlace::Caller) => Err(error),
            Err(error) => match refused_for_good(&error) {
                Some(code) => self.kept_batch_refused(id, &pending, code).await,
                None => Err(error),
            },
        }
    }

    /// A kept batch sent again and refused for good at or after its batch ID lookup: it was
    /// never applied, and goes with the local writes and outbox messages it carried; the
    /// protocol is told in that commit ([`AppEvent::BatchRefused`]), which also writes its
    /// end ([`App::kept_batch`]).
    async fn kept_batch_refused(
        &mut self,
        id: &[u8; 16],
        pending: &PendingBatch,
        code: ErrorCode,
    ) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        let reason = KeptBatchDrop::Refused {
            code: code.as_str().to_owned(),
        };
        self.end_kept_batch(id, pending, Ended::Dropped(reason), &mut tx)?;
        self.keep_duty(
            &mut tx,
            super::events::Duty::BatchRefused {
                batch_id: *id,
                code: code.as_str().to_owned(),
            },
        )?;
        self.commit(tx).await
    }

    /// A kept batch sent again and refused before the service looked at its batch ID, which
    /// tells nothing of whether it was applied ([`RefusalPlace`]). Refused about the caller,
    /// it stays kept, to go again unchanged once the cause is gone, and the error is the
    /// caller's; past the window in which a resend tells, it is dropped and reported with
    /// its attempts instead (Switch spec 12.5 "Kept batches"). Refused about these bytes,
    /// which will be refused again, it is dropped and reported so at once, and the next
    /// kept batch goes on.
    pub(crate) async fn kept_refused_before_lookup(
        &mut self,
        id: &[u8; 16],
        pending: &PendingBatch,
        batch: &Batch,
        error: AppError,
    ) -> Result<(), AppError> {
        if refused_at(&error) == Some(RefusalPlace::Caller) && self.answer_decides(pending.kept_ms)
        {
            return Err(error);
        }
        let mut tx = self.tx()?;
        self.kept_batch_dropped(id, pending, batch, &mut tx)?;
        self.commit(tx).await
    }

    /// A kept batch to send again: its signed operations are its exact bytes (Switch wire
    /// 2.1), but its unsigned `cursor.set` may name a position the service's cursor has
    /// passed since, which would take that cursor back. Such a cursor move is left out; the
    /// batch ID and the signed operations don't change.
    fn without_stale_cursor(&self, batch: Batch) -> Result<Batch, AppError> {
        match batch.cursor() {
            Some(position)
                if position.generation != self.state.meta.generation
                    || position.seq < self.state.cursor.at_service =>
            {
                Ok(Batch::new(batch.ops().to_vec(), None)?)
            }
            _ => Ok(batch),
        }
    }

    /// Send a kept batch and commit its outcome. A refusal for good drops it; any other
    /// failure keeps it, to be sent again with the same bytes (Switch wire 2.1, 6.4).
    /// `resent` for a batch that may have been sent before: one refused before the batch ID
    /// lookup stays kept ([`RefusalPlace`]). A batch's first send is stamped first, at a
    /// service time verified in this call, committed before the request leaves; a call
    /// that can't verify one leaves it kept and unsent.
    async fn run_pending(
        &mut self,
        id: &[u8; 16],
        pending: &PendingBatch,
        batch: &Batch,
        resent: bool,
    ) -> Result<Submitted, AppError> {
        let stamped;
        let pending = if pending.kept_ms.is_none() {
            self.fresh_service_time().await?;
            stamped = PendingBatch {
                kept_ms: Some(self.kept_stamp()),
                ..pending.clone()
            };
            let mut tx = self.tx()?;
            tx.put(&pending_key(id), &stamped)?;
            self.commit(tx).await?;
            &stamped
        } else {
            pending
        };
        let submitted = match self.submit(batch).await {
            Ok(submitted) => submitted,
            Err(error) => {
                self.note_kept_rate_limited(&error);
                // A first send's refusal is its caller's; one sent again is dropped and
                // reported by its caller, in one commit.
                if let Some(code) = refused_for_good(&error).filter(|_| !resent) {
                    let reason = KeptBatchDrop::Refused {
                        code: code.as_str().to_owned(),
                    };
                    let mut tx = self.tx()?;
                    self.end_kept_batch(id, pending, Ended::Dropped(reason), &mut tx)?;
                    self.commit(tx).await?;
                }
                return Err(error);
            }
        };
        let mut tx = self.tx()?;
        for (index, op) in batch.ops().iter().enumerate() {
            let proof = submitted.proofs.get(index);
            self.settle_op(op, proof, pending, &mut tx).await?;
        }
        self.settle_kept_writes(pending, &mut tx).await?;
        self.end_kept_batch(id, pending, Ended::Applied, &mut tx)?;
        tx.put(key::CURSOR, &self.state.cursor)?;
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut tx)?;
        }
        self.commit(tx).await?;
        Ok(submitted)
    }

    /// The writes a kept batch carries for its outcome: the protocol's local writes, and
    /// the messages it puts in the outbox, each once: one the outbox holds already, or that
    /// was sent, is left as it is (`STATE.md`).
    async fn settle_kept_writes(
        &self,
        pending: &PendingBatch,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        tx.local(&pending.local)?;
        // A message whose delivery the app gave up meanwhile, a copy `queue_stored` queued,
        // isn't queued again: the protocol was told it wasn't delivered.
        let now = self.now();
        for item in &pending.queued {
            if !self.knows_message(item.msg_id()).await?
                && !super::send::given_up(&self.reader(), item.msg_id(), now).await?
            {
                super::send::put_outbox_item(tx, item)?;
            }
        }
        Ok(())
    }

    /// What one answered operation settles, written to `tx`.
    pub(crate) async fn settle_op(
        &mut self,
        op: &SignedOp,
        proof: Option<&TransitionProof>,
        pending: &PendingBatch,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        match &op.body().kind {
            OpKind::RecordPut(_) => {
                if let Some(proof) = proof {
                    self.cache_own_write(op, proof, tx).await?;
                }
            }
            OpKind::Claim(fields) => {
                let Some(proof) = proof else {
                    return Ok(());
                };
                let claim_key = b64(&fields.claim_key);
                let deadline = pending
                    .deadlines
                    .iter()
                    .find(|(key, _)| *key == claim_key)
                    .map(|(_, deadline)| *deadline);
                self.keep_claim_proof(op, proof, deadline, tx).await?;
            }
            OpKind::AllowPut { pubky, kind } => {
                tx.put(&super::admission::allow_key(*kind, pubky), &())?;
            }
            OpKind::AllowDelete { pubky, kind } => {
                tx.delete(&super::admission::allow_key(*kind, pubky))?;
            }
            OpKind::DenyPut { pubky } => {
                tx.put(&super::admission::deny_key(pubky), &())?;
            }
            OpKind::DenyDelete { pubky } => {
                tx.delete(&super::admission::deny_key(pubky))?;
            }
            OpKind::InviteCodePut(put) => {
                let hash = b64(&put.code_hash);
                if let Some(note) = pending.invites.iter().find(|n| n.code_hash == hash) {
                    super::admission::keep_invite(tx, put, &note.code)?;
                }
            }
            OpKind::InviteCodeDelete { code_hash } => {
                tx.delete(&super::admission::invite_key(code_hash))?;
                tx.delete(&super::admission::code_key(code_hash))?;
            }
            _ => {}
        }
        Ok(())
    }

    /// A `record_version` condition on the version of record `key` the app holds, or the
    /// version the switch showed for it when the app refused that write: the next write
    /// builds on it (Switch wire 6.3, Switch spec 10.3). `{0, 0}` for a record the app holds
    /// nothing of, and when that write, held or refused, is a delete: `{0, 0}` matches a
    /// deleted record as an absent or forgotten one, so the condition holds once the service
    /// forgets the key.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn record_condition(&self, key: &[u8; 32]) -> Result<Condition, AppError> {
        let version = self
            .held_record(key)
            .await?
            .map_or(RecordVersion::NONE, |held| held.write_base());
        Ok(Condition::RecordVersion { key: *key, version })
    }

    /// A `claim_step` condition on the step of the claim view the app keeps for
    /// `claim_key`, 0 when it keeps none (Switch wire 6.3).
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn claim_condition(&self, claim_key: &[u8; 32]) -> Result<Condition, AppError> {
        let step = self
            .kept_claim(claim_key)
            .await?
            .and_then(|kept| kept.view().ok())
            .map_or(0, |view: ClaimView| view.step);
        Ok(Condition::ClaimStep {
            claim_key: *claim_key,
            step,
        })
    }
}

// -------------------------------------------------------------------------------------
// Kept batches at a provider change (`provider.rs`, `recovery.rs`)

impl App {
    /// The batches kept under `opq/`, by ID.
    pub(crate) async fn kept_batches(&self) -> Result<Vec<([u8; 16], PendingBatch)>, AppError> {
        self.reader()
            .scan::<PendingBatch>(PENDING_PREFIX)
            .await?
            .into_iter()
            .map(|(id, pending)| {
                pubky_switch_core::enc::unb64_array::<16>(&id)
                    .map(|id| (id, pending))
                    .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))
            })
            .collect()
    }

    /// A kept batch signed for a generation before a provider change that the app's chain
    /// can't tell about, sent again unchanged: the answer decides (Switch spec 12.5 "Kept
    /// batches", Switch wire 6.4 step 6). Its original proofs, or `409 conflict` after an
    /// import, show it applied: what it settles commits and nothing is signed again. `409
    /// stale_generation` shows it never applied: its operations are signed again for the
    /// generation followed, their bytes under a new wire batch ID while the batch stays kept
    /// under its first one (`kept.rs`), and sent, but only while the answer can
    /// tell: one kept longer than the service holds batch IDs is dropped instead, and
    /// reported with each `attempt` in it. Another refusal for good drops it; any other
    /// failure keeps it, and is the caller's error.
    pub(crate) async fn resend_earlier(
        &mut self,
        id: &[u8; 16],
        pending: &PendingBatch,
        batch: &Batch,
    ) -> Result<(), AppError> {
        let sent = self.submit(batch).await;
        if let Err(error) = &sent {
            self.note_kept_rate_limited(error);
        }
        let proofs = match sent {
            Ok(submitted) => submitted.proofs,
            Err(AppError::Switch(ClientError::Switch {
                code: ErrorCode::Conflict,
                ..
            })) => Vec::new(),
            Err(AppError::Switch(ClientError::Switch {
                code: ErrorCode::StaleGeneration,
                ..
            })) if !self.answer_decides(pending.kept_ms) => {
                // The service may have forgotten a batch it applied: past the window the
                // answer decides nothing, and the batch goes (Switch spec 12.5 "Kept
                // batches"), reported in the commit that drops it.
                let mut tx = self.tx()?;
                self.kept_batch_dropped(id, pending, batch, &mut tx)?;
                return self.commit(tx).await;
            }
            Err(AppError::Switch(ClientError::Switch {
                code: ErrorCode::StaleGeneration,
                ..
            })) => {
                let ops = batch
                    .ops()
                    .iter()
                    .map(|op| (op.body().conditions.clone(), op.body().kind.clone()))
                    .collect();
                let signed = self.sign_ops(ops, None)?;
                let wire_batch_id = signed.id().ok_or_else(|| {
                    AppError::InvalidData("a batch of operations has an ID".into())
                })?;
                // New bytes, never sent: stamped at their first send, still kept under `id`.
                let renewed = PendingBatch {
                    body: signed.body().to_vec(),
                    kept_ms: None,
                    ..pending.clone()
                };
                let mut tx = self.tx()?;
                Self::keep_signed_again(id, &renewed, &mut tx)?;
                self.commit(tx).await?;
                self.events.push(AppEvent::KeptBatchSignedAgain {
                    batch_id: *id,
                    wire_batch_id,
                });
                // Its first send: a refusal for good, other than one about the caller, which
                // keeps it, drops it with what it carried, and tells the protocol in that
                // commit, as a kept batch's refusal does; no caller waits for this one.
                let submitted = match self.run_pending(id, &renewed, &signed, true).await {
                    Ok(submitted) => submitted,
                    Err(error) if refused_at(&error) == Some(RefusalPlace::Caller) => {
                        return Err(error);
                    }
                    Err(error) => match refused_for_good(&error) {
                        Some(code) => return self.kept_batch_refused(id, &renewed, code).await,
                        None => return Err(error),
                    },
                };
                return self.check_attempts_of(&signed, &submitted).await;
            }
            Err(error) if refused_before_lookup(&error) => {
                return self
                    .kept_refused_before_lookup(id, pending, batch, error)
                    .await;
            }
            Err(error) => {
                if let Some(code) = refused_for_good(&error) {
                    return self.kept_batch_refused(id, pending, code).await;
                }
                return Err(error);
            }
        };
        // Applied: an attempt learned of this way isn't carried out on this answer; the
        // protocol reads its claim (Switch spec 12.5 "Kept batches").
        let mut tx = self.tx()?;
        for (index, op) in batch.ops().iter().enumerate() {
            self.settle_op(op, proofs.get(index), pending, &mut tx)
                .await?;
        }
        self.settle_kept_writes(pending, &mut tx).await?;
        self.end_kept_batch(id, pending, Ended::Applied, &mut tx)?;
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut tx)?;
        }
        self.commit(tx).await?;
        self.events
            .push(AppEvent::KeptBatchApplied { batch_id: *id });
        Ok(())
    }

    /// A kept batch the old service applied, though its answer was lost: what it settles
    /// without its proofs goes into `tx`, and it is no longer kept, its end written.
    pub(crate) async fn settle_kept_batch(
        &mut self,
        id: &[u8; 16],
        pending: &PendingBatch,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let batch = Batch::from_body(pending.body.clone())?;
        for op in batch.ops() {
            self.settle_op(op, None, pending, tx).await?;
        }
        self.settle_kept_writes(pending, tx).await?;
        self.end_kept_batch(id, pending, Ended::Applied, tx)
    }

    /// Keep `pending`, signed again, under `id`, the ID the batch was first kept under:
    /// the batch ID its bytes carry changes, the one it is known by doesn't (`kept.rs`).
    pub(crate) fn keep_signed_again(
        id: &[u8; 16],
        pending: &PendingBatch,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        tx.put(&pending_key(id), pending)
    }
}

/// A `server_time_in` condition: the service's time when it applies the batch lies in
/// `[start, end)`, either bound open with `None` (Switch wire 6.3).
pub fn server_time_in(start: Option<u64>, end: Option<u64>) -> Condition {
    Condition::ServerTimeIn { start, end }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_switch_core::ops::AllowKind;

    #[test]
    fn test_op_batch_adds_conditions_to_the_last_operation() {
        let batch = OpBatch::new()
            .op(OpKind::DenyPut { pubky: [1; 32] })
            .when(server_time_in(Some(1), None))
            .op(OpKind::AllowPut {
                pubky: [2; 32],
                kind: AllowKind::Contact,
            });
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.ops()[0].0.len(), 1);
        assert!(batch.ops()[1].0.is_empty());
        let ops = batch.into_ops();
        assert!(matches!(ops[1].1, OpKind::AllowPut { .. }));
    }

    #[test]
    fn test_op_batch_condition_without_an_operation_is_dropped() {
        let batch = OpBatch::new().when(server_time_in(None, Some(2)));
        assert!(batch.is_empty());
    }

    #[test]
    fn test_kept_order_follows_creation_whatever_was_sent_first() {
        let kept = |id: u8, queued_n: Option<u64>, kept_ms: Option<u64>| {
            (
                [id; 16],
                PendingBatch {
                    queued_n,
                    kept_ms,
                    ..PendingBatch::default()
                },
            )
        };
        let mut batches = [
            // Kept by this build: the later one sent first, and at an earlier time.
            kept(1, Some(8), Some(1_000)),
            kept(2, Some(7), None),
            kept(3, Some(9), Some(500)),
            // Kept by an earlier build, with no creation number.
            kept(4, None, None),
            kept(5, None, Some(3_000)),
            kept(6, None, Some(2_000)),
            kept(0, None, None),
        ];
        batches.sort_by_key(kept_order);
        let ids: Vec<u8> = batches.iter().map(|(id, _)| id[0]).collect();
        assert_eq!(ids, [6, 5, 0, 4, 2, 1, 3]);
    }

    #[test]
    fn test_pending_batch_without_a_creation_number_reads_as_one_kept_before() {
        let kept = PendingBatch {
            body: b"body".to_vec(),
            kept_ms: Some(5),
            ..PendingBatch::default()
        };
        let mut value = serde_json::to_value(&kept).unwrap();
        assert!(value.get("queued_n").is_none(), "{value}");
        value
            .as_object_mut()
            .unwrap()
            .insert("queued_n".into(), serde_json::json!(3));
        let numbered: PendingBatch = serde_json::from_value(value).unwrap();
        assert_eq!(numbered.queued_n, Some(3));
        let read: PendingBatch =
            serde_json::from_value(serde_json::to_value(&kept).unwrap()).unwrap();
        assert_eq!((read.queued_n, read.kept_ms), (None, Some(5)));
    }

    #[test]
    fn test_pending_batch_debug_hides_the_body_and_codes() {
        let pending = PendingBatch {
            body: b"secret-body".to_vec(),
            invites: vec![InviteNote {
                code_hash: "h".into(),
                code: "secret-code".into(),
            }],
            deadlines: Vec::new(),
            ..PendingBatch::default()
        };
        let text = format!("{pending:?} {:?}", pending.invites);
        assert!(!text.contains("secret"), "{text}");
    }
}
