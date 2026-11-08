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
//! what to write instead; one sent again from an earlier call is reported as
//! [`AppEvent::BatchRefused`]. A batch whose answer didn't come back, or may pass unchanged
//! later (`429`, `503`, `401 stale_timestamp`, an answer that doesn't verify), stays kept,
//! and the next call that writes sends it again, the same bytes, so the service answers it
//! as a retry (Switch spec 6.4; Switch wire 2.1, 6.4 step 5).

use pubky_switch_core::chain::TransitionProof;
use pubky_switch_core::claims::{ClaimEntry, ClaimType, ClaimView, EntryKind};
use pubky_switch_core::enc::{b64, serde_b64_vec};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{Condition, MAX_BATCH_ENTRIES, OpKind, RecordVersion, SignedOp};
use serde::{Deserialize, Serialize};

use super::claims::{ClaimOp, ObligationDeadline};
use super::error::{Refusal, refused_for_good};
use super::events::AppEvent;
use super::protocol::LocalWrite;
use super::recovery::LossStep;
use super::send::{OutboxItem, SignedMessage};
use super::state::{Tx, key};
use super::{App, AppError};
use crate::client::{Batch, Submitted};
use crate::error::ClientError;

/// The prefix of the kept batches.
const PENDING_PREFIX: &str = "opq/";

fn pending_key(batch_id: &[u8; 16]) -> String {
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
    /// The protocol's local writes, committed with the answer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) local: Vec<LocalWrite>,
    /// The messages put in the outbox with the answer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) queued: Vec<OutboxItem>,
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
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an empty batch or one over 8 entries; [`Refusal::Stopped`] or
    /// [`Refusal::Left`]; [`Refusal::NotNow`] while a provider loss is followed and the
    /// app's evidence isn't uploaded yet (Switch spec 12.6 step 3); an `attempt` while the
    /// app may not attempt ([`App::may_attempt`]); the switch's refusal for good, such as
    /// `409 conflict` with its `current`, after which nothing is kept; any other failure
    /// (the network, `429`, `503`, an answer that doesn't verify), after which the batch is
    /// kept and sent again, the same bytes, by the next call that writes. A batch kept from
    /// an earlier call that still can't be sent fails the call the same way, before the new
    /// batch is signed. [`AppError::InvalidData`] when an attempt's proof shows another
    /// state: the batch was applied and its outcome committed, and the attempt is written
    /// `failed`; a rollback for an attempt stamped at or after its deadline.
    pub async fn submit_batch(&mut self, batch: OpBatch) -> Result<Submitted, AppError> {
        Box::pin(async move { Ok(self.submit_checked(batch).await?.0) }).await
    }

    /// [`App::submit_batch`], with the claim view each own `attempt`'s proof shows, in the
    /// batch's order.
    pub(crate) async fn submit_checked(
        &mut self,
        batch: OpBatch,
    ) -> Result<(Submitted, Vec<ClaimView>), AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        self.refuse_before_upload().await?;
        match self.resume_batches().await {
            Ok(()) => {}
            // A frozen account takes no write, but the app queues its writes for the next
            // service (Switch spec 12.5 step 2): the new batch is kept too, and the call
            // reports the `410 moved` its own send gets.
            Err(AppError::Switch(ClientError::Switch {
                code: ErrorCode::Moved,
                ..
            })) => {}
            Err(error) => return Err(error),
        }
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
        let submitted = self.submit_new(batch).await?;
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

    /// The checks of an own `attempt`'s proof (Switch wire 6.5 "Binding", 6.8 "Deadline"),
    /// for a batch the protocol sent another way: the proof binds the operation, is of the
    /// generation the own `identity.json` names, before the attempt's deadline, and shows the
    /// app's own open attempt. Only then may the protocol carry the attempt out.
    /// [`App::submit_batch`] and [`App::write_claim`] give these checks to their own
    /// attempts.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an entry other than an `attempt`; a rollback for a proof
    /// stamped at or after the deadline; [`AppError::InvalidData`] for a proof that shows
    /// another state, after which the attempt is written `failed`.
    pub async fn check_attempt(
        &mut self,
        op: &ClaimOp,
        proof: &TransitionProof,
    ) -> Result<ClaimView, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            if !matches!(op.entry().kind, EntryKind::Attempt { .. }) {
                return Err(Refusal::Usage("only an attempt's proof is checked so".into()).into());
            }
            match self.check_own_attempt(op.entry(), proof).await? {
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
        if batch.ops.is_empty() || batch.ops.len() > MAX_BATCH_ENTRIES {
            return Err(
                Refusal::Usage("Switch wire 6.4: a batch has 1 to 8 entries".into()).into(),
            );
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
        };
        let mut tx = self.tx()?;
        tx.put(&pending_key(&id), &pending)?;
        self.commit(tx).await?;
        self.run_pending(&id, &pending, &signed).await
    }

    /// While a provider loss is followed and the app's evidence isn't uploaded yet, it
    /// writes nothing at the new service: it uploads before its first write there (Switch
    /// spec 12.6 step 3, Switch wire 7.4.14).
    pub(crate) async fn refuse_before_upload(&self) -> Result<(), AppError> {
        if let Some(loss) = self.loss_record().await?
            && loss.step <= LossStep::Upload
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

    /// Send the batches kept from earlier calls, oldest first by ID order, and commit their
    /// answers. One refused for good is dropped and reported ([`AppEvent::BatchRefused`]);
    /// any other failure stops here, the batch still kept, and is the caller's error, so
    /// later writes don't overtake it. Nothing is sent while the evidence of a provider loss
    /// isn't uploaded yet.
    pub(crate) async fn resume_batches(&mut self) -> Result<(), AppError> {
        if self.refuse_before_upload().await.is_err() {
            return Ok(());
        }
        let kept = self.reader().scan::<PendingBatch>(PENDING_PREFIX).await?;
        for (id, pending) in kept {
            let id = pubky_switch_core::enc::unb64_array::<16>(&id)
                .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?;
            let batch = self.without_stale_cursor(Batch::from_body(pending.body.clone())?)?;
            match self.run_pending(&id, &pending, &batch).await {
                Ok(submitted) => self.check_attempts_of(&batch, &submitted).await?,
                Err(error) => match refused_for_good(&error) {
                    Some(code) => self.events.push(AppEvent::BatchRefused {
                        batch_id: id,
                        code: code.as_str().to_owned(),
                    }),
                    None => return Err(error),
                },
            }
        }
        Ok(())
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
    async fn run_pending(
        &mut self,
        id: &[u8; 16],
        pending: &PendingBatch,
        batch: &Batch,
    ) -> Result<Submitted, AppError> {
        let submitted = match self.submit(batch).await {
            Ok(submitted) => submitted,
            Err(error) => {
                if refused_for_good(&error).is_some() {
                    let mut tx = self.tx()?;
                    tx.delete(&pending_key(id))?;
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
        tx.delete(&pending_key(id))?;
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
        for item in &pending.queued {
            if !self.knows_message(item.msg_id()).await? {
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
    /// nothing of.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn record_condition(&self, key: &[u8; 32]) -> Result<Condition, AppError> {
        let version = self
            .held_record(key)
            .await?
            .map_or(RecordVersion::NONE, |held| held.base_version());
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

    /// A kept batch the old service applied, though its answer was lost: what it settles
    /// without its proofs goes into `tx`, and it is no longer kept.
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
        tx.delete(&pending_key(id))
    }

    /// Keep `pending` under `new_id` in place of the batch kept under `id`; `None` only
    /// drops it.
    pub(crate) fn replace_kept_batch(
        id: &[u8; 16],
        replacement: Option<(&[u8; 16], &PendingBatch)>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        tx.delete(&pending_key(id))?;
        match replacement {
            Some((new_id, pending)) => tx.put(&pending_key(new_id), pending),
            None => Ok(()),
        }
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
