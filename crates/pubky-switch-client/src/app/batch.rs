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
//! A batch the switch refuses is dropped: it was not applied, and the caller decides what to
//! write instead. A batch whose answer didn't come back stays kept, and the next call that
//! writes sends it again, the same bytes, so the service answers it as a retry (Switch wire
//! 6.4 step 5).

use pubky_switch_core::chain::TransitionProof;
use pubky_switch_core::claims::{ClaimType, ClaimView};
use pubky_switch_core::enc::{b64, serde_b64_vec};
use pubky_switch_core::ops::{Condition, MAX_BATCH_ENTRIES, OpKind, RecordVersion, SignedOp};
use serde::{Deserialize, Serialize};

use super::claims::ObligationDeadline;
use super::error::Refusal;
use super::state::{Tx, key};
use super::{App, AppError};
use crate::client::{Batch, Submitted};

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
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PendingBatch {
    #[serde(with = "serde_b64_vec")]
    pub(crate) body: Vec<u8>,
    pub(crate) invites: Vec<InviteNote>,
    pub(crate) deadlines: Vec<(String, ObligationDeadline)>,
}

impl std::fmt::Debug for PendingBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PendingBatch({} body bytes)", self.body.len())
    }
}

impl App {
    /// Sign `batch` once, keep it, send it, and commit what its answer settles (module
    /// docs). The app's deferred cursor move rides along when there is room for it (Switch
    /// spec 8.2). A batch kept from an earlier call is sent first.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an empty batch or one over 8 entries; [`Refusal::Stopped`] or
    /// [`Refusal::Left`]; an `attempt` while the app may not attempt ([`App::may_attempt`]);
    /// the switch's refusal, such as `409 conflict` with its `current`, after which nothing
    /// is kept; a transport failure, after which the batch is kept and sent again by the next
    /// call that writes.
    pub async fn submit_batch(&mut self, batch: OpBatch) -> Result<Submitted, AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        self.resume_batches().await?;
        if batch.ops.is_empty() || batch.ops.len() > MAX_BATCH_ENTRIES {
            return Err(
                Refusal::Usage("Switch wire 6.4: a batch has 1 to 8 entries".into()).into(),
            );
        }
        let attempts = batch
            .ops
            .iter()
            .any(|(_, kind)| matches!(kind, OpKind::Claim(c) if c.kind == ClaimType::Attempt));
        if attempts {
            self.may_attempt(false)?;
        }
        let carry = (batch.ops.len() < MAX_BATCH_ENTRIES)
            .then_some(self.state.cursor.seq)
            .filter(|_| self.state.cursor.deferred_since_ms.is_some());
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
        };
        let mut tx = self.tx()?;
        tx.put(&pending_key(&id), &pending)?;
        self.commit(tx).await?;
        self.run_pending(&id, &pending, &signed).await
    }

    /// Send the batches kept from earlier calls, oldest first by ID order, and commit their
    /// answers. A refused one is dropped.
    pub(crate) async fn resume_batches(&mut self) -> Result<(), AppError> {
        let kept = self.reader().scan::<PendingBatch>(PENDING_PREFIX).await?;
        for (id, pending) in kept {
            let id = pubky_switch_core::enc::unb64_array::<16>(&id)
                .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?;
            let batch = Batch::from_body(pending.body.clone())?;
            match self.run_pending(&id, &pending, &batch).await {
                Ok(_) | Err(AppError::Switch(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Send a kept batch and commit its outcome.
    async fn run_pending(
        &mut self,
        id: &[u8; 16],
        pending: &PendingBatch,
        batch: &Batch,
    ) -> Result<Submitted, AppError> {
        let result = self.submit(batch).await;
        let submitted = match result {
            Ok(submitted) => submitted,
            Err(AppError::Switch(error)) => {
                let mut tx = self.tx()?;
                tx.delete(&pending_key(id))?;
                self.commit(tx).await?;
                return Err(AppError::Switch(error));
            }
            Err(error) => return Err(error),
        };
        let mut tx = self.tx()?;
        for (index, op) in batch.ops().iter().enumerate() {
            let proof = submitted.proofs.get(index);
            self.settle_op(op, proof, pending, &mut tx).await?;
        }
        tx.delete(&pending_key(id))?;
        tx.put(key::CURSOR, &self.state.cursor)?;
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut tx)?;
        }
        self.commit(tx).await?;
        Ok(submitted)
    }

    /// What one answered operation settles, written to `tx`.
    async fn settle_op(
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
        };
        let text = format!("{pending:?} {:?}", pending.invites);
        assert!(!text.contains("secret"), "{text}");
    }
}
