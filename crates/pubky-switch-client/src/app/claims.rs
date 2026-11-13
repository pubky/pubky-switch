//! Claims, the app's side (Switch spec 6.3, 8.3, 10.2; Switch wire 6.2 `claim`, 6.5, 6.8,
//! 7.4.8).
//!
//! The app doesn't decide what an obligation is or when to act on it: that is the
//! protocol's. It gives the protocol the claim primitives:
//!
//! - [`ClaimOp`] builds the entries (`attempt`, `done` with its basis, `failed`, `unknown`)
//!   for a batch, with conditions; [`App::write_claim`] writes one and checks an `attempt`'s
//!   proof before the protocol carries the attempt out (Switch wire 6.5 "Binding").
//! - [`App::read_claim`] reads a claim and checks its entries and proofs (Switch wire
//!   7.4.8).
//! - The app keeps, per claim key, the newest claim view and the proof that shows it
//!   SETTLED, with the deadline it computes itself for the obligation, as evidence until
//!   the later of the bounds of Switch wire 6.8 "Pinned deadline and evidence" has passed
//!   (`claim/<claim_key>`), and the signed entries it saw (`clent/<claim_key>/<step>`).
//!   Entries in the feed update both. A switch that shows nothing for a claim the app holds
//!   evidence of, before the service may delete it, has rolled back (Switch spec 6.3).
//! - [`App::claim_doubt`] answers the doubtful and orphaned rules (Switch spec 10.2, 12.2
//!   step 3; Switch wire 6.8 "Doubtful claims"): no automatic attempt on such a claim.

use pubky_switch_core::chain::{ChainEnvelope, TransitionProof, check_attempt_proof};
use pubky_switch_core::claims::{
    Basis, ClaimEntry, ClaimStatus, ClaimView, EntryKind, MAX_CLAIM_AGE_MS, Outcome,
    RECONCILIATION_MS, SERVICE_AHEAD_BOUND_MS,
};
use pubky_switch_core::enc::{b64, unb64_array};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{Condition, OpKind, SignedOp};
use pubky_switch_core::records::{AppCert, Standing};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::batch::OpBatch;
use super::error::{Alarm, Refusal};
use super::events::AppEvent;
use super::records::KeptOp;
use super::state::{Tx, key};
use super::{App, AppError};
use crate::client::answers::{ChainItem, ClaimAnswer};
use crate::error::ClientError;

const CLAIM_PREFIX: &str = "claim/";
const ENTRY_PREFIX: &str = "clent/";
/// A claim the app follows that a read reads again (`clread/<claim_key>`), with when it was
/// marked, device time: the oldest marks go first.
const REREAD_PREFIX: &str = "clread/";
/// The feed showed the stub of an operation since the claims the app follows were last
/// marked to read again (`clstub`).
pub(crate) const STUB_SEEN: &str = "clstub";

/// The most claims one read reads again after its feed showed the stub of an operation
/// (Switch wire 7.5). Each is a request of its own (`GET /claims/{claim_key}`), so the
/// bound keeps a read's cost and time bounded when the app follows many claims at once,
/// while covering the claims a protocol has in flight together, such as one obligation's
/// attempt and its outcome, in one read. 16 is also how many entries stored locally a read
/// tries again ([`super::PARKED_RETRIES_PER_READ`]). The claims past it stay marked, oldest
/// mark first, for the next read.
pub const CLAIM_REREADS_PER_READ: usize = 16;

pub(crate) fn claim_key_of(claim_key: &[u8; 32]) -> String {
    format!("{CLAIM_PREFIX}{}", b64(claim_key))
}

pub(super) fn reread_key(claim_key: &[u8; 32]) -> String {
    format!("{REREAD_PREFIX}{}", b64(claim_key))
}

fn entry_key(claim_key: &[u8; 32], step: u64) -> String {
    format!("{ENTRY_PREFIX}{}/{}", b64(claim_key), key::num(step))
}

/// The deadline the app computes itself for an obligation, which decides with the claim's
/// pinned one how long it keeps the claim's evidence (Switch wire 6.8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationDeadline {
    /// The app hasn't said.
    #[default]
    NotKnown,
    /// The app computes none: what created the obligation sets no deadline.
    NoDeadline,
    /// `d + 1 ms`, as an `attempt` would pin it, in Unix milliseconds.
    At(u64),
}

/// A claim entry for a batch (Switch wire 6.2 `claim`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimOp {
    entry: ClaimEntry,
}

impl ClaimOp {
    /// `attempt` (row 1): a new attempt, orphaned after `orphan_after_s` seconds, pinning
    /// `deadline` (`d + 1 ms`, [`pubky_switch_core::claims::attempt_deadline`]) or none.
    pub fn attempt(
        claim_key: [u8; 32],
        expected_step: u64,
        attempt_id: [u8; 16],
        orphan_after_s: u64,
        deadline: Option<u64>,
    ) -> Self {
        Self::of(
            claim_key,
            expected_step,
            attempt_id,
            EntryKind::Attempt {
                orphan_after: orphan_after_s,
                deadline,
            },
        )
    }

    /// `done` (rows 2 to 4), with its basis and at most one `evidence_ref`.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for basis `evidence` without `evidence_ref` (Switch wire 6.8
    /// "Malformed").
    pub fn done(
        claim_key: [u8; 32],
        expected_step: u64,
        attempt_id: [u8; 16],
        basis: Basis,
        evidence_ref: Option<[u8; 32]>,
    ) -> Result<Self, AppError> {
        if basis == Basis::Evidence && evidence_ref.is_none() {
            return Err(Refusal::Usage(
                "Switch wire 6.8: basis evidence without evidence_ref".into(),
            )
            .into());
        }
        Ok(Self::of(
            claim_key,
            expected_step,
            attempt_id,
            EntryKind::Done {
                basis,
                evidence_ref,
            },
        ))
    }

    /// `failed` (row 5).
    pub fn failed(claim_key: [u8; 32], expected_step: u64, attempt_id: [u8; 16]) -> Self {
        Self::of(claim_key, expected_step, attempt_id, EntryKind::Failed)
    }

    /// `unknown` (row 6).
    pub fn unknown(claim_key: [u8; 32], expected_step: u64, attempt_id: [u8; 16]) -> Self {
        Self::of(claim_key, expected_step, attempt_id, EntryKind::Unknown)
    }

    fn of(claim_key: [u8; 32], expected_step: u64, attempt_id: [u8; 16], kind: EntryKind) -> Self {
        Self {
            entry: ClaimEntry {
                claim_key,
                attempt_id,
                expected_step,
                kind,
            },
        }
    }

    /// The entry.
    pub fn entry(&self) -> &ClaimEntry {
        &self.entry
    }

    /// The operation, for a batch.
    pub fn kind(&self) -> OpKind {
        OpKind::Claim(self.entry.fields())
    }
}

/// `claim/<claim_key>`: what the app keeps of a claim.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct KeptClaim {
    /// The newest claim view seen.
    view: Value,
    /// The proof that shows the claim SETTLED, the newest one.
    settled_proof: Option<SignedDoc>,
    /// The service time of the newest entry seen, from its stub.
    last_entry_ms: Option<u64>,
    /// The deadline the app computes itself.
    own_deadline: ObligationDeadline,
}

impl KeptClaim {
    pub(crate) fn view(&self) -> Result<ClaimView, AppError> {
        Ok(ClaimView::from_value(&self.view)?)
    }
}

/// `clent/<claim_key>/<step>`: a signed entry and its proof, as evidence for uploads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct KeptEntry {
    op: SignedDoc,
    proof: SignedDoc,
    seq: u64,
}

/// The evidence the app keeps for a claim.
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimEvidence {
    /// The newest claim view seen.
    pub view: ClaimView,
    /// The transition proof that shows the claim SETTLED, if one was seen.
    pub settled_proof: Option<SignedDoc>,
    /// The deadline the app computes itself.
    pub own_deadline: ObligationDeadline,
    /// Until when the app keeps the evidence, service time; `None` for good (an early pin)
    /// or for a claim with an attempt still unresolved.
    pub keep_until_ms: Option<u64>,
}

/// A claim entry read with its proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimEntryRead {
    /// The claim's step before the entry.
    pub step: u64,
    /// The entry's `seq`.
    pub seq: u64,
    /// The writer.
    pub writer: Option<[u8; 16]>,
    /// The entry.
    pub entry: ClaimEntry,
    /// When the service applied it, from its proof.
    pub at_ms: u64,
}

/// A claim as `GET /claims/{claim_key}` shows it, checked (Switch wire 7.4.8).
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimRead {
    /// The claim view.
    pub view: ClaimView,
    /// The entries, oldest first; none for a tombstone.
    pub entries: Vec<ClaimEntryRead>,
}

/// An entry the switch took, with its proof.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct ClaimWritten {
    /// The claim view after the entry; for a [`ClaimWritten::repeated`] entry, the view the
    /// switch's `409 conflict` showed.
    pub view: ClaimView,
    /// The entry's transition proof, bound to the operation: for a
    /// [`ClaimWritten::repeated`] entry, the proof of the app's own earlier entry.
    pub proof: TransitionProof,
    /// The attempt the entry and its proof are about: the one the call asked for.
    pub attempt_id: [u8; 16],
    /// Whether the switch had already applied this app's own entry at the step the call
    /// asked for, of the same type and attempt: the call's own entry was refused (`409
    /// conflict`), and this is that entry's outcome ([`App::write_claim`]). It need not be
    /// the caller's own earlier call whose answer was lost, such as a kept batch sent again:
    /// it may be an entry the app kept from its feed, written by another device of the app
    /// or by an effect's batch, under the same attempt ID.
    pub repeated: bool,
}

/// Why no automatic attempt relies on a claim (Switch spec 10.2, 12.2 step 3; Switch wire
/// 6.8 "Doubtful claims").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClaimDoubt {
    /// Attempts marked `unknown`.
    pub unknown: Vec<[u8; 16]>,
    /// Open attempts orphaned now: their owner isn't current, or `orphan_after` has passed,
    /// or they came from a recovery upload.
    pub orphaned: Vec<[u8; 16]>,
    /// The next `attempt` would be flagged `possibly_duplicate`.
    pub next_possibly_duplicate: bool,
    /// Uploads after a provider loss conflict.
    pub divergent: bool,
    /// An entry by an app the own `identity.json` lists as removed, after its
    /// `distrust_from`.
    pub after_distrust: bool,
    /// The pinned deadline is earlier than the app's own (Switch wire 6.8).
    pub early_pin: bool,
}

impl ClaimDoubt {
    /// Whether any rule makes the claim doubtful.
    pub fn doubtful(&self) -> bool {
        !self.unknown.is_empty()
            || !self.orphaned.is_empty()
            || self.next_possibly_duplicate
            || self.divergent
            || self.after_distrust
            || self.early_pin
    }
}

/// The pin of a claim view: `None` while no attempt pinned one, `Some(None)` for a pin to
/// "none" (Switch wire 6.8).
fn pin_of(view: &ClaimView) -> Option<Option<u64>> {
    if view.attempts.is_empty() {
        None
    } else {
        Some(view.deadline)
    }
}

/// Until when evidence is kept (Switch wire 6.8 "Pinned deadline and evidence"); `None` for
/// good.
fn keep_until(view: &ClaimView, own: ObligationDeadline, proof_time: u64) -> Option<u64> {
    let by_age = proof_time.saturating_add(MAX_CLAIM_AGE_MS);
    match (pin_of(view), own) {
        (Some(Some(pinned)), ObligationDeadline::At(own)) => {
            Some(pinned.max(own).saturating_add(RECONCILIATION_MS))
        }
        // A pinned deadline where the app computes none is an early pin: kept for good.
        (Some(Some(_)), ObligationDeadline::NoDeadline) => None,
        (Some(Some(pinned)), ObligationDeadline::NotKnown) => {
            Some(pinned.saturating_add(RECONCILIATION_MS))
        }
        (_, ObligationDeadline::At(own)) => Some(own.saturating_add(RECONCILIATION_MS).max(by_age)),
        (_, _) => Some(by_age),
    }
}

/// From when the service may delete a finished or failed claim (Switch wire 6.8).
fn deletable_from(view: &ClaimView, last_entry: u64) -> Option<u64> {
    match pin_of(view)? {
        Some(pinned) => Some(pinned.saturating_add(RECONCILIATION_MS)),
        None => Some(last_entry.saturating_add(MAX_CLAIM_AGE_MS)),
    }
}

/// Whether the app holds a claim as finished: SETTLED with every attempt `done` or
/// `failed`, the state that compacts it (Switch wire 6.8 "Tombstones"). A SETTLED claim with
/// an attempt still open isn't: that attempt's outcome comes as a stub too (Switch wire 7.5).
fn finished(view: &ClaimView) -> bool {
    view.status == ClaimStatus::Settled && finished_or_failed(view)
}

/// Whether a claim the app holds is one it reads again after its feed showed the stub of an
/// operation (Switch wire 7.5): any claim it doesn't hold as finished, and whose view it can
/// read, but one whose every attempt failed past the time the service may delete it (Switch
/// wire 6.8 "Failed claims"), which nothing changes any more.
fn followed(kept: &KeptClaim, now: u64) -> bool {
    let Ok(view) = kept.view() else {
        return true;
    };
    if finished(&view) {
        return false;
    }
    let deletable = finished_or_failed(&view)
        .then(|| {
            kept.last_entry_ms
                .and_then(|last| deletable_from(&view, last))
        })
        .flatten();
    deletable.is_none_or(|from| now < from)
}

fn finished_or_failed(view: &ClaimView) -> bool {
    let resolved = view
        .attempts
        .iter()
        .all(|a| matches!(a.outcome, Outcome::Done | Outcome::Failed));
    !view.attempts.is_empty() && resolved
}

impl App {
    /// What the app keeps of a claim.
    pub(crate) async fn kept_claim(
        &self,
        claim_key: &[u8; 32],
    ) -> Result<Option<KeptClaim>, AppError> {
        self.reader().get(&claim_key_of(claim_key)).await
    }

    /// The evidence the app keeps for `claim_key`.
    ///
    /// # Errors
    ///
    /// A store failure, or a kept view that doesn't read.
    pub async fn claim_evidence(
        &self,
        claim_key: &[u8; 32],
    ) -> Result<Option<ClaimEvidence>, AppError> {
        let Some(kept) = self.kept_claim(claim_key).await? else {
            return Ok(None);
        };
        let view = kept.view()?;
        let keep_until_ms = if finished_or_failed(&view) {
            kept.last_entry_ms
                .and_then(|time| keep_until(&view, kept.own_deadline, time))
        } else {
            None
        };
        Ok(Some(ClaimEvidence {
            view,
            settled_proof: kept.settled_proof,
            own_deadline: kept.own_deadline,
            keep_until_ms,
        }))
    }

    /// Set the deadline the app computes itself for the obligation of `claim_key` (Switch
    /// wire 6.8).
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn set_obligation_deadline(
        &mut self,
        claim_key: &[u8; 32],
        deadline: ObligationDeadline,
    ) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let Some(mut kept) = self.kept_claim(claim_key).await? else {
                return Ok(());
            };
            kept.own_deadline = deadline;
            let mut tx = self.tx()?;
            tx.put(&claim_key_of(claim_key), &kept)?;
            self.commit(tx).await
        })
        .await
    }

    /// Write one claim entry, with `conditions`, in a batch of its own (Switch wire 6.2), and
    /// keep its proof. For an `attempt` the proof must show the app's own open attempt, of
    /// the generation its `identity.json` names, before the deadline (Switch wire 6.5
    /// "Binding"); only then may the protocol carry the attempt out. An `attempt` whose proof
    /// binds the operation but shows another state is written `failed`, and the call fails.
    ///
    /// **An entry this app already wrote.** A caller whose earlier call failed after the
    /// switch took its entry, the answer lost, makes the call again; the earlier batch, kept,
    /// goes first, in this call or in a read before it, and takes the step, so the switch
    /// refuses this call's entry with `409 conflict`. When that conflict's claim shows the
    /// step this entry asked for taken by the app's own entry, of the same type and the same
    /// attempt, whose proof the app holds, the call returns that entry's outcome instead of
    /// the conflict, marked [`ClaimWritten::repeated`]. For an `attempt` the claim must show
    /// that attempt open, not orphaned, current and owned by this app, and its proof passes
    /// the checks above. For `done`, `failed` and `unknown` the claim must show the attempt
    /// resolved so by this app. Anything else is the conflict, an `attempt` under another
    /// ID included: the app's own attempt that holds the claim may be another device's, or
    /// an effect's, and only the protocol can tell whether it carries that one out; it sees
    /// the attempt in the conflict's claim ([`claim_conflict`]). A kept batch this call
    /// settles raises [`AppEvent::ClaimChanged`] as any settle does, when it changes the
    /// view or proof the app holds.
    ///
    /// # Errors
    ///
    /// The switch's refusal, such as `409 conflict` with the claim in `current`; a rollback
    /// for a proof stamped at or after the attempt's deadline; [`AppError::InvalidData`] for
    /// an attempt written `failed` after an unexpected proof; as
    /// [`App::submit_batch`].
    pub async fn write_claim(
        &mut self,
        op: ClaimOp,
        conditions: Vec<Condition>,
        deadline: ObligationDeadline,
    ) -> Result<ClaimWritten, AppError> {
        Box::pin(async move {
            let batch = OpBatch::new()
                .op_if(op.kind(), conditions)
                .obligation_deadline(op.entry.claim_key, deadline);
            let (submitted, views) = match self.submit_checked(batch, false).await {
                Ok(answered) => answered,
                Err(error) => {
                    return match self.repeated_entry(&op.entry, &error).await? {
                        Some(written) => Ok(written),
                        None => Err(error),
                    };
                }
            };
            let proof = submitted.proofs.first().cloned().ok_or_else(|| {
                AppError::InvalidData(
                    "Switch wire 6.5: a claim entry answered without its proof".into(),
                )
            })?;
            // An attempt's view is the one its checked proof shows.
            let view = match views.into_iter().next() {
                Some(view) => view,
                None => ClaimView::from_value(&proof.body().state)?,
            };
            Ok(ClaimWritten {
                view,
                proof,
                attempt_id: op.entry.attempt_id,
                repeated: false,
            })
        })
        .await
    }

    /// The outcome of the app's own earlier entry at the step `entry` asked for, when
    /// `error` is the switch's `409 conflict` whose claim shows that step taken by it
    /// ([`App::write_claim`]): the entry the app keeps at that step (`clent/`) is its own,
    /// of the same type and attempt, signed by its key and bound by a proof of the service
    /// key of its generation; for an `attempt`, the claim shows that attempt open, not
    /// orphaned, current and the app's, and its proof passes the checks of an own attempt
    /// (Switch wire 6.5 "Binding"); for an outcome, the claim shows the attempt resolved so
    /// by the app. `None` otherwise: the conflict stands.
    async fn repeated_entry(
        &self,
        entry: &ClaimEntry,
        error: &AppError,
    ) -> Result<Option<ClaimWritten>, AppError> {
        let Some(view) = claim_conflict(error) else {
            return Ok(None);
        };
        if view.claim_key != entry.claim_key
            || Some(view.step) != entry.expected_step.checked_add(1)
        {
            return Ok(None);
        }
        let Some(kept) = self
            .reader()
            .get::<KeptEntry>(&entry_key(&entry.claim_key, entry.expected_step))
            .await?
        else {
            return Ok(None);
        };
        let me = self.state.meta.app_id;
        let identity = self.state.meta.identity;
        let Ok(op) = SignedOp::verify(
            &kept.op,
            &self.state.keys.signing_public(),
            &identity,
            Some(&me),
        ) else {
            return Ok(None);
        };
        let Some(held) = (match &op.body().kind {
            OpKind::Claim(fields) => fields.check().ok(),
            _ => None,
        }) else {
            return Ok(None);
        };
        // The same attempt: an own entry under another attempt ID, another device's or an
        // effect's, is not this call's to carry out (Switch spec 3.1 "Several devices").
        if held.claim_key != entry.claim_key
            || held.expected_step != entry.expected_step
            || held.attempt_id != entry.attempt_id
        {
            return Ok(None);
        }
        let Some(service_key) = self.service_key_of(op.body().generation).await? else {
            return Ok(None);
        };
        let Ok(proof) = TransitionProof::verify(&kept.proof, &service_key, &identity) else {
            return Ok(None);
        };
        if proof.check_binds(&op).is_err() {
            return Ok(None);
        }
        let resolved_by_me = |outcome: Outcome| {
            view.attempt(&entry.attempt_id)
                .is_some_and(|a| a.outcome == outcome && a.resolved_by == Some(me))
        };
        let holds = match (&entry.kind, &held.kind) {
            // An orphaned attempt may be resolved `unknown` by any app (Switch spec 10.2):
            // the caller doesn't hold it any more.
            (EntryKind::Attempt { .. }, EntryKind::Attempt { .. }) => {
                view.status == ClaimStatus::Attempting
                    && view.owner == Some(me)
                    && view.attempt_id == Some(held.attempt_id)
                    && view
                        .attempt(&held.attempt_id)
                        .is_some_and(|a| a.outcome == Outcome::Open && !a.orphaned)
                    && check_attempt_proof(&proof, &held, &me, self.state.own_doc.generation())
                        .is_ok()
            }
            (EntryKind::Done { .. }, EntryKind::Done { .. }) => {
                view.status == ClaimStatus::Settled && resolved_by_me(Outcome::Done)
            }
            (EntryKind::Failed, EntryKind::Failed) => resolved_by_me(Outcome::Failed),
            (EntryKind::Unknown, EntryKind::Unknown) => resolved_by_me(Outcome::Unknown),
            _ => false,
        };
        Ok(holds.then_some(ClaimWritten {
            view,
            proof,
            attempt_id: held.attempt_id,
            repeated: true,
        }))
    }

    /// The checks of the proof of an own attempt the switch applied (Switch wire 6.5
    /// "Binding", 6.8 "Deadline"): a proof stamping it at or after its deadline is a
    /// rollback; one that doesn't show the app's own open attempt, of the generation its
    /// `identity.json` names, has the attempt written `failed`, and `Err` names why.
    pub(crate) async fn check_own_attempt(
        &mut self,
        entry: &ClaimEntry,
        proof: &TransitionProof,
    ) -> Result<Result<ClaimView, String>, AppError> {
        // A stopped app takes no proof and writes nothing (Switch spec 3.6, 4.3, 10.1), even
        // when an alarm stopped it during the call that sent the attempt.
        self.refuse_when_stopped()?;
        if let EntryKind::Attempt { deadline, .. } = entry.kind
            && deadline.is_some_and(|d| proof.envelope().server_time >= d)
        {
            return Err(self
                .raise(Alarm::Rollback {
                    reason: "Switch wire 6.8: an attempt stamped at or after its deadline".into(),
                })
                .await);
        }
        let me = self.state.meta.app_id;
        let generation = self.state.own_doc.generation();
        match check_attempt_proof(proof, entry, &me, generation) {
            Ok(view) => Ok(Ok(view)),
            Err(error) => {
                let step = proof.body().step.unwrap_or_default();
                let failed = ClaimOp::failed(entry.claim_key, step, entry.attempt_id);
                // Best effort: the attempt is refused to the protocol either way, and an
                // open attempt nobody carries out ends orphaned (Switch spec 10.2).
                let _ = self.submit_new(OpBatch::new().op(failed.kind())).await;
                Ok(Err(error.to_string()))
            }
        }
    }

    /// Read a claim (`GET /claims/{claim_key}`, Switch wire 7.4.8) and check it: each entry
    /// is a `claim` of this key at its step, signed by its writer where the app knows the
    /// writer's certificate, and bound by its proof, which verifies with the service key and
    /// shows the next step; the claim's step follows the last entry. The view and a proof
    /// showing it SETTLED are kept. `None` when the switch holds nothing for the key.
    ///
    /// # Errors
    ///
    /// A rollback for an answer that contradicts itself, or for a claim the app holds
    /// evidence of that the switch shows nothing for before it may delete it (Switch spec
    /// 6.3); a failed call or commit.
    pub async fn read_claim(
        &mut self,
        claim_key: &[u8; 32],
    ) -> Result<Option<ClaimRead>, AppError> {
        Box::pin(self.read_claim_inner(claim_key)).await
    }

    pub(crate) async fn read_claim_inner(
        &mut self,
        claim_key: &[u8; 32],
    ) -> Result<Option<ClaimRead>, AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        let result = self.client.claim(claim_key).await;
        let answer = match self.take(result).await {
            Ok(answer) => answer,
            Err(error) if error.code() == Some(ErrorCode::NotFound) => {
                self.check_missing_claim(claim_key).await?;
                // Nothing more to read of it: a mark to read it again goes.
                if self.reader().exists(&reread_key(claim_key)).await? {
                    let mut tx = self.tx()?;
                    tx.delete(&reread_key(claim_key))?;
                    self.commit(tx).await?;
                }
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let read = match self.check_claim_answer(claim_key, &answer).await? {
            Ok(read) => read,
            Err(reason) => return Err(self.raise(Alarm::Rollback { reason }).await),
        };
        let mut tx = self.tx()?;
        let mut kept = self.kept_claim(claim_key).await?.unwrap_or(KeptClaim {
            view: Value::Null,
            settled_proof: None,
            last_entry_ms: None,
            own_deadline: ObligationDeadline::NotKnown,
        });
        let step_held = kept.view().map_or(0, |v| v.step);
        if read.view.step >= step_held {
            kept.view = read.view.to_value();
        }
        for (entry, item) in read.entries.iter().zip(&answer.entries) {
            kept.last_entry_ms = Some(
                kept.last_entry_ms
                    .map_or(entry.at_ms, |t| t.max(entry.at_ms)),
            );
            tx.put(
                &entry_key(claim_key, entry.step),
                &KeptEntry {
                    op: item.op.clone(),
                    proof: item.proof.clone(),
                    seq: item.seq,
                },
            )?;
            self.note_entry_writer(&item.op, &mut tx).await?;
            let state = TransitionProof::peek(&item.proof)
                .ok()
                .and_then(|p| ClaimView::from_value(&p.body().state).ok());
            if state.is_some_and(|s| s.status == ClaimStatus::Settled) {
                kept.settled_proof = Some(item.proof.clone());
            }
        }
        tx.put(&claim_key_of(claim_key), &kept)?;
        // Any read of the claim is the read again a stub asked for (Switch wire 7.5).
        tx.delete(&reread_key(claim_key))?;
        self.commit(tx).await?;
        Ok(Some(read))
    }

    /// At the end of a read: read again the claims the app follows, after its feed showed
    /// the stub of an operation (Switch wire 7.5). A stub names no object, so it may be an
    /// entry of any claim the app holds and doesn't hold as finished, compacted since, its
    /// own entries included: every such claim is marked (`clread/`), in the commit that
    /// clears the feed's note of the stub (`clstub`, written with the page that passed it,
    /// so a crash loses no mark). Then at most [`CLAIM_REREADS_PER_READ`] of them, the
    /// oldest marks first, are read (`GET /claims/{claim_key}`, one request each), and
    /// [`AppEvent::ClaimChanged`] is raised for each whose held view or SETTLED proof the
    /// read changed. A claim read is unmarked in the commit of what it read; the rest stay
    /// marked for the next read. A read that fails on the network or the switch stops the
    /// reads here, its claim and the rest still marked, and the feed's read still succeeds;
    /// an alarm or a store failure fails it. Reading a claim writes no chain item, so it
    /// shows no stub and can't mark again by itself. An app without `claims.read` can't
    /// read claims, and marks none.
    ///
    /// Returns whether marks are left that this read didn't reach, past its budget of
    /// [`CLAIM_REREADS_PER_READ`] or its time: the next read goes on with them.
    pub(crate) async fn reread_claims(
        &mut self,
        budget: Option<&super::CallBudget>,
    ) -> Result<bool, AppError> {
        if !self.state.cert.has_permission(Permission::ClaimsRead) {
            return Ok(false);
        }
        if self.reader().exists(STUB_SEEN).await? {
            let now = self.service_now();
            let marked: std::collections::BTreeSet<String> = self
                .reader()
                .scan_raw(REREAD_PREFIX)
                .await?
                .into_iter()
                .map(|(rest, _)| rest)
                .collect();
            let at = self.now();
            let mut tx = self.tx()?;
            for (rest, kept) in self.reader().scan::<KeptClaim>(CLAIM_PREFIX).await? {
                if !marked.contains(&rest) && followed(&kept, now) {
                    tx.put(&format!("{REREAD_PREFIX}{rest}"), &at)?;
                }
            }
            tx.delete(STUB_SEEN)?;
            self.commit(tx).await?;
        }
        let mut marks = self.reader().scan::<u64>(REREAD_PREFIX).await?;
        marks.sort_by(|(a_key, a_at), (b_key, b_at)| a_at.cmp(b_at).then(a_key.cmp(b_key)));
        let left = marks.len() > CLAIM_REREADS_PER_READ;
        for (index, (rest, _)) in marks.into_iter().take(CLAIM_REREADS_PER_READ).enumerate() {
            if index > 0 && budget.is_some_and(|budget| self.spent(budget)) {
                return Ok(true);
            }
            let claim_key = unb64_array::<32>(&rest)
                .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?;
            let held = |kept: Option<KeptClaim>| kept.map(|kept| (kept.view, kept.settled_proof));
            let before = held(self.kept_claim(&claim_key).await?);
            if before.is_none() {
                // No longer held: its evidence went.
                let mut tx = self.tx()?;
                tx.delete(&reread_key(&claim_key))?;
                self.commit(tx).await?;
                continue;
            }
            match self.read_claim_inner(&claim_key).await {
                Ok(_) => {}
                Err(AppError::Transport(_) | AppError::Switch(_)) => return Ok(false),
                Err(error) => return Err(error),
            }
            if held(self.kept_claim(&claim_key).await?) != before {
                self.events.push(AppEvent::ClaimChanged { claim_key });
            }
        }
        Ok(left)
    }

    /// The checks of a claim answer; `Err` names the contradiction (Switch wire 7.4.8).
    ///
    /// Each proof is checked with the service key of its own generation, from the own
    /// `identity.json` and the generations the app followed: after a move or a key change
    /// the entries carry earlier services' proofs. A proof of the current generation that
    /// doesn't verify contradicts the signed answer. One of an earlier generation whose key
    /// the app doesn't know, or that doesn't verify with it, can't be checked: it is skipped,
    /// never an alarm on its own.
    async fn check_claim_answer(
        &mut self,
        claim_key: &[u8; 32],
        answer: &ClaimAnswer,
    ) -> Result<Result<ClaimRead, String>, AppError> {
        let identity = self.state.meta.identity;
        let generation = self.state.meta.generation;
        if answer.claim.claim_key != *claim_key {
            return Ok(Err("Switch wire 7.4.8: a claim of another key".into()));
        }
        let mut entries = Vec::new();
        let mut next = None;
        for item in &answer.entries {
            let Ok(op) = SignedOp::peek(&item.op) else {
                return Ok(Err("Switch wire 7.4.8: an entry that doesn't read".into()));
            };
            let OpKind::Claim(fields) = &op.body().kind else {
                return Ok(Err("Switch wire 7.4.8: an entry that isn't a claim".into()));
            };
            let Ok(entry) = fields.check() else {
                return Ok(Err("Switch wire 7.4.8: a malformed entry".into()));
            };
            if entry.claim_key != *claim_key || entry.expected_step != item.step {
                return Ok(Err(
                    "Switch wire 7.4.8: an entry of another claim or step".into()
                ));
            }
            let Ok(peeked) = TransitionProof::peek(&item.proof) else {
                return Ok(Err("Switch wire 7.4.8: a proof that doesn't read".into()));
            };
            let of = peeked.envelope().generation;
            let key = self.service_key_of(of).await?;
            let verified =
                key.and_then(|key| TransitionProof::verify(&item.proof, &key, &identity).ok());
            match &verified {
                Some(proof) => {
                    if proof.check_binds(&op).is_err()
                        || proof.body().step != item.step.checked_add(1)
                        || (of == generation && proof.envelope().seq != item.seq)
                    {
                        return Ok(Err(
                            "Switch wire 7.4.8: a proof that doesn't name its entry".into(),
                        ));
                    }
                }
                None if of == generation => {
                    return Ok(Err("Switch wire 7.4.8: a proof that doesn't verify".into()));
                }
                None => {}
            }
            if let Some(writer) = op.body().app_id
                && let Some(cert) = self.cert_of(&writer).await?
                && SignedOp::verify(&item.op, &cert.signing_key(), &identity, Some(&writer))
                    .is_err()
            {
                return Ok(Err(
                    "Switch wire 7.4.8: an entry its writer didn't sign".into()
                ));
            }
            next = item.step.checked_add(1);
            entries.push(ClaimEntryRead {
                step: item.step,
                seq: item.seq,
                writer: op.body().app_id,
                entry,
                at_ms: verified.as_ref().unwrap_or(&peeked).envelope().server_time,
            });
        }
        if let Some(next) = next
            && next != answer.claim.step
        {
            // A claim rebuilt from uploads after a provider loss lists the entries written
            // here: an upload's step has none, so the claim's step may be past the last
            // entry's, never before it. Only on a claim the view says is rebuilt, for an
            // identity whose identity.json carries `recovery_from`, which it keeps from
            // then on, whatever the app's own history (Switch wire 7.4.8, 7.4.14, 10.5).
            let after_loss = next < answer.claim.step
                && answer.claim.rebuilt
                && self.state.own_doc.body().recovery_from.is_some();
            if !after_loss {
                return Ok(Err(
                    "Switch wire 7.4.8: the claim's step doesn't follow its last entry".into(),
                ));
            }
        }
        Ok(Ok(ClaimRead {
            view: answer.claim.clone(),
            entries,
        }))
    }

    /// A certificate the app knows for `app_id`: its own, or one kept from its own apps.
    async fn cert_of(&self, app_id: &[u8; 16]) -> Result<Option<AppCert>, AppError> {
        if *app_id == self.state.meta.app_id {
            return Ok(Some(self.state.cert.clone()));
        }
        Ok(self.own_app_certs(app_id).await?.into_iter().next())
    }

    async fn own_app_certs(&self, app_id: &[u8; 16]) -> Result<Vec<AppCert>, AppError> {
        let prefix = format!("ocert/{}/", pubky_switch_core::enc::zbase32_encode(app_id));
        let identity = self.state.meta.identity;
        Ok(self
            .reader()
            .scan::<SignedDoc>(&prefix)
            .await?
            .into_iter()
            .filter_map(|(_, signed)| AppCert::verify(&signed, &identity).ok())
            .collect())
    }

    /// The switch shows nothing for a claim: a rollback while the app holds evidence and
    /// the service may not delete the claim yet (Switch spec 6.3; Switch wire 6.8).
    async fn check_missing_claim(&mut self, claim_key: &[u8; 32]) -> Result<(), AppError> {
        let Some(kept) = self.kept_claim(claim_key).await? else {
            return Ok(());
        };
        let Ok(view) = kept.view() else {
            return Ok(());
        };
        let Some(last) = kept.last_entry_ms else {
            return Ok(());
        };
        let deletable = if finished_or_failed(&view) {
            deletable_from(&view, last)
        } else {
            None
        };
        let now = self.service_now();
        let honest = deletable.is_some_and(|from| now >= from);
        if !honest {
            return Err(self
                .raise(Alarm::Rollback {
                    reason: "Switch spec 6.3: the switch shows nothing for a claim the app holds \
                             evidence of"
                        .into(),
                })
                .await);
        }
        let differs = match (pin_of(&view), kept.own_deadline) {
            (Some(Some(pinned)), ObligationDeadline::At(own)) => pinned != own,
            (Some(Some(_)), ObligationDeadline::NoDeadline) => true,
            (Some(None), ObligationDeadline::At(_)) => true,
            _ => false,
        };
        if differs {
            self.events.push(AppEvent::ClaimPinDiffers {
                claim_key: *claim_key,
            });
        }
        Ok(())
    }

    /// The highest service time verified, or the device clock without one.
    fn service_now(&self) -> u64 {
        self.state
            .service_time
            .map_or(self.now(), |time| time.highest_ms)
    }

    /// Drop the evidence whose retention has passed (Switch wire 6.8): every bound lies
    /// before the earlier of the highest verified service time and the device clock plus 24
    /// hours. Returns how many claims' evidence went. Without a verified service time
    /// nothing goes.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn prune_claim_evidence(&mut self) -> Result<u64, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            let Some(service) = self.state.service_time.map(|t| t.highest_ms) else {
                return Ok(0);
            };
            let horizon = service.min(self.now().saturating_add(SERVICE_AHEAD_BOUND_MS));
            let mut tx = self.tx()?;
            let mut dropped = 0u64;
            for (rest, kept) in self.reader().scan::<KeptClaim>(CLAIM_PREFIX).await? {
                let Ok(view) = kept.view() else {
                    continue;
                };
                if !finished_or_failed(&view) {
                    continue;
                }
                let Some(until) = kept
                    .last_entry_ms
                    .and_then(|time| keep_until(&view, kept.own_deadline, time))
                else {
                    continue;
                };
                if until < horizon {
                    let claim_key = unb64_array::<32>(&rest)
                        .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?;
                    tx.delete(&claim_key_of(&claim_key))?;
                    tx.delete_prefix(&format!("{ENTRY_PREFIX}{}/", b64(&claim_key)))?;
                    tx.delete(&reread_key(&claim_key))?;
                    dropped = dropped.saturating_add(1);
                }
            }
            self.commit(tx).await?;
            Ok(dropped)
        })
        .await
    }

    /// The doubtful and orphaned rules for `claim_key`, from the view and entries the app
    /// keeps (Switch spec 10.2, 12.2 step 3; Switch wire 6.8). `None` for a claim it keeps
    /// nothing of.
    ///
    /// # Errors
    ///
    /// A store failure, or a kept view that doesn't read.
    pub async fn claim_doubt(&self, claim_key: &[u8; 32]) -> Result<Option<ClaimDoubt>, AppError> {
        let Some(kept) = self.kept_claim(claim_key).await? else {
            return Ok(None);
        };
        let view = kept.view()?;
        let now = self.service_now();
        let doc = &self.state.own_doc;
        let current =
            |owner: &[u8; 16]| doc.listed_cert(owner).is_some() && !doc.lists_removed(owner);
        let mut doubt = ClaimDoubt {
            next_possibly_duplicate: view.next_possibly_duplicate,
            divergent: view.divergent,
            ..ClaimDoubt::default()
        };
        for attempt in &view.attempts {
            match attempt.outcome {
                Outcome::Unknown => doubt.unknown.push(attempt.attempt_id),
                Outcome::Open => {
                    let aged = now
                        >= attempt
                            .opened_at
                            .saturating_add(attempt.orphan_after.saturating_mul(1000));
                    if attempt.orphaned || aged || !current(&attempt.owner) {
                        doubt.orphaned.push(attempt.attempt_id);
                    }
                }
                _ => {}
            }
        }
        let prefix = format!("{ENTRY_PREFIX}{}/", b64(claim_key));
        for (_, entry) in self.reader().scan::<KeptEntry>(&prefix).await? {
            let (Ok(op), Ok(proof)) = (
                SignedOp::peek(&entry.op),
                TransitionProof::peek(&entry.proof),
            ) else {
                continue;
            };
            // A removed app's standing is its `distrust_from`, whatever certificate it used.
            if let Some(writer) = op.body().app_id
                && let Standing::Removed { distrust_from } = doc.standing(&writer, &[0; 32])
                && proof.envelope().server_time > distrust_from
            {
                doubt.after_distrust = true;
            }
        }
        if let (Some(Some(pinned)), ObligationDeadline::At(own)) =
            (pin_of(&view), kept.own_deadline)
            && pinned < own
        {
            doubt.early_pin = true;
        }
        Ok(Some(doubt))
    }

    /// The claim entries the app keeps, each with a certificate of its writer that verifies
    /// it, and the SETTLED and tombstone proofs: evidence for the uploads of a move or a
    /// recovery (Switch spec 6.3, 12.5, 12.6); and how many entries it keeps without one,
    /// which an upload can't carry (Switch wire 7.4.14).
    pub(crate) async fn claim_evidence_items(
        &self,
    ) -> Result<(Vec<KeptOp>, Vec<SignedDoc>, u64), AppError> {
        let identity = self.state.meta.identity;
        let mut ops = Vec::new();
        let mut left_out = 0u64;
        for (_, entry) in self.reader().scan::<KeptEntry>(ENTRY_PREFIX).await? {
            let Some(writer) = SignedOp::peek(&entry.op)
                .ok()
                .and_then(|op| op.body().app_id)
            else {
                continue;
            };
            // Only a certificate whose key verifies the entry: a switch that forged an
            // entry in a writer's name gets nothing uploaded for it.
            let verifies = |cert: &AppCert| {
                SignedOp::verify(&entry.op, &cert.signing_key(), &identity, Some(&writer)).is_ok()
            };
            let cert = self
                .writer_certs_held(&writer)
                .await?
                .into_iter()
                .find(|cert| verifies(cert));
            match cert {
                Some(cert) => ops.push(KeptOp {
                    op: entry.op,
                    cert: cert.signed().clone(),
                    proof: Some(entry.proof),
                }),
                None => left_out = left_out.saturating_add(1),
            }
        }
        let proofs = self
            .reader()
            .scan::<KeptClaim>(CLAIM_PREFIX)
            .await?
            .into_iter()
            .filter_map(|(_, kept)| kept.settled_proof)
            .collect();
        Ok((ops, proofs, left_out))
    }

    /// Every claim the app keeps that a rule makes doubtful.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub async fn doubtful_claims(&self) -> Result<Vec<([u8; 32], ClaimDoubt)>, AppError> {
        let mut out = Vec::new();
        for (rest, _) in self.reader().scan_raw(CLAIM_PREFIX).await? {
            let claim_key = unb64_array::<32>(&rest)
                .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?;
            if let Some(doubt) = self.claim_doubt(&claim_key).await?
                && doubt.doubtful()
            {
                out.push((claim_key, doubt));
            }
        }
        Ok(out)
    }

    /// An own claim entry the switch answered: its proof and view kept.
    pub(crate) async fn keep_claim_proof(
        &mut self,
        op: &SignedOp,
        proof: &TransitionProof,
        deadline: Option<ObligationDeadline>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let OpKind::Claim(fields) = &op.body().kind else {
            return Ok(());
        };
        let Ok(entry) = fields.check() else {
            return Ok(());
        };
        self.keep_entry(&entry, op.signed(), proof, deadline, tx)
            .await
    }

    /// A `claim` chain item from the feed (Switch spec 8.3): checked against its stub and
    /// proof, then kept.
    pub(crate) async fn feed_claim_entry(
        &mut self,
        item: &ChainItem,
        envelope: &ChainEnvelope,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let Ok(op) = SignedOp::peek(&item.item) else {
            return Ok(());
        };
        let OpKind::Claim(fields) = &op.body().kind else {
            return Ok(());
        };
        let Ok(entry) = fields.check() else {
            return Ok(());
        };
        let Some(signed) = &item.proof else {
            return Ok(());
        };
        // Checked with the service key of the item's own generation: after a move or a key
        // change the feed carries earlier services' items (Switch wire 7.4.8).
        let identity = self.state.meta.identity;
        let Some(service_key) = self.service_key_of(envelope.generation).await? else {
            return Ok(());
        };
        let Ok(proof) = TransitionProof::verify(signed, &service_key, &identity) else {
            return Ok(());
        };
        if proof.check_binds(&op).is_err()
            || proof.envelope().seq != envelope.seq
            || proof.body().chain.chain_hash
                != pubky_switch_core::chain::Stub::of(envelope).chain_hash
        {
            return Err(self
                .raise(Alarm::Rollback {
                    reason: "Switch wire 6.5: a claim entry's proof isn't its stub's".into(),
                })
                .await);
        }
        self.keep_entry(&entry, &item.item, &proof, None, tx).await
    }

    async fn keep_entry(
        &mut self,
        entry: &ClaimEntry,
        op: &SignedDoc,
        proof: &TransitionProof,
        deadline: Option<ObligationDeadline>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let Ok(view) = ClaimView::from_value(&proof.body().state) else {
            return Ok(());
        };
        let claim_key = entry.claim_key;
        let mut kept = self.kept_claim(&claim_key).await?.unwrap_or(KeptClaim {
            view: Value::Null,
            settled_proof: None,
            last_entry_ms: None,
            own_deadline: ObligationDeadline::NotKnown,
        });
        let held = (kept.view.clone(), kept.settled_proof.clone());
        let held_step = kept.view().map_or(0, |v| v.step);
        if view.step >= held_step {
            kept.view = view.to_value();
        }
        if view.status == ClaimStatus::Settled {
            kept.settled_proof = Some(proof.signed().clone());
        }
        // Raised when what the app holds changed: an entry it already kept, met again (a
        // kept batch's answer, then its item in the feed), changes nothing.
        let changed = held != (kept.view.clone(), kept.settled_proof.clone());
        let at = proof.envelope().server_time;
        kept.last_entry_ms = Some(kept.last_entry_ms.map_or(at, |t| t.max(at)));
        if let Some(deadline) = deadline {
            kept.own_deadline = deadline;
        }
        tx.put(&claim_key_of(&claim_key), &kept)?;
        tx.put(
            &entry_key(&claim_key, entry.expected_step),
            &KeptEntry {
                op: op.clone(),
                proof: proof.signed().clone(),
                seq: proof.envelope().seq,
            },
        )?;
        self.note_entry_writer(op, tx).await?;
        if changed {
            self.events.push(AppEvent::ClaimChanged { claim_key });
        }
        Ok(())
    }
}

/// Whether an error is the switch's `409 conflict` on a claim, whose `current` holds the
/// claim view, read for the caller.
pub fn claim_conflict(error: &AppError) -> Option<ClaimView> {
    let AppError::Switch(ClientError::Switch {
        code: ErrorCode::Conflict,
        current,
        ..
    }) = error
    else {
        return None;
    };
    ClaimView::from_value(current.get("claim")?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_switch_core::claims::{AttemptView, ClaimStatus};

    const DAY: u64 = 86_400_000;

    fn view(deadline: Option<u64>, status: ClaimStatus, outcome: Outcome) -> ClaimView {
        ClaimView {
            claim_key: [1; 32],
            status,
            owner: None,
            attempt_id: None,
            step: 2,
            attempts: vec![AttemptView {
                attempt_id: [2; 16],
                owner: [3; 16],
                outcome,
                opened_at: 0,
                orphan_after: 60,
                orphaned: false,
                possibly_duplicate: false,
                duplicate: false,
                resolved_by: Some([3; 16]),
            }],
            tombstone: true,
            deadline,
            divergent: false,
            next_possibly_duplicate: false,
            rebuilt: false,
        }
    }

    #[test]
    fn test_claims_evidence_kept_to_the_later_deadline_plus_the_window() {
        let v = view(Some(10 * DAY), ClaimStatus::Settled, Outcome::Done);
        assert_eq!(
            keep_until(&v, ObligationDeadline::At(12 * DAY), 0),
            Some(12 * DAY + RECONCILIATION_MS)
        );
        assert_eq!(
            keep_until(&v, ObligationDeadline::NotKnown, 0),
            Some(10 * DAY + RECONCILIATION_MS)
        );
        // An early pin: kept for good.
        assert_eq!(keep_until(&v, ObligationDeadline::NoDeadline, 0), None);
    }

    #[test]
    fn test_claims_evidence_pinned_to_none_kept_400_days_after_its_proof() {
        let v = view(None, ClaimStatus::Settled, Outcome::Done);
        assert_eq!(
            keep_until(&v, ObligationDeadline::NoDeadline, 5),
            Some(5 + MAX_CLAIM_AGE_MS)
        );
        // Beside a deadline of its own: the later of the two.
        let own = MAX_CLAIM_AGE_MS + DAY;
        assert_eq!(
            keep_until(&v, ObligationDeadline::At(own), 0),
            Some(own + RECONCILIATION_MS)
        );
    }

    #[test]
    fn test_claims_open_attempt_is_neither_finished_nor_deletable() {
        let open = view(Some(DAY), ClaimStatus::Attempting, Outcome::Open);
        assert!(!finished_or_failed(&open));
        let done = view(Some(DAY), ClaimStatus::Settled, Outcome::Done);
        assert!(finished_or_failed(&done));
        assert_eq!(deletable_from(&done, 0), Some(DAY + RECONCILIATION_MS));
    }

    #[test]
    fn test_claims_done_on_evidence_needs_its_ref() {
        assert!(ClaimOp::done([1; 32], 1, [2; 16], Basis::Evidence, None).is_err());
        let op = ClaimOp::done([1; 32], 1, [2; 16], Basis::Evidence, Some([3; 32])).unwrap();
        let OpKind::Claim(fields) = op.kind() else {
            panic!("a claim")
        };
        assert_eq!(fields.check().unwrap(), *op.entry());
    }

    #[test]
    fn test_claims_doubt_names_each_rule() {
        let none = ClaimDoubt::default();
        assert!(!none.doubtful());
        let orphaned = ClaimDoubt {
            orphaned: vec![[1; 16]],
            ..ClaimDoubt::default()
        };
        assert!(orphaned.doubtful());
    }
}
