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

pub(crate) fn claim_key_of(claim_key: &[u8; 32]) -> String {
    format!("{CLAIM_PREFIX}{}", b64(claim_key))
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
pub struct ClaimWritten {
    /// The claim view after the entry.
    pub view: ClaimView,
    /// The entry's transition proof, bound to the operation.
    pub proof: TransitionProof,
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
            let (submitted, views) = self.submit_checked(batch).await?;
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
            Ok(ClaimWritten { view, proof })
        })
        .await
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
            let state = TransitionProof::peek(&item.proof)
                .ok()
                .and_then(|p| ClaimView::from_value(&p.body().state).ok());
            if state.is_some_and(|s| s.status == ClaimStatus::Settled) {
                kept.settled_proof = Some(item.proof.clone());
            }
        }
        tx.put(&claim_key_of(claim_key), &kept)?;
        self.commit(tx).await?;
        Ok(Some(read))
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
            return Ok(Err(
                "Switch wire 7.4.8: the claim's step doesn't follow its last entry".into(),
            ));
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

    /// The claim entries the app keeps, each with its writer's certificate where the app
    /// knows it, and the SETTLED and tombstone proofs: evidence for the uploads of a move
    /// or a recovery (Switch spec 6.3, 12.5, 12.6).
    pub(crate) async fn claim_evidence_items(
        &self,
    ) -> Result<(Vec<KeptOp>, Vec<SignedDoc>), AppError> {
        let mut ops = Vec::new();
        for (_, entry) in self.reader().scan::<KeptEntry>(ENTRY_PREFIX).await? {
            let Some(writer) = SignedOp::peek(&entry.op)
                .ok()
                .and_then(|op| op.body().app_id)
            else {
                continue;
            };
            if let Some(cert) = self.cert_of(&writer).await? {
                ops.push(KeptOp {
                    op: entry.op,
                    cert: cert.signed().clone(),
                    proof: Some(entry.proof),
                });
            }
        }
        let proofs = self
            .reader()
            .scan::<KeptClaim>(CLAIM_PREFIX)
            .await?
            .into_iter()
            .filter_map(|(_, kept)| kept.settled_proof)
            .collect();
        Ok((ops, proofs))
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
        let held_step = kept.view().map_or(0, |v| v.step);
        if view.step >= held_step {
            kept.view = view.to_value();
        }
        if view.status == ClaimStatus::Settled {
            kept.settled_proof = Some(proof.signed().clone());
        }
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
        self.events.push(AppEvent::ClaimChanged { claim_key });
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
