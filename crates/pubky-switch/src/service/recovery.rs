//! Staged admission after a provider loss (Switch spec 12.6 step 2; Switch wire 7.4.14):
//! `POST /v1/{id}/recovery/admission`, and ending staged admission, for the signer's call and
//! for the recovery upload that carries the contacts.

use pubky_switch_core::chain::{
    ItemType, ProofBody, ProofState, ServiceTransition, TransitionProof, item_hash,
};
use pubky_switch_core::sig::SignedDoc;

use super::{Answer, Service, store_error};
use crate::{
    http::error::{ApiError, ErrorCode},
    keys::ServiceSigner,
    store::{AccountTxn, NewChainItem},
};

/// Who ends staged admission (Switch wire 7.4.14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionEnd {
    /// The signer, at `POST /recovery/admission`: an `admission` transition records it.
    Signer,
    /// A recovery upload carrying `lists.contacts` from the app `by`, which holds
    /// `lists.manage`, in the upload's transaction. No transition records it: the `upload`
    /// transition carries only `by`, `changes`, `proofs` and `at` (Switch wire 6.5), and the
    /// signer reads the end in `GET /apps`'s `recovery.admission_staged` (7.4.12).
    Upload {
        /// The uploading app.
        by: [u8; 16],
    },
}

/// The answer while admission is staged, to a sender the account can't otherwise admit, a
/// denied one included, so the staging doesn't reveal the deny list (Switch spec 12.6 step 2).
pub(super) fn staged_admission() -> ApiError {
    ApiError::new(
        ErrorCode::Staged,
        "12.6: admission is staged after a provider loss",
    )
}

/// Chain `transition` at `seq`, which this request gave out, signed with `signer`, the
/// account's key, and give its proof (Switch wire 6.5).
pub(super) async fn chain_transition(
    txn: &mut AccountTxn,
    signer: &ServiceSigner,
    transition: &ServiceTransition,
    seq: u64,
    time_ms: u64,
) -> Result<SignedDoc, ApiError> {
    let temporary = |_| ApiError::unavailable("7.6: a temporary failure");
    let identity = txn.head().identity_key;
    let signed = transition.sign(signer, &identity).map_err(temporary)?;
    let item_bytes = signed.doc_bytes().map_err(temporary)?;
    let hash = item_hash(ItemType::Service, &item_bytes);
    let (stub, _tip) = txn
        .head()
        .chain_tip()
        .append(seq, time_ms, ItemType::Service, hash, None)
        .map_err(temporary)?;
    txn.append_chain_item(&NewChainItem {
        seq,
        item_type: ItemType::Service,
        item_bytes: &item_bytes,
        stub: &stub,
        server_time_ms: time_ms,
        only_for: None,
        proof: None,
    })
    .await
    .map_err(|e| store_error(&e))?;
    let object = transition
        .proof_object()
        .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
    let proof = TransitionProof::sign(
        signer,
        &identity,
        ProofBody::new(stub, object, &ProofState::Service(transition.to_value())),
    )
    .map_err(temporary)?;
    Ok(proof.signed().clone())
}

impl Service {
    /// End staged admission at the account `txn` holds locked, `by` the signer or an upload
    /// (Switch spec 12.6 step 2; Switch wire 7.4.14). Idempotent: when admission isn't
    /// staged, or no longer is, it writes nothing, no transition included, and gives `None`.
    /// Ended by the signer, it chains the `admission` transition, signed with `signer`, the
    /// account's key, and gives its proof; ended by an upload, it chains nothing and gives
    /// `None` ([`AdmissionEnd::Upload`]).
    pub(crate) async fn end_staged_admission(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        by: AdmissionEnd,
        time_ms: u64,
    ) -> Result<Option<SignedDoc>, ApiError> {
        if !txn.end_admission().await.map_err(|e| store_error(&e))? {
            return Ok(None);
        }
        if let AdmissionEnd::Upload { .. } = by {
            return Ok(None);
        }
        let seq = txn.next_seq().map_err(|e| store_error(&e))?;
        let transition = ServiceTransition::Admission { at: time_ms };
        chain_transition(txn, signer, &transition, seq, time_ms)
            .await
            .map(Some)
    }

    /// `POST /v1/{id}/recovery/admission`, from the signer, with an empty body (Switch wire
    /// 7.4.14): ends staged admission, answering with the `admission` transition's proof, or
    /// with none when admission wasn't staged, so a retry after a lost answer, or a call
    /// where nothing was staged, succeeds. `404` at an account whose generation began with no
    /// recovery.
    pub(super) async fn recovery_admission(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        body: &[u8],
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        if !body.is_empty() {
            return Err(ApiError::bad_request("7.4.14: the body is empty"));
        }
        if txn.recovery().await.map_err(|e| store_error(&e))?.is_none() {
            return Err(ApiError::not_found("7.4.14: no recovery"));
        }
        let proof = self
            .end_staged_admission(txn, signer, AdmissionEnd::Signer, time_ms)
            .await?;
        let head = self
            .head(txn, signer)
            .await
            .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
        let proofs: Vec<&SignedDoc> = proof.iter().collect();
        let body = super::identity::write_answer(&proofs, &head.to_json())?;
        Ok(Answer::ok(body).with_head(Some(head)))
    }
}
