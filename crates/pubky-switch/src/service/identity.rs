//! `PUT /v1/{id}/identity` and the public `GET /v1/{id}/identity` (Switch wire 7.4.2,
//! 7.4.15).

use pubky_switch_core::{
    chain::{ItemType, ProofBody, ProofState, TransitionProof, item_hash},
    enc::b64,
    http::IdentityDelivery,
    records::{AccountView, Delivery, DeliveryRefusal, IdentityDoc, KeptProofs, check_delivery},
};
use serde_json::{Value, json};

use super::{Answer, Service, store_error};
use crate::{
    http::{
        SwitchRequest,
        error::{ApiError, ErrorCode},
    },
    keys::ServiceSigner,
    store::{AccountTxn, HeldIdentity, NewChainItem},
};

/// The copy a `409 stale_identity` to the signer carries: `{ "version", "generation",
/// "hash", "identity" }`, or `null` when the account holds none (Switch wire 7.6).
pub fn stale_identity_current(held: Option<&IdentityDoc>) -> Value {
    match held {
        Some(doc) => json!({
            "version": doc.version(),
            "generation": doc.generation(),
            "hash": b64(&doc.hash()),
            "identity": doc.signed(),
        }),
        None => Value::Null,
    }
}

/// A write answer's body: `{ "proofs": [...], "head": signed head }` (Switch wire 7.1).
pub(super) fn write_answer(
    proofs: &[&pubky_switch_core::sig::SignedDoc],
    head: &[u8],
) -> Result<Vec<u8>, ApiError> {
    let mut body = b"{\"proofs\":[".to_vec();
    for (index, proof) in proofs.iter().enumerate() {
        if index > 0 {
            body.push(b',');
        }
        let encoded = serde_json::to_vec(proof)
            .map_err(|_| ApiError::unavailable("7.6: a temporary failure"))?;
        body.extend_from_slice(&encoded);
    }
    body.extend_from_slice(b"],\"head\":");
    body.extend_from_slice(head);
    body.push(b'}');
    Ok(body)
}

impl Service {
    /// `PUT /v1/{id}/identity`, from the signer (Switch wire 7.4.2).
    pub(super) async fn put_identity(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        request: &SwitchRequest,
        held: Option<&IdentityDoc>,
        time_ms: u64,
    ) -> Result<(Answer, bool), ApiError> {
        let identity_key = txn.head().identity_key;
        let delivery = IdentityDelivery::parse(&request.body)
            .map_err(|_| ApiError::bad_request("7.4.2: the body isn't a delivery"))?;
        let doc = IdentityDoc::verify(&delivery.identity, &identity_key).map_err(|_| {
            ApiError::bad_request("3.3: the identity.json doesn't verify for this identity")
        })?;
        let service_key = super::PublicKeyBytes::public_key_bytes(signer);
        let staged = !super::rules::names_this_service(held, &self.origin, &service_key);
        let pending_key = match txn.pending_key().await.map_err(|e| store_error(&e))? {
            Some(id) => Some(
                self.keys
                    .public_key(&id)
                    .await
                    .map_err(|_| ApiError::unavailable("7.6: a temporary failure"))?,
            ),
            None => None,
        };
        let kept_app_ids = txn.kept_app_ids().await.map_err(|e| store_error(&e))?;
        let app_limit = txn
            .announced_limits()
            .await
            .map_err(|e| store_error(&e))?
            .app_limit;
        let view = AccountView {
            held,
            app_limit,
            staged,
            origin: &self.origin,
            pending_key,
            kept_app_ids: &kept_app_ids,
            // No record or claim proofs are kept before operations are served.
            kept_proofs: KeptProofs::default(),
        };
        match check_delivery(&view, &doc, delivery.prev.as_ref()) {
            Err(DeliveryRefusal::BadRequest(why)) => Err(ApiError::bad_request(why)),
            Err(DeliveryRefusal::StaleIdentity(why)) => {
                Err(ApiError::new(ErrorCode::StaleIdentity, why)
                    .with_current(stale_identity_current(held)))
            }
            Err(DeliveryRefusal::Conflict { proof_generations }) => Err(ApiError::new(
                ErrorCode::Conflict,
                "3.3: a needed service key is left out",
            )
            .with_current(json!({ "proof_generations": proof_generations }))),
            Ok(Delivery::Retry) => {
                // The same bytes again: no new chain item, the original delivery's proof.
                let proof = txn
                    .held_identity()
                    .await
                    .map_err(|e| store_error(&e))?
                    .and_then(|held| held.proof);
                let head = self
                    .head(txn, signer)
                    .await
                    .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
                let proofs: Vec<_> = proof.iter().collect();
                let body = write_answer(&proofs, &head.to_json())?;
                Ok((Answer::ok(body).with_head(Some(head)), !staged))
            }
            Ok(Delivery::New(Some(_))) => Err(ApiError::unavailable(
                "7.4.2: a generation change isn't served yet",
            )),
            // A first document that starts a recovery, or at another generation than the
            // account's: its chain starts with the recovery transition, at its own
            // generation (Switch wire 7.4.2), which comes with recovery.
            Ok(Delivery::New(None))
                if held.is_none()
                    && (doc.body().recovery_from.is_some()
                        || doc.generation() != txn.head().generation) =>
            {
                Err(ApiError::unavailable(
                    "7.4.2: a generation change isn't served yet",
                ))
            }
            Ok(Delivery::New(None)) => self.chain_delivery(txn, signer, &doc, time_ms).await,
        }
    }

    /// Chain a new `identity.json` version and answer with its proof and the new head.
    async fn chain_delivery(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        doc: &IdentityDoc,
        time_ms: u64,
    ) -> Result<(Answer, bool), ApiError> {
        let failure = |_| ApiError::unavailable("7.6: a temporary failure");
        let identity_key = txn.head().identity_key;
        let seq = txn.next_seq().map_err(|e| store_error(&e))?;
        let item_bytes = doc.signed().doc_bytes().map_err(failure)?;
        let hash = item_hash(ItemType::Identity, &item_bytes);
        let (stub, _tip) = txn
            .head()
            .chain_tip()
            .append(seq, time_ms, ItemType::Identity, hash, None)
            .map_err(failure)?;
        txn.append_chain_item(&NewChainItem {
            seq,
            item_type: ItemType::Identity,
            item_bytes: &item_bytes,
            stub: &stub,
            server_time_ms: time_ms,
            only_for: None,
            proof: None,
        })
        .await
        .map_err(|e| store_error(&e))?;
        let state = ProofState::Identity {
            version: doc.version(),
            generation: doc.generation(),
            data_epoch: doc.data_epoch(),
        };
        let proof = TransitionProof::sign(
            signer,
            &identity_key,
            ProofBody::new(stub, "identity".into(), &state),
        )
        .map_err(failure)?;
        txn.set_identity(&HeldIdentity {
            doc: doc.signed().clone(),
            proof: Some(proof.signed().clone()),
        })
        .await
        .map_err(|e| store_error(&e))?;
        let head = self
            .head(txn, signer)
            .await
            .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
        let body = write_answer(&[proof.signed()], &head.to_json())?;
        let service_key = super::PublicKeyBytes::public_key_bytes(signer);
        let serving = super::rules::names_this_service(Some(doc), &self.origin, &service_key);
        Ok((Answer::ok(body).with_head(Some(head)), serving))
    }

    /// The public read of the newest `identity.json` (Switch wire 7.4.15): its limits are
    /// checked before the account's lock.
    pub(super) fn public_identity(
        &self,
        held: Option<&IdentityDoc>,
        serving: bool,
    ) -> Result<Answer, ApiError> {
        let Some(doc) = held else {
            return Err(ApiError::not_found("7.4.15: no identity.json held"));
        };
        super::rules::staged_gate(&crate::http::route::Call::GetIdentity, !serving)?;
        let mut body = b"{\"identity\":".to_vec();
        body.extend_from_slice(
            &serde_json::to_vec(doc.signed())
                .map_err(|_| ApiError::unavailable("7.6: a temporary failure"))?,
        );
        body.push(b'}');
        let mut answer = Answer::ok(body);
        answer.cacheable = true;
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_stale_current_without_a_copy_is_null() {
        assert_eq!(stale_identity_current(None), Value::Null);
    }

    #[test]
    fn test_identity_write_answer_shape() {
        let body = write_answer(&[], b"{\"seq\":0}").expect("body");
        assert_eq!(body, b"{\"proofs\":[],\"head\":{\"seq\":0}}");
    }
}
