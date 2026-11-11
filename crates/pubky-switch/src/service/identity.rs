//! `PUT /v1/{id}/identity` and the public `GET /v1/{id}/identity` (Switch wire 7.4.2,
//! 7.4.15).

use pubky_switch_core::{
    chain::{ItemType, ProofBody, ProofState, ServiceTransition, TransitionProof, item_hash},
    enc::b64,
    http::IdentityDelivery,
    records::{
        AccountView, Delivery, DeliveryRefusal, GenerationChange, IdentityDoc, KeptProofs,
        check_delivery,
    },
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
        trusted: bool,
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
        // The kept proofs all name the generation the account serves, whose key is this
        // one; an earlier generation's come with generation changes, which carry its key.
        let (record_generations, entry_generations) = txn
            .kept_proof_generations()
            .await
            .map_err(|e| store_error(&e))?;
        let generation = txn.head().generation;
        let keyed = |generations: Vec<u64>| -> Result<Vec<(u64, [u8; 32])>, ApiError> {
            generations
                .into_iter()
                .map(|g| {
                    if g == generation {
                        Ok((g, service_key))
                    } else {
                        tracing::error!(generation = g, "a kept proof of an earlier generation");
                        Err(ApiError::unavailable("7.6: a temporary failure"))
                    }
                })
                .collect()
        };
        let records = keyed(record_generations)?;
        let claim_entries = keyed(entry_generations)?;
        let view = AccountView {
            held,
            app_limit,
            staged,
            origin: &self.origin,
            pending_key,
            kept_app_ids: &kept_app_ids,
            kept_proofs: KeptProofs {
                records: &records,
                claim_entries: &claim_entries,
            },
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
            // A provider loss at this service: the account starts afresh under its pending
            // key (Switch wire 3.3, 7.4.2).
            Ok(Delivery::New(Some(GenerationChange::ProviderLoss))) => {
                self.recover_in_place(txn, &doc, trusted, time_ms).await
            }
            // A key rotation, and the move to a staged account, aren't served.
            Ok(Delivery::New(Some(_))) => Err(ApiError::unavailable(
                "7.4.2: a generation change isn't served yet",
            )),
            // A first document that starts a recovery: the account takes its generation, and
            // its chain starts with the `recovery` transition (Switch wire 3.3, 7.4.2).
            Ok(Delivery::New(None)) if held.is_none() && doc.body().recovery_from.is_some() => {
                // It names this service: its origin and the account's key (wire 7.4.2).
                if doc.inbox().url != self.origin || doc.inbox().service_key != service_key {
                    return Err(ApiError::bad_request(
                        "7.4.2: a recovery's first document names this service",
                    ));
                }
                let recovery_from = doc.body().recovery_from.unwrap_or_default();
                // Admission is staged whenever the document lists an app: the service can't
                // see their permissions yet (Switch spec 12.6 step 2).
                let stages = !doc.body().apps.is_empty();
                txn.start_recovery(doc.generation(), recovery_from, time_ms, stages)
                    .await
                    .map_err(|e| store_error(&e))?;
                self.chain_recovery(txn, signer, recovery_from, time_ms)
                    .await?;
                self.chain_delivery(txn, signer, None, &doc, trusted, time_ms)
                    .await
            }
            // A first document at another generation than the account's, an account enrolled
            // with a document: not taken without a recovery.
            Ok(Delivery::New(None))
                if held.is_none() && doc.generation() != txn.head().generation =>
            {
                Err(ApiError::unavailable(
                    "7.4.2: a generation change isn't served yet",
                ))
            }
            Ok(Delivery::New(None)) => {
                self.chain_delivery(txn, signer, held, &doc, trusted, time_ms)
                    .await
            }
        }
    }

    /// A provider loss at this service (Switch wire 3.3, 3.7, 7.4.2): `doc`, at the next
    /// generation, names the account's pending key and `recovery_from` the generation that
    /// ends. Under the account's row lock, the keying lock is taken exclusive first, so no
    /// answer of the outgoing key is signed once this commits, and nothing here signs with
    /// it. Then the account starts afresh under the pending key
    /// ([`AccountTxn::start_recovery_in_place`]), its chain begins with the `recovery`
    /// transition, and `doc` is taken as its first document. The answer is the new key's.
    async fn recover_in_place(
        &self,
        txn: &mut AccountTxn,
        doc: &IdentityDoc,
        trusted: bool,
        time_ms: u64,
    ) -> Result<(Answer, bool), ApiError> {
        let temporary = || ApiError::unavailable("7.6: a temporary failure");
        let recovery_from = doc.body().recovery_from.ok_or_else(temporary)?;
        // The generation after the one it ends, the account's (wire 3.3): checked by the
        // delivery's rules, and again here, where the account's generation changes.
        if recovery_from != txn.head().generation
            || recovery_from.checked_add(1) != Some(doc.generation())
        {
            return Err(temporary());
        }
        // It lists no App ID the pending key's enrollments named: the new generation keeps
        // them from its start, as a new account does (wire 3.7).
        let held_revoked = txn
            .pending_revoked_apps()
            .await
            .map_err(|e| store_error(&e))?;
        if doc
            .body()
            .apps
            .iter()
            .any(|app| held_revoked.contains(&app.app_id))
        {
            return Err(ApiError::bad_request(
                "3.3: apps lists an App ID the service revoked or saw depart",
            ));
        }
        let new_key = txn
            .pending_key()
            .await
            .map_err(|e| store_error(&e))?
            .ok_or_else(temporary)?;
        let new_signer = self.keys.signer(&new_key).await.map_err(|_| temporary())?;
        txn.exclude_signers().await.map_err(|e| store_error(&e))?;
        txn.start_recovery_in_place(
            &new_key,
            recovery_from,
            time_ms,
            self.limits.max_enrollments,
            !doc.body().apps.is_empty(),
        )
        .await
        .map_err(|e| store_error(&e))?;
        self.chain_recovery(txn, &new_signer, recovery_from, time_ms)
            .await?;
        let (mut answer, serving) = self
            .chain_delivery(txn, &new_signer, None, doc, trusted, time_ms)
            .await?;
        answer.rekeyed = Some(new_key);
        Ok((answer, serving))
    }

    /// The `recovery` transition, the first chain item of the generation a provider loss
    /// starts (Switch wire 6.5, 7.4.2), signed with that generation's key, `signer`.
    async fn chain_recovery(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        recovery_from: u64,
        time_ms: u64,
    ) -> Result<(), ApiError> {
        let temporary = |_| ApiError::unavailable("7.6: a temporary failure");
        let transition = ServiceTransition::Recovery {
            recovery_from,
            at: time_ms,
        };
        let identity = txn.head().identity_key;
        let signed = transition.sign(signer, &identity).map_err(temporary)?;
        let item_bytes = signed.doc_bytes().map_err(temporary)?;
        let hash = item_hash(ItemType::Service, &item_bytes);
        let seq = txn.next_seq().map_err(|e| store_error(&e))?;
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
        .map_err(|e| store_error(&e))
    }

    /// Chain a new `identity.json` version and answer with its proof and the new head.
    async fn chain_delivery(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        previous: Option<&IdentityDoc>,
        doc: &IdentityDoc,
        trusted: bool,
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
        // An app it no longer makes current stops holding entries at once (Switch wire
        // 7.4.2, 9.1).
        let release = self.release(trusted);
        let current = super::batch::settle_change(txn, previous, Some(doc), None, time_ms, release)
            .await
            .map_err(|e| store_error(&e))?;
        // After its chain item: an app it no longer makes current departs at it, its unread
        // entries no current app can open becoming unreadable items, and the shares change
        // (Switch wire 7.4.4).
        release
            .departed(txn, &current)
            .await
            .map_err(|e| store_error(&e))?;
        // Where the keys_through of each app it lists for the first time starts (Switch
        // wire 7.4.12).
        let listed = crate::store::newly_listed(previous, doc);
        txn.note_listings(&listed, doc.data_epoch())
            .await
            .map_err(|e| store_error(&e))?;
        // The departures whose rotation this version makes.
        let removed: Vec<[u8; 16]> = doc.body().removed.iter().map(|app| app.app_id).collect();
        txn.note_rotations(&removed, doc.data_epoch())
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
