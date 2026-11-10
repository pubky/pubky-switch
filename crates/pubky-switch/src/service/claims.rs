//! `GET /v1/{id}/claims/{claim_key}` (Switch wire 7.4.8), `POST /v1/{id}/apps/{app_id}/revoke`
//! (7.4.12) and the deletion of claims whose time has passed (7.3 step 4).

use pubky_switch_core::{
    chain::{ItemType, ProofBody, ProofState, ServiceTransition, TransitionProof, item_hash},
    enc::{unb64_array, zbase32_decode},
    records::{AppCert, IdentityDoc},
    scopes::Permission,
    sig::SignedDoc,
};
use serde_json::json;

use super::{Answer, Service, batch, store_error};
use crate::{
    http::error::{ApiError, ErrorCode},
    keys::ServiceSigner,
    store::{AccountTxn, NewChainItem},
};

fn temporary() -> ApiError {
    ApiError::unavailable("7.6: a temporary failure")
}

impl Service {
    /// Step 4 of Switch wire 7.3, with trusted time only: delete the tombstones and failed
    /// claims whose deadline plus the reconciliation window has passed (6.8), by the time
    /// base, never the stamped time, which a reading without trusted time may have moved
    /// ahead.
    pub(super) async fn delete_due_claims(
        &self,
        txn: &mut AccountTxn,
        base_ms: u64,
        trusted: bool,
    ) -> Result<(), ApiError> {
        if trusted {
            txn.delete_due_claims(base_ms)
                .await
                .map_err(|e| store_error(&e))?;
        }
        Ok(())
    }

    /// `GET /v1/{id}/claims/{claim_key}`, from an own app holding `claims.read` (Switch wire
    /// 7.4.8): the claim view at the service time, and its entries, none for a tombstone.
    pub(super) async fn get_claim(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        held: Option<&IdentityDoc>,
        writer: Option<&AppCert>,
        claim_key: &str,
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        if !writer.is_some_and(|cert| cert.has_permission(Permission::ClaimsRead)) {
            return Err(ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4.8: reading claims needs claims.read",
            ));
        }
        let claim_key = unb64_array::<32>(claim_key)
            .map_err(|_| ApiError::bad_request("7.4.8: a claim key is b64(32)"))?;
        let Some((_, claim)) = txn
            .claims(&[claim_key])
            .await
            .map_err(|e| store_error(&e))?
            .into_iter()
            .next()
        else {
            return Err(ApiError::not_found("7.4.8: no such claim"));
        };
        let apps = batch::load_apps(txn, held, time_ms)
            .await
            .map_err(|e| store_error(&e))?;
        let current = |app: &[u8; 16]| apps.is_current(app);
        let view = claim.view(&claim_key, time_ms, &current).to_value();
        let entries = if claim.tombstone {
            Vec::new()
        } else {
            txn.claim_entries(&claim_key)
                .await
                .map_err(|e| store_error(&e))?
                .into_iter()
                .map(|e| json!({ "step": e.step, "seq": e.seq, "op": e.op, "proof": e.proof }))
                .collect()
        };
        let body = serde_json::to_vec(&json!({ "claim": view, "entries": entries }))
            .map_err(|_| temporary())?;
        let head = self.head(txn, signer).await.ok_or_else(temporary)?;
        Ok(Answer::ok(body).with_head(Some(head)))
    }

    /// `POST /v1/{id}/apps/{app_id}/revoke`, from the signer (Switch wire 7.4.12, Switch spec
    /// 12.2 step 1): the app is kept as revoked for good, its invite codes are withdrawn and
    /// it leaves the directory, and a `revoke` transition is chained. An app revoked already
    /// gets `{ "proofs": [], "head" }`.
    pub(super) async fn revoke(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        held: Option<&IdentityDoc>,
        app_id: &str,
        body: &[u8],
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        if !body.is_empty() {
            return Err(ApiError::bad_request(
                "7.4.12: a revocation has an empty body",
            ));
        }
        let unknown =
            || ApiError::not_found("7.4.12: an app the service and identity.json don't know");
        let app = zbase32_decode::<16>(app_id).map_err(|_| unknown())?;
        let kept = txn.kept_app_ids().await.map_err(|e| store_error(&e))?;
        let stored = txn.apps().await.map_err(|e| store_error(&e))?;
        let stored_app = stored.iter().find(|a| a.app_id == app);
        let listed =
            held.is_some_and(|doc| doc.listed_cert(&app).is_some() || doc.lists_removed(&app));
        if kept.contains(&app) {
            // Revoked already, departed, or named by an enrollment: never current again.
            let head = self.head(txn, signer).await.ok_or_else(temporary)?;
            let body = super::identity::write_answer(&[], &head.to_json())?;
            return Ok(Answer::ok(body).with_head(Some(head)));
        }
        if stored_app.is_none() && !listed {
            return Err(unknown());
        }
        txn.revoke_app(&app, time_ms)
            .await
            .map_err(|e| store_error(&e))?;
        // It leaves the directory: its record and receive key no longer show, and a
        // reachable app no longer counts among the reachable ones (Switch wire 7.4.10).
        let (directory_version, apps_version) = txn
            .directory_versions()
            .await
            .map_err(|e| store_error(&e))?;
        let reachable = stored_app.is_some_and(|a| a.receive_key.is_some());
        txn.set_directory_versions(
            directory_version.saturating_add(1),
            apps_version.saturating_add(u64::from(reachable)),
        )
        .await
        .map_err(|e| store_error(&e))?;
        let identity = txn.head().identity_key;
        let transition = ServiceTransition::Revoke {
            app_id: app,
            at: time_ms,
        };
        let signed: SignedDoc = transition
            .sign(signer, &identity)
            .map_err(|_| temporary())?;
        let item_bytes = signed.doc_bytes().map_err(|_| temporary())?;
        let hash = item_hash(ItemType::Service, &item_bytes);
        let seq = txn.next_seq().map_err(|e| store_error(&e))?;
        let (stub, _tip) = txn
            .head()
            .chain_tip()
            .append(seq, time_ms, ItemType::Service, hash, None)
            .map_err(|_| temporary())?;
        txn.append_chain_item(&NewChainItem {
            seq,
            item_type: ItemType::Service,
            item_bytes: &item_bytes,
            stub: &stub,
            server_time_ms: time_ms,
            only_for: None,
        })
        .await
        .map_err(|e| store_error(&e))?;
        let object = transition.proof_object().ok_or_else(temporary)?;
        let proof = TransitionProof::sign(
            signer,
            &identity,
            ProofBody::new(stub, object, &ProofState::Service(transition.to_value())),
        )
        .map_err(|_| temporary())?;
        let head = self.head(txn, signer).await.ok_or_else(temporary)?;
        let body = super::identity::write_answer(&[proof.signed()], &head.to_json())?;
        Ok(Answer::ok(body).with_head(Some(head)))
    }
}
