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

/// A `GET /claims` read taken under the lock, whose entries are read after it.
#[derive(Debug)]
pub(super) struct ClaimRead {
    account: String,
    claim_key: [u8; 32],
    view: serde_json::Value,
    /// How many entries the claim had: its step, 0 for a tombstone.
    steps: u64,
    /// The `seq` of its last entry, which only this claim holds: entries read after the
    /// lock are this claim's, not those of one made again at its key since.
    last_seq: Option<u64>,
}

fn temporary() -> ApiError {
    ApiError::unavailable("7.6: a temporary failure")
}

impl Service {
    /// `GET /v1/{id}/claims/{claim_key}`, from an own app holding `claims.read` (Switch wire
    /// 7.4.8): the claim view at the service time, under the lock. Its entries, none for a
    /// tombstone, are read once the lock is gone ([`ClaimRead`]): entries never change once
    /// written, so the first `step` of them are the claim's at this read.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn get_claim(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        held: Option<&IdentityDoc>,
        writer: Option<&AppCert>,
        claim_key: &str,
        due: Option<u64>,
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
        let not_found = || ApiError::not_found("7.4.8: no such claim");
        let Some((_, claim)) = txn
            .claims(&[claim_key])
            .await
            .map_err(|e| store_error(&e))?
            .into_iter()
            .next()
        else {
            return Err(not_found());
        };
        // A claim that is due is gone, whatever step 4's batch reached (Switch wire 7.3).
        if due.is_some_and(|base| claim.deletable(Some(base), self.limits.max_claim_age_ms)) {
            txn.delete_claim(&claim_key)
                .await
                .map_err(|e| store_error(&e))?;
            return Err(not_found());
        }
        let apps = batch::load_apps(txn, held, time_ms)
            .await
            .map_err(|e| store_error(&e))?;
        let current = |app: &[u8; 16]| apps.is_current(app);
        let view = claim.view(&claim_key, time_ms, &current).to_value();
        let steps = if claim.tombstone { 0 } else { claim.step };
        let last_seq = match steps.checked_sub(1) {
            Some(last) => Some(
                txn.claim_entry_seq(&claim_key, last)
                    .await
                    .map_err(|e| store_error(&e))?
                    .ok_or_else(temporary)?,
            ),
            None => None,
        };
        let head = self.head(txn, signer).await.ok_or_else(temporary)?;
        let mut answer = Answer::ok(Vec::new()).with_head(Some(head));
        answer.deferred = Some(super::Deferred::Claim(ClaimRead {
            account: txn.head().id.clone(),
            claim_key,
            view,
            steps,
            last_seq,
        }));
        Ok(answer)
    }

    /// The body of a `GET /claims` answer, once the account's lock is gone: the view, and
    /// the entries of the claim at the read.
    ///
    /// # Errors
    ///
    /// `503 unavailable` if they can't be read, or the claim lost them since, as a
    /// deletion would.
    pub(super) async fn claim_body(&self, read: &ClaimRead) -> Result<Vec<u8>, ApiError> {
        let entries = self
            .store
            .claim_entries_before(&read.account, &read.claim_key, read.steps)
            .await
            .map_err(|e| store_error(&e))?;
        // The claim lost entries since, or another claim took its key: a temporary failure,
        // never a view with entries of another claim.
        if u64::try_from(entries.len()).ok() != Some(read.steps)
            || entries.last().map(|e| e.seq) != read.last_seq
        {
            return Err(temporary());
        }
        let entries: Vec<_> = entries
            .into_iter()
            .map(|e| json!({ "step": e.step, "seq": e.seq, "op": e.op, "proof": e.proof }))
            .collect();
        serde_json::to_vec(&json!({ "claim": read.view, "entries": entries }))
            .map_err(|_| temporary())
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
        // The data epoch its rotation goes above (Switch wire 7.4.12 awaiting_rotation).
        let data_epoch = held.map_or(1, IdentityDoc::data_epoch);
        txn.revoke_app(&app, time_ms, data_epoch)
            .await
            .map_err(|e| store_error(&e))?;
        // Entries no longer wait for it (Switch wire 9.1).
        batch::release_entries(txn, held, time_ms)
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
            proof: None,
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
