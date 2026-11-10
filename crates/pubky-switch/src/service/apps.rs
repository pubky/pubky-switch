//! `GET /v1/{id}/apps` (Switch wire 7.4.12): the signer's view of every app the service
//! knows or the newest `identity.json` lists, with the newest document itself and the
//! generations whose service keys that document must keep.
//!
//! The answer is signed like every other, its `Switch-Server-Time` included, and never
//! cached, so the signer may bound a removal's time by that time and take an epoch floor
//! from `keys_through` and `bundle_ranges`.

use std::collections::{BTreeMap, BTreeSet};

use pubky_switch_core::{
    enc::{b64, zbase32_encode},
    ops::{StoredPart, keys_through},
    records::{AppRecord, IdentityDoc, needed_generations},
    time::rfc3339,
};
use serde_json::{Value, json};

use super::{Answer, Service, batch::state::OpsState, store_error};
use crate::{
    http::error::ApiError,
    keys::ServiceSigner,
    store::{AccountTxn, AppsView, KeptAppId, KeptReason, StoreError},
};

fn time(at: Option<u64>) -> Value {
    at.map_or(Value::Null, |at| json!(rfc3339(at)))
}

/// Whether a departed app still awaits its rotation (Switch wire 7.4.12): until a delivered
/// `identity.json` lists it in `removed` at a higher data epoch than the newest document's
/// at its departure, which is done for good. Only a departure awaits one: the signer
/// revokes, and rotates for its own revocations.
pub(crate) fn awaiting_rotation(kept: &KeptAppId) -> bool {
    kept.reason == KeptReason::Departed && !kept.rotated
}

/// The statuses of `GET /apps`, at service time `now`, by App ID (Switch wire 7.4.12):
/// every app with a row, every App ID kept for good, and every app `doc` lists.
///
/// # Errors
///
/// A [`StoreError`] for a stored document that doesn't verify.
pub(crate) fn statuses(
    identity: [u8; 32],
    generation: u64,
    view: &AppsView,
    doc: Option<&IdentityDoc>,
    now: u64,
) -> Result<Vec<Value>, StoreError> {
    let mut state = OpsState::new(identity, generation, 0, now);
    state.doc = doc.cloned();
    for app in &view.apps {
        state
            .apps
            .insert(app.app_id, super::batch::held_app(app, &identity)?);
    }
    let kept: BTreeMap<[u8; 16], &KeptAppId> =
        view.kept.iter().map(|kept| (kept.app_id, kept)).collect();
    state.kept = kept.keys().copied().collect();
    let rows: BTreeMap<[u8; 16], &crate::store::StoredApp> =
        view.apps.iter().map(|app| (app.app_id, app)).collect();
    let mut ids: BTreeSet<[u8; 16]> = rows.keys().copied().collect();
    ids.extend(kept.keys().copied());
    if let Some(doc) = doc {
        ids.extend(doc.body().apps.iter().map(|app| app.app_id));
    }
    let mut statuses = Vec::with_capacity(ids.len());
    for id in ids {
        let row = rows.get(&id).copied();
        let kept_id = kept.get(&id).copied();
        let held = state.apps.get(&id);
        // An app with a record is current by the full rule (Switch spec 3.4); one the
        // document lists that hasn't registered yet, while it isn't kept.
        let current = if held.is_some_and(|app| app.record.is_some()) {
            state.is_current(&id)
        } else {
            kept_id.is_none() && doc.is_some_and(|doc| doc.listed_cert(&id).is_some())
        };
        let (revoked_at, departed_at) = match kept_id.map(|kept| (kept.reason, kept.at_ms)) {
            Some((KeptReason::Revoked | KeptReason::Enrolled, at)) => (Some(at), None),
            Some((KeptReason::Departed, at)) => (None, Some(at)),
            None => (None, None),
        };
        let parts = view.parts.get(&id).map(Vec::as_slice).unwrap_or_default();
        let spans: Vec<StoredPart> = parts
            .iter()
            .map(|part| StoredPart {
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
                seq: part.seq,
            })
            .collect();
        let cursor = row
            .and_then(|row| row.cursor)
            .filter(|cursor| cursor.generation == generation)
            .map_or(0, |cursor| cursor.seq);
        let open_attempts: Vec<Value> = view
            .open_attempts
            .iter()
            .filter(|attempt| attempt.owner == id)
            .map(|attempt| {
                json!({
                    "claim_key": b64(&attempt.claim_key),
                    "attempt_id": b64(&attempt.attempt_id),
                    "outcome": if attempt.unknown { "unknown" } else { "open" },
                })
            })
            .collect();
        statuses.push(json!({
            "app_id": zbase32_encode(&id),
            "current": current,
            "last_seen": time(view.last_seen.get(&id).copied()),
            "revoked_at": time(revoked_at),
            "departed_at": time(departed_at),
            "awaiting_rotation": kept_id.is_some_and(awaiting_rotation),
            "open_attempts": open_attempts,
            // The inbox comes with POST /inbox: nothing is unread, no app is lagging.
            "unread_entries": 0,
            "sole_target_unread": 0,
            "record_cert": held
                .and_then(|app| app.record.as_ref())
                .map_or(Value::Null, |record| json!(b64(&AppRecord::cert(record).hash()))),
            "record_at": time(held.and_then(|app| app.record_at)),
            "lagging": false,
            "keys_through": keys_through(view.listings.get(&id).copied(), &spans, cursor),
            "full_bundle_requested": time(held.and_then(|app| app.full_requested)),
            "bundle_ranges": parts
                .iter()
                .map(|part| json!([part.first_epoch, part.last_epoch]))
                .collect::<Vec<_>>(),
            "cert_expires_at": time(state.checked_cert(&id).map(|cert| cert.expires_at())),
        }));
    }
    Ok(statuses)
}

impl Service {
    /// `GET /v1/{id}/apps`, from the signer (Switch wire 7.4.12).
    pub(super) async fn get_apps(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        held: Option<&IdentityDoc>,
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        let head = txn.head().clone();
        let view = txn.apps_view().await.map_err(|e| store_error(&e))?;
        let apps = statuses(head.identity_key, head.generation, &view, held, time_ms)
            .map_err(|e| store_error(&e))?;
        let recovery_from = held.and_then(|doc| doc.body().recovery_from);
        let proof_generations = needed_generations(
            &view.record_generations,
            &view.claim_entry_generations,
            recovery_from,
        );
        let mut body = json!({
            "apps": apps,
            "identity": held.map_or(Value::Null, |doc| json!(doc.signed())),
            // Recovery comes with provider changes.
            "recovery": null,
        });
        // Absent when no kept proof names a generation (Switch wire 7.4.12).
        if !proof_generations.is_empty() {
            body["proof_generations"] = json!(proof_generations);
        }
        let head = self
            .head(txn, signer)
            .await
            .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
        let body = serde_json::to_vec(&body)
            .map_err(|_| ApiError::unavailable("7.6: a temporary failure"))?;
        let mut answer = Answer::ok(body).with_head(Some(head));
        // Never cached (Switch wire 7.4.12).
        answer.no_store = true;
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kept(reason: KeptReason, rotated: bool) -> KeptAppId {
        KeptAppId {
            app_id: [1; 16],
            reason,
            at_ms: 0,
            data_epoch: Some(2),
            rotated,
        }
    }

    #[test]
    fn test_apps_awaiting_rotation_of_a_departure() {
        assert!(awaiting_rotation(&kept(KeptReason::Departed, false)));
        assert!(!awaiting_rotation(&kept(KeptReason::Departed, true)));
    }

    #[test]
    fn test_apps_revocations_await_no_rotation() {
        for reason in [KeptReason::Revoked, KeptReason::Enrolled] {
            assert!(!awaiting_rotation(&kept(reason, false)));
        }
    }
}
