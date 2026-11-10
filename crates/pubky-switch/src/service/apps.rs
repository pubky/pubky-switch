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

/// A value's JSON. None of the types answered here can fail to serialize; if one ever did,
/// the answer is a temporary failure, never a signed body with something left out.
fn json_of(value: &impl serde::Serialize) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(value).map_err(|_| StoreError::Corrupt("an answer doesn't encode"))
}

/// A JSON object of `members`, in their order: the order of the wire's tables (Switch wire
/// 7.4.12), which a map of `serde_json` would sort.
fn object(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![b'{'];
    for (index, (name, value)) in members.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        // The members' names are this module's own ASCII identifiers: nothing to escape.
        out.push(b'"');
        out.extend_from_slice(name.as_bytes());
        out.push(b'"');
        out.push(b':');
        out.extend_from_slice(value);
    }
    out.push(b'}');
    out
}

/// A JSON array of `items`, each already JSON.
fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![b'['];
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(item);
    }
    out.push(b']');
    out
}

/// Whether a departed app still awaits its rotation (Switch wire 7.4.12): until a delivered
/// `identity.json` lists it in `removed` at a higher data epoch than the newest document's
/// at its departure, which is done for good. Only a departure awaits one: the signer
/// revokes, and rotates for its own revocations.
pub(crate) fn awaiting_rotation(kept: &KeptAppId) -> bool {
    kept.reason == KeptReason::Departed && !kept.rotated
}

/// The statuses of `GET /apps`, at service time `now`, by App ID, each as JSON in the order
/// of the wire's table (Switch wire 7.4.12): every app with a row, every App ID kept for
/// good, and every app `doc` lists.
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
) -> Result<Vec<Vec<u8>>, StoreError> {
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
        let open_attempts: Vec<Vec<u8>> = view
            .open_attempts
            .iter()
            .filter(|attempt| attempt.owner == id)
            .map(|attempt| {
                Ok(object(&[
                    ("claim_key", json_of(&b64(&attempt.claim_key))?),
                    ("attempt_id", json_of(&b64(&attempt.attempt_id))?),
                    (
                        "outcome",
                        json_of(&if attempt.unknown { "unknown" } else { "open" })?,
                    ),
                ]))
            })
            .collect::<Result<_, StoreError>>()?;
        let record_cert = held
            .and_then(|app| app.record.as_ref())
            .map(|record| b64(&AppRecord::cert(record).hash()));
        let ranges: Vec<[u64; 2]> = parts
            .iter()
            .map(|part| [part.first_epoch, part.last_epoch])
            .collect();
        statuses.push(object(&[
            ("app_id", json_of(&zbase32_encode(&id))?),
            ("current", json_of(&current)?),
            (
                "last_seen",
                json_of(&time(view.last_seen.get(&id).copied()))?,
            ),
            ("revoked_at", json_of(&time(revoked_at))?),
            ("departed_at", json_of(&time(departed_at))?),
            (
                "awaiting_rotation",
                json_of(&kept_id.is_some_and(awaiting_rotation))?,
            ),
            ("open_attempts", array(&open_attempts)),
            // Lagging comes with the next inbox PR.
            (
                "unread_entries",
                json_of(&view.unread.get(&id).map_or(0, |(unread, _)| *unread))?,
            ),
            (
                "sole_target_unread",
                json_of(&view.unread.get(&id).map_or(0, |(_, sole)| *sole))?,
            ),
            ("record_cert", json_of(&record_cert)?),
            (
                "record_at",
                json_of(&time(held.and_then(|app| app.record_at)))?,
            ),
            ("lagging", json_of(&false)?),
            (
                "keys_through",
                json_of(&keys_through(
                    view.listings.get(&id).copied(),
                    &spans,
                    cursor,
                ))?,
            ),
            (
                "full_bundle_requested",
                json_of(&time(held.and_then(|app| app.full_requested)))?,
            ),
            ("bundle_ranges", json_of(&ranges)?),
            (
                "cert_expires_at",
                json_of(&time(state.checked_cert(&id).map(|cert| cert.expires_at())))?,
            ),
        ]));
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
        let mut members = vec![
            ("apps", array(&apps)),
            (
                "identity",
                json_of(&held.map(IdentityDoc::signed)).map_err(|e| store_error(&e))?,
            ),
            // Recovery comes with provider changes.
            ("recovery", b"null".to_vec()),
        ];
        // Absent when no kept proof names a generation (Switch wire 7.4.12).
        if !proof_generations.is_empty() {
            members.push((
                "proof_generations",
                json_of(&proof_generations).map_err(|e| store_error(&e))?,
            ));
        }
        let head = self
            .head(txn, signer)
            .await
            .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
        let body = object(&members);
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
