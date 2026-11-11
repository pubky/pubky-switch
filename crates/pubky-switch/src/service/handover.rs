//! `PUT` and `GET /v1/{id}/handover` (Switch wire 7.4.17): the signer stores a hand-over
//! for a current app of the identity, and that app fetches it.
//!
//! The hand-over holds the identity secret, sealed to the target's certified bundle key
//! (3.12). The service never opens it: it checks the envelopes' form, their one recipient
//! and the identity key's signature, then keeps the body as received, one per account. Only
//! the target and the signer read it back; any other own app gets the `404` of a call when
//! none is held, so it learns nothing of a hand-over to another. The stored hand-over goes
//! when the account takes the next `identity.json` version (`identity::chain_delivery`),
//! and with the account.

use pubky_switch_core::{
    enc::zbase32_decode,
    json::{parse_json, reject_unknown_members},
    records::{AppCert, IdentityDoc, SignerHandover},
};
use serde::Serialize;
use serde_json::Value;

use super::{Answer, Service, batch, store_error};
use crate::{
    http::error::{ApiError, ErrorCode},
    keys::ServiceSigner,
    store::{AccountTxn, StoreError},
};

/// `PUT`'s answer, its members in the wire's order.
#[derive(Serialize)]
struct Stored {
    app_id: String,
    parts: usize,
}

/// The `404` of a `GET` when none is held, or for an own app it isn't for.
fn none_held() -> ApiError {
    ApiError::not_found("7.4.17: no hand-over is held for this caller")
}

/// Read `PUT`'s body: `{ "app_id", "handover": { "envelopes", "sig" } }`, no other member
/// at either level (Switch wire 7.4.17, 1.1).
fn parse_put(body: &[u8]) -> Result<([u8; 16], SignerHandover), ApiError> {
    let bad = |why: &str| ApiError::bad_request(format!("7.4.17: {why}"));
    let value: Value = parse_json(body).map_err(|_| bad("the body isn't JSON"))?;
    reject_unknown_members(&value, &["app_id", "handover"], "the hand-over request")
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let handover = value
        .get("handover")
        .ok_or_else(|| bad("the body names `handover`"))?;
    reject_unknown_members(handover, &["envelopes", "sig"], "the hand-over")
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let target = value
        .get("app_id")
        .and_then(Value::as_str)
        .and_then(|text| zbase32_decode::<16>(text).ok())
        .ok_or_else(|| bad("`app_id` isn't an App ID"))?;
    let handover: SignerHandover = serde_json::from_value(handover.clone())
        .map_err(|_| bad("the hand-over's envelopes or signature don't read"))?;
    Ok((target, handover))
}

impl Service {
    /// `PUT /v1/{id}/handover`, from the signer (Switch wire 7.4.17).
    ///
    /// # Errors
    ///
    /// `400` for a body that doesn't read, an envelope out of form or not for the target's
    /// certified bundle key alone, or a signature that doesn't verify; `409 conflict` when
    /// the target isn't a current app; `503` for a store failure.
    pub(super) async fn put_handover(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        held: Option<&IdentityDoc>,
        body: &[u8],
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        let (target, handover) = parse_put(body)?;
        // The target is current (Switch spec 3.4), and its bundle key is that of the
        // certificate the switch checks it against: the stored renewed one once listed,
        // else its record's (3.8).
        let state = batch::load_apps(txn, held, time_ms)
            .await
            .map_err(|e| store_error(&e))?;
        let cert: &AppCert = state
            .checked_cert(&target)
            .filter(|_| state.is_current(&target))
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Conflict,
                    "7.4.17: the hand-over's target isn't a current app",
                )
            })?;
        let identity = txn.head().identity_key;
        handover
            .check_stored(&identity, &target, &cert.bundle_key())
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        // Kept as received, replacing any held: one per account.
        txn.put_handover(&target, body)
            .await
            .map_err(|e| store_error(&e))?;
        let answer = serde_json::to_vec(&Stored {
            app_id: pubky_switch_core::enc::zbase32_encode(&target),
            parts: handover.envelopes().len(),
        })
        .map_err(|_| store_error(&StoreError::Corrupt("an answer doesn't encode")))?;
        let head = self
            .head(txn, signer)
            .await
            .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
        Ok(Answer::ok(answer).with_head(Some(head)))
    }

    /// `GET /v1/{id}/handover`, from the signer (`reader` `None`) or the own app `reader`
    /// (Switch wire 7.4.17): the `PUT` body held, for the signer or the app it is for.
    ///
    /// # Errors
    ///
    /// `404` when none is held, or for another own app; `503` for a store failure.
    pub(super) async fn get_handover(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        reader: Option<&AppCert>,
    ) -> Result<Answer, ApiError> {
        let stored = txn.handover().await.map_err(|e| store_error(&e))?;
        let stored = stored
            .filter(|stored| reader.is_none_or(|app| app.app_id() == stored.target))
            .ok_or_else(none_held)?;
        let head = self
            .head(txn, signer)
            .await
            .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
        Ok(Answer::ok(stored.body).with_head(Some(head)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handover_put_body_refuses_unknown_members() {
        let sig = pubky_switch_core::enc::b64(&[0u8; 64]);
        let ok = format!(
            r#"{{"app_id":"g7teif9k1ur75jrmidqk7z7u6w","handover":{{"envelopes":[],"sig":"{sig}"}}}}"#
        );
        assert!(parse_put(ok.as_bytes()).is_ok());
        let outer = format!(
            r#"{{"app_id":"g7teif9k1ur75jrmidqk7z7u6w","handover":{{"envelopes":[],"sig":"{sig}"}},"x":1}}"#
        );
        assert!(parse_put(outer.as_bytes()).is_err());
        let inner = format!(
            r#"{{"app_id":"g7teif9k1ur75jrmidqk7z7u6w","handover":{{"envelopes":[],"sig":"{sig}","x":1}}}}"#
        );
        assert!(parse_put(inner.as_bytes()).is_err());
        assert!(parse_put(br#"{"app_id":"g7teif9k1ur75jrmidqk7z7u6w"}"#).is_err());
        assert!(parse_put(br#"{"app_id":"nope","handover":{"envelopes":[],"sig":"AA"}}"#).is_err());
    }
}
