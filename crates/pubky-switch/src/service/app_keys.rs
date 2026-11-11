//! `GET` and `POST /v1/{id}/apps/{app_id}/keys` (Switch wire 7.4.11): an own app reads the
//! key bundle parts the signer stored for it, and asks the signer for a full key bundle.
//!
//! Only that app makes either call. The parts are the signed `key_bundle.put` operations the
//! batch rules keep for it, never overlapping (6.2); `GET` answers each part's key bundle with
//! its range and the `seq` of its operation. `POST` records the service time of the first
//! request, which `GET /apps` shows as `full_bundle_requested` until the stored parts cover
//! every data epoch from 1 to the current one (3.5); the batch rules clear it then.

use pubky_switch_core::{
    enc::app_id_decode,
    ops::{OpKind, SignedOp},
    records::{AppCert, KeyBundle},
    time::rfc3339,
};
use serde::Serialize;

use super::{Answer, Service, store_error};
use crate::{
    http::error::{ApiError, ErrorCode},
    keys::ServiceSigner,
    store::{AccountTxn, StoreError},
};

/// Which of the two calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeysCall {
    /// `GET`: the parts stored for the app.
    Read,
    /// `POST`: a full key bundle asked for.
    Request,
}

/// One stored part as `GET` answers it, its members in the wire's order (Switch wire 7.4.11).
#[derive(Serialize)]
struct Part {
    bundle: KeyBundle,
    seq: u64,
    first_epoch: u64,
    last_epoch: u64,
}

/// `GET`'s answer.
#[derive(Serialize)]
struct Parts {
    bundles: Vec<Part>,
}

/// `POST`'s answer.
#[derive(Serialize)]
struct Requested {
    requested: String,
}

/// An answer's JSON. None of these types can fail to serialize; if one ever did, the answer is
/// a temporary failure, never a signed body with something left out.
fn json_of(value: &impl Serialize) -> Result<Vec<u8>, ApiError> {
    serde_json::to_vec(value)
        .map_err(|_| store_error(&StoreError::Corrupt("an answer doesn't encode")))
}

/// The refusal of a caller that isn't the app the path names (Switch wire 7.4.11).
pub(super) fn only_that_app() -> ApiError {
    ApiError::new(
        ErrorCode::PermissionMissing,
        "7.4.11: only the app itself reads or asks for its key bundles",
    )
}

impl Service {
    /// `GET` or `POST /v1/{id}/apps/{app_id}/keys` for `caller`, the own app that verified,
    /// whose App ID must be the path's `app_id` (Switch wire 7.4.11).
    ///
    /// # Errors
    ///
    /// `403 permission_missing` for another app's path; `400` for a `POST` with a body; `404`
    /// for a `GET` when no part is stored; `503` for a store failure.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn app_keys(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        caller: &AppCert,
        app_id: &str,
        body: &[u8],
        call: KeysCall,
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        let app = caller.app_id();
        if app_id_decode(app_id).ok() != Some(app) {
            return Err(only_that_app());
        }
        let answer = match call {
            KeysCall::Read => self.read_parts(txn, &app).await?,
            KeysCall::Request => {
                if !body.is_empty() {
                    return Err(ApiError::bad_request(
                        "7.4.11: a request for a full key bundle has an empty body",
                    ));
                }
                self.request_full_bundle(txn, &app, time_ms).await?
            }
        };
        let head = self
            .head(txn, signer)
            .await
            .ok_or_else(|| ApiError::unavailable("7.6: a temporary failure"))?;
        Ok(Answer::ok(answer).with_head(Some(head)))
    }

    /// The parts stored for `app`, in `first_epoch` order: `{ "bundles": [ { "bundle",
    /// "seq", "first_epoch", "last_epoch" } ] }` (Switch wire 7.4.11).
    async fn read_parts(&self, txn: &mut AccountTxn, app: &[u8; 16]) -> Result<Vec<u8>, ApiError> {
        let parts = txn.bundle_parts(app).await.map_err(|e| store_error(&e))?;
        if parts.is_empty() {
            return Err(ApiError::not_found(
                "7.4.11: the service holds no key bundle part for this app",
            ));
        }
        let bundles = parts
            .iter()
            .map(|part| {
                let op = SignedOp::peek(&part.op)
                    .map_err(|_| store_error(&StoreError::Corrupt("a key bundle part")))?;
                let OpKind::KeyBundlePut(put) = &op.body().kind else {
                    return Err(store_error(&StoreError::Corrupt(
                        "a key bundle part isn't a key_bundle.put",
                    )));
                };
                Ok(Part {
                    bundle: put.bundle.clone(),
                    seq: part.seq,
                    first_epoch: part.first_epoch,
                    last_epoch: part.last_epoch,
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        json_of(&Parts { bundles })
    }

    /// Record the first request for a full key bundle for `app`, at `time_ms`, and answer
    /// `{ "requested": time }` with that first time (Switch wire 7.4.11, spec 3.5).
    async fn request_full_bundle(
        &self,
        txn: &mut AccountTxn,
        app: &[u8; 16],
        time_ms: u64,
    ) -> Result<Vec<u8>, ApiError> {
        let mut stored = txn
            .apps()
            .await
            .map_err(|e| store_error(&e))?
            .into_iter()
            .find(|stored| &stored.app_id == app)
            // The caller verified with its record, so the account holds it.
            .ok_or_else(|| store_error(&StoreError::Corrupt("a verified app without its row")))?;
        let requested = match stored.full_requested_ms {
            Some(first) => first,
            None => {
                stored.full_requested_ms = Some(time_ms);
                txn.put_app(&stored).await.map_err(|e| store_error(&e))?;
                time_ms
            }
        };
        json_of(&Requested {
            requested: rfc3339(requested),
        })
    }
}
