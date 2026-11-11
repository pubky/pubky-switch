//! `POST /v1/enroll` (Switch wire 3.7, 7.4.1).

use pubky_switch_core::{
    Error as CoreError,
    enc::pubky_key,
    http::{self as wire_http, RequestTarget, header},
    records::{Enrollment, EnrollmentAnswer, IdentityDoc, Limits as AnnouncedLimits},
    sig::SignedDoc,
};

use super::{
    Answer, Service,
    keyed::Proof,
    rules::{
        AccountState, Caller, EnrollmentKey, decode_claim, enrollment_key, names_this_service,
    },
    store_error,
};
use crate::{
    http::{
        SwitchRequest, SwitchResponse,
        error::{ApiError, ErrorCode},
    },
    keys::{KeyId, ServiceKey},
    limits::{Limits, fixed},
    store::NewAccount,
};

/// The limits an enrollment answer announces (Switch wire 3.7).
pub fn announced_limits(limits: &Limits) -> AnnouncedLimits {
    AnnouncedLimits {
        app_limit: u64::from(limits.app_limit),
        max_envelope: fixed::MAX_ENVELOPE,
        max_sealed_value: fixed::MAX_SEALED_VALUE,
        quota_bytes: limits.quota_bytes,
        max_batch: fixed::MAX_BATCH,
        record_quota_bytes: limits.record_quota_bytes,
        max_import_bytes: limits.max_import_bytes,
    }
}

/// Read and check the enrollment a request carries: `{ "enrollment": signed<Enrollment> }`,
/// for `identity` at `origin` (Switch wire 3.7, 7.4.1).
pub fn read_enrollment(
    body: &[u8],
    identity: &[u8; 32],
    origin: &str,
) -> Result<Enrollment, ApiError> {
    let value: serde_json::Value = pubky_switch_core::json::parse_json(body)
        .map_err(|_| ApiError::bad_request("7.4.1: the body isn't strict JSON"))?;
    let signed: SignedDoc = value
        .get("enrollment")
        .cloned()
        .and_then(|enrollment| serde_json::from_value(enrollment).ok())
        .ok_or_else(|| ApiError::bad_request("7.4.1: the body carries no enrollment"))?;
    Enrollment::verify(&signed, identity, origin).map_err(|error| match error {
        CoreError::Signature(_) => ApiError::new(
            ErrorCode::BadSignature,
            "3.7: the identity didn't sign the enrollment",
        ),
        _ => ApiError::bad_request("3.7: the enrollment breaks a rule"),
    })
}

impl Service {
    /// `POST /v1/enroll`, from the signer. Errors before an account exists are signed with
    /// the operator key; the answer with the key it names, without a head.
    pub(super) async fn enroll(
        &self,
        request: &SwitchRequest,
        base_ms: u64,
        request_signature: Option<[u8; 64]>,
    ) -> SwitchResponse {
        let signature = request_signature.as_ref();
        let (enrollment, identity_text) = match self.check_enrollment(request, base_ms) {
            Ok(checked) => checked,
            Err(error) => return self.operator_answer(signature, base_ms, &error).await,
        };
        match self
            .answer_enrollment(&enrollment, &identity_text, base_ms)
            .await
        {
            Ok((key, time_ms, limits)) => {
                let answer = EnrollmentAnswer::new(&enrollment, key.public, limits);
                let body = match answer.to_json() {
                    Ok(body) => body,
                    Err(_) => {
                        let error = ApiError::unavailable("7.6: a temporary failure");
                        return self.operator_answer(signature, base_ms, &error).await;
                    }
                };
                match self.keys.signer(&key.id).await {
                    // Signed only while the account still has the key, as its service key or
                    // its pending key: an erasure deletes both (7.4.16).
                    Ok(signer) => {
                        let proof = Proof::Checked {
                            account: &identity_text,
                            key: &key.id,
                            pending: true,
                        };
                        match self
                            .try_sign_keyed(proof, &signer, signature, |_| {
                                (Answer::ok(body), time_ms)
                            })
                            .await
                        {
                            Ok(signed) => signed,
                            Err(_) => {
                                let error = ApiError::unavailable("7.6: a temporary failure");
                                self.operator_answer(signature, base_ms, &error).await
                            }
                        }
                    }
                    Err(_) => {
                        let error = ApiError::unavailable("7.6: a temporary failure");
                        self.operator_answer(signature, base_ms, &error).await
                    }
                }
            }
            Err(error) => self.operator_answer(signature, base_ms, &error).await,
        }
    }

    /// The request's checks: the signer of its own identity, then the enrollment.
    fn check_enrollment(
        &self,
        request: &SwitchRequest,
        base_ms: u64,
    ) -> Result<(Enrollment, String), ApiError> {
        let identity_text = request
            .headers
            .get(header::IDENTITY)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiError::bad_request("7.1: Switch-Identity is missing"))?
            .to_string();
        let identity = pubky_key(&identity_text)
            .map_err(|_| ApiError::bad_request("7.1: Switch-Identity isn't a Pubky ID"))?;
        let claimed = decode_claim(&identity, &request.headers, base_ms)?;
        if claimed.caller != Caller::Signer {
            return Err(ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4.1: only the signer enrolls",
            ));
        }
        let target = RequestTarget {
            method: &request.method,
            path_and_query: &request.path_and_query,
            body: &request.body,
            origin: &self.origin,
        };
        wire_http::verify_request(&identity, &target, &claimed.headers, &claimed.signature)
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::BadSignature,
                    "7.1: the request signature doesn't verify",
                )
            })?;
        let enrollment = read_enrollment(&request.body, &identity, &self.origin)?;
        Ok((enrollment, identity_text))
    }

    /// The key that answers the enrollment, the service time of the answer, and the limits
    /// it announces: a new account's key, a staged account's own, or a serving account's
    /// pending key, with the limits the account announced at its first enrollment.
    async fn answer_enrollment(
        &self,
        enrollment: &Enrollment,
        identity_text: &str,
        base_ms: u64,
    ) -> Result<(ServiceKey, u64, AnnouncedLimits), ApiError> {
        let unavailable = || ApiError::unavailable("7.6: a temporary failure");
        let enrollment_hash = enrollment.signed().doc_hash().map_err(|_| unavailable())?;
        // An account that doesn't exist yet is made, then answered like any other.
        if self
            .store
            .begin(identity_text)
            .await
            .map_err(|e| store_error(&e))?
            .is_none()
        {
            let key = self.keys.generate().await.map_err(|_| unavailable())?;
            let account = NewAccount {
                id: identity_text.to_string(),
                identity_key: enrollment.body().identity,
                generation: enrollment.identity_doc().map_or(1, IdentityDoc::generation),
                service_key: key.id.clone(),
                created_at_ms: base_ms,
                limits: announced_limits(&self.limits),
                identity_doc: enrollment.identity_doc().map(|doc| doc.signed().clone()),
                revoked_apps: enrollment.revoked_apps().to_vec(),
                enrollment_hash,
            };
            let created = self
                .store
                .create_account(&account)
                .await
                .map_err(|e| store_error(&e))?;
            if created {
                return Ok((key, base_ms, account.limits));
            }
            // Another enrollment made the account first: its key answers.
            if let Err(failure) = self.keys.delete(&key.id).await {
                tracing::warn!(%failure, "dropping an unused service key");
            }
        }
        let mut txn = self
            .store
            .begin(identity_text)
            .await
            .map_err(|e| store_error(&e))?
            .ok_or_else(unavailable)?;
        let time_ms = txn.stamp(base_ms);
        let limits = txn.announced_limits().await.map_err(|e| store_error(&e))?;
        // The same enrollment again gets the same answer, whatever the account did since
        // (Switch wire 3.7): the key it named, recognized by the enrollment's hash. An answer
        // drops only while a rebuild would give it byte for byte: one naming the pending key,
        // as long as that key is pending. Once a generation change has retired the key it
        // named, a retry is `409 conflict`, so its signer enrolls anew.
        if let Some(key_id) = txn
            .enrollment_answer(&enrollment_hash)
            .await
            .map_err(|e| store_error(&e))?
        {
            txn.commit().await.map_err(|e| store_error(&e))?;
            let public = self
                .keys
                .public_key(&key_id)
                .await
                .map_err(|_| unavailable())?;
            return Ok((ServiceKey { id: key_id, public }, time_ms, limits));
        }
        if txn
            .retired_enrollment(&enrollment_hash)
            .await
            .map_err(|e| store_error(&e))?
            .is_some()
        {
            txn.commit().await.map_err(|e| store_error(&e))?;
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "3.7: a generation change retired the key this enrollment's answer named",
            ));
        }
        let account_key = txn.head().service_key.clone();
        let account_public = self
            .keys
            .public_key(&account_key)
            .await
            .map_err(|_| unavailable())?;
        let held = txn
            .held_identity()
            .await
            .map_err(|e| store_error(&e))?
            .map(|held| IdentityDoc::verify(&held.doc, &enrollment.body().identity))
            .transpose()
            .map_err(|_| unavailable())?;
        let pending = txn.pending_key().await.map_err(|e| store_error(&e))?;
        let state = AccountState {
            serving: names_this_service(held.as_ref(), &self.origin, &account_public),
            pending_key: pending.is_some(),
        };
        let choice = enrollment_key(Some(state));
        // A staged account's answers name its own key, which a rebuild at the serving
        // account wouldn't: each is kept as long as the account, so a staged account takes
        // at most max_enrollments distinct enrollments, its creating one included.
        let rebuildable = matches!(choice, EnrollmentKey::PendingKey { .. });
        if !rebuildable
            && txn
                .kept_enrollment_answers()
                .await
                .map_err(|e| store_error(&e))?
                >= self.limits.max_enrollments
        {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "3.7: a staged account takes at most max_enrollments enrollments",
            )
            .with_current(serde_json::json!({ "limit": "enrollments" })));
        }
        let key_id: KeyId = match choice {
            EnrollmentKey::NewAccount | EnrollmentKey::AccountKey => account_key,
            EnrollmentKey::PendingKey { exists: true } => pending.ok_or_else(unavailable)?,
            EnrollmentKey::PendingKey { exists: false } => {
                let key = self.keys.generate().await.map_err(|_| unavailable())?;
                txn.set_pending_key(&key.id)
                    .await
                    .map_err(|e| store_error(&e))?;
                key.id
            }
        };
        // An enrollment answered with the pending key: its `revoked_apps` join the account's
        // tombstones if a delivery naming that key starts the next generation (wire 3.7).
        if rebuildable {
            txn.hold_pending_revoked_apps(enrollment.revoked_apps())
                .await
                .map_err(|e| store_error(&e))?;
        }
        txn.keep_enrollment_answer(
            &enrollment_hash,
            &key_id,
            time_ms,
            self.limits.max_enrollments,
            rebuildable,
        )
        .await
        .map_err(|e| store_error(&e))?;
        txn.commit().await.map_err(|e| store_error(&e))?;
        let public = self
            .keys
            .public_key(&key_id)
            .await
            .map_err(|_| unavailable())?;
        Ok((ServiceKey { id: key_id, public }, time_ms, limits))
    }
}
