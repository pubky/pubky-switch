//! Connect requests (Switch spec 7, Switch wire 7.4.7): where the account's `identity.json`
//! turns them on, an app of another identity may ask to be invited. A request is
//! content-free, holds only the sender's Pubky ID and when it asked, and admits nothing.
//!
//! - **Asking** (`POST /connect`): after the caller's own checks, a recovery's staged
//!   admission answers `503 staged`, as `PUT /peers` does for any sender it can't otherwise
//!   admit, whatever the policy; the policy off is `403 not_admitted`; the service's copy of the sender's `identity.json` must
//!   list the app (`409 identity_needed`); then the rates, per sender (`connect_per_min`)
//!   and per account for every stranger together (`stranger_per_min`, shared with their
//!   `PUT /peers`), each refusal a hit on the sender's flag. A sender already pending is
//!   answered `pending`, full or not. A full list (the policy's `max_pending`, capped by
//!   `max_connect_pending`) refuses a new sender `429 quota_exceeded`, before the deny list
//!   is looked at, so a denied sender gets the same answer; otherwise a denied sender is
//!   answered `pending` and its request isn't kept. None waiting is dropped to make room.
//! - **Reading** (`GET /connect`, `lists.read`): the requests oldest first, the cap that
//!   applies, and whether the list is full.
//! - **Declining** (`DELETE /connect/{pubky}`, `conversation.add`): the request goes;
//!   `404` when none is pending. A contact, a conversation entry or a deny list entry for
//!   the sender answers its request too (the store does it with the entry).
//!
//! Push for connect requests (`policy.connect_requests.push`) isn't sent yet: push isn't
//! served (Switch wire 8).

use pubky_switch_core::{
    enc::{pubky_id, pubky_key},
    records::{AppCert, IdentityDoc, Standing as CertStanding},
    scopes::Permission,
    time::rfc3339,
};
use serde_json::json;

use super::{Answer, Service, store_error};
use crate::http::error::{ApiError, ErrorCode};
use crate::store::AccountTxn;

/// The pending requests' cap that applies: the policy's `max_pending`, at most
/// `max_connect_pending` (Switch wire 3.3, 9.2). At 0, every new sender is refused.
pub(crate) fn connect_cap(max_pending: u64, max_connect_pending: u64) -> u64 {
    max_pending.min(max_connect_pending)
}

fn identity_needed(version: Option<u64>) -> ApiError {
    let mut error = ApiError::new(
        ErrorCode::IdentityNeeded,
        "7.4.7: the service's copy of the sender's identity.json doesn't list the app",
    )
    .with_current(json!({ "version": version }));
    error.known_version = Some(version);
    error
}

impl Service {
    /// `POST /v1/{id}/connect` under the lock, from an app of another identity whose
    /// request verified (Switch wire 7.4.7); the module's doc gives the order.
    pub(super) async fn post_connect(
        &self,
        txn: &mut AccountTxn,
        held: Option<&IdentityDoc>,
        cert: &AppCert,
        time_ms: u64,
    ) -> Result<Answer, ApiError> {
        let account = txn.head().clone();
        let sender = cert.identity();
        let app = cert.app_id();
        // While admission is staged after a provider loss, the deny list isn't back yet and
        // a denied sender would pass for a stranger: every sender it can't otherwise admit
        // waits (Switch spec 12.6 step 2).
        let staged = txn.admission_staged().await.map_err(|e| store_error(&e))?;
        if staged {
            return Err(super::recovery::staged_admission());
        }
        let policy = held.map(|doc| &doc.body().policy.connect_requests);
        let Some(policy) = policy.filter(|p| p.enabled) else {
            return Err(ApiError::new(
                ErrorCode::NotAdmitted,
                super::admission::NOT_ADMITTED,
            ));
        };
        // Check 5 (Switch wire 7.2): the service's copy of the sender's identity.json lists
        // the app with this certificate; a removed app is answered like a stranger with no
        // copy held.
        let removed = txn
            .peer_lists_removed(&sender, &app)
            .await
            .map_err(|e| store_error(&e))?;
        if removed {
            return Err(identity_needed(None));
        }
        let copy = txn.peer_copy(&sender).await.map_err(|e| store_error(&e))?;
        let copy = copy
            .as_ref()
            .map(|held| IdentityDoc::verify_named(&held.doc))
            .transpose()
            .map_err(|_| ApiError::unavailable("7.6: a temporary failure"))?;
        match copy.as_ref().map(|doc| doc.standing(&app, &cert.hash())) {
            Some(CertStanding::Listed | CertStanding::RenewedOpen) => {}
            Some(CertStanding::RenewedClosed { .. }) => {
                return Err(ApiError::new(
                    ErrorCode::NotCurrent,
                    "3.8: the certificate's renewal has closed",
                ));
            }
            _ => return Err(identity_needed(copy.as_ref().map(IdentityDoc::version))),
        }
        let known = copy.as_ref().map(IdentityDoc::version);
        // The rates, each refusal a hit against the sender (Switch wire 9.4).
        let limited = |txn: &mut AccountTxn, result: Result<(), u64>, what: &str| {
            result.map_err(|retry_after| {
                txn.note_flag_hit(sender, self.limits.max_flags);
                ApiError::rate_limited(format!("9.4: {what}"), retry_after)
            })
        };
        let taken = self.connect_rate.take(
            (account.id.clone(), sender),
            self.limits.connect_per_min,
            time_ms,
        );
        limited(txn, taken, "connect requests from this sender")?;
        let taken =
            self.stranger_rate
                .take(account.id.clone(), self.limits.stranger_per_min, time_ms);
        limited(txn, taken, "strangers at this account")?;
        let pending = json!({ "pending": true, "known_version": known });
        if txn
            .connect_pending(&sender)
            .await
            .map_err(|e| store_error(&e))?
        {
            return Ok(Answer::ok(serde_json::to_vec(&pending).unwrap_or_default()));
        }
        // Full before the deny list is looked at, so a denied sender's answer is everyone's.
        let cap = connect_cap(policy.max_pending, self.limits.max_connect_pending);
        let count = txn.connect_count().await.map_err(|e| store_error(&e))?;
        if count >= cap {
            return Err(ApiError::quota_exceeded(
                "connect_requests",
                "9.3: the connect request list is full",
            ));
        }
        let standing = self.standing(txn, &sender).await?;
        if !standing.denied {
            txn.put_connect(&sender, time_ms)
                .await
                .map_err(|e| store_error(&e))?;
            txn.note_change();
        }
        Ok(Answer::ok(serde_json::to_vec(&pending).unwrap_or_default()))
    }

    /// `GET /v1/{id}/connect` under the lock, from an own app (Switch wire 7.4.7): needs
    /// `lists.read`.
    pub(super) async fn get_connect(
        &self,
        txn: &mut AccountTxn,
        held: Option<&IdentityDoc>,
        writer: Option<&AppCert>,
    ) -> Result<Answer, ApiError> {
        if !writer.is_some_and(|cert| cert.has_permission(Permission::ListsRead)) {
            return Err(ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4.7: reading connect requests needs lists.read",
            ));
        }
        let max_pending = held.map_or(0, |doc| {
            connect_cap(
                doc.body().policy.connect_requests.max_pending,
                self.limits.max_connect_pending,
            )
        });
        let requests = txn.connect_requests().await.map_err(|e| store_error(&e))?;
        let full = u64::try_from(requests.len()).unwrap_or(u64::MAX) >= max_pending;
        let requests: Vec<serde_json::Value> = requests
            .iter()
            .map(|request| json!({ "pubky": pubky_id(&request.pubky), "at": rfc3339(request.at_ms) }))
            .collect();
        let body = json!({ "requests": requests, "max_pending": max_pending, "full": full });
        Ok(Answer::ok(serde_json::to_vec(&body).unwrap_or_default()))
    }

    /// `DELETE /v1/{id}/connect/{pubky}` under the lock, from an own app (Switch wire
    /// 7.4.7): needs `conversation.add`; `404` when no request is pending from it.
    pub(super) async fn delete_connect(
        &self,
        txn: &mut AccountTxn,
        writer: Option<&AppCert>,
        pubky: &str,
    ) -> Result<Answer, ApiError> {
        if !writer.is_some_and(|cert| cert.has_permission(Permission::ConversationAdd)) {
            return Err(ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4.7: declining a connect request needs conversation.add",
            ));
        }
        let Ok(sender) = pubky_key(pubky) else {
            return Err(ApiError::not_found("no such connect request"));
        };
        if !txn
            .delete_connect(&sender)
            .await
            .map_err(|e| store_error(&e))?
        {
            return Err(ApiError::not_found("no such connect request"));
        }
        txn.note_change();
        let body = json!({ "declined": pubky_id(&sender) });
        Ok(Answer::ok(serde_json::to_vec(&body).unwrap_or_default()))
    }
}
