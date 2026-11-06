//! Error answers (Switch wire 7.6).
//!
//! An error body is `{ "code", "message", "current" (where the wire format gives one),
//! "known_version" (only in `409 identity_needed`), "retry_after" (on `429 rate_limited`) }`.
//! A message names the rule that refused the request and holds no internal detail.

use serde::Serialize;
use serde_json::Value;

/// An error `code` with its HTTP status (Switch wire 7.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 400: a malformed request, document or operation.
    BadRequest,
    /// 401: a signature that doesn't verify.
    BadSignature,
    /// 401: a `Switch-Timestamp` more than 5 minutes from the time base.
    StaleTimestamp,
    /// 403: a sender not admitted or denied.
    NotAdmitted,
    /// 403: a missing switch permission or scope.
    PermissionMissing,
    /// 403: the calling app isn't current.
    NotCurrent,
    /// 403: the caller's certificate has expired.
    CertExpired,
    /// 404: no such account, route or object.
    NotFound,
    /// 409: a condition or check fails.
    Conflict,
    /// 409: a sealed value at another data epoch.
    StaleEpoch,
    /// 409: an operation naming another generation.
    StaleGeneration,
    /// 409: an envelope wrapped to a receive key that isn't current.
    StaleKey,
    /// 409: a delivered `identity.json` that isn't newer.
    StaleIdentity,
    /// 409: the service's copy of the sender's `identity.json` doesn't list the app.
    IdentityNeeded,
    /// 410: the account is frozen.
    Moved,
    /// 413: a body or value over its cap.
    TooLarge,
    /// 429: too many requests in the current minute.
    RateLimited,
    /// 429: a quota or per-kind limit is full.
    QuotaExceeded,
    /// 503: the account isn't named by its `identity.json` yet.
    Staged,
    /// 503: a temporary failure, missing trusted time, or a state behind the key's mark.
    Unavailable,
}

impl ErrorCode {
    /// The HTTP status of the code.
    pub fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::BadSignature | Self::StaleTimestamp => 401,
            Self::NotAdmitted | Self::PermissionMissing | Self::NotCurrent | Self::CertExpired => {
                403
            }
            Self::NotFound => 404,
            Self::Conflict
            | Self::StaleEpoch
            | Self::StaleGeneration
            | Self::StaleKey
            | Self::StaleIdentity
            | Self::IdentityNeeded => 409,
            Self::Moved => 410,
            Self::TooLarge => 413,
            Self::RateLimited | Self::QuotaExceeded => 429,
            Self::Staged | Self::Unavailable => 503,
        }
    }

    /// The code as the wire format spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::BadSignature => "bad_signature",
            Self::StaleTimestamp => "stale_timestamp",
            Self::NotAdmitted => "not_admitted",
            Self::PermissionMissing => "permission_missing",
            Self::NotCurrent => "not_current",
            Self::CertExpired => "cert_expired",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::StaleEpoch => "stale_epoch",
            Self::StaleGeneration => "stale_generation",
            Self::StaleKey => "stale_key",
            Self::StaleIdentity => "stale_identity",
            Self::IdentityNeeded => "identity_needed",
            Self::Moved => "moved",
            Self::TooLarge => "too_large",
            Self::RateLimited => "rate_limited",
            Self::QuotaExceeded => "quota_exceeded",
            Self::Staged => "staged",
            Self::Unavailable => "unavailable",
        }
    }

    /// Whether an answer with this code counts as a failed authentication for the network
    /// source's limit: every `401` (Switch wire 7.2).
    pub fn is_failed_authentication(self) -> bool {
        self.status() == 401
    }
}

/// An error answer.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ApiError {
    /// The code.
    pub code: ErrorCode,
    /// The rule that refused the request.
    pub message: String,
    /// The current state, where the wire format gives one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<Value>,
    /// The version of the caller's `identity.json` the service holds, only in
    /// `409 identity_needed` (Switch wire 7.1). `Some(None)` is written as `null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_version: Option<Option<u64>>,
    /// Seconds to the next rate-limit window, on `429 rate_limited`; also sent as
    /// `Retry-After`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

impl ApiError {
    /// An error with a code and a message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            current: None,
            known_version: None,
            retry_after: None,
        }
    }

    /// Attach the current state.
    pub fn with_current(mut self, current: Value) -> Self {
        self.current = Some(current);
        self
    }

    /// `400 bad_request`.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadRequest, message)
    }

    /// `404 not_found`.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    /// `413 too_large`, for a body over its call's cap (Switch wire 7.1).
    pub fn body_too_large(cap: u64) -> Self {
        Self::new(
            ErrorCode::TooLarge,
            format!("7.1: the body is over this call's cap of {cap} bytes"),
        )
    }

    /// `429 rate_limited`, with the seconds to the next window.
    pub fn rate_limited(message: impl Into<String>, retry_after: u64) -> Self {
        Self {
            retry_after: Some(retry_after),
            ..Self::new(ErrorCode::RateLimited, message)
        }
    }

    /// `429 quota_exceeded`, naming the budget that is full (Switch wire 9.3).
    pub fn quota_exceeded(limit: &str, message: impl Into<String>) -> Self {
        Self::new(ErrorCode::QuotaExceeded, message)
            .with_current(serde_json::json!({ "limit": limit }))
    }

    /// `503 unavailable`.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unavailable, message)
    }

    /// The HTTP status.
    pub fn status(&self) -> u16 {
        self.code.status()
    }

    /// The JSON body.
    pub fn body(&self) -> Vec<u8> {
        // Serializing a struct of strings, numbers and JSON values can't fail; an empty
        // object stands in if it ever did.
        serde_json::to_vec(self).unwrap_or_else(|_| b"{}".to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes_and_statuses() {
        let table = [
            (ErrorCode::BadRequest, "bad_request", 400),
            (ErrorCode::BadSignature, "bad_signature", 401),
            (ErrorCode::StaleTimestamp, "stale_timestamp", 401),
            (ErrorCode::NotAdmitted, "not_admitted", 403),
            (ErrorCode::PermissionMissing, "permission_missing", 403),
            (ErrorCode::NotCurrent, "not_current", 403),
            (ErrorCode::CertExpired, "cert_expired", 403),
            (ErrorCode::NotFound, "not_found", 404),
            (ErrorCode::Conflict, "conflict", 409),
            (ErrorCode::StaleEpoch, "stale_epoch", 409),
            (ErrorCode::StaleGeneration, "stale_generation", 409),
            (ErrorCode::StaleKey, "stale_key", 409),
            (ErrorCode::StaleIdentity, "stale_identity", 409),
            (ErrorCode::IdentityNeeded, "identity_needed", 409),
            (ErrorCode::Moved, "moved", 410),
            (ErrorCode::TooLarge, "too_large", 413),
            (ErrorCode::RateLimited, "rate_limited", 429),
            (ErrorCode::QuotaExceeded, "quota_exceeded", 429),
            (ErrorCode::Staged, "staged", 503),
            (ErrorCode::Unavailable, "unavailable", 503),
        ];
        for (code, name, status) in table {
            assert_eq!(code.as_str(), name);
            assert_eq!(code.status(), status, "{name}");
            assert_eq!(
                serde_json::to_value(code).expect("json"),
                serde_json::Value::String(name.into())
            );
            assert_eq!(code.is_failed_authentication(), status == 401);
        }
    }

    #[test]
    fn test_error_body_members() {
        let plain: serde_json::Value =
            serde_json::from_slice(&ApiError::not_found("no such record").body()).expect("json");
        assert_eq!(
            plain,
            serde_json::json!({ "code": "not_found", "message": "no such record" })
        );

        let limited: serde_json::Value =
            serde_json::from_slice(&ApiError::rate_limited("9.4: appends", 42).body())
                .expect("json");
        assert_eq!(limited["retry_after"], 42);
        assert_eq!(limited["code"], "rate_limited");

        let quota: serde_json::Value =
            serde_json::from_slice(&ApiError::quota_exceeded("claims", "full").body())
                .expect("json");
        assert_eq!(quota["current"], serde_json::json!({ "limit": "claims" }));
        assert!(quota.get("retry_after").is_none());

        let mut needed = ApiError::new(ErrorCode::IdentityNeeded, "listing")
            .with_current(serde_json::json!({ "version": null }));
        needed.known_version = Some(None);
        let needed: serde_json::Value = serde_json::from_slice(&needed.body()).expect("json");
        assert_eq!(needed["known_version"], serde_json::Value::Null);
        assert!(
            needed
                .as_object()
                .expect("object")
                .contains_key("known_version")
        );
    }
}
