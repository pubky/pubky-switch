//! Error answers (Switch wire 7.6).
//!
//! An error body is `{ "code", "message", "current" (where the wire format gives one),
//! "known_version" (only in `409 identity_needed`), "retry_after" (on `429 rate_limited`) }`.
//! A message names the rule that refused the request and holds no internal detail. The codes
//! and their statuses are the core's (`pubky_switch_core::http::ErrorCode`).

use serde::Serialize;
use serde_json::Value;

pub use pubky_switch_core::http::ErrorCode;

/// Whether an answer with `code` counts as a failed authentication for the network source's
/// limit: every `401` (Switch wire 7.2).
pub fn is_failed_authentication(code: ErrorCode) -> bool {
    code.status() == 401
}

/// Write a code as the wire format spells it.
fn serialize_code<S: serde::Serializer>(
    code: &ErrorCode,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(code.as_str())
}

/// An error answer.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ApiError {
    /// The code.
    #[serde(serialize_with = "serialize_code")]
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
    fn test_error_failed_authentication_is_every_401() {
        for code in ErrorCode::ALL {
            assert_eq!(
                is_failed_authentication(code),
                code.status() == 401,
                "{code}"
            );
        }
        assert!(is_failed_authentication(ErrorCode::BadSignature));
        assert!(is_failed_authentication(ErrorCode::StaleTimestamp));
        assert!(!is_failed_authentication(ErrorCode::NotAdmitted));
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
