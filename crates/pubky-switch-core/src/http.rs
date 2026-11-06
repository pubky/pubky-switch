//! Requests to and responses from the switch (Switch wire 7.1, 7.2, 7.6), and the push
//! webhook (Switch wire 8.2): what each signature covers, signing and checking, body caps and
//! the error codes.
//!
//! The transport is the caller's: these functions build and check the signed fields of a
//! request or response whose method, path, headers and body the caller holds.

use crate::enc::{hash, u64be, unb64_array};
use crate::error::{Error, Result, invalid};
use crate::labels;
use crate::sig;
use crate::signing::Signs;

/// Header names, as the switch sends them, in lower case; names are case-insensitive
/// (Switch wire 7.1).
pub mod header {
    /// The caller's identity, a Pubky ID.
    pub const IDENTITY: &str = "switch-identity";
    /// The calling App ID; absent for the signer.
    pub const APP: &str = "switch-app";
    /// The app's certificate in compact form, for calls to another identity's account.
    pub const CERT: &str = "switch-cert";
    /// An invite code.
    pub const INVITE_CODE: &str = "switch-invite-code";
    /// The signer's export transfer in compact form, for the next service's chunk fetches.
    pub const TRANSFER: &str = "switch-transfer";
    /// The signing time, `YYYY-MM-DDTHH:MM:SSZ`.
    pub const TIMESTAMP: &str = "switch-timestamp";
    /// The request signature, `b64(64)`.
    pub const SIGNATURE: &str = "switch-signature";
    /// The response signature, `b64(64)`.
    pub const SERVICE_SIGNATURE: &str = "switch-service-signature";
    /// The identity's service time, three fraction digits.
    pub const SERVER_TIME: &str = "switch-server-time";
    /// The newest signed head, base64url of its JSON.
    pub const HEAD: &str = "switch-head";
    /// Seconds to wait, on `429`.
    pub const RETRY_AFTER: &str = "retry-after";
}

/// How far a `Switch-Timestamp` may be from the service's time base: 5 minutes (Switch wire
/// 7.1).
pub const TIMESTAMP_TOLERANCE_MS: u64 = 5 * 60 * 1000;

/// The headers a request to the switch signs, as their exact text; `None` when absent
/// (Switch wire 7.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestHeaders {
    /// `Switch-Timestamp`.
    pub timestamp: String,
    /// `Switch-Identity`.
    pub identity: String,
    /// `Switch-App`; absent for the signer.
    pub app: Option<String>,
    /// `Switch-Cert`.
    pub cert: Option<String>,
    /// `Switch-Invite-Code`.
    pub invite_code: Option<String>,
}

/// The parts of a request its signature covers besides the headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestTarget<'a> {
    /// The method, in upper case.
    pub method: &'a str,
    /// The path and query, exactly as sent.
    pub path_and_query: &'a str,
    /// The raw body bytes; empty for a request without a body.
    pub body: &'a [u8],
    /// The switch origin, exactly as `identity.json` names it in `inbox.url`, for example
    /// `https://inbox.example`. It isn't sent; both sides know it.
    pub origin: &'a str,
}

/// The fields after the label of a request signature: method, path and query,
/// `hash(body)`, `Switch-Timestamp`, switch origin, `Switch-Identity`, `Switch-App`,
/// `Switch-Cert` and `Switch-Invite-Code`, an absent header as an empty field (Switch wire
/// 7.1).
pub fn request_fields(target: &RequestTarget<'_>, headers: &RequestHeaders) -> Vec<Vec<u8>> {
    vec![
        target.method.to_ascii_uppercase().into_bytes(),
        target.path_and_query.as_bytes().to_vec(),
        hash(target.body).to_vec(),
        headers.timestamp.as_bytes().to_vec(),
        target.origin.as_bytes().to_vec(),
        headers.identity.as_bytes().to_vec(),
        headers
            .app
            .as_deref()
            .unwrap_or_default()
            .as_bytes()
            .to_vec(),
        headers
            .cert
            .as_deref()
            .unwrap_or_default()
            .as_bytes()
            .to_vec(),
        headers
            .invite_code
            .as_deref()
            .unwrap_or_default()
            .as_bytes()
            .to_vec(),
    ]
}

fn refs(fields: &[Vec<u8>]) -> Vec<&[u8]> {
    fields.iter().map(Vec::as_slice).collect()
}

/// Sign a request to the switch with the identity key or an app's signing key (Switch wire
/// 7.1): the value of `Switch-Signature`.
pub fn sign_request(
    key: &impl Signs,
    target: &RequestTarget<'_>,
    headers: &RequestHeaders,
) -> [u8; 64] {
    key.sign_fields(labels::sig::HTTP, &refs(&request_fields(target, headers)))
}

/// Check a request signature (Switch wire 7.1).
///
/// # Errors
///
/// [`Error::Signature`] if it doesn't verify with `public`.
pub fn verify_request(
    public: &[u8; 32],
    target: &RequestTarget<'_>,
    headers: &RequestHeaders,
    signature: &[u8; 64],
) -> Result<()> {
    sig::verify(
        public,
        labels::sig::HTTP,
        &refs(&request_fields(target, headers)),
        signature,
    )
}

/// The headers of the next service's export request (Switch wire 7.1, 7.2): it carries
/// `Switch-Transfer` and no `Switch-App`, `Switch-Cert` or `Switch-Invite-Code`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransferHeaders {
    /// `Switch-Timestamp`.
    pub timestamp: String,
    /// `Switch-Identity`: the account's identity.
    pub identity: String,
    /// `Switch-Transfer`: the signer's export transfer in compact form.
    pub transfer: String,
}

/// The fields after the label of the next service's request signature: method, path and
/// query, `hash(body)`, `Switch-Timestamp`, switch origin (the old service's),
/// `Switch-Identity` and `Switch-Transfer` (Switch wire 7.1).
pub fn transfer_request_fields(
    target: &RequestTarget<'_>,
    headers: &TransferHeaders,
) -> Vec<Vec<u8>> {
    vec![
        target.method.to_ascii_uppercase().into_bytes(),
        target.path_and_query.as_bytes().to_vec(),
        hash(target.body).to_vec(),
        headers.timestamp.as_bytes().to_vec(),
        target.origin.as_bytes().to_vec(),
        headers.identity.as_bytes().to_vec(),
        headers.transfer.as_bytes().to_vec(),
    ]
}

/// Sign the next service's export request with its key for the account (Switch wire 7.1).
pub fn sign_transfer_request(
    key: &impl Signs,
    target: &RequestTarget<'_>,
    headers: &TransferHeaders,
) -> [u8; 64] {
    key.sign_fields(
        labels::sig::TRANSFER_REQUEST,
        &refs(&transfer_request_fields(target, headers)),
    )
}

/// Check the next service's request signature with the key the export transfer names
/// (Switch wire 7.2).
///
/// # Errors
///
/// [`Error::Signature`] if it doesn't verify with `public`.
pub fn verify_transfer_request(
    public: &[u8; 32],
    target: &RequestTarget<'_>,
    headers: &TransferHeaders,
    signature: &[u8; 64],
) -> Result<()> {
    sig::verify(
        public,
        labels::sig::TRANSFER_REQUEST,
        &refs(&transfer_request_fields(target, headers)),
        signature,
    )
}

/// The request signature bytes a response signs: the 64 bytes decoded from the request's
/// `Switch-Signature`, or `None` when it has none that decodes (Switch wire 2.3, 7.1).
pub fn request_signature_of(header_value: Option<&str>) -> Option<[u8; 64]> {
    header_value.and_then(|text| unb64_array::<64>(text).ok())
}

/// The fields after the label of a response signature: `u64(status)`, `hash(request
/// signature bytes)`, the `Switch-Server-Time` text and `hash(body)` (Switch wire 7.1).
pub fn response_fields(
    status: u16,
    request_signature: Option<&[u8; 64]>,
    server_time: &str,
    body: &[u8],
) -> Vec<Vec<u8>> {
    let request_signature: &[u8] = match request_signature {
        Some(signature) => signature,
        None => &[],
    };
    vec![
        u64be(u64::from(status)).to_vec(),
        hash(request_signature).to_vec(),
        server_time.as_bytes().to_vec(),
        hash(body).to_vec(),
    ]
}

/// Sign a response with the account's service key, or the operator key for a response the
/// service can't tie to an account (Switch wire 7.1).
pub fn sign_response(
    key: &impl Signs,
    status: u16,
    request_signature: Option<&[u8; 64]>,
    server_time: &str,
    body: &[u8],
) -> [u8; 64] {
    key.sign_fields(
        labels::sig::HTTP_RESPONSE,
        &refs(&response_fields(
            status,
            request_signature,
            server_time,
            body,
        )),
    )
}

/// Check a response signature with the service key the client pinned (Switch wire 7.1).
///
/// A client checks this before it uses anything in the response.
///
/// # Errors
///
/// [`Error::Signature`] if it doesn't verify with `service_key`.
pub fn verify_response(
    service_key: &[u8; 32],
    status: u16,
    request_signature: Option<&[u8; 64]>,
    server_time: &str,
    body: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    sig::verify(
        service_key,
        labels::sig::HTTP_RESPONSE,
        &refs(&response_fields(
            status,
            request_signature,
            server_time,
            body,
        )),
        signature,
    )
}

/// The relay origin a webhook signature covers: `https://` and the relay URL's host,
/// without port or path (Switch wire 8.2).
///
/// # Errors
///
/// [`Error::Invalid`] if the URL isn't `https` or has no host.
pub fn relay_origin(relay_url: &str) -> Result<String> {
    let Some(rest) = relay_url.strip_prefix("https://") else {
        return invalid("Switch wire 8.2: a relay URL is https");
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.split_once(']').map_or("", |(inner, _)| inner)
    } else {
        host.split(':').next().unwrap_or_default()
    };
    if host.is_empty() {
        return invalid("Switch wire 8.2: a relay URL has a host");
    }
    if relay_url.contains("://[") {
        return Ok(format!("https://[{host}]"));
    }
    Ok(format!("https://{host}"))
}

/// A webhook body: `{"v":1,"handle":...,"ts":...,"nonce":...}`, with the service time when
/// sent and a fresh random nonce (Switch wire 8.2). It names nothing about the message.
pub fn webhook_body(handle: &str, sent_at_ms: u64, nonce: &[u8; 16]) -> Vec<u8> {
    // The members in the order Switch wire 8.2 shows them; the handle is escaped as a JSON
    // string.
    let handle = serde_json::Value::String(handle.to_owned());
    format!(
        "{{\"v\":1,\"handle\":{handle},\"ts\":\"{}\",\"nonce\":\"{}\"}}",
        crate::time::rfc3339(sent_at_ms),
        crate::enc::b64(nonce)
    )
    .into_bytes()
}

/// Sign a webhook with the registration's push key, never the service key, over
/// `lp("pubky-switch/v1/push", relay origin, body bytes)` (Switch wire 8.2).
///
/// # Errors
///
/// [`Error::Invalid`] if the relay URL has no origin.
pub fn sign_webhook(push_key: &impl Signs, relay_url: &str, body: &[u8]) -> Result<[u8; 64]> {
    let origin = relay_origin(relay_url)?;
    Ok(push_key.sign_fields(labels::sig::PUSH, &[origin.as_bytes(), body]))
}

/// Check a webhook signature, as the push relay does (Switch wire 8.2, 8.3).
///
/// # Errors
///
/// [`Error::Invalid`] if the relay URL has no origin, [`Error::Signature`] if the signature
/// doesn't verify with `push_key`.
pub fn verify_webhook(
    push_key: &[u8; 32],
    relay_url: &str,
    body: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    let origin = relay_origin(relay_url)?;
    sig::verify(
        push_key,
        labels::sig::PUSH,
        &[origin.as_bytes(), body],
        signature,
    )
}

/// The calls after `/v1/{id}/` of a path, without its query.
fn call_of(path: &str) -> Option<Vec<&str>> {
    let path = path.split('?').next().unwrap_or_default();
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match parts.as_slice() {
        ["v1", "enroll"] => Some(vec!["enroll"]),
        ["v1", _id, rest @ ..] => Some(rest.to_vec()),
        _ => None,
    }
}

/// The body cap of a call, in bytes; a larger body is `413 too_large` before it is read
/// (Switch wire 7.1). `None` for a call the table doesn't name.
pub fn body_cap(method: &str, path: &str) -> Option<usize> {
    let call = call_of(path)?;
    Some(match (method, call.as_slice()) {
        ("POST", ["enroll"]) => 256 << 10,
        ("GET", _) => 0,
        ("POST", ["inbox"]) => 65_536,
        ("POST", ["ops"] | ["import"]) => 4 << 20,
        ("PUT", ["identity"] | ["peers"]) => 256 << 10,
        ("PUT", ["import", "chunks", _]) => 1 << 20,
        ("POST", ["recovery", "upload"]) => 16 << 20,
        ("PUT", ["handover"]) => 6 << 20,
        ("POST", ["freeze"])
        | ("POST", ["unfreeze"])
        | ("POST", ["import", "activate"])
        | ("POST", ["recovery", "admission"])
        | ("POST", ["apps", _, "revoke" | "leave" | "keys"])
        | ("PUT", ["push"])
        | ("POST", ["erase"]) => 16 << 10,
        ("POST", ["connect"]) | ("DELETE", ["connect", _]) => 0,
        _ => return None,
    })
}

/// Whether a frozen account answers a call with `410 moved` (Switch wire 7.3): the writes
/// other than the export, the unfreeze and the erasure. Reads go on.
pub fn frozen_refuses(method: &str, path: &str) -> bool {
    let Some(call) = call_of(path) else {
        return false;
    };
    matches!(
        (method, call.as_slice()),
        ("POST", ["inbox"])
            | ("PUT", ["peers"])
            | ("POST", ["connect"])
            | ("DELETE", ["connect", _])
            | ("POST", ["ops"])
            | ("POST", ["apps", _, "leave" | "revoke"])
            | ("POST", ["recovery", "upload"])
            | ("PUT", ["push"])
            | ("PUT", ["handover"])
    )
}

/// The error codes of the switch, with their HTTP status (Switch wire 7.6, Switch spec 6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `400`: a malformed request, document or operation.
    BadRequest,
    /// `401`: a signature that doesn't verify.
    BadSignature,
    /// `401`: `Switch-Timestamp` more than 5 minutes from the service's clock.
    StaleTimestamp,
    /// `403`: a sender not admitted or denied.
    NotAdmitted,
    /// `403`: the caller's certificate lacks the switch permission or scope.
    PermissionMissing,
    /// `403`: the calling app isn't current.
    NotCurrent,
    /// `403`: the caller's certificate has expired.
    CertExpired,
    /// `404`: no such object.
    NotFound,
    /// `409`: a condition, an expected step or version, or a registration failed.
    Conflict,
    /// `409`: a sealed value at another data epoch.
    StaleEpoch,
    /// `409`: an operation naming another generation.
    StaleGeneration,
    /// `409`: an envelope wrapped to a receive key that isn't current.
    StaleKey,
    /// `409`: a delivered `identity.json` that isn't newer, or doesn't build on the one held.
    StaleIdentity,
    /// `409`: the service's copy of the sender identity's `identity.json` doesn't list the app.
    IdentityNeeded,
    /// `410`: the account is frozen.
    Moved,
    /// `413`: a size cap exceeded.
    TooLarge,
    /// `429`: too many requests.
    RateLimited,
    /// `429`: a quota or a per-kind limit is full.
    QuotaExceeded,
    /// `503`: the account isn't named by its `identity.json` yet, or restores its allowlist.
    Staged,
    /// `503`: a temporary failure.
    Unavailable,
}

/// Whether the same request may succeed later (the Retry column of Switch spec 6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    /// Never unchanged.
    No,
    /// With a new timestamp.
    WithNewTimestamp,
    /// After re-reading and recomputing.
    AfterReread,
    /// After fetching the key bundle.
    AfterKeyBundle,
    /// After signing again for the current generation.
    AfterResigning,
    /// After sealing again to the current keys.
    AfterResealing,
    /// After delivering the sender's `identity.json`.
    AfterDeliveringIdentity,
    /// At the next service.
    AtNextService,
    /// After `Retry-After`.
    AfterRetryAfter,
    /// Once the full limit frees.
    WhenLimitFrees,
    /// Yes, unchanged.
    Yes,
}

impl ErrorCode {
    /// Every code, in the order of the table.
    pub const ALL: [ErrorCode; 20] = [
        ErrorCode::BadRequest,
        ErrorCode::BadSignature,
        ErrorCode::StaleTimestamp,
        ErrorCode::NotAdmitted,
        ErrorCode::PermissionMissing,
        ErrorCode::NotCurrent,
        ErrorCode::CertExpired,
        ErrorCode::NotFound,
        ErrorCode::Conflict,
        ErrorCode::StaleEpoch,
        ErrorCode::StaleGeneration,
        ErrorCode::StaleKey,
        ErrorCode::StaleIdentity,
        ErrorCode::IdentityNeeded,
        ErrorCode::Moved,
        ErrorCode::TooLarge,
        ErrorCode::RateLimited,
        ErrorCode::QuotaExceeded,
        ErrorCode::Staged,
        ErrorCode::Unavailable,
    ];

    /// The `code` text.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::BadSignature => "bad_signature",
            ErrorCode::StaleTimestamp => "stale_timestamp",
            ErrorCode::NotAdmitted => "not_admitted",
            ErrorCode::PermissionMissing => "permission_missing",
            ErrorCode::NotCurrent => "not_current",
            ErrorCode::CertExpired => "cert_expired",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Conflict => "conflict",
            ErrorCode::StaleEpoch => "stale_epoch",
            ErrorCode::StaleGeneration => "stale_generation",
            ErrorCode::StaleKey => "stale_key",
            ErrorCode::StaleIdentity => "stale_identity",
            ErrorCode::IdentityNeeded => "identity_needed",
            ErrorCode::Moved => "moved",
            ErrorCode::TooLarge => "too_large",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::QuotaExceeded => "quota_exceeded",
            ErrorCode::Staged => "staged",
            ErrorCode::Unavailable => "unavailable",
        }
    }

    /// The code of a `code` text, if the switch defines it.
    pub fn parse(text: &str) -> Option<ErrorCode> {
        ErrorCode::ALL
            .into_iter()
            .find(|code| code.as_str() == text)
    }

    /// The HTTP status the code is answered with.
    pub fn status(self) -> u16 {
        match self {
            ErrorCode::BadRequest => 400,
            ErrorCode::BadSignature | ErrorCode::StaleTimestamp => 401,
            ErrorCode::NotAdmitted
            | ErrorCode::PermissionMissing
            | ErrorCode::NotCurrent
            | ErrorCode::CertExpired => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::Conflict
            | ErrorCode::StaleEpoch
            | ErrorCode::StaleGeneration
            | ErrorCode::StaleKey
            | ErrorCode::StaleIdentity
            | ErrorCode::IdentityNeeded => 409,
            ErrorCode::Moved => 410,
            ErrorCode::TooLarge => 413,
            ErrorCode::RateLimited | ErrorCode::QuotaExceeded => 429,
            ErrorCode::Staged | ErrorCode::Unavailable => 503,
        }
    }

    /// Whether the same request may succeed later (Switch spec 6.4).
    pub fn retry(self) -> Retry {
        match self {
            ErrorCode::BadRequest
            | ErrorCode::BadSignature
            | ErrorCode::NotAdmitted
            | ErrorCode::PermissionMissing
            | ErrorCode::NotCurrent
            | ErrorCode::CertExpired
            | ErrorCode::NotFound
            | ErrorCode::StaleIdentity
            | ErrorCode::TooLarge => Retry::No,
            ErrorCode::StaleTimestamp => Retry::WithNewTimestamp,
            ErrorCode::Conflict => Retry::AfterReread,
            ErrorCode::StaleEpoch => Retry::AfterKeyBundle,
            ErrorCode::StaleGeneration => Retry::AfterResigning,
            ErrorCode::StaleKey => Retry::AfterResealing,
            ErrorCode::IdentityNeeded => Retry::AfterDeliveringIdentity,
            ErrorCode::Moved => Retry::AtNextService,
            ErrorCode::RateLimited => Retry::AfterRetryAfter,
            ErrorCode::QuotaExceeded => Retry::WhenLimitFrees,
            ErrorCode::Staged | ErrorCode::Unavailable => Retry::Yes,
        }
    }

    /// Whether the answer carries `known_version` for an app of another identity: a `2xx`
    /// answer and `409 identity_needed` do, other errors don't (Switch wire 7.1).
    pub fn carries_known_version(self) -> bool {
        self == ErrorCode::IdentityNeeded
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.status(), self.as_str())
    }
}

/// Decode a header's base64url signature.
///
/// # Errors
///
/// [`Error::Signature`] if it isn't base64url of 64 bytes, as a request with such a
/// signature is answered `401` (Switch wire 7.2).
pub fn decode_signature(text: &str) -> Result<[u8; 64]> {
    unb64_array::<64>(text)
        .map_err(|_| Error::Signature("Switch wire 7.1: a signature header isn't b64(64)".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AppKeys;

    fn target(body: &[u8]) -> RequestTarget<'_> {
        RequestTarget {
            method: "POST",
            path_and_query: "/v1/x/ops",
            body,
            origin: "https://switch.example",
        }
    }

    #[test]
    fn test_request_signature_covers_body_and_headers() {
        let app = AppKeys::from_secrets([1; 32], [2; 32]);
        let headers = RequestHeaders {
            timestamp: "2026-01-01T00:00:00Z".into(),
            identity: "id".into(),
            app: Some(app.app_id()),
            ..RequestHeaders::default()
        };
        let signature = sign_request(&app, &target(b"{}"), &headers);
        let public = app.signing_public();
        assert!(verify_request(&public, &target(b"{}"), &headers, &signature).is_ok());
        assert!(verify_request(&public, &target(b"{ }"), &headers, &signature).is_err());
        let mut other = headers.clone();
        other.invite_code = Some("code".into());
        assert!(verify_request(&public, &target(b"{}"), &other, &signature).is_err());
    }

    #[test]
    fn test_response_signature_covers_the_request_signature() {
        let key = AppKeys::from_secrets([3; 32], [4; 32]);
        let request = [7u8; 64];
        let time = "2026-01-01T00:00:00.000Z";
        let signature = sign_response(&key, 200, Some(&request), time, b"{}");
        let public = key.signing_public();
        assert!(verify_response(&public, 200, Some(&request), time, b"{}", &signature).is_ok());
        assert!(verify_response(&public, 200, None, time, b"{}", &signature).is_err());
        assert!(verify_response(&public, 201, Some(&request), time, b"{}", &signature).is_err());
        // A request without a decodable signature signs the hash of the empty string.
        assert_eq!(
            response_fields(404, None, time, b"")[1],
            crate::enc::hash(b"").to_vec()
        );
        assert_eq!(request_signature_of(Some("not base64url")), None);
    }

    #[test]
    fn test_relay_origin_drops_port_path_and_user() {
        assert_eq!(
            relay_origin("https://push.example/v1/hook").unwrap(),
            "https://push.example"
        );
        assert_eq!(
            relay_origin("https://u@push.example:443/x").unwrap(),
            "https://push.example"
        );
        assert!(relay_origin("http://push.example").is_err());
        assert!(relay_origin("https:///x").is_err());
    }

    #[test]
    fn test_webhook_signature_round_trips() {
        let key = AppKeys::from_secrets([5; 32], [6; 32]);
        let body = webhook_body("handle", 1_767_225_960_000, &[9; 16]);
        let url = "https://push.example/v1/hook";
        let signature = sign_webhook(&key, url, &body).unwrap();
        assert!(verify_webhook(&key.signing_public(), url, &body, &signature).is_ok());
        assert!(
            verify_webhook(
                &key.signing_public(),
                "https://other.example",
                &body,
                &signature
            )
            .is_err()
        );
    }

    #[test]
    fn test_body_caps_and_frozen_calls() {
        assert_eq!(body_cap("POST", "/v1/enroll"), Some(256 << 10));
        assert_eq!(
            body_cap("POST", "/v1/id/inbox?apps_version=4"),
            Some(65_536)
        );
        assert_eq!(body_cap("GET", "/v1/id/feed"), Some(0));
        assert_eq!(body_cap("POST", "/v1/id/apps/a/keys"), Some(16 << 10));
        assert_eq!(body_cap("PATCH", "/v1/id/ops"), None);
        assert!(frozen_refuses("POST", "/v1/id/ops"));
        assert!(!frozen_refuses("POST", "/v1/id/unfreeze"));
        assert!(!frozen_refuses("GET", "/v1/id/feed"));
    }

    #[test]
    fn test_error_codes_round_trip() {
        for code in ErrorCode::ALL {
            assert_eq!(ErrorCode::parse(code.as_str()), Some(code));
        }
        assert_eq!(ErrorCode::parse("teapot"), None);
        assert_eq!(ErrorCode::StaleKey.status(), 409);
        assert_eq!(ErrorCode::Unavailable.retry(), Retry::Yes);
        assert_eq!(ErrorCode::StaleIdentity.retry(), Retry::No);
    }
}
