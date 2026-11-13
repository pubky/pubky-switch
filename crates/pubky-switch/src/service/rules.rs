//! The service's own rules, as pure functions: no HTTP, no storage, no clock. The endpoints
//! call them with what the account holds, and a test harness, such as the client's scripted
//! switch, can call them the same way.
//!
//! The rules of the formats themselves are the core's: an `identity.json` delivery is judged
//! by `pubky_switch_core::records::check_delivery`.

use pubky_switch_core::{
    enc::{pubky_key, unb64_array},
    http::{RequestHeaders, header},
    records::IdentityDoc,
    time::{parse_rfc3339, rfc3339},
};

use crate::http::{
    error::{ApiError, ErrorCode},
    route::Call,
};
use crate::limits::fixed;

/// Who a request claims to come from, by its headers (Switch wire 7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    /// The account's identity, without `Switch-App`: its signer.
    Signer,
    /// The account's identity, with `Switch-App`: one of its own apps.
    OwnApp(String),
    /// Another identity, with `Switch-App`: an app of that identity.
    OtherApp {
        /// The caller's identity.
        identity: [u8; 32],
        /// Its App ID.
        app: String,
    },
}

/// The signed headers of a request, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claimed {
    /// Who the request claims to come from.
    pub caller: Caller,
    /// The caller's identity key, from `Switch-Identity`.
    pub identity_key: [u8; 32],
    /// The headers its signature covers, as their exact text.
    pub headers: RequestHeaders,
    /// The request signature.
    pub signature: [u8; 64],
    /// The signing time.
    pub timestamp_ms: u64,
}

fn header_text<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Decode what a request claims (Switch wire 7.2 Order): `Switch-Identity` (`400`),
/// `Switch-Signature` (`401 bad_signature`), then `Switch-Timestamp` against `base_ms`, the
/// time base (`400`, `401 stale_timestamp`). Nothing it claims is trusted until its
/// signature verifies.
pub fn decode_claim(
    account: &[u8; 32],
    headers: &axum::http::HeaderMap,
    base_ms: u64,
) -> Result<Claimed, ApiError> {
    let identity = header_text(headers, header::IDENTITY)
        .ok_or_else(|| ApiError::bad_request("7.1: Switch-Identity is missing"))?;
    let identity_key = pubky_key(identity)
        .map_err(|_| ApiError::bad_request("7.1: Switch-Identity isn't a Pubky ID"))?;
    let signature = header_text(headers, header::SIGNATURE)
        .and_then(|text| unb64_array::<64>(text).ok())
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::BadSignature,
                "7.1: Switch-Signature isn't a signature",
            )
        })?;
    let timestamp = header_text(headers, header::TIMESTAMP)
        .ok_or_else(|| ApiError::bad_request("7.1: Switch-Timestamp is missing"))?;
    let timestamp_ms = check_timestamp(timestamp, base_ms)?;
    let app = header_text(headers, header::APP).map(str::to_string);
    let caller = match (identity_key == *account, app) {
        (true, None) => Caller::Signer,
        (true, Some(app)) => Caller::OwnApp(app),
        (false, Some(app)) => Caller::OtherApp {
            identity: identity_key,
            app,
        },
        (false, None) => {
            return Err(ApiError::new(
                ErrorCode::NotAdmitted,
                "7.2: a signer of another identity",
            ));
        }
    };
    Ok(Claimed {
        caller,
        identity_key,
        headers: RequestHeaders {
            timestamp: timestamp.to_string(),
            identity: identity.to_string(),
            app: header_text(headers, header::APP).map(str::to_string),
            cert: header_text(headers, header::CERT).map(str::to_string),
            invite_code: header_text(headers, header::INVITE_CODE).map(str::to_string),
        },
        signature,
        timestamp_ms,
    })
}

/// Check `Switch-Timestamp` against the time base: unparsable is `400 bad_request`, more
/// than 5 minutes off is `401 stale_timestamp` (Switch wire 7.1).
pub fn check_timestamp(text: &str, base_ms: u64) -> Result<u64, ApiError> {
    let well_formed = text.len() == 20 && text.ends_with('Z') && !text.contains('.');
    let at = parse_rfc3339(text)
        .ok()
        .filter(|_| well_formed)
        .ok_or_else(|| ApiError::bad_request("7.1: Switch-Timestamp isn't YYYY-MM-DDTHH:MM:SSZ"))?;
    if at.abs_diff(base_ms) > fixed::TIMESTAMP_WINDOW_MS {
        // The time base, for the retry's timestamp: the answer's Switch-Server-Time stays
        // the identity's last committed time, which a refusal before the lock can't move.
        return Err(ApiError::new(
            ErrorCode::StaleTimestamp,
            "7.1: Switch-Timestamp is more than 5 minutes from the service's time",
        )
        .with_current(serde_json::json!({ "server_time": rfc3339(base_ms) })));
    }
    Ok(at)
}

/// Whether the account serves: its newest `identity.json` names this service, its origin
/// and its service key (Switch wire 3.7). Until then it is staged.
pub fn names_this_service(
    held: Option<&IdentityDoc>,
    origin: &str,
    service_key: &[u8; 32],
) -> bool {
    held.is_some_and(|doc| doc.inbox().url == origin && doc.inbox().service_key == *service_key)
}

/// The staged gate (Switch wire 7.3 step 7): a staged account answers every call but a few
/// with `503 staged`.
pub fn staged_gate(call: &Call, staged: bool) -> Result<(), ApiError> {
    if staged && !call.passes_staged() {
        return Err(ApiError::new(
            ErrorCode::Staged,
            "7.3: the account isn't named by its identity.json yet",
        ));
    }
    Ok(())
}

/// Whether apps of other identities make `call`: `PUT /peers`, `POST /inbox`, `GET
/// /directory` and `POST /connect` (Switch wire 7.2, 7.4).
pub fn takes_other_apps(call: &Call) -> bool {
    matches!(
        call,
        Call::PutPeers | Call::Append | Call::Directory | Call::PostConnect
    )
}

/// The refusal of an app of another identity at a call it doesn't make, once its
/// certificate has passed every check, expiry included (Switch wire 7.2, 3.8): `403
/// permission_missing`, by 7.6's "a call only another caller may make", at every call only
/// own apps or the signer make: the reads only own apps make (the feed, 7.4.4, the claims,
/// the lists and the records), the key bundle calls (7.4.11), a leave (7.4.12), a recovery
/// upload (7.4.14), push and the connect reads, the hand-over (7.4.17) and the signer's
/// calls (7.4), the move's included; and `403 not_admitted` at a batch (6.4).
pub fn other_app_refusal(call: &Call) -> ApiError {
    match call {
        Call::Feed
        | Call::GetClaim(_)
        | Call::GetAllow
        | Call::GetRecord(_)
        | Call::ListRecords => ApiError::new(
            ErrorCode::PermissionMissing,
            "7.4: only the account's own apps make this read",
        ),
        Call::GetKeys(_) | Call::RequestKeys(_) => super::app_keys::only_that_app(),
        Call::Leave(_) => ApiError::new(
            ErrorCode::PermissionMissing,
            "7.4.12: only the app itself leaves",
        ),
        Call::RecoveryUpload | Call::PutPush | Call::GetConnect | Call::DeleteConnect(_) => {
            ApiError::new(
                ErrorCode::PermissionMissing,
                "7.4: only the account's own apps make this call",
            )
        }
        Call::PutHandover | Call::GetHandover => ApiError::new(
            ErrorCode::PermissionMissing,
            "7.4.17: only the signer and the app it is for",
        ),
        Call::PutIdentity
        | Call::Revoke(_)
        | Call::GetApps
        | Call::RecoveryAdmission
        | Call::Freeze
        | Call::Unfreeze
        | Call::Export
        | Call::ExportChunk(_)
        | Call::Import
        | Call::ImportChunk(_)
        | Call::ImportActivate
        | Call::Erase => ApiError::new(
            ErrorCode::PermissionMissing,
            "7.4: a call only the signer may make",
        ),
        _ => ApiError::new(
            ErrorCode::NotAdmitted,
            "6.4: an app of another identity doesn't write here",
        ),
    }
}

/// Which key answers an enrollment (Switch wire 3.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentKey {
    /// No account yet: make one, with a new key.
    NewAccount,
    /// A staged account: its own key, changing nothing.
    AccountKey,
    /// A serving account: the pending key of the next generation, made now if there is none
    /// yet, and the same for every enrollment until a document names it.
    PendingKey {
        /// Whether a pending key exists already.
        exists: bool,
    },
}

/// The key an enrollment is answered with, by what the account is.
pub fn enrollment_key(account: Option<AccountState>) -> EnrollmentKey {
    match account {
        None => EnrollmentKey::NewAccount,
        Some(AccountState { serving: false, .. }) => EnrollmentKey::AccountKey,
        Some(AccountState {
            serving: true,
            pending_key,
        }) => EnrollmentKey::PendingKey {
            exists: pending_key,
        },
    }
}

/// What an enrollment's answer depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountState {
    /// Whether the account serves.
    pub serving: bool,
    /// Whether it has a pending key for the next generation.
    pub pending_key: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    const T0: u64 = 1_767_225_600_000;
    const ALICE: &str = "6frao8w9ss5cn544qd64hynikrbr97ae1s5941c7ma5e1epifhgy";
    const BOB: &str = "7p4fn44qoshcwgfndz5grt7fyyz1eycqyduxdqe8o58of1byzodo";

    fn headers(identity: &str, app: Option<&str>, signature: &str, timestamp: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        let mut put = |name: &'static str, value: &str| {
            map.insert(name, HeaderValue::from_str(value).expect("value"));
        };
        put(header::IDENTITY, identity);
        put(header::SIGNATURE, signature);
        put(header::TIMESTAMP, timestamp);
        if let Some(app) = app {
            put(header::APP, app);
        }
        map
    }

    fn signature() -> String {
        pubky_switch_core::enc::b64(&[1u8; 64])
    }

    #[test]
    fn test_rules_decode_claim_callers() {
        let alice = pubky_key(ALICE).expect("alice");
        let at = "2026-01-01T00:00:00Z";
        let signer =
            decode_claim(&alice, &headers(ALICE, None, &signature(), at), T0).expect("signer");
        assert_eq!(signer.caller, Caller::Signer);
        let own =
            decode_claim(&alice, &headers(ALICE, Some("app"), &signature(), at), T0).expect("own");
        assert_eq!(own.caller, Caller::OwnApp("app".into()));
        let other =
            decode_claim(&alice, &headers(BOB, Some("shop"), &signature(), at), T0).expect("other");
        assert!(matches!(other.caller, Caller::OtherApp { .. }));
        let refused =
            decode_claim(&alice, &headers(BOB, None, &signature(), at), T0).expect_err("x");
        assert_eq!(refused.code, ErrorCode::NotAdmitted);
    }

    #[test]
    fn test_rules_decode_claim_refusals_in_order() {
        let alice = pubky_key(ALICE).expect("alice");
        let at = "2026-01-01T00:00:00Z";
        let code = |map: HeaderMap| decode_claim(&alice, &map, T0).expect_err("refused").code;
        assert_eq!(
            code(headers("not-a-key", None, &signature(), at)),
            ErrorCode::BadRequest
        );
        assert_eq!(
            code(headers(ALICE, None, "short", at)),
            ErrorCode::BadSignature
        );
        assert_eq!(
            code(headers(ALICE, None, &signature(), "yesterday")),
            ErrorCode::BadRequest
        );
        assert_eq!(
            code(headers(ALICE, None, &signature(), "2026-01-01T00:05:01Z")),
            ErrorCode::StaleTimestamp
        );
        let mut missing = headers(ALICE, None, &signature(), at);
        missing.remove(header::TIMESTAMP);
        assert_eq!(code(missing), ErrorCode::BadRequest);
    }

    #[test]
    fn test_rules_timestamp_window_and_form() {
        assert_eq!(
            check_timestamp("2026-01-01T00:05:00Z", T0),
            Ok(T0 + 300_000)
        );
        assert_eq!(
            check_timestamp("2025-12-31T23:55:00Z", T0),
            Ok(T0 - 300_000)
        );
        for (text, code) in [
            ("2026-01-01T00:05:01Z", ErrorCode::StaleTimestamp),
            ("2025-12-31T23:54:59Z", ErrorCode::StaleTimestamp),
            ("2026-01-01T00:00:00.000Z", ErrorCode::BadRequest),
            ("2026-01-01T00:00:00+00:00", ErrorCode::BadRequest),
            ("", ErrorCode::BadRequest),
        ] {
            assert_eq!(
                check_timestamp(text, T0).expect_err(text).code,
                code,
                "{text}"
            );
        }
    }

    #[test]
    fn test_rules_staged_gate() {
        assert!(staged_gate(&Call::PutIdentity, true).is_ok());
        assert!(staged_gate(&Call::Erase, true).is_ok());
        assert_eq!(
            staged_gate(&Call::Feed, true).expect_err("staged").code,
            ErrorCode::Staged
        );
        assert!(staged_gate(&Call::Feed, false).is_ok());
        assert_eq!(
            staged_gate(&Call::PutPush, true).expect_err("staged").code,
            ErrorCode::Staged
        );
    }

    #[test]
    fn test_rules_other_app_refusal() {
        assert!(takes_other_apps(&Call::PutPeers) && takes_other_apps(&Call::Append));
        assert!(takes_other_apps(&Call::Directory) && takes_other_apps(&Call::PostConnect));
        assert!(!takes_other_apps(&Call::Feed) && !takes_other_apps(&Call::Ops));
        assert!(!takes_other_apps(&Call::GetConnect));
        for call in [
            Call::GetConnect,
            Call::DeleteConnect(String::new()),
            Call::Feed,
            Call::GetClaim(String::new()),
            Call::GetAllow,
            Call::GetRecord(String::new()),
            Call::ListRecords,
            Call::PutIdentity,
            Call::GetApps,
            Call::Leave(String::new()),
            Call::Erase,
            Call::PutPush,
        ] {
            assert_eq!(other_app_refusal(&call).code, ErrorCode::PermissionMissing);
        }
        assert_eq!(other_app_refusal(&Call::Ops).code, ErrorCode::NotAdmitted);
    }

    #[test]
    fn test_rules_enrollment_key() {
        assert_eq!(enrollment_key(None), EnrollmentKey::NewAccount);
        let staged = AccountState {
            serving: false,
            pending_key: false,
        };
        assert_eq!(enrollment_key(Some(staged)), EnrollmentKey::AccountKey);
        let serving = AccountState {
            serving: true,
            pending_key: false,
        };
        assert_eq!(
            enrollment_key(Some(serving)),
            EnrollmentKey::PendingKey { exists: false }
        );
        let pending = AccountState {
            serving: true,
            pending_key: true,
        };
        assert_eq!(
            enrollment_key(Some(pending)),
            EnrollmentKey::PendingKey { exists: true }
        );
    }
}
