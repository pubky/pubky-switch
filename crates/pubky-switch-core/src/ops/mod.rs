//! Signed operations, conditions and batches (Switch wire 6.1 to 6.4, Switch spec 10.1 and
//! 13.5).
//!
//! Every change an app or the signer makes at the switch is a signed operation: a JSON body
//! naming its type in `op`, signed by its writer over `lp("pubky-switch/v1/op", identity,
//! body)`. Operations travel in batches of 1 to 8 entries in a `POST /v1/{id}/ops` body, all
//! or nothing, each naming the batch's random ID and count, so that every app can check from
//! the chain that a batch is complete (Switch wire 6.6).
//!
//! This module is pure: it builds and signs operations and batches for a writer, and checks
//! them for the service, as far as a check needs no state. The checks that need the account's
//! state take what they compare against as arguments, such as the record the service holds
//! for an app. A protocol's natural keys and claim inputs reach it only as blinded bytes, and
//! its scopes only as opaque strings (Switch spec 1).
//!
//! - [`OpBody`] and [`OpKind`]: an operation's members, written in the wire format's order
//!   and read strictly, refusing unknown members at every depth (Switch wire 1.1, 6.1).
//! - [`SignedOp`]: an operation signed by its writer, or verified for the caller.
//! - [`OpsRequest`] and [`Entry`]: the `POST /ops` body, its entry rules and its batch rules
//!   (Switch wire 6.4).
//! - [`Condition`] and [`ConditionState`]: conditions, checked against the state before the
//!   batch (Switch wire 6.3).
//! - The per-type rules of Switch wire 6.2 that the service applies against what it holds:
//!   [`check_app_put`], [`check_receive_key_put`], [`check_cert_put`],
//!   [`check_key_bundle_put`] and [`check_invite_code_put`], and the no-op and rate rules of
//!   Switch wire 6.4 ([`batch_effect`]).

mod batch;
pub(crate) mod body;
mod bundle_parts;
mod invite;
mod limits;
mod proof_state;
pub(crate) mod read;
mod rules;

pub use batch::{
    BATCH_PROOFS_MS, BatchEffect, BatchRecord, ConditionState, Entry, Held, MAX_BATCH_ENTRIES,
    OpsRequest, Position, RetryCheck, batch_effect, check_batch, check_conditions, depends_on_time,
    ops_hash, random_batch_id, retry_check, sign_batch, unchanged,
};
pub use body::{
    AllowKind, BatchRef, Condition, IdInputs, InviteCodePut, KeyBundlePut, MAX_OP_BYTES, OpBody,
    OpKind, RecordPut, RecordVersion, SignedOp, carrying_len,
};
pub use bundle_parts::{StoredPart, covers, keys_through, parts_to_drop};
pub use invite::invite_code_delete;
pub use limits::{Limits, List, Quota, check_quota};
pub use proof_state::{StateAfter, proof_state};
pub use rules::{
    AppPutEffect, CertPutEffect, KeyBundleEffect, MAX_INVITE_CONTEXT_BYTES, MAX_INVITE_USES, Need,
    ReceiveKeyEffect, Writer, check_app_put, check_cert_put, check_invite_code_put,
    check_key_bundle_put, check_permission, check_receive_key_put, check_shape,
};

use crate::error::{Error, SizeRefusal};
use crate::http::ErrorCode;

/// A refusal the switch answers with a fixed status and `code` (Switch wire 7.6), and the
/// `current` member the answer carries, if any.
///
/// The reason names the rule that failed, usually with its section; it never quotes the
/// refused document's text or any sealed content.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
#[error("{code}: {reason}")]
pub struct Refusal {
    /// The error code, which fixes the HTTP status.
    pub code: ErrorCode,
    /// The rule that failed.
    pub reason: String,
    /// The answer's `current`, the state the caller may read (Switch wire 7.6).
    pub current: Option<serde_json::Value>,
}

impl Refusal {
    /// A refusal with `code`, without `current`.
    pub fn new(code: ErrorCode, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
            current: None,
        }
    }

    /// A `400 bad_request`.
    pub fn bad_request(reason: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadRequest, reason)
    }

    /// A `409 conflict`.
    pub fn conflict(reason: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, reason)
    }

    /// The same refusal, carrying `current`.
    pub fn with_current(mut self, current: serde_json::Value) -> Self {
        self.current = Some(current);
        self
    }

    /// The HTTP status of the answer.
    pub fn status(&self) -> u16 {
        self.code.status()
    }
}

impl From<Error> for Refusal {
    /// A malformed document is `400 bad_request`, a signature that fails `401 bad_signature`
    /// (Switch wire 7.6).
    fn from(error: Error) -> Self {
        match error {
            Error::Signature(why) => Self::new(ErrorCode::BadSignature, why),
            Error::Invalid(why) | Error::Crypto(why) => Self::bad_request(why),
        }
    }
}

impl From<SizeRefusal> for Refusal {
    fn from(refusal: SizeRefusal) -> Self {
        match refusal {
            SizeRefusal::TooLarge(why) => Self::new(ErrorCode::TooLarge, why),
            SizeRefusal::BadRequest(why) => Self::bad_request(why),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refusal_maps_core_errors_to_their_answers() {
        let bad = Refusal::from(Error::Invalid("rule".into()));
        assert_eq!((bad.status(), bad.code), (400, ErrorCode::BadRequest));
        let sig = Refusal::from(Error::Signature("rule".into()));
        assert_eq!((sig.status(), sig.code), (401, ErrorCode::BadSignature));
        let big = Refusal::from(SizeRefusal::TooLarge("rule".into()));
        assert_eq!(big.status(), 413);
        let current = Refusal::conflict("rule").with_current(serde_json::json!({}));
        assert_eq!(current.current, Some(serde_json::json!({})));
        assert_eq!(current.to_string(), "409 conflict: rule");
    }
}
