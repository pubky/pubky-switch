//! The client's error types, one per layer: the host store ([`StoreError`]), the transport
//! ([`TransportError`]) and the Switch client ([`ClientError`]).
//!
//! No message quotes a body, a document's text, decrypted plaintext or key material: each
//! names the rule or the member that failed.

use pubky_switch_core::chain::ChainError;
use pubky_switch_core::http::{ErrorCode, Retry};

/// A failure of the host's [`crate::store::StateStore`].
///
/// The variants tell the crates what they may assume about the state after the failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Nothing was applied: the call may be retried.
    #[error("the store is unavailable; nothing was applied")]
    Unavailable,
    /// The writes may or may not have been applied: the caller reads its state again before
    /// it goes on.
    #[error("the store can't tell whether the writes were applied")]
    Unknown,
    /// The store is out of space; nothing was applied.
    #[error("the store is full")]
    Full,
    /// A stored value failed its own checks.
    #[error("a stored value is corrupt")]
    Corrupt,
    /// A write batch, or one value in it, over the working sizes
    /// ([`crate::store::MAX_VALUE_BYTES`], [`crate::store::MAX_BATCH_BYTES`]), refused before
    /// the host sees it. Nothing was applied. It is the writes' fault, not the store's: the
    /// same writes are refused again, however often they are retried.
    #[error("the writes would take {size} bytes, over the {cap}-byte size")]
    TooLarge {
        /// The size in bytes of the value, or of the batch with the refused write.
        size: u64,
        /// The cap.
        cap: u64,
    },
    /// Any other failure, described by the host. Nothing was applied.
    #[error("store: {0}")]
    Other(String),
}

impl From<BatchError> for StoreError {
    /// A size refusal is [`StoreError::TooLarge`]; a write in another namespace,
    /// [`StoreError::Other`].
    fn from(error: BatchError) -> Self {
        match error {
            BatchError::ValueTooLarge { size, cap } | BatchError::BatchTooLarge { size, cap } => {
                StoreError::TooLarge { size, cap }
            }
            BatchError::Namespace => StoreError::Other(error.to_string()),
        }
    }
}

/// A write batch over the working sizes, refused before the host sees it
/// ([`crate::store::MAX_VALUE_BYTES`], [`crate::store::MAX_BATCH_BYTES`]).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BatchError {
    /// One value is over the per-value size.
    #[error("a value of {size} bytes is over the {cap}-byte value size")]
    ValueTooLarge {
        /// The value's size in bytes.
        size: u64,
        /// The cap.
        cap: u64,
    },
    /// The batch is over the per-batch size.
    #[error("the batch would take {size} bytes, over the {cap}-byte batch size")]
    BatchTooLarge {
        /// The batch's size in bytes with the refused write.
        size: u64,
        /// The cap.
        cap: u64,
    },
    /// A namespace this crate doesn't write (the client writes only `client/<app_id>`).
    #[error("namespace isn't the client's own")]
    Namespace,
}

/// A failure to carry a request to the switch or its answer back.
///
/// None of these is an answer of the switch: a request that failed here may or may not have
/// reached it, so a write is resent with the same bytes (Switch wire 2.1). The two that
/// say nothing was sent, [`TransportError::Refused`] and [`TransportError::Connect`], are
/// relied on: a batch whose first send fails with one is kept as never sent, so a
/// transport returns them only when no byte of the request left.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The origin, or an address its host resolves to, isn't one the client may connect to
    /// (Switch wire 7.1, 8.2). Nothing was sent.
    #[error("refused origin: {0}")]
    Refused(String),
    /// No connection could be made. Nothing was sent.
    #[error("connection failed: {0}")]
    Connect(String),
    /// The call took longer than its timeout.
    #[error("timed out")]
    Timeout,
    /// The answer is larger than the transport accepts.
    #[error("the answer is over {0} bytes")]
    TooLarge(u64),
    /// The request couldn't be built, for example a header value that isn't text.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Any other failure.
    #[error("transport: {0}")]
    Other(String),
}

/// A failure of a call to the switch.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// An error answer of the switch, checked with the pinned service key (Switch wire 7.1,
    /// 7.6).
    #[error("{code}: {message}")]
    Switch {
        /// The HTTP status.
        status: u16,
        /// The error code, which fixes the status.
        code: ErrorCode,
        /// The service's message.
        message: String,
        /// The answer's `current`, `null` when absent (Switch wire 7.6).
        current: serde_json::Value,
        /// `known_version`, which only `409 identity_needed` carries; `None` when absent or
        /// `null` (Switch wire 7.1).
        known_version: Option<u64>,
        /// `retry_after` in seconds, on `429 rate_limited` (Switch wire 7.6).
        retry_after: Option<u64>,
    },
    /// The request didn't reach the switch, or its answer didn't come back.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The response signature didn't verify with the pinned service key, or the response
    /// carried none, so nothing in it was used (Switch wire 7.1). An answer the service
    /// signs with its operator key, such as the `404` for an account it doesn't host, comes
    /// back this way: the status is kept, as a signer that erased an account reads that
    /// `404` (Switch wire 7.4.16).
    #[error("the response signature didn't verify (status {status})")]
    BadServiceSignature {
        /// The response's HTTP status, unauthenticated.
        status: u16,
    },
    /// The client holds no pinned service key, so the call wasn't sent: only an enrollment
    /// is sent without one (Switch wire 7.1, Switch spec 6.1).
    #[error("no pinned service key; only an enrollment is sent without one")]
    Unpinned,
    /// An answer, checked with the pinned key, that doesn't read as the wire format gives
    /// it. The text names the rule or the member, never the body.
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    /// A head or a transition proof that doesn't verify with the service key, or proofs that
    /// don't bind the batch sent (Switch wire 6.5, 6.7). Signed by the service, it is
    /// evidence of misbehaviour, handled as a rollback (Switch spec 10.1).
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// A document that fails a check of the core.
    #[error(transparent)]
    Core(#[from] pubky_switch_core::Error),
    /// A call these credentials can't make, or arguments the wire format doesn't allow; it
    /// wasn't sent.
    #[error("usage: {0}")]
    Usage(String),
}

impl ClientError {
    /// Whether the same request may succeed later, by the Retry column of Switch spec 6.4,
    /// for an error answer of the switch; `None` for every other failure.
    pub fn retry(&self) -> Option<Retry> {
        match self {
            ClientError::Switch { code, .. } => Some(code.retry()),
            _ => None,
        }
    }

    /// The error code of an answer of the switch.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ClientError::Switch { code, .. } => Some(*code),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_error_retry_follows_the_code() {
        let error = ClientError::Switch {
            status: 429,
            code: ErrorCode::RateLimited,
            message: "too many requests".into(),
            current: serde_json::Value::Null,
            known_version: None,
            retry_after: Some(37),
        };
        assert_eq!(error.retry(), Some(Retry::AfterRetryAfter));
        assert_eq!(error.code(), Some(ErrorCode::RateLimited));
        assert_eq!(error.to_string(), "429 rate_limited: too many requests");
    }

    #[test]
    fn test_client_error_retry_is_none_for_local_failures() {
        assert_eq!(ClientError::Unpinned.retry(), None);
        assert_eq!(
            ClientError::Transport(TransportError::Timeout).retry(),
            None
        );
        assert_eq!(
            ClientError::BadServiceSignature { status: 404 }.code(),
            None
        );
    }
}
