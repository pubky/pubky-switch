//! The app layer's errors ([`AppError`]), its alarms ([`Alarm`]) and its refusals
//! ([`Refusal`]).
//!
//! No text quotes a body, a message, a key or a document: each names the rule or the
//! member that failed.

use pubky_switch_core::http::{ErrorCode, Retry};

use crate::error::{BatchError, ClientError, StoreError, TransportError};

/// Evidence of misbehaviour, or of a compromise, that stops the app (Switch spec 3.6, 4.3,
/// 10.1). The app keeps it in its store and shows it to the user; it makes no new writes
/// through the service until the user resolves it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum Alarm {
    /// The service rolled back or forked its chain, or signed an answer that contradicts
    /// itself (Switch spec 10.1). The user resolves it by moving to another provider or by
    /// declaring a provider loss.
    Rollback {
        /// The rule the chain broke.
        reason: String,
    },
    /// Two `identity.json` bodies of the own identity at one version (Switch spec 4.3).
    Equivocation {
        /// The version.
        version: u64,
    },
    /// An own `identity.json` that goes back, or lists again an App ID an earlier version
    /// listed in `removed` (Switch spec 4.3).
    IdentityRollback {
        /// The rule the document broke.
        reason: String,
    },
    /// A registration of this app that neither it nor one of its devices made: a copy of
    /// its signing key is in someone else's hands (Switch spec 3.6). The app leaves at once
    /// and asks the signer to revoke it from `distrust_from`.
    Compromise {
        /// The registration's `n`.
        n: u64,
        /// The `distrust_from` the app asks the signer for: the service time at which the
        /// registration was accepted, from its chain item. Learned of without that item, from
        /// a `409 conflict` or a directory, the later of the service times of the newest
        /// chain item the app verified and of its own last registration (Switch spec 3.6).
        /// `None` only when the app holds neither.
        distrust_from: Option<u64>,
    },
    /// A time signed by the service key that is earlier than one the app verified before
    /// (Switch spec 10.1).
    ServiceTimeBackwards {
        /// The highest time verified before, in Unix milliseconds.
        highest: u64,
        /// The earlier time now signed.
        signed: u64,
    },
}

impl std::fmt::Display for Alarm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Alarm::Rollback { reason } => write!(f, "rollback or fork: {reason}"),
            Alarm::Equivocation { version } => {
                write!(
                    f,
                    "equivocation: two identity.json bodies at version {version}"
                )
            }
            Alarm::IdentityRollback { reason } => write!(f, "identity.json rollback: {reason}"),
            Alarm::Compromise { n, .. } => {
                write!(
                    f,
                    "compromise: receive key n={n} registered by no device of this app"
                )
            }
            Alarm::ServiceTimeBackwards { highest, signed } => {
                write!(f, "the service signed time {signed} after {highest}")
            }
        }
    }
}

/// A rule of the app layer that refuses a call (nothing was sent or changed).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The app stopped on an alarm; it makes no further reads or writes.
    Stopped,
    /// The app left its identity (Switch spec 12.3) or was removed from it.
    Left,
    /// The app isn't current any more, or its account is gone (Switch spec 12.2, 12.7): it
    /// reads and writes nothing more.
    Gone,
    /// The approval doesn't pass the app's checks (Switch wire 3.10); the text names the
    /// step.
    Approval(String),
    /// The store holds no app with this App ID.
    NotJoined,
    /// After a restore the user hasn't yet answered whether the app ran on this device after
    /// the backup (Switch spec 12.4).
    RestoreQuestionOpen,
    /// The call doesn't apply now: the text says why.
    NotNow(String),
    /// A value the protocol or the host gave breaks a rule: the text names it.
    Usage(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Stopped => f.write_str("the app stopped on an alarm"),
            Refusal::Left => f.write_str("the app left its identity or was removed"),
            Refusal::Gone => f.write_str("the app isn't current any more, or its account is gone"),
            Refusal::Approval(why) => write!(f, "approval refused: {why}"),
            Refusal::NotJoined => f.write_str("no app with this App ID in the store"),
            Refusal::RestoreQuestionOpen => {
                f.write_str("the user hasn't answered the restore question yet")
            }
            Refusal::NotNow(why) => write!(f, "not now: {why}"),
            Refusal::Usage(why) => write!(f, "usage: {why}"),
        }
    }
}

/// A failure of the app layer.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum AppError {
    /// An answer of the switch, or a check of the base client, that failed. A `409
    /// conflict` and the like arrive here; the app decided what to do with it.
    #[error(transparent)]
    Switch(ClientError),
    /// The request didn't reach the switch, or its answer didn't come back; it is resent
    /// with the same bytes.
    #[error(transparent)]
    Transport(TransportError),
    /// The host store failed. After [`StoreError::Unknown`] the app reads its state again
    /// before it goes on.
    #[error(transparent)]
    Store(StoreError),
    /// Data from the network or the store that doesn't verify or doesn't read: the text
    /// names the rule.
    #[error("invalid data: {0}")]
    InvalidData(String),
    /// An alarm: the app stopped (Switch spec 3.6, 4.3, 10.1).
    #[error("alarm: {0}")]
    Alarm(Alarm),
    /// A rule of the app layer refused the call.
    #[error("refused: {0}")]
    Refused(Refusal),
}

impl AppError {
    /// The error code of an answer of the switch.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            AppError::Switch(error) => error.code(),
            _ => None,
        }
    }
}

/// Whether the switch refused these exact bytes for good, so that sending them again can't
/// pass (Switch spec 6.4): the Retry column says "No", or allows the call only once it is
/// built again (after re-reading, with the key bundle, signed again or sealed again). Every
/// other failure may pass with the same bytes later: `429`, `503`, `401 stale_timestamp`
/// (the request is signed again, the body isn't), `409 identity_needed`, `410 moved`, a
/// transport failure, or an answer whose signature didn't verify or that didn't read, which
/// may not be the service's (Switch wire 2.1, 7.1).
/// Whether a refusal for good of a batch sent again shows that the batch was never applied:
/// only an answer the service makes at or after its batch ID lookup (Switch wire 6.4 step
/// 5) does, since a batch whose ID it holds is answered there, by its original proofs or
/// `409 conflict`, before any later check. By the step order of Switch wire 6.4:
///
/// - **At or after the lookup:** `409 conflict` (step 5, or a condition or rule at steps 8
///   and 9), `409 stale_generation` (step 6), `403 permission_missing` (step 9), `409
///   stale_epoch` (a sealed field's rule, step 9), `429 quota_exceeded` (step 9).
/// - **Before it, so they tell nothing:** what authentication answers (Switch wire 7.1, 7.2:
///   `401 bad_signature`, `401 stale_timestamp`, `403 not_current`, `403 cert_expired`,
///   `410 moved`, `503 staged`), `403 not_admitted` (step 1), `400` (steps 2 to 4),
///   `413 too_large` (step 2), `401 bad_signature` (step 3).
///
/// `400` and `413 too_large` can also come from step 9 (a field's shape, a record value's
/// size); they are taken as before the lookup, which keeps the batch rather than risk
/// building it twice. Every other code is taken so too.
pub(crate) fn refused_after_lookup(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::Conflict
            | ErrorCode::StaleGeneration
            | ErrorCode::PermissionMissing
            | ErrorCode::StaleEpoch
            | ErrorCode::QuotaExceeded
    )
}

pub(crate) fn refused_for_good(error: &AppError) -> Option<ErrorCode> {
    let AppError::Switch(ClientError::Switch { code, .. }) = error else {
        return None;
    };
    match code.retry() {
        Retry::No
        | Retry::AfterReread
        | Retry::AfterKeyBundle
        | Retry::AfterResigning
        | Retry::AfterResealing => Some(*code),
        Retry::WithNewTimestamp
        | Retry::AfterDeliveringIdentity
        | Retry::AtNextService
        | Retry::AfterRetryAfter
        | Retry::WhenLimitFrees
        | Retry::Yes => None,
    }
}

impl From<ClientError> for AppError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Transport(error) => AppError::Transport(error),
            other => AppError::Switch(other),
        }
    }
}

impl From<TransportError> for AppError {
    fn from(error: TransportError) -> Self {
        AppError::Transport(error)
    }
}

impl From<StoreError> for AppError {
    fn from(error: StoreError) -> Self {
        AppError::Store(error)
    }
}

impl From<BatchError> for AppError {
    fn from(error: BatchError) -> Self {
        AppError::Store(StoreError::Other(error.to_string()))
    }
}

impl From<pubky_switch_core::Error> for AppError {
    fn from(error: pubky_switch_core::Error) -> Self {
        AppError::InvalidData(error.to_string())
    }
}

impl From<Refusal> for AppError {
    fn from(refusal: Refusal) -> Self {
        AppError::Refused(refusal)
    }
}

impl From<Alarm> for AppError {
    fn from(alarm: Alarm) -> Self {
        AppError::Alarm(alarm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_switch_core::chain::ChainError;

    #[test]
    fn test_app_error_maps_client_failures() {
        let transport: AppError = ClientError::Transport(TransportError::Timeout).into();
        assert_eq!(transport, AppError::Transport(TransportError::Timeout));
        let unpinned: AppError = ClientError::Unpinned.into();
        assert!(matches!(unpinned, AppError::Switch(ClientError::Unpinned)));
        assert_eq!(unpinned.code(), None);
        let chain: AppError = ClientError::Chain(ChainError::Proof("x".into())).into();
        assert!(matches!(chain, AppError::Switch(ClientError::Chain(_))));
    }

    fn answer(code: ErrorCode) -> AppError {
        AppError::Switch(ClientError::Switch {
            status: code.status(),
            code,
            message: String::new(),
            current: serde_json::Value::Null,
            known_version: None,
            retry_after: None,
        })
    }

    #[test]
    fn test_refused_for_good_keeps_what_may_pass_unchanged() {
        for code in [
            ErrorCode::RateLimited,
            ErrorCode::QuotaExceeded,
            ErrorCode::Unavailable,
            ErrorCode::Staged,
            ErrorCode::StaleTimestamp,
            ErrorCode::IdentityNeeded,
            ErrorCode::Moved,
        ] {
            assert_eq!(refused_for_good(&answer(code)), None, "{code}");
        }
        for code in [
            ErrorCode::BadRequest,
            ErrorCode::PermissionMissing,
            ErrorCode::NotCurrent,
            ErrorCode::Conflict,
            ErrorCode::StaleEpoch,
            ErrorCode::StaleGeneration,
            ErrorCode::TooLarge,
        ] {
            assert_eq!(refused_for_good(&answer(code)), Some(code), "{code}");
        }
        for error in [
            AppError::Switch(ClientError::BadServiceSignature { status: 502 }),
            AppError::Switch(ClientError::InvalidResponse("x".into())),
            AppError::Transport(TransportError::Timeout),
        ] {
            assert_eq!(refused_for_good(&error), None, "{error:?}");
        }
    }

    #[test]
    fn test_alarm_text_names_the_rule_only() {
        let alarm = Alarm::Compromise {
            n: 3,
            distrust_from: Some(5),
        };
        assert_eq!(
            alarm.to_string(),
            "compromise: receive key n=3 registered by no device of this app"
        );
        assert!(
            AppError::Alarm(Alarm::Equivocation { version: 2 })
                .to_string()
                .contains("version 2")
        );
        assert!(
            AppError::Refused(Refusal::Stopped)
                .to_string()
                .contains("stopped")
        );
    }
}
