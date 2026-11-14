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
    /// A restore in place ([`super::App::restore`]) would carry more of what the store
    /// still owes its protocol than one commit takes beside the backup, which fits on its
    /// own: the duty events not acknowledged and the protocol calls owed, counted here.
    /// Nothing was written. The host acknowledges the duty events it has acted on
    /// ([`super::App::ack_events`]) through the app loaded on that store, lets the protocol
    /// answer the owed calls, or restores onto an empty store, then restores again. If the
    /// store can't be loaded, the host clears the app's namespace itself and restores onto
    /// the empty store: no API of the app does that for it.
    CarriedTooLarge {
        /// The duty events the restore would carry.
        duty_events: u64,
        /// The owed protocol calls it would carry.
        owed_calls: u64,
    },
    /// [`super::App::queue_stored`] queued nothing: the message can no longer be delivered
    /// safely, or no longer fits. Nothing was written and no event raised.
    WontDeliver(WontDeliver),
    /// A write waits behind batches kept from earlier calls, which a write sends again
    /// first, one per call, and none of which it overtakes: its own batch is kept unsent
    /// behind them ([`AppError::Kept`]), to go after them. The host reads
    /// ([`super::App::receive`]), which sends the kept batches again oldest first, and finds
    /// its batch's fate with [`super::App::kept_batch`].
    KeptBatchesAhead(KeptAhead),
}

/// Why [`super::App::queue_stored`] queued nothing ([`Refusal::WontDeliver`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WontDeliver {
    /// Past the message's replay deadline, [`super::SENT_RETENTION_MS`] from its
    /// `created_at` less the clock tolerance, by the later of the device clock and a service
    /// time the app verified: a recipient that processed it may have forgotten the pair, and
    /// would process a copy as new (Switch spec 11).
    PastReplayWindow {
        /// The deadline, Unix milliseconds.
        until_ms: u64,
    },
    /// This app gave the message's delivery up already, and told the protocol so then
    /// ([`super::AppEvent::MessageUndelivered`]).
    GivenUp,
    /// Its outbox record is over the store's sizes.
    TooLarge,
}

/// The batch kept from an earlier call that a write waits behind ([`Refusal::KeptBatchesAhead`],
/// [`AppError::Ahead`]): the oldest, which goes first.
///
/// While its resend fails it blocks the batches behind it, since no write overtakes
/// another. That lasts at most until its answer window ends, [`super::KEPT_BATCH_ANSWER_MS`]
/// after its first send (`answer_until_ms`): past it no answer tells whether the switch
/// applied it, so it isn't sent again, and goes, reported with its attempts
/// ([`super::AppEvent::KeptBatchDropped`]). Until then a host waits, and reads. One never
/// sent has no window: it goes at its first send that the switch answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeptAhead {
    /// The oldest kept batch's ID ([`super::App::kept_batch`]).
    pub batch_id: [u8; 16],
    /// The time its first send was stamped at, service time in Unix milliseconds: at or
    /// before the send, and up to about a day before it, since a first send is stamped at a
    /// held service time while one under a day old is held (Switch spec 12.5 "Kept
    /// batches"). `None` while it was never sent.
    pub kept_since_ms: Option<u64>,
    /// When its answer window ends; `None` while it was never sent, which has no window.
    pub answer_until_ms: Option<u64>,
    /// How many batches are kept from earlier calls.
    pub kept: u64,
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
            Refusal::WontDeliver(WontDeliver::PastReplayWindow { until_ms }) => {
                write!(
                    f,
                    "not queued: past the message's replay deadline, {until_ms}"
                )
            }
            Refusal::WontDeliver(WontDeliver::GivenUp) => {
                f.write_str("not queued: the message's delivery was given up")
            }
            Refusal::WontDeliver(WontDeliver::TooLarge) => {
                f.write_str("not queued: the message's outbox record is over the store's sizes")
            }
            Refusal::KeptBatchesAhead(ahead) => match ahead.kept_since_ms {
                Some(since) => write!(
                    f,
                    "kept behind {} batches kept from earlier calls, the oldest first sent at {since}",
                    ahead.kept
                ),
                None => write!(
                    f,
                    "kept behind {} batches kept from earlier calls, the oldest never sent",
                    ahead.kept
                ),
            },
            Refusal::CarriedTooLarge {
                duty_events,
                owed_calls,
            } => write!(
                f,
                "the restore in place would carry {duty_events} duty events not acknowledged \
                 and {owed_calls} owed calls, more than one commit takes beside the backup"
            ),
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
    /// The protocol's own store failed in a callback the app must make, such as
    /// [`super::Protocol::provider_lost`]: the step waits, and the next call makes the
    /// callback again. The app's store didn't fail.
    #[error("the protocol's store failed: {}", .0.error())]
    Protocol(super::protocol::StoreFailure),
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
    /// The switch answers as for an account it doesn't host, an error its operator signed
    /// and the account's key didn't (an unsigned `404`), and the identity publishes no
    /// `identity.json`: the account may have been erased (Switch spec 12.7). Nothing
    /// authenticates an erasure, so the app waits: it takes the account as gone only once
    /// both hold at 5 tries at least 6 hours apart over 24 hours by its clock, then stops
    /// with [`super::AppEvent::AccountGone`]. Until then each read, and
    /// [`super::App::check_for_move`], counts a try and fails with this; `since_ms` is the
    /// first try of the wait, app clock. An answer the pinned key doesn't verify in any
    /// other case stays [`ClientError::BadServiceSignature`].
    ///
    /// It is an error, not a stopped read: nothing was read, and the app tries again at its
    /// next call, as for a service it can't reach. It is the app's own conclusion from the
    /// switch's answer, the Homeserver and the wait it keeps (`erasing`), so it is an
    /// [`AppError`], not a [`ClientError`], which only says what one answer showed.
    #[error("the switch doesn't answer as the account's, since {since_ms} (app clock)")]
    NotAnsweringAsAccount {
        /// The first try of the wait, app clock, in Unix milliseconds.
        since_ms: u64,
    },
    /// The call's own batch was signed and kept, and couldn't be settled now; `error` says
    /// why. Most often the network failed, or the switch answered `429`, `503`, `410
    /// moved`, `401 stale_timestamp` or `409 identity_needed`, or an answer didn't verify;
    /// also a refusal about the caller met before the batch was sent, such as `403
    /// cert_expired` on the service time read first, an alarm, or a failed commit after the
    /// batch was kept. The app sends it again, the same bytes, before its next write and at
    /// the start of its next read ([`super::App::submit_batch`], [`super::App::receive`]),
    /// once nothing holds it back, and the switch answers a batch it applied with its
    /// original proofs (Switch wire 6.4 step 5), so the caller doesn't build it again: what
    /// the batch settles is committed when that answer comes.
    ///
    /// The store decides it: a call of [`super::App::submit_batch`] or
    /// [`super::App::write_claim`], or one that writes through them such as
    /// [`super::App::put_record`], fails with this exactly when its own batch is still kept
    /// under `opq/` when it returns. Any other error means the batch isn't kept: it was
    /// never signed or stored, a batch kept from an earlier call couldn't be sent first
    /// ([`AppError::Ahead`]), or it was refused for good and dropped. When the store can't
    /// be read to tell, the call fails with that store error, bare: whether the batch is
    /// kept can't be told then, and a kept one goes again with the next write or read.
    /// Other calls keep their own signed artifacts elsewhere and may fail bare after keeping
    /// one: [`super::App::rotate`] its receive key registration, a join its batch, and the
    /// delivery of the app record its batch; each is sent again by itself (`STATE.md`).
    /// [`AppError::code`] and [`AppError::unkept`] see through this variant.
    #[error("the batch is kept, to be sent again: {error}")]
    Kept {
        /// The batch's ID, under which it is kept.
        batch_id: [u8; 16],
        /// Why it couldn't be settled now.
        error: Box<AppError>,
    },
    /// A write's resend of the oldest batch kept from an earlier call failed with `error`,
    /// on the network or the switch, other than `410 moved`: nothing of the write was kept
    /// or sent, since no write overtakes a kept batch. `ahead` names that batch and how long
    /// it has been kept ([`KeptAhead`]).
    /// [`AppError::code`] and [`AppError::unkept`] see through this variant.
    #[error("a batch kept from an earlier call is ahead and couldn't be sent: {error}")]
    Ahead {
        /// The kept batch ahead.
        ahead: KeptAhead,
        /// Why its resend failed.
        error: Box<AppError>,
    },
}

impl AppError {
    /// The error code of an answer of the switch, also of one that left the call's batch
    /// kept ([`AppError::Kept`]).
    pub fn code(&self) -> Option<ErrorCode> {
        match self.unkept() {
            AppError::Switch(error) => error.code(),
            _ => None,
        }
    }

    /// The error, without the [`AppError::Kept`] or [`AppError::Ahead`] around it.
    pub fn unkept(&self) -> &AppError {
        match self {
            AppError::Kept { error, .. } | AppError::Ahead { error, .. } => error.unkept(),
            other => other,
        }
    }

    /// The ID of the call's own batch, when the call kept it ([`AppError::Kept`]).
    pub fn kept_batch(&self) -> Option<[u8; 16]> {
        match self {
            AppError::Kept { batch_id, .. } => Some(*batch_id),
            _ => None,
        }
    }

    /// `error` of a call whose own batch `batch_id` was kept, given whether the store still
    /// keeps it: [`AppError::Kept`] when it does, `error` as it is when it doesn't.
    pub(crate) fn kept_or(batch_id: [u8; 16], error: AppError, still_kept: bool) -> AppError {
        if still_kept {
            AppError::Kept {
                batch_id,
                error: Box::new(error),
            }
        } else {
            error
        }
    }
}

/// Where the service made a refusal for good of a batch sent again (Switch wire 6.4), which
/// decides what the refusal tells of the batch. A batch whose ID the service holds is
/// answered at the batch ID lookup (step 5), by its original proofs or `409 conflict`,
/// before any later check; what comes before that lookup tells nothing of whether it was
/// applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RefusalPlace {
    /// At or after the batch ID lookup: the batch was never applied. `409 conflict` (step
    /// 5, or a condition or rule at steps 8 and 9), `409 stale_generation` (step 6), `403
    /// permission_missing` (step 9), `409 stale_epoch` (a sealed field's rule, step 9),
    /// `429 quota_exceeded` (step 9).
    AfterLookup,
    /// Before the lookup, about the caller: every request the app sends gets it until
    /// something outside the batch changes, so it tells nothing of the batch, which stays
    /// kept, the same bytes, and is handled as the same answer to any request.
    /// Authentication's `401 bad_signature`, `401 stale_timestamp`, `403 not_current`, `403
    /// cert_expired`, `410 moved` and `503 staged` (Switch wire 7.2, 7.3), and `403
    /// not_admitted` (step 1, a caller of another identity, decided from the request's
    /// identity and the account, not from the batch). `410 moved` is the one of these that
    /// lets feed reads go on (Switch wire 7.3 step 8); that is fine: during a freeze every
    /// write is refused, the cursor move included, so the feed can't advance at that
    /// service with or without a kept effect in front of it, and stopping the read at the
    /// `410` and having the move carry the effect across loses nothing.
    ///
    /// `401 stale_timestamp`, `410 moved` and `503 staged` are listed for completeness: they
    /// never reach [`refused_at`], since [`refused_for_good`] leaves them out (their Retry is
    /// not "No"), and they are retried as any transient answer is, the batch kept as it is.
    Caller,
    /// Before the lookup, about these bytes: the same bytes get the same answer, so the
    /// batch is never answered and is handled at once as one kept past the window: an
    /// effect's entry stored as uncertain, a batch dropped with its attempts. It is
    /// uncertain, not refused: a batch applied under an earlier service can be refused for
    /// its shape by a later one. `400` (steps 2 to 4), `413 too_large` (step 2), and every
    /// code not classified above.
    ///
    /// `400`, `413 too_large` and `404 not_found` also come from step 9, an operation's
    /// shape or its rules (an invite code not held), after the lookup, which would prove the
    /// batch never applied. The answer can't tell them apart from the request's: its body
    /// is the code, a message that isn't normative, and `current`, which none of them
    /// carries, with no operation named (Switch wire 7.6). So they are taken as before the
    /// lookup, the weaker reading: the entry is stored as uncertain where it was in fact
    /// refused.
    ///
    /// Step 9 also answers about the bytes with codes this takes as about the caller: `401
    /// bad_signature` for a `key_bundle.put` bundle, for an `app.put` record and for a
    /// `receive_key.put` record that don't verify, and `403 not_current` for an `app.put`
    /// whose certificate isn't the one `identity.json` lists. A `key_bundle.put` never
    /// reaches an app's batch: it is the signer's, and step 9 checks permission (`403
    /// permission_missing`) before shape. The caller's own `app.put` is checked at
    /// authentication, before the lookup, where such a refusal is about the caller: any
    /// batch carrying it is authenticated against that record, the batch's first `app.put`
    /// naming the caller (Switch wire 7.2, 6.4 step 7). The app's own `app.put` and
    /// `receive_key.put` go in batches of their own, sent again by their own steps
    /// (joining, the record's delivery, a registration, a move's or a loss's
    /// re-registration), never through a kept effect or a kept batch, whose answers this
    /// classifies. A protocol's effect and a host's batch may carry none of them
    /// (`refuse_lifecycle_ops`), which is what makes [`RefusalPlace::Caller`] safe until
    /// the wire's answers name the operation: otherwise one refused at step 9 would be held
    /// here as about the caller until the window ends.
    Bytes,
}

/// The place of a refusal for good of a batch sent again ([`RefusalPlace`]).
pub(crate) fn refusal_place(code: ErrorCode) -> RefusalPlace {
    match code {
        ErrorCode::Conflict
        | ErrorCode::StaleGeneration
        | ErrorCode::PermissionMissing
        | ErrorCode::StaleEpoch
        | ErrorCode::QuotaExceeded => RefusalPlace::AfterLookup,
        ErrorCode::BadSignature
        | ErrorCode::StaleTimestamp
        | ErrorCode::NotCurrent
        | ErrorCode::CertExpired
        | ErrorCode::Moved
        | ErrorCode::Staged
        | ErrorCode::NotAdmitted => RefusalPlace::Caller,
        _ => RefusalPlace::Bytes,
    }
}

/// The place of an error that refuses a batch for good; `None` for any other error.
pub(crate) fn refused_at(error: &AppError) -> Option<RefusalPlace> {
    refused_for_good(error).map(refusal_place)
}

/// Whether `error` says the request never left: the transport made no connection, or
/// refused the origin ([`TransportError::Connect`], [`TransportError::Refused`]). Any other
/// failure may have reached the switch.
pub(crate) fn never_left(error: &AppError) -> bool {
    matches!(
        error.unkept(),
        AppError::Transport(TransportError::Connect(_) | TransportError::Refused(_))
    )
}

/// Whether the switch refused these exact bytes for good, so that sending them again can't
/// pass (Switch spec 6.4): the Retry column says "No", or allows the call only once it is
/// built again (after re-reading, with the key bundle, signed again or sealed again). Every
/// other failure may pass with the same bytes later: `429`, `503`, `401 stale_timestamp`
/// (the request is signed again, the body isn't), `409 identity_needed`, `410 moved`, a
/// transport failure, or an answer whose signature didn't verify or that didn't read, which
/// may not be the service's (Switch wire 2.1, 7.1).
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
        AppError::Store(error.into())
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
