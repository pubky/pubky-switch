//! Following the own identity to another service (Switch spec 12.5), and the app's view of
//! revocation and erasure (Switch spec 12.2, 12.7). A provider loss is `recovery.rs`'s.
//!
//! The app follows the service its newest own `identity.json` names. Each step is kept in
//! one record, committed before the step's network effect and again after its outcome, so a
//! crash resumes at the step it stopped in (`STATE.md`, "Moves, recovery and push"):
//!
//! - **A cooperative move** (Switch spec 12.5). The app learns of the freeze from a feed
//!   page, a `410 moved` answer or the public read of `identity.json`, verifies it with the
//!   identity key, and pins the next service's key it names. It reads the old feed to its
//!   end, checking the chain only: the frozen service takes no write, so nothing there is
//!   processed, and the next service shows the same items again. It uploads its newest head
//!   and the evidence it keeps to the staged next service, presenting its certificate. Once
//!   `identity.json` names the next service, the app switches its client there and carries
//!   its chain view and cursor across, since the next service continues the sequence and
//!   the chain under the next generation. It reads its own entry in the next directory,
//!   re-registers its record and current receive key at the new generation, uploads the old
//!   service's proofs again, and compares the admission lists with its own copy. A
//!   cancelled freeze (the old service's public read carries none) ends the move.
//! - **A key change in place**, or a move the app never saw frozen, is followed the same way
//!   from the switch on.
//! - **Revocation and erasure.** An own `identity.json` that lists the app in `removed`, or a
//!   `403 not_current` answer from the service and generation the newest one names, while
//!   it doesn't list the app with another certificate, means the app isn't current. A `404`
//!   that the account's key didn't sign, while the identity publishes no `identity.json`,
//!   held at [`ERASURE_TRIES`] tries spread over [`ERASURE_WAIT_MS`], means its account is
//!   gone. The app keeps that, stops and reports it; an erased account seen alive again
//!   comes back.

use pubky_switch_core::claims::ClaimType;
use pubky_switch_core::enc::{b64, pubky_id, pubky_key, serde_b64, serde_b64_vec};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{AllowKind, Condition, MAX_BATCH_ENTRIES, OpBody, OpKind, Position};
use pubky_switch_core::records::{DAY_MS, Freeze, IdentityDoc, Inbox};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};

use super::error::{Alarm, AppError};
use super::events::{AppEvent, Duty};
use super::feed::{ReceiveReport, processed_writes};
use super::identity;
use super::kept::{Ended, KeptBatchDrop};
use super::state::{Tx, key};
use super::{App, OpBatch, push};
use crate::client::answers::{FeedQuery, RecoveryUpload};
use crate::client::{Batch, Credentials, SwitchClient};
use crate::error::{ClientError, StoreError};

/// The keys of this part's records (`STATE.md`, "Moves, recovery and push").
pub(crate) mod keys {
    use super::{b64, key, pubky_id};

    /// A move in progress.
    pub(crate) const MOVE: &str = "mv";
    /// The app isn't current any more, or its account is gone.
    pub(crate) const GONE: &str = "gone";
    /// Since when every try has met an unsigned `404` and no `identity.json`.
    pub(crate) const ERASING: &str = "erasing";

    /// The service and last own `identity.json` of a generation the app left.
    pub(crate) fn generation(generation: u64) -> String {
        format!("gens/{}", key::num(generation))
    }

    /// A contact in the app's copy of the lists.
    pub(crate) fn contact(pubky: &[u8; 32]) -> String {
        format!("lc/contact/{}", pubky_id(pubky))
    }

    /// A deny list entry in the app's copy of the lists.
    pub(crate) fn deny(pubky: &[u8; 32]) -> String {
        format!("lc/deny/{}", pubky_id(pubky))
    }

    /// An invite code this app registered.
    pub(crate) fn code(code_hash: &[u8; 32]) -> String {
        format!("lc/code/{}", b64(code_hash))
    }
}

/// `gens/<generation>`: the service of a generation the app left, and its last own
/// `identity.json` there, when the app took one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GenerationRecord {
    pub(crate) origin: String,
    #[serde(with = "serde_b64")]
    pub(crate) service_key: [u8; 32],
    pub(crate) doc: Option<SignedDoc>,
}

/// The steps of following a move, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum MoveStep {
    /// The freeze is verified and kept.
    Seen,
    /// The old feed was read to its end.
    Read,
    /// The evidence went to the next service; the app waits for `identity.json` to name it.
    Uploaded,
    /// The app follows the next service; its re-registration batch is kept.
    Switched,
    /// Re-registered; the checks after the move are left.
    Registered,
}

/// `mv`: a move in progress (Switch spec 12.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MoveRecord {
    /// The signed freeze; `None` for a move the app never saw frozen, or a key change.
    pub(crate) freeze: Option<SignedDoc>,
    /// The generation moved from.
    pub(crate) from_generation: u64,
    pub(crate) step: MoveStep,
    /// The re-registration batch, signed once at the switch.
    #[serde(with = "serde_b64_vec", default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) batch: Vec<u8>,
}

/// Why the app stopped for good.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum GoneReason {
    /// Revoked, departed, or removed from `identity.json` (Switch spec 12.2).
    NotCurrent,
    /// The account was erased (Switch spec 12.7).
    Erased,
}

/// How long an unsigned `404` and a missing `identity.json` must both hold, at every try,
/// before the app takes its account as erased (Switch spec 12.7): nothing authenticates an
/// erasure, and a Homeserver fault can read as a missing file.
pub(crate) const ERASURE_WAIT_MS: u64 = DAY_MS;

/// How many tries must meet an erased account, each at least [`ERASURE_TRY_SPACING_MS`]
/// after the one counted before, so the wait spans [`ERASURE_WAIT_MS`] at the least. No
/// answer in the wait carries a time any key vouches for, so the app's clock is the only
/// measure: spread over separate tries, one forward jump of it counts one try, never the
/// whole wait.
pub(crate) const ERASURE_TRIES: u32 = 5;

/// The least time, app clock, between two tries the erasure wait counts.
pub(crate) const ERASURE_TRY_SPACING_MS: u64 = ERASURE_WAIT_MS / 4;

/// `erasing`: since when, app clock, every try has met an unsigned `404` and no
/// `identity.json`, and the tries counted (Switch spec 12.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ErasingRecord {
    /// The first try, app clock.
    pub(crate) since_ms: u64,
    /// The last try counted, app clock.
    pub(crate) last_ms: u64,
    /// The tries counted.
    pub(crate) tries: u32,
}

/// `gone`: the app isn't current any more, or its account is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GoneRecord {
    pub(crate) reason: GoneReason,
    /// When the app found out, app clock.
    pub(crate) at_ms: u64,
}

/// Where following the own identity's service stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderStatus {
    /// The app follows the service its `identity.json` names; nothing to do.
    Current,
    /// The account is frozen for a move: the app uploaded its evidence and waits until
    /// `identity.json` names the next service (Switch spec 12.5 steps 2 to 4).
    AwaitingMove {
        /// The generation the freeze names.
        next_generation: u64,
    },
    /// The app followed a move, a key change or a provider loss, and reads at the service
    /// of this generation now.
    Followed {
        /// The generation.
        generation: u64,
    },
    /// The freeze was cancelled: the app stays at its service (Switch spec 12.5 "Abort").
    MoveCancelled,
    /// The app isn't current any more, or its account is gone (Switch spec 12.2, 12.7).
    Gone,
}

/// What `receive` does after a read (`feed.rs`).
pub(crate) enum TakeOver {
    /// This is the read's result.
    Done(Result<ReceiveReport, AppError>),
    /// A move or a provider change was followed: read once more, at the service followed.
    ReadAgain,
}

/// What a `404` the account's key didn't sign means.
enum Unknown {
    /// The account is gone.
    Gone,
    /// The identity names another service now.
    Moved,
    /// The account may be erased: the wait goes on, since the first such try (app clock).
    Waiting(u64),
    /// Nothing the app can tell.
    Unexplained,
}

/// How a provider change carries the batches kept for the generation left
/// ([`App::carry_kept_writes`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Carry {
    /// A cooperative move whose old feed the app read to its end: its chain tells.
    ReadToEnd,
    /// A move never seen frozen, or a key change in place: kept batches go again unchanged
    /// first (Switch spec 12.5 "Kept batches").
    ResendFirst,
    /// A provider loss (Switch spec 12.6).
    AfterLoss,
}

/// How long after it was kept a batch's resend still tells whether it was applied. The
/// service keeps a batch's proofs `batch_proofs_ms`, 30 days from when it applied the batch
/// (Switch wire 6.4 step 5, 9): a retry within that time gets them back, and after it a
/// retry gets `409 conflict`, which then can't be told from a condition that failed, and an
/// ID forgotten takes the same bytes as new. The window ends [`KEPT_BATCH_MARGIN_MS`]
/// before those 30 days from when the app kept the batch, before its first send.
pub const KEPT_BATCH_ANSWER_MS: u64 =
    pubky_switch_core::ops::BATCH_PROOFS_MS - KEPT_BATCH_MARGIN_MS;

/// How much sooner than the service's 30 days a kept batch's window ends. A resend sent just
/// inside the window, measured at the later of the device clock and a verified service
/// time, reaches the service within the device clock's tolerance of the service's (5
/// minutes, the clock tolerance), plus the 5 minutes a request's signed time is accepted for
/// (Switch wire 7.1), after the app kept it, and the service applied it no sooner than the
/// app kept it: some 20 minutes in the worst case. An hour leaves room past that.
pub const KEPT_BATCH_MARGIN_MS: u64 = 60 * 60 * 1000;

/// Whether a resend of a batch kept at `kept_ms` still tells whether it was applied, at
/// `now`: kept less than [`KEPT_BATCH_ANSWER_MS`] ago. `None` is a batch never sent, whose
/// resend can't tell: it counts as too old.
pub(crate) fn answer_decides(now: u64, kept_ms: Option<u64>) -> bool {
    kept_ms.is_some_and(|at| now.saturating_sub(at) < KEPT_BATCH_ANSWER_MS)
}

impl App {
    /// The time a batch's first send is stamped at: the earlier of the device clock and the
    /// highest service time verified with the current service key, which every path makes
    /// sure of first, before a kept batch's first send and before an effect is kept
    /// ([`App::stamp_service_time`]), so a device clock ahead doesn't make it look younger,
    /// and a time from long before doesn't make it look older.
    pub(crate) fn kept_stamp(&self) -> u64 {
        let now = self.now();
        self.state
            .service_time
            .map_or(now, |time| now.min(time.highest_ms))
    }

    /// A verified service time to stamp a first send with ([`App::kept_stamp`]). None is
    /// read when the app holds one of the current service key that is recent by the device
    /// clock ([`RECENT_SERVICE_TIME_MS`]).
    ///
    /// The stamp must be at or before the time the service applies the batch, so that the
    /// kept copy's window never outlasts the service's memory of the batch ID
    /// ([`KEPT_BATCH_ANSWER_MS`]). It is: the service's stamped time never goes back
    /// (Switch wire 7.3), so the time the key stamps the batch at is no earlier than the
    /// highest time the app verified with that key, fresh or not. The age of the held time
    /// only bounds how much sooner than needed the window ends. Without such a time (none
    /// held, one of another key, or an older one) the app reads one
    /// ([`App::fresh_service_time`]); a time an answer of the same call brought counts,
    /// and a change of service starts the call's count again. A service whose stamped time
    /// went back below the held time breaks that rule: the batch then goes once at a stamp
    /// later than its apply time, and its answer raises the alarm that stops the app
    /// ([`super::Alarm::ServiceTimeBackwards`]).
    ///
    /// # Errors
    ///
    /// The read's: nothing is stamped or sent.
    pub(crate) async fn stamp_service_time(&mut self) -> Result<(), AppError> {
        let now = self.now();
        let key = self.state.meta.service_key;
        let recent = self.state.service_time.is_some_and(|held| {
            held.key == key && now.saturating_sub(held.highest_ms) <= RECENT_SERVICE_TIME_MS
        });
        if recent {
            return Ok(());
        }
        self.fresh_service_time().await
    }

    /// A service time verified in this call, before a kept batch's age is judged: a read of
    /// a feed page with no items (Switch wire 7.4.4), a small signed answer that moves no
    /// position, when no answer of this call brought a time within
    /// [`FRESH_SERVICE_TIME_MS`] on the device clock ([`App::kept_window_now`]).
    ///
    /// # Errors
    ///
    /// The read's: the age isn't judged, and the kept batch stays as it is.
    pub(crate) async fn fresh_service_time(&mut self) -> Result<(), AppError> {
        let now = self.now();
        let fresh = self
            .time_fresh_at
            .is_some_and(|at| now >= at && now - at <= FRESH_SERVICE_TIME_MS);
        if fresh {
            return Ok(());
        }
        let query = crate::client::answers::FeedQuery {
            after: Some(Position {
                generation: self.state.cursor.generation,
                seq: self.state.cursor.seq,
            }),
            limit: Some(0),
            wait: None,
        };
        let result = self.client.feed(query).await;
        self.take(result).await?;
        Ok(())
    }

    /// The time a kept batch's age is measured at: the later of the device clock and the
    /// highest service time the app verified, in this call before any resend
    /// ([`App::fresh_service_time`]), so a device clock set back doesn't hold the window
    /// open (Switch spec 12.5 "Kept batches").
    pub(crate) fn kept_window_now(&self) -> u64 {
        let verified = self.state.service_time.map_or(0, |time| time.highest_ms);
        self.now().max(verified)
    }

    /// Whether a resend of a batch kept at `kept_ms` still tells whether it was applied,
    /// now ([`answer_decides`], at [`App::kept_window_now`]).
    pub(crate) fn answer_decides(&self, kept_ms: Option<u64>) -> bool {
        answer_decides(self.kept_window_now(), kept_ms)
    }
}

/// How long, by the device clock, a service time verified in a call counts as fresh for
/// judging a kept batch's age ([`App::fresh_service_time`]); a device clock gone back since
/// it came counts as not fresh. The window ends an hour before the service's 30 days, and
/// the worst case of the clocks and a request's accepted time takes some 20 minutes of it
/// ([`KEPT_BATCH_MARGIN_MS`]): 10 minutes between the reading and the send leaves half an
/// hour. A known limit: a device clock stepped back by about the length of a suspend
/// between the reading and the send, and left more than about 45 minutes behind true time,
/// still passes this test, since the device clock is all it measures the gap by.
pub(crate) const FRESH_SERVICE_TIME_MS: u64 = 10 * 60 * 1000;

/// How old, by the device clock, the highest service time verified with the current key may
/// be for a first send to be stamped without reading another
/// ([`App::stamp_service_time`]): a day. The stamp is at most that much before the true
/// time, so the kept copy's window ([`KEPT_BATCH_ANSWER_MS`]) ends at most a day sooner
/// than it could, of its 30 days.
pub(crate) const RECENT_SERVICE_TIME_MS: u64 = 24 * 60 * 60 * 1000;

/// How many provider changes one follow takes in a row, each given up for a newer own
/// `identity.json` met on the way; the next call goes on from there.
const FOLLOW_PASSES: usize = 4;

fn corrupt() -> AppError {
    AppError::Store(StoreError::Corrupt)
}

/// The own `attempt`s a batch carries.
pub(crate) fn attempts_in(batch: &Batch) -> Vec<super::events::ClaimAttempt> {
    batch
        .ops()
        .iter()
        .filter_map(|op| match &op.body().kind {
            OpKind::Claim(fields) if fields.kind == ClaimType::Attempt => fields.check().ok(),
            _ => None,
        })
        .map(|entry| super::events::ClaimAttempt {
            claim_key: entry.claim_key,
            attempt_id: entry.attempt_id,
        })
        .collect()
}

/// A kept batch's operations, with their conditions, to sign again.
pub(crate) fn ops_of(batch: &Batch) -> Vec<(Vec<Condition>, OpKind)> {
    batch
        .ops()
        .iter()
        .map(|op| (op.body().conditions.clone(), op.body().kind.clone()))
        .collect()
}

impl App {
    // ---------------------------------------------------------------------------------
    // Public calls

    /// Follow the own identity's service as far as it goes now (Switch spec 12.5, 12.6): a
    /// move in progress, a provider change the newest own `identity.json` shows, or a
    /// recovery left half done. [`App::receive`] does this itself; a host calls it when it
    /// wants the follow without a read.
    ///
    /// # Errors
    ///
    /// [`super::Refusal::Stopped`] or [`super::Refusal::Left`]; an alarm a step raised; a
    /// failed call or commit, after which the next call resumes at the step it stopped in.
    pub async fn follow_provider(&mut self) -> Result<ProviderStatus, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_halted()?;
            let result = self.provider_step().await;
            if result.is_err() {
                self.reload = true;
            }
            result
        })
        .await
    }

    /// Ask the own service's public read of `identity.json` whether the account is frozen
    /// (Switch wire 7.4.15), and follow a move it shows. The freeze is verified with the
    /// identity key.
    ///
    /// # Errors
    ///
    /// As [`App::follow_provider`]; [`AppError::InvalidData`] for a freeze that doesn't
    /// follow the generation the app follows; [`AppError::NotAnsweringAsAccount`] while the
    /// account may be erased, the try counted in the wait as a read's is (Switch spec 12.7).
    pub async fn check_for_move(&mut self) -> Result<ProviderStatus, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_halted()?;
            if self.state.gone.is_some() {
                // `gone` stops every read: nothing is asked.
                return self.follow_provider().await;
            }
            let result = self.client.public_identity().await;
            let public = match self.take(result).await {
                Ok(public) => public,
                // An answer the pinned key didn't sign is looked into as at a read: a try
                // of the erasure wait counts here too (Switch spec 12.7).
                Err(error @ AppError::Switch(ClientError::BadServiceSignature { status })) => {
                    self.reload_now().await?;
                    return match self.unknown_account(status).await? {
                        Unknown::Gone => Ok(ProviderStatus::Gone),
                        Unknown::Moved => self.follow_provider().await,
                        Unknown::Waiting(since_ms) => {
                            Err(AppError::NotAnsweringAsAccount { since_ms })
                        }
                        Unknown::Unexplained => Err(error),
                    };
                }
                Err(error) => return Err(error),
            };
            if let Some(freeze) = &public.freeze {
                self.note_freeze(freeze).await?;
            }
            self.follow_provider().await
        })
        .await
    }

    // ---------------------------------------------------------------------------------
    // Hooks of the read

    /// Run before a read: `Some` stops the read with that report.
    pub(crate) fn follow_provider_change(
        &mut self,
    ) -> crate::transport::BoxFuture<'_, Result<Option<ReceiveReport>, AppError>> {
        // Boxed, as `App::receive_inner` says.
        Box::pin(self.follow_provider_change_body())
    }

    async fn follow_provider_change_body(&mut self) -> Result<Option<ReceiveReport>, AppError> {
        match self.provider_step().await? {
            ProviderStatus::AwaitingMove { .. } | ProviderStatus::Gone => Ok(Some(ReceiveReport {
                stopped: true,
                cursor: self.cursor(),
                ..ReceiveReport::default()
            })),
            _ => Ok(None),
        }
    }

    /// After a read: follow what stopped it, once.
    pub(crate) async fn take_over(&mut self, result: Result<ReceiveReport, AppError>) -> TakeOver {
        match self.take_over_inner(result).await {
            Ok(over) => over,
            Err(error) => TakeOver::Done(Err(error)),
        }
    }

    async fn take_over_inner(
        &mut self,
        result: Result<ReceiveReport, AppError>,
    ) -> Result<TakeOver, AppError> {
        let error = match result {
            Ok(report) => {
                if report.stopped && self.provider_change_due().await? {
                    return Ok(TakeOver::ReadAgain);
                }
                return Ok(TakeOver::Done(Ok(report)));
            }
            Err(error) => error,
        };
        match &error {
            AppError::Switch(ClientError::Switch {
                code: ErrorCode::Moved,
                current,
                ..
            }) => {
                // Switch wire 7.6: `410 moved` carries the signed freeze.
                let freeze = self.freeze_in(current)?;
                self.reload_now().await?;
                self.note_freeze(&freeze).await?;
                Ok(TakeOver::ReadAgain)
            }
            AppError::Switch(ClientError::Switch {
                code: ErrorCode::NotCurrent,
                ..
            }) => {
                // Without a verified head the refusal came before the request verified: the
                // service holds no record of the app to check it with (Switch wire 7.1
                // "`Switch-Head` on refusals", 7.2 "Where an own app gets `403
                // not_current`"). That is an app never registered there, or one purged after
                // its revocation or departure: the newest identity.json tells them apart.
                let unverified = self.client.latest_server_time().is_none();
                self.reload_now().await?;
                if self.state.leave.is_some() {
                    return Ok(TakeOver::Done(Err(error)));
                }
                // Switch wire 7.2 "How an own app reads it": final only from the service and
                // generation the newest identity.json names, and unless it lists the app with
                // another certificate than the one it holds, a renewal it takes before it
                // asks again. Listed in `removed` or not listed, it is revoked, departed or
                // dropped (Switch spec 12.2, 12.3), with the head or without. Listed with its
                // own, the head says the service counts it as revoked or departed; without
                // the head the service only holds no record of it: the read fails, and a
                // registration owed goes again at the next one. A service the identity has
                // left may say anything: the app follows the newer document instead.
                // Without a read of the Homeserver, the newest isn't known: the answer
                // stands for now.
                let identity = self.state.meta.identity;
                match identity::read_homeserver(self.env.homeserver.as_ref(), &identity).await {
                    Ok(Some(doc)) => {
                        self.take_own_copy(doc).await?;
                    }
                    Ok(None) => {}
                    Err(_) => return Ok(TakeOver::Done(Err(error))),
                }
                let meta = &self.state.meta;
                let doc = &self.state.own_doc;
                if doc.generation() > meta.generation
                    || doc.inbox() != &Inbox::new(&meta.origin, meta.service_key)
                {
                    return Ok(TakeOver::ReadAgain);
                }
                let me = self.state.meta.app_id;
                if !doc.lists_removed(&me)
                    && doc
                        .listed_cert(&me)
                        .is_some_and(|listed| listed != self.state.cert.hash())
                {
                    // The refusal says the switch holds a record under the listed
                    // certificate now: the next read looks for it in the directory, whenever
                    // it last looked.
                    self.renewal_looked_ms = None;
                    return Ok(TakeOver::Done(Err(error)));
                }
                if unverified
                    && !doc.lists_removed(&me)
                    && doc.listed_cert(&me) == Some(self.state.cert.hash())
                {
                    return Ok(TakeOver::Done(Err(error)));
                }
                self.mark_gone(GoneReason::NotCurrent).await?;
                Ok(TakeOver::Done(Ok(self.stopped_report())))
            }
            AppError::Switch(ClientError::BadServiceSignature { status }) => {
                // An answer the pinned key didn't sign: the account's key changed, or the
                // account is gone. The own identity.json tells.
                let status = *status;
                self.reload_now().await?;
                match self.unknown_account(status).await? {
                    Unknown::Gone => Ok(TakeOver::Done(Ok(self.stopped_report()))),
                    Unknown::Moved => Ok(TakeOver::ReadAgain),
                    Unknown::Waiting(since_ms) => {
                        Ok(TakeOver::Done(Err(AppError::NotAnsweringAsAccount {
                            since_ms,
                        })))
                    }
                    Unknown::Unexplained => Ok(TakeOver::Done(Err(error))),
                }
            }
            _ => Ok(TakeOver::Done(Err(error))),
        }
    }

    fn stopped_report(&self) -> ReceiveReport {
        ReceiveReport {
            stopped: true,
            cursor: self.cursor(),
            ..ReceiveReport::default()
        }
    }

    pub(crate) async fn reload_now(&mut self) -> Result<(), AppError> {
        self.reload = true;
        self.ready_local().await
    }

    /// Whether a stopped read has something to follow now, without waiting on anyone.
    async fn provider_change_due(&self) -> Result<bool, AppError> {
        let me = self.state.meta.app_id;
        if self.state.alarm.is_some() {
            return Ok(false);
        }
        if self.state.own_doc.lists_removed(&me) {
            return Ok(!self.reader().exists(keys::GONE).await?);
        }
        if self.state.own_doc.generation() > self.state.meta.generation {
            return Ok(true);
        }
        let reader = self.reader();
        if let Some(mv) = reader.get::<MoveRecord>(keys::MOVE).await? {
            return Ok(mv.step < MoveStep::Uploaded || mv.step >= MoveStep::Switched);
        }
        Ok(self.loss_record().await?.is_some_and(|loss| !loss.done()))
    }

    // ---------------------------------------------------------------------------------
    // The steps

    /// One pass of following the own identity's service. A move or a loss that a newer own
    /// `identity.json` supersedes is given up, and the newer document followed instead
    /// (Switch spec 12.5 "Abort", 12.6), at most [`FOLLOW_PASSES`] times in a row.
    async fn provider_step(&mut self) -> Result<ProviderStatus, AppError> {
        let reader = self.reader();
        if let Some(gone) = reader.get::<GoneRecord>(keys::GONE).await?
            && !(gone.reason == GoneReason::Erased && self.revive_erased().await?)
        {
            // An erasure's duty event stays kept until the host acknowledges it.
            if gone.reason == GoneReason::NotCurrent {
                self.push_once(AppEvent::Removed);
            }
            return Ok(ProviderStatus::Gone);
        }
        let me = self.state.meta.app_id;
        if self.state.own_doc.lists_removed(&me) {
            self.mark_gone(GoneReason::NotCurrent).await?;
            return Ok(ProviderStatus::Gone);
        }
        let mut followed = None;
        for _ in 0..FOLLOW_PASSES {
            if let Some(loss) = self.loss_record().await?
                && !loss.done()
                && self.run_loss(loss).await?
            {
                followed = Some(self.state.meta.generation);
            }
            if let Some(mv) = reader.get::<MoveRecord>(keys::MOVE).await?
                && let Some(status) = self.run_move(mv).await?
            {
                return Ok(status);
            }
            if !self.provider_superseded() {
                break;
            }
            let status = self.follow_generation().await?;
            if !self.provider_superseded() {
                return Ok(status);
            }
            followed = Some(self.state.meta.generation);
        }
        Ok(match followed {
            Some(generation) => ProviderStatus::Followed { generation },
            None => ProviderStatus::Current,
        })
    }

    /// Whether the newest own `identity.json` names a later generation than the app follows.
    pub(crate) fn provider_superseded(&self) -> bool {
        self.state.own_doc.generation() > self.state.meta.generation
    }

    /// After a step of a move or a loss failed at a service: read the own `identity.json`
    /// from the Homeserver, since the identity may have gone elsewhere meanwhile, for example
    /// to a provider loss declared because that service is gone (Switch spec 12.5 "Abort").
    /// Only a failed call is looked into; a failed read changes nothing.
    pub(crate) async fn look_for_newer_doc(&mut self, error: &AppError) {
        if !matches!(error.unkept(), AppError::Switch(_) | AppError::Transport(_)) || self.reload {
            return;
        }
        let identity = self.state.meta.identity;
        if let Ok(Some(doc)) =
            identity::read_homeserver(self.env.homeserver.as_ref(), &identity).await
        {
            // An alarm the copy raises is kept; the step's own error is the one returned.
            let _ = self.take_own_copy(doc).await;
        }
    }

    /// The newest own `identity.json` names a later generation and no move is in progress:
    /// a provider loss, or a move or key change the app follows from the switch on.
    async fn follow_generation(&mut self) -> Result<ProviderStatus, AppError> {
        let doc = self.state.own_doc.clone();
        let generation = self.state.meta.generation;
        if doc
            .body()
            .recovery_from
            .is_some_and(|lost| lost >= generation)
        {
            // Switch spec 8.1, 12.6: the document records a loss of the generation followed.
            self.start_loss(&doc).await?;
            if let Some(loss) = self.loss_record().await? {
                self.run_loss(loss).await?;
            }
            return Ok(ProviderStatus::Followed {
                generation: self.state.meta.generation,
            });
        }
        let mv = MoveRecord {
            freeze: None,
            from_generation: generation,
            step: MoveStep::Uploaded,
            batch: Vec::new(),
        };
        Ok(self.run_move(mv).await?.unwrap_or(ProviderStatus::Current))
    }

    /// A freeze from a feed page, a `410 moved` or the public read, verified with the
    /// identity key by whoever read it (Switch wire 3.6): kept, so the move is followed. A
    /// freeze the app followed already is ignored; one that skips a generation is refused.
    pub(crate) async fn note_freeze(&mut self, freeze: &Freeze) -> Result<(), AppError> {
        let generation = self.state.meta.generation;
        if freeze.body().identity != self.state.meta.identity {
            return Err(AppError::InvalidData(
                "Switch wire 3.6: a freeze of another identity".into(),
            ));
        }
        let next = freeze.body().next_generation;
        if next <= generation {
            return Ok(());
        }
        if generation.checked_add(1) != Some(next) {
            return Err(AppError::InvalidData(
                "Switch wire 3.6: a freeze whose next_generation isn't the followed one plus one"
                    .into(),
            ));
        }
        let held = self.reader().get::<MoveRecord>(keys::MOVE).await?;
        if let Some(held) = &held {
            let same = held.freeze.as_ref() == Some(freeze.signed());
            if same || held.step >= MoveStep::Switched {
                return Ok(());
            }
        }
        let mv = MoveRecord {
            freeze: Some(freeze.signed().clone()),
            from_generation: generation,
            step: MoveStep::Seen,
            batch: Vec::new(),
        };
        let mut tx = self.tx()?;
        tx.put(keys::MOVE, &mv)?;
        let doc = self.state.own_doc.clone();
        self.keep_generation(&doc, &mut tx)?;
        self.commit(tx).await?;
        self.events.push(AppEvent::Moved);
        Ok(())
    }

    /// The freeze a `410 moved` answer carries, verified with the identity key.
    fn freeze_in(&self, current: &serde_json::Value) -> Result<Freeze, AppError> {
        current
            .get("freeze")
            .and_then(|value| SignedDoc::from_strict_value(value).ok())
            .and_then(|signed| Freeze::verify(&signed, &self.state.meta.identity).ok())
            .ok_or_else(|| {
                AppError::InvalidData(
                    "Switch wire 3.6: a 410 moved whose freeze doesn't verify with the identity key"
                        .into(),
                )
            })
    }

    /// Run a move's steps from where they stand. `None` when the identity went to another
    /// service than the freeze names, declared a loss, or moved on to a later generation:
    /// the move is given up at whichever step it stands, a stuck one included, and that
    /// change is followed instead (Switch spec 12.5 "Abort").
    fn run_move(
        &mut self,
        mv: MoveRecord,
    ) -> crate::transport::BoxFuture<'_, Result<Option<ProviderStatus>, AppError>> {
        // Boxed, as `App::receive_inner` says.
        Box::pin(self.run_move_body(mv))
    }

    async fn run_move_body(
        &mut self,
        mut mv: MoveRecord,
    ) -> Result<Option<ProviderStatus>, AppError> {
        let freeze = match &mv.freeze {
            None => None,
            Some(signed) => {
                Some(Freeze::verify(signed, &self.state.meta.identity).map_err(|_| corrupt())?)
            }
        };
        loop {
            if self.move_superseded(&mv, freeze.as_ref()) {
                self.give_up_move(&mv, freeze.as_ref()).await?;
                return Ok(None);
            }
            match self.move_step(&mut mv, freeze.as_ref()).await {
                Ok(None) => {}
                Ok(Some(status)) => return Ok(Some(status)),
                Err(error) => {
                    self.look_for_newer_doc(&error).await;
                    if !self.move_superseded(&mv, freeze.as_ref()) {
                        return Err(error);
                    }
                }
            }
        }
    }

    /// The generation a move goes to: the freeze's next one, or the one after the
    /// generation followed for a move the app never saw frozen.
    fn move_target(&self, mv: &MoveRecord, freeze: Option<&Freeze>) -> u64 {
        if mv.step >= MoveStep::Switched {
            return self.state.meta.generation;
        }
        freeze.map_or_else(
            || self.state.meta.generation.saturating_add(1),
            |f| f.body().next_generation,
        )
    }

    /// Whether the newest own `identity.json` supersedes the move: it records a loss of
    /// the generation moved from, names another service than the freeze at the next
    /// generation, or names a later generation than the move goes to. A move the app never
    /// saw frozen follows whatever generation the newest document names.
    fn move_superseded(&self, mv: &MoveRecord, freeze: Option<&Freeze>) -> bool {
        let doc = &self.state.own_doc;
        if mv.step >= MoveStep::Switched {
            return self.provider_superseded();
        }
        let lost = doc
            .body()
            .recovery_from
            .is_some_and(|lost| lost >= mv.from_generation);
        let Some(freeze) = freeze else {
            return lost;
        };
        let next = freeze.body().next_generation;
        let generation = doc.generation();
        generation > next || (generation == next && (lost || doc.inbox() != freeze.next()))
    }

    /// Give the move up for the newer document: the record goes, and the host is told.
    async fn give_up_move(
        &mut self,
        mv: &MoveRecord,
        freeze: Option<&Freeze>,
    ) -> Result<(), AppError> {
        let generation = self.move_target(mv, freeze);
        let mut tx = self.tx()?;
        tx.delete(keys::MOVE)?;
        self.commit(tx).await?;
        let newer = self.state.own_doc.generation();
        if newer > generation {
            self.events
                .push(AppEvent::ProviderChangeSuperseded { generation, newer });
        }
        Ok(())
    }

    /// One step of a move: `Some` ends the pass with that status.
    async fn move_step(
        &mut self,
        mv: &mut MoveRecord,
        freeze: Option<&Freeze>,
    ) -> Result<Option<ProviderStatus>, AppError> {
        match mv.step {
            MoveStep::Seen => {
                self.read_old_feed_to_end().await?;
                mv.step = MoveStep::Read;
                self.save_move(mv).await?;
            }
            MoveStep::Read => {
                if let Some(freeze) = freeze {
                    self.upload_to_next(freeze).await?;
                }
                mv.step = MoveStep::Uploaded;
                self.save_move(mv).await?;
            }
            MoveStep::Uploaded => {
                let next_generation = self.move_target(mv, freeze);
                if !self.move_published(freeze, next_generation).await? {
                    if let Some(freeze) = freeze
                        && self.move_cancelled(freeze).await?
                    {
                        return Ok(Some(ProviderStatus::MoveCancelled));
                    }
                    return Ok(Some(ProviderStatus::AwaitingMove { next_generation }));
                }
                // A document that names another service, a loss or a later generation is
                // followed instead: the next pass gives the move up.
                if !self.move_superseded(mv, freeze) {
                    let doc = self.state.own_doc.clone();
                    self.switch_over(&doc, mv).await?;
                }
            }
            MoveStep::Switched => {
                self.reregister(mv).await?;
                mv.step = MoveStep::Registered;
                mv.batch.clear();
                self.save_move(mv).await?;
            }
            MoveStep::Registered => {
                self.after_switch(mv.from_generation).await?;
                let mut tx = self.tx()?;
                tx.delete(keys::MOVE)?;
                self.commit(tx).await?;
                let generation = self.state.meta.generation;
                self.events.push(AppEvent::ProviderFollowed { generation });
                return Ok(Some(ProviderStatus::Followed { generation }));
            }
        }
        Ok(None)
    }

    async fn save_move(&mut self, mv: &MoveRecord) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        tx.put(keys::MOVE, mv)?;
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut tx)?;
        }
        self.commit(tx).await
    }

    /// Read the frozen service's feed to its end, checking each page against the chain
    /// view only (Switch spec 12.5 step 3): its writes are refused, and the next service
    /// shows the same items again from the cursor. The newest head is then verified.
    ///
    /// The read starts at the verified chain position and pages by each page's `next`,
    /// kept apart from that position (Switch wire 7.4.4): inbox entries aren't chain items
    /// (Switch spec 8.3), so a page of entries alone moves the read but not the chain.
    async fn read_old_feed_to_end(&mut self) -> Result<(), AppError> {
        let multi = self.state.device.multi_device;
        let Some(start) = self.state.chain.as_ref().map(|c| c.verified_seq()) else {
            return Ok(());
        };
        let mut after = Position {
            generation: self.state.cursor.generation,
            seq: start,
        };
        loop {
            let query = FeedQuery {
                after: Some(after),
                limit: Some(self.config.page()),
                wait: None,
            };
            let result = self.client.feed(query).await;
            let page = self.take(result).await?;
            if page.more && (page.scanned_through <= after.seq || page.next.seq <= after.seq) {
                return Err(AppError::InvalidData(
                    "Switch wire 7.4.4: a page that doesn't move past the position asked".into(),
                ));
            }
            let now = self.now();
            let Some(chain) = self.state.chain.as_mut() else {
                return Ok(());
            };
            let checked = match chain.feed_page(&page, now, multi) {
                Ok(checked) => checked,
                Err(AppError::Alarm(alarm)) => return Err(self.raise(alarm).await),
                Err(error) => return Err(error),
            };
            if let Some((verified_seq, checkpoint_seq)) = checked.gap {
                self.events.push(AppEvent::ContinuityUnverified {
                    verified_seq,
                    checkpoint_seq,
                });
            }
            let mut tx = self.tx()?;
            // The deny list's history has the same gap (Switch spec 8.3).
            if let Some((verified_seq, _)) = checked.gap {
                self.note_deny_gap(self.state.cursor.generation, verified_seq, &mut tx)
                    .await?;
            }
            if let Some(chain) = self.state.chain.as_mut() {
                chain.write(&mut tx)?;
            }
            // Reconcile mode starts anew, for every protocol (Switch spec 12.4 step 2.4).
            if checked.gap.is_some() {
                tx.delete(key::RECONCILED)?;
            }
            self.commit(tx).await?;
            if !page.more {
                return Ok(());
            }
            after = page.next;
        }
    }

    /// A client of the app at another service of its own identity, pinned to `inbox`'s key.
    pub(crate) fn client_at(&self, inbox: &Inbox) -> Result<SwitchClient, AppError> {
        let meta = &self.state.meta;
        Ok(SwitchClient::new(
            &inbox.url,
            meta.identity,
            Credentials::App {
                identity: meta.identity,
                keys: self.state.keys.clone(),
                cert: self.state.cert.clone(),
            },
            Some(inbox.service_key),
            std::sync::Arc::clone(&self.env.transport),
            std::sync::Arc::clone(&self.env.clock),
        )?)
    }

    /// Upload the newest head and the evidence kept to the staged next service, with the
    /// app's certificate (Switch spec 12.5 step 3; Switch wire 7.2, 7.4.14). An app whose
    /// continuity is unverified uploads no head. Only the old service's proofs go: the next
    /// service checks each with that key. A refusal is reported and the move goes on.
    async fn upload_to_next(&mut self, freeze: &Freeze) -> Result<(), AppError> {
        let next = self.client_at(freeze.next())?;
        let heads = self
            .state
            .chain
            .as_ref()
            .filter(|chain| chain.gap.is_none())
            .and_then(|chain| chain.newest)
            .into_iter()
            .collect();
        let old_key = self.state.meta.service_key;
        let proofs = self.kept_proofs(Some(&old_key)).await?;
        let upload = RecoveryUpload {
            heads,
            proofs,
            ..RecoveryUpload::default()
        };
        let answer = next.recovery_upload(&upload, true).await;
        self.uploaded(answer.map(|a| (a.heads, a.proofs)))
    }

    /// Report an upload's answer: the counts, or a refusal; a transport failure is retried.
    pub(crate) fn uploaded(
        &mut self,
        answer: Result<(Option<u64>, Option<u64>), ClientError>,
    ) -> Result<(), AppError> {
        match answer {
            Ok((heads, proofs)) => {
                self.events.push(AppEvent::EvidenceUploaded {
                    heads: heads.unwrap_or(0),
                    proofs: proofs.unwrap_or(0),
                });
                Ok(())
            }
            Err(ClientError::Switch { code, .. }) => {
                self.events.push(AppEvent::EvidenceRefused {
                    code: code.as_str().to_owned(),
                });
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Whether the newest own `identity.json` names the next generation: taken from the
    /// next service's public read (which answers `503 staged` until it is named), else
    /// from the Homeserver. A failed read only means not yet.
    async fn move_published(
        &mut self,
        freeze: Option<&Freeze>,
        next_generation: u64,
    ) -> Result<bool, AppError> {
        if self.state.own_doc.generation() >= next_generation {
            return Ok(true);
        }
        if let Some(freeze) = freeze {
            let next = self.client_at(freeze.next())?;
            if let Ok(public) = next.public_identity().await
                && public.identity.generation() >= next_generation
            {
                self.take_own_copy(public.identity).await?;
            }
        }
        if self.state.own_doc.generation() >= next_generation {
            return Ok(true);
        }
        let identity = self.state.meta.identity;
        if let Ok(Some(doc)) =
            identity::read_homeserver(self.env.homeserver.as_ref(), &identity).await
        {
            self.take_own_copy(doc).await?;
        }
        Ok(self.state.own_doc.generation() >= next_generation)
    }

    /// Whether the freeze was cancelled: the old service's public read carries no freeze
    /// any more (Switch spec 12.5 "Abort", Switch wire 7.4.15). The move record goes; a
    /// newer freeze the read shows replaces it.
    async fn move_cancelled(&mut self, freeze: &Freeze) -> Result<bool, AppError> {
        let result = self.client.public_identity().await;
        let Ok(public) = self.take(result).await else {
            return Ok(false);
        };
        match public.freeze {
            Some(shown) if shown.hash() == freeze.hash() => Ok(false),
            Some(shown) => {
                let mut tx = self.tx()?;
                tx.delete(keys::MOVE)?;
                self.commit(tx).await?;
                self.note_freeze(&shown).await?;
                Ok(false)
            }
            None => {
                let mut tx = self.tx()?;
                tx.delete(keys::MOVE)?;
                self.commit(tx).await?;
                self.events.push(AppEvent::MoveCancelled);
                Ok(true)
            }
        }
    }

    /// Follow the service `doc` names (Switch spec 12.5 step 4): the meta, the client, the
    /// cursor's generation and the chain view go across in one commit, with the
    /// re-registration batch signed for the new generation. Of the batches signed for the
    /// old generation, the record and the newest receive key go in the re-registration, and
    /// the kept ones are carried across ([`App::carry_kept_writes`]).
    async fn switch_over(
        &mut self,
        doc: &IdentityDoc,
        mv: &mut MoveRecord,
    ) -> Result<(), AppError> {
        let old = self.state.meta.clone();
        let mut tx = self.tx()?;
        let gen_key = keys::generation(old.generation);
        if !self.reader().exists(&gen_key).await? {
            tx.put(
                &gen_key,
                &GenerationRecord {
                    origin: old.origin.clone(),
                    service_key: old.service_key,
                    doc: None,
                },
            )?;
        }
        self.state.meta.origin = doc.inbox().url.clone();
        self.state.meta.service_key = doc.inbox().service_key;
        self.state.meta.generation = doc.generation();
        self.rebuild_client()?;
        self.state.cursor.generation = doc.generation();
        if let Some(chain) = self.state.chain.as_mut() {
            chain.switch_service();
            chain.write(&mut tx)?;
        }
        for (n, held) in self.state.receive_keys.iter_mut() {
            if !held.pending.is_empty() {
                held.pending.clear();
                tx.put(&key::receive_key(*n), held)?;
            }
        }
        // A move seen frozen read the old feed to its end, so its chain tells which kept
        // batches were applied; a move never seen frozen, or a key change in place, can't
        // tell, and sends them again unchanged first (Switch spec 12.5 "Kept batches").
        let carry = if mv.freeze.is_some() {
            Carry::ReadToEnd
        } else {
            Carry::ResendFirst
        };
        let events = self.carry_kept_writes(&mut tx, carry).await?;
        if self.state.pending_record.take().is_some() {
            tx.delete(key::PENDING_RECORD)?;
        }
        // The next service imported the record the old one accepted, so it stays the newest
        // accepted until the re-registration's answer (Switch spec 4.2, 12.5).
        // A loss followed before, its kept batch unanswered, goes on at this generation.
        if let Some(mut loss) = self.loss_record().await?
            && !loss.done()
            && !loss.batch.is_empty()
        {
            let kept = Batch::from_body(loss.batch.clone())?;
            loss.batch = self.sign_ops(ops_of(&kept), None)?.body().to_vec();
            tx.put(super::recovery::keys::LOSS, &loss)?;
        }
        let batch = self.reregistration_batch()?;
        mv.step = MoveStep::Switched;
        mv.batch = batch.body().to_vec();
        // Lists too large for one commit at the service left are tried again at the next.
        tx.delete(super::admission::LISTS_TOO_LARGE)?;
        tx.put(key::META, &self.state.meta)?;
        tx.put(key::CURSOR, &self.state.cursor)?;
        tx.put(keys::MOVE, &*mv)?;
        self.commit(tx).await?;
        self.events.extend(events);
        Ok(())
    }

    /// At a provider change, what the app signed for the generation it leaves and kept
    /// unanswered (Switch spec 12.5 step 2, 12.6, 13.5), into `tx`. Called once the app
    /// signs for the new generation, while the chain view is still the old service's: a
    /// batch whose ID that chain holds was applied there, though its answer was lost.
    ///
    /// - **`pending/effect`:** applied, its outcome commits now, so its entry isn't
    ///   processed again and an effect without conditions is never applied twice; otherwise
    ///   it goes, and its entry is read again and its effect signed anew.
    /// - **`opq/<batch_id>`:** applied, what it settles commits and it goes; otherwise its
    ///   operations are signed again for the new generation, their bytes under a new wire
    ///   batch ID, and stay kept under the ID the batch was first kept under (`kept.rs`),
    ///   sent with the next write. After a loss, one holding an `attempt` goes instead: no
    ///   automatic attempt is made on an obligation from before the loss (Switch spec 12.6
    ///   step 5).
    /// - **With [`Carry::ResendFirst`],** a kept batch or effect the chain doesn't show
    ///   applied stays as it is, to be sent again unchanged, and its answer decides (Switch
    ///   spec 12.5 "Kept batches"). One kept longer than the service holds batch IDs, 30
    ///   days less the clock tolerance, goes instead, reported as dropped. A kept effect
    ///   stays whatever its age: when the answer can't decide, its entry is stored and
    ///   passed, never applied again.
    ///
    /// Returns the informational events to report once `tx` commits; the duty events are
    /// kept in `tx`, and reported by its commit.
    pub(crate) async fn carry_kept_writes(
        &mut self,
        tx: &mut Tx,
        carry: Carry,
    ) -> Result<Vec<AppEvent>, AppError> {
        let mut events = Vec::new();
        let resend_first = carry == Carry::ResendFirst;
        let window_now = self.kept_window_now();
        let answer_decides = |kept_ms: Option<u64>| answer_decides(window_now, kept_ms);
        if let Some(pending) = self.state.pending_effect.clone() {
            let applied = Batch::from_body(pending.body.clone())?
                .id()
                .is_some_and(|id| self.applied_by_old_service(&id));
            // A kept effect stays to be sent again whatever its age: an answer that can't
            // decide parks its entry instead of building the effect again
            // (`feed.rs`).
            let stays = !applied && resend_first;
            if !stays {
                tx.delete(key::PENDING_EFFECT)?;
                self.state.pending_effect = None;
            }
            // After a loss, an effect the old chain doesn't show applied goes, and its entry
            // is read again; an `attempt` in it is never signed again, so it is reported as
            // a kept batch's is (Switch spec 12.6 step 5).
            if !applied && carry == Carry::AfterLoss {
                self.attempts_dropped(&Batch::from_body(pending.body.clone())?, tx)?;
            }
            if applied {
                let now = self.now();
                // What its operations settle without their proofs, such as a list change.
                let settles = super::batch::PendingBatch {
                    deadlines: pending.deadlines.clone(),
                    ..super::batch::PendingBatch::default()
                };
                for op in Batch::from_body(pending.body.clone())?.ops() {
                    self.settle_op(op, None, &settles, tx).await?;
                }
                processed_writes(tx, &pending.sender, &pending.msg_id, pending.hash, now)?;
                tx.local(&pending.local)?;
                for key in &pending.forget {
                    tx.delete(key)?;
                }
                // Processed: a count of the store's retries at it goes with it.
                if pending.stored.is_some() {
                    self.unpark(pending.stored, tx)?;
                } else if self.state.retries.remove(&pending.seq).is_some() {
                    tx.delete(&key::retry(pending.seq))?;
                }
                if pending.stored.is_some() {
                    // Stored before, and passed then.
                } else if pending.past_held {
                    tx.put(&key::seen(pending.seq), &())?;
                    self.state.seen.insert(pending.seq);
                } else {
                    let cursor = &mut self.state.cursor;
                    cursor.seq = cursor.seq.max(pending.seq);
                    cursor.time_ms = cursor.time_ms.max(pending.accepted_at_ms);
                }
                if let Some(to) = pending.cursor_to {
                    let cursor = &mut self.state.cursor;
                    cursor.at_service = cursor.at_service.max(to);
                }
                events.push(AppEvent::MessageReceived {
                    seq: pending.seq,
                    kind: pending.kind,
                    msg_id: pending.msg_id,
                    sender: pending.sender,
                });
            }
        }
        for (id, pending) in self.kept_batches().await? {
            let kept = Batch::from_body(pending.body.clone())?;
            // The chain holds the batch ID its bytes carry, which signing it again changed;
            // it stays kept under the ID it was first kept under (`kept.rs`).
            if kept
                .id()
                .is_some_and(|wire| self.applied_by_old_service(&wire))
            {
                self.settle_kept_batch(&id, &pending, tx).await?;
                events.push(AppEvent::KeptBatchApplied { batch_id: id });
                continue;
            }
            // A batch never sent has no answer to wait for: it is signed again for the new
            // generation, and sent as a first send, its old bytes never resent.
            let never_sent = pending.kept_ms.is_none();
            if resend_first && !never_sent {
                if !answer_decides(pending.kept_ms) {
                    self.kept_batch_dropped(&id, &pending, &kept, tx)?;
                }
                continue;
            }
            let ops = ops_of(&kept);
            let attempts = ops.iter().any(|(_, kind)| {
                matches!(kind, OpKind::Claim(claim) if claim.kind == ClaimType::Attempt)
            });
            if carry == Carry::AfterLoss && attempts {
                self.kept_batch_dropped(&id, &pending, &kept, tx)?;
                continue;
            }
            let signed = self.sign_ops(ops, None)?;
            let wire_batch_id = signed
                .id()
                .ok_or_else(|| AppError::InvalidData("a batch of operations has an ID".into()))?;
            // New bytes, never sent: stamped at their first send, still kept under `id`.
            let mut renewed = pending.clone();
            renewed.body = signed.body().to_vec();
            renewed.kept_ms = None;
            Self::keep_signed_again(&id, &renewed, tx)?;
            events.push(AppEvent::KeptBatchSignedAgain {
                batch_id: id,
                wire_batch_id,
            });
        }
        Ok(events)
    }

    /// A kept batch dropped unsent, never to go again: no longer kept, its end written
    /// ([`App::kept_batch`]), and reported, with each `attempt` in it, so the protocol treats
    /// those obligations as uncertain (Switch spec 12.5 "Kept batches", 12.6 step 5). Duty
    /// events, kept in `tx`, the commit that drops the batch. One whose first send never
    /// left was never applied; once sent, whether it was can't be told.
    pub(crate) fn kept_batch_dropped(
        &mut self,
        id: &[u8; 16],
        pending: &super::batch::PendingBatch,
        batch: &Batch,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let reason = if pending.kept_ms.is_some() {
            KeptBatchDrop::Uncertain
        } else {
            KeptBatchDrop::Unsent
        };
        self.end_kept_batch(id, pending, Ended::Dropped(reason), tx)?;
        let to = self.batch_owners(pending);
        self.keep_duty_for(tx, to, Duty::KeptBatchDropped { batch_id: *id })?;
        self.attempts_dropped(batch, tx)
    }

    /// Each `attempt` of a batch the app drops unsent, reported in `tx` so the protocol
    /// treats its obligation as uncertain (Switch spec 12.5 "Kept batches", 12.6 step 5).
    fn attempts_dropped(&mut self, batch: &Batch, tx: &mut Tx) -> Result<(), AppError> {
        for attempt in attempts_in(batch) {
            self.keep_duty(
                tx,
                Duty::AttemptDropped {
                    claim_key: attempt.claim_key,
                    attempt_id: attempt.attempt_id,
                },
            )?;
        }
        Ok(())
    }

    /// Whether the old service's chain, as the app verified it, holds batch `id`.
    fn applied_by_old_service(&self, id: &[u8; 16]) -> bool {
        self.state
            .chain
            .as_ref()
            .is_some_and(|chain| chain.holds_batch(id))
    }

    /// The app record and the newest receive key record, signed for the generation followed.
    pub(crate) fn reregistration_batch(&self) -> Result<Batch, AppError> {
        let record = self
            .state
            .receive_keys
            .values()
            .next_back()
            .map(|held| held.record.clone())
            .ok_or_else(|| AppError::InvalidData("no receive key held".into()))?;
        self.sign_ops(
            vec![
                (
                    Vec::<Condition>::new(),
                    OpKind::AppPut {
                        record: self.state.record.clone(),
                    },
                ),
                (Vec::new(), OpKind::ReceiveKeyPut { record }),
            ],
            None,
        )
    }

    /// Read the own entry in the next directory, then send the kept re-registration batch
    /// (Switch spec 12.5 step 4, 3.6). An older key of the app shown as current is a
    /// rollback of its registrations: reported, and the current key registered again. A key
    /// no device of the app made is a compromise, or, while a restore asks about it,
    /// unaccounted, the user asked ([`App::restore_asks_about`], Switch spec 12.4).
    async fn reregister(&mut self, mv: &MoveRecord) -> Result<(), AppError> {
        let current = self
            .state
            .receive_keys
            .values()
            .next_back()
            .map(|held| (held.key.n, held.key.kid));
        if let (Some(shown), Some((n, kid))) = (self.own_directory_key().await?, current)
            && shown.kid() != kid
        {
            if !self.state.known_kids.contains_key(&shown.kid())
                && !self.state.device.multi_device
                && self.restore_asks_about(shown.n())
            {
                let mut tx = self.tx()?;
                self.ask_about_registration(shown.n(), shown.kid(), None, &mut tx)?;
                self.commit(tx).await?;
                self.push_restore_question();
            } else if !self.state.known_kids.contains_key(&shown.kid()) {
                let error = self
                    .raise(Alarm::Compromise {
                        n: shown.n(),
                        distrust_from: self.distrust_bound(),
                    })
                    .await;
                self.leave_on_compromise().await;
                return Err(error);
            }
            if shown.n() < n {
                self.events.push(AppEvent::ReceiveKeyRolledBack {
                    shown: shown.n(),
                    current: n,
                });
            }
        }
        if mv.batch.is_empty() {
            return Ok(());
        }
        let batch = Batch::from_body(mv.batch.clone())?;
        let proofs = match self.submit(&batch).await {
            Ok(submitted) => {
                // The next service accepted the record the re-registration carries: it is
                // the one a publication writes from now on (Switch spec 4.2).
                let record = super::renewal::delivered_record(&batch)?;
                let mut tx = self.tx()?;
                self.note_accepted(&record, &mut tx)?;
                self.commit(tx).await?;
                self.took_accepted(record);
                submitted.proofs
            }
            // A registration the service refuses as it stands, an older own key current
            // there included, is reported; the app reads on with what the service holds.
            Err(AppError::Switch(ClientError::Switch {
                code: ErrorCode::Conflict,
                ..
            })) => Vec::new(),
            Err(error) => return Err(error),
        };
        if let (Some(proof), Some((n, _))) = (proofs.get(1), current) {
            let seq = proof.envelope().seq;
            let mut tx = self.tx()?;
            if let Some(held) = self.state.receive_keys.get_mut(&n) {
                held.reg_seq = Some(seq);
                held.reg_time_ms = Some(proof.envelope().server_time);
                tx.put(&key::receive_key(n), held)?;
            }
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// The checks once the app follows the next service (Switch spec 12.5 step 4): the old
    /// service's proofs again, the admission lists, and the push setting, which the next
    /// service doesn't hold.
    fn after_switch(
        &mut self,
        from_generation: u64,
    ) -> crate::transport::BoxFuture<'_, Result<(), AppError>> {
        // Boxed, as `App::receive_inner` says.
        Box::pin(self.after_switch_body(from_generation))
    }

    async fn after_switch_body(&mut self, from_generation: u64) -> Result<(), AppError> {
        let old_key = self
            .reader()
            .get::<GenerationRecord>(&keys::generation(from_generation))
            .await?
            .map(|record| record.service_key);
        if let Some(old_key) = old_key {
            let proofs = self.kept_proofs(Some(&old_key)).await?;
            if !proofs.is_empty() {
                let upload = RecoveryUpload {
                    proofs,
                    ..RecoveryUpload::default()
                };
                let result = self.client.recovery_upload(&upload, false).await;
                let answer = self.take(result).await;
                match answer {
                    Ok(answer) => {
                        if let Some(head) = answer.head
                            && let Err(alarm) = self.note_answer_head(head, &[])
                        {
                            return Err(self.raise(alarm).await);
                        }
                        self.uploaded(Ok((answer.heads, answer.proofs)))?;
                    }
                    Err(AppError::Switch(error)) => self.uploaded(Err(error))?,
                    Err(error) => return Err(error),
                }
            }
        }
        self.compare_lists().await?;
        self.push_after_provider_change().await
    }

    /// Compare the next service's admission lists with the app's copy (Switch spec 12.5
    /// step 4): with `lists.manage`, add back the contacts and deny list entries it lacks,
    /// and count the contacts the app never saw added, which are shown, not removed; with
    /// `conversation.add`, withdraw the invite codes it holds in this app's name that the
    /// app never registered, and those of apps that aren't current.
    async fn compare_lists(&mut self) -> Result<(), AppError> {
        let cert = &self.state.cert;
        let manage = cert.has_permission(Permission::ListsManage);
        let read = manage || cert.has_permission(Permission::ListsRead);
        let codes = cert.has_permission(Permission::ConversationAdd);
        if !read {
            return Ok(());
        }
        // Batches kept from an earlier pass go first, so the lists are compared after them.
        self.resume_batches().await?;
        let result = self.client.allow().await;
        let held = match self.take(result).await {
            Ok(held) => held,
            Err(AppError::Switch(_)) => return Ok(()),
            Err(error) => return Err(error),
        };
        let copy = self.lists_copy().await?;
        let mut ops = Vec::new();
        let mut added = 0u64;
        let mut unverified = 0u64;
        if manage {
            for pubky in copy.contacts.iter().filter(|p| !held.contacts.contains(p)) {
                ops.push(OpKind::AllowPut {
                    pubky: *pubky,
                    kind: AllowKind::Contact,
                });
                added = added.saturating_add(1);
            }
            for pubky in copy.deny.iter().filter(|p| !held.deny.contains(p)) {
                ops.push(OpKind::DenyPut { pubky: *pubky });
                added = added.saturating_add(1);
            }
            unverified = u64::try_from(
                held.contacts
                    .iter()
                    .filter(|p| !copy.contacts.contains(p))
                    .count(),
            )
            .unwrap_or(u64::MAX);
        }
        let mut withdrawn = 0u64;
        if codes {
            let me = self.state.meta.app_id;
            for code in &held.invite_codes {
                let planted = code.written_by == me && !copy.codes.contains(&code.code_hash);
                let stale = self.state.own_doc.listed_cert(&code.written_by).is_none();
                if planted || stale {
                    ops.push(OpKind::InviteCodeDelete {
                        code_hash: code.code_hash,
                    });
                    withdrawn = withdrawn.saturating_add(1);
                }
            }
        }
        if ops.is_empty() && unverified == 0 {
            return Ok(());
        }
        self.events.push(AppEvent::ListsDiffer {
            added,
            unverified_contacts: unverified,
            withdrawn_codes: withdrawn,
        });
        self.submit_ops(ops).await
    }

    /// Send `ops` in batches of at most eight, each signed once and kept before it is
    /// first sent (Switch wire 2.1): one whose answer is lost goes again, the same bytes,
    /// before any later write ([`App::submit_batch`]).
    pub(crate) async fn submit_ops(&mut self, ops: Vec<OpKind>) -> Result<(), AppError> {
        for chunk in ops.chunks(MAX_BATCH_ENTRIES) {
            let batch = chunk
                .iter()
                .fold(OpBatch::new(), |batch, op| batch.op(op.clone()));
            self.submit_batch(batch).await?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // The app's copy of the lists, from the feed (Switch spec 8.3, 12.5 step 4, 12.6 step 2)

    /// Keep an allowlist, deny list or invite code change seen in the feed.
    pub(crate) fn note_list_op(&self, body: &OpBody, tx: &mut Tx) -> Result<(), AppError> {
        match &body.kind {
            OpKind::AllowPut {
                pubky,
                kind: AllowKind::Contact,
            } => tx.put(&keys::contact(pubky), &()),
            OpKind::AllowDelete {
                pubky,
                kind: AllowKind::Contact,
            } => tx.delete(&keys::contact(pubky)),
            OpKind::DenyPut { pubky } => self.note_deny_change(pubky, true, tx),
            OpKind::DenyDelete { pubky } => self.note_deny_change(pubky, false, tx),
            OpKind::InviteCodePut(put) if body.app_id == Some(self.state.meta.app_id) => {
                tx.put(&keys::code(&put.code_hash), &())
            }
            OpKind::InviteCodeDelete { code_hash } => tx.delete(&keys::code(code_hash)),
            _ => Ok(()),
        }
    }

    /// Keep a deny list change: `pubky` denied when `added`, no longer denied otherwise.
    pub(crate) fn note_deny_change(
        &self,
        pubky: &[u8; 32],
        added: bool,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        if added {
            tx.put(&keys::deny(pubky), &())
        } else {
            tx.delete(&keys::deny(pubky))
        }
    }

    /// The app's copy of the lists.
    pub(crate) async fn lists_copy(&self) -> Result<ListsCopy, AppError> {
        let reader = self.reader();
        let pubkys = |rows: Vec<(String, Vec<u8>)>| {
            rows.into_iter()
                .map(|(rest, _)| pubky_key(&rest).map_err(|_| corrupt()))
                .collect::<Result<Vec<_>, _>>()
        };
        let codes = reader
            .scan_raw("lc/code/")
            .await?
            .into_iter()
            .map(|(rest, _)| {
                pubky_switch_core::enc::unb64_array::<32>(&rest).map_err(|_| corrupt())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ListsCopy {
            contacts: pubkys(reader.scan_raw("lc/contact/").await?)?,
            deny: pubkys(reader.scan_raw("lc/deny/").await?)?,
            codes,
        })
    }

    // ---------------------------------------------------------------------------------
    // Generations

    /// Keep the service and the last own copy of the generation the app leaves.
    pub(crate) fn keep_generation(&self, doc: &IdentityDoc, tx: &mut Tx) -> Result<(), AppError> {
        tx.put(
            &keys::generation(doc.generation()),
            &GenerationRecord {
                origin: doc.inbox().url.clone(),
                service_key: doc.inbox().service_key,
                doc: Some(doc.signed().clone()),
            },
        )
    }

    /// The service key of `generation`: the followed one's, one the app left, or one the
    /// own `identity.json` lists (Switch wire 3.3). `None` for a generation it knows none of.
    pub(crate) async fn service_key_of(
        &self,
        generation: u64,
    ) -> Result<Option<[u8; 32]>, AppError> {
        if generation == self.state.meta.generation {
            return Ok(Some(self.state.meta.service_key));
        }
        let kept = self
            .reader()
            .get::<GenerationRecord>(&keys::generation(generation))
            .await?;
        Ok(kept
            .map(|record| record.service_key)
            .or_else(|| self.state.own_doc.service_key_of(generation)))
    }

    /// The last own `identity.json` the app took at `generation`.
    pub(crate) async fn generation_doc(
        &self,
        generation: u64,
    ) -> Result<Option<SignedDoc>, AppError> {
        Ok(self
            .reader()
            .get::<GenerationRecord>(&keys::generation(generation))
            .await?
            .and_then(|record| record.doc))
    }

    // ---------------------------------------------------------------------------------
    // Revocation and erasure (Switch spec 12.2, 12.7)

    /// The app isn't current any more, or its account is gone: kept and reported. The
    /// service drops the push registration with it. An app that isn't current drops its push
    /// setting and the other devices' handles; an erased account may be seen alive again
    /// ([`App::revive_erased`]), so its setting is kept, only no longer set, for
    /// [`App::reregister_push`].
    pub(crate) async fn mark_gone(&mut self, reason: GoneReason) -> Result<(), AppError> {
        let gone = GoneRecord {
            reason,
            at_ms: self.now(),
        };
        let mut tx = self.tx()?;
        tx.put(keys::GONE, &gone)?;
        tx.delete(keys::ERASING)?;
        // An erasure is told to the protocol as a duty event, in this commit; a removal is
        // told at every call (`provider_step`).
        if reason == GoneReason::Erased {
            self.keep_duty(&mut tx, Duty::AccountGone)?;
        }
        let held = self.push_record().await?;
        let had_push = held.is_some();
        match (reason, held) {
            (GoneReason::Erased, Some(mut record)) => {
                record.push_key = None;
                record.handle = None;
                record.set = false;
                record.handles = 0;
                record.replacing = None;
                tx.put(push::KEY, &record)?;
            }
            (GoneReason::Erased, None) => {}
            (GoneReason::NotCurrent, _) => {
                tx.delete(push::KEY)?;
                tx.delete(push::DEVICES_KEY)?;
            }
        }
        self.commit(tx).await?;
        self.state.gone = Some(gone);
        self.state.erasing = None;
        if had_push {
            self.events.push(AppEvent::PushRemoved);
        }
        if reason == GoneReason::NotCurrent {
            self.push_once(AppEvent::Removed);
        }
        Ok(())
    }

    /// An erased account seen alive again: the identity publishes an `identity.json`, no
    /// older than the one the app holds, that lists the app (Switch spec 12.7). `gone` goes, the copy is taken, and the app reads
    /// on; one that lists it no longer, or in `removed`, is followed as any copy is.
    /// The [`AppEvent::AccountGone`] duty events the host hasn't acknowledged go in the same
    /// commit: they no longer hold, and a later [`App::load`] would deliver them again for a
    /// live account. Returns whether the app came back.
    async fn revive_erased(&mut self) -> Result<bool, AppError> {
        let identity = self.state.meta.identity;
        let Ok(Some(doc)) =
            identity::read_homeserver(self.env.homeserver.as_ref(), &identity).await
        else {
            return Ok(false);
        };
        let me = self.state.meta.app_id;
        // A copy older than the one held shows nothing new: the account stays gone.
        let held = &self.state.own_doc;
        if doc.version() < held.version()
            || doc.generation() < held.generation()
            || doc.listed_cert(&me).is_none()
            || doc.lists_removed(&me)
        {
            return Ok(false);
        }
        let gone_duties: Vec<u64> = self
            .reader()
            .scan_numbered::<super::events::KeptDuty>(key::DUTY_PREFIX)
            .await?
            .into_iter()
            .filter(|(_, kept)| kept.duty == Duty::AccountGone)
            .map(|(n, _)| n)
            .collect();
        // `gone` and its duty events go with the copy, in its commit: a copy that fails
        // leaves them.
        self.take_own_copy_with(doc, |tx| {
            tx.delete(keys::GONE)?;
            for n in gone_duties {
                tx.delete(&key::duty(n))?;
            }
            Ok(())
        })
        .await?;
        self.state.gone = None;
        self.events.push(AppEvent::AccountBack);
        Ok(true)
    }

    /// An answer the account's key didn't sign. A newer own `identity.json` is followed: a
    /// key change or a move the app hadn't seen yet. For a `404`, the account may be erased
    /// (Switch spec 12.7): it is gone once the identity has published no `identity.json` at
    /// every try for [`ERASURE_WAIT_MS`], unless the verified own copy the app holds names a
    /// later generation than it follows, a live account elsewhere, which is followed
    /// instead. Until then the service counts as unreachable: the app keeps its state and
    /// tries again, and the call fails with [`AppError::NotAnsweringAsAccount`] (a read and
    /// [`App::check_for_move`] both count a try). Anything else the app can't tell, and a published `identity.json` or
    /// another status starts the wait over; a Homeserver it can't reach changes nothing.
    async fn unknown_account(&mut self, status: u16) -> Result<Unknown, AppError> {
        let identity = self.state.meta.identity;
        match identity::read_homeserver(self.env.homeserver.as_ref(), &identity).await {
            Ok(None) if status == 404 && self.provider_superseded() => Ok(Unknown::Moved),
            Ok(None) if status == 404 => {
                if !self.erasure_held().await? {
                    let since = self.state.erasing.map_or(self.now(), |e| e.since_ms);
                    return Ok(Unknown::Waiting(since));
                }
                self.mark_gone(GoneReason::Erased).await?;
                Ok(Unknown::Gone)
            }
            Ok(Some(doc)) => {
                self.take_own_copy(doc).await?;
                if self.state.own_doc.generation() > self.state.meta.generation {
                    Ok(Unknown::Moved)
                } else {
                    Ok(Unknown::Unexplained)
                }
            }
            Ok(None) => {
                self.clear_erasing().await?;
                Ok(Unknown::Unexplained)
            }
            Err(_) => Ok(Unknown::Unexplained),
        }
    }

    /// Note an unsigned `404` with no `identity.json` published, and say whether both have
    /// held at [`ERASURE_TRIES`] tries spaced [`ERASURE_TRY_SPACING_MS`] apart, over at
    /// least [`ERASURE_WAIT_MS`] (Switch spec 12.7). A try sooner after the last one counted
    /// adds nothing; a clock gone back starts the wait over.
    async fn erasure_held(&mut self) -> Result<bool, AppError> {
        let now = self.now();
        let first = ErasingRecord {
            since_ms: now,
            last_ms: now,
            tries: 1,
        };
        let record = match self.state.erasing {
            Some(seen) if now >= seen.last_ms && now >= seen.since_ms => {
                if now.saturating_sub(seen.last_ms) >= ERASURE_TRY_SPACING_MS {
                    ErasingRecord {
                        last_ms: now,
                        tries: seen.tries.saturating_add(1),
                        ..seen
                    }
                } else {
                    seen
                }
            }
            _ => first,
        };
        if self.state.erasing != Some(record) {
            let mut tx = self.tx()?;
            tx.put(keys::ERASING, &record)?;
            self.commit(tx).await?;
            self.state.erasing = Some(record);
        }
        Ok(record.tries >= ERASURE_TRIES && now.saturating_sub(record.since_ms) >= ERASURE_WAIT_MS)
    }

    /// A try that met something other than an erased account, an answer verified with the
    /// pinned key or a published `identity.json`, starts the wait over.
    pub(crate) async fn clear_erasing(&mut self) -> Result<(), AppError> {
        if self.state.erasing.is_none() {
            return Ok(());
        }
        let mut tx = self.tx()?;
        tx.delete(keys::ERASING)?;
        self.commit(tx).await?;
        self.state.erasing = None;
        Ok(())
    }
}

/// The app's copy of the admission lists, kept from the feed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ListsCopy {
    pub(crate) contacts: Vec<[u8; 32]>,
    pub(crate) deny: Vec<[u8; 32]>,
    /// The invite codes this app registered, by hash.
    pub(crate) codes: Vec<[u8; 32]>,
}
