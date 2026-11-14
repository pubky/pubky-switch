//! Reading the feed (Switch spec 8.2, 8.3, 11; Switch wire 5.1, 7.4.4, 7.5).
//!
//! Each read follows the feed from the cursor to its end, page by page, the first page a
//! long-poll when asked. Every page is checked against the chain view before anything on it
//! is used. Then, in order:
//!
//! - **Entries** are opened with the held receive key their kid names and checked with the
//!   core's recipient checks 1 to 9; the protocol does check 10 and returns the effect. A
//!   message with operations is applied by one batch that carries the cursor move, signed and
//!   kept before it is sent; the processed pair, the protocol's local writes and the cursor
//!   are committed with the answer. A message without operations, a dropped one and a
//!   duplicate only move the cursor, deferred.
//! - **Dedupe** is by (sender identity, `msg_id`) with the message hash, kept for 30 days
//!   plus the clock tolerance; the same pair with other bytes is shown as a conflict. The
//!   pairs processed in the current read count before they are committed, so the same pair
//!   twice on one page is applied once.
//! - **An entry whose sender can't be checked** is held: later items go on, the cursor stays
//!   before it, and the entries processed past it are remembered. After the bounded wait it
//!   is stored locally and passed. An entry whose write hits a quota is stored and passed
//!   too, and applied once there is room. So is an entry whose effect the switch refuses for
//!   good, or that has more operations than one batch takes, which isn't tried again: a
//!   permanent refusal never stalls the feed. Pages are read from a position that moves on
//!   to each page's `scanned_through`, while the cursor stays before the held entry.
//! - **An entry whose receive step the protocol's store or the host kept from finishing**
//!   ([`Outcome::Retry`]) commits nothing of the step. While the store is unavailable it is
//!   held the same way, for the same bounded wait, and comes again at each read; from the
//!   [`RETRY_EVENT_READS`]th read in a row the app raises [`AppEvent::StoreFailing`]. After
//!   the wait, or at once when the store fails for that entry, it is stored and passed, and
//!   tried again at every read: never dropped.
//! - **An entry whose receive step waits for a scope key** the app doesn't hold yet
//!   ([`Outcome::AwaitKey`], or an effect with a write the context couldn't seal for want of
//!   the current data epoch's key) is stored and passed at once, after at most one fetch of
//!   the key bundle, which asks for a full bundle if a key is still missing. It is tried
//!   again once the app holds its epoch's keys, in the read whose fetch brought them, after
//!   any listing owed, or at a later read; until then it costs a read nothing. It is bounded
//!   with the entries whose sender couldn't be checked (Switch spec 3.5, 8.2).
//! - **An entry no held key opens** is passed; the protocol is asked to request a re-send,
//!   never for a time before the cursor's less the clock tolerance. So is an entry a departed
//!   own app left unread, accepted at or before a departure the app verified in its chain;
//!   and entries missed while lagging. A call the protocol answers with an error is kept with
//!   the item's pass and made again by later reads.
//! - **Chain items** must match their stubs. The app takes its own `identity.json`
//!   deliveries, its own receive key registrations, key bundle parts (fetched before the
//!   cursor passes them), renewed certificates, and the departures of other own apps.
//!
//! Before the feed, a read sends the batches kept from earlier calls again
//! ([`App::submit_batch`]), so a lost answer is settled by the next read too.
//!
//! A read keeps to per-call budgets: the kept batches it sends again, the pages of an owed
//! listing, the entries stored locally it tries again and the records and claims it reads
//! again. What a budget leaves goes at the next read, in the same order. The report says
//! when that is now for the kept batches and the listing ([`ReceiveReport::more`]); the
//! entries stored locally and the records and claims read again go on at the next read,
//! which a quiet feed brings within [`super::UPKEEP_READ_MS`]. The feed's pages have no
//! budget: a read follows the feed to its end. A host that waits for the feed between reads
//! does so with a handle that doesn't hold the app ([`App::feed_wait`]), paced with
//! [`super::WaitPace`].
//!
//! Cursor moves that apply nothing are deferred, for at most a few seconds while the app
//! runs, and go with the next batch or alone ([`App::flush_cursor`]).

use std::collections::HashMap;
use std::sync::Arc;

use pubky_switch_core::chain::{ChainEnvelope, ItemType, ServiceTransition, Verifier};
use pubky_switch_core::envelope::parse_header;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::message::MessagePlaintext;
use pubky_switch_core::ops::{MAX_BATCH_ENTRIES, OpKind, Position, SignedOp};
use pubky_switch_core::receive::{
    OpenedEntry, Received, Refusal as CheckRefusal, SenderIdentity, check_opened,
};
use pubky_switch_core::records::{CLOCK_TOLERANCE_MS, IdentityDoc};
use pubky_switch_core::recovery::UploadChanges;
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;

use super::batch::PendingBatch;
use super::claims::{ClaimRead, ObligationDeadline};
use super::context::{ClaimFetch, ContextWrites, ReceiveContext};
use super::error::{Alarm, Refusal, RefusalPlace, refused_at, refused_for_good};
use super::events::{AppEvent, Duty, KeptRefusal, ParkReason, RefusedCall};
use super::identity::{self, DOC_CACHE_MS, Taken};
use super::protocol::{
    DenyListChange, Effect, LocalWrite, MAX_CLAIM_READS, MAX_REGRESSION_REASON_BYTES,
    MAX_SEEN_MARK_BYTES, MAX_STEP_LOCAL_BYTES, MissedEntries, Need, OpaqueRule, Outcome,
    PARKED_RETRIES_PER_READ, Protocol, RETRY_EVENT_READS, ReceivedMessage, ResendNeeded,
    ResendReason, StoreFailure, local_writes_bytes,
};
use super::protocols::Rules;
use super::provider::TakeOver;
use super::records::{Collection, LISTING_PAGES_PER_READ, Listing, pending_name_key};
use super::rotation::RegistrationStep;
use super::state::{
    CachedDoc, HeldEntry, KeptEntry, PROTOCOL_PREFIX, ParkedEntry, ParkedRound, PendingEffect,
    Processed, RetryEntry, Tx, encode, key,
};
use super::{App, AppError, PROCESSED_RETENTION_MS};
use crate::client::Batch;
use crate::client::answers::{ChainItem, EntryItem, FeedItem, FeedPage, FeedQuery};
use crate::error::ClientError;
use crate::store::{MAX_BATCH_BYTES, MAX_VALUE_BYTES};

/// The most feed pages one read asks for ([`App::receive`]): a read that needs more stops
/// between pages, says so ([`ReceiveReport::more`]), and the next read goes on from where it
/// got.
pub const FEED_PAGES_PER_READ: u32 = 4;

/// Where a read that stopped with more to do went on to, kept so the next read goes on from
/// there rather than from the cursor, past the entries held behind it (`feed_at`, `STATE.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct FeedAt {
    generation: u64,
    after: u64,
    blocked: Option<u64>,
}

const FEED_AT: &str = "feed_at";
/// `dgap`: a gap in the deny list's history not told to every protocol yet, the position it
/// is complete through, and the protocols still owed it ([`App::note_deny_gap`]).
pub(crate) const DENY_GAP: &str = "dgap";

/// A deny list gap as `dgap` keeps it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct OwedGap {
    pub(crate) generation: u64,
    pub(crate) seq: u64,
    /// The protocols it is owed to, in registration order: all of them stay while one
    /// fails it, so each is told it again with the list the copy is taken from.
    pub(crate) to: Vec<String>,
}

/// What one read did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReceiveReport {
    /// Everything that happened, in order.
    pub events: Vec<AppEvent>,
    /// The position processed to.
    pub cursor: Position,
    /// The read stopped before the end of the feed: a key another device made that this
    /// one lacks, the app's removal, a provider change, or a call the protocol must take
    /// first that it failed (an owed call or a deny list gap, [`super::AppEvent::OwedCallHeld`]
    /// after a few reads). A wait taken after it is [`super::Woken::ReadLater`] at once,
    /// until a read gets further.
    pub stopped: bool,
    /// The read stopped on one of its per-call budgets with more to do now, all of it
    /// left for the next read, nothing lost or reordered: kept batches beyond
    /// [`KEPT_RESENDS_PER_READ`](super::KEPT_RESENDS_PER_READ), an owed listing of the
    /// collections beyond [`LISTING_PAGES_PER_READ`] pages, a second `missed` item, whose
    /// listing the next read makes, feed pages beyond [`FEED_PAGES_PER_READ`], claims or
    /// records to read again beyond [`CLAIM_REREADS_PER_READ`](super::CLAIM_REREADS_PER_READ)
    /// or [`RECORD_REREADS_PER_READ`](super::RECORD_REREADS_PER_READ), or any of these left
    /// once the time budget was spent ([`super::AppConfig::call_budget_ms`]). Entries stored
    /// locally that a read didn't retry don't set it: they are retried at the next read
    /// whenever it comes. The host calls [`App::receive`] again without waiting.
    pub more: bool,
    /// What the cursor the service holds said beside the furthest position the app
    /// committed or sent, the worst of the read's pages (Switch spec 8.3); `None` when the
    /// read read no page.
    pub held_cursor: Option<super::HeldCursor>,
}

/// How far an item lets the cursor go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Processed: the cursor may pass it.
    Pass,
    /// Not processed now: the cursor stays before it; later items go on.
    Hold,
    /// Read no further.
    Stop,
}

/// What an effect's context wrote, for the kept batch and the reads after a conflict.
#[derive(Clone, Copy)]
struct Written<'a> {
    records: &'a [([u8; 32], Collection)],
    deadlines: &'a [([u8; 32], ObligationDeadline)],
    forget: &'a [String],
}

/// How many times an effect is built for one entry in one read: once, and once more after a
/// `409 conflict`; then the entry waits for the next read.
const EFFECT_TRIES: usize = 2;

/// What became of the reads a receive step asked for.
enum Needs {
    /// Read: the step is called again.
    Read,
    /// A read failed for now: the entry waits for the next read of the feed.
    Wait,
    /// Nothing new, or past the bound: the entry is stored and passed.
    TooMany,
}

/// What became of an effect's batch.
enum Sent {
    Applied,
    Conflict(serde_json::Value),
    StaleEpoch,
    Quota,
    /// Refused for good, with the error code: the entry is stored and passed.
    Refused(String),
    /// Too large for the app to keep before it sends it: nothing was kept or sent, and the
    /// entry is stored and passed.
    TooLarge,
    /// Sent again and refused before the service looked at its batch ID, past the window in
    /// which a resend tells: its entry is stored and passed as uncertain.
    Uncertain,
}

/// `owed/<generation>/<seq>`: a protocol call about a feed item (`Protocol::resend_needed`,
/// `Protocol::missed`, `Protocol::deny_list_changed`), owed to the protocols that couldn't
/// answer it, or that owed an earlier call when it came, each until it answers. Every
/// writer names them; one that answers is taken out in the commit of its writes, so no
/// protocol is handed the call twice.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Owed {
    /// The protocols it is owed to, in registration order, each once.
    pub(crate) to: Vec<String>,
    /// The call.
    pub(crate) call: OwedCall,
}

/// A call about a feed item, as [`Owed`] keeps it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum OwedCall {
    Resend {
        #[serde(with = "pubky_switch_core::enc::serde_b64")]
        sender: [u8; 32],
        accepted_from_ms: u64,
        accepted_until_ms: u64,
        /// Whether the entry was one a departed own app left unread, rather than one
        /// wrapped to a key the app doesn't hold.
        unreadable: bool,
    },
    Missed {
        seq: u64,
        entries: u64,
        accepted_from_ms: u64,
        accepted_until_ms: u64,
    },
    /// A deny list change, owed in feed order: the calls behind it wait for it.
    Deny {
        generation: u64,
        seq: u64,
        #[serde(with = "pubky_switch_core::enc::serde_b64")]
        pubky: [u8; 32],
        added: bool,
        at_ms: u64,
    },
    /// A deny list change whose writer's certificate couldn't be looked up yet, the
    /// directory read failing: verified again, and handed or refused, at a later read.
    DenyUnverified {
        generation: u64,
        seq: u64,
        #[serde(with = "pubky_switch_core::enc::serde_b64")]
        pubky: [u8; 32],
        added: bool,
        at_ms: u64,
        /// The operation, as the feed showed it.
        op: SignedDoc,
    },
}

impl From<&ResendNeeded> for OwedCall {
    fn from(needed: &ResendNeeded) -> Self {
        Self::Resend {
            sender: needed.sender,
            accepted_from_ms: needed.accepted_from_ms,
            accepted_until_ms: needed.accepted_until_ms,
            unreadable: needed.reason == ResendReason::Unreadable,
        }
    }
}

/// Whether a call that failed with `error` may pass later unchanged: a transport failure,
/// or an answer that asks to try again later (`503 unavailable`, `staged`, `429
/// rate_limited`, `quota_exceeded`; Switch spec 6.4). A wait on such a failure holds the
/// read; any other failure is the read's error.
fn may_pass_unchanged(error: &AppError) -> bool {
    match error {
        AppError::Transport(_) => true,
        AppError::Switch(ClientError::Switch { code, .. }) => matches!(
            code.retry(),
            pubky_switch_core::http::Retry::Yes
                | pubky_switch_core::http::Retry::AfterRetryAfter
                | pubky_switch_core::http::Retry::WhenLimitFrees
        ),
        _ => false,
    }
}

/// The feed position an owed call's key names (`owed/<generation>/<seq>`, given without
/// its prefix). Every call is keyed so: a key that names none has no place in feed order,
/// and the store is corrupt.
pub(crate) fn owed_place(rest: &str) -> Result<(u64, u64), AppError> {
    let (generation, seq) = rest
        .split_once('/')
        .ok_or(AppError::Store(crate::error::StoreError::Corrupt))?;
    Ok((
        super::state::parse_num(generation)?,
        super::state::parse_num(seq)?,
    ))
}

impl OwedCall {
    /// The operation a deny list change not checked yet keeps, as the feed showed it, read
    /// for its check; `None` for any other call. The change kept beside it is read from that
    /// operation: one that doesn't parse, or isn't that change, is a corrupt store.
    pub(crate) fn kept_op_body(&self) -> Result<Option<pubky_switch_core::ops::OpBody>, AppError> {
        let Self::DenyUnverified {
            pubky, added, op, ..
        } = self
        else {
            return Ok(None);
        };
        let body = SignedOp::peek(op)
            .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?
            .body()
            .clone();
        let kept = match body.kind {
            OpKind::DenyPut { pubky } => Some((pubky, true)),
            OpKind::DenyDelete { pubky } => Some((pubky, false)),
            _ => None,
        };
        if kept != Some((*pubky, *added)) {
            return Err(AppError::Store(crate::error::StoreError::Corrupt));
        }
        Ok(Some(body))
    }

    /// Whether it is a deny list change, which every protocol must take before anything
    /// later is handed to any (Switch spec 8.3).
    fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. } | Self::DenyUnverified { .. })
    }

    /// The call, made.
    fn make(&self, protocol: &dyn Protocol) -> Result<Vec<LocalWrite>, StoreFailure> {
        match self.refused(0) {
            RefusedCall::ResendNeeded { needed, .. } => protocol.resend_needed(&needed),
            RefusedCall::Missed(missed) => protocol.missed(&missed),
            RefusedCall::DenyListChanged(change) => protocol.deny_list_changed(&change),
            _ => Ok(Vec::new()),
        }
    }

    /// The call as the protocol is handed it, about the feed item at `seq`.
    pub(crate) fn refused(&self, seq: u64) -> RefusedCall {
        match *self {
            Self::Resend {
                sender,
                accepted_from_ms,
                accepted_until_ms,
                unreadable,
            } => RefusedCall::ResendNeeded {
                seq,
                needed: ResendNeeded {
                    sender,
                    accepted_from_ms,
                    accepted_until_ms,
                    reason: if unreadable {
                        ResendReason::Unreadable
                    } else {
                        ResendReason::Unopenable
                    },
                },
            },
            Self::Missed {
                seq,
                entries,
                accepted_from_ms,
                accepted_until_ms,
            } => RefusedCall::Missed(MissedEntries {
                seq,
                entries,
                accepted_from_ms,
                accepted_until_ms,
            }),
            Self::Deny {
                generation,
                seq,
                pubky,
                added,
                at_ms,
            }
            | Self::DenyUnverified {
                generation,
                seq,
                pubky,
                added,
                at_ms,
                ..
            } => RefusedCall::DenyListChanged(DenyListChange {
                generation,
                seq,
                pubky,
                added,
                at_ms,
            }),
        }
    }
}

/// What checking a deny list operation came to ([`App::check_deny_op`]).
enum DenyCheck {
    /// The identity's own: applied and handed.
    Genuine,
    /// Not the identity's own, for this reason: refused, with an event.
    NotGenuine(&'static str),
    /// Its writer's certificate couldn't be looked up yet: owed, checked again later.
    NotYet,
    /// The directory answered without its writer, as for one revoked since: a gap.
    Unverifiable,
}

impl From<&DenyListChange> for OwedCall {
    fn from(change: &DenyListChange) -> Self {
        Self::Deny {
            generation: change.generation,
            seq: change.seq,
            pubky: change.pubky,
            added: change.added,
            at_ms: change.at_ms,
        }
    }
}

/// An entry as the feed carries it, or as the app stored it.
struct Entry {
    /// The `seq` it was read at, in `generation`.
    seq: u64,
    generation: u64,
    /// Its local ID when it is stored locally ([`ParkedEntry`]).
    stored: Option<u64>,
    sender: [u8; 32],
    cert: SignedDoc,
    accepted_at_ms: u64,
    context: Option<serde_json::Value>,
}

/// The read in progress: the writes since the last commit and where the cursor is held.
struct Read {
    tx: Tx,
    /// The lowest `seq` held in this read (held entries, or entries retried next read).
    blocked: Option<u64>,
    /// The own data epoch rose: fetch the key bundle after the page.
    epoch_rose: bool,
    /// The (sender, `msg_id`) pairs processed in this read and not yet committed, with
    /// their message hashes (Switch spec 11).
    pairs: HashMap<([u8; 32], String), [u8; 32]>,
    /// A `missed` item owed a listing of the collections: no later item of the read is
    /// processed before it (Switch wire 7.4.4).
    list_first: bool,
    /// A call of this page the protocol didn't take, or a deny list gap it noted: the page
    /// stops after its item, so nothing later is handed before it (Switch spec 8.3).
    held_after: bool,
    /// The restore's check of the held cursor as this page settled it, taken once the
    /// page's commit is done.
    restore_cursor: Option<super::held_cursor::RestoreCursor>,
}

/// How a page of the feed ended, when the read didn't stop on it.
enum PageEnd {
    /// Processed to its end; whether the feed has more.
    Read { more: bool },
    /// Processed through the `missed` item at this `seq`, which owes a listing of the
    /// collections, made before any later item is processed (Switch wire 7.4.4).
    ListFirst(u64),
    /// Processed through the item at this `seq`, and stopped there on the call's time
    /// budget: the next read goes on after it.
    Budget(u64),
}

impl Read {
    fn new(tx: Tx, blocked: Option<u64>) -> Self {
        Self {
            tx,
            blocked,
            epoch_rose: false,
            pairs: HashMap::new(),
            list_first: false,
            held_after: false,
            restore_cursor: None,
        }
    }

    /// A read outside the feed, for a copy taken from the directory or the Homeserver.
    fn outside(tx: Tx) -> Self {
        Self::new(tx, None)
    }

    fn block(&mut self, seq: u64) {
        self.blocked = Some(self.blocked.map_or(seq, |b| b.min(seq)));
    }
}

/// The least time, device clock, between two reads of one identity's `identity.json` that
/// a failed check makes: of a sender's, a failed check 7 against a held copy (Switch wire
/// 5.1 check 7), and of a recipient's, an answer of its switch that doesn't verify with the
/// key the held copy names (Switch spec 4.3). Within it, an entry of the sender failing the
/// check in a later read is held, not dropped, until the first read after it reads the
/// document again; a message to the recipient stays queued.
pub const SENDER_REREAD_MS: u64 = 60_000;

/// When a failed check 7 last had a sender's `identity.json` read again: the device time,
/// the read it came in ([`App::receive`]'s count), and whether the document could be read.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SenderReread {
    at_ms: u64,
    read: u64,
    reached: bool,
}

/// Whether `stored` is tried again now: an entry tried again at all, and, for one that
/// waits for a scope key, once no key of its epoch is missing (`gaps`) and the keys held
/// (`keys_held`) changed since its step last ran: a step whose key the certificate is never
/// given, or whose keys the app holds already, runs again only once a key comes.
fn due_again(stored: &ParkedEntry, gaps: &super::keys::KeyGaps, keys_held: u64) -> bool {
    stored.reason.tried_again()
        && stored.reason.awaited_epoch().is_none_or(|data_epoch| {
            !gaps.covers(data_epoch) && stored.keys_at.is_none_or(|at| at != keys_held)
        })
}

impl App {
    /// Read the feed to its end and process it (Switch spec 8.2, 8.3), then delete the
    /// retired receive keys the cursor passed, rotate if due, and send a deferred cursor
    /// move that is due. `wait` long-polls the first page, at most 25 seconds, and holds
    /// the app meanwhile: a host that goes on calling it waits with [`App::feed_wait`]
    /// instead and reads with no wait. Before the feed, the batches kept from earlier calls
    /// are sent again, at most [`KEPT_RESENDS_PER_READ`](super::KEPT_RESENDS_PER_READ);
    /// one that still can't be sent stays kept and is reported in this read's report
    /// ([`AppEvent::KeptBatchesWaiting`]), and the read goes on. A read that stops on a
    /// budget says so ([`ReceiveReport::more`]).
    ///
    /// **Worst case.** A read reads at most [`FEED_PAGES_PER_READ`] pages, and stops between
    /// two items, never inside a batch's items; the next read goes on from where it got
    /// (`feed_at`). The time budget ([`super::AppConfig::call_budget_ms`], 20 s by default)
    /// bounds the steps that loop: the kept batches, the listing, the stored entries, the
    /// feed and the rereads. Once it is spent each of them starts no further unit after its
    /// first, a kept batch, a listing page, a stored entry, a page or a reread, which it
    /// makes whatever the time with the requests that unit needs (a kept batch's time
    /// sample, its send again after `409 stale_generation`, and its attempts' checks, the
    /// claim reads and, for a proof of another state, the `failed` write; a stored entry's
    /// own requests, as a feed item's), so no step waits for ever behind a slow one. It doesn't
    /// bound the whole read:
    /// - an item processed after it still makes its own requests, its sender's
    ///   `identity.json` and its effect's batch;
    /// - the read's other steps take no budget and make their requests whatever the time,
    ///   among them the admission lists' refresh, the kept effect, the owed record
    ///   delivery, the owed calls, the scope keys and key bundle parts, the records'
    ///   reopening, the entries' writers, the own record's publication, the receive key
    ///   rotation and the cursor move;
    /// - a move or provider change met during the read is followed, which the budget doesn't
    ///   bound either, and the read then goes on once more under the same budget.
    ///
    /// So a read ends after its budget, the first unit of each looping step and the
    /// requests of the item it stopped on and of those other steps, each request within its
    /// timeout. Once the budget is spent, the rest of a page already downloaded is dropped,
    /// past the items processed, and the next read downloads that page again.
    ///
    /// **Order.** The kept batches go before the feed, oldest first, and no later write
    /// through [`App::submit_batch`], [`App::write_claim`], the record writes or the
    /// admission writes overtakes them. The read's own writes aren't kept
    /// batches: the effects of the messages it processes, its cursor moves and a rotation
    /// go as the read makes them, also when it left kept batches unsent, on its budget or
    /// because their resend failed. So a read's own write may reach the switch before a
    /// host's write kept from an earlier call.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`] for a stopped or departed app; an alarm the
    /// read raised; [`AppError::NotAnsweringAsAccount`] while the account may be erased
    /// (Switch spec 12.7); a kept batch whose record doesn't read
    /// ([`crate::error::StoreError::Corrupt`]), at every read until the store is repaired or
    /// restored; a failed call or commit, after which nothing past the last commit counts
    /// and the next read resumes from the store.
    pub async fn receive(&mut self, wait: Option<u32>) -> Result<ReceiveReport, AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.reopen_failures = 0;
            let budget = self.begin_budget();
            let result = self.receive_once(wait, &budget).await;
            // A move, a provider change, a revocation or an erasure met during the read is
            // followed (`provider.rs`), and the read goes on once at the service followed.
            let result = match self.take_over(result).await {
                TakeOver::Done(result) => result,
                TakeOver::ReadAgain => self.receive_once(None, &budget).await,
            };
            // A reopening outside a read is tried whenever it is asked for.
            self.reopen_failures = 0;
            if result.is_err() {
                self.reload = true;
            }
            let mut report = result?;
            if let Some(notice) = self.awaiting_keys_notice() {
                self.events.push(notice);
            }
            // A read that stopped stops at the same place until something no wait on the
            // feed shows changes ([`super::Woken::ReadLater`]).
            if report.stopped {
                self.next_wait = super::wait::NextWait::Later;
            }
            self.read_done_ms = Some(self.now());
            report.events = self.take_events();
            Ok(report)
        })
        .await
    }

    /// One read. [`AppEvent::KeptBatchesWaiting`] goes only in the report of the read that
    /// met it: a read that fails drops it, its error being the outcome, so no later report
    /// carries a stale one.
    async fn receive_once(
        &mut self,
        wait: Option<u32>,
        budget: &super::CallBudget,
    ) -> Result<ReceiveReport, AppError> {
        let raised = self.events.len();
        let result = self.receive_inner(wait, budget).await;
        if result.is_err() {
            let mut index = 0;
            self.events.retain(|event| {
                index += 1;
                index <= raised || !matches!(event, AppEvent::KeptBatchesWaiting { .. })
            });
        }
        result
    }

    fn receive_inner<'a>(
        &'a mut self,
        wait: Option<u32>,
        budget: &'a super::CallBudget,
    ) -> crate::transport::BoxFuture<'a, Result<ReceiveReport, AppError>> {
        // A read's large steps are boxed one by one, so that no poll frame holds the state
        // of the step under it. In a debug build, the paths
        // `test_receive_runs_on_a_one_mebibyte_stack` runs fit in a 1 MiB thread.
        Box::pin(self.receive_inner_body(wait, budget))
    }

    async fn receive_inner_body(
        &mut self,
        wait: Option<u32>,
        budget: &super::CallBudget,
    ) -> Result<ReceiveReport, AppError> {
        self.reads_begun = self.reads_begun.wrapping_add(1);
        self.held_cursor_read = None;
        // Where a wait for the feed starts once this read is done ([`App::feed_wait`]): set
        // again by a read that gets that far.
        self.next_wait = super::wait::NextWait::Cursor;
        if matches!(self.state.alarm, Some(Alarm::Compromise { .. })) {
            self.leave_on_compromise().await;
        }
        self.refuse_when_halted()?;
        self.finish_join().await?;
        if let Some(report) = self.follow_provider_change().await? {
            return Ok(report);
        }
        if let Some(stop) = self.not_current_here() {
            self.push_once(stop);
            return Ok(ReceiveReport {
                stopped: true,
                cursor: self.cursor(),
                ..ReceiveReport::default()
            });
        }
        if self
            .state
            .restore
            .as_ref()
            .is_some_and(|restore| !restore.key_checked)
        {
            match self.take_listed_cert().await? {
                super::renewal::Listed::Key(current) => {
                    // That was this read's look for a listed renewal: none again just after.
                    let me = self.state.meta.app_id;
                    if self
                        .state
                        .own_doc
                        .listed_cert(&me)
                        .is_some_and(|listed| listed != self.state.cert.hash())
                    {
                        self.renewal_looked_ms = Some(self.now());
                    }
                    self.check_key_after_restore(current).await?;
                }
                // A newer own document the directory brought: the next read follows it.
                super::renewal::Listed::NotCurrentHere => {
                    if let Some(stop) = self.not_current_here() {
                        self.push_once(stop);
                    }
                    return Ok(ReceiveReport {
                        stopped: true,
                        cursor: self.cursor(),
                        ..ReceiveReport::default()
                    });
                }
            }
        }
        // A renewed certificate is taken before the kept effect goes again: the effect may
        // wait on it, refused for the expired one (`403 cert_expired`). So is one another
        // device took, which the feed showed only as a stub.
        self.adopt_renewal().await?;
        if matches!(
            self.take_renewal_listed_elsewhere().await?,
            Some(super::renewal::Listed::NotCurrentHere)
        ) {
            if let Some(stop) = self.not_current_here() {
                self.push_once(stop);
            }
            return Ok(ReceiveReport {
                stopped: true,
                cursor: self.cursor(),
                ..ReceiveReport::default()
            });
        }
        // A copy of the lists not known to be complete owes the protocol a deny list gap,
        // which this read tells after the owed calls and before any entry, the ones stored
        // locally included, is handed over, the copy taken from the same answer.
        self.refresh_lists_if_owed().await?;
        self.resume_pending_effect().await?;
        // The batches kept from earlier calls go before the feed, and before anything the
        // read writes itself, so a lost answer is settled by this read (Switch wire 6.4
        // step 5).
        let (waiting, kept_left) = self.resume_batches_before_feed(Some(budget)).await?;
        if let Some(waiting) = waiting {
            self.events.push(waiting);
        }
        // The record's delivery goes before the feed. A record the switch accepts here is
        // published here too: accepting the `app.put` shows the app current, as the feed
        // would (Switch spec 4.2, `own_record.rs`). That is the read's one publication: a
        // write that failed here isn't tried again after the feed.
        let published = self.deliver_pending_record().await?;
        if published {
            self.publish_owed(false, true).await?;
        }
        self.ensure_scope_keys().await?;
        self.prune_processed().await?;
        self.retell_restored().await?;
        // The bounds on entries stored unverified go before any is tried again (Switch
        // spec 8.2).
        self.bound_unverified().await?;
        // A listing owed comes before any entry is handed to the protocol, one stored
        // locally or an owed call included (Switch spec 8.2, wire 7.4.4). One that can't be
        // made yet, for want of a scope key, ends the read here: receiving waits for the
        // key, and nothing is passed or lost meanwhile; so does one that needs more pages
        // than the read's budget, which the next read goes on with. At most one listing a
        // read, so a switch that shows one `missed` item after another can't make a read
        // list again and again: a later item that owes one ends the read, and the next read
        // lists first.
        let mut pages = LISTING_PAGES_PER_READ;
        let mut listing = self
            .list_collections_if_due(&mut pages, Some(budget))
            .await?;
        if listing == Listing::WaitsForKey {
            // The key a listing waits for comes in a key bundle part, which the feed would
            // show only past this point: fetched here, then the listing tried once more.
            self.fetch_key_parts().await?;
            listing = self
                .list_collections_if_due(&mut pages, Some(budget))
                .await?;
        }
        let waits_for_key = listing == Listing::WaitsForKey;
        let unfinished = listing == Listing::Unfinished;
        let mut listed = listing == Listing::Listed;
        // A listing this read made before any item covers a gap ahead its first page shows.
        self.listed_before_items = listed;
        // The reopening a key taken owes, a failure's from before included, before anything
        // is handed over that may read the records it opens; only an alarm it raises fails
        // the read.
        self.reopen_if_due().await?;
        let mut report = ReceiveReport {
            more: kept_left || unfinished,
            ..ReceiveReport::default()
        };
        // Where a wait for the feed starts once this read is done ([`App::feed_wait`]).
        let mut reached = None;
        // The read's listing waits for a scope key: no wait on the feed shows the key
        // arrive, so the host reads again after a pause ([`super::Woken::ReadLater`]).
        let mut key_wait = waits_for_key;
        // The entries waiting for a key that are due when the retries begin; those a fetch
        // later in the read brings the key of are tried again at its end.
        let mut due_at_start = Vec::new();
        // The owed calls first, in feed order: a deny list change or gap the protocol must
        // take before anything later stops the read while it fails, nothing handed (Switch
        // spec 8.3).
        let owed_held = !waits_for_key && !unfinished && {
            self.retry_owed().await?;
            let calls_held = self.owed_known == Some(true);
            calls_held || self.tell_deny_gap_if_owed().await?
        };
        // A call a protocol still owes holds that protocol, and counts as a read held for the
        // host's notice; a deny list change or gap, or a call every protocol owes, stops the
        // read.
        if owed_held || !self.owing.is_empty() {
            self.owed_held_reads = self.owed_held_reads.saturating_add(1);
            if self.owed_held_reads >= RETRY_EVENT_READS {
                self.events.push(AppEvent::OwedCallHeld {
                    reads: self.owed_held_reads,
                });
            }
        } else {
            self.owed_held_reads = 0;
        }
        if owed_held {
            report.stopped = true;
        }
        if waits_for_key {
            // Receiving waits for the key, and the read says so. The feed item that would
            // answer the full-bundle request isn't read meanwhile, so the request is made
            // again at a bounded interval: the signer's answer may have lacked the key.
            // The read's upkeep below goes on.
            self.ask_again_while_a_listing_waits().await?;
            self.events.push(AppEvent::ListingWaitsForKey);
        } else if !unfinished && !owed_held {
            // The stored entries' retries and the feed to its end.
            // None while a reopening is owed: the retries here skip them then.
            if !self.reader().exists(super::records::REOPEN_DUE).await? {
                due_at_start = self.awaiting_due();
            }
            self.retry_parked(Some(budget)).await?;
            let mut wait = wait.map(|seconds| self.long_poll_seconds(seconds).0);
            // The read position moves on page by page, past a held entry, while the cursor
            // stays before it (Switch spec 8.2); the held `seq` carries over to later pages.
            // A read that a budget stopped left where it got: the next one goes on from
            // there, the held `seq` with it, so the entries held behind the cursor don't take
            // each read's budget again.
            let mut after = self.state.cursor.seq;
            let mut blocked = None;
            let resumed: Option<FeedAt> = self.reader().get(FEED_AT).await?;
            // Not from at or past a call owed ahead of the cursor: the feed stops at that
            // call, so a read going on from there would never come back to the entries held
            // before it, and the cursor would never reach the call. From the cursor, the
            // read hands them once their protocols take what they owe, and the cursor gets
            // to the call (Switch spec 8.3).
            if let Some(at) = resumed
                && at.generation == self.state.cursor.generation
                && at.after >= after
                && self.owed_ahead.is_none_or(|ahead| at.after < ahead)
            {
                after = at.after;
                blocked = at.blocked;
            }
            let mut feed_pages = 0u32;
            loop {
                // At most FEED_PAGES_PER_READ pages, and none past the call's time budget
                // once one is read: the next read goes on from here.
                if feed_pages >= FEED_PAGES_PER_READ || (feed_pages > 0 && self.spent(budget)) {
                    self.feed_goes_on(after, blocked).await?;
                    report.more = true;
                    break;
                }
                feed_pages += 1;
                let generation = self.state.cursor.generation;
                let query = FeedQuery {
                    after: Some(Position {
                        generation,
                        seq: after,
                    }),
                    limit: Some(self.config.page()),
                    wait: wait.take(),
                };
                let result = self.client.feed(query).await;
                let page = self.take(result).await?;
                let scanned = page.scanned_through;
                let ended = self
                    .process_page(page, after, &mut blocked, Some(budget))
                    .await;
                self.listed_before_items = false;
                match ended? {
                    Some(PageEnd::Read { more: true }) => {
                        after = after.max(scanned).max(self.state.cursor.seq);
                    }
                    Some(PageEnd::Read { more: false }) => {
                        // Read to the end: a wait goes on past everything shown, the entries
                        // held behind the cursor included. The next read starts at the
                        // cursor again, and meets them.
                        let seq = after.max(scanned);
                        reached = Some(Position { generation, seq });
                        self.feed_read_to_end().await?;
                        break;
                    }
                    Some(PageEnd::Budget(through)) => {
                        after = after.max(through).max(self.state.cursor.seq);
                        self.feed_goes_on(after, blocked).await?;
                        report.more = true;
                        break;
                    }
                    // The listing a `missed` item owes, before any later item: ending the page's
                    // processing at the item and committing it keeps the cursor rules as they
                    // are, the listing's own commits never interleaving with a page's open
                    // writes. A listing that can't be made yet, for want of a scope key, ends
                    // the read there, and the host reads again after a pause; the next read
                    // lists first, and so does one past the read's one listing or its page
                    // budget, which the report says.
                    Some(PageEnd::ListFirst(through)) => {
                        // The page is committed through the `missed` item: a read that stops
                        // here for the listing keeps where it got, as a budget's stop does.
                        if listed {
                            self.feed_goes_on(after.max(through), blocked).await?;
                            report.more = true;
                            break;
                        }
                        let mut listing = self
                            .list_collections_if_due(&mut pages, Some(budget))
                            .await?;
                        if listing == Listing::WaitsForKey {
                            self.fetch_key_parts().await?;
                            listing = self
                                .list_collections_if_due(&mut pages, Some(budget))
                                .await?;
                        }
                        match listing {
                            Listing::Listed => listed = true,
                            Listing::Unfinished => {
                                self.feed_goes_on(after.max(through), blocked).await?;
                                report.more = true;
                                break;
                            }
                            Listing::WaitsForKey | Listing::NotDue => {
                                key_wait = true;
                                break;
                            }
                        }
                        after = after.max(through);
                    }
                    None => {
                        report.stopped = true;
                        break;
                    }
                }
            }
        }
        if self.state.alarm.is_none() {
            // What a fetch between pages owes, such as at a `missed` item's listing, before
            // the entries a key brought are tried again.
            self.reopen_if_due().await?;
            // A stopped read leaves the claims and records it marked for the next one, and so
            // do one that waits for a key and one whose listing goes on at the next read. A
            // read that read its feed publishes once the feed shows the app current. One that
            // waits for a key, or whose listing goes on, read no feed, so it publishes as a
            // call outside a read does: what is owed goes, and an app whose devices share its
            // keys writes no missing copy back (Switch spec 4.2).
            if waits_for_key || unfinished {
                if !published {
                    self.publish_owed(false, false).await?;
                }
            } else if !report.stopped {
                // Nothing is handed over while a listing is owed (Switch spec 8.2).
                if !self.reader().exists(super::records::LIST_DUE).await? {
                    self.retry_awaited(&due_at_start, Some(budget)).await?;
                }
                let claims_left = self.reread_claims(Some(budget)).await?;
                let records_left = self.reread_records(Some(budget)).await?;
                report.more |= claims_left || records_left;
                self.fetch_entry_writers().await?;
                if !published {
                    self.publish_owed(false, true).await?;
                }
            }
            self.delete_retired_keys().await?;
            self.forget_chain_behind_cursor().await?;
            self.maybe_rotate().await?;
            self.flush_cursor_if_due().await?;
        }
        // Entries the cursor stays before come again at each read, with nothing new on the
        // feed: a wait past them ends in a read when nothing comes.
        let again = !self.state.held.is_empty() || !self.state.retries.is_empty();
        self.next_wait = if key_wait {
            super::wait::NextWait::Later
        } else {
            reached
                .filter(|position: &Position| position.generation == self.state.cursor.generation)
                .map_or(super::wait::NextWait::Cursor, |position| {
                    super::wait::NextWait::From(super::wait::WaitFrom { position, again })
                })
        };
        report.cursor = self.cursor();
        report.held_cursor = self.held_cursor_read.take();
        Ok(report)
    }

    /// Keep where a read that stopped with more to do got to (`feed_at`): the next read goes
    /// on from `after`, with the lowest `seq` held so far.
    async fn feed_goes_on(&mut self, after: u64, blocked: Option<u64>) -> Result<(), AppError> {
        let at = FeedAt {
            generation: self.state.cursor.generation,
            after,
            blocked,
        };
        let mut tx = self.tx()?;
        tx.put(FEED_AT, &at)?;
        self.commit(tx).await
    }

    /// A read reached the feed's end: the next one starts at the cursor again.
    async fn feed_read_to_end(&mut self) -> Result<(), AppError> {
        if self.reader().exists(FEED_AT).await? {
            let mut tx = self.tx()?;
            tx.delete(FEED_AT)?;
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// One page, read after `after`, with the lowest `seq` held so far in this read: how it
    /// ended, or `None` when the read stops on it.
    fn process_page<'a>(
        &'a mut self,
        page: FeedPage,
        after: u64,
        blocked: &'a mut Option<u64>,
        budget: Option<&'a super::CallBudget>,
    ) -> crate::transport::BoxFuture<'a, Result<Option<PageEnd>, AppError>> {
        // Boxed, as `receive_inner` says.
        Box::pin(self.process_page_body(page, after, blocked, budget))
    }

    async fn process_page_body(
        &mut self,
        page: FeedPage,
        after: u64,
        blocked: &mut Option<u64>,
        budget: Option<&super::CallBudget>,
    ) -> Result<Option<PageEnd>, AppError> {
        let now = self.now();
        let multi = self.state.device.multi_device;
        let Some(chain) = self.state.chain.as_mut() else {
            return Err(Refusal::NotNow("the app isn't registered".into()).into());
        };
        let restore_at_read = chain.restore;
        let checked = match chain.feed_page(&page, now, multi) {
            Ok(checked) => checked,
            Err(AppError::Alarm(alarm)) => return Err(self.raise(alarm).await),
            Err(error) => return Err(error),
        };
        if restore_at_read == Some(super::state::RestorePending::Read) {
            chain.restore = None;
        }
        let history_gap = checked.gap.map(|(verified_seq, _)| verified_seq);
        if let Some((verified_seq, checkpoint_seq)) = checked.gap {
            self.events.push(AppEvent::ContinuityUnverified {
                verified_seq,
                checkpoint_seq,
            });
        }
        let start = after;
        if page.scanned_through < start || (page.more && page.scanned_through == start) {
            return Err(AppError::InvalidData(
                "Switch wire 7.4.4: a page that doesn't move past the position asked".into(),
            ));
        }
        // Held entries lie after the cursor, so each read meets each again before any later
        // item, and blocks the cursor there if it is still held; later pages of the read
        // carry the block on.
        let mut read = Read::new(self.tx()?, *blocked);
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut read.tx)?;
        }
        // Continuity unverified starts reconcile mode anew: every protocol reconciles again,
        // whichever ended the mode before (Switch spec 12.4 step 2.4).
        if history_gap.is_some() {
            read.tx.delete(key::RECONCILED)?;
        }
        // Items behind a checkpoint never come: the deny list's history has a gap, which
        // the protocol is told, with the list read after it, before anything of the page
        // (Switch spec 8.3, 12.4).
        if let Some(verified_seq) = history_gap
            && self
                .note_deny_gap(self.state.cursor.generation, verified_seq, &mut read.tx)
                .await?
        {
            self.end_page(read).await?;
            return Ok(None);
        }
        if let Some(freeze) = &page.freeze {
            // Nothing on a frozen service's page is processed: its items come again from
            // the next service (`provider.rs`).
            self.end_page(read).await?;
            self.note_freeze(freeze).await?;
            return Ok(None);
        }
        // The cursor the service holds, before anything of the page is processed, and not
        // a frozen service's (Switch spec 8.3, 12.4).
        let compared = self.compare_held_cursor(page.cursor).await?;
        let mut stopped = None;
        let mut list_through = None;
        if let Some(check) = compared.restore {
            read.tx.put(key::RESTORE_CURSOR, &check)?;
            read.restore_cursor = Some(check);
        }
        if let Some((held, position)) = compared.gap {
            // The gap ahead is handled as a `missed` item at the page's start: the
            // protocol is handed it, and a listing is owed, made before any item of the
            // page, unless this read made one before any item, as after a restore (Switch
            // spec 8.3 "Ahead", 12.4 condition 4).
            let listed = self.listed_before_items;
            self.hand_held_gap(held, position, !listed, &mut read)?;
            if !listed {
                list_through = Some(start);
            }
            // The gap's call failed: owed, and nothing of the page is handed before it.
            if read.held_after {
                stopped = Some(start.saturating_add(1));
            }
        }
        // The last item processed, and where the call's time budget stopped the page.
        let mut processed: Option<u64> = None;
        let mut budget_through = None;
        let batch_of = |seq: u64| {
            checked
                .envelopes
                .get(&seq)
                .and_then(|e| e.batch)
                .map(|b| b.id)
        };
        // A stub names no object: once the page shows the stub of an operation, the claims
        // the app follows are read again at the end of the read (Switch wire 7.5), noted in
        // the commit that passes it.
        let mut stub_noted = !self.state.cert.has_permission(Permission::ClaimsRead);
        for item in &page.items {
            if stopped.is_some() {
                break;
            }
            let seq = item.seq();
            if seq <= start {
                continue;
            }
            // An owed call carried past the cursor: the feed hands nothing after its item,
            // and not the item itself, whose call is the one owed; the next read makes it
            // (Switch spec 8.3).
            if let Some(ahead) = self.owed_ahead
                && seq >= ahead
            {
                // Never past an entry held behind it: the cursor stays before that entry,
                // and the call waits until the cursor gets there.
                let passes = seq == ahead && read.blocked.is_none_or(|b| seq < b);
                if passes {
                    self.pass(seq, item, &mut read)?;
                }
                stopped = Some(seq.saturating_add(u64::from(passes)));
                break;
            }
            if list_through.is_some() && !matches!(item, FeedItem::Missed { .. }) {
                break;
            }
            // Past the call's time budget the read stops between two items, once it has
            // processed one, and never inside a batch's items, which a page always carries
            // whole (Switch wire 7.4.4).
            if let (Some(budget), Some(last)) = (budget, processed)
                && (batch_of(last).is_none() || batch_of(last) != batch_of(seq))
                && self.spent(budget)
            {
                budget_through = Some(last);
                break;
            }
            // Room for one more item, whatever it writes: the read's writes so far are
            // committed first once they pass the high-water mark (`ITEM_ROOM_BYTES`).
            self.make_room(&mut read, ITEM_ROOM_BYTES).await?;
            let step = match item {
                // Processed past a held entry in an earlier read.
                FeedItem::Entry(_) if self.state.seen.contains(&seq) => Step::Pass,
                FeedItem::Entry(entry) => self.handle_entry(entry, &mut read).await?,
                FeedItem::Unreadable {
                    seq,
                    sender,
                    accepted_at,
                    ..
                } => self.handle_unreadable(*seq, *sender, *accepted_at, &mut read)?,
                FeedItem::Missed {
                    seq,
                    entries,
                    accepted_from,
                    accepted_until,
                } => self.handle_missed(
                    *seq,
                    *entries,
                    accepted_from.zip(*accepted_until),
                    &mut read,
                )?,
                FeedItem::Chain(chain_item) => {
                    let Some(envelope) = checked.envelopes.get(&seq).copied() else {
                        continue;
                    };
                    self.handle_chain(chain_item, &envelope, &mut read).await?
                }
                FeedItem::Stub { .. } => {
                    if !stub_noted
                        && checked
                            .envelopes
                            .get(&seq)
                            .is_some_and(|envelope| envelope.item_type == ItemType::Op)
                    {
                        read.tx.put(super::claims::STUB_SEEN, &())?;
                        stub_noted = true;
                    }
                    Step::Pass
                }
            };
            match step {
                Step::Pass => {
                    // Processed, or stored locally with its count under its local ID.
                    self.clear_retry(seq, &mut read)?;
                    if read.blocked.is_none_or(|b| seq < b) {
                        self.pass(seq, item, &mut read)?;
                    } else if matches!(item, FeedItem::Entry(_)) && !self.state.seen.contains(&seq)
                    {
                        read.tx.put(&key::seen(seq), &())?;
                        self.state.seen.insert(seq);
                    }
                }
                Step::Hold => read.block(seq),
                Step::Stop => {
                    stopped = Some(seq);
                    break;
                }
            }
            processed = Some(seq);
            if self.state.alarm.is_some() {
                stopped = Some(seq);
                break;
            }
            // A call the protocol didn't take, or a deny list gap: passed and owed, and nothing
            // after it is handed until the protocol takes it (Switch spec 8.3).
            if read.held_after {
                stopped = Some(seq.saturating_add(1));
                break;
            }
            // Switch wire 7.4.4: the listing a `missed` item owes comes before any later
            // item is processed but another `missed` item, which only tells the protocol and
            // owes the same listing.
            if read.list_first {
                list_through = Some(seq);
            }
        }
        let through = list_through
            .or(budget_through)
            .unwrap_or(page.scanned_through);
        let end = match (stopped, read.blocked) {
            (Some(stop), _) => stop
                .saturating_sub(1)
                .min(read.blocked.map_or(u64::MAX, |b| b.saturating_sub(1))),
            (None, Some(blocked)) => blocked.saturating_sub(1).min(through),
            (None, None) => through,
        };
        if end > self.state.cursor.seq {
            self.state.cursor.seq = end;
        }
        let epoch_rose = read.epoch_rose;
        *blocked = read.blocked;
        self.end_page(read).await?;
        if epoch_rose && self.state.alarm.is_none() {
            self.fetch_key_parts().await?;
        }
        // A key a fetch took on the page opens what the page's committed writes hold
        // `Unreadable` (Switch spec 3.5).
        self.reopen_if_due().await?;
        if stopped.is_some() {
            return Ok(None);
        }
        if let Some(through) = list_through {
            return Ok(Some(PageEnd::ListFirst(through)));
        }
        if let Some(through) = budget_through {
            return Ok(Some(PageEnd::Budget(through)));
        }
        Ok(Some(PageEnd::Read { more: page.more }))
    }

    /// Commit the page: the cursor, deferred when it moved past what the service holds,
    /// and the entries processed past a held one that the cursor has now passed.
    async fn end_page(&mut self, mut read: Read) -> Result<(), AppError> {
        let cursor = self.state.cursor.seq;
        if cursor > self.state.cursor.at_service && self.state.cursor.deferred_since_ms.is_none() {
            self.state.cursor.deferred_since_ms = Some(self.now());
        }
        let passed: Vec<u64> = self.state.seen.range(..=cursor).copied().collect();
        for seq in passed {
            read.tx.delete(&key::seen(seq))?;
            self.state.seen.remove(&seq);
        }
        let asked: Vec<u64> = self.state.asked.range(..=cursor).copied().collect();
        for seq in asked {
            read.tx.delete(&key::asked(seq))?;
            self.state.asked.remove(&seq);
        }
        read.tx.put(key::CURSOR, &self.state.cursor)?;
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut read.tx)?;
        }
        self.commit(read.tx).await?;
        if let Some(check) = read.restore_cursor {
            self.state.restore_cursor = Some(check);
        }
        Ok(())
    }

    /// An item the cursor passes: its acceptance time becomes the cursor's.
    fn pass(&mut self, seq: u64, item: &FeedItem, read: &mut Read) -> Result<(), AppError> {
        let accepted = match item {
            FeedItem::Entry(entry) => Some(entry.accepted_at),
            FeedItem::Unreadable { accepted_at, .. } => Some(*accepted_at),
            _ => None,
        };
        if let Some(at) = accepted {
            self.state.cursor.time_ms = self.state.cursor.time_ms.max(at);
        }
        self.state.cursor.seq = self.state.cursor.seq.max(seq);
        if self.state.held.remove(&seq).is_some() {
            read.tx.delete(&key::held(seq))?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // Entries

    fn handle_entry<'a>(
        &'a mut self,
        item: &'a EntryItem,
        read: &'a mut Read,
    ) -> crate::transport::BoxFuture<'a, Result<Step, AppError>> {
        // Boxed, as `receive_inner` says.
        Box::pin(self.handle_entry_body(item, read))
    }

    async fn handle_entry_body(
        &mut self,
        item: &EntryItem,
        read: &mut Read,
    ) -> Result<Step, AppError> {
        let entry = Entry {
            seq: item.seq,
            generation: self.state.cursor.generation,
            stored: None,
            sender: item.sender,
            cert: item.cert.clone(),
            accepted_at_ms: item.accepted_at,
            context: item.context.clone(),
        };
        let header = match parse_header(&item.envelope) {
            Ok(header) => header,
            Err(error) => return Ok(self.dropped(entry.seq, 1, error.to_string())),
        };
        let current = self.state.receive_keys.keys().next_back().copied();
        let opener = header.kids().find_map(|kid| {
            self.state
                .receive_keys
                .values()
                .find(|held| held.key.kid == kid)
                .map(|held| (held.key.n, held.key.secret()))
        });
        let Some((n, secret)) = opener else {
            return self.unopenable(&entry, read);
        };
        let identity = self.state.meta.identity;
        let plaintext = match MessagePlaintext::open(&item.envelope, &identity, &secret) {
            Ok(plaintext) => plaintext,
            Err(error) => return Ok(self.dropped(entry.seq, 1, error.to_string())),
        };
        if Some(n) == current && !self.state.rotation.opened_since {
            self.state.rotation.opened_since = true;
            read.tx.put(key::ROTATION, &self.state.rotation)?;
        }
        self.check_and_apply(&entry, plaintext, false, read).await
    }

    /// Checks 2 to 9, then the protocol's check 10 and effect.
    fn check_and_apply<'a>(
        &'a mut self,
        entry: &'a Entry,
        plaintext: MessagePlaintext,
        parked: bool,
        read: &'a mut Read,
    ) -> crate::transport::BoxFuture<'a, Result<Step, AppError>> {
        // Boxed, as `receive_inner` says.
        Box::pin(self.check_and_apply_body(entry, plaintext, parked, read))
    }

    async fn check_and_apply_body(
        &mut self,
        entry: &Entry,
        plaintext: MessagePlaintext,
        parked: bool,
        read: &mut Read,
    ) -> Result<Step, AppError> {
        let held = self.sender_doc(&entry.sender, false).await?;
        let read_now = held.as_ref().is_some_and(|(_, read_now)| *read_now);
        let doc = held.map(|(doc, _)| doc);
        // Only the opaque members of the kind's own protocol apply to its body.
        let opaque = self.protocols.opaque_of_json(plaintext.json());
        let mut checked = self.check_entry(entry, &plaintext, doc.as_ref(), &opaque);
        // Check 7 judges the standing in the sender's newest `identity.json` (Switch wire 5.1):
        // a held copy that doesn't list the certificate may be older than a renewal or a new
        // app, so it is read again once before the entry is dropped.
        if doc.is_some()
            && !read_now
            && matches!(&checked, Err(CheckRefusal::Dropped { check: 7, .. }))
        {
            checked = self
                .check_against_newer_copy(entry, &plaintext, checked, &opaque)
                .await?;
        }
        let received = match checked {
            Ok(received) => received,
            Err(CheckRefusal::Dropped { check, reason }) => {
                self.unpark(entry.stored, &mut read.tx)?;
                return Ok(self.dropped(entry.seq, check, reason));
            }
            Err(CheckRefusal::Duplicate { conflicting }) => {
                self.events.push(AppEvent::Duplicate {
                    seq: entry.seq,
                    conflicting,
                });
                return Ok(Step::Pass);
            }
            Err(CheckRefusal::SenderUnverifiable) => {
                if parked {
                    return Ok(Step::Hold);
                }
                return self.hold_or_park(entry, &plaintext, read);
            }
        };
        // Check 9, with the pairs processed in this read and not committed yet, then the
        // app's own record of processed messages.
        let pair = (entry.sender, received.message.msg_id.clone());
        if let Some(hash) = read.pairs.get(&pair).copied() {
            let conflicting = hash != received.hash();
            self.duplicate(entry, &received.message.msg_id, conflicting, read)?;
            return Ok(Step::Pass);
        }
        let processed: Option<Processed> = self
            .reader()
            .get(&key::processed(&entry.sender, &received.message.msg_id))
            .await?;
        if let Some(seen) = processed {
            let conflicting = seen.hash != received.hash();
            self.duplicate(entry, &received.message.msg_id, conflicting, read)?;
            return Ok(Step::Pass);
        }
        self.apply(entry, received, parked, read).await
    }

    /// Checks 2 to 9 of `entry` against `doc`, the sender's `identity.json` (`None` when it
    /// can't be read now).
    fn check_entry(
        &self,
        entry: &Entry,
        plaintext: &MessagePlaintext,
        doc: Option<&IdentityDoc>,
        opaque: &[OpaqueRule],
    ) -> Result<Received, CheckRefusal> {
        let opened = OpenedEntry {
            sender: entry.sender,
            cert: &entry.cert,
            accepted_at_ms: entry.accepted_at_ms,
        };
        let rules = Rules::new(&self.protocols, &self.state.cert, opaque);
        check_opened(
            plaintext.clone(),
            &opened,
            &self.state.meta.identity,
            doc.map_or(SenderIdentity::Unavailable, SenderIdentity::Held),
            &rules,
            &|_, _| None,
        )
    }

    /// Check 7 failed against a held copy of the sender's `identity.json` (`failed`): the
    /// checks run again against the copy read from the Homeserver now, at most once per
    /// [`SENDER_REREAD_MS`] for one sender, so neither a sender sending certificates its
    /// document doesn't list, nor a Homeserver serving one new version after another, makes
    /// the app read more. No entry is dropped on an answer older than the read it came in:
    /// later entries of the sender in the read that read it again are judged against that
    /// copy, or held when it couldn't be read; in a later read within the window they are
    /// held, and judged against the copy the first read after the window takes. A copy that
    /// can't be read holds the entry, as an unreachable `identity.json` does (Switch wire
    /// 5.1 "A sender that can't be checked", Switch spec 8.2), with later entries processed
    /// past it.
    async fn check_against_newer_copy(
        &mut self,
        entry: &Entry,
        plaintext: &MessagePlaintext,
        failed: Result<Received, CheckRefusal>,
        opaque: &[OpaqueRule],
    ) -> Result<Result<Received, CheckRefusal>, AppError> {
        let now = self.now();
        let read = self.reads_begun;
        let lately = |at: u64| at <= now && now - at < SENDER_REREAD_MS;
        match self.sender_rereads.get(&entry.sender) {
            // Read again in this read: the copy held is the one it took.
            Some(again) if again.read == read && again.reached => return Ok(failed),
            Some(again) if lately(again.at_ms) => {
                return Ok(Err(CheckRefusal::SenderUnverifiable));
            }
            _ => {}
        }
        let again = self.sender_doc(&entry.sender, true).await?;
        self.sender_rereads.retain(|_, again| lately(again.at_ms));
        self.sender_rereads.insert(
            entry.sender,
            SenderReread {
                at_ms: now,
                read,
                reached: again.is_some(),
            },
        );
        let doc = again.map(|(doc, _)| doc);
        Ok(self.check_entry(entry, plaintext, doc.as_ref(), opaque))
    }

    /// An entry whose message was processed before (check 9): passed, and gone if it was
    /// stored locally. One the host released is reported with a duty event in the same
    /// commit, so the host learns that its release ended without the effect.
    fn duplicate(
        &mut self,
        entry: &Entry,
        msg_id: &str,
        conflicting: bool,
        read: &mut Read,
    ) -> Result<(), AppError> {
        if let Some(id) = entry.stored
            && self.released(id)
        {
            self.keep_duty(
                &mut read.tx,
                Duty::ReleasedDuplicate {
                    seq: entry.seq,
                    stored_id: id,
                    sender: entry.sender,
                    msg_id: msg_id.to_owned(),
                    conflicting,
                },
            )?;
        }
        self.unpark(entry.stored, &mut read.tx)?;
        self.events.push(AppEvent::Duplicate {
            seq: entry.seq,
            conflicting,
        });
        Ok(())
    }

    /// Whether the entry stored locally at `id` is one the host released.
    fn released(&self, id: u64) -> bool {
        self.state
            .parked
            .get(&id)
            .is_some_and(|entry| entry.released)
    }

    /// The protocol's check 10, then its effect, at most twice after a conflict: the records
    /// and claims the effect wrote are read again before the second try (Switch spec 8.2,
    /// 10.3).
    fn apply<'a>(
        &'a mut self,
        entry: &'a Entry,
        received: Received,
        parked: bool,
        read: &'a mut Read,
    ) -> crate::transport::BoxFuture<'a, Result<Step, AppError>> {
        // Boxed, as `receive_inner` says.
        Box::pin(self.apply_body(entry, received, parked, read))
    }

    async fn apply_body(
        &mut self,
        entry: &Entry,
        received: Received,
        parked: bool,
        read: &mut Read,
    ) -> Result<Step, AppError> {
        let mut message = ReceivedMessage {
            seq: entry.seq,
            generation: entry.generation,
            sender: entry.sender,
            accepted_at_ms: entry.accepted_at_ms,
            message: received.message.clone(),
            plaintext: received.plaintext.clone(),
            cert: received.cert.clone(),
            standing: received.standing,
            context: entry.context.clone(),
            parked,
            released: entry.stored.is_some_and(|id| self.released(id)),
            conflict: None,
        };
        // The kind's protocol judges the body and builds the effect; a kind no registered
        // protocol owns failed check 8 already.
        let Some(owner) = self.protocols.of_kind(&message.message.kind).cloned() else {
            self.note_processed(entry, &received, &[], read)?;
            return Ok(self.dropped(entry.seq, 8, super::protocols::NO_OWNER.into()));
        };
        // A protocol that owes a call about an earlier feed item takes nothing later first:
        // the entry is held for it, and the read goes on for the other protocols (Switch
        // spec 8.3).
        if self.owing.contains(&owner.name) {
            return Ok(Step::Hold);
        }
        if let Err(reason) = owner.protocol.check_body(&message) {
            self.note_processed(entry, &received, &[], read)?;
            return Ok(self.dropped(entry.seq, 10, reason));
        }
        let mut tries = 0usize;
        // The claims read from the switch at the step's request, for this entry.
        let mut fetched: Vec<([u8; 32], ClaimFetch)> = Vec::new();
        loop {
            let protocol = Arc::clone(&owner.protocol);
            let store = Arc::clone(self.env.store.store());
            let may_attempt = self.may_attempt(false).is_ok();
            let (outcome, writes) = {
                let mut cx = ReceiveContext::new(
                    &self.state,
                    &self.protocols,
                    &owner.name,
                    store.as_ref(),
                    &self.ns,
                    may_attempt,
                    &fetched,
                    read.tx.pending_local(),
                    read.tx.pending_writes(),
                );
                let outcome = protocol.receive(&message, &mut cx);
                (outcome, cx.into_writes())
            };
            let mut effect = match outcome {
                Outcome::Drop { reason } => {
                    self.note_processed(entry, &received, &[], read)?;
                    return Ok(self.dropped(entry.seq, 10, reason));
                }
                Outcome::Need(needs) => match self.read_needs(&needs, &mut fetched).await? {
                    Needs::Read => continue,
                    Needs::Wait => return Ok(Step::Hold),
                    Needs::TooMany => {
                        self.park(entry, &received.plaintext, ParkReason::TooManyReads, read)?;
                        return Ok(Step::Pass);
                    }
                },
                Outcome::Retry(failure) => {
                    return self.retry_later(entry, &received.plaintext, parked, failure, read);
                }
                // Passed, not processed: no processed pair, so a re-send is delivered again
                // (`Outcome::Pass`). Nothing is unparked: an entry stored locally stays so.
                Outcome::Pass => return Ok(Step::Pass),
                Outcome::AwaitKey { data_epoch } => {
                    match self.await_key(entry, &received, data_epoch, read).await? {
                        Some(step) => return Ok(step),
                        None => continue,
                    }
                }
                Outcome::Apply(effect) => effect,
            };
            if writes.not_now.is_some() {
                // A write the effect needs can't be sealed yet, for want of the current data
                // epoch's key: the entry waits for it as for `Outcome::AwaitKey` (Switch spec
                // 3.5, 8.2).
                let data_epoch = self.state.own_doc.data_epoch();
                match self.await_key(entry, &received, data_epoch, read).await? {
                    Some(step) => return Ok(step),
                    None => continue,
                }
            }
            let ContextWrites {
                ops,
                local,
                records,
                claims,
                deadlines,
                not_now: _,
                over_local_bound,
                forget,
            } = writes;
            let forget: Vec<String> = forget.into_iter().collect();
            effect.ops = ops.into_iter().chain(effect.ops).collect();
            effect.local = local.into_iter().chain(effect.local).collect();
            // A step's local writes are bounded (`Protocol`, "Limits a receive step plans
            // for"), its forgets with them: an effect over the bound is too large, stored and
            // passed.
            if over_local_bound
                || local_writes_bytes(&effect.local)
                    .saturating_add(super::forget::forget_bytes(&forget))
                    > MAX_STEP_LOCAL_BYTES
            {
                self.too_large(entry, &received, read).await?;
                return Ok(Step::Pass);
            }
            // From here on the writes are kept and committed under the protocol's prefix.
            effect.local = super::protocols::qualify(&owner.name, effect.local);
            // The app layer's own lifecycle operations aren't a protocol's to write: an effect
            // carrying one is never sent. Its entry is stored and passed, so the feed goes on,
            // and the protocol told, as for an effect refused for good (Switch spec 8.2).
            if super::batch::refuse_lifecycle_ops(effect.ops.iter().map(|(_, kind)| kind)).is_err()
            {
                let stored = self.park(
                    entry,
                    &received.plaintext,
                    ParkReason::LifecycleOperation,
                    read,
                )?;
                self.effect_refused(entry, &received, stored, None, read)?;
                return Ok(Step::Pass);
            }
            if effect.ops.len() >= MAX_BATCH_ENTRIES {
                // Switch wire 6.4: at most 7 operations beside the cursor move. Stored and
                // passed, so the feed goes on (Switch spec 8.2).
                let stored = self.park(
                    entry,
                    &received.plaintext,
                    ParkReason::TooManyOperations,
                    read,
                )?;
                self.effect_refused(entry, &received, stored, None, read)?;
                return Ok(Step::Pass);
            }
            if !self
                .make_room(read, local_size(&self.ns, &effect.local))
                .await?
                || effect.local.iter().any(|write| {
                    matches!(write, LocalWrite::Put { value, .. }
                        if u64::try_from(value.len()).unwrap_or(u64::MAX) > MAX_VALUE_BYTES)
                })
            {
                // Switch spec 8.2: an effect too large for the store is stored and passed,
                // so the feed goes on.
                self.too_large(entry, &received, read).await?;
                return Ok(Step::Pass);
            }
            if effect.ops.is_empty() {
                self.note_processed(entry, &received, &effect.local, read)?;
                for key in &forget {
                    read.tx.delete(key)?;
                }
                self.received_event(entry, &received);
                return Ok(Step::Pass);
            }
            let written = Written {
                records: &records,
                deadlines: &deadlines,
                forget: &forget,
            };
            match self
                .send_effect(entry, &received, effect, written, parked, read)
                .await?
            {
                Sent::Applied => {
                    read.pairs.insert(
                        (entry.sender, received.message.msg_id.clone()),
                        received.hash(),
                    );
                    self.received_event(entry, &received);
                    return Ok(Step::Pass);
                }
                Sent::Conflict(current) => {
                    tries = tries.saturating_add(1);
                    if tries >= EFFECT_TRIES {
                        return Ok(Step::Hold);
                    }
                    message.conflict = Some(current);
                    for (key, read) in self.read_written_again(&records, &claims).await? {
                        if let Some((_, fetch)) = fetched.iter_mut().find(|(k, _)| *k == key) {
                            *fetch = read.map_or(ClaimFetch::Absent, ClaimFetch::Read);
                        }
                    }
                }
                Sent::StaleEpoch => {
                    self.fetch_key_parts().await?;
                    return Ok(Step::Hold);
                }
                Sent::Quota => {
                    self.park(entry, &received.plaintext, ParkReason::Quota, read)?;
                    return Ok(Step::Pass);
                }
                Sent::TooLarge => {
                    self.too_large(entry, &received, read).await?;
                    return Ok(Step::Pass);
                }
                Sent::Refused(code) => {
                    let stored =
                        self.park(entry, &received.plaintext, ParkReason::Refused, read)?;
                    self.effect_refused(entry, &received, stored, Some(code), read)?;
                    return Ok(Step::Pass);
                }
                // A first send isn't a resend; the entry was stored if it ever is.
                Sent::Uncertain => return Ok(Step::Pass),
            }
        }
    }

    /// After `409 conflict` on an effect: the records and claims it wrote, read again from
    /// the switch, so the next effect builds on what it holds (Switch spec 10.3). Returns
    /// the claims as read.
    async fn read_written_again(
        &mut self,
        records: &[([u8; 32], Collection)],
        claims: &[[u8; 32]],
    ) -> Result<Vec<([u8; 32], Option<ClaimRead>)>, AppError> {
        for (key, collection) in records {
            self.fetch_record(key, collection).await?;
        }
        let mut read = Vec::new();
        for claim_key in claims {
            read.push((*claim_key, self.read_claim_inner(claim_key).await?));
        }
        Ok(read)
    }

    /// The reads a receive step asked for ([`Outcome::Need`]), added to `fetched`: each
    /// claim read and checked as [`App::read_claim`] reads it, its view kept in that call's
    /// own commit, which records no cursor move. At most [`MAX_CLAIM_READS`] claims for one
    /// entry, and each once.
    async fn read_needs(
        &mut self,
        needs: &[Need],
        fetched: &mut Vec<([u8; 32], ClaimFetch)>,
    ) -> Result<Needs, AppError> {
        let mut new: Vec<[u8; 32]> = Vec::new();
        for need in needs {
            match need {
                Need::Claim(key) => {
                    if !fetched.iter().any(|(k, _)| k == key) && !new.contains(key) {
                        new.push(*key);
                    }
                }
            }
        }
        if new.is_empty() || fetched.len().saturating_add(new.len()) > MAX_CLAIM_READS {
            return Ok(Needs::TooMany);
        }
        for claim_key in new {
            let fetch = match self.read_claim_inner(&claim_key).await {
                Ok(Some(read)) => ClaimFetch::Read(read),
                Ok(None) => ClaimFetch::Absent,
                Err(error) => match &error {
                    AppError::Switch(_) => match refused_for_good(&error) {
                        Some(code) => ClaimFetch::Refused(code.as_str().to_owned()),
                        // `429`, `503`, an answer that doesn't verify: read again later.
                        None => return Ok(Needs::Wait),
                    },
                    AppError::Transport(_) | AppError::InvalidData(_) => return Ok(Needs::Wait),
                    _ => return Err(error),
                },
            };
            fetched.push((claim_key, fetch));
        }
        Ok(Needs::Read)
    }

    /// A receive step that waits for a scope key of `data_epoch` (Switch spec 3.5, 8.2).
    /// When a key the certificate is given is missing at that epoch, up to the current one,
    /// and no full bundle is asked for yet, the key bundle is fetched: the fetch asks for a
    /// full bundle if a key is still missing, so a key that never comes costs that one
    /// request, and later entries fetch nothing while it is asked for. `None` when the fetch
    /// brought the epoch's keys: the step runs again. After a fetch no other can come for
    /// the entry, since either the epoch's keys are held or a full bundle is asked for
    /// ([`App::key_may_come_by_fetch`]), so the step runs at most twice.
    /// Otherwise the entry is stored locally and passed at once, with no bounded wait
    /// ([`ParkReason::AwaitingKey`]); one stored already for the same epoch stays as it
    /// is. Nothing of the step is committed.
    async fn await_key(
        &mut self,
        entry: &Entry,
        received: &Received,
        data_epoch: u64,
        read: &mut Read,
    ) -> Result<Option<Step>, AppError> {
        if self.key_may_come_by_fetch(data_epoch) {
            self.fetch_key_parts().await?;
            if self.holds_epoch_keys(data_epoch) {
                return Ok(None);
            }
        }
        let reason = ParkReason::AwaitingKey { data_epoch };
        // The keys its step ran with, so it is due again only once they change. While a
        // reopening is owed, which a key this page or this step's fetch took leaves until
        // the page's end, the record the step read may be one it opens: no count then, and
        // the entry, held while the reopening is owed, is due once it is done.
        let keys_at = if self.reader().exists(super::records::REOPEN_DUE).await? {
            None
        } else {
            Some(self.keys_held())
        };
        // Stored already for the same epoch: it stays as it is, but for that count. No
        // event: nothing new.
        if let Some(id) = entry.stored
            && let Some(stored) = self.state.parked.get_mut(&id)
            && stored.reason == reason
        {
            if stored.keys_at != keys_at {
                stored.keys_at = keys_at;
                read.tx.put(&key::parked(id), &*stored)?;
            }
            return Ok(Some(Step::Hold));
        }
        let id = self.park(entry, &received.plaintext, reason, read)?;
        if keys_at.is_none()
            && let Some(stored) = self.state.parked.get_mut(&id)
        {
            stored.keys_at = None;
            read.tx.put(&key::parked(id), &*stored)?;
        }
        Ok(Some(Step::Pass))
    }

    fn received_event(&mut self, entry: &Entry, received: &Received) {
        self.events.push(AppEvent::MessageReceived {
            seq: entry.seq,
            kind: received.message.kind.clone(),
            msg_id: received.message.msg_id.clone(),
            sender: entry.sender,
        });
    }

    /// Keep the processed pair, with the protocol's local writes, in the read's commit.
    fn note_processed(
        &mut self,
        entry: &Entry,
        received: &Received,
        local: &[LocalWrite],
        read: &mut Read,
    ) -> Result<(), AppError> {
        let now = self.now();
        processed_writes(
            &mut read.tx,
            &entry.sender,
            &received.message.msg_id,
            received.hash(),
            now,
        )?;
        read.pairs.insert(
            (entry.sender, received.message.msg_id.clone()),
            received.hash(),
        );
        read.tx.local(local)?;
        self.unpark(entry.stored, &mut read.tx)?;
        Ok(())
    }

    /// Sign the effect's batch with the cursor move, keep it with what the answer commits,
    /// then send it (Switch spec 8.2: the effect and the cursor in one batch).
    fn send_effect<'a>(
        &'a mut self,
        entry: &'a Entry,
        received: &'a Received,
        effect: Effect,
        written: Written<'a>,
        parked: bool,
        read: &'a mut Read,
    ) -> crate::transport::BoxFuture<'a, Result<Sent, AppError>> {
        // Boxed, as `receive_inner` says.
        Box::pin(self.send_effect_body(entry, received, effect, written, parked, read))
    }

    async fn send_effect_body(
        &mut self,
        entry: &Entry,
        received: &Received,
        effect: Effect,
        written: Written<'_>,
        parked: bool,
        read: &mut Read,
    ) -> Result<Sent, AppError> {
        let past_held = read.blocked.is_some_and(|b| b < entry.seq);
        let cursor_to = if parked {
            None
        } else if past_held {
            read.blocked.map(|b| b.saturating_sub(1))
        } else {
            Some(entry.seq)
        };
        // Kept at a service time verified in this call ([`App::kept_stamp`]): the feed read
        // brought one; a retry of an entry stored locally may come before it, and reads
        // one, so an effect is never kept while the service can't be reached.
        self.fresh_service_time().await?;
        let batch = self.sign_ops(effect.ops, cursor_to)?;
        let pending = PendingEffect {
            body: batch.body().to_vec(),
            seq: entry.seq,
            sender: entry.sender,
            msg_id: received.message.msg_id.clone(),
            hash: received.hash(),
            accepted_at_ms: entry.accepted_at_ms,
            kind: received.message.kind.clone(),
            local: effect.local,
            cursor_to,
            past_held,
            generation: entry.generation,
            stored: entry.stored,
            deadlines: written
                .deadlines
                .iter()
                .map(|(claim_key, deadline)| (pubky_switch_core::enc::b64(claim_key), *deadline))
                .collect(),
            kept_ms: self.kept_stamp(),
            forget: written.forget.to_vec(),
            entry: KeptEntry {
                cert: entry.cert.clone(),
                plaintext: received.plaintext.encode(),
                context: entry.context.clone(),
            },
        };
        // The collection name of a record the effect creates outside the protocol's
        // collections, until its write is answered: the switch knows only its ID.
        for (key, collection) in written.records {
            if !self.collection_of_name(collection) && self.held_record(key).await?.is_none() {
                read.tx.put(&pending_name_key(key), &collection.name)?;
            }
        }
        // A kept effect over the store's value size can't be kept, so it isn't sent: the
        // same effect is refused again however often it is built (Switch spec 8.2).
        let kept = u64::try_from(encode(&pending)?.len()).unwrap_or(u64::MAX);
        if kept > MAX_VALUE_BYTES
            || !self
                .make_room(
                    read,
                    kept.saturating_add(write_size(&self.ns, key::PENDING_EFFECT, 0)),
                )
                .await?
        {
            return Ok(Sent::TooLarge);
        }
        // Everything read so far, with the kept batch, before it is sent.
        read.tx.put(key::PENDING_EFFECT, &pending)?;
        read.tx.put(key::CURSOR, &self.state.cursor)?;
        let tx = std::mem::replace(&mut read.tx, self.tx()?);
        self.state.pending_effect = Some(pending.clone());
        self.commit(tx).await?;
        self.run_effect(pending, &batch, false).await
    }

    /// Send a kept effect and commit its outcome: what its operations settle (a record
    /// write cached at the version its proof gives, a claim entry's proof and view kept),
    /// the processed pair, the protocol's local writes and the cursor. An own `attempt` in
    /// it then gets the checks of its proof (Switch wire 6.5 "Binding").
    ///
    /// `resent` for an effect that may have been sent before, its answer lost: a refusal
    /// the service made before its batch ID lookup tells nothing of whether it was applied
    /// ([`RefusalPlace`]). One about the caller keeps the effect, to go again unchanged once
    /// the cause is gone, such as after a renewed certificate, and is the read's error, as
    /// the same answer to any request; past the window in which a resend tells, its entry is
    /// stored as uncertain instead. One about these bytes will come again: the entry is
    /// stored as uncertain at once ([`App::effect_uncertain`]), and the read goes on.
    fn run_effect<'a>(
        &'a mut self,
        pending: PendingEffect,
        batch: &'a Batch,
        resent: bool,
    ) -> crate::transport::BoxFuture<'a, Result<Sent, AppError>> {
        // Boxed, as `receive_inner` says.
        Box::pin(self.run_effect_body(pending, batch, resent))
    }

    async fn run_effect_body(
        &mut self,
        pending: PendingEffect,
        batch: &Batch,
        resent: bool,
    ) -> Result<Sent, AppError> {
        let result = self.submit(batch).await;
        let submitted = match result {
            Ok(submitted) => submitted,
            Err(error)
                if resent
                    && matches!(
                        refused_at(&error),
                        Some(RefusalPlace::Caller | RefusalPlace::Bytes)
                    ) =>
            {
                if refused_at(&error) == Some(RefusalPlace::Caller)
                    && self.answer_decides(Some(pending.kept_ms))
                {
                    return Err(error);
                }
                self.effect_uncertain(&pending).await?;
                return Ok(Sent::Uncertain);
            }
            // A quota is stored and passed, and applied once there is room (Switch spec 8.2).
            Err(error) if error.code() == Some(ErrorCode::QuotaExceeded) => {
                self.drop_pending_effect().await?;
                return Ok(Sent::Quota);
            }
            Err(error) => {
                let Some(code) = refused_for_good(&error) else {
                    // It may pass unchanged later (`429`, `503`, the network, an answer that
                    // doesn't verify): kept, and sent again, the same bytes, by the next
                    // read (Switch wire 2.1).
                    return Err(error);
                };
                let sent = match (code, error) {
                    (
                        ErrorCode::Conflict,
                        AppError::Switch(ClientError::Switch { current, .. }),
                    ) => Sent::Conflict(current),
                    (ErrorCode::StaleEpoch, _) => Sent::StaleEpoch,
                    (ErrorCode::TooLarge, _) => Sent::Quota,
                    // The app isn't current, its certificate expired, or the batch names
                    // another generation: nothing it writes passes until that changes. The
                    // kept batch goes, and the entry is read again then.
                    (
                        ErrorCode::NotCurrent | ErrorCode::CertExpired | ErrorCode::StaleGeneration,
                        error,
                    ) => {
                        self.drop_pending_effect().await?;
                        return Err(error);
                    }
                    // This effect is refused for good, the app's other writes aren't.
                    (code, _) => Sent::Refused(code.as_str().to_owned()),
                };
                self.drop_pending_effect().await?;
                return Ok(sent);
            }
        };
        self.commit_effect(&pending, batch, &submitted.proofs)
            .await?;
        self.check_attempts_of(batch, &submitted).await?;
        Ok(Sent::Applied)
    }

    /// The outcome of an applied effect, with the proofs its answer carried, if any: what
    /// its operations settle, the processed pair, the protocol's local writes and the
    /// cursor, in one commit.
    async fn commit_effect(
        &mut self,
        pending: &PendingEffect,
        batch: &Batch,
        proofs: &[pubky_switch_core::chain::TransitionProof],
    ) -> Result<(), AppError> {
        let now = self.now();
        let mut tx = self.tx()?;
        let settles = PendingBatch {
            deadlines: pending.deadlines.clone(),
            ..PendingBatch::default()
        };
        for (index, op) in batch.ops().iter().enumerate() {
            self.settle_op(op, proofs.get(index), &settles, &mut tx)
                .await?;
        }
        processed_writes(&mut tx, &pending.sender, &pending.msg_id, pending.hash, now)?;
        tx.local(&pending.local)?;
        for key in &pending.forget {
            tx.delete(key)?;
        }
        // Processed: a count of the store's retries at it goes with it.
        if pending.stored.is_some() {
            self.unpark(pending.stored, &mut tx)?;
        } else if self.state.retries.remove(&pending.seq).is_some() {
            tx.delete(&key::retry(pending.seq))?;
        }
        if pending.stored.is_some() {
            // Stored before, and passed then.
        } else if pending.past_held {
            tx.put(&key::seen(pending.seq), &())?;
            self.state.seen.insert(pending.seq);
        } else {
            self.state.cursor.seq = self.state.cursor.seq.max(pending.seq);
            self.state.cursor.time_ms = self.state.cursor.time_ms.max(pending.accepted_at_ms);
        }
        tx.delete(key::PENDING_EFFECT)?;
        tx.put(key::CURSOR, &self.state.cursor)?;
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut tx)?;
        }
        self.state.pending_effect = None;
        self.commit(tx).await
    }

    /// A kept effect signed for a generation before a provider change that the app's chain
    /// can't tell about, sent again unchanged: the answer decides (Switch spec 12.5 "Kept
    /// batches", Switch wire 6.4 step 6). Its original proofs, or `409 conflict` after an
    /// import, show it applied, and its outcome commits; any other refusal for good, `409
    /// stale_generation` among them, means it wasn't: it goes, and its entry is read again
    /// and its effect signed anew. `409 stale_generation` tells that only while the service
    /// still holds the batch's ID: past the window, the effect's entry is stored and
    /// passed instead ([`App::effect_uncertain`]); so is it at once on a refusal about these
    /// bytes ([`RefusalPlace::Bytes`]). Any other failure keeps it.
    async fn resend_earlier_effect(
        &mut self,
        pending: PendingEffect,
        batch: &Batch,
    ) -> Result<(), AppError> {
        let proofs = match self.submit(batch).await {
            Ok(submitted) => submitted.proofs,
            Err(AppError::Switch(ClientError::Switch {
                code: ErrorCode::Conflict,
                ..
            })) => Vec::new(),
            Err(AppError::Switch(ClientError::Switch {
                code: ErrorCode::StaleGeneration,
                ..
            })) if !self.answer_decides(Some(pending.kept_ms)) => {
                return self.effect_uncertain(&pending).await;
            }
            // Refused before the batch ID lookup, which tells nothing: about the caller, kept,
            // to go again unchanged, or past the window stored as uncertain; about these
            // bytes, stored as uncertain at once.
            Err(error)
                if matches!(
                    refused_at(&error),
                    Some(RefusalPlace::Caller | RefusalPlace::Bytes)
                ) =>
            {
                if refused_at(&error) == Some(RefusalPlace::Caller)
                    && self.answer_decides(Some(pending.kept_ms))
                {
                    return Err(error);
                }
                return self.effect_uncertain(&pending).await;
            }
            Err(error) if refused_for_good(&error).is_some() => {
                return self.drop_pending_effect().await;
            }
            Err(error) => return Err(error),
        };
        self.commit_effect(&pending, batch, &proofs).await?;
        self.events.push(AppEvent::MessageReceived {
            seq: pending.seq,
            kind: pending.kind,
            msg_id: pending.msg_id,
            sender: pending.sender,
        });
        Ok(())
    }

    /// A kept effect answered `409 stale_generation` past the window in which that answer
    /// means it was never applied (Switch spec 12.5 "Kept batches"): the service may have
    /// forgotten a batch it applied, so the effect goes and is never built again. Its entry
    /// is stored and passed, and the protocol told, in the commit that drops it
    /// ([`App::park_uncertain`]).
    async fn effect_uncertain(&mut self, pending: &PendingEffect) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        tx.delete(key::PENDING_EFFECT)?;
        self.park_uncertain(pending, &mut tx)?;
        tx.put(key::CURSOR, &self.state.cursor)?;
        self.state.pending_effect = None;
        self.commit(tx).await
    }

    /// The entry of a kept effect whose fate can't be known: building the effect again
    /// could apply it twice, so the entry is stored locally and passed, like an effect
    /// refused for good (Switch spec 8.2), and the protocol is told ([`Duty::Parked`],
    /// [`Duty::EffectUncertain`]), with its processed pair, all in `tx`; it decides from the
    /// current state. One stored before only changes its reason.
    fn park_uncertain(&mut self, pending: &PendingEffect, tx: &mut Tx) -> Result<(), AppError> {
        let reason = ParkReason::Uncertain;
        let stored = pending
            .stored
            .and_then(|id| self.state.parked.get(&id).cloned().map(|entry| (id, entry)));
        let (id, parked) = match stored {
            Some((id, stored)) => (id, ParkedEntry { reason, ..stored }),
            None => (
                self.new_stored_id(tx)?,
                ParkedEntry {
                    seq: pending.seq,
                    generation: pending.generation,
                    sender: pending.sender,
                    cert: pending.entry.cert.clone(),
                    accepted_at_ms: pending.accepted_at_ms,
                    plaintext: pending.entry.plaintext.clone(),
                    context: pending.entry.context.clone(),
                    reason,
                    round: self.state.parked_round.number,
                    released: false,
                    keys_at: None,
                },
            ),
        };
        tx.put(&key::parked(id), &parked)?;
        self.state.parked.insert(id, parked);
        // Stored for good: a count of the store's retries at it goes.
        self.drop_retries(pending.stored.is_none().then_some(pending.seq), id, tx)?;
        // Processed, so a re-send of the message is a duplicate, not applied (Switch spec
        // 11).
        let now = self.now();
        uncertain_processed(tx, &pending.sender, &pending.msg_id, pending.hash, now)?;
        if pending.stored.is_some() {
            // Stored before, and passed then.
        } else if pending.past_held {
            tx.put(&key::seen(pending.seq), &())?;
            self.state.seen.insert(pending.seq);
        } else {
            let cursor = &mut self.state.cursor;
            cursor.seq = cursor.seq.max(pending.seq);
            cursor.time_ms = cursor.time_ms.max(pending.accepted_at_ms);
            if cursor.seq > cursor.at_service && cursor.deferred_since_ms.is_none() {
                cursor.deferred_since_ms = Some(now);
            }
        }
        // Duty events, kept in `tx`, the commit that stores the entry.
        self.keep_duty(
            tx,
            Duty::Parked {
                seq: pending.seq,
                stored_id: id,
                reason,
            },
        )?;
        self.keep_duty(
            tx,
            Duty::EffectUncertain {
                seq: pending.seq,
                stored_id: id,
                sender: pending.sender,
                msg_id: pending.msg_id.clone(),
                kind: pending.kind.clone(),
                attempts: super::provider::attempts_in(&Batch::from_body(pending.body.clone())?),
            },
        )
    }

    async fn drop_pending_effect(&mut self) -> Result<(), AppError> {
        let mut tx = self.tx()?;
        tx.delete(key::PENDING_EFFECT)?;
        self.state.pending_effect = None;
        self.commit(tx).await
    }

    /// A kept effect from before a crash or a lost answer: sent again, the same bytes.
    async fn resume_pending_effect(&mut self) -> Result<(), AppError> {
        let Some(pending) = self.state.pending_effect.clone() else {
            return Ok(());
        };
        let batch = Batch::from_body(pending.body.clone())?;
        // Past the window no answer tells whether it was applied, at any generation: a
        // retry after the service dropped its proofs gets `409 conflict`, and a forgotten
        // ID takes the same bytes as new. It isn't sent again; its entry is stored as
        // uncertain (Switch wire 6.4 step 5, Switch spec 12.5 "Kept batches"). Past it by
        // the clocks at hand is past it; only a "still inside" needs a fresh service time.
        if !self.answer_decides(Some(pending.kept_ms)) {
            return self.effect_uncertain(&pending).await;
        }
        self.fresh_service_time().await?;
        if !self.answer_decides(Some(pending.kept_ms)) {
            return self.effect_uncertain(&pending).await;
        }
        if super::batch_generation(&batch).is_some_and(|g| g < self.state.meta.generation) {
            return self.resend_earlier_effect(pending, &batch).await;
        }
        match self.run_effect(pending.clone(), &batch, true).await? {
            Sent::Applied => self.events.push(AppEvent::MessageReceived {
                seq: pending.seq,
                kind: pending.kind,
                msg_id: pending.msg_id,
                sender: pending.sender,
            }),
            // The entry is read again from the cursor, which didn't pass it, or from the
            // local store, and its effect built again.
            Sent::Conflict(_)
            | Sent::StaleEpoch
            | Sent::Quota
            | Sent::Refused(_)
            | Sent::Uncertain
            // Only a first send that can't be kept is too large; a kept effect was kept.
            | Sent::TooLarge => {}
        }
        Ok(())
    }

    /// A receive step the protocol's store or the host kept from finishing
    /// ([`Outcome::Retry`]), with nothing of the step committed. A failure of the entry
    /// stores it and passes it at once. Otherwise the reads in a row that end so are
    /// counted, to raise [`AppEvent::StoreFailing`] from [`RETRY_EVENT_READS`] on, and the
    /// count is kept until the entry is processed, while it is stored locally too. An
    /// entry stored locally stays so; one on the feed is held until the bounded wait since
    /// the first retry, which an entry whose sender can't be checked gets too, then stored
    /// and passed (Switch spec 8.2). Never dropped.
    fn retry_later(
        &mut self,
        entry: &Entry,
        plaintext: &MessagePlaintext,
        parked: bool,
        failure: StoreFailure,
        read: &mut Read,
    ) -> Result<Step, AppError> {
        if failure.is_of_entry() && !parked {
            self.park(entry, plaintext, ParkReason::StoreRejected, read)?;
            return Ok(Step::Pass);
        }
        let now = self.now();
        let fresh = RetryEntry {
            reads: 0,
            since_ms: now,
        };
        // Counted under the entry's local ID while it is stored, its `seq` before.
        let retry = match entry.stored {
            Some(id) => {
                let retry = self.state.stored_retries.entry(id).or_insert(fresh);
                retry.reads = retry.reads.saturating_add(1);
                let retry = *retry;
                read.tx.put(&key::stored_retry(id), &retry)?;
                retry
            }
            None => {
                let retry = self.state.retries.entry(entry.seq).or_insert(fresh);
                retry.reads = retry.reads.saturating_add(1);
                let retry = *retry;
                read.tx.put(&key::retry(entry.seq), &retry)?;
                retry
            }
        };
        // Raised from the count's threshold on, and at every try of an entry stored
        // locally for the store, which waited out the bounded wait or can't be mended by
        // waiting: the host hears of it again at each, however few its tries.
        if retry.reads >= RETRY_EVENT_READS || parked {
            self.events.push(AppEvent::StoreFailing {
                seq: entry.seq,
                stored_id: entry.stored,
                reads: retry.reads,
                since_ms: retry.since_ms,
                failure,
            });
        }
        if parked {
            // Stored already: it stays so, and is tried again at the next read.
            return Ok(Step::Hold);
        }
        if now.saturating_sub(retry.since_ms) >= self.config.park_after_ms {
            self.park(entry, plaintext, ParkReason::StoreUnavailable, read)?;
            return Ok(Step::Pass);
        }
        Ok(Step::Hold)
    }

    /// An entry processed at last, and not stored locally: its count of retries goes.
    fn clear_retry(&mut self, seq: u64, read: &mut Read) -> Result<(), AppError> {
        if self.state.retries.remove(&seq).is_some() {
            read.tx.delete(&key::retry(seq))?;
        }
        Ok(())
    }

    fn dropped(&mut self, seq: u64, check: u8, reason: String) -> Step {
        self.events
            .push(AppEvent::MessageDropped { seq, check, reason });
        Step::Pass
    }

    /// An entry whose sender can't be checked: held, or stored and passed once it waited
    /// longer than the bounded wait (Switch spec 8.2).
    fn hold_or_park(
        &mut self,
        entry: &Entry,
        plaintext: &MessagePlaintext,
        read: &mut Read,
    ) -> Result<Step, AppError> {
        let now = self.now();
        let since = match self.state.held.get(&entry.seq) {
            Some(held) => held.since_ms,
            None => {
                let held = HeldEntry { since_ms: now };
                read.tx.put(&key::held(entry.seq), &held)?;
                self.state.held.insert(entry.seq, held);
                now
            }
        };
        if now.saturating_sub(since) >= self.config.park_after_ms {
            self.park(entry, plaintext, ParkReason::Unverifiable, read)?;
            return Ok(Step::Pass);
        }
        self.events.push(AppEvent::Held { seq: entry.seq });
        Ok(Step::Hold)
    }

    /// Store `entry` locally for `reason`, under its local ID, a new one for an entry read
    /// from the feed, and pass it (Switch spec 8.2). Returns the local ID.
    fn park(
        &mut self,
        entry: &Entry,
        plaintext: &MessagePlaintext,
        reason: ParkReason,
        read: &mut Read,
    ) -> Result<u64, AppError> {
        let id = match entry.stored {
            Some(id) => id,
            None => self.new_stored_id(&mut read.tx)?,
        };
        let parked = ParkedEntry {
            seq: entry.seq,
            generation: entry.generation,
            sender: entry.sender,
            cert: entry.cert.clone(),
            accepted_at_ms: entry.accepted_at_ms,
            plaintext: plaintext.encode(),
            context: entry.context.clone(),
            reason,
            round: self.state.parked_round.number,
            // Stored again, a released entry stays released, whatever it waits for now.
            released: entry
                .stored
                .and_then(|id| self.state.parked.get(&id))
                .is_some_and(|entry| entry.released),
            // The step of an entry that waits for a key ran with the keys held now.
            keys_at: reason.awaited_epoch().map(|_| self.keys_held()),
        };
        read.tx.put(&key::parked(id), &parked)?;
        // An entry read from the feed may have been held there; a stored one's `seq` names
        // no position of the feed read now.
        if entry.stored.is_none() {
            read.tx.delete(&key::held(entry.seq))?;
            self.state.held.remove(&entry.seq);
        }
        self.state.parked.insert(id, parked);
        if reason.tried_again() {
            if reason.awaited_epoch().is_some() {
                // Its step finished, waiting for a key: a count of the store's retries at it
                // ends, and none is kept while it waits.
                self.drop_retries(
                    entry.stored.is_none().then_some(entry.seq),
                    id,
                    &mut read.tx,
                )?;
            } else if entry.stored.is_none()
                && let Some(retry) = self.state.retries.remove(&entry.seq)
            {
                // Its count of the store's retries goes with it, under its local ID.
                read.tx.delete(&key::retry(entry.seq))?;
                read.tx.put(&key::stored_retry(id), &retry)?;
                self.state.stored_retries.insert(id, retry);
            }
            self.events.push(AppEvent::Parked {
                id: None,
                seq: entry.seq,
                stored_id: id,
                reason,
            });
        } else {
            // Stored for good, never tried again: a count of the store's retries at it goes.
            self.drop_retries(
                entry.stored.is_none().then_some(entry.seq),
                id,
                &mut read.tx,
            )?;
            // A duty event, kept in the commit that stores the entry.
            self.keep_duty(
                &mut read.tx,
                Duty::Parked {
                    seq: entry.seq,
                    stored_id: id,
                    reason,
                },
            )?;
        }
        Ok(id)
    }

    /// The local ID the next entry stored locally takes, counted up in `tx`.
    pub(crate) fn new_stored_id(&mut self, tx: &mut Tx) -> Result<u64, AppError> {
        let id = self.state.next_stored_id;
        self.state.next_stored_id = id.saturating_add(1);
        tx.put(key::STORED_NEXT, &self.state.next_stored_id)?;
        Ok(id)
    }

    /// The counts of the store's retries at an entry go: at its `seq` while it was read
    /// from the feed, and at its local ID once stored.
    fn drop_retries(&mut self, seq: Option<u64>, id: u64, tx: &mut Tx) -> Result<(), AppError> {
        if let Some(seq) = seq
            && self.state.retries.remove(&seq).is_some()
        {
            tx.delete(&key::retry(seq))?;
        }
        if self.state.stored_retries.remove(&id).is_some() {
            tx.delete(&key::stored_retry(id))?;
        }
        Ok(())
    }

    /// The entry stored locally at `stored`, if any, goes: processed, dropped or a
    /// duplicate, its count of retries with it.
    pub(crate) fn unpark(&mut self, stored: Option<u64>, tx: &mut Tx) -> Result<(), AppError> {
        if let Some(id) = stored {
            tx.delete(&key::parked(id))?;
            self.state.parked.remove(&id);
            self.drop_retries(None, id, tx)?;
        }
        Ok(())
    }

    /// An effect too large for the store ([`ParkReason::EffectTooLarge`]): its entry stored
    /// and passed, and the protocol told.
    async fn too_large(
        &mut self,
        entry: &Entry,
        received: &Received,
        read: &mut Read,
    ) -> Result<(), AppError> {
        self.make_room(read, PARK_ROOM_BYTES).await?;
        let stored = self.park(entry, &received.plaintext, ParkReason::EffectTooLarge, read)?;
        self.effect_refused(entry, received, stored, None, read)
    }

    /// Room in the read's commit for `bytes` more, with what processing an entry adds: when
    /// the read's writes so far and `bytes` would be over the store's batch size, the read's
    /// writes are committed first, with the cursor, as before a kept effect. `false` when
    /// `bytes` alone wouldn't fit one commit.
    async fn make_room(&mut self, read: &mut Read, bytes: u64) -> Result<bool, AppError> {
        let needed = bytes.saturating_add(ENTRY_RESERVE_BYTES);
        if needed > MAX_BATCH_BYTES {
            return Ok(false);
        }
        if read.tx.size().saturating_add(needed) > MAX_BATCH_BYTES && !read.tx.is_empty() {
            read.tx.put(key::CURSOR, &self.state.cursor)?;
            let tx = std::mem::replace(&mut read.tx, self.tx()?);
            self.commit(tx).await?;
        }
        Ok(true)
    }

    fn effect_refused(
        &mut self,
        entry: &Entry,
        received: &Received,
        stored_id: u64,
        code: Option<String>,
        read: &mut Read,
    ) -> Result<(), AppError> {
        self.keep_duty(
            &mut read.tx,
            Duty::EffectRefused {
                seq: entry.seq,
                stored_id,
                sender: entry.sender,
                msg_id: received.message.msg_id.clone(),
                kind: received.message.kind.clone(),
                code,
            },
        )
    }

    /// Entries stored locally, checked and applied again now (Switch spec 8.2); the cursor is
    /// past them. One that waits for a scope key is due only once the app holds every key of
    /// its epoch the certificate is given ([`App::holds_epoch_keys`]): until then it costs
    /// a read nothing.
    ///
    /// At most [`PARKED_RETRIES_PER_READ`] each read, starting where the last read stopped
    /// and going round, so none waits for ever behind others the store keeps failing.
    ///
    /// Past the call's time budget it stops once it has tried one, and the round moves on
    /// only past the entries it reached: the next read starts at the first one it left. So
    /// with the budget spent at every read, each read still tries one entry, and every
    /// entry due is tried within two rounds of one read per entry. No `more` is said for
    /// them: an entry the store keeps failing comes again at every read, so the host's next
    /// read, not one at once, tries it.
    async fn retry_parked(&mut self, budget: Option<&super::CallBudget>) -> Result<(), AppError> {
        let gaps = self.key_gaps();
        let keys_held = self.keys_held();
        // An entry that waits for a key may read the records a reopening still owes: it
        // waits for that too, its count of keys untouched, so it is due once it is done.
        let reopen_owed = self.reader().exists(super::records::REOPEN_DUE).await?;
        let due: Vec<(u64, u64)> = self
            .state
            .parked
            .iter()
            .filter(|(_, stored)| {
                due_again(stored, &gaps, keys_held)
                    && !(reopen_owed && stored.reason.awaited_epoch().is_some())
            })
            .map(|(id, stored)| (*id, stored.round))
            .collect();
        if due.is_empty() {
            return Ok(());
        }
        let before = self.state.parked_round;
        let (ids, round) = before.turn(&due, PARKED_RETRIES_PER_READ);
        // Committed before the retries, so an entry whose retry fails the read doesn't
        // hold the round at it.
        self.commit_parked_round(round).await?;
        let given = ids.len();
        let reached = self.retry_stored(ids, budget).await?;
        if reached < given {
            // A smaller turn takes the same first entries: the round stands past those
            // reached, and the next read starts at the first one left.
            self.commit_parked_round(before.turn(&due, reached).1)
                .await?;
        }
        Ok(())
    }

    /// Keep where the retries of entries stored locally stand (`parkn`), when it changed.
    async fn commit_parked_round(&mut self, round: ParkedRound) -> Result<(), AppError> {
        if round != self.state.parked_round {
            self.state.parked_round = round;
            let mut tx = self.tx()?;
            tx.put(key::PARKED_NEXT, &round)?;
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// The entries waiting for a scope key that a fetch in the read brought the keys of,
    /// tried again at the end of the read: those due now that weren't when the read's
    /// retries began (`due_at_start`), at most [`PARKED_RETRIES_PER_READ`] in local ID order;
    /// the rest are due at the next read's retries. The caller makes sure no listing is
    /// owed, so nothing is handed to the protocol before one (Switch spec 8.2).
    async fn retry_awaited(
        &mut self,
        due_at_start: &[u64],
        budget: Option<&super::CallBudget>,
    ) -> Result<(), AppError> {
        // Not while a reopening is owed, which their steps may read (`retry_parked`).
        if self.reader().exists(super::records::REOPEN_DUE).await? {
            return Ok(());
        }
        let ids: Vec<u64> = self
            .awaiting_due()
            .into_iter()
            .filter(|id| !due_at_start.contains(id))
            .take(PARKED_RETRIES_PER_READ)
            .collect();
        self.retry_stored(ids, budget).await.map(|_| ())
    }

    /// The local IDs of the entries waiting for a scope key that are due now, in order.
    fn awaiting_due(&self) -> Vec<u64> {
        let gaps = self.key_gaps();
        let keys_held = self.keys_held();
        self.state
            .parked
            .iter()
            .filter(|(_, stored)| {
                stored.reason.awaited_epoch().is_some() && due_again(stored, &gaps, keys_held)
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// The report's notice of the entries waiting for scope keys
    /// ([`AppEvent::AwaitingKeys`]), if any wait.
    fn awaiting_keys_notice(&self) -> Option<AppEvent> {
        let mut epochs: Vec<u64> = self
            .state
            .parked
            .values()
            .filter_map(|stored| stored.reason.awaited_epoch())
            .collect();
        if epochs.is_empty() {
            return None;
        }
        let entries = u64::try_from(epochs.len()).unwrap_or(u64::MAX);
        epochs.sort_unstable();
        epochs.dedup();
        Some(AppEvent::AwaitingKeys { epochs, entries })
    }

    /// The entries stored locally at `ids`, each checked and applied again in a commit of
    /// its own. Past the call's time budget, once one is tried, it stops: the rest go at a
    /// later read. Returns how many of `ids` it reached, in order, those it passed over
    /// included.
    async fn retry_stored(
        &mut self,
        ids: Vec<u64>,
        budget: Option<&super::CallBudget>,
    ) -> Result<usize, AppError> {
        let given = ids.len();
        for (index, id) in ids.into_iter().enumerate() {
            if index > 0 && budget.is_some_and(|budget| self.spent(budget)) {
                return Ok(index);
            }
            let Some(stored) = self.state.parked.get(&id).cloned() else {
                continue;
            };
            // A refusal for good, an effect over one batch, a step that asked for more reads
            // than an entry gets, or an effect whose fate can't be known, isn't tried again.
            if !stored.reason.tried_again() {
                continue;
            }
            let plaintext = MessagePlaintext::decode(&stored.plaintext)
                .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?;
            let entry = Entry {
                seq: stored.seq,
                generation: stored.generation,
                stored: Some(id),
                sender: stored.sender,
                cert: stored.cert,
                accepted_at_ms: stored.accepted_at_ms,
                context: stored.context,
            };
            let mut read = Read::new(self.tx()?, None);
            let step = self
                .check_and_apply(&entry, plaintext, true, &mut read)
                .await?;
            self.commit(read.tx).await?;
            self.reopen_if_due().await?;
            if step == Step::Pass && !self.state.parked.contains_key(&id) {
                self.events.push(AppEvent::Unparked {
                    seq: stored.seq,
                    stored_id: id,
                });
            }
        }
        Ok(given)
    }

    /// The sender's newest `identity.json` for check 7: the own one, or a copy at most 10
    /// minutes old, read again from the Homeserver otherwise (`force` reads it again
    /// whatever its age), with whether it was read in this call. `None` when it can't be
    /// read now, or the identity equivocated.
    async fn sender_doc(
        &mut self,
        sender: &[u8; 32],
        force: bool,
    ) -> Result<Option<(IdentityDoc, bool)>, AppError> {
        if *sender == self.state.meta.identity {
            return Ok(Some((self.state.own_doc.clone(), true)));
        }
        let reader = self.reader();
        if reader.exists(&key::ident_equivocated(sender)).await? {
            return Ok(None);
        }
        let held = identity::held_copy(&reader, sender).await?;
        let now = self.now();
        if let Some((doc, fetched)) = &held
            && !force
            && now.saturating_sub(*fetched) < DOC_CACHE_MS
        {
            return Ok(Some((doc.clone(), false)));
        }
        let fetched = match identity::read_homeserver(self.env.homeserver.as_ref(), sender).await {
            Ok(Some(doc)) => doc,
            Ok(None) | Err(_) => return Ok(None),
        };
        let mut tx = self.tx()?;
        let held_doc = held.as_ref().map(|(doc, _)| doc);
        let taken = identity::take_copy(&reader, &mut tx, &fetched, held_doc, now).await?;
        let doc = match taken {
            Err(equivocation) => {
                self.events.push(AppEvent::PeerEquivocation {
                    identity: *sender,
                    version: equivocation.version,
                });
                self.commit(tx).await?;
                return Ok(None);
            }
            Ok(Taken::Newer) => fetched,
            Ok(Taken::Same | Taken::Older) => {
                let doc = held_doc.cloned().unwrap_or(fetched);
                tx.put(
                    &key::ident_doc(sender),
                    &CachedDoc {
                        doc: doc.signed().clone(),
                        fetched_ms: now,
                    },
                )?;
                doc
            }
        };
        self.commit(tx).await?;
        Ok(Some((doc, true)))
    }

    // ---------------------------------------------------------------------------------
    // Entries the app can't read

    /// The earliest acceptance time the app asks a re-send for: its cursor's, less the
    /// clock tolerance (Switch spec 8.2).
    /// A gap the cursor the service holds shows ahead of the app's position, handled as a
    /// `missed` item is (Switch spec 8.3 "Ahead"): entries after `position` that an instance
    /// of the app passed, which the service may have deleted. The protocol is handed the
    /// range accepted from the cursor's time, less the clock tolerance, with no end and no
    /// count (`entries` 0), and, with `list`, a listing is owed; once for each higher report
    /// (`hgap`).
    fn hand_held_gap(
        &mut self,
        held: u64,
        position: u64,
        list: bool,
        read: &mut Read,
    ) -> Result<(), AppError> {
        let call = OwedCall::Missed {
            seq: held,
            entries: 0,
            accepted_from_ms: self.resend_floor(),
            accepted_until_ms: u64::MAX,
        };
        // Owed at the compared position, at or before the cursor, so the queue makes it
        // before anything after the gap (Switch spec 8.3).
        self.hand_call(position, call, read)?;
        self.gap_handed(held, &mut read.tx)?;
        if list {
            super::records::owe_listing(&mut read.tx)?;
            read.list_first = true;
        }
        Ok(())
    }

    fn resend_floor(&self) -> u64 {
        self.state.cursor.time_ms.saturating_sub(CLOCK_TOLERANCE_MS)
    }

    fn unopenable(&mut self, entry: &Entry, read: &mut Read) -> Result<Step, AppError> {
        let ask =
            entry.accepted_at_ms >= self.resend_floor() && entry.sender != self.state.meta.identity;
        let asked = ask
            && self.ask_resend(
                entry.seq,
                ResendNeeded {
                    sender: entry.sender,
                    accepted_from_ms: entry.accepted_at_ms,
                    accepted_until_ms: entry.accepted_at_ms,
                    reason: ResendReason::Unopenable,
                },
                read,
            )?;
        self.events.push(AppEvent::Unopenable {
            seq: entry.seq,
            resend_asked: asked,
        });
        Ok(Step::Pass)
    }

    /// Hand a re-send to the protocol once per item; returns whether it was asked now.
    fn ask_resend(
        &mut self,
        seq: u64,
        needed: ResendNeeded,
        read: &mut Read,
    ) -> Result<bool, AppError> {
        if !self.state.asked.insert(seq) {
            return Ok(false);
        }
        // A protocol not asked yet is owed the call, and asked by a later read.
        let asked = self.hand_call(seq, OwedCall::from(&needed), read)?;
        read.tx.put(&key::asked(seq), &())?;
        Ok(asked)
    }

    /// Hand a call about the feed item at `seq` to every protocol, in registration order,
    /// each answer's writes going with the read under that protocol's prefix. A protocol
    /// that fails, or that still owes an earlier call, which it must take first, is owed
    /// this one (Switch spec 8.3). Whether every protocol took it now.
    fn hand_call(&mut self, seq: u64, call: OwedCall, read: &mut Read) -> Result<bool, AppError> {
        let protocols: Vec<super::protocols::Registered> = self.protocols.iter().cloned().collect();
        let mut owed_to = Vec::new();
        for registered in protocols {
            if self.owing.contains(&registered.name) {
                owed_to.push(registered.name);
                continue;
            }
            match call.make(registered.protocol.as_ref()) {
                Ok(writes) if local_writes_bytes(&writes) > MAX_STEP_LOCAL_BYTES => {
                    self.local_writes_refused(seq, &registered.name, call.clone(), read)?;
                }
                Ok(writes) => read
                    .tx
                    .local(&super::protocols::qualify(&registered.name, writes))?,
                Err(_) => owed_to.push(registered.name),
            }
        }
        if owed_to.is_empty() {
            return Ok(true);
        }
        self.owe(seq, owed_to, call, read)?;
        Ok(false)
    }

    /// A call whose answer's local writes are over [`MAX_STEP_LOCAL_BYTES`]: not committed,
    /// and not owed, since making it again would bring the same answer; the protocol that
    /// gave them is told in the commit that passes its item.
    fn local_writes_refused(
        &mut self,
        seq: u64,
        protocol: &str,
        call: OwedCall,
        read: &mut Read,
    ) -> Result<(), AppError> {
        self.keep_duty_for(
            &mut read.tx,
            vec![protocol.to_owned()],
            Duty::LocalWritesRefused {
                call: KeptRefusal::Owed { seq, call },
            },
        )
    }

    /// Hand a deny list change to the protocol, its writes committed with the cursor passing
    /// the item; owed when the protocol fails, or when an earlier change is still owed, so
    /// the protocol gets them in feed order (Switch spec 8.3).
    fn tell_deny_change(
        &mut self,
        change: &DenyListChange,
        read: &mut Read,
    ) -> Result<(), AppError> {
        if !self.state.cert.has_permission(Permission::ListsRead) {
            return Ok(());
        }
        self.hand_call(change.seq, OwedCall::from(change), read)
            .map(|_| ())
    }

    /// Note a gap in the deny list's history after `generation` and `seq`, in `tx`, for an
    /// app holding `lists.read`: every protocol is told of it, with the lists read after it,
    /// before anything later ([`Protocol::deny_list_gap`]). The earliest gap owed is kept.
    /// Every gap noted is told to every protocol, also at a position a gap was told at
    /// before and to a protocol that took a gap still owed to another: that gap's list may
    /// predate what this one covers, and a gap told again only sets the same state.
    /// Whether one was noted now.
    pub(crate) async fn note_deny_gap(
        &self,
        generation: u64,
        seq: u64,
        tx: &mut Tx,
    ) -> Result<bool, AppError> {
        if !self.state.cert.has_permission(Permission::ListsRead) {
            return Ok(false);
        }
        let reader = self.reader();
        // Every gap noted is told to every protocol, whichever of them took a gap owed
        // before: the earliest position is kept, and the gap is owed to all of them again.
        let at = match reader.get::<OwedGap>(DENY_GAP).await? {
            Some(owed) => (owed.generation, owed.seq).min((generation, seq)),
            None => (generation, seq),
        };
        let owed = OwedGap {
            generation: at.0,
            seq: at.1,
            to: self.protocols.names(),
        };
        tx.put(DENY_GAP, &owed)?;
        tx.delete(super::admission::LISTS_AT)?;
        Ok(true)
    }

    /// A deny list gap owed, told now, after the owed calls and before anything later
    /// (Switch spec 8.3): the lists are read (`GET /allow`) for it, however long the copy
    /// of the lists waits after one too large for a commit, and the gap is told with the
    /// deny list they give, in a commit of its own. The copy of the lists is then replaced
    /// from the same answer, best effort. A read that fails or is refused leaves the gap
    /// owed and the read held; only an answer that verifies but can't be read tells the gap
    /// without the list (`list_read` false), and deletes `lc/lists_at` in the telling
    /// commit, so the next read owes a gap again (`App::refresh_lists_if_owed`): such a
    /// protocol is told `list_read` false at each read for as long as the answer can't be
    /// read, and the list once it can.
    /// Whether a gap is still owed.
    async fn tell_deny_gap_if_owed(&mut self) -> Result<bool, AppError> {
        if !self.state.cert.has_permission(Permission::ListsRead) {
            return Ok(false);
        }
        let Some(owed) = self.reader().get::<OwedGap>(DENY_GAP).await? else {
            return Ok(false);
        };
        // Every writer names at least one protocol: a gap owed to none is a corrupt store.
        if owed.to.is_empty() {
            return Err(AppError::Store(crate::error::StoreError::Corrupt));
        }
        // A gap goes to every protocol after what each owes from before it: while one owes a
        // call it failed, the gap waits, and the read holds for every protocol, as for a deny
        // list change one of them can't take yet (Switch spec 8.3).
        if owed.to.iter().any(|name| self.owing.contains(name)) {
            return Ok(true);
        }
        let (generation, seq) = (owed.generation, owed.seq);
        let result = self.client.allow().await;
        let list = match self.take(result).await {
            Ok(list) => Some(list),
            // An answer that verifies but doesn't read: the gap is told without the list.
            Err(
                AppError::Switch(crate::error::ClientError::InvalidResponse(_))
                | AppError::InvalidData(_),
            ) => None,
            // What may pass later unchanged, a transport failure, `503`, `429` or a limit
            // that frees: the gap stays owed, and the read holds.
            Err(error) if may_pass_unchanged(&error) => return Ok(true),
            // Anything else is the read's error, as for the feed's own call, so the read's
            // handling of it runs: a revocation, a key change, an erasure or a move is
            // followed, never held as a call the protocol owes (`App::take_over`).
            Err(error) => return Err(error),
        };
        let gap = super::protocol::DenyListGap {
            generation,
            seq,
            denied: list
                .as_ref()
                .map(|list| list.deny.clone())
                .unwrap_or_default(),
            list_read: list.is_some(),
        };
        // Each protocol owed the gap, its writes in this commit; one that fails keeps the
        // gap owed to every one of them, and the read holds.
        let mut tx = self.tx()?;
        let mut left = Vec::new();
        for name in owed.to.iter().cloned() {
            let Some(protocol) = self.protocols.get(&name).cloned() else {
                return Err(AppError::Store(crate::error::StoreError::Corrupt));
            };
            let writes = match protocol.deny_list_gap(&gap) {
                Ok(writes) => writes,
                Err(_) => {
                    left.push(name);
                    continue;
                }
            };
            if local_writes_bytes(&writes) > MAX_STEP_LOCAL_BYTES {
                self.keep_duty_for(
                    &mut tx,
                    vec![name],
                    Duty::LocalWritesRefused {
                        call: KeptRefusal::DenyGap { generation, seq },
                    },
                )?;
            } else {
                tx.local(&super::protocols::qualify(&name, writes))?;
            }
        }
        if !left.is_empty() {
            // One protocol failed it: the gap stays owed to every protocol it was owed to,
            // those told now too, so the next tell hands each of them the list the copy of
            // the lists is then taken from, and none keeps a list the copy isn't.
            tx.put(
                DENY_GAP,
                &OwedGap {
                    generation,
                    seq,
                    to: owed.to,
                },
            )?;
            self.commit(tx).await?;
            return Ok(true);
        }
        tx.delete(DENY_GAP)?;
        if list.is_none() {
            // The protocol has no baseline yet: the copy isn't known complete either, so the
            // next read owes the gap again, with the list once it reads, whatever waits on
            // the copy (one `GET /allow` a read while the answer can't be read).
            tx.delete(super::admission::LISTS_AT)?;
            tx.delete(super::admission::LISTS_TOO_LARGE)?;
        }
        self.commit(tx).await?;
        // The copy from the same answer, best effort: one too large for a commit keeps its
        // mark, and the read goes on, the gap told.
        if let Some(list) = list {
            match self.take_lists(&list).await {
                Ok(()) | Err(AppError::Store(crate::error::StoreError::TooLarge { .. })) => {}
                Err(error @ (AppError::Alarm(_) | AppError::Store(_))) => return Err(error),
                Err(_) => {}
            }
        }
        Ok(false)
    }

    /// What a deny list operation is, checked as Switch wire 6.2 has it: the identity's
    /// own, signed by an app of the identity whose certificate holds `lists.manage`, and
    /// not after that app's `distrust_from` (Switch spec 12.2). Wire 6.2 gives the signer
    /// no deny list operation. The body alone is the service's word.
    ///
    /// A writer whose certificate the app doesn't hold has the own directory read for it,
    /// once a read. A read that fails leaves the operation unverified for now; one that
    /// answers without the writer leaves it unverifiable, as for a writer revoked since.
    async fn check_deny_op(
        &mut self,
        doc: &SignedDoc,
        body: &pubky_switch_core::ops::OpBody,
        at_ms: u64,
        tx: &Tx,
    ) -> Result<DenyCheck, AppError> {
        let identity = self.state.meta.identity;
        if body.identity != identity {
            return Ok(DenyCheck::NotGenuine("Switch wire 6.2: another identity's"));
        }
        let Some(writer) = body.app_id else {
            return Ok(DenyCheck::NotGenuine("Switch wire 6.2: no app signed it"));
        };
        let mut certs = self.writer_certs_held(&writer).await?;
        certs.extend(self.pending_certs(tx, &writer));
        if certs.is_empty() {
            let answered = match self.deny_directory_read {
                Some((read, answered)) if read == self.reads_begun => answered,
                _ => {
                    // Only what may pass later unchanged leaves the change to be checked
                    // again; anything else is the read's error, so a revocation, a key
                    // change, an erasure or a move is followed (`App::take_over`).
                    let answered = match self.refresh_own_apps().await {
                        Ok(()) => true,
                        Err(error) if may_pass_unchanged(&error) => false,
                        Err(error) => return Err(error),
                    };
                    self.deny_directory_read = Some((self.reads_begun, answered));
                    answered
                }
            };
            certs = self.writer_certs_held(&writer).await?;
            if certs.is_empty() {
                return Ok(if answered {
                    DenyCheck::Unverifiable
                } else {
                    DenyCheck::NotYet
                });
            }
        }
        let verifies = |cert: &&pubky_switch_core::records::AppCert| {
            cert.app_id() == writer
                && SignedOp::verify(doc, &cert.signing_key(), &identity, Some(&writer)).is_ok()
        };
        let Some(signer) = certs
            .iter()
            .filter(verifies)
            .find(|cert| cert.has_permission(Permission::ListsManage))
        else {
            // Signed with the writer's key, but under no certificate held that holds
            // `lists.manage`: it may have been made under an earlier one the app doesn't
            // hold, so it is a gap, not a refusal.
            if certs.iter().any(|cert| verifies(&cert)) {
                return Ok(DenyCheck::Unverifiable);
            }
            return Ok(DenyCheck::NotGenuine(
                "Switch wire 6.2: not signed by an app of the identity",
            ));
        };
        if let pubky_switch_core::records::Standing::Removed { distrust_from } =
            self.state.own_doc.standing(&writer, &signer.hash())
            && at_ms > distrust_from
        {
            return Ok(DenyCheck::NotGenuine(
                "Switch spec 12.2: a removed app's change after distrust_from",
            ));
        }
        Ok(DenyCheck::Genuine)
    }

    /// A deny list operation the feed shows in full, at `seq`: checked, then applied to the
    /// copy of the lists and handed to the protocol, refused with an event, owed for a
    /// later check, or noted as a gap in the deny list's history (Switch spec 8.3).
    async fn take_deny_op(
        &mut self,
        doc: &SignedDoc,
        body: &pubky_switch_core::ops::OpBody,
        change: DenyListChange,
        read: &mut Read,
    ) -> Result<(), AppError> {
        // A change past a held entry, handed at an earlier read: the cursor stays before
        // the entry, so the feed shows it again (Switch spec 8.2).
        if self.state.seen.contains(&change.seq) {
            return Ok(());
        }
        match self
            .check_deny_op(doc, body, change.at_ms, &read.tx)
            .await?
        {
            DenyCheck::Genuine => {
                self.note_list_op(body, &mut read.tx)?;
                self.tell_deny_change(&change, read)?;
            }
            DenyCheck::NotGenuine(reason) => {
                self.events.push(AppEvent::DenyListChangeRefused {
                    generation: change.generation,
                    seq: change.seq,
                    reason: reason.into(),
                });
            }
            DenyCheck::NotYet => {
                let call = OwedCall::DenyUnverified {
                    generation: change.generation,
                    seq: change.seq,
                    pubky: change.pubky,
                    added: change.added,
                    at_ms: change.at_ms,
                    op: doc.clone(),
                };
                let to = self.protocols.names();
                self.owe(change.seq, to, call, read)?;
            }
            DenyCheck::Unverifiable => {
                if self
                    .note_deny_gap(
                        change.generation,
                        change.seq.saturating_sub(1),
                        &mut read.tx,
                    )
                    .await?
                {
                    read.held_after = true;
                }
            }
        }
        if read.blocked.is_some_and(|b| b < change.seq) {
            read.tx.put(&key::seen(change.seq), &())?;
            self.state.seen.insert(change.seq);
        }
        Ok(())
    }

    /// A call the protocols `to` couldn't answer, or must take after an earlier one they
    /// owe: kept in the commit that passes its item, and made again by later reads
    /// ([`App::retry_owed`]), so the cursor never passes what a protocol wasn't told. Those
    /// protocols are handed nothing later until they take it; a deny list change stops the
    /// page after its item, so nothing later is handed to any protocol before it (Switch
    /// spec 8.3).
    fn owe(
        &mut self,
        seq: u64,
        to: Vec<String>,
        call: OwedCall,
        read: &mut Read,
    ) -> Result<(), AppError> {
        if self.owed_held_reads == 0 {
            // The first of the reads that end with a call owed.
            self.owed_held_reads = 1;
        }
        self.owing.extend(to.iter().cloned());
        // A deny list change, or a call every protocol now owes, stops the page after its
        // item: nothing later is handed to any protocol before it, and with one protocol a
        // call it fails stops the read.
        if call.is_deny() || self.all_owing() {
            read.held_after = true;
            self.owed_known = Some(true);
        }
        read.tx.put(
            &key::owed(self.state.cursor.generation, seq),
            &Owed { to, call },
        )
    }

    /// Where the item at (`generation`, `seq`) stands in feed order (Switch spec 8.3). A
    /// cooperative move and a key change in place continue the sequence, so the positions
    /// of the current sequence compare by `seq` alone, whatever generation names them. A
    /// position of a sequence a provider loss ended comes before all of them, by
    /// generation, then `seq`: the newest own `identity.json` names only the newest loss,
    /// so two positions of one lost sequence at different generations may compare out of
    /// feed order; the deny list gap the loss leaves, told after them, carries the full
    /// list. One of a generation past the newest own `identity.json` the app holds, as a
    /// restore in place may carry, is of a sequence it doesn't know yet: it comes after
    /// everything it knows, and waits until the app follows it.
    fn feed_order(&self, generation: u64, seq: u64) -> (u8, u64, u64) {
        if generation > self.state.own_doc.generation() {
            (2, generation, seq)
        } else if self.current_sequence(generation) {
            (1, 0, seq)
        } else {
            (0, generation, seq)
        }
    }

    /// Whether the owed call stored under `stored` (`owed/<generation>/<seq>`) is at a
    /// position past `cursor` in feed order ([`App::feed_order`]); a key of no other form
    /// isn't.
    pub(crate) fn owed_after(&self, stored: &str, cursor: super::state::Cursor) -> bool {
        stored
            .strip_prefix(key::OWED_PREFIX)
            .and_then(|rest| owed_place(rest).ok())
            .is_some_and(|(generation, seq)| {
                self.feed_order(generation, seq) > self.feed_order(cursor.generation, cursor.seq)
            })
    }

    /// Whether positions of the two generations are of one sequence, as far as the app
    /// knows ([`App::feed_order`]).
    fn same_sequence(&self, a: u64, b: u64) -> bool {
        a == b || (self.feed_order(a, 0).0 == 1 && self.feed_order(b, 0).0 == 1)
    }

    /// The calls the protocols couldn't answer before, made again in feed order
    /// ([`App::feed_order`]), each to the protocols it is owed to, in one commit with their
    /// writes and with their names taken out, so none is handed a call twice. One that
    /// fails again holds back every later call of that protocol, and the read hands that
    /// protocol nothing after it; a deny list change a protocol fails, or can't take yet
    /// behind an earlier call, holds every later call of every protocol, and the read hands
    /// nothing after it (Switch spec 8.3). A deny list change owed for its check is checked
    /// again first: handed, refused with an event, owed still, or noted as a gap. A deny
    /// list change behind the cursor is noted as a gap at the cursor instead.
    async fn retry_owed(&mut self) -> Result<(), AppError> {
        let owed = self.reader().scan::<Owed>(key::OWED_PREFIX).await?;
        let mut held = false;
        // The protocols a call failed for in this pass: their later calls wait.
        let mut blocked: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let cursor = self.state.cursor;
        let cursor_at = self.feed_order(cursor.generation, cursor.seq);
        self.owed_ahead = None;
        // In feed order, not key order: the keys name the generation each item was read
        // at, and a restore in place carries calls of a generation the sequence went on
        // from. Every call is keyed by its feed position (`owed/<generation>/<seq>`): a
        // key that doesn't name one has no place in that order, so the store is corrupt,
        // and no call is made out of order or dropped.
        let mut owed = owed
            .into_iter()
            .map(|(rest, owed)| {
                let place = owed_place(&rest)?;
                let order = self.feed_order(place.0, place.1);
                Ok((order, place, rest, owed))
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        owed.sort_by_key(|(order, ..)| *order);
        for (order, (generation, seq), rest, Owed { to, call }) in owed {
            // Every writer names at least one protocol: a call owed to none is a corrupt
            // store, neither made nor dropped.
            if to.is_empty() {
                return Err(AppError::Store(crate::error::StoreError::Corrupt));
            }
            let at = format!("{}{rest}", key::OWED_PREFIX);
            // A call past the cursor, as a restore in place carries one, waits for the
            // feed to reach its item: the feed stops before anything later.
            if order > cursor_at {
                if self.same_sequence(generation, cursor.generation) {
                    self.owed_ahead = Some(seq);
                }
                break;
            }
            // Neither dropped nor handed while the store is corrupt (fail closed).
            let kept_body = call.kept_op_body()?;
            let mut tx = self.tx()?;
            // A deny list change behind the cursor, as a restore in place from a newer
            // backup carries one, or one of a sequence a provider loss ended once the
            // cursor follows the next: the feed handed the later changes before it, and
            // won't hand them again. Handed now, or applied to the copy of the lists, it
            // would set an older state over them, so it is a gap in the deny list's
            // history at the cursor instead: the protocol and the copy both take the list
            // as it stands (Switch spec 8.3). A change not checked yet is checked first, as
            // at the cursor: one that isn't genuine is refused with its event, never made a
            // gap, and one that can't be checked yet stays owed and holds the rest.
            if order < cursor_at
                && matches!(
                    call,
                    OwedCall::Deny { .. } | OwedCall::DenyUnverified { .. }
                )
            {
                if let OwedCall::DenyUnverified {
                    generation,
                    seq,
                    at_ms,
                    op,
                    ..
                } = &call
                {
                    let Some(body) = &kept_body else {
                        return Err(AppError::Store(crate::error::StoreError::Corrupt));
                    };
                    match self.check_deny_op(op, body, *at_ms, &tx).await? {
                        DenyCheck::NotGenuine(reason) => {
                            self.events.push(AppEvent::DenyListChangeRefused {
                                generation: *generation,
                                seq: *seq,
                                reason: reason.into(),
                            });
                            tx.delete(&at)?;
                            self.commit(tx).await?;
                            continue;
                        }
                        DenyCheck::NotYet => {
                            held = true;
                            break;
                        }
                        DenyCheck::Genuine | DenyCheck::Unverifiable => {}
                    }
                }
                self.note_deny_gap(cursor.generation, cursor.seq, &mut tx)
                    .await?;
                tx.delete(&at)?;
                self.commit(tx).await?;
                continue;
            }
            let call = match call {
                OwedCall::DenyUnverified {
                    generation,
                    seq,
                    pubky,
                    added,
                    at_ms,
                    op,
                } => {
                    let Some(body) = kept_body else {
                        return Err(AppError::Store(crate::error::StoreError::Corrupt));
                    };
                    match self.check_deny_op(&op, &body, at_ms, &tx).await? {
                        DenyCheck::Genuine => {
                            self.note_list_op(&body, &mut tx)?;
                            if !self.state.cert.has_permission(Permission::ListsRead) {
                                tx.delete(&at)?;
                                self.commit(tx).await?;
                                continue;
                            }
                            OwedCall::Deny {
                                generation,
                                seq,
                                pubky,
                                added,
                                at_ms,
                            }
                        }
                        DenyCheck::NotGenuine(reason) => {
                            self.events.push(AppEvent::DenyListChangeRefused {
                                generation,
                                seq,
                                reason: reason.into(),
                            });
                            tx.delete(&at)?;
                            self.commit(tx).await?;
                            continue;
                        }
                        DenyCheck::NotYet => {
                            held = true;
                            break;
                        }
                        DenyCheck::Unverifiable => {
                            self.note_deny_gap(generation, seq.saturating_sub(1), &mut tx)
                                .await?;
                            tx.delete(&at)?;
                            self.commit(tx).await?;
                            continue;
                        }
                    }
                }
                // At the cursor: the copy of the lists takes the change in the commit that
                // hands it to the protocol, so the two never disagree after a crash. Where
                // the feed applied it when the call was owed, this sets the same state
                // again; after a restore in place, whose feed passes the carried call's
                // item without applying it, this is where the copy takes it, after the
                // changes the feed handed before it (Switch spec 8.3).
                // An app that no longer holds `lists.read`, a renewal having removed it, is
                // handed no deny list change (Switch spec 8.3): the copy still takes it, and
                // the call is gone, as for a change checked here.
                call @ OwedCall::Deny { pubky, added, .. } => {
                    self.note_deny_change(&pubky, added, &mut tx)?;
                    if !self.state.cert.has_permission(Permission::ListsRead) {
                        tx.delete(&at)?;
                        self.commit(tx).await?;
                        continue;
                    }
                    call
                }
                call => call,
            };
            // A deny list change goes to no protocol while one it is owed to can't take
            // it, behind an earlier call it failed: the read holds for every protocol.
            if call.is_deny() && to.iter().any(|name| blocked.contains(name)) {
                held = true;
                break;
            }
            let mut left = Vec::new();
            for name in to {
                if blocked.contains(&name) {
                    left.push(name);
                    continue;
                }
                let Some(protocol) = self.protocols.get(&name).cloned() else {
                    return Err(AppError::Store(crate::error::StoreError::Corrupt));
                };
                let Ok(writes) = call.make(protocol.as_ref()) else {
                    blocked.insert(name.clone());
                    left.push(name);
                    continue;
                };
                if local_writes_bytes(&writes) > MAX_STEP_LOCAL_BYTES {
                    // Over the bound: not committed, and the call made no more, since the
                    // same answer would come at every read; the protocol is told.
                    self.keep_duty_for(
                        &mut tx,
                        vec![name],
                        Duty::LocalWritesRefused {
                            call: KeptRefusal::Owed {
                                seq,
                                call: call.clone(),
                            },
                        },
                    )?;
                } else {
                    tx.local(&super::protocols::qualify(&name, writes))?;
                }
            }
            let failed_deny = call.is_deny() && !left.is_empty();
            if left.is_empty() {
                tx.delete(&at)?;
            } else {
                tx.put(&at, &Owed { to: left, call })?;
            }
            self.commit(tx).await?;
            if failed_deny {
                held = true;
                break;
            }
        }
        // Every protocol owes a call it failed: nothing can be handed to any, so the read
        // holds, as it does for one protocol.
        let every = !blocked.is_empty()
            && self
                .protocols
                .iter()
                .all(|registered| blocked.contains(&registered.name));
        self.owed_known = Some(held || every);
        self.owing = blocked;
        Ok(())
    }

    /// Whether every registered protocol owes a call it hasn't taken yet ([`App::owe`]).
    fn all_owing(&self) -> bool {
        self.protocols
            .iter()
            .all(|registered| self.owing.contains(&registered.name))
    }

    fn handle_unreadable(
        &mut self,
        seq: u64,
        sender: [u8; 32],
        accepted_at: u64,
        read: &mut Read,
    ) -> Result<Step, AppError> {
        let me = self.state.meta.app_id;
        let departed = self
            .state
            .departed
            .iter()
            .any(|(app, at)| *app != me && accepted_at <= *at);
        let asked = departed
            && sender != self.state.meta.identity
            && accepted_at >= self.resend_floor()
            && self.ask_resend(
                seq,
                ResendNeeded {
                    sender,
                    accepted_from_ms: accepted_at,
                    accepted_until_ms: accepted_at,
                    reason: ResendReason::Unreadable,
                },
                read,
            )?;
        self.events.push(AppEvent::Unreadable {
            seq,
            resend_asked: asked,
        });
        Ok(Step::Pass)
    }

    /// A `missed` item, with its first and last acceptance times when both parse.
    fn handle_missed(
        &mut self,
        seq: u64,
        entries: u64,
        accepted: Option<(u64, u64)>,
        read: &mut Read,
    ) -> Result<Step, AppError> {
        let Some((from, until)) = accepted else {
            // The service writes the item: one whose times don't parse asks for no re-send,
            // but still owes the listing (Switch spec 8.2, wire 7.4.4).
            if self.state.asked.insert(seq) {
                read.tx.put(&key::asked(seq), &())?;
                super::records::owe_listing(&mut read.tx)?;
                read.list_first = true;
            }
            return Ok(Step::Pass);
        };
        if self.state.asked.insert(seq) {
            let accepted_from_ms = from.max(self.resend_floor());
            let call = OwedCall::Missed {
                seq,
                entries,
                accepted_from_ms,
                accepted_until_ms: until.max(accepted_from_ms),
            };
            self.hand_call(seq, call, read)?;
            read.tx.put(&key::asked(seq), &())?;
            super::records::owe_listing(&mut read.tx)?;
            read.list_first = true;
            self.events.push(AppEvent::Missed { seq, entries });
        }
        Ok(Step::Pass)
    }

    // ---------------------------------------------------------------------------------
    // Chain items

    async fn handle_chain(
        &mut self,
        item: &ChainItem,
        envelope: &ChainEnvelope,
        read: &mut Read,
    ) -> Result<Step, AppError> {
        let bytes = item.item.doc_bytes()?;
        if let Err(error) = Verifier::check_item(envelope, item.item_type, &bytes) {
            return Err(self
                .raise(Alarm::Rollback {
                    reason: error.to_string(),
                })
                .await);
        }
        let identity = self.state.meta.identity;
        let me = self.state.meta.app_id;
        match item.item_type {
            ItemType::Identity => {
                let Ok(doc) = IdentityDoc::verify(&item.item, &identity) else {
                    return Ok(Step::Pass);
                };
                self.own_identity_copy(doc, read).await
            }
            ItemType::Op => {
                let Ok(op) = SignedOp::peek(&item.item) else {
                    return Ok(Step::Pass);
                };
                let body = op.body();
                if let OpKind::DenyPut { pubky } | OpKind::DenyDelete { pubky } = &body.kind {
                    let change = DenyListChange {
                        generation: envelope.generation,
                        seq: item.seq,
                        pubky: *pubky,
                        added: matches!(body.kind, OpKind::DenyPut { .. }),
                        at_ms: envelope.server_time,
                    };
                    let body = body.clone();
                    self.take_deny_op(&item.item, &body, change, read).await?;
                    return Ok(Step::Pass);
                }
                self.note_list_op(body, &mut read.tx)?;
                match &body.kind {
                    OpKind::ReceiveKeyPut { record } if body.app_id == Some(me) => {
                        match self.own_registration(
                            item.seq,
                            envelope.server_time,
                            record,
                            &mut read.tx,
                        )? {
                            RegistrationStep::Continue => Ok(Step::Pass),
                            RegistrationStep::Stop => Ok(Step::Stop),
                            RegistrationStep::Compromise(alarm) => {
                                let error = self.raise(alarm).await;
                                self.leave_on_compromise().await;
                                Err(error)
                            }
                        }
                    }
                    OpKind::KeyBundlePut(put)
                        if put.target_app_id == me && body.app_id.is_none() =>
                    {
                        // Fetched before the cursor passes the part (Switch spec 3.5). A
                        // part stored after the full-bundle request answers it.
                        self.part_stored(envelope.server_time);
                        self.fetch_key_parts().await?;
                        Ok(Step::Pass)
                    }
                    OpKind::CertPut {
                        target_app_id,
                        cert,
                    } if *target_app_id == me && body.app_id.is_none() => {
                        self.note_renewal(cert, &mut read.tx)?;
                        Ok(Step::Pass)
                    }
                    // A record write is judged and marked for the protocol of its collection:
                    // not past a call that protocol owes. It is held, as that protocol's
                    // entries are, the cursor staying before it, and judged once the protocol
                    // took what it owes; so is one whose protocol the app can't tell while
                    // any protocol owes (Switch spec 8.3).
                    OpKind::RecordPut(put)
                        if !self.owing.is_empty()
                            && self
                                .record_protocol(&put.key)
                                .await?
                                .is_none_or(|name| self.owing.contains(&name)) =>
                    {
                        Ok(Step::Hold)
                    }
                    OpKind::RecordPut(_)
                    | OpKind::Claim(_)
                    | OpKind::AppPut { .. }
                    | OpKind::AllowPut { .. }
                    | OpKind::AllowDelete { .. }
                    | OpKind::DenyPut { .. }
                    | OpKind::DenyDelete { .. } => {
                        self.feed_shared_item(item, envelope, &mut read.tx).await?;
                        Ok(Step::Pass)
                    }
                    _ => Ok(Step::Pass),
                }
            }
            ItemType::Service => {
                // Transitions of an earlier generation came with a move, signed by the
                // service of their generation.
                let Some(service_key) = self.service_key_of(envelope.generation).await? else {
                    return Ok(Step::Pass);
                };
                let Ok(transition) = ServiceTransition::verify(&item.item, &service_key, &identity)
                else {
                    return Ok(Step::Pass);
                };
                match transition {
                    ServiceTransition::Leave { app_id, at }
                    | ServiceTransition::Revoke { app_id, at } => {
                        if app_id == me {
                            self.push_once(AppEvent::Removed);
                            return Ok(Step::Stop);
                        }
                        read.tx.put(&key::departed(&app_id), &at)?;
                        self.state.departed.insert(app_id, at);
                        Ok(Step::Pass)
                    }
                    // What an upload merged here has no chain item of its own: the claims
                    // and records it lists are read again at the end of the read (Switch
                    // wire 7.4.14). Changes that don't read mark nothing.
                    ServiceTransition::Upload { changes, .. } => {
                        if let Ok(changes) = UploadChanges::from_value(&changes) {
                            // Owned keys: the read's future stays `Send` across the awaits.
                            let records = changes.records.iter().chain(&changes.divergent);
                            let claims = changes.claims.iter().chain(&changes.divergent_claims);
                            self.mark_uploaded(
                                records.copied().collect(),
                                claims.copied().collect(),
                                &mut read.tx,
                            )
                            .await?;
                            // One past the record marks owes a listing: made before any
                            // later entry is handed over, as a `missed` item's is.
                            if read.tx.pending_state(super::records::LIST_DUE) == Some(true) {
                                read.list_first = true;
                            }
                        }
                        Ok(Step::Pass)
                    }
                    // A frozen account's pages carry the freeze, which `process_page` takes
                    // before any item; a freeze transition on another page is history: a
                    // move followed, read again at the next service, or a cancelled one.
                    _ => Ok(Step::Pass),
                }
            }
        }
    }

    /// An own `identity.json` copy from the feed, the directory or the Homeserver (Switch
    /// spec 4.3): another body at a version seen, or a later version that lists a removed
    /// App ID again, is an alarm; a lower one is ignored; a newer one is taken.
    async fn own_identity_copy(
        &mut self,
        doc: IdentityDoc,
        read: &mut Read,
    ) -> Result<Step, AppError> {
        let held = self.state.own_doc.clone();
        if held.compare(&doc) == pubky_switch_core::records::VersionOrder::Newer
            && let Err(alarm) = identity::check_own_successor(&held, &doc)
        {
            return Err(self.raise(alarm).await);
        }
        let now = self.now();
        let reader = self.reader();
        let taken = identity::take_copy(&reader, &mut read.tx, &doc, Some(&held), now).await?;
        let doc = match taken {
            Err(equivocation) => {
                return Err(self
                    .raise(Alarm::Equivocation {
                        version: equivocation.version,
                    })
                    .await);
            }
            Ok(Taken::Newer) => doc,
            Ok(Taken::Same | Taken::Older) => return Ok(Step::Pass),
        };
        let me = self.state.meta.app_id;
        if doc.data_epoch() > held.data_epoch() {
            read.epoch_rose = true;
        }
        if doc.generation() != held.generation() {
            // The last copy of the generation left, for its service key and the uploads of
            // a recovery (`provider.rs`).
            self.keep_generation(&held, &mut read.tx)?;
        }
        self.state.own_doc = doc.clone();
        self.events.push(AppEvent::IdentityUpdated {
            version: doc.version(),
        });
        if doc.lists_removed(&me) {
            self.push_once(AppEvent::Removed);
            return Ok(Step::Stop);
        }
        if doc.generation() != self.state.meta.generation {
            self.push_once(AppEvent::ProviderChanged {
                generation: doc.generation(),
            });
            return Ok(Step::Stop);
        }
        if self
            .state
            .renewal
            .as_ref()
            .is_some_and(|r| doc.listed_cert(&me) == Some(r.hash()))
        {
            // Everything read so far first, so the delivery is in the store.
            read.tx.put(key::CURSOR, &self.state.cursor)?;
            let tx = std::mem::replace(&mut read.tx, self.tx()?);
            self.commit(tx).await?;
            self.adopt_renewal().await?;
        }
        Ok(Step::Pass)
    }

    /// Whether the newest own `identity.json` says the app isn't current at this service:
    /// removed, or the identity moved to another generation, which the provider-change flow
    /// follows.
    pub(crate) fn not_current_here(&self) -> Option<AppEvent> {
        let doc = &self.state.own_doc;
        if doc.lists_removed(&self.state.meta.app_id) {
            return Some(AppEvent::Removed);
        }
        (doc.generation() != self.state.meta.generation).then(|| AppEvent::ProviderChanged {
            generation: doc.generation(),
        })
    }

    /// Take an own copy outside the feed and commit what it changed.
    pub(crate) async fn take_own_copy(&mut self, doc: IdentityDoc) -> Result<bool, AppError> {
        self.take_own_copy_with(doc, |_| Ok(())).await
    }

    /// [`App::take_own_copy`], with `also` written in the same commit as the copy, and only
    /// if the copy is taken.
    pub(crate) async fn take_own_copy_with(
        &mut self,
        doc: IdentityDoc,
        also: impl FnOnce(&mut Tx) -> Result<(), AppError>,
    ) -> Result<bool, AppError> {
        // A published `identity.json`: the erasure wait starts over (Switch spec 12.7).
        self.clear_erasing().await?;
        let version = self.state.own_doc.version();
        let mut read = Read::outside(self.tx()?);
        let result = self.own_identity_copy(doc, &mut read).await;
        if result.is_err() {
            self.reload = true;
        }
        result?;
        also(&mut read.tx)?;
        let epoch_rose = read.epoch_rose;
        self.commit(read.tx).await?;
        if epoch_rose {
            self.fetch_key_bundle().await?;
        }
        Ok(self.state.own_doc.version() > version)
    }

    // ---------------------------------------------------------------------------------
    // Cursor moves and housekeeping

    /// Send a deferred cursor move that waited long enough (Switch spec 8.2).
    pub(crate) async fn flush_cursor_if_due(&mut self) -> Result<(), AppError> {
        let Some(since) = self.state.cursor.deferred_since_ms else {
            return Ok(());
        };
        if self.now() < since.saturating_add(self.config.defer_ms()) {
            return Ok(());
        }
        self.send_cursor().await
    }

    /// Send a deferred cursor move now, alone: before the app stops reading, for example
    /// when it goes to the background (Switch spec 8.2).
    ///
    /// # Errors
    ///
    /// A failed call or commit.
    pub async fn flush_cursor(&mut self) -> Result<(), AppError> {
        Box::pin(async move {
            self.ready_local().await?;
            self.refuse_when_stopped()?;
            self.send_cursor().await
        })
        .await
    }

    async fn send_cursor(&mut self) -> Result<(), AppError> {
        let cursor = self.state.cursor;
        if cursor.seq <= cursor.at_service {
            if cursor.deferred_since_ms.is_some() {
                self.state.cursor.deferred_since_ms = None;
                let mut tx = self.tx()?;
                tx.put(key::CURSOR, &self.state.cursor)?;
                self.commit(tx).await?;
            }
            return Ok(());
        }
        let batch = Batch::cursor_only(Position {
            generation: cursor.generation,
            seq: cursor.seq,
        });
        self.submit(&batch).await?;
        let mut tx = self.tx()?;
        tx.put(key::CURSOR, &self.state.cursor)?;
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut tx)?;
        }
        self.commit(tx).await
    }

    /// Forget processed pairs past their retention (Switch spec 11), oldest first.
    async fn prune_processed(&mut self) -> Result<(), AppError> {
        let cutoff = self.now().saturating_sub(PROCESSED_RETENTION_MS);
        let prefix = b"proct/";
        let page = self.env.store.scan(&self.ns, prefix, None, 256).await?;
        let mut tx = self.tx()?;
        for (raw, _) in page {
            let Some(rest) = raw
                .get(prefix.len()..)
                .and_then(|rest| std::str::from_utf8(rest).ok())
            else {
                continue;
            };
            let mut parts = rest.splitn(3, '/');
            let (Some(at), Some(sender), Some(msg_id)) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let Ok(at) = super::state::parse_num(at) else {
                continue;
            };
            if at >= cutoff {
                break;
            }
            let sender = pubky_switch_core::enc::pubky_key(sender)
                .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?;
            tx.delete(&key::processed(&sender, msg_id))?;
            tx.delete(&key::processed_at(at, &sender, msg_id))?;
        }
        if !tx.is_empty() {
            self.commit(tx).await?;
        }
        Ok(())
    }
}

/// The processed pair of a message whose entry is parked as [`ParkReason::Uncertain`]: its
/// effect may have been applied, so a re-send of it is a duplicate and never applies it
/// again (Switch spec 11, 12.5 "Kept batches"). Every park as `Uncertain` writes it, in the
/// same commit.
pub(crate) fn uncertain_processed(
    tx: &mut Tx,
    sender: &[u8; 32],
    msg_id: &str,
    hash: [u8; 32],
    now: u64,
) -> Result<(), AppError> {
    processed_writes(tx, sender, msg_id, hash, now)
}

/// The processed pair and its time index.
pub(crate) fn processed_writes(
    tx: &mut Tx,
    sender: &[u8; 32],
    msg_id: &str,
    hash: [u8; 32],
    now: u64,
) -> Result<(), AppError> {
    tx.put(
        &key::processed(sender, msg_id),
        &Processed { hash, at_ms: now },
    )?;
    tx.put(&key::processed_at(now, sender, msg_id), &())?;
    Ok(())
}

/// What processing one entry writes beside its effect's own writes, at most: its processed
/// pair, the cursor, a parked or retry record removed, and the chain view's small fields.
const ENTRY_RESERVE_BYTES: u64 = 256 * 1024;

/// What storing an entry locally writes, at most: its plaintext (the 64 KiB envelope, 87
/// KiB in base64), the sender's certificate (under 33 KiB) and its duty events.
const PARK_ROOM_BYTES: u64 = 256 * 1024;

/// The room a read keeps for its next feed item: the read's writes are committed early
/// before an item once more would leave less, so the page's commit always fits the 32 MiB
/// batch size (high-water mark: 32 - 12 = 20 MiB). One item writes at most:
/// - a kept effect, under 10.9 MiB (`MAX_STEP_LOCAL_BYTES`), which goes in a commit of its
///   own at once (`send_effect`);
/// - an effect without operations, its local writes at most 4 MiB as stored
///   (`MAX_STEP_LOCAL_BYTES`), with its processed pair;
/// - a call's local writes ([`Protocol::resend_needed`], [`Protocol::missed`],
///   [`Protocol::deny_list_changed`]), at most 4 MiB, or a duty event refusing them;
/// - an entry stored locally ([`PARK_ROOM_BYTES`]) and its duty events;
/// - a chain item's cached record write, its operation and proof and opened value, under
///   1.2 MiB.
///
/// The largest is under 11 MiB; [`ENTRY_RESERVE_BYTES`] and a margin make 12 MiB.
pub(crate) const ITEM_ROOM_BYTES: u64 = 12 * 1024 * 1024;

/// What an applied effect's outcome caches of one record write, at most: its operation
/// (`MAX_OP_BYTES`, 512 KiB) and opened value (256 KiB), both in base64, and its proof.
pub(crate) const CACHED_RECORD_BYTES: u64 = 1_258_291; // 1.2 MiB

/// What a record's mark takes as stored, at most: [`MAX_SEEN_MARK_BYTES`] in base64
/// (87,382 bytes), its key, namespace and encoding (256 bytes).
pub(crate) const KEPT_MARK_BYTES: u64 = (MAX_SEEN_MARK_BYTES as u64).div_ceil(3) * 4 + 256;

// An applied effect's outcome is committed on its own: its local writes, at most
// `MAX_STEP_LOCAL_BYTES` as stored, at most 7 cached record writes with their marks, and
// what processing its entry writes always fit one commit, so an applied effect can't fail
// to commit its outcome for its size.
const _: () = assert!(
    (MAX_STEP_LOCAL_BYTES as u64)
        + 7 * (CACHED_RECORD_BYTES + KEPT_MARK_BYTES)
        + ENTRY_RESERVE_BYTES
        <= MAX_BATCH_BYTES
);
/// The `POST /ops` body cap (Switch wire 7.1), what a kept effect's batch takes at most.
const OPS_BODY_BYTES: u64 = 4 * 1024 * 1024;

/// A kept effect at its largest (`pending/effect`, `MAX_STEP_LOCAL_BYTES`): its batch and
/// its local writes in base64, its plaintext in base64 (the 64 KiB envelope), the
/// certificate (33 KiB), a context (1 KiB) and its other fields (8 KiB).
const KEPT_EFFECT_BYTES: u64 =
    (OPS_BODY_BYTES + MAX_STEP_LOCAL_BYTES as u64).div_ceil(3) * 4 + 87_382 + (42 << 10);

// What one feed item writes, at most, fits [`ITEM_ROOM_BYTES`]:
// - a kept effect, which also fits one value;
const _: () = assert!(KEPT_EFFECT_BYTES <= MAX_VALUE_BYTES);
const _: () = assert!(KEPT_EFFECT_BYTES + ENTRY_RESERVE_BYTES <= ITEM_ROOM_BYTES);
// - an effect without operations, or a call's local writes, with a duty event or an entry
//   stored locally;
const _: () = assert!(
    (MAX_STEP_LOCAL_BYTES as u64) + PARK_ROOM_BYTES + ENTRY_RESERVE_BYTES <= ITEM_ROOM_BYTES
);
// - a chain item's cached record write, its mark and a flagged write's rule.
const _: () = assert!(
    CACHED_RECORD_BYTES
        + KEPT_MARK_BYTES
        + (MAX_REGRESSION_REASON_BYTES as u64)
        + ENTRY_RESERVE_BYTES
        <= ITEM_ROOM_BYTES
);
// So one more item always fits beside the read's writes kept to the high-water mark.
const _: () = assert!(ITEM_ROOM_BYTES + ENTRY_RESERVE_BYTES < MAX_BATCH_BYTES);

/// The bytes a write of `value_len` value bytes at `key` counts against a batch in `ns`.
fn write_size(ns: &str, key: &str, value_len: u64) -> u64 {
    let len = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    len(ns.len())
        .saturating_add(len(key.len()))
        .saturating_add(value_len)
}

/// The bytes the protocol's local writes count against a batch in `ns`, under its prefix.
fn local_size(ns: &str, local: &[LocalWrite]) -> u64 {
    let prefix = u64::try_from(PROTOCOL_PREFIX.len()).unwrap_or(u64::MAX);
    let len = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    local.iter().fold(0u64, |total, write| {
        let (key, value) = match write {
            LocalWrite::Put { key, value } => (key.len(), value.len()),
            LocalWrite::Delete { key } => (key.len(), 0),
            LocalWrite::DeletePrefix { prefix } => (prefix.len(), 0),
        };
        total
            .saturating_add(len(ns.len()))
            .saturating_add(prefix)
            .saturating_add(len(key))
            .saturating_add(len(value))
    })
}
