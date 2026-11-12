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
    Effect, LocalWrite, MAX_CLAIM_READS, MAX_REGRESSION_REASON_BYTES, MAX_SEEN_MARK_BYTES,
    MAX_STEP_LOCAL_BYTES, MissedEntries, Need, OpaqueRule, Outcome, PARKED_RETRIES_PER_READ,
    Protocol, RETRY_EVENT_READS, ReceivedMessage, ResendNeeded, ResendReason, Rules, StoreFailure,
    local_writes_bytes,
};
use super::provider::TakeOver;
use super::records::{Collection, pending_name_key};
use super::rotation::RegistrationStep;
use super::state::{
    CachedDoc, HeldEntry, KeptEntry, PROTOCOL_PREFIX, ParkedEntry, PendingEffect, Processed,
    RetryEntry, Tx, encode, key,
};
use super::{App, AppError, PROCESSED_RETENTION_MS};
use crate::client::Batch;
use crate::client::answers::{ChainItem, EntryItem, FeedItem, FeedPage, FeedQuery};
use crate::error::ClientError;
use crate::store::{MAX_BATCH_BYTES, MAX_VALUE_BYTES};

/// What one read did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReceiveReport {
    /// Everything that happened, in order.
    pub events: Vec<AppEvent>,
    /// The position processed to.
    pub cursor: Position,
    /// The read stopped before the end of the feed: a key another device made that this
    /// one lacks, the app's removal, or a provider change.
    pub stopped: bool,
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

/// `owed/<generation>/<seq>`: a protocol call about a feed item that the protocol couldn't
/// answer (`Protocol::resend_needed`, `Protocol::missed`), kept until it does.
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

impl OwedCall {
    /// The call, made again.
    fn make(&self, protocol: &dyn Protocol) -> Result<Vec<LocalWrite>, StoreFailure> {
        match self.refused(0) {
            RefusedCall::ResendNeeded { needed, .. } => protocol.resend_needed(&needed),
            RefusedCall::Missed(missed) => protocol.missed(&missed),
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
            } => RefusedCall::Missed(MissedEntries {
                seq,
                entries,
                accepted_from_ms,
            }),
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
    /// The protocol's opaque rules.
    opaque: Vec<OpaqueRule>,
    /// The own data epoch rose: fetch the key bundle after the page.
    epoch_rose: bool,
    /// The (sender, `msg_id`) pairs processed in this read and not yet committed, with
    /// their message hashes (Switch spec 11).
    pairs: HashMap<([u8; 32], String), [u8; 32]>,
}

impl Read {
    fn new(tx: Tx, blocked: Option<u64>, opaque: Vec<OpaqueRule>) -> Self {
        Self {
            tx,
            blocked,
            opaque,
            epoch_rose: false,
            pairs: HashMap::new(),
        }
    }

    /// A read outside the feed, for a copy taken from the directory or the Homeserver.
    fn outside(tx: Tx) -> Self {
        Self::new(tx, None, Vec::new())
    }

    fn block(&mut self, seq: u64) {
        self.blocked = Some(self.blocked.map_or(seq, |b| b.min(seq)));
    }
}

/// The least time, device clock, between two reads of one sender's `identity.json` that a
/// failed check 7 against a held copy makes (Switch wire 5.1 check 7). Within it, an entry
/// of the sender failing the check in a later read is held, not dropped, until the first
/// read after it reads the document again.
pub const SENDER_REREAD_MS: u64 = 60_000;

/// When a failed check 7 last had a sender's `identity.json` read again: the device time,
/// the read it came in ([`App::receive`]'s count), and whether the document could be read.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SenderReread {
    at_ms: u64,
    read: u64,
    reached: bool,
}

impl App {
    /// Read the feed to its end and process it (Switch spec 8.2, 8.3), then delete the
    /// retired receive keys the cursor passed, rotate if due, and send a deferred cursor
    /// move that is due. `wait` long-polls the first page, at most 25 seconds. Before the
    /// feed, the batches kept from earlier calls are sent again; one that still can't be
    /// sent stays kept and is reported in this read's report
    /// ([`AppEvent::KeptBatchesWaiting`]), and the read goes on.
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
            let result = self.receive_once(wait).await;
            // A move, a provider change, a revocation or an erasure met during the read is
            // followed (`provider.rs`), and the read goes on once at the service followed.
            let result = match self.take_over(result).await {
                TakeOver::Done(result) => result,
                TakeOver::ReadAgain => self.receive_once(None).await,
            };
            if result.is_err() {
                self.reload = true;
            }
            let mut report = result?;
            report.events = self.take_events();
            Ok(report)
        })
        .await
    }

    /// One read. [`AppEvent::KeptBatchesWaiting`] goes only in the report of the read that
    /// met it: a read that fails drops it, its error being the outcome, so no later report
    /// carries a stale one.
    async fn receive_once(&mut self, wait: Option<u32>) -> Result<ReceiveReport, AppError> {
        let raised = self.events.len();
        let result = self.receive_inner(wait).await;
        if result.is_err() {
            let mut index = 0;
            self.events.retain(|event| {
                index += 1;
                index <= raised || !matches!(event, AppEvent::KeptBatchesWaiting { .. })
            });
        }
        result
    }

    async fn receive_inner(&mut self, wait: Option<u32>) -> Result<ReceiveReport, AppError> {
        self.reads_begun = self.reads_begun.wrapping_add(1);
        if matches!(self.state.alarm, Some(Alarm::Compromise { .. })) {
            self.leave_on_compromise().await;
        }
        self.refuse_when_halted()?;
        self.finish_join().await?;
        if let Some(report) = self.follow_provider_change().await? {
            return Ok(report);
        }
        if let Some(stop) = self.not_current_here() {
            self.events.push(stop);
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
                    self.check_key_after_restore(current).await?;
                }
                // A newer own document the directory brought: the next read follows it.
                super::renewal::Listed::NotCurrentHere => {
                    if let Some(stop) = self.not_current_here() {
                        self.events.push(stop);
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
        // wait on it, refused for the expired one (`403 cert_expired`).
        self.adopt_renewal().await?;
        // A copy of the lists not known to be complete is refreshed before any entry, the
        // ones stored locally included, is handed over.
        self.refresh_lists_if_owed().await?;
        self.resume_pending_effect().await?;
        // The batches kept from earlier calls go before the feed, and before anything the
        // read writes itself, so a lost answer is settled by this read (Switch wire 6.4
        // step 5).
        let waiting = self.resume_batches_before_feed().await?;
        if let Some(waiting) = waiting {
            self.events.push(waiting);
        }
        self.deliver_record().await?;
        self.ensure_scope_keys().await?;
        self.prune_processed().await?;
        self.retell_restored().await?;
        // The bounds on entries stored unverified go before any is tried again (Switch
        // spec 8.2).
        self.bound_unverified().await?;
        self.retry_parked().await?;
        self.retry_owed().await?;
        self.list_collections_if_due().await?;
        let mut report = ReceiveReport::default();
        let mut wait = wait.map(|w| w.min(25));
        // The read position moves on page by page, past a held entry, while the cursor
        // stays before it (Switch spec 8.2); the held `seq` carries over to later pages.
        let mut after = self.state.cursor.seq;
        let mut blocked = None;
        loop {
            if let (Some(seconds), Some(since)) = (wait, self.state.cursor.deferred_since_ms) {
                let due = since.saturating_add(self.config.defer_ms());
                let left = due.saturating_sub(self.now()).div_ceil(1000).max(1);
                wait = Some(seconds.min(u32::try_from(left).unwrap_or(u32::MAX)));
            }
            let query = FeedQuery {
                after: Some(Position {
                    generation: self.state.cursor.generation,
                    seq: after,
                }),
                limit: Some(self.config.page()),
                wait: wait.take(),
            };
            let result = self.client.feed(query).await;
            let page = self.take(result).await?;
            let scanned = page.scanned_through;
            match self.process_page(page, after, &mut blocked).await? {
                Some(true) => after = after.max(scanned).max(self.state.cursor.seq),
                Some(false) => break,
                None => {
                    report.stopped = true;
                    break;
                }
            }
        }
        if self.state.alarm.is_none() {
            // A stopped read leaves the claims and records it marked for the next one.
            if !report.stopped {
                self.reread_claims().await?;
                self.reread_records().await?;
                self.fetch_entry_writers().await?;
            }
            self.delete_retired_keys().await?;
            self.forget_chain_behind_cursor().await?;
            self.maybe_rotate().await?;
            self.flush_cursor_if_due().await?;
        }
        report.cursor = self.cursor();
        Ok(report)
    }

    /// One page, read after `after`, with the lowest `seq` held so far in this read:
    /// `Some(more)`, or `None` when the read stops on it.
    async fn process_page(
        &mut self,
        page: FeedPage,
        after: u64,
        blocked: &mut Option<u64>,
    ) -> Result<Option<bool>, AppError> {
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
        let mut read = Read::new(self.tx()?, *blocked, self.protocol.opaque_members());
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut read.tx)?;
        }
        if let Some(freeze) = &page.freeze {
            // Nothing on a frozen service's page is processed: its items come again from
            // the next service (`provider.rs`).
            self.end_page(read).await?;
            self.note_freeze(freeze).await?;
            return Ok(None);
        }
        let mut stopped = None;
        // A stub names no object: once the page shows the stub of an operation, the claims
        // the app follows are read again at the end of the read (Switch wire 7.5), noted in
        // the commit that passes it.
        let mut stub_noted = !self.state.cert.has_permission(Permission::ClaimsRead);
        for item in &page.items {
            let seq = item.seq();
            if seq <= start {
                continue;
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
                    ..
                } => self.handle_missed(*seq, *entries, *accepted_from, &mut read)?,
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
            if self.state.alarm.is_some() {
                stopped = Some(seq);
                break;
            }
        }
        let end = match (stopped, read.blocked) {
            (Some(stop), _) => stop
                .saturating_sub(1)
                .min(read.blocked.map_or(u64::MAX, |b| b.saturating_sub(1))),
            (None, Some(blocked)) => blocked.saturating_sub(1).min(page.scanned_through),
            (None, None) => page.scanned_through,
        };
        if end > self.state.cursor.seq {
            self.state.cursor.seq = end;
        }
        let epoch_rose = read.epoch_rose;
        *blocked = read.blocked;
        self.end_page(read).await?;
        if epoch_rose && self.state.alarm.is_none() {
            self.fetch_key_bundle().await?;
        }
        if stopped.is_some() {
            return Ok(None);
        }
        Ok(Some(page.more))
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
        self.commit(read.tx).await
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

    async fn handle_entry(&mut self, item: &EntryItem, read: &mut Read) -> Result<Step, AppError> {
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
    async fn check_and_apply(
        &mut self,
        entry: &Entry,
        plaintext: MessagePlaintext,
        parked: bool,
        read: &mut Read,
    ) -> Result<Step, AppError> {
        let held = self.sender_doc(&entry.sender, false).await?;
        let read_now = held.as_ref().is_some_and(|(_, read_now)| *read_now);
        let doc = held.map(|(doc, _)| doc);
        let mut checked = self.check_entry(entry, &plaintext, doc.as_ref(), &read.opaque);
        // Check 7 judges the standing in the sender's newest `identity.json` (Switch wire 5.1):
        // a held copy that doesn't list the certificate may be older than a renewal or a new
        // app, so it is read again once before the entry is dropped.
        if doc.is_some()
            && !read_now
            && matches!(&checked, Err(CheckRefusal::Dropped { check: 7, .. }))
        {
            checked = self
                .check_against_newer_copy(entry, &plaintext, checked, &read.opaque)
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
        let rules = Rules::new(self.protocol.as_ref(), &self.state.cert, opaque);
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
            .is_some_and(ParkedEntry::was_released)
    }

    /// The protocol's check 10, then its effect, at most twice after a conflict: the records
    /// and claims the effect wrote are read again before the second try (Switch spec 8.2,
    /// 10.3).
    async fn apply(
        &mut self,
        entry: &Entry,
        received: Received,
        parked: bool,
        read: &mut Read,
    ) -> Result<Step, AppError> {
        let mut message = ReceivedMessage {
            seq: entry.seq,
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
        if let Err(reason) = self.protocol.check_body(&message) {
            self.note_processed(entry, &received, &[], read)?;
            return Ok(self.dropped(entry.seq, 10, reason));
        }
        let mut tries = 0usize;
        let mut keys_fetched = false;
        // The claims read from the switch at the step's request, for this entry.
        let mut fetched: Vec<([u8; 32], ClaimFetch)> = Vec::new();
        loop {
            let protocol = Arc::clone(&self.protocol);
            let store = Arc::clone(self.env.store.store());
            let may_attempt = self.may_attempt(false).is_ok();
            let (outcome, writes) = {
                let mut cx = ReceiveContext::new(
                    &self.state,
                    protocol.as_ref(),
                    store.as_ref(),
                    &self.ns,
                    may_attempt,
                    &fetched,
                    read.tx.pending_local(),
                    read.tx.pending_writes(),
                );
                let outcome = protocol.receive_with(&message, &mut cx);
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
                Outcome::Apply(effect) => effect,
            };
            if writes.not_now.is_some() {
                // A write the effect needs can't be built yet, for want of a scope key: the
                // key bundle is fetched and the effect built again once; without the key
                // still, the entry waits (Switch spec 3.5).
                if keys_fetched {
                    return Ok(Step::Hold);
                }
                keys_fetched = true;
                self.fetch_key_bundle().await?;
                continue;
            }
            let ContextWrites {
                ops,
                local,
                records,
                claims,
                deadlines,
                not_now: _,
                over_local_bound,
            } = writes;
            effect.ops = ops.into_iter().chain(effect.ops).collect();
            effect.local = local.into_iter().chain(effect.local).collect();
            // A step's local writes are bounded (`Protocol`, "Limits a receive step plans
            // for"): an effect over the bound is too large, stored and passed.
            if over_local_bound || local_writes_bytes(&effect.local) > MAX_STEP_LOCAL_BYTES {
                self.too_large(entry, &received, read).await?;
                return Ok(Step::Pass);
            }
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
                self.received_event(entry, &received);
                return Ok(Step::Pass);
            }
            let written = Written {
                records: &records,
                deadlines: &deadlines,
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
                    self.fetch_key_bundle().await?;
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
    async fn send_effect(
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
        // brought one, a retry of an entry stored locally may come before it.
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
            kept_ms: Some(self.kept_stamp()),
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
    async fn run_effect(
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
                    && self.answer_decides(pending.kept_ms)
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
            })) if !self.answer_decides(pending.kept_ms) => {
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
                    && self.answer_decides(pending.kept_ms)
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
            Some((id, stored)) => (
                id,
                ParkedEntry {
                    reason,
                    released: stored.was_released(),
                    ..stored
                },
            ),
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
        if !self.answer_decides(pending.kept_ms) {
            return self.effect_uncertain(&pending).await;
        }
        self.fresh_service_time().await?;
        if !self.answer_decides(pending.kept_ms) {
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
                .is_some_and(ParkedEntry::was_released),
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
            // Its count of the store's retries goes with it, under its local ID.
            if entry.stored.is_none()
                && let Some(retry) = self.state.retries.remove(&entry.seq)
            {
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
    /// past them.
    ///
    /// At most [`PARKED_RETRIES_PER_READ`] each read, starting where the last read stopped
    /// and going round, so none waits for ever behind others the store keeps failing.
    async fn retry_parked(&mut self) -> Result<(), AppError> {
        let due: Vec<(u64, u64)> = self
            .state
            .parked
            .iter()
            .filter(|(_, stored)| stored.reason.tried_again())
            .map(|(id, stored)| (*id, stored.round))
            .collect();
        if due.is_empty() {
            return Ok(());
        }
        let (ids, round) = self.state.parked_round.turn(&due, PARKED_RETRIES_PER_READ);
        if round != self.state.parked_round {
            self.state.parked_round = round;
            let mut tx = self.tx()?;
            tx.put(key::PARKED_NEXT, &round)?;
            self.commit(tx).await?;
        }
        for id in ids {
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
            let mut read = Read::new(self.tx()?, None, self.protocol.opaque_members());
            let step = self
                .check_and_apply(&entry, plaintext, true, &mut read)
                .await?;
            self.commit(read.tx).await?;
            if step == Step::Pass && !self.state.parked.contains_key(&id) {
                self.events.push(AppEvent::Unparked {
                    seq: stored.seq,
                    stored_id: id,
                });
            }
        }
        Ok(())
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
        let asked = match self.protocol.resend_needed(&needed) {
            Ok(writes) if local_writes_bytes(&writes) > MAX_STEP_LOCAL_BYTES => {
                self.local_writes_refused(seq, OwedCall::from(&needed), read)?;
                false
            }
            Ok(writes) => {
                read.tx.local(&writes)?;
                true
            }
            // Not asked yet: owed, and asked by a later read.
            Err(_) => {
                self.owe(seq, OwedCall::from(&needed), read)?;
                false
            }
        };
        read.tx.put(&key::asked(seq), &())?;
        Ok(asked)
    }

    /// A call whose answer's local writes are over [`MAX_STEP_LOCAL_BYTES`]: not committed,
    /// and not owed, since making it again would bring the same answer; the protocol is
    /// told in the commit that passes its item.
    fn local_writes_refused(
        &mut self,
        seq: u64,
        call: OwedCall,
        read: &mut Read,
    ) -> Result<(), AppError> {
        self.keep_duty(
            &mut read.tx,
            Duty::LocalWritesRefused {
                call: KeptRefusal::Owed { seq, call },
            },
        )
    }

    /// A call the protocol couldn't answer: kept in the commit that passes its item, and
    /// made again by later reads ([`App::retry_owed`]), so the cursor never passes what the
    /// protocol wasn't told.
    fn owe(&mut self, seq: u64, call: OwedCall, read: &mut Read) -> Result<(), AppError> {
        read.tx
            .put(&key::owed(self.state.cursor.generation, seq), &call)
    }

    /// The calls the protocol couldn't answer before, made again, oldest first, each on its
    /// own: one answered commits its writes and goes, in one commit; one that fails again
    /// stays for the next read, and the others are still made.
    async fn retry_owed(&mut self) -> Result<(), AppError> {
        let owed = self.reader().scan::<OwedCall>(key::OWED_PREFIX).await?;
        for (rest, call) in owed {
            let answer = call.make(self.protocol.as_ref());
            let Ok(writes) = answer else {
                continue;
            };
            let mut tx = self.tx()?;
            if local_writes_bytes(&writes) > MAX_STEP_LOCAL_BYTES {
                // Over the bound: not committed, and the call made no more, since the same
                // answer would come at every read; the protocol is told.
                let seq = rest
                    .rsplit('/')
                    .next()
                    .and_then(|seq| super::state::parse_num(seq).ok())
                    .unwrap_or(0);
                self.keep_duty(
                    &mut tx,
                    Duty::LocalWritesRefused {
                        call: KeptRefusal::Owed { seq, call },
                    },
                )?;
            } else {
                tx.local(&writes)?;
            }
            tx.delete(&format!("{}{rest}", key::OWED_PREFIX))?;
            self.commit(tx).await?;
        }
        Ok(())
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

    fn handle_missed(
        &mut self,
        seq: u64,
        entries: u64,
        accepted_from: Option<u64>,
        read: &mut Read,
    ) -> Result<Step, AppError> {
        let Some(from) = accepted_from else {
            // The service writes the item; one whose times don't parse is ignored.
            return Ok(Step::Pass);
        };
        if self.state.asked.insert(seq) {
            let missed = MissedEntries {
                seq,
                entries,
                accepted_from_ms: from.max(self.resend_floor()),
            };
            match self.protocol.missed(&missed) {
                Ok(writes) if local_writes_bytes(&writes) > MAX_STEP_LOCAL_BYTES => self
                    .local_writes_refused(
                        seq,
                        OwedCall::Missed {
                            seq,
                            entries,
                            accepted_from_ms: missed.accepted_from_ms,
                        },
                        read,
                    )?,
                Ok(writes) => read.tx.local(&writes)?,
                Err(_) => self.owe(
                    seq,
                    OwedCall::Missed {
                        seq,
                        entries,
                        accepted_from_ms: missed.accepted_from_ms,
                    },
                    read,
                )?,
            }
            read.tx.put(&key::asked(seq), &())?;
            read.tx.put(super::records::LIST_DUE, &true)?;
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
                        self.fetch_key_bundle().await?;
                        Ok(Step::Pass)
                    }
                    OpKind::CertPut {
                        target_app_id,
                        cert,
                    } if *target_app_id == me && body.app_id.is_none() => {
                        self.note_renewal(cert, &mut read.tx)?;
                        Ok(Step::Pass)
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
                            self.events.push(AppEvent::Removed);
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
                            self.mark_uploaded(
                                changes.records.iter().chain(&changes.divergent),
                                changes.claims.iter().chain(&changes.divergent_claims),
                                &mut read.tx,
                            )
                            .await?;
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
            self.events.push(AppEvent::Removed);
            return Ok(Step::Stop);
        }
        if doc.generation() != self.state.meta.generation {
            self.events.push(AppEvent::ProviderChanged {
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
/// - a call's local writes ([`Protocol::resend_needed`], [`Protocol::missed`]), at most 4
///   MiB, or a duty event refusing them;
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
