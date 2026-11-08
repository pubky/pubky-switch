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
//!   plus the clock tolerance; the same pair with other bytes is shown as a conflict.
//! - **An entry whose sender can't be checked** is held: later items go on, the cursor stays
//!   before it, and the entries processed past it are remembered. After the bounded wait it
//!   is stored locally and passed. An entry whose write hits a quota is stored and passed
//!   too, and applied once there is room.
//! - **An entry no held key opens** is passed; the protocol is asked to request a re-send,
//!   never for a time before the cursor's less the clock tolerance. So is an entry a departed
//!   own app left unread, accepted at or before a departure the app verified in its chain;
//!   and entries missed while lagging.
//! - **Chain items** must match their stubs. The app takes its own `identity.json`
//!   deliveries, its own receive key registrations, key bundle parts (fetched before the
//!   cursor passes them), renewed certificates, and the departures of other own apps.
//!
//! Cursor moves that apply nothing are deferred, for at most a few seconds while the app
//! runs, and go with the next batch or alone ([`App::flush_cursor`]).

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
use pubky_switch_core::sig::SignedDoc;

use super::error::{Alarm, Refusal};
use super::events::{AppEvent, ParkReason};
use super::identity::{self, DOC_CACHE_MS, Taken};
use super::protocol::{
    Effect, LocalWrite, MissedEntries, OpaqueRule, Outcome, ReceivedMessage, ResendNeeded,
    ResendReason, Rules,
};
use super::provider::TakeOver;
use super::rotation::RegistrationStep;
use super::state::{CachedDoc, HeldEntry, ParkedEntry, PendingEffect, Processed, Tx, key};
use super::{App, AppError, PROCESSED_RETENTION_MS};
use crate::client::Batch;
use crate::client::answers::{ChainItem, EntryItem, FeedItem, FeedPage, FeedQuery};
use crate::error::ClientError;

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

/// What became of an effect's batch.
enum Sent {
    Applied,
    Conflict(serde_json::Value),
    StaleEpoch,
    Quota,
}

/// An entry as the feed carries it, or as the app stored it.
struct Entry {
    seq: u64,
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
}

impl Read {
    /// A read outside the feed, for a copy taken from the directory or the Homeserver.
    fn outside(tx: Tx) -> Self {
        Self {
            tx,
            blocked: None,
            opaque: Vec::new(),
            epoch_rose: false,
        }
    }

    fn block(&mut self, seq: u64) {
        self.blocked = Some(self.blocked.map_or(seq, |b| b.min(seq)));
    }
}

impl App {
    /// Read the feed to its end and process it (Switch spec 8.2, 8.3), then delete the
    /// retired receive keys the cursor passed, rotate if due, and send a deferred cursor
    /// move that is due. `wait` long-polls the first page, at most 25 seconds.
    ///
    /// # Errors
    ///
    /// [`Refusal::Stopped`] or [`Refusal::Left`] for a stopped or departed app; an alarm the
    /// read raised; a failed call or commit, after which nothing past the last commit counts
    /// and the next read resumes from the store.
    pub async fn receive(&mut self, wait: Option<u32>) -> Result<ReceiveReport, AppError> {
        self.ready_local().await?;
        let result = self.receive_inner(wait).await;
        // A move, a provider change, a revocation or an erasure met during the read is
        // followed (`provider.rs`), and the read goes on once at the service followed.
        let result = match self.take_over(result).await {
            TakeOver::Done(result) => result,
            TakeOver::ReadAgain => self.receive_inner(None).await,
        };
        if result.is_err() {
            self.reload = true;
        }
        let mut report = result?;
        report.events = self.take_events();
        Ok(report)
    }

    async fn receive_inner(&mut self, wait: Option<u32>) -> Result<ReceiveReport, AppError> {
        if matches!(self.state.alarm, Some(Alarm::Compromise { .. })) {
            self.leave_on_compromise().await;
        }
        self.refuse_when_stopped()?;
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
            self.take_listed_cert().await?;
            self.check_key_after_restore().await?;
        }
        self.resume_pending_effect().await?;
        self.deliver_record().await?;
        self.adopt_renewal().await?;
        self.ensure_scope_keys().await?;
        self.prune_processed().await?;
        self.retry_parked().await?;
        let mut report = ReceiveReport::default();
        let mut wait = wait.map(|w| w.min(25));
        loop {
            if let (Some(seconds), Some(since)) = (wait, self.state.cursor.deferred_since_ms) {
                let due = since.saturating_add(self.config.defer_ms());
                let left = due.saturating_sub(self.now()).div_ceil(1000).max(1);
                wait = Some(seconds.min(u32::try_from(left).unwrap_or(u32::MAX)));
            }
            let query = FeedQuery {
                after: Some(Position {
                    generation: self.state.cursor.generation,
                    seq: self.state.cursor.seq,
                }),
                limit: Some(self.config.page()),
                wait: wait.take(),
            };
            let result = self.client.feed(query).await;
            let page = self.take(result).await?;
            match self.process_page(page).await? {
                Some(true) => continue,
                Some(false) => break,
                None => {
                    report.stopped = true;
                    break;
                }
            }
        }
        if self.state.alarm.is_none() {
            self.delete_retired_keys().await?;
            self.maybe_rotate().await?;
            self.flush_cursor_if_due().await?;
        }
        report.cursor = self.cursor();
        Ok(report)
    }

    /// One page: `Some(more)`, or `None` when the read stops on it.
    async fn process_page(&mut self, page: FeedPage) -> Result<Option<bool>, AppError> {
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
        let start = self.state.cursor.seq;
        if page.scanned_through < start || (page.more && page.scanned_through == start) {
            return Err(AppError::InvalidData(
                "Switch wire 7.4.4: a page that doesn't move past the position asked".into(),
            ));
        }
        // Held entries lie after the cursor, so this read meets each again before any later
        // item, and blocks the cursor there if it is still held.
        let mut read = Read {
            tx: self.tx()?,
            blocked: None,
            opaque: self.protocol.opaque_members(),
            epoch_rose: false,
        };
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
        for item in &page.items {
            let seq = item.seq();
            if seq <= start {
                continue;
            }
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
                FeedItem::Stub { .. } => Step::Pass,
            };
            match step {
                Step::Pass => {
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
        self.end_page(read).await?;
        if epoch_rose {
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
        let doc = self.sender_doc(&entry.sender).await?;
        let sender_identity = match &doc {
            Some(doc) => SenderIdentity::Held(doc),
            None => SenderIdentity::Unavailable,
        };
        let opened = OpenedEntry {
            sender: entry.sender,
            cert: &entry.cert,
            accepted_at_ms: entry.accepted_at_ms,
        };
        let protocol = Arc::clone(&self.protocol);
        let rules = Rules::new(protocol.as_ref(), &self.state.cert, &read.opaque);
        let checked = check_opened(
            plaintext.clone(),
            &opened,
            &self.state.meta.identity,
            sender_identity,
            &rules,
            &|_, _| None,
        );
        let received = match checked {
            Ok(received) => received,
            Err(CheckRefusal::Dropped { check, reason }) => {
                if parked {
                    read.tx.delete(&key::parked(entry.seq))?;
                    self.state.parked.remove(&entry.seq);
                }
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
        // Check 9, with the app's own record of processed messages.
        let processed: Option<Processed> = self
            .reader()
            .get(&key::processed(&entry.sender, &received.message.msg_id))
            .await?;
        if let Some(seen) = processed {
            if parked {
                read.tx.delete(&key::parked(entry.seq))?;
                self.state.parked.remove(&entry.seq);
            }
            self.events.push(AppEvent::Duplicate {
                seq: entry.seq,
                conflicting: seen.hash != received.hash(),
            });
            return Ok(Step::Pass);
        }
        self.apply(entry, received, parked, read).await
    }

    /// The protocol's check 10 and effect, at most twice after a conflict.
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
            conflict: None,
        };
        for _ in 0..2 {
            let protocol = Arc::clone(&self.protocol);
            let effect = match protocol.receive(&message) {
                Outcome::Drop { reason } => {
                    self.note_processed(entry, &received, &[], parked, read)?;
                    return Ok(self.dropped(entry.seq, 10, reason));
                }
                Outcome::Apply(effect) => effect,
            };
            if effect.ops.len() >= MAX_BATCH_ENTRIES {
                return Err(Refusal::Usage(
                    "Switch wire 6.4: an effect of more than 7 operations".into(),
                )
                .into());
            }
            if effect.ops.is_empty() {
                self.note_processed(entry, &received, &effect.local, parked, read)?;
                self.received_event(entry, &received);
                return Ok(Step::Pass);
            }
            match self
                .send_effect(entry, &received, effect, parked, read)
                .await?
            {
                Sent::Applied => {
                    self.received_event(entry, &received);
                    return Ok(Step::Pass);
                }
                Sent::Conflict(current) => message.conflict = Some(current),
                Sent::StaleEpoch => {
                    self.fetch_key_bundle().await?;
                    return Ok(Step::Hold);
                }
                Sent::Quota => {
                    self.park(entry, &received.plaintext, ParkReason::Quota, read)?;
                    return Ok(Step::Pass);
                }
            }
        }
        Ok(Step::Hold)
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
        parked: bool,
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
        read.tx.local(local)?;
        if parked {
            read.tx.delete(&key::parked(entry.seq))?;
            self.state.parked.remove(&entry.seq);
        }
        Ok(())
    }

    /// Sign the effect's batch with the cursor move, keep it with what the answer commits,
    /// then send it (Switch spec 8.2: the effect and the cursor in one batch).
    async fn send_effect(
        &mut self,
        entry: &Entry,
        received: &Received,
        effect: Effect,
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
            parked,
        };
        // Everything read so far, with the kept batch, before it is sent.
        read.tx.put(key::PENDING_EFFECT, &pending)?;
        read.tx.put(key::CURSOR, &self.state.cursor)?;
        let tx = std::mem::replace(&mut read.tx, self.tx()?);
        self.state.pending_effect = Some(pending.clone());
        self.commit(tx).await?;
        self.run_effect(pending, &batch).await
    }

    /// Send a kept effect and commit its outcome.
    async fn run_effect(
        &mut self,
        pending: PendingEffect,
        batch: &Batch,
    ) -> Result<Sent, AppError> {
        let result = self.submit(batch).await;
        let sent = match result {
            Ok(_) => Sent::Applied,
            Err(AppError::Switch(ClientError::Switch { code, current, .. })) => match code {
                ErrorCode::Conflict => Sent::Conflict(current),
                ErrorCode::StaleEpoch => Sent::StaleEpoch,
                ErrorCode::QuotaExceeded | ErrorCode::TooLarge => Sent::Quota,
                other => {
                    // Refused for good: the kept batch goes, and the entry is read again.
                    self.drop_pending_effect().await?;
                    return Err(AppError::Switch(ClientError::Switch {
                        status: other.status(),
                        code: other,
                        message: "the effect's batch was refused".into(),
                        current,
                        known_version: None,
                        retry_after: None,
                    }));
                }
            },
            Err(error) => return Err(error),
        };
        if !matches!(sent, Sent::Applied) {
            self.drop_pending_effect().await?;
            return Ok(sent);
        }
        let now = self.now();
        let mut tx = self.tx()?;
        processed_writes(&mut tx, &pending.sender, &pending.msg_id, pending.hash, now)?;
        tx.local(&pending.local)?;
        if pending.parked {
            tx.delete(&key::parked(pending.seq))?;
            self.state.parked.remove(&pending.seq);
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
        self.commit(tx).await?;
        Ok(Sent::Applied)
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
        match self.run_effect(pending.clone(), &batch).await? {
            Sent::Applied => self.events.push(AppEvent::MessageReceived {
                seq: pending.seq,
                kind: pending.kind,
                msg_id: pending.msg_id,
                sender: pending.sender,
            }),
            // The entry is read again from the cursor, which didn't pass it, or from the
            // local store, and its effect built again.
            Sent::Conflict(_) | Sent::StaleEpoch | Sent::Quota => {}
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

    fn park(
        &mut self,
        entry: &Entry,
        plaintext: &MessagePlaintext,
        reason: ParkReason,
        read: &mut Read,
    ) -> Result<(), AppError> {
        let parked = ParkedEntry {
            sender: entry.sender,
            cert: entry.cert.clone(),
            accepted_at_ms: entry.accepted_at_ms,
            plaintext: plaintext.encode(),
            context: entry.context.clone(),
            reason,
        };
        read.tx.put(&key::parked(entry.seq), &parked)?;
        read.tx.delete(&key::held(entry.seq))?;
        self.state.held.remove(&entry.seq);
        self.state.parked.insert(entry.seq, parked);
        self.events.push(AppEvent::Parked {
            seq: entry.seq,
            reason,
        });
        Ok(())
    }

    /// Entries stored locally, checked and applied again now (Switch spec 8.2); the cursor is
    /// past them.
    async fn retry_parked(&mut self) -> Result<(), AppError> {
        let seqs: Vec<u64> = self.state.parked.keys().copied().collect();
        for seq in seqs {
            let Some(stored) = self.state.parked.get(&seq).cloned() else {
                continue;
            };
            let plaintext = MessagePlaintext::decode(&stored.plaintext)
                .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?;
            let entry = Entry {
                seq,
                sender: stored.sender,
                cert: stored.cert,
                accepted_at_ms: stored.accepted_at_ms,
                context: stored.context,
            };
            let mut read = Read {
                tx: self.tx()?,
                blocked: None,
                opaque: self.protocol.opaque_members(),
                epoch_rose: false,
            };
            let step = self
                .check_and_apply(&entry, plaintext, true, &mut read)
                .await?;
            self.commit(read.tx).await?;
            if step == Step::Pass && !self.state.parked.contains_key(&seq) {
                self.events.push(AppEvent::Unparked { seq });
            }
        }
        Ok(())
    }

    /// The sender's newest `identity.json` for check 7: the own one, or a copy at most 10
    /// minutes old, read again from the Homeserver otherwise. `None` when it can't be read
    /// now, or the identity equivocated.
    async fn sender_doc(&mut self, sender: &[u8; 32]) -> Result<Option<IdentityDoc>, AppError> {
        if *sender == self.state.meta.identity {
            return Ok(Some(self.state.own_doc.clone()));
        }
        let reader = self.reader();
        if reader.exists(&key::ident_equivocated(sender)).await? {
            return Ok(None);
        }
        let held = identity::held_copy(&reader, sender).await?;
        let now = self.now();
        if let Some((doc, fetched)) = &held
            && now.saturating_sub(*fetched) < DOC_CACHE_MS
        {
            return Ok(Some(doc.clone()));
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
        Ok(Some(doc))
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
        let writes = self.protocol.resend_needed(&needed);
        read.tx.local(&writes)?;
        read.tx.put(&key::asked(seq), &())?;
        Ok(true)
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
            let writes = self.protocol.missed(&missed);
            read.tx.local(&writes)?;
            read.tx.put(&key::asked(seq), &())?;
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
                        // Fetched before the cursor passes the part (Switch spec 3.5).
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
    fn not_current_here(&self) -> Option<AppEvent> {
        let doc = &self.state.own_doc;
        if doc.lists_removed(&self.state.meta.app_id) {
            return Some(AppEvent::Removed);
        }
        (doc.generation() != self.state.meta.generation).then(|| AppEvent::ProviderChanged {
            generation: doc.generation(),
        })
    }

    /// Read the own `identity.json` from the Homeserver and take it if newer (Switch spec
    /// 4.3): the app calls this when the Homeserver's event stream names the document, and
    /// after waking. Returns whether a newer copy was taken.
    ///
    /// # Errors
    ///
    /// The alarm a copy raises (equivocation, a removed app listed again); a failed read.
    pub async fn refresh_identity(&mut self) -> Result<bool, AppError> {
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        let identity = self.state.meta.identity;
        let Some(doc) = identity::read_homeserver(self.env.homeserver.as_ref(), &identity).await?
        else {
            return Ok(false);
        };
        self.take_own_copy(doc).await
    }

    /// Take an own copy outside the feed and commit what it changed.
    pub(crate) async fn take_own_copy(&mut self, doc: IdentityDoc) -> Result<bool, AppError> {
        let version = self.state.own_doc.version();
        let mut read = Read::outside(self.tx()?);
        let result = self.own_identity_copy(doc, &mut read).await;
        if result.is_err() {
            self.reload = true;
        }
        result?;
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
        self.ready_local().await?;
        self.refuse_when_stopped()?;
        self.send_cursor().await
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

/// The processed pair and its time index.
fn processed_writes(
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
