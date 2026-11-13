//! The app's view of its service's chain (Switch spec 8.3, 10.1; Switch wire 6.6, 6.7,
//! 7.4.4): the core's [`Verifier`] driven page by page, the newest head seen, checkpoints,
//! and the decision when the stubs from the app's position are missing.
//!
//! - Every stub of a feed page must extend the verified chain, batches complete, stamps
//!   never going back and no batch ID repeated within 30 days; every head seen must match
//!   the chain, and a read that reaches the end of the feed must reach every head seen.
//! - A stub at or before the verified position is a re-read (after a crash, or with the
//!   cursor kept before a held entry): it must match the chain hash verified there, if the
//!   app still keeps it.
//! - A checkpoint beyond the verified position is accepted only once the stubs extend the
//!   chain through it. Without them, their absence is a rollback while the service rule
//!   keeps them: the chain item at the verified position is less than 30 days old (less the
//!   clock tolerance, on the app's clock), or the app holds a head or own-write stub in
//!   between from an answer that recent, and the app wasn't restored and doesn't share its
//!   cursor with other devices. Otherwise the app continues from the checkpoint as a
//!   recovery decision: continuity is unverified, which is reconcile mode.
//!
//! The view persists as records (`STATE.md`): its small fields in one, each chain hash and
//! each batch ID in its own, written as a difference to what was last saved.

use std::collections::BTreeMap;

use pubky_switch_core::chain::{
    ChainEnvelope, ChainError, SignedHead, Stub, Verifier, VerifierState,
};
use pubky_switch_core::enc::{b64, unb64_array};
use pubky_switch_core::ops::BatchRef;
use pubky_switch_core::records::{CLOCK_TOLERANCE_MS, DAY_MS};

use super::error::AppError;
use super::state::{ChainRecord, Reader, RestorePending, Tx, key, parse_num};
use crate::client::answers::{FeedItem, FeedPage};
use crate::error::StoreError;

/// How old the chain item at an app's verified position may be, on the app's clock, while
/// the service still keeps the stubs after it: 30 days, less the clock tolerance, since the
/// service measures the item's age on its own clock (Switch wire 7.4.4).
pub const STUBS_KEPT_FOR_MS: u64 = 30 * DAY_MS - CLOCK_TOLERANCE_MS;

/// The most held heads and own-write stubs the view keeps beyond its verified position.
pub const HELD_MARKS: usize = 256;

/// How many chain hashes behind the cursor the view keeps before it forgets them: they are
/// forgotten in one step, so the store isn't rewritten on every read.
pub(crate) const HASHES_BEHIND: usize = 64;

/// A chain view as plain data: its record, chain hashes and batch IDs.
pub(crate) type ChainExport = (ChainRecord, Vec<(u64, [u8; 32])>, Vec<([u8; 16], u64)>);

/// The app's view of the chain.
#[derive(Clone, Debug)]
pub(crate) struct ChainView {
    verifier: Verifier,
    /// The verifier's state as last saved, to write only what changed.
    saved: VerifierState,
    pub(crate) newest: Option<SignedHead>,
    /// Continuity since `.0` is unverified: the app continued from the checkpoint at `.1`.
    pub(crate) gap: Option<(u64, u64)>,
    held: BTreeMap<u64, u64>,
    pub(crate) restore: Option<RestorePending>,
}

/// What reading one page did to the view.
#[derive(Clone, Debug, Default)]
pub(crate) struct PageCheck {
    /// The verified envelope of each stub the page carried, by `seq`, re-reads included.
    pub(crate) envelopes: BTreeMap<u64, ChainEnvelope>,
    /// Continuity became unverified on this page.
    pub(crate) gap: Option<(u64, u64)>,
}

fn rollback(error: ChainError) -> AppError {
    AppError::Alarm(super::error::Alarm::Rollback {
        reason: error.to_string(),
    })
}

impl ChainView {
    /// The highest service time of a chain item verified, if any.
    pub(crate) fn highest_time(&self) -> Option<u64> {
        self.verifier.highest_time()
    }

    /// A view anchored at `seq`, whose chain hash is `chain_hash`: a new app's anchor, just
    /// before the batch that registered its first receive key (Switch spec 8.3), taken
    /// from the transition proof the service signed for that batch.
    pub(crate) fn anchored(generation: u64, seq: u64, chain_hash: [u8; 32]) -> Self {
        let mut at = BTreeMap::new();
        at.insert(seq, chain_hash);
        let state = VerifierState {
            generation,
            last_seq: seq,
            last_hash: chain_hash,
            at,
            pruned_seq: seq,
            ..VerifierState::default()
        };
        Self {
            verifier: Verifier::from_state(state),
            saved: VerifierState::default(),
            newest: None,
            gap: None,
            held: BTreeMap::new(),
            restore: None,
        }
    }

    /// A view following `generation` from its first item.
    #[cfg(test)]
    pub(crate) fn from_start(generation: u64) -> Self {
        let mut view = Self::anchored(generation, 0, pubky_switch_core::chain::ZERO_HASH);
        view.verifier = Verifier::new(generation);
        view
    }

    /// The last verified `seq`.
    pub(crate) fn verified_seq(&self) -> u64 {
        self.verifier.last().0
    }

    /// The verified chain hash at `seq`, while the view keeps it.
    pub(crate) fn hash_at(&self, seq: u64) -> Option<[u8; 32]> {
        self.verifier.chain_hash_at(seq)
    }

    /// Whether the verified chain holds a batch with this ID within its 30-day window
    /// (Switch spec 13.5): the service applied it.
    pub(crate) fn holds_batch(&self, id: &[u8; 16]) -> bool {
        self.verifier.holds_batch(id)
    }

    /// Forget the chain hashes behind `seq`, once more than [`HASHES_BEHIND`] of them are
    /// kept. The app never reads behind its cursor again, so nothing compares a stub there;
    /// heads and checkpoints at or behind the new floor are no longer compared, as behind
    /// a checkpoint (Switch wire 7.4.4). The tip's hash is always kept. Returns whether
    /// anything was forgotten.
    pub(crate) fn forget_behind(&mut self, seq: u64) -> bool {
        let mut state = self.verifier.state();
        let floor = seq.min(state.last_seq);
        if floor <= state.pruned_seq || state.at.range(..floor).count() <= HASHES_BEHIND {
            return false;
        }
        state.at = state.at.split_off(&floor);
        state.pruned_seq = floor;
        self.verifier = Verifier::from_state(state);
        true
    }

    /// The app follows a cooperative move or a key change in place (Switch spec 12.5, Switch
    /// wire 7.4.4): the chain, its hashes and batch IDs go on under the next generation, and
    /// checkpoints are compared only with those accepted from the next service.
    pub(crate) fn switch_service(&mut self) {
        self.verifier.switch_service();
    }

    /// A head from any answer of the own switch: it must agree with the verified chain;
    /// one beyond it waits for the stubs (Switch spec 10.1).
    pub(crate) fn observe_head(&mut self, head: SignedHead) -> Result<(), AppError> {
        self.verifier.head(head).map_err(rollback)?;
        if self.newest.as_ref().is_none_or(|n| head.seq > n.seq) {
            self.newest = Some(head);
        }
        Ok(())
    }

    /// A head or own-write stub at `seq` the app holds, from an answer stamped
    /// `server_time_ms`; ones the verified chain covers aren't kept.
    pub(crate) fn note_held(&mut self, seq: u64, server_time_ms: u64) {
        if seq <= self.verified_seq() {
            return;
        }
        let at = self.held.entry(seq).or_insert(server_time_ms);
        *at = (*at).max(server_time_ms);
        while self.held.len() > HELD_MARKS {
            self.held.pop_first();
        }
    }

    /// Check one feed page (Switch wire 7.4.4). `now_ms` is the app's clock;
    /// `multi_device` says whether other devices share the cursor.
    ///
    /// # Errors
    ///
    /// [`AppError::Alarm`] with a rollback: the service rolled back or forked, or signed a
    /// page that contradicts itself.
    pub(crate) fn feed_page(
        &mut self,
        page: &FeedPage,
        now_ms: u64,
        multi_device: bool,
    ) -> Result<PageCheck, AppError> {
        let position = self.verified_seq();
        if let Some(newest) = &self.newest
            && page.head.seq < newest.seq
        {
            return Err(rollback(ChainError::Head { seq: page.head.seq }));
        }
        let stubs: Vec<&Stub> = page
            .items
            .iter()
            .filter_map(|item| match item {
                FeedItem::Chain(chain) => Some(&chain.stub),
                FeedItem::Stub { stub, .. } => Some(stub),
                _ => None,
            })
            .collect();
        let mut trial = self.verifier.clone();
        if let Some(checkpoint) = page.checkpoint {
            trial.checkpoint(checkpoint).map_err(rollback)?;
        }
        let mut check = PageCheck::default();
        let mut broken = None;
        for stub in &stubs {
            match push_onto(&mut trial, stub) {
                Ok(envelope) => {
                    check.envelopes.insert(envelope.seq, envelope);
                }
                Err(error) => {
                    broken = Some(error);
                    break;
                }
            }
        }
        let unreached = page
            .checkpoint
            .filter(|cp| cp.seq > position && trial.last().0 < cp.seq);
        match unreached {
            None => {
                if let Some(error) = broken {
                    return Err(rollback(error));
                }
                self.verifier = trial;
            }
            // The stubs so far extend the chain and more follow before the checkpoint.
            Some(cp) if broken.is_none() && page.more && page.scanned_through < cp.seq => {
                self.verifier = trial;
            }
            Some(cp) => {
                // Neither evidence holds for an app whose devices share its cursor: another
                // device may have moved it past the stubs, which then went honestly.
                if (!multi_device && self.stubs_kept(now_ms))
                    || self.holds_fresh_mark(position, cp.seq, now_ms, multi_device)
                {
                    return Err(rollback(ChainError::Checkpoint { seq: cp.seq }));
                }
                // A recovery decision: continue from the checkpoint, continuity unverified.
                let mut from = Verifier::from_checkpoint(&cp);
                check.envelopes.clear();
                for stub in &stubs {
                    let envelope = stub.open().map_err(rollback)?;
                    if envelope.seq > cp.seq {
                        let envelope = from.push(stub).map_err(rollback)?;
                        check.envelopes.insert(envelope.seq, envelope);
                    }
                }
                self.verifier = from;
                self.gap = Some((position, cp.seq));
                check.gap = self.gap;
            }
        }
        let verified = self.verified_seq();
        self.held.retain(|seq, _| *seq > verified);
        self.observe_head(page.head)?;
        if !page.more {
            self.verifier.end_of_feed().map_err(rollback)?;
        }
        Ok(check)
    }

    /// Whether the service rule keeps the stubs from the app's position: the chain item
    /// there is less than 30 days old, less the tolerance, and the app wasn't restored
    /// since (Switch wire 7.4.4). The caller doesn't ask for an app whose devices share its
    /// cursor, which another device may have moved past them.
    fn stubs_kept(&self, now_ms: u64) -> bool {
        self.restore.is_none()
            && self
                .verifier
                .state()
                .last_time
                .is_some_and(|at| now_ms.saturating_sub(at) < STUBS_KEPT_FOR_MS)
    }

    /// Whether the app holds a head or own-write stub in `(position, checkpoint]` from an
    /// answer less than 30 days old: its stub is kept behind the app's cursor, so its
    /// absence is a rollback. Not for an app whose devices share the cursor, or restored.
    fn holds_fresh_mark(&self, position: u64, checkpoint: u64, now_ms: u64, multi: bool) -> bool {
        if multi || self.restore.is_some() || checkpoint <= position {
            return false;
        }
        self.held
            .range(position.saturating_add(1)..=checkpoint)
            .any(|(_, at)| now_ms.saturating_sub(*at) < STUBS_KEPT_FOR_MS)
    }

    /// Write what changed since the last save.
    pub(crate) fn write(&mut self, tx: &mut Tx) -> Result<(), AppError> {
        let state = self.verifier.state();
        tx.put(key::CHAIN, &self.record_of(&state))?;
        for (seq, hash) in &state.at {
            if self.saved.at.get(seq) != Some(hash) {
                tx.put(&key::chain_at(*seq), &b64(hash))?;
            }
        }
        for seq in self.saved.at.keys() {
            if !state.at.contains_key(seq) {
                tx.delete(&key::chain_at(*seq))?;
            }
        }
        for (id, time) in &state.batches {
            if self.saved.batches.get(id) != Some(time) {
                tx.put(&key::chain_batch(id), time)?;
            }
        }
        for id in self.saved.batches.keys() {
            if !state.batches.contains_key(id) {
                tx.delete(&key::chain_batch(id))?;
            }
        }
        self.saved = state;
        Ok(())
    }

    /// Every record of the view, for a fresh namespace (a restore) or a full rewrite.
    pub(crate) fn write_all(&mut self, tx: &mut Tx) -> Result<(), AppError> {
        tx.delete_prefix("chain/")?;
        self.saved = VerifierState::default();
        self.write(tx)
    }

    fn record_of(&self, state: &VerifierState) -> ChainRecord {
        ChainRecord {
            generation: state.generation,
            last_seq: state.last_seq,
            last_hash: state.last_hash,
            last_time: state.last_time,
            open_batch: state
                .open_batch
                .map(|(batch, seen)| (b64(&batch.id), batch.count, seen)),
            pending_heads: state
                .pending_heads
                .iter()
                .map(SignedHead::to_value)
                .collect(),
            checkpoint_seq: state.checkpoint_seq,
            pruned_seq: state.pruned_seq,
            pending_checkpoint: state.pending_checkpoint.as_ref().map(SignedHead::to_value),
            highest_time: state.highest_time,
            newest: self.newest.as_ref().map(SignedHead::to_value),
            gap: self.gap,
            held: self.held.clone(),
            restore: self.restore,
        }
    }

    /// The view as a [`ChainRecord`] with its chain hashes and batch IDs, for a backup.
    pub(crate) fn export(&self) -> ChainExport {
        let state = self.verifier.state();
        (
            self.record_of(&state),
            state.at.iter().map(|(s, h)| (*s, *h)).collect(),
            state.batches.iter().map(|(i, t)| (*i, *t)).collect(),
        )
    }

    /// Rebuild a view from its record, chain hashes and batch IDs.
    pub(crate) fn import(
        record: ChainRecord,
        at: BTreeMap<u64, [u8; 32]>,
        batches: BTreeMap<[u8; 16], u64>,
    ) -> Result<Self, AppError> {
        let corrupt = || AppError::Store(StoreError::Corrupt);
        let head = |value: &serde_json::Value| SignedHead::from_value(value).map_err(|_| corrupt());
        let open_batch = match record.open_batch {
            None => None,
            Some((id, count, seen)) => Some((
                BatchRef {
                    id: unb64_array::<16>(&id).map_err(|_| corrupt())?,
                    count,
                },
                seen,
            )),
        };
        let state = VerifierState {
            generation: record.generation,
            last_seq: record.last_seq,
            last_hash: record.last_hash,
            last_time: record.last_time,
            open_batch,
            batches,
            at,
            pending_heads: record
                .pending_heads
                .iter()
                .map(head)
                .collect::<Result<_, _>>()?,
            checkpoint_seq: record.checkpoint_seq,
            pruned_seq: record.pruned_seq,
            pending_checkpoint: record.pending_checkpoint.as_ref().map(head).transpose()?,
            highest_time: record.highest_time,
        };
        Ok(Self {
            verifier: Verifier::from_state(state.clone()),
            saved: state,
            newest: record.newest.as_ref().map(head).transpose()?,
            gap: record.gap,
            held: record.held,
            restore: record.restore,
        })
    }

    /// Load the view from the store.
    pub(crate) async fn load(reader: &Reader) -> Result<Option<Self>, AppError> {
        let Some(record) = reader.get::<ChainRecord>(key::CHAIN).await? else {
            return Ok(None);
        };
        let corrupt = || AppError::Store(StoreError::Corrupt);
        let mut at = BTreeMap::new();
        for (rest, hash) in reader.scan::<String>("chain/at/").await? {
            at.insert(
                parse_num(&rest)?,
                unb64_array::<32>(&hash).map_err(|_| corrupt())?,
            );
        }
        let mut batches = BTreeMap::new();
        for (rest, time) in reader.scan::<u64>("chain/batch/").await? {
            batches.insert(unb64_array::<16>(&rest).map_err(|_| corrupt())?, time);
        }
        let mut view = Self::import(record, at, batches)?;
        view.saved = view.verifier.state();
        Ok(Some(view))
    }
}

/// Push one stub; a stub at or before the verified position is a re-read and must match
/// the chain hash verified there while the verifier keeps it.
fn push_onto(verifier: &mut Verifier, stub: &Stub) -> Result<ChainEnvelope, ChainError> {
    let envelope = stub.open()?;
    if envelope.seq <= verifier.last().0 {
        return match verifier.chain_hash_at(envelope.seq) {
            Some(known) if known != stub.chain_hash => Err(ChainError::Link { seq: envelope.seq }),
            _ => Ok(envelope),
        };
    }
    verifier.push(stub)
}

impl super::App {
    /// After the cursor's commit: forget the chain hashes behind the cursor, which no read
    /// meets again, so the view's records stay bounded however long the app runs without
    /// checkpoints (Switch wire 7.4.4).
    pub(crate) async fn forget_chain_behind_cursor(&mut self) -> Result<(), AppError> {
        let cursor = self.state.cursor;
        let Some(chain) = self.state.chain.as_mut() else {
            return Ok(());
        };
        // A cooperative move continues the sequence, so the cursor's `seq` stays comparable.
        if !chain.forget_behind(cursor.seq) {
            return Ok(());
        }
        let mut tx = self.tx()?;
        if let Some(chain) = self.state.chain.as_mut() {
            chain.write(&mut tx)?;
        }
        self.commit(tx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MemoryStore, StoreHandle};
    use ed25519_dalek::SigningKey;
    use pubky_switch_core::chain::{ChainTip, ItemType, ZERO_HASH};
    use pubky_switch_core::ops::Position;
    use std::sync::Arc;

    const START: u64 = 1_767_225_600_000;
    const IDENTITY: [u8; 32] = [7; 32];

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[5; 32])
    }

    /// `n` identity items, one a minute from `START`.
    fn chain(n: u64) -> (Vec<Stub>, Vec<ChainTip>) {
        let mut tip = ChainTip {
            generation: 1,
            seq: 0,
            chain_hash: ZERO_HASH,
        };
        let mut stubs = Vec::new();
        let mut tips = vec![tip];
        for seq in 1..=n {
            let (stub, next) = tip
                .append(
                    seq,
                    START + seq * 60_000,
                    ItemType::Identity,
                    [seq as u8; 32],
                    None,
                )
                .unwrap();
            stubs.push(stub);
            tip = next;
            tips.push(tip);
        }
        (stubs, tips)
    }

    fn head(tip: &ChainTip) -> SignedHead {
        SignedHead::sign(&key(), &IDENTITY, tip)
    }

    fn page(stubs: &[Stub], from: u64, head: SignedHead, more: bool) -> FeedPage {
        let items: Vec<FeedItem> = stubs
            .iter()
            .map(|stub| FeedItem::Stub {
                seq: stub.open().unwrap().seq,
                stub: stub.clone(),
            })
            .collect();
        let last = items.last().map_or(from, FeedItem::seq);
        FeedPage {
            items,
            next: Position {
                generation: 1,
                seq: last,
            },
            scanned_through: last,
            more,
            head,
            checkpoint: None,
            freeze: None,
        }
    }

    #[test]
    fn test_chain_view_accepts_a_page_that_extends_it() {
        let (stubs, tips) = chain(4);
        let mut view = ChainView::from_start(1);
        let check = view
            .feed_page(&page(&stubs, 0, head(&tips[4]), false), START, false)
            .unwrap();
        assert_eq!(check.envelopes.len(), 4);
        assert_eq!(view.verified_seq(), 4);
        // A re-read of the same stubs matches what was verified.
        view.feed_page(&page(&stubs[2..], 2, head(&tips[4]), false), START, false)
            .unwrap();
    }

    #[test]
    fn test_chain_view_refuses_a_fork() {
        let (stubs, tips) = chain(3);
        let mut view = ChainView::from_start(1);
        view.feed_page(&page(&stubs, 0, head(&tips[3]), false), START, false)
            .unwrap();
        // Another chain of the same length: its stubs don't match the verified hashes.
        let (forked, _) = tips[1]
            .append(2, START, ItemType::Identity, [99; 32], None)
            .unwrap();
        let error = view
            .feed_page(&page(&[forked], 1, head(&tips[3]), false), START, false)
            .unwrap_err();
        assert!(matches!(error, AppError::Alarm(_)));
    }

    #[test]
    fn test_chain_view_refuses_a_head_older_than_one_seen() {
        let (stubs, tips) = chain(3);
        let mut view = ChainView::from_start(1);
        view.observe_head(head(&tips[3])).unwrap();
        let error = view
            .feed_page(&page(&stubs[..1], 0, head(&tips[1]), false), START, false)
            .unwrap_err();
        assert!(matches!(error, AppError::Alarm(_)));
    }

    #[test]
    fn test_chain_view_end_of_feed_must_reach_every_head() {
        let (stubs, tips) = chain(3);
        let mut view = ChainView::from_start(1);
        view.observe_head(head(&tips[3])).unwrap();
        // The feed ends at seq 2 though a head at 3 was seen: a rollback.
        let error = view
            .feed_page(&page(&stubs[..2], 0, head(&tips[3]), false), START, false)
            .unwrap_err();
        assert!(matches!(error, AppError::Alarm(_)));
    }

    #[test]
    fn test_chain_view_gap_behind_a_fresh_checkpoint_is_a_rollback() {
        let (stubs, tips) = chain(6);
        let mut view = ChainView::from_start(1);
        view.feed_page(&page(&stubs[..2], 0, head(&tips[2]), false), START, false)
            .unwrap();
        // The service shows a checkpoint at 5 and only the stub after it.
        let mut p = page(&stubs[5..], 5, head(&tips[6]), false);
        p.checkpoint = Some(head(&tips[5]));
        let error = view.feed_page(&p, START + DAY_MS, false).unwrap_err();
        assert!(matches!(error, AppError::Alarm(_)));
    }

    #[test]
    fn test_chain_view_gap_behind_an_old_position_is_unverified_continuity() {
        let (stubs, tips) = chain(6);
        let mut view = ChainView::from_start(1);
        view.feed_page(&page(&stubs[..2], 0, head(&tips[2]), false), START, false)
            .unwrap();
        let mut p = page(&stubs[5..], 5, head(&tips[6]), false);
        p.checkpoint = Some(head(&tips[5]));
        let check = view.feed_page(&p, START + 40 * DAY_MS, false).unwrap();
        assert_eq!(check.gap, Some((2, 5)));
        assert_eq!(view.verified_seq(), 6);
        // A held head in the gap, from a recent answer, makes it a rollback after all.
        let mut view = ChainView::from_start(1);
        view.feed_page(&page(&stubs[..2], 0, head(&tips[2]), false), START, false)
            .unwrap();
        view.note_held(4, START + 39 * DAY_MS);
        assert!(view.feed_page(&p, START + 40 * DAY_MS, false).is_err());
        // Unless other devices share the cursor.
        let mut view = ChainView::from_start(1);
        view.feed_page(&page(&stubs[..2], 0, head(&tips[2]), false), START, false)
            .unwrap();
        view.note_held(4, START + 39 * DAY_MS);
        assert!(view.feed_page(&p, START + 40 * DAY_MS, true).is_ok());
    }

    #[test]
    fn test_chain_view_checkpoint_beyond_waits_for_more_stubs() {
        let (stubs, tips) = chain(6);
        let mut view = ChainView::from_start(1);
        let mut p = page(&stubs[..3], 0, head(&tips[6]), true);
        p.checkpoint = Some(head(&tips[5]));
        view.feed_page(&p, START, false).unwrap();
        let p2 = page(&stubs[3..], 3, head(&tips[6]), false);
        view.feed_page(&p2, START, false).unwrap();
        assert_eq!(view.verified_seq(), 6);
        assert_eq!(view.gap, None);
    }

    #[test]
    fn test_chain_view_forgets_hashes_behind_a_floor() {
        let (stubs, tips) = chain(100);
        let mut view = ChainView::from_start(1);
        view.feed_page(&page(&stubs, 0, head(&tips[100]), false), START, false)
            .unwrap();
        // Too few hashes behind the floor: nothing goes.
        assert!(!view.forget_behind(10));
        assert_eq!(view.hash_at(5), Some(tips[5].chain_hash));
        assert!(view.forget_behind(90));
        assert_eq!(view.hash_at(89), None);
        assert_eq!(view.hash_at(90), Some(tips[90].chain_hash));
        assert!(!view.forget_behind(90));
        // A head behind the floor can't be compared; one at a kept `seq` still is.
        let mut stale = head(&tips[5]);
        stale.chain_hash = [1; 32];
        view.observe_head(stale).unwrap();
        let mut forged = head(&tips[95]);
        forged.chain_hash = [1; 32];
        assert!(view.observe_head(forged).is_err());
        // A re-read from the floor on is still matched.
        let (forked, _) = tips[94]
            .append(95, START, ItemType::Identity, [99; 32], None)
            .unwrap();
        let error = view
            .feed_page(&page(&[forked], 94, head(&tips[100]), false), START, false)
            .unwrap_err();
        assert!(matches!(error, AppError::Alarm(_)));
        // The tip's hash is always kept.
        assert!(!view.forget_behind(500));
        assert_eq!(view.hash_at(100), Some(tips[100].chain_hash));
    }

    #[tokio::test]
    async fn test_chain_view_persists_by_difference_and_reloads() {
        let (stubs, tips) = chain(5);
        let store = StoreHandle::inline(Arc::new(MemoryStore::new()));
        let reader = Reader {
            ns: "client/a".into(),
            store: store.clone(),
        };
        let mut view = ChainView::from_start(1);
        view.feed_page(&page(&stubs[..3], 0, head(&tips[3]), false), START, false)
            .unwrap();
        let mut tx = Tx::new("client/a");
        view.write(&mut tx).unwrap();
        tx.commit(&store).await.unwrap();
        view.feed_page(&page(&stubs[3..], 3, head(&tips[5]), false), START, false)
            .unwrap();
        let mut tx = Tx::new("client/a");
        view.write(&mut tx).unwrap();
        // Only the record and the two new hashes are written.
        assert_eq!(format!("{tx:?}").matches("Put(").count(), 3);
        tx.commit(&store).await.unwrap();
        let mut loaded = ChainView::load(&reader).await.unwrap().unwrap();
        assert_eq!(loaded.verified_seq(), 5);
        assert_eq!(loaded.hash_at(4), view.hash_at(4));
        // The reloaded view goes on checking: a head that doesn't match is refused.
        let mut bad = head(&tips[4]);
        bad.chain_hash = [1; 32];
        assert!(loaded.observe_head(bad).is_err());
    }
}
