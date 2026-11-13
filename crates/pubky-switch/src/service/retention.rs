//! Chain stub retention at a request's step 4 (Switch wire 7.4.4 "Checkpoints", 9.1;
//! Switch spec 8.3), after the sweeps of `sweeps.rs`: with trusted time only, for a caller
//! that has verified, under the account's lock and in the request's transaction. It reads at
//! most `retention_per_request` kept stubs, the oldest first, and in that window:
//!
//! 1. **The cut**: the stubs that may go run from the oldest kept one up to the first that
//!    every current app's cursor hasn't passed and that is younger than `cursor_hold_ms` by
//!    its `server_time`, against the time base. The head item never goes. A cut inside a
//!    batch stops before the batch's first item.
//! 2. **The checkpoint**: once `checkpoint_behind` of them lie past the latest checkpoint,
//!    one is signed at the cut, the newest of them outside a batch; with
//!    `checkpoint_at_head`, at the head, once that many chain items were added since the
//!    last. The window holds at least a batch's eight items, so a batch at its start is
//!    always whole in it, and each request moves the cut on.
//! 3. **The drop**: the stubs up to the cut and no further than the latest checkpoint go,
//!    their `seq` and chain hash noted as the newest dropped, and with them the batch
//!    records whose proofs are gone and none of whose stubs is kept (wire 6.4 step 5).
//!
//! Nothing is signed or dropped with `chain_retention` off, for a staged account, which doesn't serve the chain, or one
//! whose state is behind its key's mark, which signs no checkpoint (spec 6.5), or when the
//! mark can't be read: keeping a stub is always safe. Freezes aren't served, so there is no
//! frozen account to stop at; the check comes with the cooperative move (spec 12.5). Each
//! write is in the request's transaction, so a failure rolls the whole step back.
//!
//! Current state never depends on a dropped row: records, claim entries and key bundle parts
//! keep their own signed operations and proofs, and the feed reads current documents through
//! them (store `feed.rs`).

use pubky_switch_core::{
    chain::ChainTip, ops::Position, records::IdentityDoc, signing::Signs as _,
};

use super::Service;
use crate::{
    keys::{ServiceSigner, check_mark, sign_checkpoint},
    store::{AccountTxn, KeptStub, StoreError},
};

/// Where a current app's cursor stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cursor {
    /// The app isn't registered here yet: no app record of it is stored.
    Unregistered,
    /// Registered, and its cursor not moved yet.
    Unmoved,
    /// At this position.
    At(Position),
}

/// The cursors of the current apps: those the held `identity.json` lists, listed or in an
/// open renewal, neither revoked nor departed (Switch wire 7.4.4, 9.1).
pub(super) struct CurrentCursors {
    /// The held `identity.json`, verified.
    pub(super) held: IdentityDoc,
    /// Each current app's cursor.
    pub(super) cursors: Vec<([u8; 16], Cursor)>,
}

impl CurrentCursors {
    /// The newest `seq` of `generation` that every current app's cursor has passed, or
    /// that it doesn't need (Switch wire 7.4.4):
    /// - an app not registered here yet needs none of the stubs kept: its first read starts
    ///   at its registration (wire 7.4.4 "Start of a new app"), after them, and so does one
    ///   that registers again after a recovery in place, whose chain starts afresh;
    /// - a registered app whose cursor hasn't moved needs every stub from its registration,
    ///   whose `seq` isn't kept here, so it holds every one; so does a cursor of another
    ///   generation.
    ///
    /// No bound with no app holding one.
    fn passed(&self, generation: u64) -> u64 {
        self.cursors
            .iter()
            .filter_map(|(_, cursor)| match cursor {
                Cursor::Unregistered => None,
                Cursor::At(at) if at.generation == generation => Some(at.seq),
                Cursor::Unmoved | Cursor::At(_) => Some(0),
            })
            .min()
            .unwrap_or(u64::MAX)
    }
}

impl Service {
    /// The current apps' cursors, `None` while no `identity.json` is held. Forgetting deleted
    /// keys and dropping chain stubs wait for the same apps.
    pub(super) async fn current_cursors(
        &self,
        txn: &mut AccountTxn,
    ) -> Result<Option<CurrentCursors>, StoreError> {
        let identity_key = txn.head().identity_key;
        let Some(held) = txn.held_identity().await? else {
            return Ok(None);
        };
        let held = IdentityDoc::verify(&held.doc, &identity_key)
            .map_err(|_| StoreError::Corrupt("the held identity.json"))?;
        let kept = txn.kept_app_ids().await?;
        let listed: Vec<[u8; 16]> = held
            .body()
            .apps
            .iter()
            .map(|listed| listed.app_id)
            .filter(|app| !kept.contains(app))
            .collect();
        let rows = txn.waited_cursors(&listed).await?;
        let cursors = listed
            .iter()
            .map(|app| {
                let cursor = match rows.iter().find(|(id, _, _)| id == app) {
                    Some((_, Some(at), _)) => Cursor::At(*at),
                    Some((_, None, true)) => Cursor::Unmoved,
                    None | Some((_, None, false)) => Cursor::Unregistered,
                };
                (*app, cursor)
            })
            .collect();
        Ok(Some(CurrentCursors { held, cursors }))
    }

    /// Step 4's chain stub retention at service time `base` (the module's doc), with
    /// `signer`, the account's service key.
    pub(super) async fn retain_chain(
        &self,
        txn: &mut AccountTxn,
        signer: &ServiceSigner,
        base: u64,
    ) -> Result<(), StoreError> {
        if !self.limits.chain_retention {
            return Ok(());
        }
        let head = txn.head().clone();
        let Some(head_mark) = head.head_mark() else {
            return Ok(());
        };
        let Some(current) = self.current_cursors(txn).await? else {
            return Ok(());
        };
        if !super::rules::names_this_service(
            Some(&current.held),
            &self.origin,
            &signer.public_key(),
        ) {
            return Ok(());
        }
        let Ok(mark) = self.keys.mark(&head.service_key).await else {
            return Ok(());
        };
        if !check_mark(mark.as_ref(), &head_mark).allows_signing() {
            return Ok(());
        }
        let retained = txn.chain_retention().await?;
        let after = retained.dropped.map_or(0, |(seq, _)| seq);
        let limits = &self.limits;
        let window = txn.kept_stubs(after, limits.retention_per_request).await?;
        let passed = current.passed(head.generation);
        let old = base.checked_sub(limits.cursor_hold_ms);
        let may_go = |stub: &KeptStub| {
            stub.seq < head_mark.seq
                && (stub.seq <= passed || old.is_some_and(|old| stub.server_time_ms <= old))
        };
        let mut cut = window.iter().take_while(|stub| may_go(stub)).count();
        // Counted before the batch edge: the stubs that may go are what a checkpoint waits
        // for, and the edge only says where it can be signed. Counted after it, a window
        // that ends inside a batch would wait for good.
        let may_go_past = |checkpoint: u64| {
            let count = window[..cut]
                .iter()
                .filter(|stub| stub.seq > checkpoint)
                .count();
            u64::try_from(count).unwrap_or(u64::MAX)
        };
        let mut checkpoint = retained.checkpoint.as_ref().map_or(0, |c| c.seq);
        let enough = may_go_past(checkpoint) >= limits.checkpoint_behind;
        if let Some(last) = cut.checked_sub(1).map(|at| window[at])
            && let Some(first) = txn.batch_across(last.seq).await?
        {
            cut = window[..cut]
                .iter()
                .take_while(|stub| stub.seq < first)
                .count();
        }
        let goes = &window[..cut];
        let at = if limits.checkpoint_at_head {
            let added = txn
                .chain_items_after(checkpoint, limits.checkpoint_behind)
                .await?;
            (added >= limits.checkpoint_behind).then(|| head.chain_tip())
        } else {
            goes.last()
                .filter(|stub| enough && stub.seq > checkpoint)
                .map(|stub| ChainTip {
                    generation: head.generation,
                    seq: stub.seq,
                    chain_hash: stub.chain_hash,
                })
        };
        if let Some(at) = at {
            let Ok(signed) = sign_checkpoint(
                signer,
                mark.as_ref(),
                &head.identity_key,
                &head.chain_tip(),
                &at,
            ) else {
                return Ok(());
            };
            txn.keep_checkpoint(&signed).await?;
            checkpoint = signed.seq;
        }
        let dropped = goes.iter().rev().find(|stub| stub.seq <= checkpoint);
        if let Some(through) = dropped {
            txn.drop_stubs_through(after, through).await?;
        }
        // Also when nothing more goes now: a batch's proofs may have gone since its stubs did.
        let through = dropped
            .map(|stub| stub.seq)
            .or(retained.dropped.map(|(seq, _)| seq));
        if let Some(through) = through {
            txn.drop_spent_batches(through, limits.retention_per_request)
                .await?;
        }
        Ok(())
    }
}
