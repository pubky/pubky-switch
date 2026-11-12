//! The sweeps a request runs at step 4 (Switch wire 7.3, 9.1; Switch spec 10.3), beside the
//! deletion of due claims: with trusted time only, for a caller that has verified, under
//! the account's lock and in the request's transaction, so an erasure or a recovery in
//! place never runs beside one. Each is bounded per run and decides by the service's time
//! base, never a client's; a run cut short leaves only rows a later one takes, and a
//! failure anywhere in it rolls the whole request back.
//!
//! Once a minute of service time (`AccountTxn::minute_sweep_due`), at most [`PER_MINUTE`]
//! of each, the oldest first:
//! - **Deleted keys** nothing refers to are forgotten (`AccountTxn::forget_deleted_keys`
//!   gives the rule): once the cursor of every app the held `identity.json` lists, not
//!   revoked or departed, is past the delete. A lagging app is waited for like any other:
//!   a listing doesn't show a key the service forgot, so an app that missed the delete
//!   would keep the record.
//! - **Invite codes** that expired or ran out.
//! - **Transition proofs** of batches past `batch_proofs_ms`. A batch's ID and operation
//!   hash stay, so a retry is answered `409 conflict` (6.4 step 5). The whole batch record
//!   goes only once none of its chain stubs is kept (9.1); no stub is dropped yet, so no
//!   batch record is deleted yet: that comes with chain stub retention.
//!
//! An account no request reaches is never swept: the spec lets the service forget a
//! deleted key, not makes it (spec 10.3), and wire 9.1 dates the other two by the
//! account's next request.
//!
//! A request in a minute that isn't due pays one indexed update that matches no row. A due
//! one with no deleted key held pays one lookup in `shared_records_deleted`.

use pubky_switch_core::records::IdentityDoc;

use super::{DUE_CLAIMS_PER_REQUEST, Service};
use crate::store::{AccountTxn, StoreError};

/// The most deleted keys, invite codes and batches' proofs one minute's sweep takes, of
/// each.
pub(super) const PER_MINUTE: u64 = 256;

impl Service {
    /// Step 4 at service time `base`: the due claims go, then, once a minute, the sweeps
    /// (the module's doc).
    pub(super) async fn step_four(
        &self,
        txn: &mut AccountTxn,
        base: u64,
    ) -> Result<(), StoreError> {
        txn.delete_due_claims(base, self.limits.max_claim_age_ms, DUE_CLAIMS_PER_REQUEST)
            .await?;
        if !txn.minute_sweep_due(base).await? {
            return Ok(());
        }
        // Not yet: spec 10.3 also keeps a frozen account's deleted keys ("the account isn't
        // frozen, since an export carries it"). Freezes aren't served, so there is nothing
        // to check; the check comes with the cooperative move.
        if txn.deleted_key_held().await? {
            self.forget_deleted_keys(txn).await?;
        }
        txn.drop_spent_invite_codes(base, PER_MINUTE).await?;
        txn.drop_expired_batch_proofs(base, self.limits.batch_proofs_ms, PER_MINUTE)
            .await?;
        Ok(())
    }

    /// Forget the deleted keys nothing refers to, up to the lowest cursor they wait for
    /// (Switch spec 10.3): the cursor of every app the held `identity.json` lists that isn't
    /// revoked or departed, whether it is current, lagging or yet to register here. An
    /// app listed with no row here or no cursor yet holds every key, since it may still
    /// read the delete or, after a provider loss, upload its copy of the record, which a key
    /// forgotten here would let back in (spec 12.6). With no `identity.json` held, nothing
    /// goes. Forgetting is the service's choice, not a promise: an app that stops reading
    /// only delays it, and removing that app, the signer's own path, frees the keys.
    async fn forget_deleted_keys(&self, txn: &mut AccountTxn) -> Result<(), StoreError> {
        let identity_key = txn.head().identity_key;
        let Some(held) = txn.held_identity().await? else {
            return Ok(());
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
        let cursors = txn.waited_cursors(&listed).await?;
        let mut through: Option<pubky_switch_core::ops::Position> = None;
        for app in &listed {
            let Some((_, Some(cursor))) = cursors.iter().find(|(id, _)| id == app) else {
                return Ok(());
            };
            through = Some(match through {
                Some(low) if (low.generation, low.seq) <= (cursor.generation, cursor.seq) => low,
                _ => *cursor,
            });
        }
        txn.forget_deleted_keys(through, PER_MINUTE).await?;
        Ok(())
    }
}
