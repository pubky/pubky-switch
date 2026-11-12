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
//!   gives the rule). A lagging app isn't waited for only while it has a `missed` item to
//!   pass, on which it lists its collections again (7.4.4); a lagging app with none is
//!   waited for, as a returning app that doesn't list could keep a record forgotten past
//!   its cursor. A new app lists at join.
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
//! one with no deleted key held pays one probe of `shared_records_deleted`.

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
            self.forget_deleted_keys(txn, base).await?;
        }
        txn.drop_spent_invite_codes(base, PER_MINUTE).await?;
        txn.drop_expired_batch_proofs(base, self.limits.batch_proofs_ms, PER_MINUTE)
            .await?;
        Ok(())
    }

    /// Forget the deleted keys nothing refers to, up to the lowest cursor they wait for:
    /// none while an app they wait for has no cursor yet.
    async fn forget_deleted_keys(&self, txn: &mut AccountTxn, base: u64) -> Result<(), StoreError> {
        // The current apps by the held identity.json.
        let identity_key = txn.head().identity_key;
        let held = match txn.held_identity().await? {
            Some(held) => Some(
                IdentityDoc::verify(&held.doc, &identity_key)
                    .map_err(|_| StoreError::Corrupt("the held identity.json"))?,
            ),
            None => None,
        };
        let current = super::batch::load_apps(txn, held.as_ref(), base)
            .await?
            .current_app_ids();
        let lagging: Vec<[u8; 16]> = txn
            .lagging_apps()
            .await?
            .into_iter()
            .filter(|app| current.contains(app))
            .collect();
        let cursors = txn.waited_cursors(&current, &lagging).await?;
        let mut through = None;
        for cursor in cursors {
            let Some(cursor) = cursor else {
                return Ok(());
            };
            through = Some(
                through.map_or(cursor, |low: pubky_switch_core::ops::Position| {
                    if (cursor.generation, cursor.seq) < (low.generation, low.seq) {
                        cursor
                    } else {
                        low
                    }
                }),
            );
        }
        txn.forget_deleted_keys(through, PER_MINUTE).await?;
        Ok(())
    }
}
