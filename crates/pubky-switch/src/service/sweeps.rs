//! The sweeps a request runs at step 4 (Switch wire 7.3, 9.1; Switch spec 10.3), beside the
//! deletion of due claims: with trusted time only, for a caller that has verified, under
//! the account's lock and in the request's transaction, so an erasure or a recovery in
//! place never runs beside one. Each is bounded per request and decides by the service's
//! time base, never a client's; a run cut short leaves only rows a later one takes.
//!
//! - **Deleted keys** are forgotten at every such request, at most
//!   [`FORGOTTEN_KEYS_PER_REQUEST`] (`AccountTxn::forget_deleted_keys` gives the rule). An
//!   app that was lagging, which the rule doesn't wait for, lists its collections again on
//!   its return (7.4.4), and a new app lists at join.
//! - **Once a minute of service time** (`AccountTxn::minute_sweep_due`): invite codes that
//!   expired or ran out, and the transition proofs of batches past `batch_proofs_ms`, at
//!   most [`SPENT_PER_MINUTE`] of each. A batch's ID and operation hash stay while any of
//!   its chain stubs is kept, which today is always: no stub is dropped yet, so a retry is
//!   answered `409 conflict` from then on (6.4 step 5).
//! - **Not yet:** the spec's "the account isn't frozen" for forgetting has nothing to check
//!   while freezes aren't served; it comes with the move.

use pubky_switch_core::records::IdentityDoc;

use super::{DUE_CLAIMS_PER_REQUEST, Service};
use crate::store::{AccountTxn, StoreError};

/// The most deleted keys one request forgets.
pub(super) const FORGOTTEN_KEYS_PER_REQUEST: u64 = 64;

/// The most invite codes, and the most batches' proofs, one minute's sweep drops.
pub(super) const SPENT_PER_MINUTE: u64 = 256;

impl Service {
    /// Step 4 at service time `base`: the due claims go, then the sweeps (the module's
    /// doc).
    pub(super) async fn step_four(
        &self,
        txn: &mut AccountTxn,
        base: u64,
    ) -> Result<(), StoreError> {
        txn.delete_due_claims(base, self.limits.max_claim_age_ms, DUE_CLAIMS_PER_REQUEST)
            .await?;
        if txn.deleted_key_to_forget().await? {
            // The current apps by the held identity.json, read only when a key may go.
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
            txn.forget_deleted_keys(&current, &lagging, FORGOTTEN_KEYS_PER_REQUEST)
                .await?;
        }
        if txn.minute_sweep_due(base).await? {
            txn.drop_spent_invite_codes(base, SPENT_PER_MINUTE).await?;
            txn.drop_expired_batch_proofs(base, self.limits.batch_proofs_ms, SPENT_PER_MINUTE)
                .await?;
        }
        Ok(())
    }
}
