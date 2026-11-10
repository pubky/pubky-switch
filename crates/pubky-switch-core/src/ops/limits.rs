//! The per-kind limits and the storage quota, decided over the counts the caller passes in
//! (Switch wire 9.1, 9.3). They refuse only the write that would create something new;
//! writes to existing objects, deletions and removals always pass.

use serde_json::json;

use crate::claims::ClaimLimits;
use crate::http::ErrorCode;

use super::Refusal;

/// The per-kind limits and the storage quota (Switch wire 9.2), by their names. The claim
/// limits are [`ClaimLimits`], whose [`ClaimLimits::check_attempt`] decides an `attempt`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The claim limits.
    pub claims: ClaimLimits,
    /// `max_record_keys`: live shared record keys.
    pub max_record_keys: u64,
    /// `record_quota_bytes`: the storage quota.
    pub record_quota_bytes: u64,
    /// `max_contacts`.
    pub max_contacts: u64,
    /// `max_conversations`.
    pub max_conversations: u64,
    /// `max_deny`.
    pub max_deny: u64,
    /// `max_invite_codes`: live invite codes.
    pub max_invite_codes: u64,
    /// `max_invite_uses`: the most uses an `invite_code.put` may name, which
    /// [`super::check_invite_code_put`] checks.
    pub max_invite_uses: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            claims: ClaimLimits::default(),
            max_record_keys: 100_000,
            record_quota_bytes: 64 * 1024 * 1024,
            max_contacts: 100_000,
            max_conversations: 100_000,
            max_deny: 100_000,
            max_invite_codes: 1_000,
            max_invite_uses: super::MAX_INVITE_USES,
        }
    }
}

/// A list an `allow.put` or `deny.put` adds to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum List {
    /// Contacts (`max_contacts`).
    Contacts,
    /// Conversation entries (`max_conversations`).
    Conversations,
    /// The deny list (`max_deny`).
    Deny,
}

/// A write, with the counts its per-kind limit or quota is decided on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quota {
    /// A `record.put` of `new_bytes` (0 for a delete).
    Record {
        /// Live keys the account holds.
        live_keys: u64,
        /// The bytes its current values count: each value's `ct` (Switch wire 9.1).
        stored_bytes: u64,
        /// Whether this key is live: its current value isn't a delete.
        key_live: bool,
        /// The bytes this key's current value counts, 0 when none or a delete.
        current_bytes: u64,
        /// The bytes the write counts.
        new_bytes: u64,
    },
    /// An `allow.put` or `deny.put` into `list`.
    List {
        /// The list.
        list: List,
        /// Its entries.
        entries: u64,
        /// Whether the entry is there already.
        present: bool,
    },
    /// An `invite_code.put`.
    InviteCode {
        /// Live codes the account holds.
        live: u64,
        /// Whether this code is held already.
        held: bool,
    },
}

/// `429 quota_exceeded`, naming the full budget in `current.limit` (Switch wire 9.3).
fn full(limit: &str, reason: &str) -> Refusal {
    Refusal::new(ErrorCode::QuotaExceeded, reason).with_current(json!({ "limit": limit }))
}

/// Decide a write's per-kind limit or quota (Switch wire 9.3).
///
/// - A `record.put` that makes a key live, a new one or a deleted one written again, needs
///   room under `max_record_keys` (`record_keys`); one that grows the stored bytes needs
///   room under the storage quota (`storage`). Checked in that order.
/// - A new list entry needs room in its list (`contacts`, `conversations`, `deny`).
/// - A new invite code needs room under `max_invite_codes` (`invite_codes`).
///
/// # Errors
///
/// The `429 quota_exceeded` refusal of the first budget that is full, its `current.limit`
/// naming it.
pub fn check_quota(quota: &Quota, limits: &Limits) -> Result<(), Refusal> {
    match *quota {
        Quota::Record {
            live_keys,
            stored_bytes,
            key_live,
            current_bytes,
            new_bytes,
        } => {
            if new_bytes > 0 && !key_live && live_keys >= limits.max_record_keys {
                return Err(full(
                    "record_keys",
                    "Switch wire 9.3: the identity holds its limit of record keys",
                ));
            }
            let after = stored_bytes
                .saturating_sub(current_bytes)
                .saturating_add(new_bytes);
            if new_bytes > current_bytes && after > limits.record_quota_bytes {
                return Err(full(
                    "storage",
                    "Switch wire 9.3: the shared records fill the storage quota",
                ));
            }
            Ok(())
        }
        Quota::List {
            list,
            entries,
            present,
        } => {
            let (limit, name) = match list {
                List::Contacts => (limits.max_contacts, "contacts"),
                List::Conversations => (limits.max_conversations, "conversations"),
                List::Deny => (limits.max_deny, "deny"),
            };
            if !present && entries >= limit {
                return Err(full(
                    name,
                    "Switch wire 9.3: the list holds its limit of entries",
                ));
            }
            Ok(())
        }
        Quota::InviteCode { live, held } => {
            if !held && live >= limits.max_invite_codes {
                return Err(full(
                    "invite_codes",
                    "Switch wire 9.3: the identity holds its limit of invite codes",
                ));
            }
            Ok(())
        }
    }
}
