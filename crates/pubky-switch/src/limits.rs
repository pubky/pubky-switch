//! Limits, quotas and rates (Switch wire 9).
//!
//! [`Limits`] holds every limit an operator may set, under the names of Switch wire 9.2,
//! with the defaults the wire format gives. Defaults are for one identity on a shared
//! service; an operator may raise them. [`fixed`] holds the values the wire format fixes,
//! which no configuration changes.

use serde::{Deserialize, Serialize};

/// Values the wire format fixes. They bound encodings and body caps that every client
/// relies on, so they aren't configurable.
pub mod fixed {
    /// Envelope cap in bytes (Switch wire 4.4, 9.2 `max_envelope`).
    pub const MAX_ENVELOPE: u64 = 65_536;
    /// Sealed value plaintext cap in bytes (Switch wire 9.2 `max_sealed_value`).
    pub const MAX_SEALED_VALUE: u64 = 262_144;
    /// Entries per batch (Switch wire 6.4, 9.2 `max_batch`).
    pub const MAX_BATCH: u64 = 8;
    /// Envelopes of the one hand-over an account holds (Switch wire 7.4.17, 9.2
    /// `max_handover_parts`).
    pub const MAX_HANDOVER_PARTS: u64 = 64;
    /// Bytes of one export chunk (Switch wire 10.3, 9.2 `max_chunk_bytes`).
    pub const MAX_CHUNK_BYTES: u64 = 1_048_576;
    /// Default items per feed page (Switch wire 7.4.4).
    pub const FEED_LIMIT_DEFAULT: u64 = 100;
    /// Most items per feed page (Switch wire 7.4.4).
    pub const FEED_LIMIT_MAX: u64 = 500;
    /// Most positions one feed page examines, shown or not (Switch wire 7.4.4).
    pub const FEED_SCAN_LIMIT: u64 = 1_000;
    /// Longest long-poll wait, in seconds (Switch wire 7.4.4).
    pub const FEED_MAX_WAIT_S: u64 = 25;
    /// How far a request's `Switch-Timestamp` may be from the time base (Switch wire 7.1).
    pub const TIMESTAMP_WINDOW_MS: u64 = 5 * 60 * 1000;
    /// The reconciliation window after a claim's deadline (Switch wire 9.1).
    pub const RECONCILIATION_WINDOW_MS: u64 = 30 * 24 * 3600 * 1000;
    /// The highest app limit `identity.json` may carry (Switch wire 9.2 `app_limit`).
    pub const APP_LIMIT_MAX: u32 = 255;
}

/// Every configurable limit, by its Switch wire 9.2 name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Most apps in `identity.json`, never above 255. Announced at enrollment.
    pub app_limit: u32,
    /// Inbox quota in bytes. Announced at enrollment.
    pub quota_bytes: u64,
    /// Storage quota in bytes, for current shared record values. Announced at enrollment.
    pub record_quota_bytes: u64,
    /// Bytes each inbox entry counts besides its envelope.
    pub entry_overhead_bytes: u64,
    /// Live shared record keys.
    pub max_record_keys: u64,
    /// Live claims plus tombstones.
    pub max_claims: u64,
    /// Attempts on one claim.
    pub max_attempts_per_claim: u64,
    /// Attempts one app holds `open` or `unknown` at once.
    pub open_attempts_per_app: u64,
    /// The share of `max_claims`, in percent, that the claims one app created may hold;
    /// 100 turns the share off.
    pub claim_share_percent: u8,
    /// How long a finished or failed claim pinned to no deadline is kept after its last
    /// entry. May be raised, never lowered: apps judge a missing claim by it.
    pub max_claim_age_ms: u64,
    /// Contacts.
    pub max_contacts: u64,
    /// Conversation entries.
    pub max_conversations: u64,
    /// Deny list entries.
    pub max_deny: u64,
    /// Live invite codes.
    pub max_invite_codes: u64,
    /// The highest `max_pending` a connect request policy may name.
    pub max_connect_pending: u64,
    /// Retired receive key records per app.
    pub max_retired_keys: u64,
    /// Peers' `identity.json` copies.
    pub max_peers: u64,
    /// Enrollment answers kept per account.
    pub max_enrollments: u64,
    /// Flagged senders kept.
    pub max_flags: u64,
    /// How long a batch's proofs, and at least its ID, are kept. May be raised, never
    /// lowered: apps compare batch IDs over 30 days.
    pub batch_proofs_ms: u64,
    /// Batches with an ordinary operation or a repeatable control mutation, per app per
    /// minute.
    pub ops_per_min: u32,
    /// Batches with a repeatable control mutation, per app per minute.
    pub control_per_min: u32,
    /// How long an app's cursor holds a chain stub back.
    pub cursor_hold_ms: u64,
    /// Divergent uploads kept per record.
    pub max_divergent_uploads: u64,
    /// Bytes of one staged import. Announced at enrollment.
    pub max_import_bytes: u64,
    /// Appends per sender identity per minute.
    pub sender_per_min: u32,
    /// Appends per sender app per minute.
    pub sender_app_per_min: u32,
    /// Directory reads and peer deliveries with one invite code per minute.
    pub invite_reads_per_min: u32,
    /// Failed authentications per network source per minute, at all accounts together.
    pub auth_failures_per_source_per_min: u32,
    /// Connect requests and peer deliveries of senders admitted only because connect
    /// requests are on, per account per minute.
    pub stranger_per_min: u32,
    /// The share of `quota_bytes`, in percent, one sender identity's unread entries may
    /// hold; 100 turns the share off.
    pub sender_share_percent: u8,
    /// The most uses an invite code may be registered with.
    pub max_invite_uses: u64,
    /// Public reads of `identity.json` per account per minute, from all sources together.
    pub identity_reads_per_min: u32,
    /// Public reads of `identity.json` per network source per account per minute.
    pub identity_reads_per_source_per_min: u32,
    /// Most records per `GET /records` page.
    pub list_page: u64,
    /// Chain items that may go before the service signs a checkpoint; `None` signs none.
    pub checkpoint_behind: Option<u64>,
    /// Sign each checkpoint at the newest chain item.
    pub checkpoint_at_head: bool,
    /// Mark lagging apps.
    pub mark_lagging: bool,
    /// Appends with `notify` per sender identity per minute.
    pub notify_per_min: u32,
    /// Connect requests per sender identity per minute.
    pub connect_per_min: u32,
    /// Refusals after which a sender shows as flagged (Switch wire 9.4).
    pub flag_after: u32,
}

/// 30 days in milliseconds.
const DAYS_30_MS: u64 = 30 * 24 * 3600 * 1000;
/// 400 days in milliseconds.
const DAYS_400_MS: u64 = 400 * 24 * 3600 * 1000;

impl Default for Limits {
    fn default() -> Self {
        Self {
            app_limit: 32,
            quota_bytes: 64 * 1024 * 1024,
            record_quota_bytes: 64 * 1024 * 1024,
            entry_overhead_bytes: 256,
            max_record_keys: 100_000,
            max_claims: 1_000_000,
            max_attempts_per_claim: 64,
            open_attempts_per_app: 1_000,
            claim_share_percent: 25,
            max_claim_age_ms: DAYS_400_MS,
            max_contacts: 100_000,
            max_conversations: 100_000,
            max_deny: 100_000,
            max_invite_codes: 1_000,
            max_connect_pending: 1_000,
            max_retired_keys: 8,
            max_peers: 10_000,
            max_enrollments: 16,
            max_flags: 1_000,
            batch_proofs_ms: DAYS_30_MS,
            ops_per_min: 3_000,
            control_per_min: 60,
            cursor_hold_ms: DAYS_30_MS,
            max_divergent_uploads: 8,
            max_import_bytes: 4 * 1024 * 1024 * 1024,
            sender_per_min: 120,
            sender_app_per_min: 120,
            invite_reads_per_min: 30,
            auth_failures_per_source_per_min: 60,
            stranger_per_min: 60,
            sender_share_percent: 25,
            max_invite_uses: 100,
            identity_reads_per_min: 6_000,
            identity_reads_per_source_per_min: 60,
            list_page: 1_000,
            checkpoint_behind: None,
            checkpoint_at_head: false,
            mark_lagging: true,
            notify_per_min: 20,
            connect_per_min: 5,
            flag_after: 3,
        }
    }
}

/// A limit set that breaks a rule of the wire format.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("limits.{name}: {reason}")]
pub struct LimitError {
    /// The limit's name.
    pub name: &'static str,
    /// What is wrong with it.
    pub reason: &'static str,
}

impl Limits {
    /// Check the rules the wire format sets on the limits: the app limit's ceiling, the
    /// limits that may be raised but not lowered, percentages, and limits that must not be
    /// zero.
    pub fn validate(&self) -> Result<(), LimitError> {
        let defaults = Self::default();
        let fail = |name, reason| Err(LimitError { name, reason });
        if self.app_limit == 0 || self.app_limit > fixed::APP_LIMIT_MAX {
            return fail("app_limit", "must be between 1 and 255");
        }
        if self.max_claim_age_ms < defaults.max_claim_age_ms {
            return fail(
                "max_claim_age_ms",
                "may be raised but not lowered below 400 days",
            );
        }
        if self.batch_proofs_ms < defaults.batch_proofs_ms {
            return fail(
                "batch_proofs_ms",
                "may be raised but not lowered below 30 days",
            );
        }
        for (name, percent) in [
            ("claim_share_percent", self.claim_share_percent),
            ("sender_share_percent", self.sender_share_percent),
        ] {
            if percent == 0 || percent > 100 {
                return fail(name, "must be between 1 and 100");
            }
        }
        if self.checkpoint_behind == Some(0) {
            return fail("checkpoint_behind", "must be at least 1, or absent");
        }
        let nonzero: [(&'static str, u64); 33] = [
            ("quota_bytes", self.quota_bytes),
            ("record_quota_bytes", self.record_quota_bytes),
            ("max_record_keys", self.max_record_keys),
            ("max_claims", self.max_claims),
            ("max_attempts_per_claim", self.max_attempts_per_claim),
            ("open_attempts_per_app", self.open_attempts_per_app),
            ("max_contacts", self.max_contacts),
            ("max_conversations", self.max_conversations),
            ("max_deny", self.max_deny),
            ("max_invite_codes", self.max_invite_codes),
            ("max_connect_pending", self.max_connect_pending),
            ("max_retired_keys", self.max_retired_keys),
            ("max_peers", self.max_peers),
            ("max_enrollments", self.max_enrollments),
            ("max_flags", self.max_flags),
            ("ops_per_min", u64::from(self.ops_per_min)),
            ("control_per_min", u64::from(self.control_per_min)),
            ("cursor_hold_ms", self.cursor_hold_ms),
            ("max_divergent_uploads", self.max_divergent_uploads),
            ("max_import_bytes", self.max_import_bytes),
            ("sender_per_min", u64::from(self.sender_per_min)),
            ("sender_app_per_min", u64::from(self.sender_app_per_min)),
            ("invite_reads_per_min", u64::from(self.invite_reads_per_min)),
            (
                "auth_failures_per_source_per_min",
                u64::from(self.auth_failures_per_source_per_min),
            ),
            ("stranger_per_min", u64::from(self.stranger_per_min)),
            ("max_invite_uses", self.max_invite_uses),
            (
                "identity_reads_per_min",
                u64::from(self.identity_reads_per_min),
            ),
            (
                "identity_reads_per_source_per_min",
                u64::from(self.identity_reads_per_source_per_min),
            ),
            ("list_page", self.list_page),
            ("notify_per_min", u64::from(self.notify_per_min)),
            ("connect_per_min", u64::from(self.connect_per_min)),
            ("flag_after", u64::from(self.flag_after)),
            ("entry_overhead_bytes", self.entry_overhead_bytes),
        ];
        if let Some((name, _)) = nonzero.into_iter().find(|(_, value)| *value == 0) {
            return fail(name, "must be at least 1");
        }
        Ok(())
    }

    /// The most claims one app's `attempt`s may have created, live and tombstones:
    /// `floor(max_claims * claim_share_percent / 100)` (Switch wire 9.2).
    pub fn claim_share(&self) -> u64 {
        share(self.max_claims, self.claim_share_percent)
    }

    /// The most inbox quota bytes one sender identity's unread entries may hold
    /// (Switch wire 9.3).
    pub fn sender_share_bytes(&self) -> u64 {
        share(self.quota_bytes, self.sender_share_percent)
    }
}

/// `floor(total * percent / 100)`, without overflow.
fn share(total: u64, percent: u8) -> u64 {
    let product = u128::from(total) * u128::from(percent) / 100;
    u64::try_from(product).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_limits_defaults_match_wire_table() {
        let limits = Limits::default();
        assert_eq!(limits.app_limit, 32);
        assert_eq!(limits.quota_bytes, 67_108_864);
        assert_eq!(limits.record_quota_bytes, 67_108_864);
        assert_eq!(limits.entry_overhead_bytes, 256);
        assert_eq!(limits.max_record_keys, 100_000);
        assert_eq!(limits.max_claims, 1_000_000);
        assert_eq!(limits.max_attempts_per_claim, 64);
        assert_eq!(limits.open_attempts_per_app, 1_000);
        assert_eq!(limits.claim_share_percent, 25);
        assert_eq!(limits.max_claim_age_ms, 34_560_000_000);
        assert_eq!(limits.max_contacts, 100_000);
        assert_eq!(limits.max_conversations, 100_000);
        assert_eq!(limits.max_deny, 100_000);
        assert_eq!(limits.max_invite_codes, 1_000);
        assert_eq!(limits.max_connect_pending, 1_000);
        assert_eq!(limits.max_retired_keys, 8);
        assert_eq!(limits.max_peers, 10_000);
        assert_eq!(limits.max_enrollments, 16);
        assert_eq!(limits.max_flags, 1_000);
        assert_eq!(limits.batch_proofs_ms, 2_592_000_000);
        assert_eq!(limits.ops_per_min, 3_000);
        assert_eq!(limits.control_per_min, 60);
        assert_eq!(limits.cursor_hold_ms, 2_592_000_000);
        assert_eq!(limits.max_divergent_uploads, 8);
        assert_eq!(limits.max_import_bytes, 4_294_967_296);
        assert_eq!(limits.sender_per_min, 120);
        assert_eq!(limits.sender_app_per_min, 120);
        assert_eq!(limits.invite_reads_per_min, 30);
        assert_eq!(limits.auth_failures_per_source_per_min, 60);
        assert_eq!(limits.stranger_per_min, 60);
        assert_eq!(limits.sender_share_percent, 25);
        assert_eq!(limits.max_invite_uses, 100);
        assert_eq!(limits.identity_reads_per_min, 6_000);
        assert_eq!(limits.identity_reads_per_source_per_min, 60);
        assert_eq!(limits.list_page, 1_000);
        assert_eq!(limits.checkpoint_behind, None);
        assert!(!limits.checkpoint_at_head);
        assert!(limits.mark_lagging);
        assert_eq!(limits.notify_per_min, 20);
        assert_eq!(limits.connect_per_min, 5);
        assert_eq!(limits.flag_after, 3);
        assert_eq!(limits.validate(), Ok(()));
    }

    #[test]
    fn test_limits_shares_round_down() {
        let limits = Limits {
            max_claims: 1_003,
            quota_bytes: 10,
            ..Limits::default()
        };
        assert_eq!(limits.claim_share(), 250);
        assert_eq!(limits.sender_share_bytes(), 2);
        assert_eq!(Limits::default().claim_share(), 250_000);
    }

    #[test]
    fn test_limits_raised_values_pass() {
        let limits = Limits {
            app_limit: 255,
            max_claim_age_ms: DAYS_400_MS * 2,
            batch_proofs_ms: DAYS_30_MS * 2,
            claim_share_percent: 100,
            quota_bytes: u64::MAX,
            ..Limits::default()
        };
        assert_eq!(limits.validate(), Ok(()));
        assert_eq!(limits.sender_share_bytes(), u64::MAX / 4);
    }

    #[test]
    fn test_limits_validation_failures() {
        let cases: Vec<(Limits, &str)> = vec![
            (
                Limits {
                    app_limit: 256,
                    ..Limits::default()
                },
                "app_limit",
            ),
            (
                Limits {
                    app_limit: 0,
                    ..Limits::default()
                },
                "app_limit",
            ),
            (
                Limits {
                    max_claim_age_ms: DAYS_400_MS - 1,
                    ..Limits::default()
                },
                "max_claim_age_ms",
            ),
            (
                Limits {
                    batch_proofs_ms: DAYS_30_MS - 1,
                    ..Limits::default()
                },
                "batch_proofs_ms",
            ),
            (
                Limits {
                    claim_share_percent: 0,
                    ..Limits::default()
                },
                "claim_share_percent",
            ),
            (
                Limits {
                    sender_share_percent: 101,
                    ..Limits::default()
                },
                "sender_share_percent",
            ),
            (
                Limits {
                    checkpoint_behind: Some(0),
                    ..Limits::default()
                },
                "checkpoint_behind",
            ),
            (
                Limits {
                    sender_per_min: 0,
                    ..Limits::default()
                },
                "sender_per_min",
            ),
            (
                Limits {
                    entry_overhead_bytes: 0,
                    ..Limits::default()
                },
                "entry_overhead_bytes",
            ),
        ];
        for (limits, name) in cases {
            let error = limits.validate().expect_err(name);
            assert_eq!(error.name, name);
        }
    }
}
