//! The protocol an app is built with: the [`Protocol`] trait.
//!
//! The Switch knows no protocol (Switch spec 1): scopes, message kinds and collections are
//! opaque strings to it. A protocol on the Switch supplies what the app layer can't know:
//! the opaque members of its message bodies, which of its scopes have keys, its kind rules
//! for the recipient checks 6 and 8 (Switch wire 5.1), and what a received message does.
//!
//! The trait is object-safe and takes and returns plain owned types, so a binding can
//! implement it across a language boundary.
//!
//! - **Receiving** ([`Protocol::check_body`], [`Protocol::receive`]): the app hands over
//!   each message that passed checks 1 to 9. The protocol checks the body (check 10) on its
//!   own, without effects, which is also what a push extension's peek runs; for a body that
//!   passes, it returns the shared record writes and other operations to commit in the same
//!   batch as the cursor move, and the writes of its own local state to commit with the
//!   outcome (Switch spec 8.2: "writes the effect to its shared record and advances its
//!   cursor in one batch").
//! - **Re-sends** ([`Protocol::resend_needed`], [`Protocol::missed`]): the kind that asks a
//!   counterparty to send again is a protocol's (Switch spec 11), so the app hands over
//!   what it needs and the protocol queues its request with the local writes it returns.
//!
//! The protocol's local state lives in the app's namespace under [`LocalWrite`] keys, which
//! the app keeps apart from its own (`STATE.md`).

use pubky_switch_core::json::OpaqueMember;
use pubky_switch_core::message::{Message, MessagePlaintext};
use pubky_switch_core::ops::{Condition, OpKind};
use pubky_switch_core::receive::KindRules;
use pubky_switch_core::records::{AppCert, AppRecord, Standing};
use serde_json::Value;

use super::records::Collection;
use super::recovery::{LossActions, ProviderLoss};
use super::send::{RecordJob, SentMessage};

/// An opaque member of a protocol's message bodies (Switch wire 1.1): its numbers aren't
/// checked against the integer range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueRule {
    /// The kind the rule applies to, or `None` for every kind.
    pub kind: Option<String>,
    /// The member of `body`.
    pub member: String,
}

/// A message that passed the recipient checks 1 to 9 (Switch wire 5.1), handed to the
/// protocol for check 10 ([`Protocol::check_body`]) and its effect ([`Protocol::receive`]).
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    /// The entry's `seq` in the current generation.
    pub seq: u64,
    /// The sender identity.
    pub sender: [u8; 32],
    /// When the inbox accepted it, service time in Unix milliseconds.
    pub accepted_at_ms: u64,
    /// The message's common fields and body.
    pub message: Message,
    /// The signed plaintext, kept for verifiable copies (Switch spec 8.2).
    pub plaintext: MessagePlaintext,
    /// The sender's certificate, verified.
    pub cert: AppCert,
    /// The sender app's standing when the message was accepted.
    pub standing: Standing,
    /// The invite code's context, if one admitted the entry; opaque.
    pub context: Option<Value>,
    /// Whether the entry was stored locally before and the cursor is past it already.
    pub parked: bool,
    /// After a `409 conflict` on the effect's batch: the answer's `current`, so the
    /// protocol builds its effect again on what the service holds now.
    pub conflict: Option<Value>,
}

/// A write of the protocol's own local state, under keys the app prefixes so they never
/// meet its own (`STATE.md`).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LocalWrite {
    /// Set `key` to `value`.
    Put {
        /// The key, in the protocol's key space.
        key: Vec<u8>,
        /// The value.
        value: Vec<u8>,
    },
    /// Remove `key`.
    Delete {
        /// The key, in the protocol's key space.
        key: Vec<u8>,
    },
    /// Remove every key starting with `prefix`.
    DeletePrefix {
        /// The prefix, in the protocol's key space.
        prefix: Vec<u8>,
    },
}

impl std::fmt::Debug for LocalWrite {
    // Values may hold message content: only sizes are shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalWrite::Put { key, value } => {
                write!(
                    f,
                    "Put({} key bytes, {} value bytes)",
                    key.len(),
                    value.len()
                )
            }
            LocalWrite::Delete { key } => write!(f, "Delete({} key bytes)", key.len()),
            LocalWrite::DeletePrefix { prefix } => {
                write!(f, "DeletePrefix({} prefix bytes)", prefix.len())
            }
        }
    }
}

/// What a received message does: the operations committed in one batch with the cursor
/// move, and the protocol's local writes committed with the outcome.
#[derive(Clone, Debug, Default)]
pub struct Effect {
    /// Signed by the app and sent in one batch with the cursor move: at most 7, the cursor
    /// taking the eighth entry (Switch wire 6.4). Empty when the message has no lasting
    /// effect, or another own app applied it already: only the cursor moves.
    pub ops: Vec<(Vec<Condition>, OpKind)>,
    /// The protocol's local writes, committed once the batch is answered, with the
    /// processed pair and the cursor.
    pub local: Vec<LocalWrite>,
}

/// The protocol's answer for a received message.
#[derive(Clone, Debug)]
pub enum Outcome {
    /// Apply the effect.
    Apply(Effect),
    /// A rule the protocol states for the kind fails (Switch wire 5.1 check 10), one that
    /// [`Protocol::check_body`] couldn't judge: the entry is dropped, kept as processed, and
    /// the cursor moves past it.
    Drop {
        /// The rule, without content.
        reason: String,
    },
}

/// Entries the app can't read and whose senders it asks to send again (Switch spec 8.2):
/// the acceptance times to ask for. The app never asks for a time before its cursor's, less
/// the clock tolerance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResendNeeded {
    /// The sender to ask.
    pub sender: [u8; 32],
    /// The first acceptance time to ask for, service time in Unix milliseconds.
    pub accepted_from_ms: u64,
    /// The last acceptance time to ask for.
    pub accepted_until_ms: u64,
    /// Why: an entry wrapped to a key the app doesn't hold, or one a departed own app left
    /// unread.
    pub reason: ResendReason,
}

/// Why the app asks for a re-send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResendReason {
    /// The entry is wrapped to a key the app doesn't hold (after a restore).
    Unopenable,
    /// A departed own app left the entry unread.
    Unreadable,
}

/// Entries the service deleted while the app was lagging (Switch spec 8.2): the protocol
/// asks the counterparties of its unfinished activity to re-send what their inboxes
/// accepted from `accepted_from_ms`, and lists its collections again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissedEntries {
    /// The item's `seq`.
    pub seq: u64,
    /// How many entries were missed.
    pub entries: u64,
    /// The time to ask from: the later of the item's first acceptance time and the cursor's
    /// time, less the clock tolerance.
    pub accepted_from_ms: u64,
}

/// A protocol on the Switch, as the app layer uses it. Object-safe; the app holds an
/// `Arc<dyn Protocol>`.
pub trait Protocol: Send + Sync {
    /// The opaque members of the protocol's message bodies (Switch wire 1.1). None by
    /// default.
    fn opaque_members(&self) -> Vec<OpaqueRule> {
        Vec::new()
    }

    /// Whether `scope`, a scope of a certificate (a name, or a name and a sub-scope), has
    /// Shared Data Keys (Switch spec 3.5). A sub-scope's keys are its sub-scope keys.
    fn has_keys(&self, scope: &str) -> bool;

    /// Whether the protocol sends `kind` between apps of one identity (Switch wire 5.1
    /// check 6).
    fn sent_between_own_apps(&self, kind: &str) -> bool;

    /// Check 8 (Switch wire 5.1): the sender's certificate holds a scope that sends the
    /// kind, and the own certificate one that receives it, with the protocol's narrower
    /// rules.
    ///
    /// # Errors
    ///
    /// The rule the message breaks, without content: the entry is dropped.
    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String>;

    /// The kinds the app's record lists in `accepts` for a certificate: never wider than
    /// what its scopes receive (Switch spec 3.4).
    fn accepts(&self, cert: &AppCert) -> Vec<String>;

    /// Check 10 (Switch wire 5.1) of a message that passed checks 1 to 9, with no effect:
    /// the body parses as its kind's body, the members read have their types, and the
    /// protocol's rules for the kind hold. The app runs it before [`Protocol::receive`], and
    /// a push extension's peek runs it alone (Switch spec 9 step 5), so it must refuse every
    /// body that `receive` would drop, and change nothing.
    ///
    /// # Errors
    ///
    /// The rule the body breaks, without content: the entry is dropped, and a peek shows a
    /// generic notification for it.
    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String>;

    /// The effect of a message whose body passed [`Protocol::check_body`].
    fn receive(&self, message: &ReceivedMessage) -> Outcome;

    /// Entries the app can't read: the protocol queues its re-send request and returns the
    /// local writes that queue it, committed with the cursor passing the entries.
    fn resend_needed(&self, needed: &ResendNeeded) -> Vec<LocalWrite>;

    /// Entries missed while lagging: as [`Protocol::resend_needed`].
    fn missed(&self, missed: &MissedEntries) -> Vec<LocalWrite>;

    /// A provider loss the app follows (Switch spec 12.6 steps 2 and 4): the protocol queues
    /// its re-send requests to the counterparties of its unfinished activity, for what their
    /// inboxes accepted from [`ProviderLoss::accepted_from_ms`] on, and names the
    /// counterparties whose conversation entries the app adds back. The app commits the
    /// local writes once, with that step; a crash before that commit calls it again.
    /// Nothing by default.
    fn provider_lost(&self, loss: &ProviderLoss) -> LossActions {
        let _ = loss;
        LossActions::default()
    }

    /// Whether a certificate's scopes allow its app to receive `kind`, which a sender checks
    /// before wrapping a message to the app (Switch spec 3.4). By default, whether the kinds
    /// [`Protocol::accepts`] gives for the certificate list it, which are never wider than
    /// what its scopes receive.
    fn receives(&self, kind: &str, cert: &AppCert) -> bool {
        self.accepts(cert).iter().any(|k| k == kind)
    }

    /// The protocol's narrower rule for senders (Switch spec 3.4): whether `message` goes to
    /// the app whose record is `recipient`, beyond its certificate and `accepts`. Every app
    /// by default.
    fn sends_to(&self, message: &Message, recipient: &AppRecord) -> bool {
        let _ = (message, recipient);
        true
    }

    /// Whether a first message of `kind` to a counterparty that isn't a contact adds a
    /// conversation entry before it is sent (Switch spec 7): every kind but the protocol's
    /// re-send request, which answers entries the app can't check. Every kind by default.
    fn adds_conversation(&self, kind: &str) -> bool {
        let _ = kind;
        true
    }

    /// The protocol's collections, each with its fixed policy (Switch spec 10.3). The app
    /// lists those it may read at join and after a `missed` item, and takes writes to them
    /// from the feed; writes to any other collection are left alone. None by default.
    fn collections(&self) -> Vec<Collection> {
        Vec::new()
    }

    /// What the app has seen of a record, its high water (Switch spec 8.2): the protocol's
    /// mark after `value`, from the mark held (`None` for a write of the app's own, built on
    /// what it trusts), or `None` to keep no mark. None by default.
    fn record_seen(
        &self,
        collection: &str,
        seen: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        let _ = (collection, seen, value);
        None
    }

    /// Whether a newer write of a record goes back on what the app has seen there (Switch
    /// spec 8.2), such as dropping or replacing a message of a role it saw: the rule it
    /// breaks, without content, and the write is flagged and not acted on. `value` is
    /// `None` for a delete or an unreadable value. Never by default.
    fn record_regression(
        &self,
        collection: &str,
        seen: &[u8],
        value: Option<&[u8]>,
    ) -> Option<String> {
        let _ = (collection, seen, value);
        None
    }

    /// The shared record write of a sent message (Switch spec 8.2): the record's next value
    /// from its current one (`None` for none, deleted or unreadable), or `None` when the
    /// record already reflects the message. Nothing by default.
    fn sent_record(
        &self,
        job: &RecordJob,
        sent: &SentMessage,
        current: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        let _ = (job, sent, current);
        None
    }
}

/// The protocol's kind rules as the core's recipient checks take them, with the own
/// certificate for check 8.
pub(crate) struct Rules<'a> {
    pub(crate) protocol: &'a dyn Protocol,
    pub(crate) own: &'a AppCert,
    pub(crate) opaque: Vec<OpaqueMember<'a>>,
}

impl<'a> Rules<'a> {
    pub(crate) fn new(
        protocol: &'a dyn Protocol,
        own: &'a AppCert,
        rules: &'a [OpaqueRule],
    ) -> Self {
        Self {
            protocol,
            own,
            opaque: rules
                .iter()
                .map(|rule| OpaqueMember {
                    kind: rule.kind.as_deref(),
                    member: rule.member.as_str(),
                })
                .collect(),
        }
    }
}

impl KindRules for Rules<'_> {
    fn opaque_members(&self) -> &[OpaqueMember<'_>] {
        &self.opaque
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.protocol.sent_between_own_apps(kind)
    }

    fn check_scopes(&self, message: &Message, sender: &AppCert) -> pubky_switch_core::Result<()> {
        self.protocol
            .check_scopes(message, sender, self.own)
            .map_err(pubky_switch_core::Error::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_write_debug_hides_values() {
        let write = LocalWrite::Put {
            key: b"note".to_vec(),
            value: b"secret-body".to_vec(),
        };
        let text = format!("{write:?}");
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains("11 value bytes"));
    }
}
