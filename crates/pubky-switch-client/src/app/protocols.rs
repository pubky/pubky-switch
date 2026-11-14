//! The protocols an app runs: a [`ProtocolSet`], and how the app routes each callback to
//! one of them.
//!
//! One certificate may hold the scopes of several protocols, so one app takes part in each
//! of them under one App ID (Switch spec 3.2, wire 3.1 "Several protocols"). Each protocol
//! has a name, and each scope root and kind prefix belongs to the protocol whose name owns
//! it (Switch spec 3.3 "Scope roots", wire 3.1). The app routes by that rule:
//!
//! - **By kind:** a message's checks 6, 8 and 10, its receive step, its opaque members, and
//!   a sender's checks of a recipient go to the protocol owning the kind's prefix. A kind no
//!   registered protocol owns fails check 8 and is dropped, so one protocol's scopes never
//!   authorize another's kinds, and only the owner ever judges its kinds.
//! - **By scope root:** whether a scope has keys ([`super::Protocol::has_keys`]). A scope
//!   no registered protocol owns has none, and an app whose certificate holds one doesn't
//!   start ([`ProtocolSet::unowned_root`]).
//! - **By collection:** record marks and regressions, and a sent message's record write.
//! - **To every protocol:** what carries no kind, such as an entry the app can't read, a
//!   `missed` item, a deny list change or gap, and a provider loss. Each protocol's answer
//!   is its own: one that fails is owed to that protocol alone.
//!
//! Each protocol's local state lives under its own prefix (`p/<name>/`, `STATE.md`): the
//! app qualifies every write where it enters, so one protocol's writes, a
//! `DeletePrefix` of everything included, never reach another's state.

use std::sync::Arc;

use pubky_switch_core::json::OpaqueMember;
use pubky_switch_core::message::Message;
use pubky_switch_core::receive::KindRules;
use pubky_switch_core::records::AppCert;
use pubky_switch_core::scopes::{is_protocol_name, owns_root};

use super::error::{AppError, Refusal};
use super::events::CertificateRefusal;
use super::protocol::{LocalWrite, OpaqueRule, Protocol, ReceivedMessage, WriteBase};
use super::records::Collection;
use super::send::{RecordJob, SentMessage};

/// The protocols an app runs, in the order the host registers them, each under its
/// [`Protocol::name`]. [`super::App::join`], [`super::App::load`] and
/// [`super::App::restore`] take one; cloning it shares the protocols.
#[derive(Clone)]
pub struct ProtocolSet {
    protocols: Vec<Registered>,
}

/// One protocol of a set, with the name it gave when registered.
#[derive(Clone)]
pub(crate) struct Registered {
    pub(crate) name: String,
    pub(crate) protocol: Arc<dyn Protocol>,
}

/// The set of one protocol, checked when an app is built with it: [`super::App::join`],
/// [`super::App::load`] and [`super::App::restore`] refuse it as [`ProtocolSet::new`] would.
impl From<Arc<dyn Protocol>> for ProtocolSet {
    fn from(protocol: Arc<dyn Protocol>) -> Self {
        Self {
            protocols: vec![Registered {
                name: protocol.name(),
                protocol,
            }],
        }
    }
}

/// As the set of an `Arc<dyn Protocol>`.
impl<P: Protocol + 'static> From<Arc<P>> for ProtocolSet {
    fn from(protocol: Arc<P>) -> Self {
        Self::from(protocol as Arc<dyn Protocol>)
    }
}

impl std::fmt::Debug for ProtocolSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.names()).finish()
    }
}

/// The root of a message kind: its prefix, before the first `.` (Switch wire 5.1).
fn kind_root(kind: &str) -> &str {
    kind.split_once('.').map_or(kind, |(root, _)| root)
}

/// The root of a scope: its name, before any `:` (Switch wire 3.1).
fn scope_root(scope: &str) -> &str {
    scope.split_once(':').map_or(scope, |(root, _)| root)
}

impl ProtocolSet {
    /// The set of `protocols`, in this order.
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for an empty list, a name that isn't a protocol name (1 to 32
    /// characters of `a-z` and `0-9`, starting with a letter: Switch wire 3.1 "Scope roots"),
    /// a name given twice, or a collection name two protocols give.
    pub fn new(protocols: Vec<Arc<dyn Protocol>>) -> Result<Self, AppError> {
        let set = Self {
            protocols: protocols
                .into_iter()
                .map(|protocol| Registered {
                    name: protocol.name(),
                    protocol,
                })
                .collect(),
        };
        set.validate()?;
        Ok(set)
    }

    /// The rules [`ProtocolSet::new`] checks, checked again by the app's constructors for a
    /// set made from one protocol ([`From`]).
    pub(crate) fn validate(&self) -> Result<(), AppError> {
        if self.protocols.is_empty() {
            return Err(Refusal::Usage("a protocol set needs a protocol".into()).into());
        }
        let mut collections: Vec<String> = Vec::new();
        for (at, registered) in self.protocols.iter().enumerate() {
            let name = &registered.name;
            if !is_protocol_name(name) {
                return Err(Refusal::Usage(format!("`{name}` isn't a protocol name")).into());
            }
            if self.protocols.iter().take(at).any(|r| &r.name == name) {
                return Err(Refusal::Usage(format!("the protocol `{name}` is given twice")).into());
            }
            for collection in registered.protocol.collections() {
                if collections.contains(&collection.name) {
                    return Err(Refusal::Usage(format!(
                        "the collection `{}` is given by two protocols",
                        collection.name
                    ))
                    .into());
                }
                collections.push(collection.name);
            }
        }
        Ok(())
    }

    /// The set of one protocol.
    ///
    /// # Errors
    ///
    /// As [`ProtocolSet::new`].
    pub fn single(protocol: Arc<dyn Protocol>) -> Result<Self, AppError> {
        Self::new(vec![protocol])
    }

    /// The names of the protocols, in registration order.
    pub fn names(&self) -> Vec<String> {
        self.protocols.iter().map(|r| r.name.clone()).collect()
    }

    /// The protocol registered under `name`.
    pub fn get(&self, name: &str) -> Option<&Arc<dyn Protocol>> {
        self.protocols
            .iter()
            .find(|r| r.name == name)
            .map(|r| &r.protocol)
    }

    /// Whether a protocol is registered under `name`.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Registered> {
        self.protocols.iter()
    }

    /// The protocol owning `kind`'s prefix.
    pub(crate) fn of_kind(&self, kind: &str) -> Option<&Registered> {
        let root = kind_root(kind);
        self.protocols.iter().find(|r| owns_root(&r.name, root))
    }

    /// The protocol owning `scope`'s root.
    pub(crate) fn of_scope(&self, scope: &str) -> Option<&Registered> {
        let root = scope_root(scope);
        self.protocols.iter().find(|r| owns_root(&r.name, root))
    }

    /// The protocol giving the collection `name`.
    pub(crate) fn of_collection(&self, name: &str) -> Option<&Registered> {
        self.protocols
            .iter()
            .find(|r| r.protocol.collections().iter().any(|c| c.name == name))
    }

    /// The root of a scope of `cert` that no registered protocol owns, if one is. Key bundle
    /// parts hold exactly the keys of the certificate's scopes that have keys, and only a
    /// scope's own protocol knows whether it has any (Switch spec 3.5, wire 3.5): with such a
    /// scope the app can't tell an exact part from a wrong one, so it doesn't start.
    pub(crate) fn unowned_root(&self, cert: &AppCert) -> Option<String> {
        cert.scopes()
            .iter()
            .find(|scope| self.of_scope(scope).is_none())
            .map(|scope| scope_root(scope).to_owned())
    }

    /// [`Refusal::Usage`] when [`ProtocolSet::unowned_root`] finds a root.
    pub(crate) fn check_cert(&self, cert: &AppCert) -> Result<(), AppError> {
        match self.unowned_root(cert) {
            None => Ok(()),
            Some(root) => Err(Refusal::Usage(format!(
                "the certificate holds the scope root `{root}`, which no registered protocol \
                 owns: register every protocol whose scopes the certificate holds"
            ))
            .into()),
        }
    }

    /// Each protocol's check of the app's own certificate
    /// ([`Protocol::check_own_certificate`]), in registration order.
    pub(crate) fn check_own_certificate(&self, cert: &AppCert) -> Result<(), AppError> {
        for r in &self.protocols {
            r.protocol
                .check_own_certificate(cert)
                .map_err(|reason| Refusal::Certificate {
                    protocol: r.name.clone(),
                    reason,
                })?;
        }
        Ok(())
    }

    /// Why the app can't take `cert` as its own, if it can't: a scope root no registered
    /// protocol owns ([`ProtocolSet::check_cert`]), or a protocol's refusal
    /// ([`ProtocolSet::check_own_certificate`]), in that order, as at a join or a load.
    pub(crate) fn certificate_refusal(&self, cert: &AppCert) -> Option<CertificateRefusal> {
        if let Some(root) = self.unowned_root(cert) {
            return Some(CertificateRefusal::UnownedRoot(root));
        }
        self.protocols.iter().find_map(|r| {
            r.protocol.check_own_certificate(cert).err().map(|reason| {
                CertificateRefusal::Protocol {
                    protocol: r.name.clone(),
                    reason,
                }
            })
        })
    }

    /// Whether `scope` has keys, by its root's protocol; `false` for a root none owns.
    pub(crate) fn has_keys(&self, scope: &str) -> bool {
        self.of_scope(scope)
            .is_some_and(|r| r.protocol.has_keys(scope))
    }

    /// The kinds the app's record accepts for `cert`: each protocol's, in registration
    /// order, each kept only when that protocol owns it.
    pub(crate) fn accepts(&self, cert: &AppCert) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in &self.protocols {
            for kind in r.protocol.accepts(cert) {
                if owns_root(&r.name, kind_root(&kind)) && !out.contains(&kind) {
                    out.push(kind);
                }
            }
        }
        out
    }

    /// Whether `cert`'s app may receive `kind`, by the kind's protocol.
    pub(crate) fn receives(&self, kind: &str, cert: &AppCert) -> bool {
        self.of_kind(kind)
            .is_some_and(|r| r.protocol.receives(kind, cert))
    }

    /// Every protocol's collections, in registration order.
    pub(crate) fn collections(&self) -> Vec<Collection> {
        self.protocols
            .iter()
            .flat_map(|r| r.protocol.collections())
            .collect()
    }

    /// The opaque members of `kind`'s protocol: only its rules apply to its bodies, so a
    /// rule for every kind covers every kind of that protocol alone.
    pub(crate) fn opaque_of_kind(&self, kind: &str) -> Vec<OpaqueRule> {
        self.of_kind(kind)
            .map(|r| r.protocol.opaque_members())
            .unwrap_or_default()
    }

    /// The opaque members of the protocol of the kind a message plaintext's JSON names,
    /// read without its other members; none when no kind reads, and the checks then refuse
    /// the message on their own.
    pub(crate) fn opaque_of_json(&self, json: &[u8]) -> Vec<OpaqueRule> {
        kind_of_json(json)
            .map(|kind| self.opaque_of_kind(&kind))
            .unwrap_or_default()
    }

    /// Check 10 of a message, by its kind's protocol.
    pub(crate) fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        match self.of_kind(&message.message.kind) {
            Some(r) => r.protocol.check_body(message),
            None => Err(NO_OWNER.into()),
        }
    }

    /// Whether a first message of `kind` adds a conversation entry, by its protocol.
    pub(crate) fn adds_conversation(&self, kind: &str) -> bool {
        self.of_kind(kind)
            .is_none_or(|r| r.protocol.adds_conversation(kind))
    }

    /// A record's mark, by its collection's protocol; none for a collection none gives.
    pub(crate) fn record_seen(
        &self,
        collection: &str,
        seen: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        self.of_collection(collection)
            .and_then(|r| r.protocol.record_seen(collection, seen, value))
    }

    /// A record regression, by its collection's protocol.
    pub(crate) fn record_regression(
        &self,
        collection: &str,
        seen: &[u8],
        value: Option<&[u8]>,
        base: WriteBase,
    ) -> Option<String> {
        self.of_collection(collection)
            .and_then(|r| r.protocol.record_regression(collection, seen, value, base))
    }

    /// A sent message's record write, by the record's collection's protocol.
    pub(crate) fn sent_record(
        &self,
        job: &RecordJob,
        sent: &SentMessage,
        current: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        self.of_collection(&job.target.collection.name)
            .and_then(|r| r.protocol.sent_record(job, sent, current))
    }
}

/// The `kind` a message plaintext's JSON names, read without its other members.
pub(crate) fn kind_of_json(json: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct KindOnly {
        kind: String,
    }
    serde_json::from_slice::<KindOnly>(json)
        .ok()
        .map(|read| read.kind)
}

/// The `kind` of an encoded message plaintext, as an entry stored locally keeps it.
pub(crate) fn kind_of_plaintext(encoded: &[u8]) -> Option<String> {
    pubky_switch_core::message::MessagePlaintext::decode(encoded)
        .ok()
        .and_then(|plaintext| kind_of_json(plaintext.json()))
}

/// Why a message of a kind no registered protocol owns is dropped at check 8.
pub(crate) const NO_OWNER: &str = "no protocol of this app takes the kind";

/// The separator between a protocol's name and its keys in the app's local state.
const NAME_END: u8 = b'/';

/// `key`, of the key space of the protocol `name`, as the app keeps it: `<name>/<key>`,
/// under the local-state prefix (`p/`).
pub(crate) fn qualified_key(name: &str, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len().saturating_add(1).saturating_add(key.len()));
    out.extend_from_slice(name.as_bytes());
    out.push(NAME_END);
    out.extend_from_slice(key);
    out
}

/// `writes` of the protocol `name`, qualified: each key and prefix as [`qualified_key`]
/// gives it, so they land under that protocol's prefix alone.
pub(crate) fn qualify(name: &str, writes: impl IntoIterator<Item = LocalWrite>) -> Vec<LocalWrite> {
    writes
        .into_iter()
        .map(|write| match write {
            LocalWrite::Put { key, value } => LocalWrite::Put {
                key: qualified_key(name, &key),
                value,
            },
            LocalWrite::Delete { key } => LocalWrite::Delete {
                key: qualified_key(name, &key),
            },
            LocalWrite::DeletePrefix { prefix } => LocalWrite::DeletePrefix {
                prefix: qualified_key(name, &prefix),
            },
        })
        .collect()
}

/// The writes of `qualified` that are the protocol `name`'s, in its own key space.
pub(crate) fn unqualify(name: &str, qualified: &[LocalWrite]) -> Vec<LocalWrite> {
    let own = qualified_key(name, b"");
    let strip = |key: &[u8]| key.strip_prefix(own.as_slice()).map(<[u8]>::to_vec);
    qualified
        .iter()
        .filter_map(|write| match write {
            LocalWrite::Put { key, value } => strip(key).map(|key| LocalWrite::Put {
                key,
                value: value.clone(),
            }),
            LocalWrite::Delete { key } => strip(key).map(|key| LocalWrite::Delete { key }),
            LocalWrite::DeletePrefix { prefix } => {
                strip(prefix).map(|prefix| LocalWrite::DeletePrefix { prefix })
            }
        })
        .collect()
}

/// The protocols' kind rules as the core's recipient checks take them, with the own
/// certificate for check 8 and the opaque members of the message's protocol.
pub(crate) struct Rules<'a> {
    pub(crate) protocols: &'a ProtocolSet,
    pub(crate) own: &'a AppCert,
    pub(crate) opaque: Vec<OpaqueMember<'a>>,
}

impl<'a> Rules<'a> {
    /// The rules, with `rules` the opaque members of the message's protocol
    /// ([`ProtocolSet::opaque_of_json`]).
    pub(crate) fn new(
        protocols: &'a ProtocolSet,
        own: &'a AppCert,
        rules: &'a [OpaqueRule],
    ) -> Self {
        Self {
            protocols,
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
        self.protocols
            .of_kind(kind)
            .is_some_and(|r| r.protocol.sent_between_own_apps(kind))
    }

    fn check_scopes(&self, message: &Message, sender: &AppCert) -> pubky_switch_core::Result<()> {
        match self.protocols.of_kind(&message.kind) {
            Some(r) => r
                .protocol
                .check_scopes(message, sender, self.own)
                .map_err(pubky_switch_core::Error::Invalid),
            None => Err(pubky_switch_core::Error::Invalid(NO_OWNER.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qualify_keeps_each_protocol_apart() {
        let writes = vec![
            LocalWrite::Put {
                key: b"a".to_vec(),
                value: b"1".to_vec(),
            },
            LocalWrite::DeletePrefix { prefix: Vec::new() },
        ];
        let chat = qualify("chat", writes.clone());
        assert_eq!(
            chat[1],
            LocalWrite::DeletePrefix {
                prefix: b"chat/".to_vec()
            }
        );
        assert_eq!(unqualify("chat", &chat), writes);
        assert!(unqualify("tasks", &chat).is_empty());
        // A name that extends another's is still apart.
        assert!(unqualify("cha", &chat).is_empty());
    }

    #[test]
    fn test_kind_and_scope_roots_route_by_name() {
        assert_eq!(kind_root("tasks.assignment"), "tasks");
        assert_eq!(kind_root("tasks_ext.note"), "tasks_ext");
        assert_eq!(scope_root("tasks_assign:team1"), "tasks_assign");
        assert_eq!(scope_root("chat"), "chat");
    }
}
