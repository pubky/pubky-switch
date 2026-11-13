//! The protocols on the Switch, as the signer sees them (Switch spec 1, 3.2, 3.3, 3.5).
//!
//! The Switch knows no scope names, and neither does the signer. A protocol on the Switch
//! tells it which scope names it owns, which of them have Shared Data Keys, which switch
//! permissions a set of its scopes needs (its permission table), any rule of its own on which
//! scopes go together, and any path it adds to an app's Pubky grant. The host registers every
//! protocol it supports once, in a [`Protocols`] set, when it opens the signer. The set isn't
//! an argument to each approval: the signer needs the same answers long after an approval, to
//! renew certificates, to judge reductions, to make each app's key bundles at every data epoch
//! rotation, and to check a hand-over or a backup it receives.
//!
//! The Switch's own rules stay here and apply on top of every protocol: the scope rule
//! (Switch spec 3.3), the fixed order of switch permissions (Switch wire 3.1), and the rules on
//! grant paths (Switch spec 3.4, Switch wire 3.9 step 3).

use std::collections::BTreeMap;
use std::sync::Arc;

use pubky_switch_core::records::{IDENTITY_PATH, SIGNER_BACKUP_PATH};
use pubky_switch_core::scopes::{self, Permission};

use crate::error::{Refusal, Result};

/// The longest protocol name, in characters (Switch wire 3.1 "Scope roots").
pub const MAX_PROTOCOL_NAME: usize = 32;

/// The Switch's own Homeserver folders. Only the Switch's formats live there, so a protocol
/// adds no grant path inside them (Switch spec 3.4, 4.1).
const SWITCH_FOLDERS: [&str; 2] = ["/pub/pubky-switch/", "/priv/pubky-switch/"];

/// A scope name a protocol owns (Switch spec 3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeDef {
    /// The scope name: 1 to 32 characters of `a-z`, `0-9`, `_` and `-`, starting with a letter
    /// or digit, without a sub-scope. Owning a name covers its sub-scopes, `name:<sub>`.
    pub name: String,
    /// Whether the scope has Shared Data Keys (Switch spec 3.5). Its sub-scopes have keys
    /// exactly when it does: theirs derive from its key (Switch wire 1.5).
    pub has_keys: bool,
}

impl ScopeDef {
    /// A scope name with Shared Data Keys.
    pub fn keyed(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            has_keys: true,
        }
    }

    /// A scope name without keys.
    pub fn unkeyed(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            has_keys: false,
        }
    }
}

/// A Homeserver path a protocol adds to an app's Pubky grant, which the user allows or not at
/// approval (Switch spec 3.4, Switch wire 3.9 step 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantPath {
    /// The path, granted read and write: a file, or a folder ending in `/`.
    pub path: String,
    /// What the path is for, in the protocol's words, for the host to show the user.
    pub purpose: String,
}

/// A protocol on the Switch, as the signer needs to know it (Switch spec 1).
///
/// Implementations are pure and deterministic: the same input gives the same answer every
/// time, on every install, since a signer that receives the identity in a hand-over must judge
/// the same certificates the same way.
pub trait Protocol: Send + Sync {
    /// The protocol's name: 1 to 32 characters of `a-z` and `0-9`, starting with a letter. It is
    /// the root of its scopes, and the name it uses in app records and as the prefix of its
    /// kinds (Switch wire 3.1 "Scope roots").
    fn name(&self) -> &str;

    /// The scope names the protocol owns, each once: its name, or its name followed by `_` or
    /// `-` and more characters (Switch wire 3.1 "Scope roots"). The [`Protocols`] set reads them
    /// once, when it is built.
    fn scopes(&self) -> Vec<ScopeDef>;

    /// The protocol's own rule on a requested set of its scopes, beyond the Switch's scope
    /// rule: for example, two scopes that never go together (Switch wire 3.9 step 1).
    /// `scopes` holds only the scopes this protocol owns, in the order they were asked for,
    /// and they already follow the Switch's scope rule.
    ///
    /// # Errors
    ///
    /// A reason to show the user. It should name the rule, not repeat the request's text.
    fn check_scopes(&self, scopes: &[&str]) -> std::result::Result<(), String>;

    /// The switch permissions `scopes` need, by the protocol's permission table (Switch spec
    /// 3.2). `scopes` holds only the scopes this protocol owns. Order and repeats don't
    /// matter: the set merges every protocol's answer into the fixed order.
    fn permissions(&self, scopes: &[&str]) -> Vec<Permission>;

    /// The paths the protocol adds to the grant of an app holding `scopes`, its own scopes
    /// only, beside the app's own record and backup paths. None by default.
    fn grant_paths(&self, app_id: &[u8; 16], scopes: &[&str]) -> Vec<GrantPath> {
        let _ = (app_id, scopes);
        Vec::new()
    }

    /// The protocol's own rule on which of its grant paths one grant may cover, beyond the
    /// Switch's rules: for example, two paths that go only together (Switch spec 3.4, Switch
    /// wire 3.9). `app_id` and `scopes`, its own scopes only, are those [`Protocol::grant_paths`]
    /// was given for the app. `allowed` holds the paths this protocol added for it that the
    /// grant would cover: those the app asks for, less those the user declines, in the order
    /// the auth request names them. Every set passes by default.
    ///
    /// # Errors
    ///
    /// A reason to show the user. It should name the rule, such as which paths go together.
    fn check_grant_paths(
        &self,
        app_id: &[u8; 16],
        scopes: &[&str],
        allowed: &[&str],
    ) -> std::result::Result<(), String> {
        let _ = (app_id, scopes, allowed);
        Ok(())
    }
}

/// A protocol the host registered that is malformed, or that answered with something the
/// Switch's rules don't allow. It is a fault of the host's set-up, not of a request.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// No protocol was registered.
    #[error("protocols: none registered")]
    NoProtocols,
    /// A protocol name that isn't 1 to 32 characters of `a-z` and `0-9` starting with a letter
    /// (Switch wire 3.1 "Scope roots").
    #[error("protocols: a protocol name that isn't 1 to 32 of a-z and 0-9, starting with a letter")]
    BadName,
    /// A scope name that isn't the protocol's own root: its name, or its name followed by `_`
    /// or `-` and more characters (Switch wire 3.1 "Scope roots"). A protocol claims no other
    /// root, even where it is the only one installed.
    #[error("protocols: protocol {protocol} declares the scope {scope}, a root that isn't its own")]
    ForeignRoot {
        /// The protocol.
        protocol: String,
        /// The scope name it declared.
        scope: String,
    },
    /// Two protocols registered under one name.
    #[error("protocols: protocol {name} registered twice")]
    DuplicateProtocol {
        /// The name.
        name: String,
    },
    /// A protocol that owns no scope.
    #[error("protocols: protocol {protocol} owns no scope")]
    NoScopes {
        /// The protocol.
        protocol: String,
    },
    /// A scope name that breaks the Switch's scope rule, or that has a sub-scope (Switch spec
    /// 3.3).
    #[error("protocols: protocol {protocol} declares a scope that isn't a plain scope name")]
    BadScopeName {
        /// The protocol.
        protocol: String,
    },
    /// One scope name declared twice, by one protocol or by two. Every name belongs to one
    /// protocol.
    #[error("protocols: scope {scope} is declared by {first} and again by {second}")]
    ScopeClaimedTwice {
        /// The scope name.
        scope: String,
        /// The protocol that declared it first.
        first: String,
        /// The protocol that declared it again.
        second: String,
    },
    /// A grant path a protocol added that the Switch's rules don't allow (Switch spec 3.4,
    /// Switch wire 3.9 step 3).
    #[error("protocols: protocol {protocol} adds a grant path that isn't allowed: {rule}")]
    BadGrantPath {
        /// The protocol.
        protocol: String,
        /// The rule the path breaks.
        rule: &'static str,
    },
}

/// What the Switch and the registered protocols make of an app's scopes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeTerms {
    /// The switch permissions the scopes need, each once, in the fixed order a certificate
    /// lists them in (Switch wire 3.1).
    pub permissions: Vec<Permission>,
    /// The scopes that have Shared Data Keys, in the order they were asked for (Switch spec
    /// 3.5).
    pub keyed: Vec<String>,
}

impl ScopeTerms {
    /// The permissions' names, as a certificate carries them.
    pub fn permission_names(&self) -> Vec<String> {
        scopes::permission_names(&self.permissions)
    }
}

/// Who owns a scope name.
#[derive(Clone, Copy, Debug)]
struct Owner {
    protocol: usize,
    has_keys: bool,
}

/// The protocols a host supports, each owning its scope names.
#[derive(Clone)]
pub struct Protocols {
    protocols: Vec<Arc<dyn Protocol>>,
    owners: BTreeMap<String, Owner>,
}

impl std::fmt::Debug for Protocols {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Protocols")
            .field("protocols", &self.names())
            .field("scopes", &self.owners.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Protocols {
    /// The set of `protocols`. Each scope name belongs to exactly one of them.
    ///
    /// # Errors
    ///
    /// [`ProtocolError`] for an empty set, a malformed or repeated protocol name, a protocol
    /// owning no scope, a scope name that breaks the scope rule or has a sub-scope, a scope
    /// whose root isn't the protocol's own (Switch wire 3.1 "Scope roots"), and a scope name
    /// declared twice.
    pub fn new(protocols: Vec<Arc<dyn Protocol>>) -> std::result::Result<Self, ProtocolError> {
        if protocols.is_empty() {
            return Err(ProtocolError::NoProtocols);
        }
        let mut owners: BTreeMap<String, Owner> = BTreeMap::new();
        for (index, protocol) in protocols.iter().enumerate() {
            let name = protocol.name();
            if !is_protocol_name(name) {
                return Err(ProtocolError::BadName);
            }
            if protocols[..index].iter().any(|p| p.name() == name) {
                return Err(ProtocolError::DuplicateProtocol {
                    name: name.to_owned(),
                });
            }
            let declared = protocol.scopes();
            if declared.is_empty() {
                return Err(ProtocolError::NoScopes {
                    protocol: name.to_owned(),
                });
            }
            for def in declared {
                if !scopes::is_name(&def.name) {
                    return Err(ProtocolError::BadScopeName {
                        protocol: name.to_owned(),
                    });
                }
                if !owns_root(name, &def.name) {
                    return Err(ProtocolError::ForeignRoot {
                        protocol: name.to_owned(),
                        scope: def.name,
                    });
                }
                if let Some(owner) = owners.get(&def.name) {
                    let first = protocols
                        .get(owner.protocol)
                        .map(|p| p.name().to_owned())
                        .unwrap_or_default();
                    return Err(ProtocolError::ScopeClaimedTwice {
                        scope: def.name,
                        first,
                        second: name.to_owned(),
                    });
                }
                owners.insert(
                    def.name,
                    Owner {
                        protocol: index,
                        has_keys: def.has_keys,
                    },
                );
            }
        }
        Ok(Self { protocols, owners })
    }

    /// The registered protocols' names, in the order they were registered.
    pub fn names(&self) -> Vec<&str> {
        self.protocols.iter().map(|p| p.name()).collect()
    }

    /// The owner of `scope`, by its name; `None` for a string that isn't a scope, or a scope
    /// no registered protocol owns.
    fn owner(&self, scope: &str) -> Option<Owner> {
        let (name, _) = scopes::split(scope)?;
        self.owners.get(name).copied()
    }

    /// Whether a registered protocol owns `scope`, a name or `name:<sub>` (Switch wire 3.9
    /// step 1). This is the predicate the core's app request check takes.
    pub fn knows_scope(&self, scope: &str) -> bool {
        self.owner(scope).is_some()
    }

    /// Whether `scope`, a name or `name:<sub>`, has Shared Data Keys (Switch spec 3.5). A
    /// sub-scope has them exactly when its name does. This is the predicate the core's key
    /// bundle functions take.
    ///
    /// A scope no registered protocol owns has no answer, and reads as `false` here. So before
    /// making any bundle, callers check [`Protocols::unowned`] and make none for that app
    /// rather than leave a key out.
    pub fn has_keys(&self, scope: &str) -> bool {
        self.owner(scope).is_some_and(|o| o.has_keys)
    }

    /// The registered protocols that own some of `scopes`, each once, in the order they were
    /// registered.
    pub fn protocols_of(&self, scopes: &[String]) -> Vec<&str> {
        let mut owners: Vec<usize> = scopes
            .iter()
            .filter_map(|scope| self.owner(scope))
            .map(|owner| owner.protocol)
            .collect();
        owners.sort_unstable();
        owners.dedup();
        owners
            .into_iter()
            .filter_map(|protocol| self.protocols.get(protocol))
            .map(|protocol| protocol.name())
            .collect()
    }

    /// The scopes of `scopes` that no registered protocol owns, in their order. A certificate
    /// holding one blocks every step that needs its app's keys, and a hand-over or a backup
    /// whose certificates hold one is refused.
    pub fn unowned(&self, scopes: &[String]) -> Vec<String> {
        scopes
            .iter()
            .filter(|s| !self.knows_scope(s))
            .cloned()
            .collect()
    }

    /// Each protocol that owns some of `scopes`, with its scopes in their order.
    fn by_protocol<'a>(&self, scopes: &'a [String]) -> Vec<(&Arc<dyn Protocol>, Vec<&'a str>)> {
        let mut groups: Vec<(usize, Vec<&'a str>)> = Vec::new();
        for scope in scopes {
            let Some(owner) = self.owner(scope) else {
                continue;
            };
            match groups
                .iter_mut()
                .find(|(index, _)| *index == owner.protocol)
            {
                Some((_, own)) => own.push(scope),
                None => groups.push((owner.protocol, vec![scope])),
            }
        }
        groups
            .into_iter()
            .filter_map(|(index, own)| self.protocols.get(index).map(|p| (p, own)))
            .collect()
    }

    /// Check a requested set of scopes and work out what a certificate for them carries
    /// (Switch spec 3.2, Switch wire 3.9 step 1), in this order:
    ///
    /// 1. the Switch's scope rule (Switch spec 3.3);
    /// 2. every scope's name is owned by a registered protocol;
    /// 3. each owning protocol's own rule on its scopes;
    /// 4. the switch permissions, the union of every owning protocol's table, in the fixed
    ///    order;
    /// 5. the scopes with Shared Data Keys.
    ///
    /// # Errors
    ///
    /// [`Refusal::Scopes`], [`Refusal::UnknownScopes`] or [`Refusal::ProtocolRule`], at the
    /// first step that fails.
    pub fn terms(&self, scopes: &[String]) -> Result<ScopeTerms> {
        scopes::check_scopes(scopes).map_err(|error| Refusal::Scopes(error.to_string()))?;
        let unknown = self.unowned(scopes);
        if !unknown.is_empty() {
            return Err(Refusal::UnknownScopes { scopes: unknown }.into());
        }
        let mut permissions: Vec<Permission> = Vec::new();
        for (protocol, own) in self.by_protocol(scopes) {
            protocol
                .check_scopes(&own)
                .map_err(|reason| Refusal::ProtocolRule {
                    protocol: protocol.name().to_owned(),
                    reason,
                })?;
            permissions.extend(protocol.permissions(&own));
        }
        permissions.sort_unstable();
        permissions.dedup();
        let keyed = scopes
            .iter()
            .filter(|s| self.has_keys(s))
            .cloned()
            .collect();
        Ok(ScopeTerms { permissions, keyed })
    }

    /// The grant paths the owning protocols add for an app with `app_id` holding `scopes`,
    /// each checked against the Switch's rules (Switch spec 3.4, Switch wire 3.9 step 3): an
    /// absolute path the capability text can carry, outside the Switch's own folders, and
    /// covering neither `identity.json` nor the signer's backup. Each path appears once, and
    /// none covers another, of its protocol or another one, so that a path the user declines
    /// is off the grant.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::BadGrantPath`] for a path that breaks a rule, that two protocols
    /// add, or that covers or lies in another added path.
    pub fn grant_paths(&self, app_id: &[u8; 16], scopes: &[String]) -> Result<Vec<GrantPath>> {
        let mut out: Vec<GrantPath> = Vec::new();
        for (protocol, own) in self.by_protocol(scopes) {
            for path in protocol.grant_paths(app_id, &own) {
                let bad = |rule| ProtocolError::BadGrantPath {
                    protocol: protocol.name().to_owned(),
                    rule,
                };
                check_grant_path(&path.path).map_err(bad)?;
                if out.iter().any(|p| p.path == path.path) {
                    return Err(bad("a path added twice").into());
                }
                if out
                    .iter()
                    .any(|p| covers(&p.path, &path.path) || covers(&path.path, &p.path))
                {
                    return Err(bad("a path that covers another").into());
                }
                out.push(path);
            }
        }
        Ok(out)
    }

    /// Each owning protocol's rule on the grant paths `allowed` (Switch spec 3.4, Switch wire
    /// 3.9): every protocol owning some of `scopes` is given those of `allowed` that it adds
    /// for an app with `app_id`, in their order, none included.
    ///
    /// # Errors
    ///
    /// [`Refusal::ProtocolRule`] from the first protocol whose rule refuses its paths.
    pub fn check_grant_paths(
        &self,
        app_id: &[u8; 16],
        scopes: &[String],
        allowed: &[&str],
    ) -> Result<()> {
        for (protocol, own) in self.by_protocol(scopes) {
            let added = protocol.grant_paths(app_id, &own);
            let its: Vec<&str> = allowed
                .iter()
                .copied()
                .filter(|path| added.iter().any(|a| a.path == *path))
                .collect();
            protocol
                .check_grant_paths(app_id, &own, &its)
                .map_err(|reason| Refusal::ProtocolRule {
                    protocol: protocol.name().to_owned(),
                    reason,
                })?;
        }
        Ok(())
    }
}

/// Whether `name` is a protocol name: 1 to 32 characters of `a-z` and `0-9`, starting with a
/// letter, so that no protocol's root is another's (Switch wire 3.1 "Scope roots").
fn is_protocol_name(name: &str) -> bool {
    (1..=MAX_PROTOCOL_NAME).contains(&name.len())
        && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Whether the protocol `name` may claim the root `root`: its name, or its name followed by
/// `_` or `-` and more characters (Switch wire 3.1 "Scope roots").
fn owns_root(name: &str, root: &str) -> bool {
    root == name
        || root
            .strip_prefix(name)
            .is_some_and(|rest| rest.len() > 1 && (rest.starts_with('_') || rest.starts_with('-')))
}

/// Whether `path`, a capability's path, covers `target`: it is that path, or a folder it lies
/// in (Switch wire 3.9 step 3).
fn covers(path: &str, target: &str) -> bool {
    path == target || (path.ends_with('/') && target.starts_with(path))
}

/// The Switch's rules on a path a protocol adds to an app's grant.
fn check_grant_path(path: &str) -> std::result::Result<(), &'static str> {
    if !path.starts_with('/') || path.len() < 2 {
        return Err("not an absolute path");
    }
    // The capability text is `path:rw` entries joined by `,` (Switch wire 3.9 step 3).
    if path
        .bytes()
        .any(|b| b == b',' || b == b':' || b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("a character the capability text can't carry");
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err("a '.' or '..' segment");
    }
    if path.contains("//") {
        return Err("an empty segment");
    }
    if covers(path, IDENTITY_PATH) || covers(path, SIGNER_BACKUP_PATH) {
        return Err("it covers identity.json or the signer's backup");
    }
    if SWITCH_FOLDERS
        .iter()
        .any(|folder| path.starts_with(folder) || covers(path, folder))
    {
        return Err("it lies in or covers the Switch's own folders");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SignerError;

    /// A test protocol with neutral scope names.
    struct Alpha;

    impl Protocol for Alpha {
        fn name(&self) -> &str {
            "alpha"
        }
        fn scopes(&self) -> Vec<ScopeDef> {
            vec![
                ScopeDef::keyed("alpha"),
                ScopeDef::keyed("alpha_write"),
                ScopeDef::unkeyed("alpha-notes"),
            ]
        }
        fn check_scopes(&self, scopes: &[&str]) -> std::result::Result<(), String> {
            if scopes.contains(&"alpha_write") && !scopes.contains(&"alpha") {
                return Err("write needs read".into());
            }
            Ok(())
        }
        fn permissions(&self, scopes: &[&str]) -> Vec<Permission> {
            let mut out = Vec::new();
            for scope in scopes {
                match *scope {
                    "alpha_write" => {
                        out.extend([Permission::ConversationAdd, Permission::ClaimsWrite])
                    }
                    "alpha" => out.push(Permission::ClaimsRead),
                    _ => {}
                }
            }
            out
        }
    }

    /// A second test protocol, with a keyed name used with sub-scopes and a grant path.
    struct Beta {
        path: &'static str,
    }

    impl Protocol for Beta {
        fn name(&self) -> &str {
            "beta"
        }
        fn scopes(&self) -> Vec<ScopeDef> {
            vec![ScopeDef::keyed("beta"), ScopeDef::unkeyed("beta_lists")]
        }
        fn check_scopes(&self, _: &[&str]) -> std::result::Result<(), String> {
            Ok(())
        }
        fn permissions(&self, scopes: &[&str]) -> Vec<Permission> {
            if scopes.contains(&"beta_lists") {
                vec![
                    Permission::ListsManage,
                    Permission::ListsRead,
                    Permission::ClaimsRead,
                ]
            } else {
                Vec::new()
            }
        }
        fn grant_paths(&self, _: &[u8; 16], scopes: &[&str]) -> Vec<GrantPath> {
            if scopes.iter().any(|s| s.starts_with("beta")) {
                vec![GrantPath {
                    path: self.path.to_owned(),
                    purpose: "the public tag file".into(),
                }]
            } else {
                Vec::new()
            }
        }
    }

    /// A protocol made of parts, for the registration failures.
    struct Custom {
        name: &'static str,
        scopes: Vec<ScopeDef>,
    }

    impl Protocol for Custom {
        fn name(&self) -> &str {
            self.name
        }
        fn scopes(&self) -> Vec<ScopeDef> {
            self.scopes.clone()
        }
        fn check_scopes(&self, _: &[&str]) -> std::result::Result<(), String> {
            Ok(())
        }
        fn permissions(&self, _: &[&str]) -> Vec<Permission> {
            Vec::new()
        }
    }

    fn set() -> Protocols {
        Protocols::new(vec![
            Arc::new(Alpha),
            Arc::new(Beta {
                path: "/pub/beta/tags.json",
            }),
        ])
        .unwrap()
    }

    fn owned(scopes: &[&str]) -> Vec<String> {
        scopes.iter().map(|s| (*s).to_owned()).collect()
    }

    fn custom(name: &'static str, scopes: Vec<ScopeDef>) -> Arc<dyn Protocol> {
        Arc::new(Custom { name, scopes })
    }

    #[test]
    fn test_protocols_registration_accepts_disjoint_protocols() {
        let protocols = set();
        assert_eq!(protocols.names(), ["alpha", "beta"]);
        let debug = format!("{protocols:?}");
        assert!(debug.contains("alpha") && debug.contains("beta"), "{debug}");
    }

    #[test]
    fn test_protocols_registration_refusals() {
        let keyed = ScopeDef::keyed("p");
        let cases: Vec<(Vec<Arc<dyn Protocol>>, ProtocolError)> = vec![
            (Vec::new(), ProtocolError::NoProtocols),
            (
                vec![custom("", vec![keyed.clone()])],
                ProtocolError::BadName,
            ),
            (
                vec![custom("Upper", vec![keyed.clone()])],
                ProtocolError::BadName,
            ),
            (
                vec![
                    custom("p", vec![keyed.clone()]),
                    custom("p", vec![ScopeDef::keyed("p_two")]),
                ],
                ProtocolError::DuplicateProtocol { name: "p".into() },
            ),
            (
                vec![custom("p", vec![])],
                ProtocolError::NoScopes {
                    protocol: "p".into(),
                },
            ),
            (
                vec![custom("p", vec![ScopeDef::keyed("p:sub")])],
                ProtocolError::BadScopeName {
                    protocol: "p".into(),
                },
            ),
            (
                vec![custom("p", vec![ScopeDef::keyed("Bad")])],
                ProtocolError::BadScopeName {
                    protocol: "p".into(),
                },
            ),
            (
                vec![custom("p", vec![keyed.clone(), ScopeDef::unkeyed("p")])],
                ProtocolError::ScopeClaimedTwice {
                    scope: "p".into(),
                    first: "p".into(),
                    second: "p".into(),
                },
            ),
            (
                vec![custom("p", vec![keyed.clone()]), custom("q", vec![keyed])],
                ProtocolError::ForeignRoot {
                    protocol: "q".into(),
                    scope: "p".into(),
                },
            ),
        ];
        for (protocols, expected) in cases {
            assert_eq!(Protocols::new(protocols).unwrap_err(), expected);
        }
        let long = "a".repeat(MAX_PROTOCOL_NAME + 1);
        assert!(!is_protocol_name(&long));
        assert!(is_protocol_name(&long[1..]));
        for bad in ["9chat", "chat_x", "chat-x", "chat.x", "Chat", ""] {
            assert!(!is_protocol_name(bad), "{bad}");
        }
    }

    #[test]
    fn test_protocols_scope_ownership_and_keys() {
        let protocols = set();
        for scope in ["alpha", "alpha-notes", "beta", "beta:shop-1", "beta_lists"] {
            assert!(protocols.knows_scope(scope), "{scope}");
        }
        for scope in ["other", "other:sub", "Read", "beta:", ""] {
            assert!(!protocols.knows_scope(scope), "{scope}");
        }
        // A sub-scope has keys exactly when its name does (Switch spec 3.5).
        assert!(protocols.has_keys("beta"));
        assert!(protocols.has_keys("beta:shop-1"));
        assert!(!protocols.has_keys("alpha-notes"));
        assert!(!protocols.has_keys("beta_lists:x"));
        assert!(!protocols.has_keys("other"));
        assert_eq!(
            protocols.unowned(&owned(&["alpha", "other", "beta:a", "x:y"])),
            owned(&["other", "x:y"])
        );
    }

    #[test]
    fn test_protocols_terms_union_in_fixed_order() {
        let protocols = set();
        let terms = protocols
            .terms(&owned(&[
                "beta_lists",
                "alpha_write",
                "alpha",
                "beta:shop-1",
                "alpha-notes",
            ]))
            .unwrap();
        // Alpha gives claims.read, claims.write and conversation.add; beta lists.read,
        // lists.manage and claims.read again: one list, each once, in the fixed order.
        assert_eq!(terms.permissions, Permission::ALL);
        assert_eq!(
            terms.permission_names(),
            owned(&[
                "claims.read",
                "claims.write",
                "lists.read",
                "lists.manage",
                "conversation.add"
            ])
        );
        assert_eq!(terms.keyed, owned(&["alpha_write", "alpha", "beta:shop-1"]));

        // Exactly the union, nothing more: alpha's `read` needs claims.read and beta's `lists`
        // lists.read, lists.manage and claims.read again.
        let some = protocols
            .terms(&owned(&["beta_lists", "alpha", "beta"]))
            .unwrap();
        assert_eq!(
            some.permissions,
            [
                Permission::ClaimsRead,
                Permission::ListsRead,
                Permission::ListsManage
            ]
        );
        assert_eq!(some.keyed, owned(&["alpha", "beta"]));

        let none = protocols.terms(&owned(&["alpha-notes"])).unwrap();
        assert!(none.permissions.is_empty());
        assert!(none.keyed.is_empty());
    }

    #[test]
    fn test_protocols_terms_refuse_the_scope_rule() {
        let protocols = set();
        let too_many: Vec<String> = (0..33).map(|i| format!("beta:t{i}")).collect();
        for scopes in [
            owned(&["alpha", "alpha"]),
            owned(&["beta", "beta:shop-1"]),
            owned(&["Read"]),
            owned(&["alpha:"]),
            too_many,
        ] {
            let error = protocols.terms(&scopes).unwrap_err();
            assert!(
                matches!(error, SignerError::Refused(Refusal::Scopes(_))),
                "{scopes:?}: {error:?}"
            );
        }
    }

    #[test]
    fn test_protocols_terms_refuse_unknown_scopes() {
        let protocols = set();
        let error = protocols
            .terms(&owned(&["alpha", "secret-thing", "other:sub"]))
            .unwrap_err();
        assert_eq!(
            error,
            SignerError::Refused(Refusal::UnknownScopes {
                scopes: owned(&["secret-thing", "other:sub"])
            })
        );
        // The text names the rule, not the request's scopes.
        let text = error.to_string();
        assert!(!text.contains("secret-thing"), "{text}");
        assert!(text.contains("2 scope(s)"), "{text}");
    }

    #[test]
    fn test_protocols_terms_apply_each_protocols_rule() {
        let protocols = set();
        let error = protocols
            .terms(&owned(&["alpha_write", "beta"]))
            .unwrap_err();
        assert_eq!(
            error,
            SignerError::Refused(Refusal::ProtocolRule {
                protocol: "alpha".into(),
                reason: "write needs read".into()
            })
        );
        protocols
            .terms(&owned(&["beta", "alpha", "alpha_write"]))
            .unwrap();
    }

    #[test]
    fn test_protocols_grant_paths_from_owning_protocols() {
        let protocols = set();
        let id = [7u8; 16];
        let paths = protocols
            .grant_paths(&id, &owned(&["alpha", "beta:a"]))
            .unwrap();
        assert_eq!(
            paths,
            [GrantPath {
                path: "/pub/beta/tags.json".into(),
                purpose: "the public tag file".into()
            }]
        );
        // A protocol that owns none of the app's scopes adds nothing.
        assert!(
            protocols
                .grant_paths(&id, &owned(&["alpha"]))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn test_protocols_grant_paths_refuse_paths_the_switch_forbids() {
        for path in [
            "relative/path",
            "/",
            "/pub/beta/a,b",
            "/pub/beta/a:rw",
            "/pub/beta/a b",
            "/pub/beta/../pubky-switch/v1/identity.json",
            "/pub/beta//a.json",
            "/pub/beta/a//",
            "/pub/",
            "/pub/pubky-switch/",
            "/pub/pubky-switch/v1/identity.json",
            "/pub/pubky-switch/v1/signer-backup.json",
            "/pub/pubky-switch/v1/apps/x.json",
            "/priv/pubky-switch/v1/apps/x/",
        ] {
            let protocols = Protocols::new(vec![Arc::new(Beta { path })]).unwrap();
            let error = protocols
                .grant_paths(&[1; 16], &owned(&["beta"]))
                .unwrap_err();
            assert!(
                matches!(
                    &error,
                    SignerError::Protocol(ProtocolError::BadGrantPath { protocol, .. })
                        if protocol == "beta"
                ),
                "{path}: {error:?}"
            );
        }
        for path in ["/pub/beta/tags.json", "/priv/beta/", "/pub/beta.example/x"] {
            assert!(check_grant_path(path).is_ok(), "{path}");
        }
    }

    #[test]
    fn test_protocols_grant_paths_refuse_a_path_added_twice() {
        struct Gamma;
        impl Protocol for Gamma {
            fn name(&self) -> &str {
                "gamma"
            }
            fn scopes(&self) -> Vec<ScopeDef> {
                vec![ScopeDef::unkeyed("gamma")]
            }
            fn check_scopes(&self, _: &[&str]) -> std::result::Result<(), String> {
                Ok(())
            }
            fn permissions(&self, _: &[&str]) -> Vec<Permission> {
                Vec::new()
            }
            fn grant_paths(&self, _: &[u8; 16], _: &[&str]) -> Vec<GrantPath> {
                vec![GrantPath {
                    path: "/pub/beta/tags.json".into(),
                    purpose: "the same file".into(),
                }]
            }
        }
        let protocols = Protocols::new(vec![
            Arc::new(Beta {
                path: "/pub/beta/tags.json",
            }),
            Arc::new(Gamma),
        ])
        .unwrap();
        let error = protocols
            .grant_paths(&[1; 16], &owned(&["beta", "gamma"]))
            .unwrap_err();
        assert_eq!(
            error,
            SignerError::Protocol(ProtocolError::BadGrantPath {
                protocol: "gamma".into(),
                rule: "a path added twice"
            })
        );
    }

    #[test]
    fn test_protocols_grant_paths_refuse_a_path_that_covers_another() {
        // A declined path another added path covers would stay on the grant, so neither one
        // protocol nor two may add paths that cover one another (Switch spec 3.4).
        struct Nested(&'static [&'static str]);
        impl Protocol for Nested {
            fn name(&self) -> &str {
                "gamma"
            }
            fn scopes(&self) -> Vec<ScopeDef> {
                vec![ScopeDef::unkeyed("gamma")]
            }
            fn check_scopes(&self, _: &[&str]) -> std::result::Result<(), String> {
                Ok(())
            }
            fn permissions(&self, _: &[&str]) -> Vec<Permission> {
                Vec::new()
            }
            fn grant_paths(&self, _: &[u8; 16], _: &[&str]) -> Vec<GrantPath> {
                self.0
                    .iter()
                    .map(|path| GrantPath {
                        path: (*path).into(),
                        purpose: "a file".into(),
                    })
                    .collect()
            }
        }
        let covering = |protocol: &str| {
            SignerError::Protocol(ProtocolError::BadGrantPath {
                protocol: protocol.into(),
                rule: "a path that covers another",
            })
        };
        for paths in [
            &["/pub/gamma/", "/pub/gamma/a.json"][..],
            &["/pub/gamma/a/b.json", "/pub/gamma/a/"][..],
        ] {
            let one = Protocols::new(vec![Arc::new(Nested(paths))]).unwrap();
            let error = one.grant_paths(&[1; 16], &owned(&["gamma"])).unwrap_err();
            assert_eq!(error, covering("gamma"));
        }
        // A folder of one protocol covering the other's file, whichever the scopes name
        // first.
        let two = Protocols::new(vec![
            Arc::new(Beta {
                path: "/pub/beta/tags.json",
            }),
            Arc::new(Nested(&["/pub/beta/"])),
        ])
        .unwrap();
        for (scopes, second) in [(["beta", "gamma"], "gamma"), (["gamma", "beta"], "beta")] {
            let error = two.grant_paths(&[1; 16], &owned(&scopes)).unwrap_err();
            assert_eq!(error, covering(second));
        }
        // Paths side by side pass, a folder and a file named like its start included.
        let apart = Protocols::new(vec![Arc::new(Nested(&[
            "/pub/gamma/a.json",
            "/pub/gamma/ab/",
            "/pub/gamma/a",
        ]))])
        .unwrap();
        assert_eq!(
            apart
                .grant_paths(&[1; 16], &owned(&["gamma"]))
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn test_protocols_feed_the_core_app_request_caps_check() {
        // The paths the set adds are the `extra_paths` of the core's caps check (Switch wire
        // 3.9 step 3): the app's record plus an allowed protocol path passes, a path the set
        // didn't add doesn't.
        use pubky_switch_core::records::{app_record_path, check_caps};
        let protocols = set();
        let id = [9u8; 16];
        let paths = protocols.grant_paths(&id, &owned(&["beta"])).unwrap();
        let extra: Vec<&str> = paths.iter().map(|p| p.path.as_str()).collect();
        let record = app_record_path(&id);
        check_caps(&format!("{record}:rw,{}:rw", extra[0]), &id, &extra).unwrap();
        assert!(check_caps(&format!("{record}:rw,/pub/other.json:rw"), &id, &extra).is_err());
    }
}

#[cfg(test)]
mod roots {
    use super::*;

    struct Claims(&'static str, &'static str);

    impl Protocol for Claims {
        fn name(&self) -> &str {
            self.0
        }
        fn scopes(&self) -> Vec<ScopeDef> {
            vec![ScopeDef::keyed(self.1)]
        }
        fn check_scopes(&self, _: &[&str]) -> std::result::Result<(), String> {
            Ok(())
        }
        fn permissions(&self, _: &[&str]) -> Vec<Permission> {
            Vec::new()
        }
    }

    #[test]
    fn test_protocols_of_scopes_in_registration_order() {
        let protocols = Protocols::new(vec![
            Arc::new(Claims("chat", "chat")),
            Arc::new(Claims("notes", "notes")),
        ])
        .unwrap();
        let scopes = ["notes", "chat:team", "notes", "other"].map(String::from);
        assert_eq!(protocols.protocols_of(&scopes), ["chat", "notes"]);
        assert!(protocols.protocols_of(&["other".into()]).is_empty());
    }

    #[test]
    fn test_protocols_a_protocol_claims_only_its_own_roots() {
        for root in ["chat", "chat_read", "chat-history"] {
            Protocols::new(vec![Arc::new(Claims("chat", root))]).unwrap();
        }
        // Another root, even with only this protocol installed (Switch wire 3.1 "Scope roots").
        for root in ["tasks", "chatter", "chat_", "cha", "other_chat"] {
            let error = Protocols::new(vec![Arc::new(Claims("chat", root))]).unwrap_err();
            assert_eq!(
                error,
                ProtocolError::ForeignRoot {
                    protocol: "chat".into(),
                    scope: root.into()
                },
                "{root}"
            );
        }
    }

    #[test]
    fn test_protocols_every_name_of_the_rule_takes_its_roots() {
        // One rule for every protocol: no name is set aside for one protocol, and none is
        // refused for being, or beginning, another protocol's root (Switch wire 3.1 "Scope roots").
        for (name, root) in [
            ("notes", "notes"),
            ("photos", "photos_share"),
            ("files", "files-sync"),
            ("a1", "a1_b"),
        ] {
            Protocols::new(vec![Arc::new(Claims(name, root))])
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        let error = Protocols::new(vec![Arc::new(Claims("tasks", "notes"))]).unwrap_err();
        assert_eq!(
            error,
            ProtocolError::ForeignRoot {
                protocol: "tasks".into(),
                scope: "notes".into()
            }
        );
    }
}
