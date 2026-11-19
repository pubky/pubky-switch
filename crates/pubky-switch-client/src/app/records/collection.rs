//! Collections and their policy members (Switch spec 3.3, 8.2, 10.3).

use pubky_switch_core::ident::{Policy, collection_id};
use pubky_switch_core::ops::RecordPut;
use pubky_switch_core::records::AppCert;

use super::{App, AppError, Refusal};

/// Which policies a collection's records may have (Switch spec 3.3, 10.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PolicyFamily {
    /// The fixed policy alone.
    #[default]
    Fixed,
    /// The fixed policy, whose read scope is a name, and one policy per sub-scope of that
    /// name: for `<sub>`, the read scope `<name>:<sub>`, and the write scopes with `<name>`
    /// narrowed to `<name>:<sub>` and the others kept. An app holding `<name>` reads every
    /// member, one holding only `<name>:<sub>` its own (Switch spec 3.3, 8.2).
    SubScopes,
    /// Records with the same read and write scopes and a permanent policy naming
    /// their generation (Switch spec 10.3.1). Each record carries its own generation.
    PermanentGenerations,
}

/// A collection of a protocol and its fixed policy (Switch spec 10.3). The collection name
/// is the protocol's opaque string. One name may come with several policies, such as one per
/// sub-scope: either each as a collection of its own here, or as one collection with the
/// family [`PolicyFamily::SubScopes`], which lists and reads every member the app holds
/// the read scope of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    /// The collection name.
    pub name: String,
    /// The fixed policy; with [`PolicyFamily::SubScopes`], the name scope's.
    pub policy: Policy,
    /// The policies besides the fixed one.
    pub family: PolicyFamily,
}

impl Collection {
    /// A collection with its fixed policy alone.
    pub fn new(name: &str, policy: Policy) -> Self {
        Self {
            name: name.to_owned(),
            policy,
            family: PolicyFamily::Fixed,
        }
    }

    /// A collection with the name scope's `policy` and one policy per sub-scope
    /// ([`PolicyFamily::SubScopes`]).
    pub fn with_sub_scopes(name: &str, policy: Policy) -> Self {
        Self {
            name: name.to_owned(),
            policy,
            family: PolicyFamily::SubScopes,
        }
    }

    /// Read permanent records naming any generation with exactly these scopes. For a
    /// particular record, use a fixed collection naming its generation.
    pub fn with_permanent_generations(name: &str, read_scope: &str, write_scopes: &[&str]) -> Self {
        Self {
            name: name.to_owned(),
            policy: Policy::new(read_scope, write_scopes),
            family: PolicyFamily::PermanentGenerations,
        }
    }

    /// The collection ID of `identity` (Switch spec 13.3).
    pub fn id(&self, identity: &[u8; 32]) -> [u8; 32] {
        collection_id(&self.name, identity)
    }

    /// The policy of sub-scope `sub` ([`PolicyFamily::SubScopes`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::Usage`] for a collection without sub-scope policies, a fixed read scope
    /// that isn't a name, or a `sub` that isn't a sub-scope (Switch spec 3.3).
    pub fn sub_scope_policy(&self, sub: &str) -> Result<Policy, AppError> {
        let name = self.policy.read_scope.as_str();
        if self.family != PolicyFamily::SubScopes
            || !pubky_switch_core::scopes::is_name(name)
            || !pubky_switch_core::scopes::is_sub(sub)
        {
            return Err(Refusal::Usage(
                "Switch spec 3.3: no sub-scope policy of this collection for that sub-scope".into(),
            )
            .into());
        }
        let narrowed = format!("{name}:{sub}");
        let narrow = |scope: &String| {
            if scope == name {
                narrowed.clone()
            } else {
                scope.clone()
            }
        };
        let mut policy = self.policy.clone();
        policy.write_scopes = self.policy.write_scopes.iter().map(narrow).collect();
        policy.write_scopes.sort();
        policy.write_scopes.dedup();
        policy.create_scope = self.policy.create_scope.as_ref().map(narrow);
        policy.read_scope = narrowed;
        Ok(policy)
    }

    /// The collection of sub-scope `sub` alone: its records, read and written under that
    /// sub-scope's policy, for a [`RecordTarget`].
    ///
    /// # Errors
    ///
    /// As [`Collection::sub_scope_policy`].
    pub fn sub_scope(&self, sub: &str) -> Result<Collection, AppError> {
        Ok(Collection::new(&self.name, self.sub_scope_policy(sub)?))
    }

    /// Which member of the family `policy` is: `Some(None)` for the fixed policy,
    /// or a named permanent generation, `Some(Some(sub))` for the policy of sub-scope
    /// `sub`, `None` for a policy the
    /// collection doesn't have.
    pub fn member(&self, policy: &Policy) -> Option<Option<String>> {
        if self.family == PolicyFamily::PermanentGenerations {
            return (policy.read_scope == self.policy.read_scope
                && policy.write_scopes == self.policy.write_scopes
                && policy.create_scope == self.policy.create_scope
                && policy
                    .permanent
                    .and_then(|p| p.generation)
                    .is_some_and(|g| (1..=pubky_switch_core::json::MAX_INT).contains(&g)))
            .then_some(None);
        }
        if *policy == self.policy {
            return Some(None);
        }
        if self.family != PolicyFamily::SubScopes {
            return None;
        }
        let (name, sub) = pubky_switch_core::scopes::split(&policy.read_scope)?;
        let sub = sub?;
        if name != self.policy.read_scope {
            return None;
        }
        let expected = self.sub_scope_policy(sub).ok()?;
        (expected == *policy).then(|| Some(sub.to_owned()))
    }

    /// Whether a record may have `policy` in this collection.
    pub fn admits(&self, policy: &Policy) -> bool {
        self.member(policy).is_some()
    }

    /// Whether a read scope accessible to `cert` matches `check` (Switch spec 3.3, 10.3).
    /// Fixed scopes include any child opened with its parent key. A child-only holder
    /// reads only that member of a sub-scope family.
    pub(crate) fn any_read_scope(&self, cert: &AppCert, check: impl Fn(&str) -> bool) -> bool {
        let read = self.policy.read_scope.as_str();
        if cert.holds_scope(read) {
            return check(read);
        }
        self.family == PolicyFamily::SubScopes
            && cert
                .scopes()
                .iter()
                .any(|scope| pubky_switch_core::scopes::parent(scope) == Some(read) && check(scope))
    }

    /// Whether a certificate holds the read scope of any member, so its app lists the
    /// collection (Switch spec 8.3).
    pub fn readable_by(&self, cert: &AppCert) -> bool {
        self.any_read_scope(cert, |_| true)
    }
}

/// A record by its collection and natural key, which the naming key blinds (Switch spec
/// 13.3). Its `Debug` shows no natural key.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordTarget {
    /// The collection and its fixed policy.
    pub collection: Collection,
    /// The natural key, the protocol's bytes.
    pub natural_key: Vec<u8>,
}

impl std::fmt::Debug for RecordTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecordTarget({}, ..)", self.collection.name)
    }
}

impl RecordTarget {
    pub(crate) fn key_with(
        &self,
        naming: &pubky_switch_core::ident::NamingKey,
    ) -> Result<[u8; 32], AppError> {
        Ok(naming.record_key(
            &self.collection.name,
            &self.natural_key,
            &self.concrete_policy()?.hash()?,
        ))
    }

    pub(crate) fn concrete_policy(&self) -> Result<&Policy, AppError> {
        if self.collection.family == PolicyFamily::PermanentGenerations {
            return Err(Refusal::Usage(
                "Switch spec 10.3.1: a record target must name its permanent generation".into(),
            )
            .into());
        }
        Ok(&self.collection.policy)
    }

    /// The record of `natural_key` in `collection`.
    pub fn new(collection: Collection, natural_key: &[u8]) -> Self {
        Self {
            collection,
            natural_key: natural_key.to_vec(),
        }
    }
}

impl App {
    /// The registered protocol other than `name` that the record `put` writes belongs to
    /// ([`super::ProtocolSet::foreign_owner`]): by the collection of a registered protocol
    /// it names, or by its read scope.
    pub(crate) fn foreign_put(&self, name: &str, put: &RecordPut) -> Option<String> {
        // Ownership belongs to the collection ID even when the supplied policy is not
        // one this protocol accepts for reading (Switch spec 3.3).
        let collection = self
            .protocols
            .collections()
            .into_iter()
            .find(|collection| collection.id(&self.state.meta.identity) == put.collection)
            .map(|collection| collection.name);
        self.protocols
            .foreign_owner(name, collection.as_deref(), &put.policy.read_scope)
            .map(str::to_owned)
    }

    /// The collection member matching both the ID and an admitted policy.
    pub(super) fn collection_of(&self, put: &RecordPut) -> Option<Collection> {
        let identity = self.state.meta.identity;
        self.protocols
            .collections()
            .into_iter()
            .find(|c| c.id(&identity) == put.collection && c.admits(&put.policy))
            .map(|c| Collection::new(&c.name, put.policy.clone()))
    }

    pub(crate) fn collection_of_name(&self, collection: &Collection) -> bool {
        self.protocols
            .collections()
            .iter()
            .any(|c| c.name == collection.name && c.admits(&collection.policy))
    }
}
