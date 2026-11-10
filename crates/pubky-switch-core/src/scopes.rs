//! Scopes and switch permissions (Switch spec 3.2, 3.3; Switch wire 3.1).
//!
//! The switch knows no scope names: a scope is a protocol's string, and the switch applies
//! only one generic rule to it, a name or a name and a sub-scope, `name:<sub>`, with one rule
//! of hierarchy, holding `name` covers every `name:<sub>`. A protocol may bound its scopes
//! further; those bounds are its own verifiers' and don't live here.
//!
//! The switch permissions are the switch's own: a certificate lists them, and the switch
//! enforces exactly that list, never deriving permissions from scopes.

use crate::error::{Result, invalid};

mod reserved;

pub use reserved::{ReservedProtocol, reserved};

/// The most scopes one certificate holds (Switch wire 3.1, "Scope names").
pub const MAX_SCOPES: usize = 32;

/// The longest scope name, and the longest sub-scope, in characters (Switch wire 3.1).
pub const MAX_SCOPE_PART: usize = 32;

/// Whether `text` is a scope name: 1 to 32 characters of `a-z`, `0-9`, `_` and `-`, starting
/// with a letter or digit (Switch spec 3.3).
pub fn is_name(text: &str) -> bool {
    is_part(text, true)
}

/// Whether `text` is a sub-scope: 1 to 32 characters of `a-z`, `0-9` and `-`, starting with a
/// letter or digit (Switch spec 3.3).
pub fn is_sub(text: &str) -> bool {
    is_part(text, false)
}

fn is_part(text: &str, underscore: bool) -> bool {
    let bytes = text.as_bytes();
    let allowed = |b: &u8| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || (underscore && *b == b'_')
    };
    (1..=MAX_SCOPE_PART).contains(&bytes.len())
        && bytes.iter().all(allowed)
        && bytes
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// A scope split into its name and sub-scope: `name` is `(name, None)` and `name:<sub>` is
/// `(name, Some(sub))`, split at the first `:`. `None` for a string that is neither (Switch
/// spec 3.3).
pub fn split(scope: &str) -> Option<(&str, Option<&str>)> {
    match scope.split_once(':') {
        None => is_name(scope).then_some((scope, None)),
        Some((name, sub)) => (is_name(name) && is_sub(sub)).then_some((name, Some(sub))),
    }
}

/// Whether `scope` follows the scope rule: a name, or `name:<sub>` (Switch spec 3.3).
pub fn is_scope(scope: &str) -> bool {
    split(scope).is_some()
}

/// The parent name of a sub-scope `name:<sub>`; `None` for a name or a string that isn't a
/// scope.
pub fn parent(scope: &str) -> Option<&str> {
    match split(scope)? {
        (name, Some(_)) => Some(name),
        (_, None) => None,
    }
}

/// Check a certificate's scopes against the scope rule (Switch spec 3.3, Switch wire 3.1):
/// at most 32, each a name or `name:<sub>`, each once, and never a name beside one of its own
/// sub-scopes, which it covers.
///
/// Every reader applies this rule, the switch included; a protocol's own bounds come on top.
///
/// # Errors
///
/// [`crate::Error::Invalid`] naming the part of the rule that failed. The message never
/// repeats a scope, which is the refused document's text.
pub fn check_scopes(scopes: &[String]) -> Result<()> {
    if scopes.len() > MAX_SCOPES {
        return invalid("Switch wire 3.1: scopes: more than 32 scopes");
    }
    for (i, scope) in scopes.iter().enumerate() {
        if !is_scope(scope) {
            return invalid("Switch wire 3.1: scopes: a scope that isn't a name or name:<sub>");
        }
        if scopes.iter().take(i).any(|earlier| earlier == scope) {
            return invalid("Switch wire 3.1: scopes: a scope listed twice");
        }
        if let Some(name) = parent(scope)
            && scopes.iter().any(|other| other == name)
        {
            return invalid(
                "Switch wire 3.1: scopes: a name beside one of its sub-scopes, which it covers",
            );
        }
    }
    Ok(())
}

/// Whether the scopes `held` hold `scope`: by equal strings, or by its parent name, since
/// holding `name` covers every `name:<sub>` (Switch wire 3.1, "Scope names").
///
/// This is the one rule of hierarchy among scopes. The switch applies it to shared record
/// policies, and apps to the scope keys they hold. A sub-scope covers nothing but itself.
pub fn holds(held: &[String], scope: &str) -> bool {
    held.iter().any(|h| h == scope) || parent(scope).is_some_and(|p| held.iter().any(|h| h == p))
}

/// A switch permission (Switch spec 3.2). The variants are in the fixed order a certificate
/// lists them in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// `claims.read`: read claims, and see claim entries in the feed.
    ClaimsRead,
    /// `claims.write`: write claim entries.
    ClaimsWrite,
    /// `lists.read`: list contacts, conversation entries and the deny list.
    ListsRead,
    /// `lists.manage`: change contacts and the deny list, remove conversation entries, and
    /// restore the lists after a provider loss.
    ListsManage,
    /// `conversation.add`: add conversation entries, invites included.
    ConversationAdd,
}

impl Permission {
    /// Every switch permission, in the fixed order (Switch wire 3.1).
    pub const ALL: [Permission; 5] = [
        Permission::ClaimsRead,
        Permission::ClaimsWrite,
        Permission::ListsRead,
        Permission::ListsManage,
        Permission::ConversationAdd,
    ];

    /// The permission's name, as a certificate carries it.
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::ClaimsRead => "claims.read",
            Permission::ClaimsWrite => "claims.write",
            Permission::ListsRead => "lists.read",
            Permission::ListsManage => "lists.manage",
            Permission::ConversationAdd => "conversation.add",
        }
    }

    /// The permission of a name; `None` for a name the switch doesn't define.
    pub fn from_name(name: &str) -> Option<Permission> {
        Permission::ALL.into_iter().find(|p| p.as_str() == name)
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Read a certificate's `permissions`: only switch permissions, each once, in the fixed order
/// (Switch wire 3.1, "Switch permissions"). Any subset in that order is well formed, the empty
/// list included.
///
/// # Errors
///
/// [`crate::Error::Invalid`] for a name that isn't a switch permission, a name twice, or names
/// out of the fixed order. Every reader refuses such a list, the switch included.
pub fn check_permissions(names: &[String]) -> Result<Vec<Permission>> {
    let mut out: Vec<Permission> = Vec::with_capacity(names.len());
    for name in names {
        let Some(permission) = Permission::from_name(name) else {
            return invalid("Switch wire 3.1: permissions: a name that isn't a switch permission");
        };
        if out.last().is_some_and(|last| *last >= permission) {
            return invalid("Switch wire 3.1: permissions: not each once in the fixed order");
        }
        out.push(permission);
    }
    Ok(out)
}

/// The names of `permissions`, as a certificate lists them.
pub fn permission_names(permissions: &[Permission]) -> Vec<String> {
    permissions.iter().map(|p| p.as_str().to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(scopes: &[&str]) -> Vec<String> {
        scopes.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn test_scope_names_follow_the_character_rules() {
        let long = "a".repeat(32);
        let too_long = "a".repeat(33);
        for ok in ["a", "scope-a", "scope_b", "0x", long.as_str()] {
            assert!(is_name(ok), "{ok}");
        }
        for bad in ["", "-a", "_a", "Scope", "a.b", "a b", too_long.as_str()] {
            assert!(!is_name(bad), "{bad}");
        }
        assert!(is_sub("sub-1"));
        assert!(!is_sub("sub_1"), "no underscore in a sub-scope");
        assert!(!is_sub("-sub"));
    }

    #[test]
    fn test_split_reads_names_and_sub_scopes() {
        assert_eq!(split("name"), Some(("name", None)));
        assert_eq!(split("name:sub"), Some(("name", Some("sub"))));
        let sub = format!("name:{}", "b".repeat(32));
        assert!(split(&sub).is_some());
        let over = format!("name:{}", "b".repeat(33));
        for bad in [
            ":x",
            "name:",
            "name:a:b",
            "name:a.b",
            "Name:x",
            over.as_str(),
        ] {
            assert_eq!(split(bad), None, "{bad}");
        }
        assert_eq!(parent("name:sub"), Some("name"));
        assert_eq!(parent("name"), None);
    }

    #[test]
    fn test_check_scopes_takes_valid_lists() {
        check_scopes(&owned(&["scope-a", "scope-b", "name:sub"])).unwrap();
        check_scopes(&[]).unwrap();
        let many: Vec<String> = (0..32).map(|i| format!("s{i}")).collect();
        check_scopes(&many).unwrap();
        check_scopes(&owned(&["name:a", "name:b"])).unwrap();
    }

    #[test]
    fn test_check_scopes_refuses_each_rule() {
        let mut many: Vec<String> = (0..32).map(|i| format!("s{i}")).collect();
        many.push("one-more".into());
        for (scopes, rule) in [
            (many, "more than 32"),
            (owned(&["Scope"]), "isn't a name"),
            (owned(&["scope-a", "scope-a"]), "twice"),
            (owned(&["name", "name:sub"]), "beside one of its sub-scopes"),
            (
                owned(&["name:sub", "other", "name"]),
                "beside one of its sub-scopes",
            ),
        ] {
            let error = check_scopes(&scopes).unwrap_err().to_string();
            assert!(error.contains(rule), "{scopes:?}: {error}");
            assert!(!error.contains("Scope\""), "never quotes a scope");
        }
    }

    #[test]
    fn test_holds_covers_sub_scopes_of_a_held_name() {
        let held = owned(&["name", "other:x"]);
        assert!(holds(&held, "name"));
        assert!(holds(&held, "name:any"));
        assert!(holds(&held, "other:x"));
        assert!(
            !holds(&held, "other"),
            "a sub-scope covers nothing but itself"
        );
        assert!(!holds(&held, "other:y"));
        assert!(!holds(&held, "name:a:b"), "not a scope");
    }

    #[test]
    fn test_check_permissions_takes_every_ordered_subset() {
        for mask in 0..32u32 {
            let names: Vec<String> = Permission::ALL
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, p)| p.as_str().to_owned())
                .collect();
            let parsed = check_permissions(&names).unwrap();
            assert_eq!(permission_names(&parsed), names);
        }
    }

    #[test]
    fn test_check_permissions_refuses_malformed_lists() {
        for (names, rule) in [
            (owned(&["claims.admin"]), "isn't a switch permission"),
            (owned(&["Claims.read"]), "isn't a switch permission"),
            (owned(&["claims.read", "claims.read"]), "fixed order"),
            (owned(&["conversation.add", "claims.read"]), "fixed order"),
        ] {
            let error = check_permissions(&names).unwrap_err().to_string();
            assert!(error.contains(rule), "{names:?}: {error}");
        }
    }
}
