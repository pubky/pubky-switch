//! The reserved protocol names and scope roots (Switch wire 3.1, "Scope roots").
//!
//! The list is the spec's: `spec/reserved-roots.json`, embedded here and read once. It is the
//! machine-readable copy of the wire format's list, and a test checks that the two agree. The
//! core gives these names no meaning beyond the Switch's rule: each root belongs to the
//! protocol it is listed under.
//!
//! The file is embedded from the repository's `spec/`, outside the crate's own folder. That
//! works wherever the crate is built from the repository, as a git dependency is; a crate
//! published on its own would have to copy the file into the crate at build time.

use std::sync::OnceLock;

use serde::Deserialize;

use crate::error::{Error, Result, invalid};
use crate::scopes::is_name;

/// The file, as the spec holds it.
const RESERVED_JSON: &str = include_str!("../../../../spec/reserved-roots.json");

/// A protocol whose name and scope roots are reserved for it (Switch wire 3.1, "Scope
/// roots").
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct ReservedProtocol {
    /// The protocol's name.
    pub name: String,
    /// The scope roots that belong to it, and only to it.
    pub roots: Vec<String>,
}

#[derive(Deserialize)]
struct ReservedFile {
    reserved: Vec<ReservedProtocol>,
}

static RESERVED: OnceLock<std::result::Result<Vec<ReservedProtocol>, String>> = OnceLock::new();

/// The reserved protocols, each with its roots, as `spec/reserved-roots.json` lists them.
///
/// # Errors
///
/// [`Error::Invalid`] when the embedded file doesn't read, or breaks its own rules: every name
/// and root follows the scope name rule, no root is listed twice, and no protocol is listed
/// without roots. A caller that can't read the list refuses rather than reserves nothing.
pub fn reserved() -> Result<&'static [ReservedProtocol]> {
    match RESERVED.get_or_init(|| parse(RESERVED_JSON).map_err(|e| e.to_string())) {
        Ok(list) => Ok(list),
        Err(why) => Err(Error::Invalid(why.clone())),
    }
}

fn parse(json: &str) -> Result<Vec<ReservedProtocol>> {
    let file: ReservedFile = serde_json::from_str(json)?;
    let mut seen: Vec<&str> = Vec::new();
    for protocol in &file.reserved {
        if !is_name(&protocol.name) || protocol.roots.is_empty() {
            return invalid("Switch wire 3.1: a reserved protocol without a valid name or roots");
        }
        for root in &protocol.roots {
            if !is_name(root) || seen.contains(&root.as_str()) {
                return invalid("Switch wire 3.1: a reserved root that isn't a name, or twice");
            }
            seen.push(root);
        }
    }
    Ok(file.reserved)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The backticked words of `line`, in order.
    fn ticked(line: &str) -> Vec<&str> {
        line.split('`').skip(1).step_by(2).collect()
    }

    #[test]
    fn test_reserved_roots_match_the_wire_format() {
        let wire = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/wire-format.md"
        ))
        .unwrap();
        // The "Scope roots" bullet that lists the reserved roots and the name they belong to.
        let line = wire
            .lines()
            .find(|l| l.contains("roots are reserved for") && l.contains("Its name is"))
            .expect("wire 3.1 lists the reserved roots");
        let (roots, name) = line.split_once("Its name is").unwrap();
        let roots: Vec<&str> = ticked(roots);
        let name = ticked(name)[0];
        let list = reserved().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, name);
        assert_eq!(list[0].roots, roots);
    }

    #[test]
    fn test_reserved_roots_refuse_a_malformed_list() {
        for bad in [
            r#"{"reserved":[{"name":"Bad","roots":["a"]}]}"#,
            r#"{"reserved":[{"name":"a","roots":[]}]}"#,
            r#"{"reserved":[{"name":"a","roots":["x","x"]}]}"#,
            r#"{"reserved":[{"name":"a","roots":["x"]},{"name":"b","roots":["x"]}]}"#,
            r#"{"reserved":[{"name":"a","roots":["x:y"]}]}"#,
            "not json",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            parse(r#"{"reserved":[{"name":"a","roots":["x","x_y"]}]}"#).unwrap(),
            [ReservedProtocol {
                name: "a".into(),
                roots: vec!["x".into(), "x_y".into()]
            }]
        );
    }
}
