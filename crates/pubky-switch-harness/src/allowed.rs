//! The allowed differences: where the scripted switch answers an honest flow differently
//! from the service, and why each is accepted.
//!
//! This list is the source of truth for honest-path differences between the scripted switch
//! (`pubky-switch-client`'s `testing` module) and the service. A flow's test fails on a
//! difference this list doesn't hold, and on an entry of the flow that matched nothing, so
//! the list can neither miss a difference nor keep one that is gone.
//!
//! What the scripted switch fakes or leaves out beyond honest flows (limits, rates,
//! retention, refusals) is in that module's `FAKES.md`.

use crate::compare::Difference;

/// One accepted difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allowed {
    /// The flow it shows in; [`EVERY_FLOW`] for a difference of the two switches as a whole.
    pub flow: &'static str,
    /// The line's label, as [`crate::trace::Line::label`] gives it. `*` stands for any run
    /// of characters, here and in the next three.
    pub label: &'static str,
    /// The fact that differs.
    pub fact: &'static str,
    /// What the service shows; `(nothing)` when it shows nothing there.
    pub service: &'static str,
    /// What the scripted switch shows; `(nothing)` when it shows nothing there.
    pub scripted: &'static str,
    /// Why the difference is accepted.
    pub reason: &'static str,
    /// The clause of the wire format or the line of `FAKES.md` it follows from.
    pub reference: &'static str,
}

/// In [`Allowed::flow`]: the entry holds in every flow. Such an entry must show in one flow
/// at least.
pub const EVERY_FLOW: &str = "*";

/// What stands for a fact one run didn't show.
pub const NOTHING: &str = "(nothing)";

impl Allowed {
    /// Whether this entry allows `difference`.
    pub fn allows(&self, difference: &Difference) -> bool {
        let shown = |value: &Option<String>| value.clone().unwrap_or_else(|| NOTHING.to_owned());
        matches(self.label, &difference.label)
            && matches(self.fact, &difference.fact)
            && matches(self.service, &shown(&difference.service))
            && matches(self.scripted, &shown(&difference.scripted))
    }
}

/// Whether `text` matches `pattern`, where each `*` stands for any run of characters.
fn matches(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let Some(first) = parts.next() else {
        return text.is_empty();
    };
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let mut parts = parts.peekable();
    if parts.peek().is_none() {
        return rest.is_empty();
    }
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return rest.ends_with(part);
        }
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    true
}

/// The scripted switch's error bodies.
const NULL_CURRENT: &str = "The scripted switch writes `current: null` in every error body that \
    has no `current`; the service leaves the member out, as a writer should. A reader takes the \
    two alike.";

/// Every accepted difference: those of the two switches as a whole, then by flow.
pub static ALLOWED: &[Allowed] = &[
    Allowed {
        flow: EVERY_FLOW,
        label: "*",
        fact: "* (member order)",
        service: "*",
        scripted: "*",
        reason: "The service writes an answer's members in the order of the wire format's \
                 tables and examples; the scripted switch writes them sorted by name. A writer \
                 may use any order, and no reader depends on it.",
        reference: "Switch wire 1.1, \"Exact bytes\"",
    },
    Allowed {
        flow: "join",
        label: "{alice/wallet} GET /v1/{alice}/apps/{wallet}/keys",
        fact: "body.current",
        service: NOTHING,
        scripted: "null",
        reason: NULL_CURRENT,
        reference: "Switch wire, Conventions, \"Absent and null\"; Switch wire 7.1, error bodies",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_with_and_without_stars() {
        assert!(matches("status", "status"));
        assert!(!matches("status", "status code"));
        assert!(matches("body.apps*", "body.apps[0].current"));
        assert!(matches("*", ""));
        assert!(matches("body.*.seq", "body.head.seq"));
        assert!(!matches("body.*.seq", "body.head.seq.more"));
        assert!(matches("*seq", "body.head.seq"));
        assert!(!matches("body.*.seq", "body.seq"));
        assert!(matches("a*b*c", "a-b-b-c"));
        assert!(!matches("a*b*c", "a-c"));
    }

    #[test]
    fn test_allowed_entry_names_both_sides() {
        let entry = Allowed {
            flow: "example",
            label: "{alice} GET /v1/{alice}/apps",
            fact: "body.recovery",
            service: "null",
            scripted: "(nothing)",
            reason: "an example",
            reference: "nowhere",
        };
        let mut difference = Difference {
            line: 3,
            label: "{alice} GET /v1/{alice}/apps".into(),
            fact: "body.recovery".into(),
            service: Some("null".into()),
            scripted: None,
        };
        assert!(entry.allows(&difference));
        difference.scripted = Some("bool true".into());
        assert!(!entry.allows(&difference), "another value there");
        difference.scripted = None;
        difference.label = "{bob} GET /v1/{bob}/apps".into();
        assert!(!entry.allows(&difference), "another call");
    }
}
