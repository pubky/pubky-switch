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
    /// What the scripted switch shows; `(nothing)` when it shows nothing there, and
    /// [`ONE_MORE`] for a number one above the service's.
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

/// In [`Allowed::scripted`]: the scripted switch shows a number one above the service's, as a
/// counter does that starts one higher and moves at the same events.
pub const ONE_MORE: &str = "one more than the service";

impl Allowed {
    /// Whether this entry allows `difference`.
    pub fn allows(&self, difference: &Difference) -> bool {
        let shown = |value: &Option<String>| value.clone().unwrap_or_else(|| NOTHING.to_owned());
        let (service, scripted) = (shown(&difference.service), shown(&difference.scripted));
        let scripted_allowed = if self.scripted == ONE_MORE {
            match (number_of(&service), number_of(&scripted)) {
                (Some(service), Some(scripted)) => service.checked_add(1) == Some(scripted),
                _ => false,
            }
        } else {
            matches(self.scripted, &scripted)
        };
        matches(self.label, &difference.label)
            && matches(self.fact, &difference.fact)
            && matches(self.service, &service)
            && scripted_allowed
    }
}

/// The number a fact shows: of a JSON number, or of a short string of digits, as a query
/// parameter carries one.
fn number_of(fact: &str) -> Option<u64> {
    fact.strip_prefix("number ")
        .or_else(|| fact.strip_prefix("text "))?
        .parse()
        .ok()
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
        flow: "invite code",
        label: "{alice/wallet} GET /v1/{alice}/feed",
        fact: "body.items[1].context*",
        service: "*",
        scripted: NOTHING,
        reason: "fake batch pending: the service shows the invite code's context on the \
                 conversation entry it wrote at the code's first use, as a feed item; the \
                 scripted switch shows it on the entry the code admitted and leaves it off \
                 the conversation entry.",
        reference: "Switch wire 7.5, the `chain` item's `context`",
    },
    Allowed {
        flow: "invite code",
        label: "{alice/wallet} GET /v1/{alice}/allow",
        fact: "body.conversations[0].context*",
        service: "*",
        scripted: NOTHING,
        reason: "fake batch pending: the service lists a conversation entry an invite code \
                 made with the code's context; the scripted switch lists it without.",
        reference: "Switch wire 7.4.6, `conversations`",
    },
    Allowed {
        flow: "invite code",
        label: "{alice/wallet} GET /v1/{alice}/allow",
        fact: "body.conversations[0].last_used",
        service: "time *",
        scripted: NOTHING,
        reason: "fake batch pending: the service keeps the time of the last append a \
                 conversation entry admitted; the scripted switch keeps none, so an app \
                 that prunes idle entries by it finds every entry never used.",
        reference: "Switch wire 7.4.6, `last_used`",
    },
    Allowed {
        flow: "renewal, a scope dropped",
        label: "{alice/phone} GET /v1/{alice}/records/*",
        fact: "body.cert.*",
        service: "*",
        scripted: "*",
        reason: "fake batch pending: a record view carries the certificate the service checked \
                 the write against, which a later renewal doesn't change; the scripted switch \
                 gives the writer's current certificate, here one without the write scope.",
        reference: "Switch wire 7.4.9, the record view's `cert`",
    },
    Allowed {
        flow: "renewal, a scope dropped",
        label: "{alice/tablet} GET /v1/{alice}/records",
        fact: "body.records[0].cert.*",
        service: "*",
        scripted: "*",
        reason: "fake batch pending: a record view carries the certificate the service checked \
                 the write against, which a later renewal doesn't change; the scripted switch \
                 gives the writer's current certificate, here one without the write scope.",
        reference: "Switch wire 7.4.9, the record view's `cert`",
    },
    Allowed {
        flow: "renewal, a scope dropped",
        label: "{alice/tablet} GET /v1/{alice}/records/*",
        fact: "body.cert.*",
        service: "*",
        scripted: "*",
        reason: "fake batch pending: a record view carries the certificate the service checked \
                 the write against, which a later renewal doesn't change; the scripted switch \
                 gives the writer's current certificate, here one without the write scope.",
        reference: "Switch wire 7.4.9, the record view's `cert`",
    },
    Allowed {
        flow: "renewal, a scope dropped",
        label: "outcome the tablet joined after the renewal and listed the collection",
        fact: "outcome.listed",
        service: "number 1",
        scripted: "number 0",
        reason: "fake batch pending: with the writer's current certificate in the record view, \
                 an app that joins after the renewal refuses the write (Switch wire 6.2 \
                 step 5), where with the certificate of the write it takes it.",
        reference: "Switch wire 7.4.9, the record view's `cert`",
    },
    Allowed {
        flow: "renewal, a scope dropped",
        label: "outcome what the tablet holds of the record",
        fact: "outcome.*",
        service: "*",
        scripted: "*",
        reason: "fake batch pending: with the writer's current certificate in the record view, \
                 an app that joins after the renewal refuses the write (Switch wire 6.2 \
                 step 5), where with the certificate of the write it takes it.",
        reference: "Switch wire 7.4.9, the record view's `cert`",
    },
    Allowed {
        flow: "renewal, a scope dropped",
        label: "outcome what the tablet reads of the record",
        fact: "outcome.*",
        service: "*",
        scripted: "*",
        reason: "fake batch pending: with the writer's current certificate in the record view, \
                 an app that joins after the renewal refuses the write (Switch wire 6.2 \
                 step 5), where with the certificate of the write it takes it.",
        reference: "Switch wire 7.4.9, the record view's `cert`",
    },
    Allowed {
        flow: "two collections",
        label: "{alice/*} GET /v1/{alice}/records/*",
        fact: "status",
        service: "403",
        scripted: "200",
        reason: "fake batch pending: the service refuses a read of a record whose read scope the \
                 caller's certificate lacks; the scripted switch answers it with the record's \
                 view, and the app then keeps a record it can't open.",
        reference: "Switch wire 7.4.9, `GET /records/{key}`",
    },
    Allowed {
        flow: "two collections",
        label: "{alice/*} GET /v1/{alice}/records/*",
        fact: "body.code",
        service: "text permission_missing",
        scripted: NOTHING,
        reason: "fake batch pending: the service refuses a read of a record whose read scope the \
                 caller's certificate lacks; the scripted switch answers it with the record's \
                 view, and the app then keeps a record it can't open.",
        reference: "Switch wire 7.4.9, `GET /records/{key}`",
    },
    Allowed {
        flow: "two collections",
        label: "{alice/*} GET /v1/{alice}/records/*",
        fact: "body.*",
        service: NOTHING,
        scripted: "*",
        reason: "fake batch pending: the service refuses a read of a record whose read scope the \
                 caller's certificate lacks; the scripted switch answers it with the record's \
                 view, and the app then keeps a record it can't open.",
        reference: "Switch wire 7.4.9, `GET /records/{key}`",
    },
    Allowed {
        flow: "two collections",
        label: "outcome what the * reads of *, outside its scope",
        fact: "outcome.*",
        service: "*",
        scripted: "*",
        reason: "fake batch pending: the service refuses a read of a record whose read scope the \
                 caller's certificate lacks; the scripted switch answers it with the record's \
                 view, and the app then keeps a record it can't open.",
        reference: "Switch wire 7.4.9, `GET /records/{key}`",
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
    fn test_allowed_one_more_takes_only_a_number_one_above() {
        let entry = Allowed {
            flow: "example",
            label: "*",
            fact: "body.apps_version",
            service: "number *",
            scripted: ONE_MORE,
            reason: "an example",
            reference: "nowhere",
        };
        let difference = |service: &str, scripted: &str| Difference {
            line: 0,
            label: "{bob/shop} GET /v1/{alice}/directory".into(),
            fact: "body.apps_version".into(),
            service: Some(service.into()),
            scripted: Some(scripted.into()),
        };
        assert!(entry.allows(&difference("number 1", "number 2")));
        assert!(entry.allows(&difference("number 9", "number 10")));
        assert!(
            !entry.allows(&difference("number 1", "number 3")),
            "two more"
        );
        assert!(
            !entry.allows(&difference("number 2", "number 1")),
            "one less"
        );
        assert!(!entry.allows(&difference("number 1", "null")), "no number");
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
