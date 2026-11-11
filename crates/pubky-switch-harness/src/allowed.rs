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

/// The scripted switch's error bodies.
const NULL_CURRENT: &str = "The scripted switch writes `current: null` in every error body that \
    has no `current`; the service leaves the member out, as a writer should. A reader takes the \
    two alike.";

/// Where the directory's counters start.
const COUNTER_START: &str = "The wire format says when `apps_version` and `directory_version` \
    change, not where they start: the service's start at 0, the scripted switch's at 1. They \
    move at the same events, so the scripted switch's is one more; a sender only hands the \
    number back.";

/// A list operation in the feed of an app that may not read the lists.
const UNREAD_LIST_ITEM: &str = "The first item is the pad's own `allow.put`, the contact it \
    saved. The pad holds `lists.manage` and not `lists.read`, so the service shows it the \
    operation as a stub; the scripted switch applies no visibility rule and shows every chain \
    item in full. The app does the same with both: it checks the stub and moves on.";

/// The entries of a finished claim in the feed.
const COMPACTED_CLAIM: &str = "The `done` entry settles the claim with every attempt `done` or \
    `failed`, so the service compacts the claim at once and its entries lose their documents: \
    the feed shows the `done` entry as a stub, also to an app with `claims.read`. The scripted \
    switch compacts nothing and shows the entry in full, so the app raises a `ClaimChanged` \
    event from its feed there and none at the service.";

/// What an app that only follows its feed knows of a claim another app settled.
const SETTLED_UNSEEN: &str = "The wallet's `done` entry settles the claim, which the service \
    compacts at once: in the feed of the phone, which holds `claims.read`, the entry is a stub. \
    So the phone raises no event for it and goes on holding the claim as attempting, at step 1, \
    until it reads the claim; and since a compacted claim's read has no entries, it never holds \
    the proof that shows the claim settled. The scripted switch shows the entry in full, so \
    there the phone holds the claim settled, with that proof, from its feed alone.";

/// The wallet's own entries of the claim it settled, in its own feed.
const OWN_ENTRIES_COMPACTED: &str = "Once its claim is settled and compacted, the wallet's own \
    `attempt` and `done` entries are stubs in its feed at the service; the scripted switch \
    goes on showing them in full, and the wallet raises a `ClaimChanged` event for each as it \
    reads them.";

/// An entry of the `watching` flow about the compacted claim.
const fn watching(
    label: &'static str,
    fact: &'static str,
    service: &'static str,
    scripted: &'static str,
    reason: &'static str,
) -> Allowed {
    Allowed {
        flow: "watching",
        label,
        fact,
        service,
        scripted,
        reason,
        reference: "Switch wire 6.8 \"Tombstones\"; 7.5, the entries of compacted claims",
    }
}

/// The key of the `watching` flow's claim, as its events show it.
const WATCHED: &str = "text ClaimChanged a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s";

/// The feed reads of the `watching` flow.
const PHONE_FEED: &str = "{alice/phone} GET /v1/{alice}/feed";
const WALLET_FEED: &str = "{alice/wallet} GET /v1/{alice}/feed";

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
        label: "{alice/wallet} GET /v1/{alice}/apps/{alice/wallet}/keys",
        fact: "body.current",
        service: NOTHING,
        scripted: "null",
        reason: NULL_CURRENT,
        reference: "Switch wire, Conventions, \"Absent and null\"; Switch wire 7.1, error bodies",
    },
    Allowed {
        flow: "messaging",
        label: "{bob/shop} GET /v1/{alice}/directory",
        fact: "body.apps_version",
        service: "number 1",
        scripted: ONE_MORE,
        reason: COUNTER_START,
        reference: "Switch wire 7.4.10, `apps_version`",
    },
    Allowed {
        flow: "messaging",
        label: "{bob/shop} GET /v1/{alice}/directory",
        fact: "body.directory_version",
        service: "number 4",
        scripted: ONE_MORE,
        reason: COUNTER_START,
        reference: "Switch wire 7.4.10, `directory_version`",
    },
    Allowed {
        flow: "messaging",
        label: "{bob/shop} POST /v1/{alice}/inbox",
        fact: "request query apps_version",
        service: "text 1",
        scripted: ONE_MORE,
        reason: COUNTER_START,
        reference: "Switch wire 7.4.3, the query's `apps_version`; 7.4.10",
    },
    Allowed {
        flow: "messaging",
        label: "{bob/shop} POST /v1/{alice}/inbox",
        fact: "body.directory_version",
        service: "number 4",
        scripted: ONE_MORE,
        reason: COUNTER_START,
        reference: "Switch wire 7.4.3, the answer's `directory_version`; 7.4.10",
    },
    Allowed {
        flow: "lists without read",
        label: "{alice/pad} GET /v1/{alice}/feed",
        fact: "body.items[0].type",
        service: "text stub",
        scripted: "text chain",
        reason: UNREAD_LIST_ITEM,
        reference: "Switch wire 7.5: `allow.*` is for apps with `lists.read`",
    },
    Allowed {
        flow: "lists without read",
        label: "{alice/pad} GET /v1/{alice}/feed",
        fact: "body.items[0].item*",
        service: NOTHING,
        scripted: "*",
        reason: UNREAD_LIST_ITEM,
        reference: "Switch wire 7.5: a stub carries `seq` and `stub`, no `item_type` or `item`",
    },
    Allowed {
        flow: "lists without read",
        label: "{alice/pad} GET /v1/{alice}/feed",
        fact: "body.items[0].proof*",
        service: NOTHING,
        scripted: "*",
        reason: UNREAD_LIST_ITEM,
        reference: "Switch wire 7.5: a stub carries `seq` and `stub`, no `proof`",
    },
    Allowed {
        flow: "claim",
        label: "{alice/wallet} GET /v1/{alice}/claims/*",
        fact: "body.current",
        service: NOTHING,
        scripted: "null",
        reason: NULL_CURRENT,
        reference: "Switch wire, Conventions, \"Absent and null\"; Switch wire 7.1, error bodies",
    },
    Allowed {
        flow: "claim",
        label: "{alice/wallet} GET /v1/{alice}/feed",
        fact: "body.items[0].type",
        service: "text stub",
        scripted: "text chain",
        reason: COMPACTED_CLAIM,
        reference: "Switch wire 6.8 \"Tombstones\"; 7.5, the entries of compacted claims",
    },
    Allowed {
        flow: "claim",
        label: "{alice/wallet} GET /v1/{alice}/feed",
        fact: "body.items[0].item*",
        service: NOTHING,
        scripted: "*",
        reason: COMPACTED_CLAIM,
        reference: "Switch wire 7.5: a stub carries `seq` and `stub`, no `item_type` or `item`",
    },
    Allowed {
        flow: "claim",
        label: "{alice/wallet} GET /v1/{alice}/feed",
        fact: "body.items[0].proof*",
        service: NOTHING,
        scripted: "*",
        reason: COMPACTED_CLAIM,
        reference: "Switch wire 7.5: a stub carries `seq` and `stub`, no `proof`",
    },
    Allowed {
        flow: "claim",
        label: "outcome received after done",
        fact: "outcome.events",
        service: "array of 0",
        scripted: "array of 1",
        reason: COMPACTED_CLAIM,
        reference: "Switch wire 6.8 \"Tombstones\"; 7.5",
    },
    Allowed {
        flow: "claim",
        label: "outcome received after done",
        fact: "outcome.events[0]",
        service: NOTHING,
        scripted: "text ClaimChanged WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
        reason: COMPACTED_CLAIM,
        reference: "Switch wire 6.8 \"Tombstones\"; 7.5",
    },
    Allowed {
        flow: "revocation",
        label: "{alice/phone} GET /v1/{alice}/apps/{alice/phone}/keys",
        fact: "body.current",
        service: NOTHING,
        scripted: "null",
        reason: NULL_CURRENT,
        reference: "Switch wire, Conventions, \"Absent and null\"; Switch wire 7.1, error bodies",
    },
    Allowed {
        flow: "revocation",
        label: "{alice/tablet} GET /v1/{alice}/apps/{alice/tablet}/keys",
        fact: "body.current",
        service: NOTHING,
        scripted: "null",
        reason: NULL_CURRENT,
        reference: "Switch wire, Conventions, \"Absent and null\"; Switch wire 7.1, error bodies",
    },
    Allowed {
        flow: "departure",
        label: "{alice} GET /v1/{alice}/apps",
        fact: "body.apps[0].last_seen",
        service: "time 2026-01-01T00:05:06.250Z",
        scripted: "time 2026-01-01T00:04:05.000Z",
        reason: "The phone's `leave` is its latest request past authentication, so the service \
                 shows the leave's time as its `last_seen`. The scripted switch doesn't count \
                 the leave and shows the time of the phone's request before it.",
        reference: "Switch wire 7.4.12, `last_seen`, which the table gives no rule; `FAKES.md` \
                    says the scripted switch means the latest request past authentication",
    },
    // The phone's feed after the wallet's `done`.
    watching(
        PHONE_FEED,
        "body.items[0].type",
        "text stub",
        "text chain",
        SETTLED_UNSEEN,
    ),
    watching(
        PHONE_FEED,
        "body.items[0].item*",
        NOTHING,
        "*",
        SETTLED_UNSEEN,
    ),
    watching(
        PHONE_FEED,
        "body.items[0].proof*",
        NOTHING,
        "*",
        SETTLED_UNSEEN,
    ),
    watching(
        "outcome the phone after the outcome",
        "outcome.events",
        "array of 0",
        "array of 1",
        SETTLED_UNSEEN,
    ),
    watching(
        "outcome the phone after the outcome",
        "outcome.events[0]",
        NOTHING,
        WATCHED,
        SETTLED_UNSEEN,
    ),
    watching(
        "outcome the claim the phone holds after the outcome",
        "outcome.status",
        "text Attempting",
        "text Settled",
        SETTLED_UNSEEN,
    ),
    watching(
        "outcome the claim the phone holds after the outcome",
        "outcome.step",
        "number 1",
        "number 2",
        SETTLED_UNSEEN,
    ),
    watching(
        "outcome the claim the phone holds after the outcome",
        "outcome.tombstone",
        "bool false",
        "bool true",
        SETTLED_UNSEEN,
    ),
    watching(
        "outcome the claim the phone holds after the outcome",
        "outcome.settled_proof",
        "bool false",
        "bool true",
        SETTLED_UNSEEN,
    ),
    watching(
        "outcome the claim the phone holds after reading it",
        "outcome.settled_proof",
        "bool false",
        "bool true",
        SETTLED_UNSEEN,
    ),
    // The wallet's own entries, in the two feed reads it makes after settling the claim.
    watching(
        WALLET_FEED,
        "body.items[0].type",
        "text stub",
        "text chain",
        OWN_ENTRIES_COMPACTED,
    ),
    watching(
        WALLET_FEED,
        "body.items[0].item*",
        NOTHING,
        "*",
        OWN_ENTRIES_COMPACTED,
    ),
    watching(
        WALLET_FEED,
        "body.items[0].proof*",
        NOTHING,
        "*",
        OWN_ENTRIES_COMPACTED,
    ),
    watching(
        WALLET_FEED,
        "body.items[1].type",
        "text stub",
        "text chain",
        OWN_ENTRIES_COMPACTED,
    ),
    watching(
        WALLET_FEED,
        "body.items[1].item*",
        NOTHING,
        "*",
        OWN_ENTRIES_COMPACTED,
    ),
    watching(
        WALLET_FEED,
        "body.items[1].proof*",
        NOTHING,
        "*",
        OWN_ENTRIES_COMPACTED,
    ),
    watching(
        "outcome the wallet at the end",
        "outcome.events",
        "array of 0",
        "array of 2",
        OWN_ENTRIES_COMPACTED,
    ),
    watching(
        "outcome the wallet at the end",
        "outcome.events[*]",
        NOTHING,
        WATCHED,
        OWN_ENTRIES_COMPACTED,
    ),
    Allowed {
        flow: "restore",
        label: "{alice/wallet} GET /v1/{alice}/directory",
        fact: "body.apps_version",
        service: "number 3",
        scripted: ONE_MORE,
        reason: COUNTER_START,
        reference: "Switch wire 7.4.10, `apps_version`",
    },
    Allowed {
        flow: "restore",
        label: "{alice/wallet} GET /v1/{alice}/directory",
        fact: "body.directory_version",
        service: "number 9",
        scripted: ONE_MORE,
        reason: COUNTER_START,
        reference: "Switch wire 7.4.10, `directory_version`",
    },
    Allowed {
        flow: "append retry",
        label: "{bob/shop} GET /v1/{alice}/directory",
        fact: "body.apps_version",
        service: "number 1",
        scripted: ONE_MORE,
        reason: COUNTER_START,
        reference: "Switch wire 7.4.10, `apps_version`",
    },
    Allowed {
        flow: "append retry",
        label: "{bob/shop} GET /v1/{alice}/directory",
        fact: "body.directory_version",
        service: "number 4",
        scripted: ONE_MORE,
        reason: COUNTER_START,
        reference: "Switch wire 7.4.10, `directory_version`",
    },
    Allowed {
        flow: "append retry",
        label: "{bob/shop} POST /v1/{alice}/inbox",
        fact: "request query apps_version",
        service: "text 1",
        scripted: ONE_MORE,
        reason: COUNTER_START,
        reference: "Switch wire 7.4.3, the query's `apps_version`; 7.4.10",
    },
    Allowed {
        flow: "append retry",
        label: "{bob/shop} POST /v1/{alice}/inbox",
        fact: "body.directory_version",
        service: "number 4",
        scripted: ONE_MORE,
        reason: COUNTER_START,
        reference: "Switch wire 7.4.3, the answer's `directory_version`; 7.4.10",
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
