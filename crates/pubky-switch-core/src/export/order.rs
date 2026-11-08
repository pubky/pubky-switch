//! The part order of an export (Switch wire 10.3 "Part order").

use super::part::Part;
use super::{MAX_DIVERGENT_PER_RECORD, bad, reason};
use crate::enc::{b64, pubky_id, zbase32_encode};
use crate::ops::Refusal;

/// A part's place: its group's rank, and its key within the group.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    /// `meta`: exactly one, the first part.
    First,
    /// A `seq`, compared as a number.
    Num(u64),
    /// A key's text as the part writes it, compared as ASCII.
    Text(String),
    /// `connect`: `at`, as an instant, non-decreasing.
    Time(u64),
    /// `divergent`: `key` as text, then `index`.
    Pair(String, u64),
}

/// A child part, which follows its parent's part inside the parent's group: its parent's
/// kind, the key naming the parent, and its own order key.
struct Child {
    parent: &'static str,
    of: String,
    order: u64,
}

/// The groups of Switch wire 10.3 in their order. A `key_bundle` part ranks with `app`, a
/// `claim_entry` part with `claim`.
const GROUPS: [&str; 17] = [
    "meta",
    "chain",
    "entry",
    "app",
    "claim",
    "tombstone",
    "record",
    "batch",
    "contact",
    "conversation",
    "deny",
    "invite_code",
    "connect",
    "flag",
    "peer",
    "peer_floor",
    "divergent",
];

fn rank(kind: &str) -> usize {
    let kind = match kind {
        "key_bundle" => "app",
        "claim_entry" => "claim",
        other => other,
    };
    GROUPS
        .iter()
        .position(|k| *k == kind)
        .unwrap_or(GROUPS.len())
}

fn child(part: &Part) -> Option<Child> {
    match part {
        Part::KeyBundle(p) => Some(Child {
            parent: "app",
            of: zbase32_encode(&p.app_id),
            order: p.first_epoch,
        }),
        Part::ClaimEntry(p) => Some(Child {
            parent: "claim",
            of: b64(&p.claim_key),
            order: p.step,
        }),
        _ => None,
    }
}

fn key(part: &Part) -> std::result::Result<Key, Refusal> {
    Ok(match part {
        Part::Meta(_) => Key::First,
        Part::Chain(p) => Key::Num(p.seq),
        Part::Entry(p) => Key::Num(p.seq),
        Part::App(p) => Key::Text(zbase32_encode(&p.app_id)),
        Part::Claim(p) => Key::Text(b64(&p.claim_key)),
        Part::Tombstone(p) => Key::Text(b64(&p.claim_key)),
        Part::Record(r) => Key::Text(b64(&r.key)),
        Part::Batch(p) => Key::Text(b64(&p.id)),
        Part::Contact(pubky) | Part::Deny(pubky) => Key::Text(pubky_id(pubky)),
        Part::Conversation(p) => Key::Text(pubky_id(&p.pubky)),
        Part::InviteCode(p) => Key::Text(b64(&p.code_hash)),
        Part::Connect(p) => Key::Time(p.at),
        Part::Flag(p) => Key::Text(pubky_id(&p.pubky)),
        Part::Peer(p) => Key::Text(pubky_id(&p.identity().map_err(|e| bad(reason(e)))?)),
        Part::PeerFloor(p) => Key::Text(pubky_id(&p.identity)),
        Part::Divergent(p) => Key::Pair(b64(&p.key), p.index),
        Part::KeyBundle(_) | Part::ClaimEntry(_) => Key::First,
    })
}

/// The part's own key, the parent key a child part names it by.
fn parent_key(part: &Part) -> Option<(&'static str, String)> {
    match part {
        Part::App(p) => Some(("app", zbase32_encode(&p.app_id))),
        Part::Claim(p) => Some(("claim", b64(&p.claim_key))),
        _ => None,
    }
}

/// Check the parts are in the order of Switch wire 10.3: `meta` first and only first, then
/// each kind's group in turn, each group by its key, keys ascending strictly as the part
/// writes them (a `seq` as a number, `connect` non-decreasing by `at` as an instant); an
/// app's `key_bundle` parts right after its `app` part, `first_epoch` strictly ascending; a
/// live claim's `claim_entry` parts right after its `claim` part, `step` strictly
/// ascending; and a record's `divergent` parts one after another, `index` 0, 1, 2 and so on,
/// at most 8.
///
/// # Errors
///
/// `400 bad_request` naming the part out of order.
pub fn check_part_order(parts: &[Part]) -> std::result::Result<(), Refusal> {
    let refuse = |i: usize, kind: &str, why: &str| {
        Err(bad(format!(
            "Switch wire 10.3: part {i} ({kind}) is out of order: {why}"
        )))
    };
    let mut last: Option<(usize, Key)> = None;
    // The parent the child parts that follow may belong to, and its last child's order key.
    let mut parent: Option<(&'static str, String, Option<u64>)> = None;
    for (i, part) in parts.iter().enumerate() {
        let kind = part.kind();
        if let Some(c) = child(part) {
            match &mut parent {
                Some((of, name, prev)) if *of == c.parent && *name == c.of => {
                    if prev.is_some_and(|p| c.order <= p) {
                        return refuse(i, kind, "its order key doesn't ascend strictly");
                    }
                    *prev = Some(c.order);
                }
                _ => return refuse(i, kind, "it doesn't follow its parent's part"),
            }
            continue;
        }
        let r = rank(kind);
        if (r == 0) != (i == 0) {
            return refuse(i, kind, "the first part, and only the first, is meta");
        }
        let k = key(part)?;
        if let Key::Pair(name, index) = &k {
            let previous = match &last {
                Some((lr, Key::Pair(pn, pi))) if *lr == r && pn == name => pi.checked_add(1),
                _ => Some(0),
            };
            if Some(*index) != previous || *index >= MAX_DIVERGENT_PER_RECORD {
                return refuse(
                    i,
                    kind,
                    "a record's divergent parts run 0, 1, 2 in order, at most 8",
                );
            }
        }
        if let Some((lr, lk)) = &last {
            if *lr > r {
                return refuse(i, kind, "it comes after a later group");
            }
            let ascends = match (&k, lk) {
                (Key::Time(t), Key::Time(lt)) => t >= lt,
                _ => k > *lk,
            };
            if *lr == r && !ascends {
                return refuse(i, kind, "its key doesn't ascend in its group");
            }
        }
        parent = parent_key(part).map(|(of, name)| (of, name, None));
        last = Some((r, k));
    }
    Ok(())
}
