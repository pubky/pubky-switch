//! Admission (Switch spec 7, wire 7.2) and the judgment of a delivered peer copy (wire
//! 7.4.5), as pure functions over what the account holds.
//!
//! Every refusal reads the same, `403 not_admitted` with one message, whether the sender is
//! denied, unknown, or holds an unknown, expired or used-up invite code, so no answer shows
//! the deny list.

use crate::store::{HeldPeer, PeerFloor};

/// The one message of every admission refusal (Switch spec 7).
pub(crate) const NOT_ADMITTED: &str = "7: sender not admitted";

/// Where the account's lists put a sender identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Standing {
    /// A contact.
    pub(crate) contact: bool,
    /// A conversation entry names it.
    pub(crate) conversation: bool,
    /// On the deny list.
    pub(crate) denied: bool,
}

/// What admits a sender (Switch spec 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admitted {
    /// A contact or conversation entry.
    Listed,
    /// The invite code of this hash, valid now.
    InviteCode([u8; 32]),
    /// Nothing, but the account's policy lets strangers deliver their `identity.json` and
    /// ask to connect: a stranger, or a denied sender answered exactly like one.
    ConnectRequests,
}

/// Admit a sender of `standing`, for a delivery of its `identity.json` or a directory read
/// (Switch spec 7, wire 7.2): the deny list overrides everything, and where connect
/// requests are on a denied sender is answered like a stranger; a removed app counts only
/// an invite code, never a contact or conversation entry; `invite` is the hash of the code
/// it presents, only if that code is live now. `None` is `403 not_admitted`.
pub(crate) fn admit(
    standing: Standing,
    removed: bool,
    invite: Option<[u8; 32]>,
    connect_requests: bool,
) -> Option<Admitted> {
    let stranger = connect_requests.then_some(Admitted::ConnectRequests);
    if standing.denied {
        return stranger;
    }
    if !removed && (standing.contact || standing.conversation) {
        return Some(Admitted::Listed);
    }
    invite.map(Admitted::InviteCode).or(stranger)
}

/// How a delivered copy compares with what the account holds of its identity (Switch wire
/// 7.4.5, 3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Judgment {
    /// The held version with the held body bytes: a no-op.
    Same,
    /// Newer than the held copy or the floor, or the first: kept.
    Keep,
    /// Below the held copy's or the floor's version or generation, or another body at a
    /// floor's version: `409 stale_identity` naming that version.
    Stale {
        /// The held copy's or the floor's version.
        version: u64,
    },
    /// Another body at the held version: equivocation, `409 stale_identity` with the held
    /// copy.
    Equivocation,
}

/// Judge a delivered copy of `version`, `generation` and body hash `body_hash` against the
/// copy `held`, or the floor `floor` a dropped copy left (Switch wire 7.4.5): a delivery at
/// the held version is judged by its body first, whatever its generation.
pub(crate) fn judge(
    held: Option<&HeldPeer>,
    floor: Option<&PeerFloor>,
    version: u64,
    generation: u64,
    body_hash: &[u8; 32],
) -> Judgment {
    if let Some(held) = held {
        if version == held.version {
            return if *body_hash == held.body_hash {
                Judgment::Same
            } else {
                Judgment::Equivocation
            };
        }
        if version < held.version || generation < held.generation {
            return Judgment::Stale {
                version: held.version,
            };
        }
        return Judgment::Keep;
    }
    if let Some(floor) = floor
        && (version < floor.version
            || generation < floor.generation
            || (version == floor.version && *body_hash != floor.body_hash))
    {
        return Judgment::Stale {
            version: floor.version,
        };
    }
    Judgment::Keep
}

#[cfg(test)]
mod tests {
    use pubky_switch_core::sig::SignedDoc;

    use super::*;

    fn listed(contact: bool, conversation: bool, denied: bool) -> Standing {
        Standing {
            contact,
            conversation,
            denied,
        }
    }

    #[test]
    fn test_admission_deny_overrides_and_reads_like_a_stranger() {
        let code = Some([3; 32]);
        // Denied: refused, however listed and whatever code; a stranger where connect
        // requests are on.
        assert_eq!(admit(listed(true, true, true), false, code, false), None);
        assert_eq!(
            admit(listed(true, false, true), false, code, true),
            Some(Admitted::ConnectRequests)
        );
        assert_eq!(
            admit(listed(true, false, false), false, None, false),
            Some(Admitted::Listed)
        );
        assert_eq!(
            admit(listed(false, true, false), false, None, false),
            Some(Admitted::Listed)
        );
        assert_eq!(
            admit(listed(false, false, false), false, code, false),
            Some(Admitted::InviteCode([3; 32]))
        );
        assert_eq!(admit(listed(false, false, false), false, None, false), None);
    }

    #[test]
    fn test_admission_of_a_removed_app_counts_only_a_code() {
        assert_eq!(admit(listed(true, true, false), true, None, false), None);
        assert_eq!(
            admit(listed(true, false, false), true, Some([4; 32]), false),
            Some(Admitted::InviteCode([4; 32]))
        );
        assert_eq!(
            admit(listed(true, false, false), true, None, true),
            Some(Admitted::ConnectRequests)
        );
    }

    fn held(version: u64, generation: u64, body: u8) -> HeldPeer {
        HeldPeer {
            doc: SignedDoc::from_parts(b"{}", &[0; 64]),
            version,
            generation,
            body_hash: [body; 32],
            removed: Vec::new(),
        }
    }

    #[test]
    fn test_peer_judgment_against_the_held_copy() {
        let copy = held(3, 2, 7);
        // The held version: by its body, whatever the generation.
        assert_eq!(judge(Some(&copy), None, 3, 1, &[7; 32]), Judgment::Same);
        assert_eq!(
            judge(Some(&copy), None, 3, 2, &[8; 32]),
            Judgment::Equivocation
        );
        assert_eq!(
            judge(Some(&copy), None, 2, 2, &[8; 32]),
            Judgment::Stale { version: 3 }
        );
        assert_eq!(
            judge(Some(&copy), None, 4, 1, &[8; 32]),
            Judgment::Stale { version: 3 }
        );
        assert_eq!(judge(Some(&copy), None, 4, 2, &[8; 32]), Judgment::Keep);
    }

    #[test]
    fn test_peer_judgment_against_a_floor() {
        let floor = PeerFloor {
            version: 5,
            generation: 2,
            body_hash: [9; 32],
        };
        assert_eq!(
            judge(None, Some(&floor), 4, 2, &[1; 32]),
            Judgment::Stale { version: 5 }
        );
        assert_eq!(
            judge(None, Some(&floor), 6, 1, &[1; 32]),
            Judgment::Stale { version: 5 }
        );
        assert_eq!(
            judge(None, Some(&floor), 5, 2, &[1; 32]),
            Judgment::Stale { version: 5 }
        );
        // The floor's own document again, or a newer one: held again.
        assert_eq!(judge(None, Some(&floor), 5, 2, &[9; 32]), Judgment::Keep);
        assert_eq!(judge(None, Some(&floor), 6, 2, &[1; 32]), Judgment::Keep);
        assert_eq!(judge(None, None, 1, 1, &[1; 32]), Judgment::Keep);
    }
}
