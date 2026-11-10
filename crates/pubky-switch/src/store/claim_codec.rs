//! The service's own encoding of a claim's state (Switch wire 6.8) as JSON, for the `claims`
//! table. It isn't a wire format: only this service reads it back, and an export carries the
//! claim's entries, not this encoding (Switch wire 10.3).

use pubky_switch_core::claims::{Attempt, Claim, Outcome, Pin};
use serde::{Deserialize, Serialize};

use super::StoreError;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAttempt {
    attempt_id: [u8; 16],
    owner: [u8; 16],
    outcome: String,
    opened_at: u64,
    orphan_after: u64,
    possibly_duplicate: bool,
    duplicate: bool,
    resolved_by: Option<[u8; 16]>,
    from_upload: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredClaim {
    step: u64,
    attempts: Vec<StoredAttempt>,
    current: Option<usize>,
    settled: bool,
    tombstone: bool,
    /// `null` unpinned, `"none"` pinned to no deadline, else the deadline.
    pin: Option<PinValue>,
    divergent: bool,
    rebuilt: bool,
    creator: Option<[u8; 16]>,
    last_entry: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum PinValue {
    At(u64),
    None(NoDeadline),
}

#[derive(Serialize, Deserialize)]
enum NoDeadline {
    #[serde(rename = "none")]
    None,
}

fn outcome_text(outcome: Outcome) -> &'static str {
    outcome.as_str()
}

fn outcome_of(text: &str) -> Result<Outcome, StoreError> {
    Ok(match text {
        "open" => Outcome::Open,
        "done" => Outcome::Done,
        "failed" => Outcome::Failed,
        "unknown" => Outcome::Unknown,
        _ => return Err(StoreError::Corrupt("a claim attempt's outcome")),
    })
}

/// Encode `claim`.
pub(crate) fn encode(claim: &Claim) -> Result<Vec<u8>, StoreError> {
    let stored = StoredClaim {
        step: claim.step,
        attempts: claim
            .attempts
            .iter()
            .map(|a| StoredAttempt {
                attempt_id: a.attempt_id,
                owner: a.owner,
                outcome: outcome_text(a.outcome).to_string(),
                opened_at: a.opened_at,
                orphan_after: a.orphan_after,
                possibly_duplicate: a.possibly_duplicate,
                duplicate: a.duplicate,
                resolved_by: a.resolved_by,
                from_upload: a.from_upload,
            })
            .collect(),
        current: claim.current,
        settled: claim.settled,
        tombstone: claim.tombstone,
        pin: match claim.pin {
            Pin::Unpinned => None,
            Pin::NoDeadline => Some(PinValue::None(NoDeadline::None)),
            Pin::At(at) => Some(PinValue::At(at)),
        },
        divergent: claim.divergent,
        rebuilt: claim.rebuilt,
        creator: claim.creator,
        last_entry: claim.last_entry,
    };
    serde_json::to_vec(&stored).map_err(|_| StoreError::Corrupt("a claim doesn't encode"))
}

/// Decode a claim [`encode`] wrote.
pub(crate) fn decode(bytes: &[u8]) -> Result<Claim, StoreError> {
    let stored: StoredClaim =
        serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt("a stored claim"))?;
    let attempts = stored
        .attempts
        .into_iter()
        .map(|a| {
            Ok(Attempt {
                attempt_id: a.attempt_id,
                owner: a.owner,
                outcome: outcome_of(&a.outcome)?,
                opened_at: a.opened_at,
                orphan_after: a.orphan_after,
                possibly_duplicate: a.possibly_duplicate,
                duplicate: a.duplicate,
                resolved_by: a.resolved_by,
                from_upload: a.from_upload,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    if stored.current.is_some_and(|i| i >= attempts.len()) {
        return Err(StoreError::Corrupt("a stored claim's current attempt"));
    }
    Ok(Claim {
        step: stored.step,
        attempts,
        current: stored.current,
        settled: stored.settled,
        tombstone: stored.tombstone,
        pin: match stored.pin {
            None => Pin::Unpinned,
            Some(PinValue::None(_)) => Pin::NoDeadline,
            Some(PinValue::At(at)) => Pin::At(at),
        },
        divergent: stored.divergent,
        rebuilt: stored.rebuilt,
        creator: stored.creator,
        last_entry: stored.last_entry,
    })
}

/// The owner of each attempt open or unknown, once per attempt, which the per-app limit on
/// open attempts counts (Switch wire 6.8); none for a tombstone.
pub(crate) fn open_owners(claim: &Claim) -> Vec<Vec<u8>> {
    if claim.tombstone {
        return Vec::new();
    }
    claim
        .attempts
        .iter()
        .filter(|a| a.outcome.unresolved())
        .map(|a| a.owner.to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(outcome: Outcome) -> Attempt {
        Attempt {
            attempt_id: [1; 16],
            owner: [2; 16],
            outcome,
            opened_at: 1_767_225_600_000,
            orphan_after: 3600,
            possibly_duplicate: true,
            duplicate: false,
            resolved_by: Some([3; 16]),
            from_upload: true,
        }
    }

    #[test]
    fn test_claim_codec_round_trip() {
        for pin in [Pin::Unpinned, Pin::NoDeadline, Pin::At(1_767_312_000_001)] {
            let claim = Claim {
                step: 3,
                attempts: vec![attempt(Outcome::Failed), attempt(Outcome::Open)],
                current: Some(1),
                settled: false,
                tombstone: false,
                pin,
                divergent: true,
                rebuilt: true,
                creator: Some([2; 16]),
                last_entry: Some(1_767_225_601_000),
            };
            let decoded = decode(&encode(&claim).expect("encode")).expect("decode");
            assert_eq!(decoded, claim);
            assert_eq!(open_owners(&claim), vec![vec![2; 16]]);
        }
    }

    #[test]
    fn test_claim_codec_refuses_a_bad_current() {
        let claim = Claim {
            current: Some(0),
            ..Claim::default()
        };
        let bytes = encode(&claim).expect("encode");
        assert!(decode(&bytes).is_err());
        assert!(decode(b"{}").is_err());
    }
}
