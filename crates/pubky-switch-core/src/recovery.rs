//! The merge of a recovery upload after a provider loss (Switch wire 7.4.14, Switch spec 12.6
//! step 3): how an uploaded `record.put` and uploaded claim entries change what the service
//! holds, and what the `upload` transition lists.
//!
//! An upload is evidence, not authority: it fills in what the service lacks, adds attempts,
//! moves claims toward SETTLED, and keeps what conflicts as divergent. It never supersedes a
//! write made at the service, and nothing in it is refused for its content: an item that
//! doesn't count is left out and counted ([`UploadChanges`]).
//!
//! The functions here are pure. The caller verifies each uploaded operation with its
//! certificate, each transition proof with the lost generation's service key, and judges a
//! removed app's operations ([`removed_app_counts`]); it passes in only what counted.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::claims::{
    Attempt, Basis, Claim, ClaimEntry, ClaimStatus, ClaimView, EntryKind, Outcome, Pin,
};
use crate::enc::b64;
use crate::ops::RecordVersion;
use crate::{Error, Result};

/// The version an uploaded `record.put` is merged at (Switch wire 7.4.14 "Records").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadVersion {
    /// The version, or its lower bound.
    pub version: RecordVersion,
    /// The lost service's transition proof gave it; otherwise it is a lower bound.
    pub exact: bool,
}

impl UploadVersion {
    /// The version the lost service's transition proof gives the write.
    pub fn proved(version: RecordVersion) -> Self {
        Self {
            version,
            exact: true,
        }
    }

    /// The lower bound of a write without a proof: the least version of the operation's own
    /// generation above the one it built on, `expected_version` (Switch wire 7.4.14). `None`
    /// when it built on a later generation than its own, which no service applies.
    pub fn bound(op_generation: u64, built_on: RecordVersion) -> Option<Self> {
        let version = if built_on.generation == op_generation {
            RecordVersion::new(op_generation, built_on.version.checked_add(1)?)
        } else if built_on.generation < op_generation {
            RecordVersion::new(op_generation, 1)
        } else {
            return None;
        };
        Some(Self {
            version,
            exact: false,
        })
    }
}

/// An uploaded `record.put`, as the merge compares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadedRecord {
    /// `doc_hash` of the signed operation.
    pub op_hash: [u8; 32],
    /// The version it built on, its `expected_version`.
    pub built_on: RecordVersion,
    /// Its version: the proof's, or the lower bound.
    pub version: UploadVersion,
}

/// The uploaded version the first write here built on (Switch wire 10.3 `upload_base`), and
/// its operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadBase {
    /// Its version.
    pub version: RecordVersion,
    /// `doc_hash` of its operation.
    pub op_hash: [u8; 32],
}

/// A record as the merge sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeldRecord<'a> {
    /// The service holds no record at the key.
    Lacking,
    /// Its current write came from an upload.
    FromUpload {
        /// `doc_hash` of the signed operation.
        op_hash: [u8; 32],
        /// The version it built on, its operation's `expected_version`.
        built_on: RecordVersion,
        /// Its version.
        version: UploadVersion,
        /// `doc_hash` of each divergent upload kept for the record.
        divergent: &'a [[u8; 32]],
    },
    /// Its current write was made at this service.
    WrittenHere {
        /// What the first write here built on, or `None` when the writes here built on no
        /// upload.
        upload_base: Option<UploadBase>,
        /// `doc_hash` of each divergent upload kept for the record.
        divergent: &'a [[u8; 32]],
    },
}

/// What an uploaded `record.put` does to the record at its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordMerge {
    /// It becomes the record: the service lacked one.
    Fill,
    /// It replaces a record held only from uploads, at a lower version.
    Replace,
    /// The same operation, now with a proof where the record held a lower bound: the
    /// record's version becomes the proof's.
    MakeExact,
    /// It conflicts: kept as a divergent upload, or dropped past the limit (`kept: false`),
    /// and listed in `divergent` either way.
    Divergent {
        /// Whether it is kept.
        kept: bool,
    },
    /// It changes nothing: the same operation again, an older upload, or one no newer than
    /// the version the writes here built on.
    Unchanged,
}

/// Merge `upload` into the record at its key (Switch wire 7.4.14 "Records", Switch spec 12.6
/// step 3), in this order:
///
/// 1. the same operation again, as the record's, as a kept divergent upload, or as the one
///    the writes here built on, changes nothing; with a proof where the record held a lower
///    bound, it makes the record's version the proof's;
/// 2. a record the service lacks is filled in;
/// 3. against a record held only from uploads, another operation at the same version, or one
///    that built on the same version, is divergent; otherwise a strictly newer upload
///    replaces it and an older one changes nothing, a lower bound counting as its value;
/// 4. against a record written here, an upload newer than the uploaded version the writes
///    here built on, or any upload when they built on none, is divergent: writes here are
///    never superseded.
///
/// Past `max_divergent` uploads kept for the record, a new divergent one is dropped and still
/// divergent.
pub fn merge_record(
    held: &HeldRecord<'_>,
    upload: &UploadedRecord,
    max_divergent: usize,
) -> RecordMerge {
    let divergent = |kept: &[[u8; 32]]| RecordMerge::Divergent {
        kept: kept.len() < max_divergent,
    };
    match *held {
        HeldRecord::Lacking => RecordMerge::Fill,
        HeldRecord::FromUpload {
            op_hash,
            built_on,
            version,
            divergent: kept,
        } => {
            if upload.op_hash == op_hash {
                return if upload.version.exact && !version.exact {
                    RecordMerge::MakeExact
                } else {
                    RecordMerge::Unchanged
                };
            }
            if kept.contains(&upload.op_hash) {
                return RecordMerge::Unchanged;
            }
            if upload.version.version == version.version || upload.built_on == built_on {
                divergent(kept)
            } else if upload.version.version > version.version {
                RecordMerge::Replace
            } else {
                RecordMerge::Unchanged
            }
        }
        HeldRecord::WrittenHere {
            upload_base,
            divergent: kept,
        } => {
            if upload_base.is_some_and(|base| base.op_hash == upload.op_hash)
                || kept.contains(&upload.op_hash)
            {
                RecordMerge::Unchanged
            } else if upload_base.is_none_or(|base| upload.version.version > base.version) {
                divergent(kept)
            } else {
                RecordMerge::Unchanged
            }
        }
    }
}

/// Whether an operation of an app the newest `identity.json` lists in `removed` counts in an
/// upload: only when the lost service's transition proof dates it at or before the app's
/// `distrust_from` (Switch wire 7.4.14, Switch spec 10.3). `proof_at` is the proof's service
/// time, `None` without a verified proof.
pub fn removed_app_counts(proof_at: Option<u64>, distrust_from: u64) -> bool {
    proof_at.is_some_and(|at| at <= distrust_from)
}

/// The lost service's transition proof of an uploaded claim entry, verified by the caller:
/// its service time and the claim view it shows after the entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryProof {
    /// The proof's service time, in Unix milliseconds.
    pub at: u64,
    /// The claim view after the entry.
    pub view: ClaimView,
}

/// An uploaded claim entry that counted: its operation verified with a certificate holding
/// `claims.write`, and a removed app's was dated before its `distrust_from`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadedEntry {
    /// The entry.
    pub entry: ClaimEntry,
    /// The App ID that signed it.
    pub writer: [u8; 16],
    /// The lost service's proof of it, when one verified.
    pub proof: Option<EntryProof>,
}

/// What an upload's entries did to one claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimMerge {
    /// The claim after them.
    pub claim: Option<Claim>,
    /// Whether they changed it: its key goes in `claims`.
    pub changed: bool,
    /// Whether they made it divergent, and it still is, or dropped an attempt past the limit:
    /// its key goes in `divergent_claims`.
    pub divergent: bool,
    /// The entries left out by the writer rules, or for an attempt no proof showed: `refused`.
    pub refused: u64,
}

/// Merge an upload's entries for one claim key into the claim the service holds (`None` for
/// none, a tombstone included), at service time `now` (Switch wire 7.4.14 "How a claim
/// merges", Switch spec 12.6 step 3). The entries apply in `expected_step` order, without
/// re-checking their conditions or `expected_step`:
///
/// - an entry without a proof counts only if the live writer rules allow it: `done` with basis
///   `owner`, and `failed`, only from the attempt's owner;
/// - an `attempt` N lacks is added, marked `from_upload`: current on a FREE claim or a new
///   one, beside an open attempt (divergent) or on a SETTLED claim; a tombstone is reopened
///   first. Past `max_attempts` it is dropped, and the claim listed as divergent, and made
///   so while an attempt on it is unresolved;
/// - an outcome for an attempt N doesn't hold first adds the attempt from its proof's view,
///   and without one is refused;
/// - `done` settles; `failed` and `unknown` apply to an open attempt, and on one with another
///   outcome make the claim divergent instead.
///
/// A claim the upload changed is `rebuilt`, its `step` one more, its last entry at `now`, and
/// compacted once finished.
pub fn merge_claim(
    held: Option<&Claim>,
    entries: &[UploadedEntry],
    now: u64,
    max_attempts: u64,
) -> ClaimMerge {
    let mut ordered: Vec<&UploadedEntry> = entries.iter().collect();
    ordered.sort_by_key(|e| e.entry.expected_step);
    let mut claim = held.cloned();
    let mut refused = 0;
    let mut made_divergent = false;
    let mut dropped = false;
    for uploaded in ordered {
        match apply_uploaded(&mut claim, uploaded, now, max_attempts) {
            Applied::Refused => refused += 1,
            Applied::Divergent => made_divergent = true,
            Applied::Dropped => dropped = true,
            Applied::Merged => {}
        }
    }
    // A claim N held nothing for gets one only from what the upload added.
    if held.is_none() && claim.as_ref().is_some_and(|c| c.attempts.is_empty()) {
        claim = None;
    }
    let changed = claim.as_ref() != held;
    if changed && let Some(c) = claim.as_mut() {
        c.settle_divergence();
        c.rebuilt = true;
        c.step = c.step.saturating_add(1);
        c.last_entry = Some(now);
        if c.creator.is_none() {
            c.creator = c.attempts.first().map(|a| a.owner);
        }
        if c.is_finished() {
            c.tombstone = true;
            c.current = None;
        }
    }
    // Listed when the upload made the claim divergent, or found it not so and left it so.
    let divergent = dropped
        || (claim.as_ref().is_some_and(|c| c.divergent)
            && (made_divergent || !held.is_some_and(|h| h.divergent)));
    ClaimMerge {
        claim,
        changed,
        divergent,
        refused,
    }
}

/// What one uploaded entry did.
enum Applied {
    Merged,
    Divergent,
    Refused,
    /// Past the attempt limit.
    Dropped,
}

fn apply_uploaded(
    claim: &mut Option<Claim>,
    uploaded: &UploadedEntry,
    now: u64,
    max_attempts: u64,
) -> Applied {
    let entry = &uploaded.entry;
    let id = entry.attempt_id;
    // A proof counts only for its own claim: one whose view is of another claim key binds
    // nothing here, and the entry is judged as one without a proof (Switch wire 7.4.14
    // "Members by stage").
    let proof = uploaded
        .proof
        .as_ref()
        .filter(|proof| proof.view.claim_key == entry.claim_key);
    if let EntryKind::Attempt {
        orphan_after,
        deadline,
    } = entry.kind
    {
        if claim
            .as_ref()
            .is_some_and(|c| c.attempts.iter().any(|a| a.attempt_id == id))
        {
            return Applied::Merged;
        }
        let opened_at = proof.map_or(now, |p| p.at);
        let attempt = |c: &Claim| Attempt {
            attempt_id: id,
            owner: uploaded.writer,
            outcome: Outcome::Open,
            opened_at,
            orphan_after,
            possibly_duplicate: c.next_possibly_duplicate(),
            duplicate: false,
            resolved_by: None,
            from_upload: true,
        };
        return add_attempt(claim, attempt, Pin::of(deadline), max_attempts);
    }
    // An outcome: for an attempt N doesn't hold, the attempt its proof's view shows is added
    // first; without one, neither its owner nor its members are known.
    let held = |claim: &Option<Claim>| {
        claim
            .as_ref()
            .is_some_and(|c| c.attempts.iter().any(|a| a.attempt_id == id))
    };
    if !held(claim) {
        let Some(proof) = proof else {
            return Applied::Refused;
        };
        let Some(shown) = proof.view.attempt(&id) else {
            return Applied::Refused;
        };
        let attempt = |_: &Claim| Attempt {
            attempt_id: id,
            owner: shown.owner,
            outcome: Outcome::Open,
            opened_at: shown.opened_at,
            orphan_after: shown.orphan_after,
            possibly_duplicate: shown.possibly_duplicate,
            duplicate: false,
            resolved_by: None,
            from_upload: true,
        };
        let added = add_attempt(claim, attempt, Pin::of(proof.view.deadline), max_attempts);
        if !held(claim) {
            // Past the attempt limit: nothing to apply the outcome to.
            return added;
        }
    }
    let Some(c) = claim.as_mut() else {
        return Applied::Refused;
    };
    let Some(i) = c.attempts.iter().position(|a| a.attempt_id == id) else {
        return Applied::Refused;
    };
    let owners_only = matches!(
        entry.kind,
        EntryKind::Done {
            basis: Basis::Owner,
            ..
        } | EntryKind::Failed
    );
    if proof.is_none() && owners_only && uploaded.writer != c.attempts[i].owner {
        return Applied::Refused;
    }
    let outcome = match entry.kind {
        EntryKind::Done { .. } => Outcome::Done,
        EntryKind::Failed => Outcome::Failed,
        EntryKind::Unknown => Outcome::Unknown,
        EntryKind::Attempt { .. } => return Applied::Merged,
    };
    let was = c.attempts[i].outcome;
    if was == outcome {
        return Applied::Merged;
    }
    if outcome == Outcome::Done {
        // A writer-signed `done` of any basis settles the attempt.
        reopen(c);
        let other_done = c
            .attempts
            .iter()
            .enumerate()
            .any(|(j, a)| j != i && a.outcome == Outcome::Done);
        let a = &mut c.attempts[i];
        a.outcome = Outcome::Done;
        a.duplicate = other_done;
        a.resolved_by = Some(uploaded.writer);
        c.settled = true;
        if c.current == Some(i) {
            c.current = None;
        }
        return Applied::Merged;
    }
    if was != Outcome::Open {
        // Two outcomes for one attempt: divergent instead, which clears as after any entry
        // once no attempt is open or `unknown`, so a claim with none stays as it is.
        if !c.attempts.iter().any(|a| a.outcome.unresolved()) {
            return Applied::Merged;
        }
        reopen(c);
        c.divergent = true;
        return Applied::Divergent;
    }
    let a = &mut c.attempts[i];
    a.outcome = outcome;
    a.resolved_by = Some(uploaded.writer);
    if c.current == Some(i) {
        c.current = None;
    }
    Applied::Merged
}

/// Add an uploaded attempt to the claim, by the claim's state: a new claim with it current,
/// current on a FREE claim, beside an open attempt (divergent) or on a SETTLED claim, after
/// reopening a tombstone; dropped past `max_attempts`.
fn add_attempt(
    claim: &mut Option<Claim>,
    attempt: impl Fn(&Claim) -> Attempt,
    pin: Pin,
    max_attempts: u64,
) -> Applied {
    let c = claim.get_or_insert_with(Claim::default);
    if u64::try_from(c.attempts.len()).unwrap_or(u64::MAX) >= max_attempts {
        // N lacks evidence of an attempt, so the obligation is doubtful while an attempt on
        // it is unresolved. With none, the claim takes no further attempt here anyway: the
        // attempt limit refuses it (Switch wire 6.8).
        if c.attempts.iter().any(|a| a.outcome.unresolved()) {
            reopen(c);
            c.divergent = true;
        }
        return Applied::Dropped;
    }
    reopen(c);
    let added = attempt(c);
    // On a SETTLED claim an uploaded attempt can't move the obligation away from SETTLED, so
    // it is added beside the others without making it divergent (Switch wire 7.4.14).
    let beside_open = !c.settled && c.attempts.iter().any(|a| a.outcome == Outcome::Open);
    if c.pin == Pin::Unpinned {
        c.pin = pin;
    }
    c.attempts.push(added);
    if beside_open {
        c.divergent = true;
        return Applied::Divergent;
    }
    if c.status() == ClaimStatus::Free {
        c.current = c.attempts.len().checked_sub(1);
    }
    Applied::Merged
}

/// A tombstone that evidence reaches is live again, rebuilt from uploads, with its step and
/// attempts, and stays SETTLED (Switch spec 12.6 step 3).
fn reopen(claim: &mut Claim) {
    claim.tombstone = false;
}

/// The tombstone a SETTLED proof of the lost service rebuilds for an obligation the service
/// holds nothing for (Switch spec 12.6 step 3, Switch wire 7.4.14): its attempts, marked
/// `from_upload`, its deadline, its first attempt's owner as creator and the proof's time
/// `at` as its last entry. `None` unless the view is SETTLED with every attempt `done` or
/// `failed`.
pub fn tombstone_from_proof(view: &ClaimView, at: u64) -> Option<Claim> {
    let finished = view
        .attempts
        .iter()
        .all(|a| matches!(a.outcome, Outcome::Done | Outcome::Failed));
    if view.status != ClaimStatus::Settled || view.attempts.is_empty() || !finished {
        return None;
    }
    let attempts: Vec<Attempt> = view
        .attempts
        .iter()
        .map(|a| Attempt {
            attempt_id: a.attempt_id,
            owner: a.owner,
            outcome: a.outcome,
            opened_at: a.opened_at,
            orphan_after: a.orphan_after,
            possibly_duplicate: a.possibly_duplicate,
            duplicate: a.duplicate,
            resolved_by: a.resolved_by,
            from_upload: true,
        })
        .collect();
    Some(Claim {
        step: view.step,
        creator: attempts.first().map(|a| a.owner),
        attempts,
        current: None,
        settled: true,
        tombstone: true,
        pin: Pin::of(view.deadline),
        divergent: false,
        rebuilt: false,
        last_entry: Some(at),
    })
}

/// What an upload changed, as the `upload` transition and the upload's answer list it (Switch
/// wire 7.4.14 "Answer", 6.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UploadChanges {
    /// The record keys whose state the upload changed.
    pub records: BTreeSet<[u8; 32]>,
    /// The record keys that became divergent, or gained a divergent upload.
    pub divergent: BTreeSet<[u8; 32]>,
    /// The claim keys whose state the upload changed.
    pub claims: BTreeSet<[u8; 32]>,
    /// The claim keys that became divergent.
    pub divergent_claims: BTreeSet<[u8; 32]>,
    /// Uploaded items that count for nothing.
    pub unverified: u64,
    /// Operations of removed apps that no proof dates before their `distrust_from`.
    pub distrusted: u64,
    /// Proofless claim entries the live writer rules refuse.
    pub refused: u64,
    /// The heads that verified.
    pub heads: u64,
    /// Whether `lists` added an entry.
    pub lists: bool,
}

impl UploadChanges {
    /// Note a changed record key; each key is listed once, in key order.
    pub fn record(&mut self, key: [u8; 32]) {
        self.records.insert(key);
    }

    /// Note a record key that became divergent or gained a divergent upload, once.
    pub fn divergent_record(&mut self, key: [u8; 32]) {
        self.divergent.insert(key);
    }

    /// Note what a claim merge did to `key`.
    pub fn claim(&mut self, key: [u8; 32], merge: &ClaimMerge) {
        if merge.changed {
            self.claims.insert(key);
        }
        if merge.divergent {
            self.divergent_claims.insert(key);
        }
        self.refused = self.refused.saturating_add(merge.refused);
    }

    /// The `changes` object (Switch wire 7.4.14).
    pub fn to_value(&self) -> Value {
        let keys = |keys: &BTreeSet<[u8; 32]>| keys.iter().map(|k| b64(k)).collect::<Vec<_>>();
        json!({
            "records": keys(&self.records),
            "divergent": keys(&self.divergent),
            "claims": keys(&self.claims),
            "divergent_claims": keys(&self.divergent_claims),
            "unverified": self.unverified,
            "distrusted": self.distrusted,
            "refused": self.refused,
            "heads": self.heads,
            "lists": self.lists,
        })
    }

    /// Read a `changes` object (Switch wire 7.4.14).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a member missing or of the wrong type.
    pub fn from_value(v: &Value) -> Result<Self> {
        use crate::ops::read::{req, req_int};
        let what = "an upload's changes";
        let keys = |member: &str| -> Result<BTreeSet<[u8; 32]>> {
            let Some(items) = req(v, member, what)?.as_array() else {
                return Err(Error::Invalid(format!(
                    "Switch wire 7.4.14: {member} isn't an array"
                )));
            };
            items
                .iter()
                .map(|k| {
                    k.as_str()
                        .ok_or_else(|| {
                            Error::Invalid(format!("Switch wire 7.4.14: a {member} key isn't text"))
                        })
                        .and_then(crate::enc::unb64_array::<32>)
                })
                .collect()
        };
        let Some(lists) = req(v, "lists", what)?.as_bool() else {
            return Err(Error::Invalid(
                "Switch wire 7.4.14: lists isn't a bool".to_owned(),
            ));
        };
        Ok(Self {
            records: keys("records")?,
            divergent: keys("divergent")?,
            claims: keys("claims")?,
            divergent_claims: keys("divergent_claims")?,
            unverified: req_int(v, "unverified", what)?,
            distrusted: req_int(v, "distrusted", what)?,
            refused: req_int(v, "refused", what)?,
            heads: req_int(v, "heads", what)?,
            lists,
        })
    }
}

#[cfg(test)]
mod tests;
