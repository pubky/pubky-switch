use super::*;
use crate::claims::Basis;

const NOW: u64 = 1_800_000_000_000;
const KEY: [u8; 32] = [7; 32];
const WALLET: [u8; 16] = [1; 16];
const PHONE: [u8; 16] = [2; 16];

fn v(generation: u64, version: u64) -> RecordVersion {
    RecordVersion::new(generation, version)
}

fn bound(generation: u64, built_on: RecordVersion) -> UploadVersion {
    UploadVersion::bound(generation, built_on).unwrap()
}

// Records

#[test]
fn test_recovery_record_bound_is_the_least_version_above_its_base() {
    assert_eq!(bound(3, v(3, 9)).version, v(3, 10));
    // Built on an earlier generation's version, or on none.
    assert_eq!(bound(3, v(2, 40)).version, v(3, 1));
    assert_eq!(bound(3, v(0, 0)).version, v(3, 1));
    assert!(!bound(3, v(3, 9)).exact);
    // No service applies a write that built on a later generation than its own.
    assert_eq!(UploadVersion::bound(3, v(4, 1)), None);
}

#[test]
fn test_recovery_record_fills_in_a_record_the_service_lacks() {
    let merge = merge_record(&HeldRecord::Lacking, [1; 32], bound(3, v(3, 2)), 8);
    assert_eq!(merge, RecordMerge::Fill);
}

#[test]
fn test_recovery_record_newer_upload_replaces_an_uploaded_one() {
    let held = HeldRecord::FromUpload {
        op_hash: [1; 32],
        version: UploadVersion::proved(v(3, 9)),
        divergent: &[],
    };
    // A bound counts as its value: (3, 10) is newer than (3, 9).
    assert_eq!(
        merge_record(&held, [2; 32], bound(3, v(3, 9)), 8),
        RecordMerge::Replace
    );
    assert_eq!(
        merge_record(&held, [2; 32], UploadVersion::proved(v(3, 12)), 8),
        RecordMerge::Replace
    );
}

#[test]
fn test_recovery_record_older_upload_changes_nothing() {
    let held = HeldRecord::FromUpload {
        op_hash: [1; 32],
        version: UploadVersion::proved(v(3, 9)),
        divergent: &[],
    };
    assert_eq!(
        merge_record(&held, [2; 32], UploadVersion::proved(v(3, 4)), 8),
        RecordMerge::Unchanged
    );
    assert_eq!(
        merge_record(&held, [2; 32], bound(3, v(3, 2)), 8),
        RecordMerge::Unchanged
    );
}

#[test]
fn test_recovery_record_another_op_at_one_version_is_divergent() {
    let held = HeldRecord::FromUpload {
        op_hash: [1; 32],
        version: UploadVersion::proved(v(3, 9)),
        divergent: &[],
    };
    assert_eq!(
        merge_record(&held, [2; 32], UploadVersion::proved(v(3, 9)), 8),
        RecordMerge::Divergent { kept: true }
    );
    // A bound equal to the held version, with another operation.
    assert_eq!(
        merge_record(&held, [2; 32], bound(3, v(3, 8)), 8),
        RecordMerge::Divergent { kept: true }
    );
}

#[test]
fn test_recovery_record_two_bounds_on_one_base_are_divergent() {
    let held = HeldRecord::FromUpload {
        op_hash: [1; 32],
        version: bound(3, v(3, 5)),
        divergent: &[],
    };
    assert_eq!(
        merge_record(&held, [2; 32], bound(3, v(3, 5)), 8),
        RecordMerge::Divergent { kept: true }
    );
}

#[test]
fn test_recovery_record_same_op_with_a_proof_makes_the_version_exact() {
    let held = HeldRecord::FromUpload {
        op_hash: [1; 32],
        version: bound(3, v(3, 5)),
        divergent: &[],
    };
    assert_eq!(
        merge_record(&held, [1; 32], UploadVersion::proved(v(3, 6)), 8),
        RecordMerge::MakeExact
    );
    // Again without a proof, or with one where the version is already exact: nothing.
    assert_eq!(
        merge_record(&held, [1; 32], bound(3, v(3, 5)), 8),
        RecordMerge::Unchanged
    );
    let exact = HeldRecord::FromUpload {
        op_hash: [1; 32],
        version: UploadVersion::proved(v(3, 6)),
        divergent: &[],
    };
    assert_eq!(
        merge_record(&exact, [1; 32], UploadVersion::proved(v(3, 6)), 8),
        RecordMerge::Unchanged
    );
}

#[test]
fn test_recovery_record_any_upload_conflicts_with_writes_that_built_on_none() {
    let held = HeldRecord::WrittenHere {
        upload_base: None,
        divergent: &[],
    };
    assert_eq!(
        merge_record(&held, [2; 32], bound(3, v(3, 1)), 8),
        RecordMerge::Divergent { kept: true }
    );
}

#[test]
fn test_recovery_record_upload_newer_than_the_base_writes_built_on_is_divergent() {
    let held = HeldRecord::WrittenHere {
        upload_base: Some(v(3, 9)),
        divergent: &[],
    };
    assert_eq!(
        merge_record(&held, [2; 32], UploadVersion::proved(v(3, 10)), 8),
        RecordMerge::Divergent { kept: true }
    );
    // At the base itself, or older: not newer, so nothing.
    assert_eq!(
        merge_record(&held, [2; 32], UploadVersion::proved(v(3, 9)), 8),
        RecordMerge::Unchanged
    );
    assert_eq!(
        merge_record(&held, [2; 32], bound(3, v(3, 7)), 8),
        RecordMerge::Unchanged
    );
}

#[test]
fn test_recovery_record_divergent_uploads_stop_at_the_limit() {
    let kept = [[5; 32], [6; 32]];
    let held = HeldRecord::WrittenHere {
        upload_base: None,
        divergent: &kept,
    };
    assert_eq!(
        merge_record(&held, [2; 32], bound(3, v(3, 1)), 2),
        RecordMerge::Divergent { kept: false }
    );
    // One already kept changes nothing.
    assert_eq!(
        merge_record(&held, [5; 32], bound(3, v(3, 1)), 2),
        RecordMerge::Unchanged
    );
}

#[test]
fn test_recovery_removed_app_counts_only_when_dated_at_or_before_distrust() {
    assert!(removed_app_counts(Some(100), 100));
    assert!(removed_app_counts(Some(99), 100));
    assert!(!removed_app_counts(Some(101), 100));
    assert!(!removed_app_counts(None, 100));
}

// Claims

fn entry(attempt: u8, step: u64, kind: EntryKind) -> ClaimEntry {
    ClaimEntry {
        claim_key: KEY,
        attempt_id: [attempt; 16],
        expected_step: step,
        kind,
    }
}

fn attempt_kind(deadline: Option<u64>) -> EntryKind {
    EntryKind::Attempt {
        orphan_after: 86_400,
        deadline,
    }
}

fn done(basis: Basis) -> EntryKind {
    EntryKind::Done {
        basis,
        evidence_ref: None,
    }
}

fn up(entry: ClaimEntry, writer: [u8; 16]) -> UploadedEntry {
    UploadedEntry {
        entry,
        writer,
        proof: None,
    }
}

fn attempt_of(id: u8, owner: [u8; 16], outcome: Outcome) -> Attempt {
    Attempt {
        attempt_id: [id; 16],
        owner,
        outcome,
        opened_at: NOW - 10_000,
        orphan_after: 86_400,
        possibly_duplicate: false,
        duplicate: false,
        resolved_by: (outcome != Outcome::Open).then_some(owner),
        from_upload: false,
    }
}

/// A live claim with `attempts`, current the open one if any, SETTLED when one is done.
fn claim_with(attempts: Vec<Attempt>) -> Claim {
    let current = attempts.iter().position(|a| a.outcome == Outcome::Open);
    let settled = attempts.iter().any(|a| a.outcome == Outcome::Done);
    Claim {
        step: u64::try_from(attempts.len()).unwrap(),
        current: if settled { None } else { current },
        settled,
        pin: Pin::At(NOW + 1),
        creator: attempts.first().map(|a| a.owner),
        last_entry: Some(NOW - 10_000),
        attempts,
        ..Claim::default()
    }
}

fn proof_of(claim: &Claim, at: u64) -> EntryProof {
    EntryProof {
        at,
        view: claim.view(&KEY, at, &|_| true),
    }
}

#[test]
fn test_recovery_claim_attempt_on_no_claim_makes_a_rebuilt_one() {
    let merge = merge_claim(
        None,
        &[up(entry(9, 0, attempt_kind(Some(NOW + 5))), WALLET)],
        NOW,
        64,
    );
    assert!(merge.changed && !merge.divergent);
    let claim = merge.claim.unwrap();
    assert_eq!(claim.current, Some(0));
    let a = &claim.attempts[0];
    assert!(a.from_upload && a.outcome == Outcome::Open && a.owner == WALLET);
    // Without a proof, opened at the upload's time.
    assert_eq!(a.opened_at, NOW);
    assert_eq!(claim.pin, Pin::At(NOW + 5));
    assert_eq!(claim.creator, Some(WALLET));
    assert!(claim.rebuilt);
    assert_eq!((claim.step, claim.last_entry), (1, Some(NOW)));
}

#[test]
fn test_recovery_claim_attempt_with_a_proof_opens_at_the_proofs_time() {
    let mut shown = claim_with(vec![attempt_of(9, WALLET, Outcome::Open)]);
    shown.attempts[0].opened_at = NOW - 500;
    let mut uploaded = up(entry(9, 0, attempt_kind(Some(NOW + 1))), WALLET);
    uploaded.proof = Some(proof_of(&shown, NOW - 500));
    let claim = merge_claim(None, &[uploaded], NOW, 64).claim.unwrap();
    assert_eq!(claim.attempts[0].opened_at, NOW - 500);
}

#[test]
fn test_recovery_claim_attempt_on_a_free_claim_becomes_current() {
    let held = claim_with(vec![attempt_of(1, WALLET, Outcome::Failed)]);
    assert_eq!(held.status(), ClaimStatus::Free);
    let merge = merge_claim(
        Some(&held),
        &[up(entry(9, 0, attempt_kind(Some(NOW + 1))), PHONE)],
        NOW,
        64,
    );
    assert!(!merge.divergent);
    let claim = merge.claim.unwrap();
    assert_eq!(claim.current, Some(1));
    assert!(!claim.divergent);
    assert_eq!(claim.step, held.step + 1);
}

#[test]
fn test_recovery_claim_attempt_beside_an_open_one_is_divergent() {
    let held = claim_with(vec![attempt_of(1, WALLET, Outcome::Open)]);
    let merge = merge_claim(
        Some(&held),
        &[up(entry(9, 0, attempt_kind(Some(NOW + 1))), PHONE)],
        NOW,
        64,
    );
    assert!(merge.divergent);
    let claim = merge.claim.unwrap();
    assert!(claim.divergent);
    // The open attempt stays current; the uploaded one is beside it.
    assert_eq!(claim.current, Some(0));
    assert_eq!(claim.attempts.len(), 2);
}

#[test]
fn test_recovery_claim_attempt_on_a_settled_claim_isnt_divergent() {
    let mut held = claim_with(vec![
        attempt_of(1, WALLET, Outcome::Done),
        attempt_of(2, WALLET, Outcome::Unknown),
    ]);
    held.attempts[1].resolved_by = Some(PHONE);
    let merge = merge_claim(
        Some(&held),
        &[up(entry(9, 0, attempt_kind(Some(NOW + 1))), PHONE)],
        NOW,
        64,
    );
    assert!(merge.changed && !merge.divergent);
    let claim = merge.claim.unwrap();
    assert!(!claim.divergent && claim.settled && claim.current.is_none());
    assert_eq!(claim.attempts.len(), 3);
}

#[test]
fn test_recovery_claim_evidence_reopens_a_tombstone() {
    let mut held = claim_with(vec![attempt_of(1, WALLET, Outcome::Done)]);
    held.tombstone = true;
    let merge = merge_claim(
        Some(&held),
        &[up(entry(9, 0, attempt_kind(Some(NOW + 1))), PHONE)],
        NOW,
        64,
    );
    let claim = merge.claim.unwrap();
    // Live again, SETTLED, with the tombstone's attempts and step.
    assert!(!claim.tombstone && claim.settled && claim.rebuilt);
    assert_eq!(claim.attempts[0], held.attempts[0]);
    assert_eq!(claim.step, held.step + 1);
}

#[test]
fn test_recovery_claim_attempt_already_held_changes_nothing() {
    let held = claim_with(vec![attempt_of(1, WALLET, Outcome::Open)]);
    let merge = merge_claim(
        Some(&held),
        &[up(entry(1, 0, attempt_kind(Some(NOW + 1))), WALLET)],
        NOW,
        64,
    );
    assert!(!merge.changed);
    assert_eq!(merge.claim.as_ref(), Some(&held));
}

#[test]
fn test_recovery_claim_attempt_past_the_limit_is_dropped_and_divergent() {
    let held = claim_with(vec![
        attempt_of(1, WALLET, Outcome::Failed),
        attempt_of(2, WALLET, Outcome::Failed),
    ]);
    let merge = merge_claim(
        Some(&held),
        &[up(entry(9, 0, attempt_kind(Some(NOW + 1))), PHONE)],
        NOW,
        2,
    );
    // Listed as divergent; with every attempt final the claim takes no further attempt at N
    // anyway, so it isn't made so.
    assert!(merge.divergent && !merge.changed);
    let claim = merge.claim.unwrap();
    assert_eq!(claim.attempts.len(), 2);
    assert!(!claim.divergent);
    // With an attempt still open, it is.
    let held = claim_with(vec![
        attempt_of(1, WALLET, Outcome::Failed),
        attempt_of(2, WALLET, Outcome::Open),
    ]);
    let merge = merge_claim(
        Some(&held),
        &[up(entry(9, 0, attempt_kind(Some(NOW + 1))), PHONE)],
        NOW,
        2,
    );
    assert!(merge.divergent && merge.claim.unwrap().divergent);
}

#[test]
fn test_recovery_claim_entries_apply_in_expected_step_order() {
    // The outcome comes first in the upload, but its step is after the attempt's.
    let merge = merge_claim(
        None,
        &[
            up(entry(9, 1, EntryKind::Failed), WALLET),
            up(entry(9, 0, attempt_kind(Some(NOW + 1))), WALLET),
        ],
        NOW,
        64,
    );
    assert_eq!(merge.refused, 0);
    let claim = merge.claim.unwrap();
    assert_eq!(claim.attempts[0].outcome, Outcome::Failed);
}

#[test]
fn test_recovery_claim_outcome_for_an_unseen_attempt_needs_its_proof() {
    let without = merge_claim(
        None,
        &[up(entry(9, 1, done(Basis::Owner)), WALLET)],
        NOW,
        64,
    );
    assert_eq!(without.refused, 1);
    assert!(without.claim.is_none() && !without.changed);
    // With a proof whose view shows the attempt, it is added from the view and settled.
    let shown = claim_with(vec![attempt_of(9, WALLET, Outcome::Done)]);
    let mut uploaded = up(entry(9, 1, done(Basis::Owner)), WALLET);
    uploaded.proof = Some(proof_of(&shown, NOW - 50));
    let with = merge_claim(None, &[uploaded], NOW, 64);
    assert_eq!(with.refused, 0);
    let claim = with.claim.unwrap();
    let a = &claim.attempts[0];
    assert!(a.from_upload && a.outcome == Outcome::Done && a.owner == WALLET);
    assert_eq!(a.opened_at, shown.attempts[0].opened_at);
    assert!(claim.settled);
}

#[test]
fn test_recovery_claim_proofless_owner_outcomes_need_the_owner() {
    let held = claim_with(vec![attempt_of(1, WALLET, Outcome::Open)]);
    for kind in [done(Basis::Owner), EntryKind::Failed] {
        let merge = merge_claim(Some(&held), &[up(entry(1, 1, kind), PHONE)], NOW, 64);
        assert_eq!(merge.refused, 1, "{kind:?}");
        assert!(!merge.changed);
    }
    // With the lost service's proof, the writer rules don't apply.
    let mut proved = up(entry(1, 1, EntryKind::Failed), PHONE);
    proved.proof = Some(proof_of(&held, NOW - 50));
    let merge = merge_claim(Some(&held), &[proved], NOW, 64);
    assert_eq!(merge.claim.unwrap().attempts[0].outcome, Outcome::Failed);
    // Other outcomes need no owner.
    let merge = merge_claim(
        Some(&held),
        &[up(entry(1, 1, done(Basis::Evidence)), PHONE)],
        NOW,
        64,
    );
    assert_eq!(merge.refused, 0);
    assert!(merge.claim.unwrap().settled);
}

#[test]
fn test_recovery_claim_done_settles_and_flags_a_duplicate() {
    let held = claim_with(vec![
        attempt_of(1, WALLET, Outcome::Done),
        attempt_of(2, PHONE, Outcome::Open),
    ]);
    let merge = merge_claim(
        Some(&held),
        &[up(entry(2, 2, done(Basis::Owner)), PHONE)],
        NOW,
        64,
    );
    let claim = merge.claim.unwrap();
    let a = &claim.attempts[1];
    assert!(a.outcome == Outcome::Done && a.duplicate && a.resolved_by == Some(PHONE));
    // Finished, so compacted.
    assert!(claim.tombstone && claim.current.is_none());
}

#[test]
fn test_recovery_claim_done_settles_a_failed_attempt() {
    let held = claim_with(vec![attempt_of(1, WALLET, Outcome::Failed)]);
    let merge = merge_claim(
        Some(&held),
        &[up(entry(1, 1, done(Basis::Owner)), WALLET)],
        NOW,
        64,
    );
    let claim = merge.claim.unwrap();
    assert!(claim.settled && claim.attempts[0].outcome == Outcome::Done);
    assert!(!claim.attempts[0].duplicate);
}

#[test]
fn test_recovery_claim_failed_or_unknown_applies_to_an_open_attempt() {
    let held = claim_with(vec![attempt_of(1, WALLET, Outcome::Open)]);
    let failed = merge_claim(
        Some(&held),
        &[up(entry(1, 1, EntryKind::Failed), WALLET)],
        NOW,
        64,
    );
    let claim = failed.claim.unwrap();
    assert_eq!(claim.attempts[0].outcome, Outcome::Failed);
    assert!(claim.current.is_none());
    let unknown = merge_claim(
        Some(&held),
        &[up(entry(1, 1, EntryKind::Unknown), PHONE)],
        NOW,
        64,
    );
    let claim = unknown.claim.unwrap();
    assert_eq!(claim.attempts[0].outcome, Outcome::Unknown);
    assert_eq!(claim.attempts[0].resolved_by, Some(PHONE));
}

#[test]
fn test_recovery_claim_another_outcome_makes_it_divergent_instead() {
    let mut held = claim_with(vec![attempt_of(1, WALLET, Outcome::Unknown)]);
    held.attempts[0].resolved_by = Some(PHONE);
    let merge = merge_claim(
        Some(&held),
        &[up(entry(1, 1, EntryKind::Failed), WALLET)],
        NOW,
        64,
    );
    assert!(merge.divergent);
    let claim = merge.claim.unwrap();
    // Not applied: the attempt stays unknown, and the claim is divergent.
    assert_eq!(claim.attempts[0].outcome, Outcome::Unknown);
    assert!(claim.divergent);
}

#[test]
fn test_recovery_claim_conflict_on_resolved_attempts_changes_nothing() {
    // Every attempt final: the divergence would clear at once, so nothing changes.
    let held = claim_with(vec![attempt_of(1, WALLET, Outcome::Failed)]);
    let merge = merge_claim(
        Some(&held),
        &[up(entry(1, 1, EntryKind::Unknown), PHONE)],
        NOW,
        64,
    );
    assert!(!merge.changed && !merge.divergent);
    // The same outcome again changes nothing either.
    let merge = merge_claim(
        Some(&held),
        &[up(entry(1, 1, EntryKind::Failed), WALLET)],
        NOW,
        64,
    );
    assert!(!merge.changed);
}

#[test]
fn test_recovery_claim_divergence_clears_once_nothing_is_open() {
    let mut held = claim_with(vec![
        attempt_of(1, WALLET, Outcome::Open),
        attempt_of(2, PHONE, Outcome::Open),
    ]);
    held.divergent = true;
    let merge = merge_claim(
        Some(&held),
        &[
            up(entry(1, 2, EntryKind::Failed), WALLET),
            up(entry(2, 3, EntryKind::Failed), PHONE),
        ],
        NOW,
        64,
    );
    assert!(!merge.divergent);
    assert!(!merge.claim.unwrap().divergent);
}

#[test]
fn test_recovery_tombstone_from_a_settled_proof() {
    let shown = claim_with(vec![
        attempt_of(1, WALLET, Outcome::Failed),
        attempt_of(2, PHONE, Outcome::Done),
    ]);
    let view = shown.view(&KEY, NOW - 50, &|_| true);
    let tomb = tombstone_from_proof(&view, NOW - 50).unwrap();
    assert!(tomb.tombstone && tomb.settled);
    assert!(tomb.attempts.iter().all(|a| a.from_upload));
    assert_eq!(tomb.creator, Some(WALLET));
    assert_eq!(tomb.last_entry, Some(NOW - 50));
    assert_eq!(tomb.pin, Pin::At(NOW + 1));
    assert_eq!(tomb.step, shown.step);
}

#[test]
fn test_recovery_tombstone_needs_every_attempt_final_and_settled() {
    let open = claim_with(vec![
        attempt_of(1, WALLET, Outcome::Done),
        attempt_of(2, PHONE, Outcome::Unknown),
    ]);
    assert_eq!(
        tombstone_from_proof(&open.view(&KEY, NOW, &|_| true), NOW),
        None
    );
    let failed = claim_with(vec![attempt_of(1, WALLET, Outcome::Failed)]);
    assert_eq!(
        tombstone_from_proof(&failed.view(&KEY, NOW, &|_| true), NOW),
        None
    );
}

// Changes

#[test]
fn test_recovery_changes_round_trip() {
    let mut changes = UploadChanges {
        unverified: 2,
        distrusted: 1,
        heads: 1,
        lists: true,
        ..UploadChanges::default()
    };
    changes.record([1; 32]);
    changes.record([1; 32]);
    changes.divergent_record([2; 32]);
    changes.claim(
        [3; 32],
        &ClaimMerge {
            claim: None,
            changed: true,
            divergent: true,
            refused: 2,
        },
    );
    assert_eq!(changes.records, vec![[1; 32]]);
    assert_eq!(changes.refused, 2);
    let value = changes.to_value();
    assert_eq!(value["claims"][0], b64(&[3; 32]));
    assert_eq!(UploadChanges::from_value(&value).unwrap(), changes);
}

#[test]
fn test_recovery_changes_refuse_a_malformed_object() {
    let mut value = UploadChanges::default().to_value();
    value["lists"] = json!(1);
    assert!(UploadChanges::from_value(&value).is_err());
    let mut value = UploadChanges::default().to_value();
    value["records"] = json!(["not base64!"]);
    assert!(UploadChanges::from_value(&value).is_err());
    let mut value = UploadChanges::default().to_value();
    value.as_object_mut().unwrap().remove("heads");
    assert!(UploadChanges::from_value(&value).is_err());
}
