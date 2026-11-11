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
//
// Versions are seqs (spec 10.3): an operation built on (3, 10) and applied by O at seq 50 is
// proved (3, 50), and its bound is (3, 11).

const OP1: [u8; 32] = [11; 32];
const OP2: [u8; 32] = [22; 32];

fn upload(op_hash: [u8; 32], built_on: RecordVersion, version: UploadVersion) -> UploadedRecord {
    UploadedRecord {
        op_hash,
        built_on,
        version,
    }
}

/// An upload without a proof: its bound.
fn unproved(op_hash: [u8; 32], built_on: RecordVersion) -> UploadedRecord {
    upload(
        op_hash,
        built_on,
        bound(built_on.generation.max(3), built_on),
    )
}

fn held_upload(
    op_hash: [u8; 32],
    built_on: RecordVersion,
    version: UploadVersion,
    divergent: &[[u8; 32]],
) -> HeldRecord<'_> {
    HeldRecord::FromUpload {
        op_hash,
        built_on,
        version,
        divergent,
    }
}

fn written_on(base: Option<(RecordVersion, [u8; 32])>, divergent: &[[u8; 32]]) -> HeldRecord<'_> {
    HeldRecord::WrittenHere {
        upload_base: base.map(|(version, op_hash)| UploadBase { version, op_hash }),
        divergent,
    }
}

const KEPT: RecordMerge = RecordMerge::Divergent { kept: true };

#[test]
fn test_recovery_record_bound_past_the_integer_range_is_none() {
    // A bound past 2^53 - 1 no record view carries (Switch wire 1.1): the operation counts
    // as unverified, never as a record no reader can read.
    let last = crate::json::MAX_INT;
    assert_eq!(UploadVersion::bound(3, v(3, last)), None);
    assert_eq!(
        UploadVersion::bound(3, v(3, last - 1)).map(|b| b.version),
        Some(v(3, last))
    );
}

#[test]
fn test_recovery_record_bound_is_the_least_version_above_its_base() {
    assert_eq!(bound(3, v(3, 9)).version, v(3, 10));
    // Built on an earlier generation's version, or on none.
    assert_eq!(bound(3, v(2, 40)).version, v(3, 1));
    assert_eq!(bound(3, v(0, 0)).version, v(3, 1));
    assert!(!bound(3, v(3, 9)).exact);
    // No service applies a write that built on a later generation than its own, nor one
    // past the last seq.
    assert_eq!(UploadVersion::bound(3, v(4, 1)), None);
    assert_eq!(UploadVersion::bound(3, v(3, u64::MAX)), None);
}

#[test]
fn test_recovery_record_fills_in_a_record_the_service_lacks() {
    let merge = merge_record(&HeldRecord::Lacking, &unproved(OP1, v(3, 1)), 8);
    assert_eq!(merge, RecordMerge::Fill);
}

#[test]
fn test_recovery_record_newer_upload_replaces_an_uploaded_one() {
    let held = held_upload(OP1, v(3, 5), UploadVersion::proved(v(3, 9)), &[]);
    // A bound counts as its value: built on (3, 9), (3, 10) is newer than (3, 9).
    assert_eq!(
        merge_record(&held, &unproved(OP2, v(3, 9)), 8),
        RecordMerge::Replace
    );
    assert_eq!(
        merge_record(
            &held,
            &upload(OP2, v(3, 11), UploadVersion::proved(v(3, 12))),
            8
        ),
        RecordMerge::Replace
    );
}

#[test]
fn test_recovery_record_older_upload_changes_nothing() {
    let held = held_upload(OP1, v(3, 8), UploadVersion::proved(v(3, 9)), &[]);
    assert_eq!(
        merge_record(
            &held,
            &upload(OP2, v(3, 2), UploadVersion::proved(v(3, 4))),
            8
        ),
        RecordMerge::Unchanged
    );
    assert_eq!(
        merge_record(&held, &unproved(OP2, v(3, 1)), 8),
        RecordMerge::Unchanged
    );
}

#[test]
fn test_recovery_record_another_op_at_one_version_is_divergent() {
    let held = held_upload(OP1, v(3, 5), UploadVersion::proved(v(3, 9)), &[]);
    assert_eq!(
        merge_record(
            &held,
            &upload(OP2, v(3, 6), UploadVersion::proved(v(3, 9))),
            8
        ),
        KEPT
    );
    // A bound equal to the held version, with another operation.
    assert_eq!(merge_record(&held, &unproved(OP2, v(3, 8)), 8), KEPT);
}

#[test]
fn test_recovery_record_two_bounds_on_one_base_are_divergent() {
    let held = held_upload(OP1, v(3, 5), bound(3, v(3, 5)), &[]);
    assert_eq!(merge_record(&held, &unproved(OP2, v(3, 5)), 8), KEPT);
}

#[test]
fn test_recovery_record_an_op_on_the_same_base_is_divergent_whatever_its_proof() {
    // Held op1 proved (3, 50), built on (3, 10): op2 on (3, 10) without a proof.
    let exact = held_upload(OP1, v(3, 10), UploadVersion::proved(v(3, 50)), &[]);
    assert_eq!(merge_record(&exact, &unproved(OP2, v(3, 10)), 8), KEPT);
    // The other order: held op2's bound, op1 arriving with its proof.
    let bounded = held_upload(OP2, v(3, 10), bound(3, v(3, 10)), &[]);
    assert_eq!(
        merge_record(
            &bounded,
            &upload(OP1, v(3, 10), UploadVersion::proved(v(3, 50))),
            8
        ),
        KEPT
    );
    // A forked O: op1 at seq 50 and op2 at seq 51, both on (3, 10), each proved.
    assert_eq!(
        merge_record(
            &exact,
            &upload(OP2, v(3, 10), UploadVersion::proved(v(3, 51))),
            8
        ),
        KEPT
    );
}

#[test]
fn test_recovery_record_same_op_with_a_proof_makes_the_version_exact() {
    // Held op1's bound (3, 11); op1 again with its proof (3, 50).
    let held = held_upload(OP1, v(3, 10), bound(3, v(3, 10)), &[]);
    assert_eq!(
        merge_record(
            &held,
            &upload(OP1, v(3, 10), UploadVersion::proved(v(3, 50))),
            8
        ),
        RecordMerge::MakeExact
    );
    // Again without a proof: nothing.
    assert_eq!(
        merge_record(&held, &unproved(OP1, v(3, 10)), 8),
        RecordMerge::Unchanged
    );
    // Held exact: the same op with another proof, even at a later seq, changes nothing.
    let exact = held_upload(OP1, v(3, 10), UploadVersion::proved(v(3, 50)), &[]);
    assert_eq!(
        merge_record(
            &exact,
            &upload(OP1, v(3, 10), UploadVersion::proved(v(3, 60))),
            8
        ),
        RecordMerge::Unchanged
    );
}

#[test]
fn test_recovery_record_a_kept_divergent_upload_again_changes_nothing() {
    // op2 is kept divergent; it comes again with its proof: it never replaces the record.
    let kept = [OP2];
    let held = held_upload(OP1, v(3, 10), bound(3, v(3, 10)), &kept);
    assert_eq!(
        merge_record(
            &held,
            &upload(OP2, v(3, 10), UploadVersion::proved(v(3, 50))),
            8
        ),
        RecordMerge::Unchanged
    );
}

#[test]
fn test_recovery_record_any_upload_conflicts_with_writes_that_built_on_none() {
    let held = written_on(None, &[]);
    assert_eq!(merge_record(&held, &unproved(OP2, v(3, 0)), 8), KEPT);
}

#[test]
fn test_recovery_record_upload_newer_than_the_base_writes_built_on_is_divergent() {
    let held = written_on(Some((v(3, 9), OP1)), &[]);
    assert_eq!(
        merge_record(
            &held,
            &upload(OP2, v(3, 9), UploadVersion::proved(v(3, 10))),
            8
        ),
        KEPT
    );
    // At the base itself, or older: not newer, so nothing.
    assert_eq!(
        merge_record(
            &held,
            &upload(OP2, v(3, 5), UploadVersion::proved(v(3, 9))),
            8
        ),
        RecordMerge::Unchanged
    );
    assert_eq!(
        merge_record(&held, &unproved(OP2, v(3, 6)), 8),
        RecordMerge::Unchanged
    );
}

#[test]
fn test_recovery_record_the_base_op_again_after_a_write_here_changes_nothing() {
    // A write here built on op1's bound (3, 11); op1 itself comes with its proof (3, 50):
    // the operation the writes here built on, again (Switch wire 7.4.14).
    let held = written_on(Some((v(3, 11), OP1)), &[]);
    assert_eq!(
        merge_record(
            &held,
            &upload(OP1, v(3, 10), UploadVersion::proved(v(3, 50))),
            8
        ),
        RecordMerge::Unchanged
    );
}

#[test]
fn test_recovery_record_divergent_uploads_stop_at_the_limit() {
    let kept = [[5; 32], [6; 32]];
    let held = written_on(None, &kept);
    assert_eq!(
        merge_record(&held, &unproved(OP2, v(3, 0)), 2),
        RecordMerge::Divergent { kept: false }
    );
    // One already kept changes nothing.
    assert_eq!(
        merge_record(&held, &unproved([5; 32], v(3, 0)), 2),
        RecordMerge::Unchanged
    );
    // The ninth at the default limit.
    let eight: Vec<[u8; 32]> = (0..8u8).map(|i| [100 + i; 32]).collect();
    let full = written_on(None, &eight);
    assert_eq!(
        merge_record(&full, &unproved(OP2, v(3, 0)), 8),
        RecordMerge::Divergent { kept: false }
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

#[test]
fn test_recovery_claim_attempt_on_a_settled_claim_with_an_open_attempt_isnt_divergent() {
    // SETTLED by A1's evidence with A2 still open: an uploaded attempt can't move it away
    // from SETTLED, so it isn't divergent (Switch wire 7.4.14).
    let held = claim_with(vec![
        attempt_of(1, WALLET, Outcome::Done),
        attempt_of(2, PHONE, Outcome::Open),
    ]);
    let merge = merge_claim(
        Some(&held),
        &[up(entry(9, 2, attempt_kind(Some(NOW + 1))), PHONE)],
        NOW,
        64,
    );
    assert!(!merge.divergent);
    assert!(!merge.claim.unwrap().divergent);
}

#[test]
fn test_recovery_claim_outcome_adding_an_attempt_beside_an_open_one_lists_it_divergent() {
    // An outcome for an attempt N lacks adds it from its proof's view, beside A1 still open:
    // the claim becomes divergent, and its key is listed so.
    let held = claim_with(vec![attempt_of(1, WALLET, Outcome::Open)]);
    let shown = claim_with(vec![attempt_of(9, PHONE, Outcome::Done)]);
    let mut uploaded = up(entry(9, 1, done(Basis::Evidence)), PHONE);
    uploaded.proof = Some(proof_of(&shown, NOW - 50));
    let merge = merge_claim(Some(&held), &[uploaded], NOW, 64);
    assert!(merge.divergent);
    assert!(merge.claim.unwrap().divergent);
}

#[test]
fn test_recovery_claim_a_proof_of_another_claim_counts_as_none() {
    // A proof whose view is of another claim key binds nothing here: the entry is judged as
    // one without a proof, so an outcome for an attempt N lacks is refused.
    let shown = claim_with(vec![attempt_of(9, PHONE, Outcome::Done)]);
    let mut uploaded = up(entry(9, 1, done(Basis::Evidence)), PHONE);
    uploaded.proof = Some(EntryProof {
        at: NOW - 50,
        view: shown.view(&[8; 32], NOW - 50, &|_| true),
    });
    let merge = merge_claim(None, &[uploaded], NOW, 64);
    assert_eq!(merge.refused, 1);
    assert!(merge.claim.is_none());
    // And an attempt it came with opens at the upload's time, not the proof's.
    let mut attempt = up(entry(9, 0, attempt_kind(Some(NOW + 1))), PHONE);
    attempt.proof = Some(EntryProof {
        at: NOW - 500,
        view: shown.view(&[8; 32], NOW - 500, &|_| true),
    });
    let claim = merge_claim(None, &[attempt], NOW, 64).claim.unwrap();
    assert_eq!(claim.attempts[0].opened_at, NOW);
}

#[test]
fn test_recovery_claim_uploaded_attempt_keeps_the_claims_pin() {
    // The deadline the claim's first attempt pinned stays: an upload doesn't re-check
    // conditions, nor re-pin (Switch spec 12.6 step 3).
    let held = claim_with(vec![attempt_of(1, WALLET, Outcome::Failed)]);
    let merge = merge_claim(
        Some(&held),
        &[up(entry(9, 1, attempt_kind(Some(NOW + 99))), PHONE)],
        NOW,
        64,
    );
    assert_eq!(merge.claim.unwrap().pin, Pin::At(NOW + 1));
}

#[test]
fn test_recovery_claim_uploaded_attempt_is_possibly_duplicate_after_a_doubtful_one() {
    // After an attempt whose outcome is unknown, the next attempt is possibly a duplicate
    // (Switch wire 6.8 row 1), an uploaded one too.
    let mut doubtful = claim_with(vec![attempt_of(1, WALLET, Outcome::Unknown)]);
    doubtful.attempts[0].resolved_by = Some(PHONE);
    let merge = merge_claim(
        Some(&doubtful),
        &[up(entry(9, 1, attempt_kind(Some(NOW + 1))), PHONE)],
        NOW,
        64,
    );
    assert!(merge.claim.unwrap().attempts[1].possibly_duplicate);
    // After one its owner failed, it isn't.
    let failed = claim_with(vec![attempt_of(1, WALLET, Outcome::Failed)]);
    let merge = merge_claim(
        Some(&failed),
        &[up(entry(9, 1, attempt_kind(Some(NOW + 1))), PHONE)],
        NOW,
        64,
    );
    assert!(!merge.claim.unwrap().attempts[1].possibly_duplicate);
}

#[test]
fn test_recovery_claim_done_leaves_no_current_attempt() {
    // The current attempt done while another stays open: no attempt is current, as after a
    // live `done` (the export's `current` shows it).
    let mut held = claim_with(vec![
        attempt_of(1, WALLET, Outcome::Open),
        attempt_of(2, PHONE, Outcome::Open),
    ]);
    held.current = Some(0);
    held.divergent = true;
    let merge = merge_claim(
        Some(&held),
        &[up(entry(1, 2, done(Basis::Owner)), WALLET)],
        NOW,
        64,
    );
    let claim = merge.claim.unwrap();
    assert!(claim.settled && !claim.tombstone);
    assert_eq!(claim.current, None);
}

#[test]
fn test_recovery_claims_merge_by_the_order_uploads_come_in() {
    // Two uploads, both orders, on a claim N lacks: each step follows the rules, and the
    // ends differ (accepted: the merge depends on the order uploads arrive).
    let u1 = [
        up(entry(1, 0, attempt_kind(Some(NOW + 1))), WALLET),
        up(entry(1, 1, done(Basis::Owner)), WALLET),
    ];
    let u2 = [up(entry(2, 0, attempt_kind(Some(NOW + 1))), PHONE)];
    let a = merge_claim(None, &u1, NOW, 64).claim;
    let ab = merge_claim(a.as_ref(), &u2, NOW + 1, 64).claim.unwrap();
    let b = merge_claim(None, &u2, NOW, 64).claim;
    let ba = merge_claim(b.as_ref(), &u1, NOW + 1, 64).claim.unwrap();
    assert!(ab.settled && ba.settled);
    assert_eq!((ab.creator, ba.creator), (Some(WALLET), Some(PHONE)));
}

#[test]
fn test_recovery_tombstone_from_a_proof_keeps_its_step_and_isnt_rebuilt() {
    let shown = claim_with(vec![attempt_of(1, WALLET, Outcome::Done)]);
    let tomb = tombstone_from_proof(&shown.view(&KEY, NOW, &|_| true), NOW).unwrap();
    assert!(!tomb.rebuilt);
    assert_eq!(tomb.step, shown.step);
}

// Changes

#[test]
fn test_recovery_changes_list_only_claims_that_changed() {
    let mut changes = UploadChanges::default();
    changes.claim(
        [3; 32],
        &ClaimMerge {
            claim: None,
            changed: false,
            divergent: false,
            refused: 1,
        },
    );
    assert!(changes.claims.is_empty() && changes.divergent_claims.is_empty());
    assert_eq!(changes.refused, 1);
}

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
    assert_eq!(changes.records, BTreeSet::from([[1; 32]]));
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

// The merge's edges: creates again, forks, bases of two generations, proofs of other claims.

const OP3: [u8; 32] = [33; 32];

fn proved(generation: u64, seq: u64) -> UploadVersion {
    UploadVersion::proved(v(generation, seq))
}

#[test]
fn test_recovery_record_kept_divergent_proved_above_the_record_is_unchanged() {
    // A kept divergent operation, now with a proof above the current record, is that
    // operation again: unchanged, also against a record written here.
    let kept = [OP2];
    let held = held_upload(OP1, v(3, 10), bound(3, v(3, 10)), &kept);
    let again = upload(OP2, v(3, 10), proved(3, 90));
    assert_eq!(merge_record(&held, &again, 8), RecordMerge::Unchanged);
    let written = written_on(Some((v(3, 11), OP1)), &kept);
    assert_eq!(merge_record(&written, &again, 8), RecordMerge::Unchanged);
}

#[test]
fn test_recovery_record_two_creates_are_on_one_base() {
    // Two creates at one key both build on {0, 0}: one base, so divergent, even when the
    // record was deleted and created again at the lost service, op1 being op3's history.
    let held = held_upload(OP3, RecordVersion::NONE, proved(3, 12), &[]);
    let first = upload(OP1, RecordVersion::NONE, proved(3, 5));
    assert_eq!(merge_record(&held, &first, 8), KEPT);
}

#[test]
fn test_recovery_record_bases_of_two_generations_are_two() {
    // Bases that differ only by generation aren't one base.
    let held = held_upload(OP1, v(3, 10), proved(3, 50), &[]);
    for version in [proved(2, 11), bound(3, v(2, 10))] {
        let other = upload(OP2, v(2, 10), version);
        assert_eq!(merge_record(&held, &other, 8), RecordMerge::Unchanged);
    }
}

#[test]
fn test_recovery_record_a_fork_of_a_replaced_upload_depends_on_the_order() {
    // Held op3, built on op1's (3, 50): op2, a fork of op1 on (3, 10), is older and not on
    // op3's base, so unchanged. In the other order, op1 then op2 then op3, op2 is kept
    // divergent and op3 still replaces op1.
    let held = held_upload(OP3, v(3, 50), proved(3, 60), &[]);
    let fork = upload(OP2, v(3, 10), bound(3, v(3, 10)));
    assert_eq!(merge_record(&held, &fork, 8), RecordMerge::Unchanged);
    let first = held_upload(OP1, v(3, 10), proved(3, 50), &[]);
    assert_eq!(merge_record(&first, &fork, 8), KEPT);
    let kept = [OP2];
    let then = held_upload(OP1, v(3, 10), proved(3, 50), &kept);
    let last = upload(OP3, v(3, 50), proved(3, 60));
    assert_eq!(merge_record(&then, &last, 8), RecordMerge::Replace);
}

#[test]
fn test_recovery_record_a_linear_history_is_never_divergent() {
    // op1 on (3, 10) at seq 50, op3 on (3, 50) at seq 60, each with or without its proof,
    // in any order.
    let ops = [
        (OP1, v(3, 10), proved(3, 50)),
        (OP1, v(3, 10), bound(3, v(3, 10))),
        (OP3, v(3, 50), proved(3, 60)),
        (OP3, v(3, 50), bound(3, v(3, 50))),
    ];
    for (held_op, held_on, held_version) in ops {
        for (op, on, version) in ops {
            let held = held_upload(held_op, held_on, held_version, &[]);
            let merge = merge_record(&held, &upload(op, on, version), 8);
            assert!(
                !matches!(merge, RecordMerge::Divergent { .. }),
                "{held_op:?}/{held_version:?} vs {op:?}/{version:?}: {merge:?}"
            );
        }
    }
}

#[test]
fn test_recovery_claim_a_foreign_proof_leaves_the_writer_rules() {
    // A proof of another claim key on a held attempt: the writer rules apply as without
    // one, so a `failed` from an app other than the owner is refused; with its own claim's
    // proof it applies.
    let held = claim_with(vec![attempt_of(1, WALLET, Outcome::Open)]);
    let mut failed = up(entry(1, 1, EntryKind::Failed), PHONE);
    failed.proof = Some(EntryProof {
        at: NOW - 50,
        view: held.view(&[8; 32], NOW - 50, &|_| true),
    });
    let merge = merge_claim(Some(&held), &[failed.clone()], NOW, 64);
    assert_eq!((merge.refused, merge.changed), (1, false));
    failed.proof = Some(proof_of(&held, NOW - 50));
    let merge = merge_claim(Some(&held), &[failed], NOW, 64);
    assert_eq!(merge.claim.unwrap().attempts[0].outcome, Outcome::Failed);
}
