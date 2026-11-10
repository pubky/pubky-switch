//! Claims (Switch wire 6.2 `claim`, 6.8; Switch spec 10.2): the claim entry an operation
//! carries, and the claim state machine as pure functions over an explicit claim value.
//!
//! A claim tracks one thing that must happen at most once, named by its claim key, which is
//! opaque to the switch: a protocol's apps derive it from what the obligation names, blinded
//! with the naming key. Its entries (`attempt`, `done`, `failed`, `unknown`) follow the rule
//! table of Switch wire 6.8, which [`apply_entry`] applies to a [`Claim`] the caller holds,
//! returning the claim after the entry or the refusal the service answers.
//!
//! Nothing here reads a clock or storage: the service's time, who is current and the counts
//! the per-app limits compare with come in as arguments. The deletion of tombstones and
//! failed claims ([`Claim::deletable`]) is decided against a time base the caller has only
//! with trusted time (Switch wire 7.3 step 4).

use serde_json::{Value, json};

use crate::enc::{b64, zbase32_encode};
use crate::error::{Error, Result, invalid};
use crate::http::ErrorCode;
use crate::ops::Refusal;
use crate::time::rfc3339;

/// The reconciliation window, 30 days: a tombstone, and a claim whose every attempt failed,
/// are kept until the time base reaches the pinned deadline plus this (Switch wire 6.8).
pub const RECONCILIATION_MS: u64 = 2_592_000_000;

/// `max_claim_age_ms`, 400 days: a finished or failed claim pinned to no deadline is kept
/// until the time base reaches its last entry plus this (Switch wire 6.8, 9.2). An operator
/// may raise it but not lower it.
pub const MAX_CLAIM_AGE_MS: u64 = 34_560_000_000;

/// How far ahead of its device clock an app takes the highest verified service time when it
/// drops evidence: 24 hours (Switch wire 6.8, Switch spec 10.1).
pub const SERVICE_AHEAD_BOUND_MS: u64 = 86_400_000;

/// The `deadline` an `attempt` carries: `d + 1 ms`, `d` being the last instant at which the
/// protocol takes an attempt, truncated to milliseconds (Switch wire 6.2, Switch spec 10.2).
/// Which instant `d` is, is the protocol's; the service refuses the attempt from the deadline
/// itself (Switch wire 6.8), so `d` is the last instant it takes. A `d` at the last time the
/// grammar writes saturates there, meaning "never" (Switch wire 1.1).
pub fn attempt_deadline(last_instant_ms: u64) -> u64 {
    last_instant_ms
        .saturating_add(1)
        .min(crate::time::MAX_TIME_MS)
}

/// A claim entry's type (Switch wire 6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClaimType {
    /// `attempt`: an app starts an attempt.
    Attempt,
    /// `done`: an attempt succeeded.
    Done,
    /// `failed`: an attempt failed.
    Failed,
    /// `unknown`: an orphaned attempt's outcome isn't known.
    Unknown,
}

impl ClaimType {
    /// The type as `type` carries it.
    pub fn as_str(self) -> &'static str {
        match self {
            ClaimType::Attempt => "attempt",
            ClaimType::Done => "done",
            ClaimType::Failed => "failed",
            ClaimType::Unknown => "unknown",
        }
    }

    pub(crate) fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "attempt" => ClaimType::Attempt,
            "done" => ClaimType::Done,
            "failed" => ClaimType::Failed,
            "unknown" => ClaimType::Unknown,
            _ => {
                return invalid(
                    "Switch wire 6.2: claim type isn't attempt, done, failed or unknown",
                );
            }
        })
    }
}

/// The basis of a `done` (Switch wire 6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Basis {
    /// `owner`: the attempt's owner reports it (row 2).
    Owner,
    /// `evidence`: any app, citing the counterparty's confirmation (row 3).
    Evidence,
    /// `reconcile`: any app, for an open, orphaned attempt (row 4).
    Reconcile,
}

impl Basis {
    /// The basis as `basis` carries it.
    pub fn as_str(self) -> &'static str {
        match self {
            Basis::Owner => "owner",
            Basis::Evidence => "evidence",
            Basis::Reconcile => "reconcile",
        }
    }

    pub(crate) fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "owner" => Basis::Owner,
            "evidence" => Basis::Evidence,
            "reconcile" => Basis::Reconcile,
            _ => return invalid("Switch wire 6.2: basis isn't owner, evidence or reconcile"),
        })
    }
}

/// A `claim` operation's members as read, before the shape rules (Switch wire 6.2, 6.8
/// "Malformed"), which come after the caller's permission (Switch wire 6.4 step 9).
///
/// Lengths are kept as read, so that a claim key or attempt ID of the wrong length is a shape
/// refusal. [`ClaimFields::check`] turns these into a [`ClaimEntry`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimFields {
    /// The claim key: 32 bytes.
    pub claim_key: Vec<u8>,
    /// The entry's type.
    pub kind: ClaimType,
    /// The claim's step the writer read: the number of entries so far.
    pub expected_step: u64,
    /// The attempt: 16 bytes.
    pub attempt_id: Vec<u8>,
    /// On `attempt`, required: seconds.
    pub orphan_after: Option<u64>,
    /// On `attempt` only, optional: Unix milliseconds.
    pub deadline: Option<u64>,
    /// On `done`, required.
    pub basis: Option<Basis>,
    /// On `done` only: 32 bytes, required with basis `evidence`.
    pub evidence_ref: Option<Vec<u8>>,
}

impl ClaimFields {
    pub(crate) fn read(v: &Value) -> Result<Self> {
        use crate::ops::read::{opt, opt_int, req_b64, req_int, req_str, text, time};
        let what = "claim";
        let evidence_ref = match opt(v, "evidence_ref") {
            None => None,
            Some(_) => Some(req_b64(v, "evidence_ref", what)?),
        };
        Ok(Self {
            claim_key: req_b64(v, "claim_key", what)?,
            kind: ClaimType::parse(req_str(v, "type", what)?)?,
            expected_step: req_int(v, "expected_step", what)?,
            attempt_id: req_b64(v, "attempt_id", what)?,
            orphan_after: opt_int(v, "orphan_after", what)?,
            deadline: opt(v, "deadline")
                .map(|d| time(d, "deadline", what))
                .transpose()?,
            basis: opt(v, "basis")
                .map(|b| text(b, "basis", what).and_then(Basis::parse))
                .transpose()?,
            evidence_ref,
        })
    }

    pub(crate) fn write(&self, o: &mut crate::ops::body::Obj) {
        o.str("claim_key", &b64(&self.claim_key))
            .str("type", self.kind.as_str())
            .int("expected_step", self.expected_step)
            .str("attempt_id", &b64(&self.attempt_id));
        if let Some(seconds) = self.orphan_after {
            o.int("orphan_after", seconds);
        }
        if let Some(deadline) = self.deadline {
            o.str("deadline", &rfc3339(deadline));
        }
        if let Some(basis) = self.basis {
            o.str("basis", basis.as_str());
        }
        if let Some(evidence) = &self.evidence_ref {
            o.str("evidence_ref", &b64(evidence));
        }
    }

    /// The shape rules of a claim entry (Switch wire 6.2, 6.8 "Malformed"): an `attempt`
    /// carries `orphan_after`; only an `attempt` carries `deadline`; a `done` carries a
    /// basis, and basis `evidence` an `evidence_ref`; only a `done` carries `evidence_ref`; a
    /// claim key of 32 bytes, an attempt ID of 16 and an `evidence_ref` of 32.
    ///
    /// # Errors
    ///
    /// `400 bad_request` naming the rule.
    pub fn check(&self) -> std::result::Result<ClaimEntry, Refusal> {
        let bad = |why: &str| Err(Refusal::bad_request(format!("Switch wire 6.8: {why}")));
        let Ok(claim_key) = <[u8; 32]>::try_from(self.claim_key.as_slice()) else {
            return bad("a claim key isn't 32 bytes");
        };
        let Ok(attempt_id) = <[u8; 16]>::try_from(self.attempt_id.as_slice()) else {
            return bad("an attempt ID isn't 16 bytes");
        };
        if self.kind != ClaimType::Attempt && self.deadline.is_some() {
            return bad("deadline on a type other than attempt");
        }
        if self.kind != ClaimType::Done && self.evidence_ref.is_some() {
            return bad("evidence_ref on a type other than done");
        }
        if self.kind != ClaimType::Attempt && self.orphan_after.is_some() {
            return bad("orphan_after on a type other than attempt");
        }
        if self.kind != ClaimType::Done && self.basis.is_some() {
            return bad("basis on a type other than done");
        }
        let kind = match self.kind {
            ClaimType::Attempt => match self.orphan_after {
                Some(orphan_after) => EntryKind::Attempt {
                    orphan_after,
                    deadline: self.deadline,
                },
                None => return bad("attempt without orphan_after"),
            },
            ClaimType::Done => {
                let evidence_ref = match &self.evidence_ref {
                    None => None,
                    Some(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                        Ok(hash) => Some(hash),
                        Err(_) => return bad("an evidence_ref isn't 32 bytes"),
                    },
                };
                match (self.basis, evidence_ref) {
                    (None, _) => return bad("done without a basis"),
                    (Some(Basis::Evidence), None) => {
                        return bad("basis evidence without evidence_ref");
                    }
                    (Some(basis), evidence_ref) => EntryKind::Done {
                        basis,
                        evidence_ref,
                    },
                }
            }
            ClaimType::Failed => EntryKind::Failed,
            ClaimType::Unknown => EntryKind::Unknown,
        };
        Ok(ClaimEntry {
            claim_key,
            attempt_id,
            expected_step: self.expected_step,
            kind,
        })
    }
}

/// The type of a claim entry, with the members it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// `attempt`.
    Attempt {
        /// Seconds after which the open attempt is orphaned.
        orphan_after: u64,
        /// `d + 1 ms`, `d` the last instant the protocol takes an attempt; `None` for none.
        deadline: Option<u64>,
    },
    /// `done`.
    Done {
        /// Who reports it, and why.
        basis: Basis,
        /// The hash of the evidence, never interpreted by the switch.
        evidence_ref: Option<[u8; 32]>,
    },
    /// `failed`.
    Failed,
    /// `unknown`.
    Unknown,
}

/// A claim entry that passed the shape rules (Switch wire 6.8 "Malformed").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClaimEntry {
    /// The claim key.
    pub claim_key: [u8; 32],
    /// The attempt the entry names.
    pub attempt_id: [u8; 16],
    /// The claim's step the writer read.
    pub expected_step: u64,
    /// The type and its members.
    pub kind: EntryKind,
}

impl ClaimEntry {
    /// The members an operation carries for this entry.
    pub fn fields(&self) -> ClaimFields {
        let mut fields = ClaimFields {
            claim_key: self.claim_key.to_vec(),
            kind: ClaimType::Attempt,
            expected_step: self.expected_step,
            attempt_id: self.attempt_id.to_vec(),
            orphan_after: None,
            deadline: None,
            basis: None,
            evidence_ref: None,
        };
        match self.kind {
            EntryKind::Attempt {
                orphan_after,
                deadline,
            } => {
                fields.orphan_after = Some(orphan_after);
                fields.deadline = deadline;
            }
            EntryKind::Done {
                basis,
                evidence_ref,
            } => {
                fields.kind = ClaimType::Done;
                fields.basis = Some(basis);
                fields.evidence_ref = evidence_ref.map(|e| e.to_vec());
            }
            EntryKind::Failed => fields.kind = ClaimType::Failed,
            EntryKind::Unknown => fields.kind = ClaimType::Unknown,
        }
        fields
    }

    /// The entry's type.
    pub fn claim_type(&self) -> ClaimType {
        match self.kind {
            EntryKind::Attempt { .. } => ClaimType::Attempt,
            EntryKind::Done { .. } => ClaimType::Done,
            EntryKind::Failed => ClaimType::Failed,
            EntryKind::Unknown => ClaimType::Unknown,
        }
    }
}

/// An attempt's outcome (Switch wire 6.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Not reported yet.
    Open,
    /// Done.
    Done,
    /// Failed.
    Failed,
    /// Its outcome isn't known.
    Unknown,
}

impl Outcome {
    /// The outcome as the claim view writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Open => "open",
            Outcome::Done => "done",
            Outcome::Failed => "failed",
            Outcome::Unknown => "unknown",
        }
    }

    pub(crate) fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "open" => Outcome::Open,
            "done" => Outcome::Done,
            "failed" => Outcome::Failed,
            "unknown" => Outcome::Unknown,
            _ => return invalid("Switch wire 6.8: an attempt outcome isn't known"),
        })
    }

    /// Whether the outcome is still to be resolved: `open` or `unknown`.
    pub fn unresolved(self) -> bool {
        matches!(self, Outcome::Open | Outcome::Unknown)
    }
}

/// One attempt at a claim (Switch wire 6.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// The attempt ID, never interpreted by the switch.
    pub attempt_id: [u8; 16],
    /// The app that wrote its `attempt` entry.
    pub owner: [u8; 16],
    /// Its outcome.
    pub outcome: Outcome,
    /// The service time of its `attempt` entry, in Unix milliseconds.
    pub opened_at: u64,
    /// Seconds after `opened_at` from which it is orphaned while open.
    pub orphan_after: u64,
    /// Opened while an earlier attempt made a second one doubtful (row 1).
    pub possibly_duplicate: bool,
    /// Done while another attempt was already done (row 2).
    pub duplicate: bool,
    /// The app that wrote its outcome; `None` while open.
    pub resolved_by: Option<[u8; 16]>,
    /// It came from a recovery upload after a provider loss, so it is orphaned while open
    /// (Switch spec 12.6).
    pub from_upload: bool,
}

impl Attempt {
    /// Whether the attempt is orphaned at `now` (Switch wire 6.8): open, and its owner isn't
    /// current, or `now >= opened_at + orphan_after`, or it came from a recovery upload.
    /// `orphan_after` is at most 2^53 - 1 seconds and the sum saturates, so a large one means
    /// "not yet".
    pub fn orphaned(&self, now: u64, is_current: &dyn Fn(&[u8; 16]) -> bool) -> bool {
        self.outcome == Outcome::Open
            && (!is_current(&self.owner)
                || now
                    >= self
                        .opened_at
                        .saturating_add(self.orphan_after.saturating_mul(1000))
                || self.from_upload)
    }

    /// Whether a later attempt is `possibly_duplicate` because of this one (row 1): it is
    /// `unknown`, or its `failed` or `unknown` was written by an app other than its owner. A
    /// `done` attempt settles the claim, so no attempt follows it.
    fn makes_next_doubtful(&self) -> bool {
        let by_other = self.resolved_by.is_some_and(|by| by != self.owner);
        self.outcome == Outcome::Unknown || (by_other && self.outcome == Outcome::Failed)
    }
}

/// A claim's deadline pin (Switch wire 6.8): none before its first `attempt`, then the
/// deadline that attempt named, "none" included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Pin {
    /// No `attempt` yet.
    Unpinned,
    /// The first `attempt` named no deadline.
    NoDeadline,
    /// The first `attempt` named this deadline, in Unix milliseconds.
    At(u64),
}

impl Pin {
    fn of(deadline: Option<u64>) -> Self {
        deadline.map_or(Pin::NoDeadline, Pin::At)
    }

    /// The pinned deadline, if one is pinned.
    pub fn deadline(self) -> Option<u64> {
        match self {
            Pin::At(d) => Some(d),
            Pin::Unpinned | Pin::NoDeadline => None,
        }
    }
}

/// A claim's state (Switch wire 6.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClaimStatus {
    /// No attempt is current and none is done.
    Free,
    /// An attempt is current.
    Attempting,
    /// An attempt is done.
    Settled,
}

impl ClaimStatus {
    /// The state as the claim view writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            ClaimStatus::Free => "FREE",
            ClaimStatus::Attempting => "ATTEMPTING",
            ClaimStatus::Settled => "SETTLED",
        }
    }
}

/// A claim as the service holds it: live or compacted to a tombstone (Switch wire 6.8).
///
/// Its creator and the time of its last entry are kept for the per-app limits and the
/// deletion of a claim pinned to "none", and an export carries them (Switch wire 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// The number of entries.
    pub step: u64,
    /// Every attempt, oldest first.
    pub attempts: Vec<Attempt>,
    /// The index in `attempts` of the current attempt, while ATTEMPTING.
    pub current: Option<usize>,
    /// An attempt is done.
    pub settled: bool,
    /// Compacted: SETTLED with every attempt `done` or `failed`.
    pub tombstone: bool,
    /// The deadline the first `attempt` pinned.
    pub pin: Pin,
    /// Uploads after a provider loss conflict (Switch spec 12.6).
    pub divergent: bool,
    /// Rebuilt from uploads after a provider loss, so its owner may still record `done` on a
    /// `failed` attempt (row 2).
    pub rebuilt: bool,
    /// The app whose `attempt` created the claim (Switch wire 6.8 "Per app").
    pub creator: Option<[u8; 16]>,
    /// The service time of its last entry, in Unix milliseconds.
    pub last_entry: Option<u64>,
}

impl Default for Claim {
    fn default() -> Self {
        Self {
            step: 0,
            attempts: Vec::new(),
            current: None,
            settled: false,
            tombstone: false,
            pin: Pin::Unpinned,
            divergent: false,
            rebuilt: false,
            creator: None,
            last_entry: None,
        }
    }
}

impl Claim {
    /// The claim's state.
    pub fn status(&self) -> ClaimStatus {
        if self.settled {
            ClaimStatus::Settled
        } else if self.current.is_some() {
            ClaimStatus::Attempting
        } else {
            ClaimStatus::Free
        }
    }

    /// The current attempt, while ATTEMPTING.
    pub fn current_attempt(&self) -> Option<&Attempt> {
        if self.settled {
            return None;
        }
        self.current.and_then(|i| self.attempts.get(i))
    }

    /// Whether the claim is finished: SETTLED with every attempt `done` or `failed`, so it is
    /// compacted to a tombstone at once (Switch wire 6.8 "Tombstones").
    pub fn is_finished(&self) -> bool {
        self.settled
            && self
                .attempts
                .iter()
                .all(|a| matches!(a.outcome, Outcome::Done | Outcome::Failed))
    }

    /// Whether the claim never settled and its every attempt failed (Switch wire 6.8 "Failed
    /// claims").
    pub fn is_failed(&self) -> bool {
        !self.settled
            && !self.attempts.is_empty()
            && self.attempts.iter().all(|a| a.outcome == Outcome::Failed)
    }

    /// Whether the next `attempt` would be flagged `possibly_duplicate` (row 1); always
    /// `false` on a SETTLED claim, since row 7 refuses every later attempt.
    pub fn next_possibly_duplicate(&self) -> bool {
        !self.settled && self.attempts.iter().any(Attempt::makes_next_doubtful)
    }

    /// The first instant at which the service may delete the claim, by the time base (Switch
    /// wire 6.8 "Tombstones", "Failed claims"): for a tombstone or a failed claim, its pinned
    /// deadline plus the reconciliation window, or, pinned to "none", its last entry plus
    /// `max_claim_age_ms`. `None` for any other claim, which age never deletes: one with an
    /// open or `unknown` attempt included.
    pub fn deletable_from(&self, max_claim_age_ms: u64) -> Option<u64> {
        if !(self.tombstone || self.is_failed())
            || self.attempts.iter().any(|a| a.outcome.unresolved())
        {
            return None;
        }
        match self.pin {
            Pin::At(deadline) => Some(deadline.saturating_add(RECONCILIATION_MS)),
            Pin::NoDeadline => self
                .last_entry
                .map(|at| at.saturating_add(max_claim_age_ms)),
            Pin::Unpinned => None,
        }
    }

    /// Whether the service deletes the claim at a request (Switch wire 7.3 step 4): only with
    /// trusted time, so `time_base` is `None` without it, and by the time base, never by the
    /// stamped service time.
    pub fn deletable(&self, time_base: Option<u64>, max_claim_age_ms: u64) -> bool {
        match (time_base, self.deletable_from(max_claim_age_ms)) {
            (Some(now), Some(from)) => now >= from,
            _ => false,
        }
    }

    /// The claim view at `now` (Switch wire 6.8): the `state` of claim proofs, the `claim` of
    /// `GET /claims` and the `current.claim` of conflicts.
    pub fn view(
        &self,
        claim_key: &[u8; 32],
        now: u64,
        is_current: &dyn Fn(&[u8; 16]) -> bool,
    ) -> ClaimView {
        let current = if self.tombstone {
            None
        } else {
            self.current_attempt()
        };
        ClaimView {
            claim_key: *claim_key,
            status: self.status(),
            owner: current.map(|a| a.owner),
            attempt_id: current.map(|a| a.attempt_id),
            step: self.step,
            attempts: self
                .attempts
                .iter()
                .map(|a| AttemptView {
                    attempt_id: a.attempt_id,
                    owner: a.owner,
                    outcome: a.outcome,
                    opened_at: a.opened_at,
                    orphan_after: a.orphan_after,
                    orphaned: a.orphaned(now, is_current),
                    possibly_duplicate: a.possibly_duplicate,
                    duplicate: a.duplicate,
                    resolved_by: a.resolved_by,
                })
                .collect(),
            tombstone: self.tombstone,
            deadline: self.pin.deadline(),
            divergent: self.divergent,
            next_possibly_duplicate: self.next_possibly_duplicate(),
        }
    }

    /// A divergent claim clears once no attempt on it is open or `unknown` (Switch spec
    /// 12.6).
    fn settle_divergence(&mut self) {
        if self.divergent && !self.attempts.iter().any(|a| a.outcome.unresolved()) {
            self.divergent = false;
        }
    }
}

/// One attempt in a claim view (Switch wire 6.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptView {
    /// The attempt ID.
    pub attempt_id: [u8; 16],
    /// Its owner.
    pub owner: [u8; 16],
    /// Its outcome.
    pub outcome: Outcome,
    /// The time of its `attempt` entry.
    pub opened_at: u64,
    /// Seconds.
    pub orphan_after: u64,
    /// Orphaned at the time of the answer.
    pub orphaned: bool,
    /// Row 1's flag.
    pub possibly_duplicate: bool,
    /// Row 2's flag.
    pub duplicate: bool,
    /// The app that wrote its outcome; absent while open.
    pub resolved_by: Option<[u8; 16]>,
}

/// The claim view (Switch wire 6.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimView {
    /// The claim key.
    pub claim_key: [u8; 32],
    /// `FREE`, `ATTEMPTING` or `SETTLED`.
    pub status: ClaimStatus,
    /// While ATTEMPTING: the current attempt's owner.
    pub owner: Option<[u8; 16]>,
    /// While ATTEMPTING: the current attempt.
    pub attempt_id: Option<[u8; 16]>,
    /// The number of entries.
    pub step: u64,
    /// Every attempt, oldest first.
    pub attempts: Vec<AttemptView>,
    /// A compacted finished claim.
    pub tombstone: bool,
    /// The pinned deadline; absent when none was pinned or the pin is "none".
    pub deadline: Option<u64>,
    /// Uploads after a provider loss conflict.
    pub divergent: bool,
    /// The next `attempt` would be flagged `possibly_duplicate`.
    pub next_possibly_duplicate: bool,
}

impl ClaimView {
    /// The view as a JSON value. Its members serialize sorted by name, as the service writes
    /// a proof's `state`.
    pub fn to_value(&self) -> Value {
        let attempts: Vec<Value> = self
            .attempts
            .iter()
            .map(|a| {
                let mut attempt = json!({
                    "attempt_id": b64(&a.attempt_id),
                    "owner": zbase32_encode(&a.owner),
                    "outcome": a.outcome.as_str(),
                    "opened_at": rfc3339(a.opened_at),
                    "orphan_after": a.orphan_after,
                    "orphaned": a.orphaned,
                    "possibly_duplicate": a.possibly_duplicate,
                    "duplicate": a.duplicate,
                });
                if let (Some(by), Some(map)) = (a.resolved_by, attempt.as_object_mut()) {
                    map.insert("resolved_by".into(), zbase32_encode(&by).into());
                }
                attempt
            })
            .collect();
        let mut view = json!({
            "claim_key": b64(&self.claim_key),
            "state": self.status.as_str(),
            "step": self.step,
            "attempts": attempts,
            "tombstone": self.tombstone,
            "divergent": self.divergent,
            "next_possibly_duplicate": self.next_possibly_duplicate,
        });
        if let Some(map) = view.as_object_mut() {
            if let Some(owner) = self.owner {
                map.insert("owner".into(), zbase32_encode(&owner).into());
            }
            if let Some(attempt) = self.attempt_id {
                map.insert("attempt_id".into(), b64(&attempt).into());
            }
            if let Some(deadline) = self.deadline {
                map.insert("deadline".into(), rfc3339(deadline).into());
            }
        }
        view
    }

    /// Read a claim view, as an app reads a proof's `state` or a `GET /claims` answer.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if a member is missing or malformed.
    pub fn from_value(v: &Value) -> Result<Self> {
        use crate::ops::read::{app_id, opt, req, req_app_id, req_b64n, req_int, req_str, time};
        let what = "a claim view";
        let flag = |v: &Value, member: &str| -> Result<bool> {
            match opt(v, member) {
                None => Ok(false),
                Some(b) => b.as_bool().ok_or_else(|| {
                    Error::Invalid(format!("Switch wire 6.8: {member} isn't a bool"))
                }),
            }
        };
        let status = match req_str(v, "state", what)? {
            "FREE" => ClaimStatus::Free,
            "ATTEMPTING" => ClaimStatus::Attempting,
            "SETTLED" => ClaimStatus::Settled,
            _ => return invalid("Switch wire 6.8: a claim state isn't known"),
        };
        let Some(items) = req(v, "attempts", what)?.as_array() else {
            return invalid("Switch wire 6.8: attempts isn't an array");
        };
        let attempts = items
            .iter()
            .map(|a| {
                Ok(AttemptView {
                    attempt_id: req_b64n::<16>(a, "attempt_id", what)?,
                    owner: req_app_id(a, "owner", what)?,
                    outcome: Outcome::parse(req_str(a, "outcome", what)?)?,
                    opened_at: crate::ops::read::req_time(a, "opened_at", what)?,
                    orphan_after: req_int(a, "orphan_after", what)?,
                    orphaned: flag(a, "orphaned")?,
                    possibly_duplicate: flag(a, "possibly_duplicate")?,
                    duplicate: flag(a, "duplicate")?,
                    resolved_by: opt(a, "resolved_by")
                        .map(|r| app_id(r, "resolved_by", what))
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            claim_key: req_b64n::<32>(v, "claim_key", what)?,
            status,
            owner: opt(v, "owner")
                .map(|o| app_id(o, "owner", what))
                .transpose()?,
            attempt_id: opt(v, "attempt_id")
                .map(|_| req_b64n::<16>(v, "attempt_id", what))
                .transpose()?,
            step: req_int(v, "step", what)?,
            attempts,
            tombstone: flag(v, "tombstone")?,
            deadline: opt(v, "deadline")
                .map(|d| time(d, "deadline", what))
                .transpose()?,
            divergent: flag(v, "divergent")?,
            next_possibly_duplicate: flag(v, "next_possibly_duplicate")?,
        })
    }

    /// The view of attempt `attempt_id`.
    pub fn attempt(&self, attempt_id: &[u8; 16]) -> Option<&AttemptView> {
        self.attempts.iter().find(|a| &a.attempt_id == attempt_id)
    }

    /// Whether an app attempts the claim automatically (Switch wire 6.8 "Doubtful claims"):
    /// never with an `unknown` or orphaned attempt, or with `next_possibly_duplicate`.
    pub fn doubtful(&self) -> bool {
        self.next_possibly_duplicate
            || self.divergent
            || self
                .attempts
                .iter()
                .any(|a| a.outcome == Outcome::Unknown || a.orphaned)
    }
}

/// A per-app claim limit, as `current.limit` of `429 quota_exceeded` names it (Switch wire
/// 6.8, 9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClaimLimit {
    /// `claims`: the live claims and tombstones number `max_claims`.
    Claims,
    /// `claim_share`: the claims the app created number its claim share.
    ClaimShare,
    /// `attempts`: the claim holds `max_attempts_per_claim` attempts.
    Attempts,
    /// `open_attempts`: the app owns `open_attempts_per_app` attempts `open` or `unknown`.
    OpenAttempts,
}

impl ClaimLimit {
    /// The limit's name.
    pub fn as_str(self) -> &'static str {
        match self {
            ClaimLimit::Claims => "claims",
            ClaimLimit::ClaimShare => "claim_share",
            ClaimLimit::Attempts => "attempts",
            ClaimLimit::OpenAttempts => "open_attempts",
        }
    }
}

/// The claim limits (Switch wire 6.8 "Per app", 9.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClaimLimits {
    /// Live claims plus tombstones.
    pub max_claims: u64,
    /// Attempts on one claim.
    pub max_attempts_per_claim: u64,
    /// Attempts one app owns `open` or `unknown`, over every live claim.
    pub open_attempts_per_app: u64,
    /// The share of `max_claims` the claims one app created may hold; 100 turns it off.
    pub claim_share_percent: u64,
}

impl Default for ClaimLimits {
    /// The defaults of Switch wire 9.2.
    fn default() -> Self {
        Self {
            max_claims: 1_000_000,
            max_attempts_per_claim: 64,
            open_attempts_per_app: 1_000,
            claim_share_percent: 25,
        }
    }
}

impl ClaimLimits {
    /// The most claims one app may have created: `floor(max_claims * claim_share_percent /
    /// 100)` (Switch wire 6.8).
    pub fn claim_share(&self) -> u64 {
        self.max_claims.saturating_mul(self.claim_share_percent) / 100
    }

    /// The limits of an `attempt`, in the order of Switch wire 6.8 "Per app": on a new claim
    /// (`claim` `None`) `claims`, then `claim_share`; on a live claim `attempts`; then
    /// `open_attempts`. Outcomes are never refused.
    ///
    /// # Errors
    ///
    /// `429 quota_exceeded` with `current.limit`, the first limit the attempt would exceed.
    pub fn check_attempt(
        &self,
        claim: Option<&Claim>,
        tally: &ClaimTally,
    ) -> std::result::Result<(), Refusal> {
        let refuse = |limit: ClaimLimit| {
            Err(Refusal::new(
                ErrorCode::QuotaExceeded,
                format!("Switch wire 6.8: the {} limit is full", limit.as_str()),
            )
            .with_current(json!({ "limit": limit.as_str() })))
        };
        match claim {
            None => {
                if tally.claims >= self.max_claims {
                    return refuse(ClaimLimit::Claims);
                }
                if self.claim_share_percent < 100 && tally.created_by_writer >= self.claim_share() {
                    return refuse(ClaimLimit::ClaimShare);
                }
            }
            Some(claim) => {
                if !claim.tombstone
                    && u64::try_from(claim.attempts.len()).unwrap_or(u64::MAX)
                        >= self.max_attempts_per_claim
                {
                    return refuse(ClaimLimit::Attempts);
                }
            }
        }
        if tally.open_attempts_of_writer >= self.open_attempts_per_app {
            return refuse(ClaimLimit::OpenAttempts);
        }
        Ok(())
    }
}

/// The counts the per-app limits compare with, before an entry (Switch wire 6.8 "Per app").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ClaimTally {
    /// The live claims and tombstones.
    pub claims: u64,
    /// The claims the writer created, live and tombstones.
    pub created_by_writer: u64,
    /// The attempts the writer owns `open` or `unknown`, over every live claim.
    pub open_attempts_of_writer: u64,
}

impl ClaimTally {
    /// Count the claims an account holds, live and tombstones, for `writer`.
    pub fn count<'a>(claims: impl IntoIterator<Item = &'a Claim>, writer: &[u8; 16]) -> Self {
        let mut tally = Self::default();
        for claim in claims {
            tally.claims = tally.claims.saturating_add(1);
            if claim.creator.as_ref() == Some(writer) {
                tally.created_by_writer = tally.created_by_writer.saturating_add(1);
            }
            if !claim.tombstone {
                let open = claim
                    .attempts
                    .iter()
                    .filter(|a| &a.owner == writer && a.outcome.unresolved())
                    .count();
                tally.open_attempts_of_writer = tally
                    .open_attempts_of_writer
                    .saturating_add(u64::try_from(open).unwrap_or(u64::MAX));
            }
        }
        tally
    }
}

/// What a claim entry is applied against: its writer, the service's time and who is current
/// (Switch wire 6.8).
pub struct EntryContext<'a> {
    /// The writing app.
    pub writer: [u8; 16],
    /// The service's time when it applies the batch, in Unix milliseconds.
    pub now: u64,
    /// Whether the writer holds `claims.read`, so that a refusal's `current` shows the claim
    /// (Switch wire 7.6).
    pub can_read: bool,
    /// Whether an app is current: listed with an unexpired certificate, neither revoked nor
    /// departed (Switch spec 3.4, 10.2).
    pub is_current: &'a dyn Fn(&[u8; 16]) -> bool,
    /// The claim limits.
    pub limits: ClaimLimits,
    /// The counts before the entry.
    pub tally: ClaimTally,
}

impl EntryContext<'_> {
    /// `current` of a claim conflict: `{ "claim": view | null }` to a writer with
    /// `claims.read`, else `{}` (Switch wire 7.6).
    fn claim_current(&self, claim_key: &[u8; 32], claim: Option<&Claim>) -> Value {
        if !self.can_read {
            return json!({});
        }
        let view = claim.map_or(Value::Null, |c| {
            c.view(claim_key, self.now, self.is_current).to_value()
        });
        json!({ "claim": view })
    }

    fn conflict(&self, claim_key: &[u8; 32], claim: Option<&Claim>, why: &str) -> Refusal {
        Refusal::conflict(format!("Switch wire 6.8: {why}"))
            .with_current(self.claim_current(claim_key, claim))
    }
}

/// Apply one claim entry to the claim the service holds for its key (`None` when it holds
/// nothing), in the order of Switch wire 6.8: for an `attempt` the claim limits, then the
/// deadline, then `expected_step`, then the row rules. The caller has checked the writer's
/// `claims.write` and the entry's shape before (Switch wire 6.4 step 9).
///
/// Returns the claim after the entry: its step one more, its last entry at `now`, its
/// creator set by its first entry, and compacted to a tombstone once finished.
///
/// # Errors
///
/// `429 quota_exceeded` with `current.limit`; `409 conflict` with `current.claim` (and
/// `current.server_time` for a passed deadline), or `{}` to a writer without `claims.read`.
pub fn apply_entry(
    claim: Option<&Claim>,
    entry: &ClaimEntry,
    cx: &EntryContext<'_>,
) -> std::result::Result<Claim, Refusal> {
    let key = &entry.claim_key;
    if let EntryKind::Attempt { deadline, .. } = entry.kind {
        cx.limits.check_attempt(claim, &cx.tally)?;
        // The deadline comes first, whatever the claim's state: a deleted tombstone leaves
        // the claim FREE, so this is what refuses a re-sent copy.
        if deadline.is_some_and(|d| cx.now >= d) {
            let mut current = cx.claim_current(key, claim);
            if let Some(map) = current.as_object_mut() {
                map.insert("server_time".into(), rfc3339(cx.now).into());
            }
            return Err(
                Refusal::conflict("Switch wire 6.8: the attempt's deadline has passed")
                    .with_current(current),
            );
        }
    }
    let step = claim.map_or(0, |c| c.step);
    if entry.expected_step != step {
        return Err(cx.conflict(key, claim, "a stale expected_step"));
    }
    let mut next = claim.cloned().unwrap_or_default();
    let index = next
        .attempts
        .iter()
        .position(|a| a.attempt_id == entry.attempt_id);
    let applied = match entry.kind {
        EntryKind::Attempt {
            orphan_after,
            deadline,
        } => row_attempt(
            &mut next,
            index,
            cx,
            entry.attempt_id,
            (orphan_after, deadline),
        ),
        EntryKind::Done { basis, .. } => row_done(&mut next, index, cx, basis),
        EntryKind::Failed => row_failed(&mut next, index, cx),
        EntryKind::Unknown => row_unknown(&mut next, index, cx),
    };
    if let Err(why) = applied {
        return Err(cx.conflict(key, claim, why));
    }
    next.settle_divergence();
    next.step = next.step.saturating_add(1);
    next.last_entry = Some(cx.now);
    if next.creator.is_none() {
        next.creator = Some(cx.writer);
    }
    if next.is_finished() {
        next.tombstone = true;
        next.current = None;
    }
    Ok(next)
}

/// Row 1, and row 7 for `attempt`.
fn row_attempt(
    claim: &mut Claim,
    index: Option<usize>,
    cx: &EntryContext<'_>,
    attempt_id: [u8; 16],
    (orphan_after, deadline): (u64, Option<u64>),
) -> std::result::Result<(), &'static str> {
    if claim.settled || claim.tombstone {
        return Err("row 7: the claim is SETTLED");
    }
    if claim.attempts.iter().any(|a| a.outcome == Outcome::Open) {
        return Err("row 1: another attempt is open");
    }
    if index.is_some() {
        return Err("row 1: the attempt_id isn't new for the claim");
    }
    let named = Pin::of(deadline);
    if claim.pin != Pin::Unpinned && claim.pin != named {
        return Err("row 1: the attempt names another deadline than the pinned one");
    }
    let possibly_duplicate = claim.attempts.iter().any(Attempt::makes_next_doubtful);
    claim.attempts.push(Attempt {
        attempt_id,
        owner: cx.writer,
        outcome: Outcome::Open,
        opened_at: cx.now,
        orphan_after,
        possibly_duplicate,
        duplicate: false,
        resolved_by: None,
        from_upload: false,
    });
    claim.pin = named;
    claim.current = claim.attempts.len().checked_sub(1);
    Ok(())
}

/// Rows 2, 3 and 4.
fn row_done(
    claim: &mut Claim,
    index: Option<usize>,
    cx: &EntryContext<'_>,
    basis: Basis,
) -> std::result::Result<(), &'static str> {
    let Some(i) = index else {
        return Err("an entry for an unknown attempt_id");
    };
    let Some(attempt) = claim.attempts.get(i) else {
        return Err("an entry for an unknown attempt_id");
    };
    if attempt.outcome == Outcome::Done {
        return Err("a repeated done for a done attempt");
    }
    let allowed = match basis {
        Basis::Owner => {
            !claim.tombstone
                && attempt.owner == cx.writer
                && (attempt.outcome.unresolved()
                    || (attempt.outcome == Outcome::Failed && claim.rebuilt))
        }
        Basis::Evidence => true,
        Basis::Reconcile => !claim.tombstone && attempt.orphaned(cx.now, cx.is_current),
    };
    if !allowed {
        return Err(match basis {
            Basis::Owner => "row 2: basis owner from another app, or on a resolved attempt",
            Basis::Evidence => "row 3",
            Basis::Reconcile => "row 4: basis reconcile needs an open, orphaned attempt",
        });
    }
    let other_done = claim
        .attempts
        .iter()
        .enumerate()
        .any(|(j, a)| j != i && a.outcome == Outcome::Done);
    if let Some(attempt) = claim.attempts.get_mut(i) {
        attempt.outcome = Outcome::Done;
        attempt.duplicate = other_done;
        attempt.resolved_by = Some(cx.writer);
    }
    claim.settled = true;
    if claim.current == Some(i) {
        claim.current = None;
    }
    Ok(())
}

/// Row 5.
fn row_failed(
    claim: &mut Claim,
    index: Option<usize>,
    cx: &EntryContext<'_>,
) -> std::result::Result<(), &'static str> {
    let Some(i) = index else {
        return Err("an entry for an unknown attempt_id");
    };
    if claim.tombstone {
        return Err("only row 3 applies on a tombstone");
    }
    let Some(attempt) = claim.attempts.get_mut(i) else {
        return Err("an entry for an unknown attempt_id");
    };
    if !attempt.outcome.unresolved() {
        return Err("row 5: the attempt isn't open or unknown");
    }
    if attempt.owner != cx.writer && (cx.is_current)(&attempt.owner) {
        return Err("row 5: failed from another app while the owner is current");
    }
    attempt.outcome = Outcome::Failed;
    attempt.resolved_by = Some(cx.writer);
    if claim.current == Some(i) {
        claim.current = None;
    }
    Ok(())
}

/// Row 6, and row 7 for `unknown`.
fn row_unknown(
    claim: &mut Claim,
    index: Option<usize>,
    cx: &EntryContext<'_>,
) -> std::result::Result<(), &'static str> {
    if claim.settled || claim.tombstone {
        return Err("row 7: the claim is SETTLED");
    }
    let Some(i) = index else {
        return Err("an entry for an unknown attempt_id");
    };
    let Some(attempt) = claim.attempts.get_mut(i) else {
        return Err("an entry for an unknown attempt_id");
    };
    if !attempt.orphaned(cx.now, cx.is_current) {
        return Err("row 6: unknown needs an open, orphaned attempt");
    }
    attempt.outcome = Outcome::Unknown;
    attempt.resolved_by = Some(cx.writer);
    if claim.current == Some(i) {
        claim.current = None;
    }
    Ok(())
}

/// Whether a claim entry's outcome depends on the service's time, so that it is `503
/// unavailable` without trusted time (Switch wire 7.3, Switch spec 10.1): an `attempt`, and an
/// outcome by an app other than the attempt's owner while the owner is current, which only
/// the attempt's orphan age or its owner's certificate expiry allows. `owner_current` judges
/// "current" without certificate expiry: listed or renewed and still open, neither revoked nor
/// departed.
pub fn entry_depends_on_time(
    claim: Option<&Claim>,
    entry: &ClaimEntry,
    writer: &[u8; 16],
    owner_current: &dyn Fn(&[u8; 16]) -> bool,
) -> bool {
    let outcome_by_other = || {
        claim
            .and_then(|c| c.attempts.iter().find(|a| a.attempt_id == entry.attempt_id))
            .is_some_and(|a| &a.owner != writer && !a.from_upload && owner_current(&a.owner))
    };
    match entry.kind {
        EntryKind::Attempt { .. } => true,
        EntryKind::Done {
            basis: Basis::Evidence,
            ..
        } => false,
        EntryKind::Done { .. } | EntryKind::Failed | EntryKind::Unknown => outcome_by_other(),
    }
}

/// Whether an app still keeps its evidence for an obligation, its SETTLED and tombstone
/// proofs (Switch wire 6.8 "Pinned deadline and evidence").
///
/// - `pinned`: the deadline the claim pinned, `None` for a pin to "none";
/// - `own`: the deadline the app computes itself, if any;
/// - `proof_time`: the time the proof's stub carries;
/// - `highest_verified` and `device_now`: the highest service time the app verified and its
///   device clock.
///
/// It keeps the evidence to the later of the bounds that apply: the later of the two
/// deadlines plus the reconciliation window; with a pin to "none", `max_claim_age` after the
/// proof's time, and beside a deadline of its own, the later of that deadline plus 30 days and
/// that. A pinned deadline where it computes none is an early pin, kept for good. It drops the
/// evidence once every bound lies before the earlier of `highest_verified` and `device_now`
/// plus 24 hours: kept at the boundary itself, dropped from the next millisecond.
pub fn evidence_kept(
    pinned: Option<u64>,
    own: Option<u64>,
    proof_time: u64,
    highest_verified: u64,
    device_now: u64,
) -> bool {
    let by_age = proof_time.saturating_add(MAX_CLAIM_AGE_MS);
    let boundary = match (pinned, own) {
        (Some(p), Some(o)) => p.max(o).saturating_add(RECONCILIATION_MS),
        (Some(_), None) => return true,
        (None, Some(o)) => o.saturating_add(RECONCILIATION_MS).max(by_age),
        (None, None) => by_age,
    };
    let reference = highest_verified.min(device_now.saturating_add(SERVICE_AHEAD_BOUND_MS));
    boundary >= reference
}

/// Whether the service may have deleted the claim's tombstone at `service_time`, so that an
/// app holding evidence for it doesn't read its absence as a rollback (Switch wire 6.8): from
/// the pinned deadline plus the reconciliation window, or with a pin to "none" (`pinned`
/// `None`) from the proof's time plus `max_claim_age`, reached at that instant.
pub fn service_may_delete(pinned: Option<u64>, proof_time: u64, service_time: u64) -> bool {
    service_time
        >= match pinned {
            Some(d) => d.saturating_add(RECONCILIATION_MS),
            None => proof_time.saturating_add(MAX_CLAIM_AGE_MS),
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 16] = [0xA; 16];
    const B: [u8; 16] = [0xB; 16];
    const KEY: [u8; 32] = [1; 32];
    const START: u64 = 1_767_225_600_000;

    fn all_current(_: &[u8; 16]) -> bool {
        true
    }

    fn only_b_current(app: &[u8; 16]) -> bool {
        app == &B
    }

    fn cx(writer: [u8; 16], now: u64) -> EntryContext<'static> {
        EntryContext {
            writer,
            now,
            can_read: true,
            is_current: &all_current,
            limits: ClaimLimits::default(),
            tally: ClaimTally::default(),
        }
    }

    fn entry(step: u64, attempt: u8, kind: EntryKind) -> ClaimEntry {
        ClaimEntry {
            claim_key: KEY,
            attempt_id: [attempt; 16],
            expected_step: step,
            kind,
        }
    }

    fn attempt(step: u64, id: u8) -> ClaimEntry {
        entry(
            step,
            id,
            EntryKind::Attempt {
                orphan_after: 60,
                deadline: None,
            },
        )
    }

    fn done(step: u64, id: u8, basis: Basis) -> ClaimEntry {
        entry(
            step,
            id,
            EntryKind::Done {
                basis,
                evidence_ref: Some([3; 32]),
            },
        )
    }

    fn apply(claim: Option<&Claim>, e: &ClaimEntry, cx: &EntryContext<'_>) -> Claim {
        apply_entry(claim, e, cx).unwrap()
    }

    #[test]
    fn test_attempt_deadline_is_one_millisecond_after_the_last_instant() {
        assert_eq!(attempt_deadline(START), START + 1);
        assert_eq!(
            rfc3339(attempt_deadline(START + 999)),
            "2026-01-01T00:00:01.000Z"
        );
        assert_eq!(attempt_deadline(u64::MAX), crate::time::MAX_TIME_MS);
    }

    #[test]
    fn test_claim_row1_attempt_opens_and_a_second_conflicts() {
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        assert_eq!(c.status(), ClaimStatus::Attempting);
        assert_eq!((c.step, c.creator), (1, Some(A)));
        assert_eq!(c.attempts[0].attempt_id, [1; 16]);
        let refused = apply_entry(Some(&c), &attempt(1, 2), &cx(B, START)).unwrap_err();
        assert_eq!(refused.status(), 409);
        let current = refused.current.unwrap();
        assert_eq!(current["claim"]["state"], "ATTEMPTING");
    }

    #[test]
    fn test_claim_stale_expected_step_conflicts() {
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        let refused = apply_entry(Some(&c), &done(0, 1, Basis::Owner), &cx(A, START)).unwrap_err();
        assert_eq!(refused.code, ErrorCode::Conflict);
        let refused = apply_entry(None, &attempt(3, 1), &cx(A, START)).unwrap_err();
        assert_eq!(refused.current.unwrap()["claim"], Value::Null);
    }

    #[test]
    fn test_claim_row2_owner_done_settles_and_compacts() {
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        assert!(apply_entry(Some(&c), &done(1, 1, Basis::Owner), &cx(B, START)).is_err());
        let settled = apply(Some(&c), &done(1, 1, Basis::Owner), &cx(A, START));
        assert!(settled.tombstone && settled.settled);
        assert_eq!(settled.attempts[0].resolved_by, Some(A));
        // A repeated done conflicts; so do attempt and unknown (row 7).
        assert!(apply_entry(Some(&settled), &done(2, 1, Basis::Owner), &cx(A, START)).is_err());
        assert!(apply_entry(Some(&settled), &attempt(2, 2), &cx(B, START)).is_err());
        let unknown = entry(2, 1, EntryKind::Unknown);
        assert!(apply_entry(Some(&settled), &unknown, &cx(B, START)).is_err());
    }

    #[test]
    fn test_claim_row2_owner_done_on_failed_only_when_rebuilt() {
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        let failed = apply(Some(&c), &entry(1, 1, EntryKind::Failed), &cx(A, START));
        assert!(apply_entry(Some(&failed), &done(2, 1, Basis::Owner), &cx(A, START)).is_err());
        let mut rebuilt = failed.clone();
        rebuilt.rebuilt = true;
        let settled = apply(Some(&rebuilt), &done(2, 1, Basis::Owner), &cx(A, START));
        assert!(settled.settled);
    }

    #[test]
    fn test_claim_row3_evidence_on_failed_and_tombstone_flags_duplicate() {
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        let failed = apply(Some(&c), &entry(1, 1, EntryKind::Failed), &cx(A, START));
        assert_eq!(failed.status(), ClaimStatus::Free);
        assert!(failed.is_failed());
        let second = apply(Some(&failed), &attempt(2, 2), &cx(B, START));
        let tomb = apply(Some(&second), &done(3, 2, Basis::Owner), &cx(B, START));
        assert!(tomb.tombstone);
        let late = apply(Some(&tomb), &done(4, 1, Basis::Evidence), &cx(A, START));
        assert!(late.attempts[0].duplicate && late.tombstone);
        assert_eq!(late.step, 5);
        // Any other entry on a tombstone conflicts.
        assert!(apply_entry(Some(&late), &entry(5, 2, EntryKind::Failed), &cx(B, START)).is_err());
    }

    #[test]
    fn test_claim_row4_reconcile_needs_an_orphaned_attempt() {
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        assert!(apply_entry(Some(&c), &done(1, 1, Basis::Reconcile), &cx(B, START)).is_err());
        let late = START + 60_000;
        let settled = apply(Some(&c), &done(1, 1, Basis::Reconcile), &cx(B, late));
        assert_eq!(settled.attempts[0].resolved_by, Some(B));
        // An owner that isn't current orphans its attempt at once.
        let mut other = cx(B, START);
        other.is_current = &only_b_current;
        assert!(apply_entry(Some(&c), &done(1, 1, Basis::Reconcile), &other).is_ok());
    }

    #[test]
    fn test_claim_row5_failed_by_owner_or_once_owner_isnt_current() {
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        assert!(apply_entry(Some(&c), &entry(1, 1, EntryKind::Failed), &cx(B, START)).is_err());
        let mut other = cx(B, START);
        other.is_current = &only_b_current;
        let failed = apply(Some(&c), &entry(1, 1, EntryKind::Failed), &other);
        assert_eq!(failed.attempts[0].outcome, Outcome::Failed);
        // The next attempt is possibly a duplicate: another app wrote the failure.
        assert!(failed.next_possibly_duplicate());
        let next = apply(Some(&failed), &attempt(2, 2), &cx(B, START));
        assert!(next.attempts[1].possibly_duplicate);
        // failed again on a failed attempt conflicts.
        assert!(
            apply_entry(
                Some(&failed),
                &entry(2, 1, EntryKind::Failed),
                &cx(A, START)
            )
            .is_err()
        );
    }

    #[test]
    fn test_claim_row6_unknown_needs_orphaned_and_frees() {
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        let unknown = entry(1, 1, EntryKind::Unknown);
        assert!(apply_entry(Some(&c), &unknown, &cx(B, START + 59_999)).is_err());
        let free = apply(Some(&c), &unknown, &cx(B, START + 60_000));
        assert_eq!(free.status(), ClaimStatus::Free);
        assert!(free.next_possibly_duplicate());
        let view = free.view(&KEY, START, &all_current);
        assert!(view.doubtful());
    }

    #[test]
    fn test_claim_unknown_attempt_id_conflicts() {
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        assert!(apply_entry(Some(&c), &entry(1, 9, EntryKind::Failed), &cx(A, START)).is_err());
        assert!(apply_entry(Some(&c), &done(1, 9, Basis::Evidence), &cx(A, START)).is_err());
    }

    #[test]
    fn test_claim_deadline_pins_and_refuses_from_itself() {
        let pinned = entry(
            0,
            1,
            EntryKind::Attempt {
                orphan_after: 60,
                deadline: Some(START + 1_000),
            },
        );
        let c = apply(None, &pinned, &cx(A, START));
        assert_eq!(c.pin, Pin::At(START + 1_000));
        let failed = apply(Some(&c), &entry(1, 1, EntryKind::Failed), &cx(A, START));
        // Another deadline, or none, conflicts; the pinned one opens.
        let mut other = pinned;
        other.attempt_id = [2; 16];
        other.expected_step = 2;
        other.kind = EntryKind::Attempt {
            orphan_after: 60,
            deadline: None,
        };
        assert!(apply_entry(Some(&failed), &other, &cx(B, START)).is_err());
        other.kind = EntryKind::Attempt {
            orphan_after: 60,
            deadline: Some(START + 1_000),
        };
        assert!(apply_entry(Some(&failed), &other, &cx(B, START)).is_ok());
        // At the deadline itself: refused with the service time, before expected_step.
        other.expected_step = 7;
        let refused = apply_entry(Some(&failed), &other, &cx(B, START + 1_000)).unwrap_err();
        let current = refused.current.unwrap();
        assert_eq!(current["server_time"], rfc3339(START + 1_000));
        assert_eq!(current["claim"]["step"], 2);
    }

    #[test]
    fn test_claim_settled_with_open_attempt_keeps_it() {
        // Evidence settling the only open attempt finishes the claim at once.
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        let settled = apply(Some(&c), &done(1, 1, Basis::Evidence), &cx(B, START));
        assert!(settled.tombstone, "every attempt is done");
        // A SETTLED claim with another attempt open stays live until that one is resolved.
        let mut two = Claim {
            settled: true,
            step: 2,
            ..Claim::default()
        };
        two.attempts.push(settled.attempts[0].clone());
        let mut open = c.attempts[0].clone();
        open.attempt_id = [2; 16];
        two.attempts.push(open);
        let duplicate = apply(Some(&two), &done(2, 2, Basis::Owner), &cx(A, START));
        assert!(duplicate.attempts[1].duplicate && duplicate.tombstone);
        let failed = apply(Some(&two), &entry(2, 2, EntryKind::Failed), &cx(A, START));
        assert!(failed.tombstone);
        assert!(!failed.next_possibly_duplicate());
    }

    #[test]
    fn test_claim_view_shows_owner_only_while_attempting() {
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        let view = c.view(&KEY, START, &all_current).to_value();
        assert_eq!(view["owner"], zbase32_encode(&A));
        assert_eq!(view["attempts"][0]["orphaned"], false);
        assert!(view.get("deadline").is_none());
        let read = ClaimView::from_value(&view).unwrap();
        assert_eq!(read, c.view(&KEY, START, &all_current));
        let tomb = apply(Some(&c), &done(1, 1, Basis::Owner), &cx(A, START));
        let view = tomb.view(&KEY, START, &all_current).to_value();
        assert!(view.get("owner").is_none() && view.get("attempt_id").is_none());
        assert_eq!(view["attempts"][0]["resolved_by"], zbase32_encode(&A));
        // Its members are sorted, as a proof's state is written.
        let text = serde_json::to_string(&view).unwrap();
        assert!(text.starts_with("{\"attempts\":"), "{text}");
    }

    #[test]
    fn test_claim_conflict_hides_the_claim_without_claims_read() {
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        let mut blind = cx(B, START);
        blind.can_read = false;
        let refused = apply_entry(Some(&c), &attempt(1, 2), &blind).unwrap_err();
        assert_eq!(refused.current, Some(json!({})));
    }

    #[test]
    fn test_claim_limits_in_order() {
        let limits = ClaimLimits {
            max_claims: 12,
            max_attempts_per_claim: 2,
            open_attempts_per_app: 2,
            claim_share_percent: 25,
        };
        assert_eq!(limits.claim_share(), 3);
        let full = ClaimTally {
            claims: 12,
            created_by_writer: 3,
            open_attempts_of_writer: 2,
        };
        let limit = |claim: Option<&Claim>, tally: ClaimTally| {
            limits
                .check_attempt(claim, &tally)
                .err()
                .map(|r| r.current.unwrap()["limit"].clone())
        };
        assert_eq!(limit(None, full), Some(json!("claims")));
        let share = ClaimTally { claims: 4, ..full };
        assert_eq!(limit(None, share), Some(json!("claim_share")));
        let open = ClaimTally {
            claims: 4,
            created_by_writer: 1,
            open_attempts_of_writer: 2,
        };
        assert_eq!(limit(None, open), Some(json!("open_attempts")));
        let busy = Claim {
            attempts: vec![apply(None, &attempt(0, 1), &cx(A, START)).attempts[0].clone(); 2],
            ..Claim::default()
        };
        assert_eq!(limit(Some(&busy), open), Some(json!("attempts")));
        assert_eq!(limit(None, ClaimTally::default()), None);
        let off = ClaimLimits {
            claim_share_percent: 100,
            ..limits
        };
        let shared_out = ClaimTally {
            open_attempts_of_writer: 0,
            ..share
        };
        assert!(off.check_attempt(None, &shared_out).is_ok());
        assert!(limits.check_attempt(None, &shared_out).is_err());
    }

    #[test]
    fn test_claim_tally_counts_live_and_tombstones() {
        let open = apply(None, &attempt(0, 1), &cx(A, START));
        let tomb = apply(Some(&open), &done(1, 1, Basis::Owner), &cx(A, START));
        let other = apply(None, &attempt(0, 2), &cx(B, START));
        let tally = ClaimTally::count([&open, &tomb, &other], &A);
        assert_eq!(
            tally,
            ClaimTally {
                claims: 3,
                created_by_writer: 2,
                open_attempts_of_writer: 1
            }
        );
    }

    #[test]
    fn test_claim_deletion_after_the_reconciliation_window() {
        let pinned = entry(
            0,
            1,
            EntryKind::Attempt {
                orphan_after: 60,
                deadline: Some(START + 1_000),
            },
        );
        let c = apply(None, &pinned, &cx(A, START));
        let tomb = apply(Some(&c), &done(1, 1, Basis::Owner), &cx(A, START));
        let from = START + 1_000 + RECONCILIATION_MS;
        assert_eq!(tomb.deletable_from(MAX_CLAIM_AGE_MS), Some(from));
        assert!(!tomb.deletable(Some(from - 1), MAX_CLAIM_AGE_MS));
        assert!(tomb.deletable(Some(from), MAX_CLAIM_AGE_MS));
        assert!(
            !tomb.deletable(None, MAX_CLAIM_AGE_MS),
            "never without trusted time"
        );
        // A live claim with an open attempt is never deleted by age.
        assert_eq!(c.deletable_from(MAX_CLAIM_AGE_MS), None);
        // A failed claim pinned to "none" goes 400 days after its last entry.
        let none = apply(None, &attempt(0, 1), &cx(A, START));
        let failed = apply(
            Some(&none),
            &entry(1, 1, EntryKind::Failed),
            &cx(A, START + 5),
        );
        assert_eq!(
            failed.deletable_from(MAX_CLAIM_AGE_MS),
            Some(START + 5 + MAX_CLAIM_AGE_MS)
        );
    }

    #[test]
    fn test_claim_fields_shape_rules() {
        let good = attempt(0, 1).fields();
        assert_eq!(good.check().unwrap(), attempt(0, 1));
        let bad = |f: ClaimFields| f.check().unwrap_err().status();
        assert_eq!(
            bad(ClaimFields {
                orphan_after: None,
                ..good.clone()
            }),
            400
        );
        assert_eq!(
            bad(ClaimFields {
                claim_key: vec![1; 31],
                ..good.clone()
            }),
            400
        );
        assert_eq!(
            bad(ClaimFields {
                attempt_id: vec![1; 17],
                ..good.clone()
            }),
            400
        );
        assert_eq!(
            bad(ClaimFields {
                evidence_ref: Some(vec![1; 32]),
                ..good.clone()
            }),
            400
        );
        let done_fields = done(1, 1, Basis::Owner).fields();
        assert!(done_fields.check().is_ok());
        assert_eq!(
            bad(ClaimFields {
                basis: None,
                ..done_fields.clone()
            }),
            400
        );
        assert_eq!(
            bad(ClaimFields {
                deadline: Some(START),
                ..done_fields.clone()
            }),
            400
        );
        let evidence = ClaimFields {
            basis: Some(Basis::Evidence),
            evidence_ref: None,
            ..done_fields.clone()
        };
        assert_eq!(bad(evidence), 400);
        let short = ClaimFields {
            evidence_ref: Some(vec![1; 3]),
            ..done_fields.clone()
        };
        assert_eq!(bad(short), 400);
        // `orphan_after` only on an attempt, `basis` only on a done.
        assert_eq!(
            bad(ClaimFields {
                orphan_after: Some(60),
                ..done_fields.clone()
            }),
            400
        );
        assert_eq!(
            bad(ClaimFields {
                basis: Some(Basis::Owner),
                ..good.clone()
            }),
            400
        );
    }

    #[test]
    fn test_entry_depends_on_time() {
        let c = apply(None, &attempt(0, 1), &cx(A, START));
        assert!(entry_depends_on_time(
            None,
            &attempt(0, 1),
            &A,
            &all_current
        ));
        let failed = entry(1, 1, EntryKind::Failed);
        assert!(!entry_depends_on_time(Some(&c), &failed, &A, &all_current));
        assert!(entry_depends_on_time(Some(&c), &failed, &B, &all_current));
        assert!(!entry_depends_on_time(
            Some(&c),
            &failed,
            &B,
            &only_b_current
        ));
        let evidence = done(1, 1, Basis::Evidence);
        assert!(!entry_depends_on_time(
            Some(&c),
            &evidence,
            &B,
            &all_current
        ));
    }

    #[test]
    fn test_evidence_kept_to_the_later_bound() {
        let day = 86_400_000;
        let d = START + 10 * day;
        // Pinned and own deadline: the later plus 30 days, kept at the boundary itself.
        let edge = d + RECONCILIATION_MS;
        assert!(evidence_kept(Some(d), Some(d - day), START, edge, edge));
        assert!(!evidence_kept(
            Some(d),
            Some(d - day),
            START,
            edge + 1,
            edge + 1
        ));
        // An early pin is kept for good.
        assert!(evidence_kept(
            Some(d),
            None,
            START,
            u64::MAX,
            u64::MAX - day
        ));
        // A pin to "none": 400 days after the proof's time.
        let aged = START + MAX_CLAIM_AGE_MS;
        assert!(evidence_kept(None, None, START, aged, aged));
        assert!(!evidence_kept(None, None, START, aged + 1, aged + 1));
        // A far-future verified time is bounded by the device clock plus 24 hours.
        assert!(evidence_kept(None, None, START, u64::MAX, aged - day));
        assert!(service_may_delete(Some(d), START, edge));
        assert!(!service_may_delete(Some(d), START, edge - 1));
        assert!(service_may_delete(None, START, aged));
    }
}
