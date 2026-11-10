//! What the signer tells the user: alerts it keeps until the user has seen them.
//!
//! Each alert carries the facts to show; the wording is the host's.

use serde::{Deserialize, Serialize};

/// Where the signer saw a copy of `identity.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    /// The switch's copy.
    Switch,
    /// The Homeserver's copy.
    Homeserver,
    /// The signer backup on the Homeserver.
    Backup,
}

/// Something the user needs to know.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Alert {
    /// A copy of `identity.json` older than the newest one a service accepted from this signer:
    /// a rollback, which the signer doesn't build on (Switch spec 4.3, Switch wire 3.3 "Never
    /// back").
    Rollback {
        /// Where the copy was seen.
        source: Source,
        /// The copy's version; `None` when the source holds no copy at all.
        version: Option<u64>,
        /// The copy's generation; `None` when the source holds no copy at all.
        generation: Option<u64>,
        /// The newest version a service accepted from this signer.
        high_water_version: u64,
    },
    /// Another `identity.json` at the version of the newest one a service accepted from this
    /// signer: equivocation (Switch spec 4.3).
    Equivocation {
        /// Where the copy was seen.
        source: Source,
        /// The version.
        version: u64,
    },
    /// Another install is the identity's signer, as the newest `identity.json` or the
    /// signer's backup names it. This install signs nothing until the user has it take over
    /// (Switch spec 4.3, 12.8).
    ManagedByOtherInstall {
        /// That install's signer ID.
        install: [u8; 16],
    },
    /// The signer's backup on the Homeserver didn't open. The switch still held the newest
    /// version this signer delivered, so no other install had taken over, and the signer
    /// wrote its own backup over it (Switch wire 3.13).
    BackupUnreadable,
    /// Before this install's first version was delivered, the Homeserver held a signer backup
    /// it can't open: another install may sign for the identity, or the file is damaged. The
    /// signer writes nothing and delivers nothing until the user deals with it (Switch wire
    /// 3.13): by restoring from it on the install that wrote it, or, sure that no other
    /// install signs, by removing it from the Homeserver, after which `resume` goes on.
    UnreadableBackupBeforeEnrollment,
    /// The Homeserver held no signer backup, though this signer had written one. The switch
    /// still held the newest version this signer delivered, so the signer wrote its backup
    /// again (Switch wire 3.13).
    BackupMissing,
    /// The switch or the Homeserver holds a newer `identity.json` that this install signed
    /// itself: its records are behind, as after a restore of an old device backup. Signing
    /// on top of its older records would roll the identity's state back (its data epoch,
    /// apps and renewals), so it signs nothing more. The way forward is a restore from the
    /// signer backup, which is written before every delivery and so holds that newer
    /// version (Switch wire 3.13). (A newer one by another install isn't this alert: this
    /// install adopts it and stops.)
    RecordsBehind {
        /// Where the newer copy was.
        source: Source,
        /// Its version.
        version: u64,
        /// The newest version this signer's records hold.
        high_water_version: u64,
    },
    /// The switch gave no service time for a reduction's renewing delivery, even on a retry,
    /// so the earlier certificates of these apps aren't cut off yet: a reduction's cutoff is
    /// the service's time, never the signer's own (Switch wire 3.8). The signer closes them at
    /// the service time of the next version the user signs, and the alert stays until then.
    /// Nothing is delivered on its own to get a time: to force the cut-off, the user makes a
    /// change, or revokes the app, which cuts it off at once. A switch that keeps doing this
    /// is faulty, and the user moves to another provider.
    ReductionNotClosed {
        /// The apps whose reduction stays open.
        apps: Vec<[u8; 16]>,
    },
    /// A rotation gave this app no keys for its new data epoch: its certificate holds scopes
    /// no registered protocol owns, so the signer can't tell which keys it holds (design note,
    /// decision 2). Its next bundle, once a protocol owns them, starts after the epochs it
    /// holds, so it catches up (Switch wire 3.5).
    RotationSkipped {
        /// The app left without the new epoch's keys.
        app_id: [u8; 16],
        /// Its scopes that no registered protocol owns.
        scopes: Vec<String>,
    },
}
