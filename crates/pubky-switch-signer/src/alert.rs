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
    /// The Homeserver publishes a newer `identity.json` than the one the switch holds as this
    /// signer's mark. The signer writes nothing over it: a version the switch never took, or a
    /// switch behind its Homeserver, is for the user to look into (Switch spec 4.3).
    HomeserverAhead {
        /// The Homeserver's version.
        version: u64,
        /// The newest version a service accepted from this signer.
        high_water_version: u64,
    },
}
