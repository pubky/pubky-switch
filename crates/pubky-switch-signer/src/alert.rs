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
        /// The copy's version.
        version: u64,
        /// The copy's generation.
        generation: u64,
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
    /// The signer's backup on the Homeserver didn't open, so it couldn't tell whether another
    /// install had taken over; the signer wrote its own backup over it (Switch wire 3.13).
    BackupUnreadable,
}
