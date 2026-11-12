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

/// Why the signer didn't renew a certificate past half its lifetime by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RenewalSkip {
    /// The certificate holds scopes no registered protocol owns, which a renewal can only
    /// remove (design note, decision 2).
    UnownedScopes {
        /// Those scopes.
        scopes: Vec<String>,
    },
    /// The registered protocols now give the certificate's scopes other switch permissions
    /// than it holds. A renewal the user didn't ask for never changes what a certificate
    /// grants: the user renews it, and sees the change.
    PermissionsChanged {
        /// The permissions the certificate holds.
        held: Vec<String>,
        /// The permissions a renewal would give it now.
        now: Vec<String>,
    },
    /// The certificate's scopes now fail a scope rule, the Switch's or their protocol's: a
    /// renewal keeping them would be refused.
    ScopesRefused {
        /// The protocol whose rule refused them; `None` for the Switch's own scope rule.
        protocol: Option<String>,
        /// The rule's own reason, as its code gives it.
        reason: String,
    },
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
    /// The end of the staged admission a recovery started didn't go through at the new
    /// service: it stays owed and is sent again at every run, and the alert goes once `GET
    /// /apps` shows the wait ended (Switch spec 12.6 step 2).
    AdmissionNotEnded,
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
    /// A reduction's closing is owed and can't be delivered now, so the earlier certificates
    /// of these apps aren't cut off yet. Either an alarm blocks every signing step: the
    /// closing is delivered once the user has cleared the alarm and the switch is confirmed
    /// again. Or the switch gave no service time for the renewing delivery, even on a retry:
    /// a reduction's cutoff is the service's time, never the signer's own (Switch wire 3.8). The signer closes them at
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
    /// No record of this app took up either of its last two automatic renewals, so the signer
    /// stops renewing it by itself (Switch spec 3.1). The app lapses at `expires_at`: from
    /// then the switch refuses its every request, its feed read included, and readers check
    /// what it writes or sends against that expiry. The user renews it, which brings it back
    /// with nothing from the app (Switch wire 3.8 "An expired certificate"), or removes it.
    /// Cleared once the user renews it, a record of it carries the newest certificate, or the
    /// app is removed.
    RenewalsStopped {
        /// The app.
        app_id: [u8; 16],
        /// When its certificate expires, in Unix milliseconds.
        expires_at: u64,
    },
    /// This app's renewal didn't happen (Switch spec 3.2): the switch refused it for good, at
    /// the storage of its certificate and key bundle or at its delivery, or its flow ended
    /// without it, as at an alarm or when the epoch completion it waited for was cut off. The
    /// app keeps the certificate `identity.json` lists, with its scopes, their keys, its
    /// switch permissions and its expiry. For a `reduction` the access was not reduced: the
    /// app still holds the scope, or the permission, or the later expiry, that the user asked
    /// to remove. The user renews or reduces it again, or revokes it.
    ///
    /// Raised whichever call met it, the renewal's own or a later [`crate::Signer::resume`]
    /// or [`crate::Signer::run_due`], for a renewal the user asked for (`by_user`) and for an
    /// automatic one, which the next run tries again. One per app, kept in its place, and the
    /// user's wins: a refused automatic renewal leaves the user's alert as it is, and a second
    /// refused renewal the user asked for adds what it asks to the first's, the user's newest
    /// request counting where two contradict (a scope asked to be removed, then added; an
    /// earlier expiry, then a later one). Not raised for an app being revoked, whose removal
    /// tells of it.
    ///
    /// Whether it holds is judged from the certificate `identity.json` lists for the app,
    /// whoever's renewal listed it, against what the user asked, which the records keep
    /// beside the alert:
    ///
    /// - a reduction the user asked for stays while that certificate still holds a scope the
    ///   user asked to remove, by the scope hierarchy, or a switch permission the reduction
    ///   would have removed, or expires later than they asked;
    /// - another renewal the user asked for stays until a certificate holding what they asked
    ///   is listed, or a later renewal they ask for is delivered for the app;
    /// - an automatic renewal's stays until the app is renewed;
    /// - each goes once a version removing the app is delivered.
    ///
    /// A user who clears it doesn't see it again, and what they asked goes with it. It is this
    /// install's own: a restore, in place or on a new install, doesn't bring it back, nor what
    /// the user asked, which only this install knew; the listed certificate shows what the app
    /// holds.
    RenewalRefused {
        /// The app.
        app_id: [u8; 16],
        /// Whether the renewal refused was a reduction (Switch wire 3.8 "Reductions").
        reduction: bool,
        /// Whether the user asked for it, rather than an automatic renewal.
        by_user: bool,
    },
    /// An app whose renewals stopped ([`Alert::RenewalsStopped`]) still owns attempts open
    /// or `unknown`, as `GET /apps` lists them: at `expires_at` it isn't current any more, its
    /// open ones are orphaned, and its `unknown` ones are left, for the identity's other apps
    /// or the user to resolve (Switch spec 3.2, 10.2). The user renews it, which keeps them its own, or lets it lapse. Brought up
    /// to date at each run; cleared once it owns none, its renewals start again, or it is
    /// removed.
    LapsingWithOpenAttempts {
        /// The app.
        app_id: [u8; 16],
        /// When its certificate expires, in Unix milliseconds.
        expires_at: u64,
        /// How many attempts it owns that are open or `unknown`.
        open_attempts: u64,
    },
    /// An app being revoked, or revoked, owns attempts open or `unknown`, as `GET /apps`
    /// lists them: they remain, the open ones orphaned, for the identity's other apps or the
    /// user to resolve (Switch spec 12.2, 10.2). The revocation goes on all the same; before
    /// it, the host shows the count [`crate::Signer::open_attempts`] gives. Brought up to date
    /// at each read of `GET /apps` the removal makes; cleared once it owns none. It is this
    /// install's own: a new install, restored once the removal is delivered, doesn't find it
    /// again.
    RevokedWithOpenAttempts {
        /// The app.
        app_id: [u8; 16],
        /// How many attempts it owns that are open or `unknown`.
        open_attempts: u64,
    },
    /// This app's certificate is past half its lifetime, and the signer doesn't renew it by
    /// itself, for `reason` (Switch spec 3.2). Unless the user renews it, the certificate
    /// expires and the switch stops serving the app.
    RenewalSkipped {
        /// The app whose certificate isn't renewed.
        app_id: [u8; 16],
        /// Why.
        reason: RenewalSkip,
    },
    /// The newest `identity.json`, as delivered or as a move's enrollment would carry it,
    /// takes more than three quarters of the most that body may carry (the body caps of `PUT
    /// /identity` and `POST /enroll`, Switch wire 3.7, 7.1), in the body it comes nearest to
    /// filling. Near it, the signer refuses changes that would leave it no room
    /// ([`crate::Refusal::IdentityTooLarge`]); past it no version can be delivered, a
    /// revocation's included, or no move can enroll. Its `renewed` entries are what grow it:
    /// an entry stays once its renewal is closed, until its app is removed.
    IdentityNearLimit {
        /// The version's size in that body, in bytes.
        bytes: u64,
        /// That body's cap, in bytes.
        limit: u64,
    },
    /// The device clock and the switch's signed time differ by more than the clock tolerance
    /// (Switch spec 10.1): certificates are stamped with the device clock, so the signer
    /// renews none by itself, and refuses to issue or renew one, until they agree again. It
    /// clears itself at the first run that finds them agreeing.
    ClockOff,
    /// The switch answers `GET /apps` with a `404` its pinned key didn't sign, while no
    /// erasure of this install's is in progress: the operator's answer for an identity the
    /// service doesn't host, or an intermediary's. This install can't tell which, so it
    /// deletes and changes nothing, and signs nothing while the switch can't be read (Switch
    /// wire 7.3 step 2, 7.4.16). The account may have been erased from another copy of this
    /// install; the way out is the user's, a restore or an enrollment elsewhere. It clears
    /// itself at the next check whose `GET /apps` gets an answer the pinned key signs, an
    /// error included, since only a hosted account's key signs one; an unsigned answer or no
    /// answer leaves it. Every signing step checks first, so it outlasts the switch's
    /// recovery by one check at most. Never raised once the account is erased.
    AccountNotHosted,
    /// A removed app's Pubky grants still let it write its Homeserver paths: each approved
    /// request made one, and the Pubky SDK offers no call to revoke a grant yet, so the user
    /// revokes every grant of the app in the Homeserver's own settings (Switch spec 3.4, 12.2 step 1; design note, decision 4). Raised once for each
    /// removed app, also while its record's deletion keeps failing.
    GrantRevocationOwed {
        /// The removed app.
        app_id: [u8; 16],
    },
    /// The switch took the revocation of this app but gave no time for it, neither in its
    /// answer's proof nor in `GET /apps` (Switch wire 7.4.12). The app is cut off at the switch,
    /// but no version removes it yet; each run tries again. A switch that keeps doing this is
    /// faulty, and the user moves to another provider.
    RevocationUnconfirmed {
        /// The app.
        app_id: [u8; 16],
    },
    /// The switch shows this app revoked or departed, which this signer didn't ask for: it
    /// was removed from that time, and its App ID is kept for good (Switch spec 12.2, 12.3).
    /// The user checks that the app was meant to go.
    RemovedAtSwitch {
        /// The app.
        app_id: [u8; 16],
        /// Whether the app left on its own, rather than being revoked.
        left: bool,
    },
    /// The switch reported a revocation or departure time for this app before it took this
    /// signer's newest version, which lists the app: its own answer contradicts it, since it
    /// refuses a version listing a revoked or departed App ID (Switch wire 3.3). The app is
    /// distrusted only from that version's time, so its earlier messages stand; the switch
    /// may be faulty.
    RemovalTimeBounded {
        /// The app.
        app_id: [u8; 16],
        /// The time the switch reported.
        reported: u64,
        /// The time it was removed from.
        distrust_from: u64,
    },
    /// The switch refused the key bundle answering this app's full-bundle request. The
    /// request isn't tried again until the app asks anew; the other apps' are answered.
    FullBundleRefused {
        /// The app.
        app_id: [u8; 16],
    },
    /// A revocation is asked for and no version removes the app yet: the switch couldn't be
    /// reached or refused it, or the version waits for an alarm to be cleared, and each run
    /// tries again; or a recovery is in progress, when no run sends it and it waits for the
    /// new service to take the recovery's version (Switch spec 12.2, 12.6 step 1). The App ID
    /// is refused for good already, and gets no key.
    RevocationPending {
        /// The app.
        app_id: [u8; 16],
        /// Whether the switch took the revocation, so it serves the app no more, while
        /// `identity.json` still lists it. An alert raised with `false` isn't rewritten when a
        /// later send succeeds.
        at_switch: bool,
    },
    /// After a restore, the signer backup couldn't be written once its delivery won (Switch
    /// wire 3.13). The backup on the Homeserver is the one restored from; the next version's
    /// backup write replaces it.
    BackupNotWritten,
    /// The switch refused to store the hand-over to this app for good (Switch wire 7.4.17),
    /// as when it isn't current there. An earlier send may still be stored, so the hand-over
    /// stays in progress: it takes effect if that app takes over, and the user aborts it
    /// otherwise.
    HandOverRefused {
        /// The new signer's App ID.
        to_app: [u8; 16],
    },
    /// The take-over's delivery won, but the vault didn't take the received secret, or didn't
    /// give it back (Switch wire 3.12). The take-over keeps the hand-over as received, and
    /// [`crate::Signer::resume`] puts the secret in the vault again; nothing is signed until
    /// then.
    KeyNotInstalled,
    /// The switch refused the take-over's first delivery for good, as with a `400`, a `403`
    /// or a `409 conflict` (Switch wire 3.12). The take-over stays undecided and is sent again;
    /// the old signer's abort is the way out.
    TakeOverRefused,
    /// This install took the identity back from `from`, which the user confirmed lost (Switch
    /// wire 3.12). If `from` is still around, it holds the key too, and stops as an install
    /// that isn't named; nothing deletes it there.
    TakenBack {
        /// The signer ID the switch's copy named.
        from: [u8; 16],
    },
    /// A restore found the switch or the backup claiming keys sent past the next data
    /// epoch, which can't be: epochs never skip, and at most one is in progress beyond
    /// `data_epoch` (Switch spec 3.2, 3.5). The floor is kept at the next epoch.
    EpochFloorBounded {
        /// The highest epoch claimed.
        claimed: u64,
        /// The floor kept.
        kept: u64,
    },
}
