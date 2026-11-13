//! The signer of one identity: enrolling it at a switch, signing and delivering its
//! `identity.json` versions with the high-water mark, the one-signer rule, and the backup of
//! its records (Switch spec 4.3, 12.8; Switch wire 3.3, 3.7, 3.13, 7.4.1, 7.4.2).
//!
//! Every network effect follows one rule: sign the artifact and commit it with the flow's
//! next step, send exactly those bytes until there is an answer, then commit the outcome. The
//! signer takes a new state as its own only once the store holds it. A crash anywhere is
//! finished by [`Signer::resume`], which resends the bytes kept, so nothing is signed twice
//! (Switch wire 2.1).
//!
//! A new version takes these steps (Switch spec 4.3, Switch wire 3.13):
//!
//! 1. this install must be the one named;
//! 2. sign the version, naming this install as `signer`, above every version this install
//!    signed before, and commit it;
//! 3. read the backup on the Homeserver: one naming another install at or past the high-water
//!    mark means that install took over, and this one stops, unless it builds on what the mark
//!    built on: a losing delivery's, which this install writes over. One that doesn't open, or none
//!    where this signer wrote one, stops it too, unless the switch still holds the high-water
//!    version;
//! 4. write the backup holding the new version; a failed write stops the delivery;
//! 5. deliver it with `PUT /identity`, naming the version it builds on;
//! 6. take the answer: success moves the high-water mark; `409 stale_identity` carries the
//!    switch's copy, which is adopted only when it is strictly newer, and raises an alarm when
//!    it is older or another body at the high-water version;
//! 7. publish it on the Homeserver.

use std::sync::{Arc, Mutex, PoisonError};

use pubky_switch_client::client::answers::AppsAnswer;
use pubky_switch_client::clock::Clock;
use pubky_switch_client::store::StoreHandle;
use pubky_switch_client::transport::Transport;
use pubky_switch_client::{ClientError, StoreError};
use pubky_switch_core::enc::{pubky_id, random_bytes};
use pubky_switch_core::http::{ErrorCode, IdentityDelivery};

use pubky_switch_core::records::{
    AppCert, ConnectRequests, Enrollment, EnrollmentBody, IDENTITY_PATH, IdentityBody, IdentityDoc,
    IdentityPolicy, Inbox, SIGNER_BACKUP_PATH, SignerBackup,
};
use pubky_switch_core::sig::SignedDoc;

use serde_json::Value;

use crate::alert::{Alert, Source};
use crate::error::{Refusal, Result, SignerError, SizedBody};
use crate::homeserver::Homeserver;
use crate::key::{BackupView, IdentityKeyring, SigningKey};
use crate::protocol::Protocols;
use crate::state::{self, DeliverStep, Flow, Newest, Service, SignerState};

mod approval;
mod clients;
mod erasure;
pub(crate) mod gate;
mod handover;
mod recovery;
mod renewal;
mod restore;
mod revocation;
mod takeover;
#[cfg(test)]
mod vector_cases;
#[cfg(test)]
#[path = "../tests/common/vector_protocol.rs"]
mod vector_protocol;

pub use approval::{AppReview, ApprovedRequest};
use clients::{RequestClient, SigningClient, Target};
pub use handover::AbortOutcome;
pub use renewal::{CertChange, RunDue};
pub use revocation::UserConfirmed;
pub use takeover::ReceivingApp;

/// What the signer works with, from the host.
#[derive(Clone)]
pub struct SignerEnv {
    /// The host's durable store.
    pub store: StoreHandle,
    /// The clock requests are signed with.
    pub clock: Arc<dyn Clock>,
    /// The transport to the switches.
    pub transport: Arc<dyn Transport>,
    /// The identity's own Homeserver.
    pub homeserver: Arc<dyn Homeserver>,
    /// The protocols the host supports (Switch spec 1).
    pub protocols: Protocols,
}

impl std::fmt::Debug for SignerEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerEnv")
            .field("protocols", &self.protocols)
            .finish_non_exhaustive()
    }
}

/// The signer's high-water mark: the newest `identity.json` a service accepted from it, or
/// that it adopted (Switch spec 4.3). It never adopts or republishes a copy with a lower
/// version or generation, or another body at this version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HighWater {
    /// The generation.
    pub generation: u64,
    /// The version.
    pub version: u64,
    /// The document hash.
    pub doc_hash: [u8; 32],
    /// The hash of the body bytes, which equivocation compares.
    pub body_hash: [u8; 32],
}

impl HighWater {
    fn of(doc: &IdentityDoc) -> Self {
        Self {
            generation: doc.generation(),
            version: doc.version(),
            doc_hash: doc.hash(),
            body_hash: doc.body_hash(),
        }
    }
}

/// Where the signer stands.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignerStatus {
    /// Set up, but no switch has accepted a first `identity.json` yet: [`Signer::resume`]
    /// finishes the enrollment.
    Enrolling,
    /// This install signs for the identity.
    Signing,
    /// Another install is the identity's signer; this one signs nothing until the user has it
    /// take over (Switch spec 4.3, 12.8).
    ManagedBy {
        /// That install's signer ID.
        install: [u8; 16],
    },
    /// The switch or the Homeserver holds a newer version this install signed itself: its
    /// records are behind, and it signs nothing until they are restored from the signer
    /// backup ([`Alert::RecordsBehind`]).
    RecordsBehind {
        /// That version.
        version: u64,
    },
    /// This install is handing the identity over to the app `to_app`, until the hand-over
    /// takes effect or is aborted (Switch wire 3.12).
    HandingOver {
        /// The new signer's App ID.
        to_app: [u8; 16],
    },
    /// This install is taking the identity over, until its first delivery has won.
    TakingOver,
    /// A rollback or an equivocation was seen: its alert is held, or the switch hasn't
    /// confirmed since that it holds this signer's newest version. Claims are held, and
    /// nothing is signed, an owed closing included, until the user clears the alert
    /// ([`Signer::clear_alert`]) and the switch is confirmed again.
    Alarm,
    /// The identity's account at its switch is being erased ([`Signer::close_account`]):
    /// `identity.json` may be off the Homeserver already, and nothing else is signed until
    /// the erasure is done or aborted ([`Signer::abort_erasure`]).
    Erasing,
    /// The erasure's request may have landed, and a check or a retry met an unsigned `404` at
    /// `since_ms`, by the device clock, with no answer the pinned key signs since: the account
    /// looks erased, unconfirmed until the `404` has held for 24 hours (Switch wire 7.4.16,
    /// spec 12.7 step 5). Nothing else is signed, the revocations included, and the erasure
    /// can't be aborted.
    ErasedUnconfirmed {
        /// When a check first met the `404`, in Unix milliseconds, by the device clock.
        since_ms: u64,
    },
    /// The identity's account at its switch is erased ([`Signer::close_account`]): the
    /// records stay, and nothing more is signed for it.
    Erased,
    /// A provider loss is declared ([`Signer::declare_provider_loss`]) and the service at
    /// `origin` hasn't taken the recovery's version yet: [`Signer::resume`] goes on with it,
    /// and nothing else is signed meanwhile (Switch spec 12.6 step 1). Declaring it again, at
    /// that service or another, replaces it.
    Recovering {
        /// The service the recovery goes to.
        origin: String,
    },
    /// The service at `origin` refused the recovery's version for good: nothing is sent there
    /// again, and the recovery waits for the user to declare it again, at that service or
    /// another (Switch spec 12.6 step 1). Nothing else is signed meanwhile.
    RecoveryRefused {
        /// The service that refused it.
        origin: String,
    },
}

/// Where the records `state` stand: what holds signing back is the signing gate's verdict
/// ([`gate::refusal`]), so the status says signing only when the gate lets it through.
fn status_of(state: &SignerState) -> SignerStatus {
    match gate::refusal(state) {
        Some(SignerError::NotNamed { install }) => SignerStatus::ManagedBy { install },
        Some(SignerError::Refused(Refusal::RecordsBehind { version })) => {
            SignerStatus::RecordsBehind { version }
        }
        Some(SignerError::Refused(Refusal::HandingOver { to_app })) => {
            SignerStatus::HandingOver { to_app }
        }
        Some(SignerError::Refused(Refusal::TakingOver)) => SignerStatus::TakingOver,
        Some(SignerError::Refused(Refusal::Erased)) => SignerStatus::Erased,
        Some(_) => SignerStatus::Alarm,
        None if state.newest.is_none() => SignerStatus::Enrolling,
        None => SignerStatus::Signing,
    }
}

/// The signer of one identity, on one install.
pub struct Signer {
    env: SignerEnv,
    keyring: IdentityKeyring,
    state: SignerState,
    flow: Option<Flow>,
    /// A commit answered that the store can't tell whether it applied: the records and the
    /// flow are read again before the next step.
    unsure: bool,
    /// What the [`Signer::run_due`] in progress left because a bound cut it short.
    left: RunDue,
    /// What the public call in progress may still do: one budget for the whole call, however
    /// its steps nest, a [`Signer::run_due`] or a direct one. Empty between calls; a guard
    /// empties it when the call ends, also when its future is dropped part way.
    run: Arc<Mutex<Option<Allowance>>>,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("identity", &pubky_id(&self.state.identity))
            .field("status", &self.status())
            .field("high_water", &self.high_water().map(|h| h.version))
            .finish_non_exhaustive()
    }
}

impl Signer {
    /// Set up the signer of a new identity, whose key `keyring` holds, to enroll at the switch
    /// at `origin`: pick this install's signer ID, sign the enrollment and commit both
    /// (Switch spec 4.3, Switch wire 3.7). Nothing is sent: [`Signer::resume`] enrolls,
    /// delivers the first `identity.json` and publishes it.
    ///
    /// # Errors
    ///
    /// [`Refusal::AlreadySetUp`] when the store holds signer records for this identity,
    /// [`SignerError::InvalidData`] for an origin that isn't a switch origin, or a key, store
    /// or random generator failure.
    pub async fn create(env: SignerEnv, keyring: IdentityKeyring, origin: &str) -> Result<Self> {
        let identity = keyring.public_key();
        if state::set_up(&env.store, &identity).await? {
            return Err(Refusal::AlreadySetUp.into());
        }
        let install = random_bytes::<16>()?;
        let policy = IdentityPolicy::default();
        let state = SignerState::new(identity, install);
        let enrollment = {
            let key = gate::signing_key(&keyring, &state)?;
            let body = EnrollmentBody {
                identity,
                origin: origin.to_owned(),
                nonce: random_bytes()?,
                policy,
                identity_doc: None,
                revoked_apps: None,
            };
            Enrollment::sign(&key, body)?
        };
        // The enrollment's own check refuses an origin that isn't a switch origin.
        Enrollment::verify(enrollment.signed(), &identity, origin)?;
        let flow = Flow::Enroll {
            origin: origin.to_owned(),
            enrollment: enrollment.signed().clone(),
            policy,
        };
        state::save(&env.store, &state, Some(&flow)).await?;
        Ok(Self {
            env,
            keyring,
            state,
            flow: Some(flow),
            unsure: false,
            left: RunDue::default(),
            run: Arc::default(),
        })
    }

    /// The signer whose records the store holds for the identity `keyring` holds the key of.
    /// Nothing is sent: [`Signer::resume`] finishes a flow a crash left.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotSetUp`] when the store holds none, [`SignerError::Records`] when they
    /// don't read, or the store's error.
    pub async fn open(env: SignerEnv, keyring: IdentityKeyring) -> Result<Self> {
        let identity = keyring.public_key();
        let (state, flow) = state::load(&env.store, &identity)
            .await?
            .ok_or(Refusal::NotSetUp)?;
        let handed_over = state.handed_over_to;
        let mut signer = Self {
            env,
            keyring,
            state,
            flow,
            unsure: false,
            left: RunDue::default(),
            run: Arc::default(),
        };
        // Records of a hand-over that took effect: the deletion is finished now.
        if let Some(install) = handed_over {
            signer.delete_handed_over(install).await?;
        }
        Ok(signer)
    }

    /// Finish the flow in progress, resending what it signed, then publish the newest version
    /// if it isn't published yet. A call that fails leaves the flow to the next one.
    ///
    /// # Errors
    ///
    /// The error of the step that failed: a switch, Homeserver, store or key error;
    /// [`SignerError::NotNamed`] when another install took over; [`SignerError::Alarm`] for a
    /// rollback or an equivocation; [`Refusal::RecordsBehind`] when the switch or the
    /// Homeserver holds a newer version this install signed itself.
    pub async fn resume(&mut self) -> Result<()> {
        // One budget for this call and what it runs, unless a call in progress holds one.
        let _budget = self.budget();
        self.refresh().await?;
        loop {
            self.finish_flow().await?;
            // An erased account: nothing more is owed to it (Switch spec 12.7).
            if self.state.erased {
                return Ok(());
            }
            // A recovery whose version no service took waits to be declared again: that
            // version isn't published, and nothing else is owed before one is delivered
            // (Switch spec 12.6 step 1).
            if self.state.recovering {
                return Ok(());
            }
            // A restore's recovery taken after the restore: the version naming this install
            // comes next, as the restore would have signed it (Switch wire 3.13), after the
            // copies a restore checks first. The switch's is the version just delivered. The
            // Homeserver's must be neither newer nor another body at it, and the backup must
            // name neither another install that took over nor a newer own version; the one
            // this install was restored from holds that version itself, and is no take-over.
            if self.state.owes_own_version && gate::refusal(&self.state).is_none() {
                self.check_before_own_version().await?;
                self.sign_own_version().await?;
                continue;
            }
            // Right after a recovery's delivery, before its publication, which is how apps
            // find the new service: the revocations its version still lists go there, so no
            // app revoked is current there meanwhile. The version removing them follows
            // (Switch spec 12.6 step 1).
            if self.state.revoke_at_service {
                self.revoke_at_switch().await?;
                let mut state = self.state.clone();
                state.revoke_at_service = false;
                self.commit(state, self.flow.clone()).await?;
            }
            // While a hand-over is in progress nothing routine is signed: its own step only,
            // and owed work stays owed (Switch wire 3.12).
            if self.state.handing_over.is_some() {
                self.continue_hand_over().await?;
                // Still handing over: nothing more this run. Over, as when its own abort or
                // take-back is found to have won: the run goes on.
                if self.state.handing_over.is_some() {
                    return Ok(());
                }
                continue;
            }
            // A closing delivery a reduction owes comes before anything else, publication
            // included: it cuts the earlier certificate off at the switch, and a Homeserver
            // that refuses writes must not hold it back (Switch wire 3.8 "A closing delivery
            // owed"). Only the backup write comes before it, as before every delivery
            // (Switch wire 3.13).
            if !self.queue_owed_closing().await? {
                // A restore's backup is written once its delivery has won, before publication,
                // so a failed publication doesn't hold it back (Switch wire 3.13).
                self.write_owed_backup().await?;
                self.publish().await?;
                self.check_owed_deletions().await?;
                // A removed app's record goes once its removal is published (Switch spec
                // 12.2 step 4).
                self.clean_up_removed().await?;
                // The end of a staged admission comes last, after publication, which is how
                // apps find the new service: it stays owed, and is sent again at the next
                // run, without holding any other step back (Switch spec 12.6 step 2).
                // Only once published: a version waiting for an alarm to be cleared waits
                // with it (Switch wire 7.4.14).
                let published = self.state.newest.as_ref().is_some_and(|n| n.published);
                if published
                    && self.state.admission_owed
                    && self.end_owed_admission().await.is_err()
                {
                    let mut state = self.state.clone();
                    state.alert(Alert::AdmissionNotEnded);
                    if state != self.state {
                        self.commit(state, self.flow.clone()).await?;
                    }
                }
                return Ok(());
            }
        }
    }

    /// The copies a restore checks before it signs the version naming this install (Switch
    /// wire 3.13), checked again before the owed one (the caller's comment).
    async fn check_before_own_version(&mut self) -> Result<()> {
        let Some(newest) = self.state.newest_doc()? else {
            return Ok(());
        };
        self.judge_homeserver(&newest).await?;
        let found = self
            .env
            .homeserver
            .get(SIGNER_BACKUP_PATH)
            .await
            .map_err(SignerError::Homeserver)?;
        if let Some(found) = found.and_then(|bytes| self.open_backup(&bytes).transpose()) {
            let found = found?;
            if found.identity_doc.hash() != newest.hash() {
                self.judge_backup(&found).await?;
            }
        }
        Ok(())
    }

    /// Run the flow in progress to its end.
    async fn finish_flow(&mut self) -> Result<()> {
        while let Some(flow) = self.flow.clone() {
            match flow {
                Flow::Renew {
                    batches,
                    sent,
                    doc,
                    prev,
                } => self.send_renewal(&batches, sent, doc, prev).await?,
                Flow::Enroll {
                    origin,
                    enrollment,
                    policy,
                } => self.enroll(&origin, &enrollment, policy).await?,
                Flow::TakingOver { delivery, .. } => self.take_over(delivery).await?,
                Flow::Recover { origin, enrollment } => self.recover(&origin, &enrollment).await?,
                Flow::Erase {
                    unpublished,
                    reminded,
                    unanswered,
                    ..
                } => self.erase(unpublished, reminded, unanswered).await?,
                Flow::Deliver {
                    doc,
                    prev,
                    backup,
                    step: DeliverStep::Signed,
                } => self.write_backup(&doc, prev, backup).await?,
                Flow::Deliver {
                    doc,
                    prev,
                    step: DeliverStep::BackupWritten,
                    ..
                } => self.deliver(doc, prev).await?,
            }
        }
        Ok(())
    }

    /// The identity.
    pub fn identity(&self) -> [u8; 32] {
        self.state.identity
    }

    /// This install's signer ID (Switch spec 4.3).
    pub fn install_id(&self) -> [u8; 16] {
        self.state.install
    }

    /// Where the signer stands.
    pub fn status(&self) -> SignerStatus {
        match &self.flow {
            Some(Flow::Erase {
                first_404_ms: Some(since_ms),
                ..
            }) => {
                return SignerStatus::ErasedUnconfirmed {
                    since_ms: *since_ms,
                };
            }
            Some(Flow::Erase { .. }) => return SignerStatus::Erasing,
            _ => {}
        }
        // A recovery shows as one while its own gate lets it go on: another install named,
        // records behind, a hand-over or a take-over stop it as they stop every step.
        if self.state.recovering && gate::recovery_refusal(&self.state).is_none() {
            let origin = match &self.flow {
                Some(Flow::Recover { origin, .. }) => Some(origin.clone()),
                _ => self
                    .state
                    .recovery_origin
                    .clone()
                    .or_else(|| self.state.service.as_ref().map(|s| s.origin.clone())),
            }
            .unwrap_or_default();
            return match self.flow {
                Some(_) => SignerStatus::Recovering { origin },
                None => SignerStatus::RecoveryRefused { origin },
            };
        }
        status_of(&self.state)
    }

    /// The newest `identity.json` a service accepted from this signer, or that it adopted.
    ///
    /// # Errors
    ///
    /// [`SignerError::InvalidData`] when the stored copy no longer verifies.
    pub fn identity_doc(&self) -> Result<Option<IdentityDoc>> {
        self.state.newest_doc()
    }

    /// The high-water mark; `None` before the first delivery.
    pub fn high_water(&self) -> Option<HighWater> {
        self.state
            .newest_doc()
            .ok()
            .flatten()
            .map(|doc| HighWater::of(&doc))
    }

    /// The alerts the user hasn't cleared, oldest first.
    pub fn alerts(&self) -> &[Alert] {
        &self.state.alerts
    }

    /// Clear `alert`, once the user has seen it. [`Alert::ReductionNotClosed`] stays until its
    /// renewals are closed.
    ///
    /// A rollback or an equivocation leaves the switch unconfirmed: the signer doesn't know that
    /// it holds the high-water version, so it releases no claim (Switch spec 4.3). Clearing such
    /// an alert doesn't confirm it. The signer delivers the newest version it signed again, the
    /// same bytes naming the version they build on (Switch wire 2.1, 7.4.2). A switch that went
    /// back to that version takes it, and the signer is confirmed again; a switch that holds an
    /// older version, none, or another body at the high-water version raises the alarm again,
    /// and everything stays held. If it keeps coming back, the user moves to another provider,
    /// or declares a provider loss.
    ///
    /// Nothing is delivered again when the alarm saw no copy at all, since that switch lost
    /// the account's state and must not serve it again under this generation (Switch spec
    /// 6.5). Then the switch's copy is read instead: one at the mark, as after a single bad
    /// answer, confirms the switch, and signing goes on; none raises the alarm again, and the
    /// user declares a provider loss. Nothing is delivered or read once another install is
    /// the signer, nor once the account is erased: then only the alert goes.
    ///
    /// # Errors
    ///
    /// The store's error, or the delivery's as [`Signer::resume`] gives it, the alarm again
    /// among them.
    pub async fn clear_alert(&mut self, alert: &Alert) -> Result<()> {
        self.refresh().await?;
        if !self.state.alerts.contains(alert) {
            return Ok(());
        }
        // Records that are behind stay so until a restore, and so does their alert.
        if matches!(alert, Alert::RecordsBehind { .. }) && self.state.records_behind.is_some() {
            return Ok(());
        }
        // A reduction's alert stays until its renewals are closed (Switch wire 3.8).
        if matches!(alert, Alert::ReductionNotClosed { .. }) && !self.owed()?.is_empty() {
            return Ok(());
        }
        let mut state = self.state.clone();
        state.alerts.retain(|held| held != alert);
        // What the user asked of a refused renewal goes with its alert (Switch spec 3.2).
        renewal::keep_asked_with_alerts(&mut state);
        // An erased account has no switch to deliver to or read: the alert goes, nothing else
        // (Switch spec 12.7).
        if self.state.erased {
            return self.commit(state, self.flow.clone()).await;
        }
        // Nothing is delivered, published or read for an install that isn't the one to sign:
        // another install named, or records behind (Switch spec 4.3, wire 3.13).
        let named = self.check_named().is_ok();
        // Seen, another body on the Homeserver is published over with the switch's copy once
        // the switch is confirmed to hold this signer's newest version (Switch wire 3.3).
        let republish = named
            && matches!(
                alert,
                Alert::Equivocation {
                    source: Source::Homeserver,
                    ..
                }
            )
            && state.homeserver_other.is_some();
        if republish {
            state.republish_over = state.homeserver_other;
            if let Some(newest) = state.newest.as_mut() {
                newest.published = false;
            }
        }
        // Delivered again only when the alarm saw a copy at the switch: one that holds nothing
        // has lost the account's state, and a version 1 delivered onto it would start the
        // account afresh at the same generation (Switch spec 6.5 "No restore and continue");
        // the way out is a provider loss. Never once another install signs, or while the
        // records are behind, where the delivery could never go.
        let alarm = matches!(
            alert,
            Alert::Rollback {
                version: Some(_),
                ..
            } | Alert::Equivocation { .. }
        );
        let again = match (&self.state.newest, &self.flow) {
            (Some(newest), None) if alarm && named && state.switch_unconfirmed => {
                Some(Flow::Deliver {
                    doc: newest.doc.clone(),
                    prev: newest.prev,
                    backup: None,
                    step: DeliverStep::BackupWritten,
                })
            }
            _ => None,
        };
        let deliver_again = again.is_some();
        let flow = again.or_else(|| self.flow.clone());
        self.commit(state, flow).await?;
        if deliver_again || republish {
            self.resume().await?;
        } else if named && self.state.switch_unconfirmed && gate::held_alarm(&self.state).is_none()
        {
            // Nothing to deliver again: the switch's copy confirms it, if it holds the mark.
            // One that holds nothing raises the alarm again; the way out is a provider loss.
            self.switch_at_mark().await?;
        }
        Ok(())
    }

    /// Set the record age limit, in seconds, or clear it for the 90-day default (Switch spec
    /// 4.3), in a new version. Returns that version once it is delivered and published.
    ///
    /// # Errors
    ///
    /// As [`Signer::resume`]; [`Refusal::FlowInProgress`] while a flow is in progress, and
    /// [`SignerError::InvalidData`] for a limit of 0.
    pub async fn set_record_max_age(&mut self, seconds: Option<u64>) -> Result<IdentityDoc> {
        self.new_version(|body| body.record_max_age = seconds).await
    }

    /// Set the connect request settings of the policy (Switch spec 7, Switch wire 3.3), in a
    /// new version. Returns that version once it is delivered and published.
    ///
    /// # Errors
    ///
    /// As [`Signer::set_record_max_age`].
    pub async fn set_connect_requests(&mut self, settings: ConnectRequests) -> Result<IdentityDoc> {
        self.new_version(|body| body.policy.connect_requests = settings)
            .await
    }

    /// Sign the next version, built from the newest with `change`, and deliver it. Its
    /// version is above every version this install committed a signed document at, so a
    /// version whose document went out in a flow that was dropped is never signed again
    /// (Switch spec 4.3, 13.2).
    async fn new_version(&mut self, change: impl FnOnce(&mut IdentityBody)) -> Result<IdentityDoc> {
        self.ready().await?;
        let key = self.signing_key()?;
        let (doc, flow) = self.next_version(&key, change)?;
        drop(key);
        let mut state = self.state.clone();
        state.signed_through = doc.version();
        self.commit(state, Some(flow)).await?;
        self.resume().await?;
        Ok(doc)
    }

    /// Ready for a new signing call: the store read again if a commit left it unsure, this
    /// install named, no flow in progress, the copies checked, and the signing gate passed
    /// ([`gate::refusal`]).
    pub(crate) async fn ready(&mut self) -> Result<()> {
        self.ready_and_read().await.map(drop)
    }

    /// [`Signer::ready`], and the `GET /apps` whose copy that check confirmed: one read for
    /// both, so the apps a step goes by are those of the switch it found holding its mark.
    /// Read again only when that check read no copy, or delivered since.
    pub(crate) async fn ready_at_switch(&mut self) -> Result<SwitchRead> {
        match self.ready_and_read().await? {
            Some(read) => Ok(read),
            None => self.switch_at_mark().await,
        }
    }

    /// [`Signer::ready`], and the `GET /apps` answer its copy check read, while nothing was
    /// delivered since: `None` before the first version, which no copy is checked against,
    /// and after a closing owed was delivered.
    pub(crate) async fn ready_and_read(&mut self) -> Result<Option<SwitchRead>> {
        self.refresh().await?;
        // An erased account has no switch to read (Switch spec 12.7).
        if self.state.erased {
            return Err(Refusal::Erased.into());
        }
        self.check_named()?;
        if self.flow.is_some() {
            return Err(Refusal::FlowInProgress.into());
        }
        // A recovery in progress has no switch whose copy to read: the lost one can't be
        // asked, and the new one holds nothing yet (Switch spec 12.6 step 1).
        if self.state.recovering {
            return Err(Refusal::Recovering.into());
        }
        // The copies are read first, so a take-over or records behind are found also while an
        // alarm holds signing back; then the signing gate decides.
        let read = self.check_copies().await?;
        if let Some(refused) = gate::refusal(&self.state) {
            return Err(refused);
        }
        if self.owes_closing()? {
            self.resume().await?;
            // The delivery changed what the switch holds.
            return Ok(None);
        }
        Ok(read)
    }

    /// Before a new version is signed, check every copy that could show this install's
    /// records aren't the newest: the switch's copy is its mark, the signer backup names
    /// neither another install that took over nor a newer version of this install's own, and
    /// the Homeserver's `identity.json` is neither newer nor another body at the mark (Switch
    /// spec 4.3, Switch wire 3.13). So nothing stale is signed, backed up or sent. Returns
    /// the switch's answer that showed its copy, `None` before the first version.
    async fn check_copies(&mut self) -> Result<Option<SwitchRead>> {
        let Some(newest) = self.state.newest_doc()? else {
            return Ok(None);
        };
        let read = self.ensure_signer().await?;
        self.judge_homeserver(&newest).await?;
        Ok(Some(read))
    }

    /// Stop at a backup that shows another install took over, or that holds a version of
    /// this install's own above every version its records signed: the records are behind,
    /// and that backup is the one to restore from, so it is never written over (Switch wire
    /// 3.13).
    async fn judge_backup(&mut self, found: &BackupView) -> Result<()> {
        let doc = &found.identity_doc;
        let mark = self.state.newest_doc()?;
        // The backup this install's records came from, before a version of its own: it
        // holds nothing they don't, as after a restore whose delivery of that version was
        // refused mid-recovery (Switch spec 12.6 step 1).
        if mark.as_ref().is_some_and(|mark| mark.hash() == doc.hash()) && self.state.recovering {
            return Ok(());
        }
        let mark_prev = self.state.newest.as_ref().and_then(|n| n.prev);
        if found.taken_over(&self.state.install, mark.as_ref(), mark_prev) {
            return self.managed_by(doc.body().signer).await;
        }
        if doc.body().signer == self.state.install && doc.version() > self.state.signed_through {
            return self.records_behind(Source::Backup, doc.version()).await;
        }
        Ok(())
    }

    /// Judge the Homeserver's `identity.json` against `mine`, the mark (Switch spec 4.3): a
    /// newer copy, a higher version at no lower generation, is taken as [`Signer::adopt`]
    /// says; another body at the mark's version is equivocation, kept as it is. Returns
    /// whether it holds `mine` already.
    async fn judge_homeserver(&mut self, mine: &IdentityDoc) -> Result<bool> {
        let held = self
            .env
            .homeserver
            .get(IDENTITY_PATH)
            .await
            .map_err(SignerError::Homeserver)?;
        // A copy that doesn't verify is written over.
        let Some(copy) = held
            .and_then(|bytes| serde_json::from_slice::<SignedDoc>(&bytes).ok())
            .and_then(|signed| IdentityDoc::verify(&signed, &self.state.identity).ok())
        else {
            return Ok(false);
        };
        if copy.version() > mine.version() && copy.generation() >= mine.generation() {
            self.adopt(copy, Source::Homeserver).await?;
            return Ok(false);
        }
        if copy.version() == mine.version() && copy.body_hash() != mine.body_hash() {
            // The switch decides which body is the version, and the Homeserver only publishes
            // it (Switch wire 3.3 "Deliver, then publish"). Another body there needed the
            // identity key, so the user is told first; once they have cleared the alert, the
            // switch's copy is published over it.
            let other = copy.hash();
            if self.state.republish_over == Some(other) {
                return Ok(false);
            }
            let alert = Alert::Equivocation {
                source: Source::Homeserver,
                version: mine.version(),
            };
            let mut state = self.state.clone();
            state.homeserver_other = Some(other);
            state.alert(alert.clone());
            state.switch_unconfirmed = true;
            self.commit(state, self.erasure_kept()).await?;
            return Err(SignerError::Alarm(alert));
        }
        Ok(copy.signed() == mine.signed())
    }

    /// The next version, built from the newest with `change` and signed with `key`, and the
    /// flow that delivers it, for a change that adds content: it keeps [`CAP_HEADROOM`] under
    /// the cap. Nothing is committed.
    pub(crate) fn next_version(
        &self,
        key: &SigningKey,
        change: impl FnOnce(&mut IdentityBody),
    ) -> Result<(IdentityDoc, Flow)> {
        self.next_version_in(key, change, Room::Headroom)
    }

    /// As [`Signer::next_version`], for a version that adds no content to what is signed
    /// already: a closing of renewals, an epoch completion, a restore's next version. Measured
    /// against the plain cap, since the headroom kept when that content was signed is there
    /// for exactly this: a digit more of `version` or `data_epoch`.
    pub(crate) fn next_version_closing(
        &self,
        key: &SigningKey,
        change: impl FnOnce(&mut IdentityBody),
    ) -> Result<(IdentityDoc, Flow)> {
        self.next_version_in(key, change, Room::Cap)
    }

    fn next_version_in(
        &self,
        key: &SigningKey,
        change: impl FnOnce(&mut IdentityBody),
        room: Room,
    ) -> Result<(IdentityDoc, Flow)> {
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let body = self.next_body_on(&newest, change, room)?;
        let doc = IdentityDoc::sign(key, body)?;
        let flow = Flow::Deliver {
            doc: doc.signed().clone(),
            prev: Some(newest.hash()),
            backup: None,
            step: DeliverStep::Signed,
        };
        Ok((doc, flow))
    }

    /// The body of the next version built on `base` with `change`, at a version above both
    /// `base`'s and every version this install signed, measured against the cap with `room`.
    /// Nothing is signed.
    fn next_body_on(
        &self,
        base: &IdentityDoc,
        change: impl FnOnce(&mut IdentityBody),
        room: Room,
    ) -> Result<IdentityBody> {
        let version = base
            .version()
            .max(self.state.signed_through)
            .checked_add(1)
            .ok_or_else(|| SignerError::Records("the version can't go higher".into()))?;
        let mut body = base.body().clone();
        body.version = version;
        body.signer = self.state.install;
        change(&mut body);
        // Never a version the switch can't take: its delivery would be over `PUT /identity`'s
        // body cap (Switch wire 7.1), and could never be delivered. Nor one whose closings
        // couldn't be: an open `renewed` entry is closed in a later version, its `null` turned
        // into a time (wire 3.3, 3.8), so the version is measured with every open entry closed.
        // Otherwise a closing owed past the cap would stop every later step. A removal, which
        // drops the app's `renewed` entries with it, makes the document smaller.
        // Nor one that couldn't move: a move's enrollment carries it again, encoded once more,
        // with the App IDs revoked (wire 3.7), so each body it travels in is measured.
        let mut closed = body.clone();
        for entry in &mut closed.renewed {
            // Every time is written at the same length, three fraction digits (wire 1.6).
            entry.until.get_or_insert(0);
        }
        // Measured as a delivery built on `base`, which a recovery's `null` is no longer than.
        let prev = Some(base.hash());
        for measure in measures(&self.state, &closed, prev)? {
            if over_cap(measure.bytes, measure.limit, room) {
                return Err(Refusal::IdentityTooLarge {
                    body: measure.body,
                    bytes: u64::try_from(measure.bytes).unwrap_or(u64::MAX),
                    limit: u64::try_from(measure.limit).unwrap_or(u64::MAX),
                }
                .into());
            }
        }
        Ok(body)
    }

    /// Refuse every signing call while another install is the signer (Switch spec 4.3).
    /// Nor while its records are behind its own newer version.
    fn check_named(&self) -> Result<()> {
        clients::Named::check(&self.state).map(drop)
    }

    /// Commit `state` and `flow`, and only then take them as the signer's own, so the signer
    /// never acts on anything the store doesn't hold. A commit the store can't tell about
    /// makes the signer read the store again before its next step.
    pub(crate) async fn commit(
        &mut self,
        mut state: SignerState,
        flow: Option<Flow>,
    ) -> Result<()> {
        if flow.is_none() {
            // A flow that ended without its version delivered leaves no certificate or claim.
            state.prune_unreferenced();
        }
        match state::save(&self.env.store, &state, flow.as_ref()).await {
            Ok(()) => {
                self.state = state;
                self.flow = flow;
                self.unsure = false;
                Ok(())
            }
            Err(SignerError::Store(StoreError::Unknown)) => {
                self.unsure = true;
                let _ = self.refresh().await;
                Err(StoreError::Unknown.into())
            }
            Err(error) => Err(error),
        }
    }

    /// After a commit the store couldn't tell about, read the records and the flow again.
    async fn refresh(&mut self) -> Result<()> {
        if self.unsure {
            let (state, flow) = state::load(&self.env.store, &self.state.identity)
                .await?
                .ok_or(Refusal::NotSetUp)?;
            self.state = state;
            self.flow = flow;
            self.unsure = false;
        }
        // A hand-over that took effect: what is left of the key and the records goes first.
        if let Some(install) = self.state.handed_over_to {
            return self.delete_handed_over(install).await;
        }
        Ok(())
    }

    fn service(&self) -> Result<Service> {
        self.state
            .service
            .clone()
            .ok_or_else(|| SignerError::Records("no switch before the enrollment".into()))
    }

    /// A client of the switch the identity is enrolled at, for requests: it signs no
    /// operation ([`crate::key::IdentityKeyring::request_signer`]).
    fn service_client(&self) -> Result<RequestClient> {
        let service = self.service()?;
        RequestClient::new(&self.env, &self.service_target(&service), &self.keyring)
    }

    /// What the call in progress may still do: a full budget when none was taken.
    pub(crate) fn allowance(&self) -> Allowance {
        let run = self.run.lock().unwrap_or_else(PoisonError::into_inner);
        run.unwrap_or(Allowance::RUN)
    }

    /// Spend from the call's budget.
    pub(crate) fn spend(&mut self, spend: impl FnOnce(&mut Allowance)) {
        let mut run = self.run.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(run) = run.as_mut() {
            spend(run);
        }
    }

    /// Take one budget for the public call that begins here, unless a call in progress holds
    /// one already, which its nested steps share. The guard returned gives it back when the
    /// call ends, or when its future is dropped part way.
    pub(crate) fn budget(&self) -> Option<BudgetGuard> {
        let mut run = self.run.lock().unwrap_or_else(PoisonError::into_inner);
        if run.is_some() {
            return None;
        }
        *run = Some(Allowance::RUN);
        Some(BudgetGuard(Arc::clone(&self.run)))
    }

    /// Whether the key a recovery in place's service served the lost generation with is
    /// pinned for the service the signer goes to ([`Signer::service_target`]).
    fn pins_the_lost_generations_key(&self) -> Result<bool> {
        let service = self.service()?;
        Ok(self
            .state
            .recovery_serving
            .as_ref()
            .is_some_and(|serving| serving.origin == service.origin))
    }

    /// While recovering, whether the service the signer goes to took a version of this
    /// recovery under a key an earlier declaration's enrollment answered there, read under
    /// each such key but the one pinned ([`Signer::taken_under_an_earlier_key`], which reads
    /// nothing unless recovering): that version is then delivered.
    async fn taken_under_a_remembered_key(&mut self) -> Result<bool> {
        let origin = self.service()?.origin;
        self.taken_under_an_earlier_key(&origin, true).await
    }

    /// Whether the service the signer goes to answers `GET /apps` under the key the version
    /// in flight names, the key its records hold for it: an error it signs counts too.
    async fn version_key_signs(&self) -> Result<bool> {
        let service = self.service()?;
        let target = Target {
            origin: &service.origin,
            pinned: Some(service.service_key),
            identity: self.state.identity,
        };
        let read = RequestClient::new(&self.env, &target, &self.keyring)?
            .apps()
            .await;
        Ok(matches!(read, Ok(_) | Err(ClientError::Switch { .. })))
    }

    /// Where the clients of the enrolled switch go. While a recovery declared in place goes
    /// to the service that served the lost generation, its answers are checked with the key
    /// it served that generation with, but the `200` of the delivery that starts the new
    /// generation, which the client checks with the pending key the version names (Switch
    /// wire 3.13, 7.4.2): no answer under a third key is taken, and none under the earlier
    /// key as the new generation's.
    fn service_target<'a>(&self, service: &'a Service) -> Target<'a> {
        let serving = self
            .state
            .recovery_serving
            .as_ref()
            .filter(|serving| serving.origin == service.origin);
        Target {
            origin: &service.origin,
            pinned: Some(serving.map_or(service.service_key, |s| s.service_key)),
            identity: self.state.identity,
        }
    }

    /// A client of the switch the identity is enrolled at that signs operations with `key`,
    /// which the signing gate handed out.
    pub(super) fn signing_client(&self, key: &SigningKey) -> Result<SigningClient> {
        let service = self.service()?;
        SigningClient::new(&self.env, &self.service_target(&service), key)
    }

    /// The identity key for this call's signing steps, through the signing gate
    /// ([`gate::signing_key`]).
    pub(crate) fn signing_key(&self) -> Result<SigningKey> {
        gate::signing_key(&self.keyring, &self.state)
    }

    /// Enroll at the switch, then sign the first `identity.json` naming it (Switch spec 4.3
    /// steps 1 to 3, Switch wire 3.7).
    async fn enroll(
        &mut self,
        origin: &str,
        signed: &SignedDoc,
        policy: IdentityPolicy,
    ) -> Result<()> {
        let identity = self.state.identity;
        let enrollment = Enrollment::verify(signed, &identity, origin)?;
        let target = Target {
            origin,
            pinned: None,
            identity,
        };
        let answer = RequestClient::new(&self.env, &target, &self.keyring)?
            .enroll(&enrollment)
            .await?;
        let key = self.signing_key()?;
        let body = IdentityBody::first(
            identity,
            self.state.install,
            Inbox::new(origin, answer.service_key),
            policy,
        );
        let doc = IdentityDoc::sign(&key, body)?;
        let mut state = self.state.clone();
        state.service = Some(Service {
            origin: origin.to_owned(),
            service_key: answer.service_key,
            limits: answer.limits,
        });
        state.signed_through = state.signed_through.max(doc.version());
        let flow = Flow::Deliver {
            doc: doc.signed().clone(),
            prev: None,
            backup: None,
            step: DeliverStep::Signed,
        };
        self.commit(state, Some(flow)).await
    }

    /// Check the backup the Homeserver holds, then write the one holding the new version
    /// (Switch wire 3.13 "When it is written", "Another install's backup").
    ///
    /// A backup that names another install at or past the high-water mark stops the signer
    /// without writing, unless it builds on what the mark built on: a losing delivery's, which
    /// is written over. So does a backup that doesn't open, or none where this signer has
    /// written one, unless the switch still holds the newest version this signer delivered:
    /// then no other install has taken over, since one that takes over delivers before it
    /// writes its backup, and the signer writes its own with an alert.
    async fn write_backup(
        &mut self,
        doc: &SignedDoc,
        prev: Option<[u8; 32]>,
        backup: Option<SignerBackup>,
    ) -> Result<()> {
        self.check_named()?;
        let backup = match backup {
            Some(backup) => backup,
            None => {
                // Sealed once and kept, so a retry writes the same bytes. Sealed and committed
                // before the check, so only the check's read comes before the write.
                let backup = self.seal_backup(doc, prev)?;
                let flow = Flow::Deliver {
                    doc: doc.clone(),
                    prev,
                    backup: Some(backup.clone()),
                    step: DeliverStep::Signed,
                };
                self.commit(self.state.clone(), Some(flow)).await?;
                backup
            }
        };
        let bytes = serde_json::to_vec(&backup).map_err(|e| SignerError::Records(e.to_string()))?;
        let raised = self.check_backup_write().await?;
        let mut state = self.state.clone();
        if let Some(alert) = raised {
            state.alert(alert);
        }
        self.env
            .homeserver
            .put(SIGNER_BACKUP_PATH, bytes)
            .await
            .map_err(SignerError::Homeserver)?;
        // A newer backup replaces one a restore owed.
        state.backup_owed = false;
        state.alerts.retain(|a| *a != Alert::BackupNotWritten);
        let flow = Flow::Deliver {
            doc: doc.clone(),
            prev,
            backup: Some(backup),
            step: DeliverStep::BackupWritten,
        };
        self.commit(state, Some(flow)).await
    }

    /// The checks before any write of this install's backup, over the one the Homeserver
    /// holds (Switch wire 3.13 "When it is written", "Another install's backup"): this
    /// install is named, and the backup there names neither another install that took over,
    /// at or past the high-water mark, nor a newer version of this install's own
    /// ([`Signer::judge_backup`]). Another install's backup that builds on what the mark built
    /// on and isn't the mark itself is a losing delivery's, whatever its version, and is
    /// written over.
    /// One that doesn't open, or none where this signer has written one, is written over only
    /// while the switch still holds the newest version this signer delivered: then no other
    /// install has taken over, since one that takes over delivers before it writes its
    /// backup. Returns the alert the write raises, if any.
    ///
    /// The Homeserver has no conditional write, so a backup written between this read and
    /// the write can't be told apart: the check narrows the race to that window.
    async fn check_backup_write(&mut self) -> Result<Option<Alert>> {
        self.check_named()?;
        let found = self
            .env
            .homeserver
            .get(SIGNER_BACKUP_PATH)
            .await
            .map_err(SignerError::Homeserver)?;
        match found {
            Some(bytes) => match self.open_backup(&bytes)? {
                Some(found) => {
                    self.judge_backup(&found).await?;
                    Ok(None)
                }
                None if self.state.newest.is_none() => {
                    // No mark yet, so no copy of the switch to judge: a staged account shows
                    // none. The backup may be another install's, so nothing is written.
                    self.unreadable_before_mark().await.map(|()| None)
                }
                // A recovery can't ask the lost service whether another install took over:
                // the Homeserver's copy is asked instead (Switch spec 12.6 step 1).
                None if self.state.recovering => self
                    .homeserver_agrees()
                    .await
                    .map(|()| Some(Alert::BackupUnreadable)),
                None => {
                    self.switch_at_mark().await?;
                    Ok(Some(Alert::BackupUnreadable))
                }
            },
            None if self.state.recovering => self
                .homeserver_agrees()
                .await
                .map(|()| Some(Alert::BackupMissing)),
            None if self.state.newest.is_some() => {
                self.switch_at_mark().await?;
                Ok(Some(Alert::BackupMissing))
            }
            None => Ok(None),
        }
    }

    /// While a recovery is in flight, the check a missing or unreadable backup is written over
    /// on: the lost service can't say whether another install took over, so the Homeserver's
    /// `identity.json`, which names the signer (Switch spec 4.3), must agree that this install
    /// signs and isn't ahead of its records. A copy that is missing or doesn't verify agrees
    /// only when the declaration waived it: the records explained it, or the user confirmed
    /// them (Switch spec 12.6 step 1).
    async fn homeserver_agrees(&mut self) -> Result<()> {
        let held = self
            .env
            .homeserver
            .get(IDENTITY_PATH)
            .await
            .map_err(SignerError::Homeserver)?;
        let waived = self.state.homeserver_copy_waived;
        let Some(bytes) = held else {
            return if waived {
                Ok(())
            } else {
                Err(Refusal::HomeserverCopyMissing.into())
            };
        };
        let copy = serde_json::from_slice::<SignedDoc>(&bytes)
            .ok()
            .and_then(|signed| IdentityDoc::verify(&signed, &self.state.identity).ok());
        let Some(copy) = copy else {
            return if waived {
                Ok(())
            } else {
                Err(Refusal::HomeserverCopyUnreadable.into())
            };
        };
        let signer = copy.body().signer;
        let mark = self.high_water().map_or(0, |h| h.version);
        // Another install's copy below the mark is one this install signed over already.
        if signer != self.state.install && copy.version() >= mark {
            return self.managed_by(signer).await;
        }
        if signer == self.state.install && copy.version() > self.state.signed_through {
            return self
                .records_behind(Source::Homeserver, copy.version())
                .await;
        }
        Ok(())
    }

    /// A backup this install can't open, found before its first version was delivered: keep
    /// the flow, so [`Signer::resume`] goes on once the backup is dealt with, and tell the
    /// user (Switch wire 3.13).
    async fn unreadable_before_mark(&mut self) -> Result<()> {
        let mut state = self.state.clone();
        state.alert(Alert::UnreadableBackupBeforeEnrollment);
        self.commit(state, self.flow.clone()).await?;
        Err(Refusal::UnreadableBackup.into())
    }

    /// Check that the switch still holds the newest version this signer delivered (`GET
    /// /apps` `identity`, Switch wire 7.4.12). Any other copy stops the flow, as
    /// [`Signer::judge_copy`] says. Returns the answer, with the device clock when it came.
    async fn switch_at_mark(&mut self) -> Result<SwitchRead> {
        let read = self.read_apps().await?;
        self.confirm_copy(read.answer.identity.as_ref()).await?;
        Ok(read)
    }

    /// `GET /apps` (Switch wire 7.4.12), for a check of the switch's copy: the answer, with the
    /// device clock when it came. A `404` the pinned key didn't sign, with no erasure of this
    /// install's in progress, raises [`Alert::AccountNotHosted`] and is returned as the error
    /// it is; the next answer the pinned key signs clears it, an error included. Never raised
    /// once the account is erased. Nothing else changes: an unauthenticated `404` with no
    /// request in doubt is never an erasure (Switch wire 7.4.16).
    pub(crate) async fn read_apps(&mut self) -> Result<SwitchRead> {
        let read = self.service_client()?.apps().await;
        // The device clock when the answer came, before the alert's commit below, so a step
        // judging the clock against the answer's time isn't off by that commit.
        let device_ms = self.env.clock.now_ms();
        let raised = self.state.alerts.contains(&Alert::AccountNotHosted);
        // An erasure in progress judges the `404` itself (Switch wire 7.4.16).
        let erasing = matches!(self.flow, Some(Flow::Erase { .. }));
        // Any answer the pinned key signs, an error included, shows the account hosted: it
        // clears the alert, and ends an erasure's wait for the operator's `404` to hold, here
        // where it arrives, whatever the step that read it does next (Switch wire 7.3 step 2,
        // 7.4.16).
        let signed = matches!(
            &read,
            Ok(_) | Err(ClientError::Switch { .. } | ClientError::InvalidResponse(_))
        );
        let raise = match &read {
            _ if signed && raised => Some(false),
            Err(ClientError::BadServiceSignature { status: 404 })
                if !raised && !erasing && !self.state.erased =>
            {
                Some(true)
            }
            _ => None,
        };
        let mut state = self.state.clone();
        match raise {
            Some(true) => state.alert(Alert::AccountNotHosted),
            Some(false) => state
                .alerts
                .retain(|alert| *alert != Alert::AccountNotHosted),
            None => {}
        }
        // Whether the end of a staged admission is owed is the switch's to say (Switch wire
        // 7.4.12 `recovery`), so a restore or a take-over finds it too: owed while the wait is
        // staged and no listed app could end it, or the user asked; never once it ended or
        // without a recovery (Switch spec 12.6 step 2).
        if let Ok(answer) = &read {
            match &answer.recovery {
                Some(recovery) if recovery.admission_staged => {
                    if let Some(newest) = state.newest_doc()?
                        && !self.listed_may_manage_lists(&newest)?
                    {
                        state.admission_owed = true;
                    }
                }
                _ => {
                    state.admission_owed = false;
                    state
                        .alerts
                        .retain(|alert| *alert != Alert::AdmissionNotEnded);
                }
            }
        }
        let mut flow = self.flow.clone();
        if signed && let Some(Flow::Erase { first_404_ms, .. }) = flow.as_mut() {
            *first_404_ms = None;
        }
        if state != self.state || flow != self.flow {
            self.commit(state, flow).await?;
        }
        Ok(SwitchRead {
            answer: read?,
            device_ms,
        })
    }

    /// Judge the switch's copy of `identity.json`, `held` as `GET /apps` gave it, against the
    /// mark: its own version goes on; a newer one is adopted and an older one, none or another
    /// body at the mark raises the alarm, and either stops the flow (Switch spec 4.3).
    pub(crate) async fn confirm_copy(
        &mut self,
        held: Option<&pubky_switch_core::sig::SignedDoc>,
    ) -> Result<()> {
        let copy = match held {
            Some(signed) => Some(IdentityDoc::verify(signed, &self.state.identity)?),
            None => None,
        };
        match self.judge_copy(copy.as_ref()) {
            Ok(Verdict::AtMark) => {
                // The switch's own copy, authenticated with its pinned key and verified for
                // the identity, is the mark's document: it confirms the switch as a delivery
                // does, once no alarm's alert is held (Switch spec 4.3).
                let mark = self.state.newest_doc()?.map(|doc| doc.hash());
                let same = copy.as_ref().is_some_and(|c| Some(c.hash()) == mark);
                if same && self.state.switch_unconfirmed && gate::held_alarm(&self.state).is_none()
                {
                    let mut state = self.state.clone();
                    state.switch_unconfirmed = false;
                    self.commit(state, self.flow.clone()).await?;
                }
                Ok(())
            }
            Ok(Verdict::Newer) => match copy {
                Some(copy) => self.adopt(copy, Source::Switch).await,
                None => Ok(()),
            },
            Err(alert) => self.alarm(alert).await,
        }
    }

    /// Check that this install still signs before a write at the switch: it is named, the
    /// switch's copy is its mark, and the backup on the Homeserver names neither another
    /// install that took over nor a newer version of this install's own (Switch spec 4.3,
    /// 12.8; Switch wire 3.13). Returns the switch's answer that showed its copy.
    pub(crate) async fn ensure_signer(&mut self) -> Result<SwitchRead> {
        self.check_named()?;
        let read = self.switch_at_mark().await?;
        self.check_backup_copy().await?;
        Ok(read)
    }

    /// Read the signer backup on the Homeserver and stop at one that shows another install
    /// took over, or a newer version of this install's own ([`Signer::judge_backup`]).
    pub(crate) async fn check_backup_copy(&mut self) -> Result<()> {
        let found = self
            .env
            .homeserver
            .get(SIGNER_BACKUP_PATH)
            .await
            .map_err(SignerError::Homeserver)?;
        // A backup that doesn't open, or none, is the backup write's to judge.
        if let Some(found) = found.and_then(|bytes| self.open_backup(&bytes).transpose()) {
            self.judge_backup(&found?).await?;
        }
        Ok(())
    }

    /// The records a backup holds, opened with the identity key; `None` for one that doesn't
    /// read, open or verify.
    fn open_backup(&self, bytes: &[u8]) -> Result<Option<BackupView>> {
        let Ok(backup) = serde_json::from_slice::<SignerBackup>(bytes) else {
            return Ok(None);
        };
        Ok(self.keyring.open_backup(&backup)?)
    }

    /// Seal the signer's records, holding `doc`, to the backup key (Switch wire 3.13). The
    /// identity secret goes into it, so it is the backup's export (Switch spec 12.8).
    fn seal_backup(&self, doc: &SignedDoc, prev: Option<[u8; 32]>) -> Result<SignerBackup> {
        let identity = self.state.identity;
        let doc = IdentityDoc::verify(doc, &identity)?;
        let issued = self
            .state
            .certs
            .iter()
            .map(|cert| AppCert::verify(cert, &identity))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let limits = self.service()?.limits;
        // Sealing signs the backup, so it takes the gated key: a recovery's, while one is
        // delivered (Switch spec 12.6 step 1).
        let key = if self.state.recovering {
            gate::recovery_key(&self.keyring, &self.state)?
        } else {
            self.signing_key()?
        };
        Ok(key.seal_backup(
            doc,
            &self.state.tombstones,
            &issued,
            limits,
            &self.state.bundle_parts,
            prev,
            &self.state.picked_distrust(),
        )?)
    }

    /// Deliver the new version (Switch wire 7.4.2) and take the answer.
    async fn deliver(&mut self, doc: SignedDoc, prev: Option<[u8; 32]>) -> Result<()> {
        self.check_named()?;
        let delivery = IdentityDelivery {
            identity: doc.clone(),
            prev,
        };
        match self.service_client()?.put_identity(&delivery).await {
            Ok(answer) => {
                let delivered_at = answer
                    .proofs
                    .first()
                    .and_then(|proof| proof.body().chain.open().ok())
                    .map(|envelope| envelope.server_time);
                self.delivered(doc, prev, delivered_at).await
            }
            Err(ClientError::Switch {
                code: ErrorCode::StaleIdentity,
                current,
                ..
            }) => self.stale(&current, doc, prev).await,
            // The key the lost generation served with is pinned in place, and an answer other
            // than a `200` it didn't sign may be the service's under the key the version names:
            // that version was taken, by this install or another, or the account is one the
            // enrollment made, so the lost generation is served no more (Switch wire 7.4.2).
            // One read under that key tells: an answer it signs ends the earlier key's pin, and
            // the delivery is sent again under it. Nothing else is taken from that read, and
            // once the pin is gone this read isn't made again.
            Err(error @ ClientError::BadServiceSignature { status })
                if status != 200 && self.pins_the_lost_generations_key()? =>
            {
                if self.version_key_signs().await? {
                    let mut state = self.state.clone();
                    state.recovery_serving = None;
                    return self.commit(state, self.flow.clone()).await;
                }
                // Not the version's key either: it may still be the key an earlier
                // declaration's enrollment answered here, as below. The service refuses a
                // version of this recovery sent after it took an earlier one with `409`,
                // `stale_identity` or `conflict`, and the read is made whatever the refusal.
                // So one failed delivery reads `GET /apps` at most 1 + R times after its send:
                // once under the version's key, once under each of the R keys earlier
                // declarations' enrollments answered at this service.
                if self.taken_under_a_remembered_key().await? {
                    return Ok(());
                }
                Err(error.into())
            }
            // A refusal the pinned key didn't sign, while recovering at a service an earlier
            // declaration enrolled at: one that took that version answers under the key it
            // serves, so it is read under that key (Switch wire 3.7, 7.4.2).
            Err(error @ ClientError::BadServiceSignature { status: 409 })
                if self.state.recovering =>
            {
                if self.taken_under_a_remembered_key().await? {
                    return Ok(());
                }
                Err(error.into())
            }
            Err(
                error @ ClientError::Switch {
                    status: 400 | 413, ..
                },
            ) => {
                // A definite refusal, a `400` or a `413 too_large` (Switch wire 7.1): the same
                // bytes would be refused again. The version stays spent (`signed_through`). A
                // renewal it carried didn't happen, and the user is told in the same commit.
                let mut state = self.state.clone();
                self.note_refused_renewals(&mut state, &doc)?;
                self.commit(state, None).await?;
                Err(error.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// The switch took `doc`, built on `prev`, at the service time `delivered_at` when its
    /// answer gave one: it is the mark. An abort that won ends the hand-over (Switch wire
    /// 3.12).
    async fn delivered(
        &mut self,
        doc: SignedDoc,
        prev: Option<[u8; 32]>,
        delivered_at: Option<u64>,
    ) -> Result<()> {
        let mut state = self.state.clone();
        let verified = IdentityDoc::verify(&doc, &state.identity);
        // A recovery's version, the only delivery while one is declared: the new service's
        // account is the one served from here (Switch spec 12.6 step 1). Whether the end of
        // its staged admission is owed, the next `GET /apps` says, publication's check first.
        if state.recovering
            && let Ok(delivered) = &verified
        {
            Self::recovered_in(&mut state, delivered);
        }
        if let (Some(at), Ok(delivered)) = (delivered_at, &verified) {
            for app in &delivered.body().apps {
                if !state.listed_at.iter().any(|(id, _)| *id == app.app_id) {
                    state.listed_at.push((app.app_id, at));
                }
            }
        }
        if let Ok(delivered) = &verified
            && let Some(handing) = state.handing_over.clone()
        {
            // The abort or the take-back won: the hand-over is over, and this install signs
            // again, so an alert that another install manages the identity no longer holds
            // (Switch wire 3.12).
            let take_back = handing.take_back.filter(|t| t.doc == doc);
            if handing.abort == Some(delivered.hash()) || take_back.is_some() {
                state.handing_over = None;
                state
                    .alerts
                    .retain(|a| !matches!(a, Alert::ManagedByOtherInstall { .. }));
            }
            if let Some(take_back) = take_back {
                state.alert(Alert::TakenBack {
                    from: take_back.from,
                });
            }
        }
        // A refused renewal is told of until a renewal the user asked for is delivered for
        // the app, or a version removing it: an automatic renewal keeps the scopes the user
        // may have asked to remove (Switch spec 3.2).
        if let Ok(delivered) = &verified {
            let renewed_by_user = std::mem::take(&mut state.user_renewals);
            let before = state.newest_doc()?;
            let asked = state.asked_renewals.clone();
            let certs = self.held_certs()?;
            state.alerts.retain(|alert| match alert {
                Alert::RenewalRefused {
                    app_id, by_user, ..
                } => delivered.listed_cert(app_id).is_some_and(|now| {
                    if !*by_user {
                        // An automatic renewal's: until the app is renewed.
                        return before.as_ref().and_then(|b| b.listed_cert(app_id)) == Some(now);
                    }
                    // The user's: judged from the certificate listed now, whoever renewed it.
                    let Some(asked) = asked.iter().find(|a| a.app_id == *app_id) else {
                        return true;
                    };
                    let met = certs
                        .iter()
                        .find(|cert| cert.hash() == now)
                        .is_some_and(|cert| asked.met_by(cert));
                    // Another renewal the user asks for, delivered, ends one that reduces
                    // nothing: it is the user's newest choice.
                    let superseded =
                        !asked.reduction() && renewed_by_user.contains(&(*app_id, now));
                    !(met || superseded)
                }),
                _ => true,
            });
            renewal::keep_asked_with_alerts(&mut state);
        }
        // How close the version comes to the most a delivery, or a move's enrollment, may
        // carry (Switch wire 3.7, 7.1).
        let nearest = version_size(&state, &doc, prev)?;
        state.note_size(nearest.bytes, nearest.limit);
        let published = state
            .newest
            .as_ref()
            .is_some_and(|n| n.doc == doc && n.published);
        state.newest = Some(Newest {
            doc,
            prev,
            published,
            delivered_at,
        });
        // The switch took this version, built on the one before: it holds the mark.
        state.switch_unconfirmed = false;
        self.commit(state, None).await
    }

    /// `409 stale_identity`: the switch holds another version than the one this delivery
    /// builds on, and its answer carries the copy, or `null` when it holds none (Switch wire
    /// 3.3 "Never back", 7.4.2). The delivery is over whatever the copy is. A copy that is
    /// `doc` itself means the switch took it, and the answer that said so was lost.
    async fn stale(
        &mut self,
        current: &Value,
        doc: SignedDoc,
        prev: Option<[u8; 32]>,
    ) -> Result<()> {
        let copy = match current.get("identity") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let verified = serde_json::from_value::<SignedDoc>(value.clone())
                    .map_err(|e| pubky_switch_core::Error::Invalid(e.to_string()))
                    .and_then(|signed| IdentityDoc::verify(&signed, &self.state.identity));
                match verified {
                    Ok(copy) => Some(copy),
                    Err(error) => {
                        let mut state = self.state.clone();
                        self.note_refused_renewals(&mut state, &doc)?;
                        self.commit(state, None).await?;
                        return Err(error.into());
                    }
                }
            }
        };
        if copy.as_ref().is_some_and(|copy| copy.signed() == &doc) {
            return self.delivered(doc, prev, None).await;
        }
        if let Some(copy) = copy.as_ref().filter(|copy| self.own_recovery_version(copy)) {
            return self.own_recovery_held(copy.clone()).await;
        }
        match self.judge_copy(copy.as_ref()) {
            Err(alert) => self.alarm(alert).await,
            Ok(Verdict::Newer) => match copy {
                Some(copy) => self.adopt(copy, Source::Switch).await,
                None => {
                    self.commit(self.state.clone(), None).await?;
                    Err(stale_without_copy())
                }
            },
            Ok(Verdict::AtMark) => {
                // The switch holds the version this delivery builds on, yet refused it. A
                // renewal it carried didn't happen (Switch spec 3.2).
                let mut state = self.state.clone();
                self.note_refused_renewals(&mut state, &doc)?;
                self.commit(state, None).await?;
                Err(stale_without_copy())
            }
        }
    }

    /// Whether `copy`, while a recovery is in progress, is a version of that recovery this
    /// install signed: its own, declaring the same generation lost, at a version it spent
    /// (Switch spec 12.6 step 1), as an earlier declaration's version the service took, its
    /// answer lost; or, after a restore mid-recovery, the backup's version it was restored
    /// from.
    pub(super) fn own_recovery_version(&self, copy: &IdentityDoc) -> bool {
        // A restore's recovery is built on the backup's version itself, which the install
        // the backup came from signed (Switch wire 3.13).
        let restored = self.state.recovery_base.as_ref().is_some_and(|base| {
            base == copy.signed()
                && copy.body().recovery_from.is_some()
                && copy.body().recovery_from == self.state.lost_generation
        });
        self.state.recovering
            && (restored
                || (copy.body().signer == self.state.install
                    && copy.body().recovery_from.is_some()
                    && copy.body().recovery_from == self.state.lost_generation
                    && copy.version() <= self.state.signed_through))
    }

    /// The service holds `copy`, a version of the recovery in progress ([`Signer::
    /// own_recovery_version`]): naming that service and the key pinned for it, the one its
    /// answer verified with, it is the recovery's version delivered, as its answer would have
    /// said. Naming another, it was taken elsewhere and this delivery is over: the recovery
    /// waits to be declared again. Never records behind: this install signed it for this
    /// recovery.
    pub(super) async fn own_recovery_held(&mut self, copy: IdentityDoc) -> Result<()> {
        let names_it = self.state.service.as_ref().is_some_and(|service| {
            service.origin == copy.inbox().url && service.service_key == copy.inbox().service_key
        });
        if !names_it {
            self.commit(self.state.clone(), None).await?;
            return Err(stale_without_copy());
        }
        self.delivered(copy.signed().clone(), None, None).await
    }

    /// Judge a copy of `identity.json` from the switch against the high-water mark (Switch
    /// spec 4.3, Switch wire 3.3 "Never back"): an older copy, or none under a mark, is a
    /// rollback, and another body at the mark's version is equivocation.
    fn judge_copy(&self, copy: Option<&IdentityDoc>) -> std::result::Result<Verdict, Alert> {
        let Some(high) = self.high_water() else {
            return Ok(Verdict::Newer);
        };
        let Some(copy) = copy else {
            return Err(Alert::Rollback {
                source: Source::Switch,
                version: None,
                generation: None,
                high_water_version: high.version,
            });
        };
        if copy.version() < high.version || copy.generation() < high.generation {
            return Err(Alert::Rollback {
                source: Source::Switch,
                version: Some(copy.version()),
                generation: Some(copy.generation()),
                high_water_version: high.version,
            });
        }
        if copy.version() == high.version {
            if copy.body_hash() != high.body_hash {
                return Err(Alert::Equivocation {
                    source: Source::Switch,
                    version: high.version,
                });
            }
            return Ok(Verdict::AtMark);
        }
        Ok(Verdict::Newer)
    }

    /// Take a strictly newer copy from `source`, ending the flow (Switch spec 4.3). Another
    /// signer's is adopted, and it isn't this install's to publish. This install's own means
    /// its records are behind: nothing it holds accounts for that version, so it is neither
    /// adopted nor signed over, and this install stops until a restore from the signer
    /// backup.
    ///
    /// While a hand-over is in progress (Switch wire 3.12), the switch's copy of this
    /// install's own abort or take-back means that delivery won. Another install's newer
    /// version from the switch is the proof that it took the identity only with that install's
    /// backup on the Homeserver ([`Signer::succeeded`]); then the key and the records are
    /// deleted. Any other newer copy stops this install as one that isn't named, keeping the
    /// key and the hand-over, which it looks at again at each run.
    async fn adopt(&mut self, copy: IdentityDoc, source: Source) -> Result<()> {
        let version = copy.version();
        let signer = copy.body().signer;
        if self.state.handing_over.is_some() {
            if source == Source::Switch {
                if let Some(prev) = self.own_hand_over_delivery(&copy) {
                    return self
                        .delivered(copy.signed().clone(), Some(prev), None)
                        .await;
                }
                if self.succeeded_by(&copy) {
                    return self.succeeded(&copy).await;
                }
            }
            if signer != self.state.install {
                return Err(Refusal::SuccessorUnproven { install: signer }.into());
            }
        }
        if signer == self.state.install {
            return self.records_behind(source, version).await;
        }
        let mut state = self.state.clone();
        state.handing_over = None;
        state.newest = Some(Newest {
            doc: copy.signed().clone(),
            prev: None,
            published: true,
            delivered_at: None,
        });
        state.signed_through = state.signed_through.max(version);
        state.backup_owed = false;
        state.managed_by = Some(signer);
        state.alert(Alert::ManagedByOtherInstall { install: signer });
        // An erasure in progress ends without erasing, in the same commit (Switch spec 12.7).
        self.end_erasure_in(&mut state)?;
        self.commit(state, None).await?;
        Err(SignerError::NotNamed { install: signer })
    }

    /// A newer version of this install's own, `version`, seen at `source`: its records are
    /// behind, and it signs nothing more until a restore, ending the flow.
    async fn records_behind(&mut self, source: Source, version: u64) -> Result<()> {
        let mut state = self.state.clone();
        // A backup owed would hold the older records: the one there is newer.
        state.backup_owed = false;
        state.records_behind = Some(version);
        state.signed_through = state.signed_through.max(version);
        state.alert(Alert::RecordsBehind {
            source,
            version,
            high_water_version: self.high_water().map_or(0, |h| h.version),
        });
        self.commit(state, self.erasure_kept()).await?;
        Err(Refusal::RecordsBehind { version }.into())
    }

    /// Another install is the signer: this one stops signing (Switch spec 4.3, 12.8).
    async fn managed_by(&mut self, install: [u8; 16]) -> Result<()> {
        let mut state = self.state.clone();
        // Another install's backup is never written over.
        state.backup_owed = false;
        state.managed_by = Some(install);
        state.alert(Alert::ManagedByOtherInstall { install });
        // An erasure in progress ends without erasing, in the same commit (Switch spec 12.7).
        self.end_erasure_in(&mut state)?;
        self.commit(state, None).await?;
        Err(SignerError::NotNamed { install })
    }

    /// Keep `alert` and end the flow: the signer doesn't build on what it saw. An erasure in
    /// progress is kept ([`Signer::erasure_kept`]).
    async fn alarm(&mut self, alert: Alert) -> Result<()> {
        let mut state = self.state.clone();
        state.alert(alert.clone());
        state.switch_unconfirmed = true;
        // The flow ends, a renewal it carried with it: the user is told it didn't happen
        // (Switch spec 3.2).
        if let Some(Flow::Renew { doc, .. } | Flow::Deliver { doc, .. }) = &self.flow {
            self.note_refused_renewals(&mut state, doc)?;
        }
        self.commit(state, self.erasure_kept()).await?;
        Err(SignerError::Alarm(alert))
    }

    /// The flow an alarm or records behind keep: an erasure in progress, whose request may be
    /// in doubt, in the same commit, so neither a crash nor another caller loses it; any other
    /// flow ends (Switch spec 12.7). The signing gate holds the erasure's steps back meanwhile.
    fn erasure_kept(&self) -> Option<Flow> {
        self.flow
            .clone()
            .filter(|flow| matches!(flow, Flow::Erase { .. }))
    }

    /// Publish the newest version again where the Homeserver's copy is older, missing or
    /// doesn't verify (Switch wire 3.3 "Deliver, then publish"; design note, section 4.5 step
    /// 9). It passes the gate of every signing step first ([`Signer::ready`]): this install
    /// is the one named, the switch holds its newest version, no alarm is held, no hand-over
    /// or take-over is in progress (Switch wire 3.12), and the copies were judged, so another
    /// body at that version stays the alarm and a newer copy stops this install. Only a
    /// version published already is published again: the first publication is
    /// [`Signer::publish`]'s, which a take-over's first version passes only once its backup is
    /// written. A write that fails is tried again at the next run. Returns whether it wrote,
    /// failed or not.
    pub(super) async fn republish(&mut self) -> Result<bool> {
        self.ready().await?;
        let Some(newest) = self.state.newest.clone() else {
            return Ok(false);
        };
        if !newest.published {
            return Ok(false);
        }
        let mine = IdentityDoc::verify(&newest.doc, &self.state.identity)?;
        if self.judge_homeserver(&mine).await? {
            return Ok(false);
        }
        let bytes =
            serde_json::to_vec(&newest.doc).map_err(|e| SignerError::Records(e.to_string()))?;
        let _ = self.env.homeserver.put(IDENTITY_PATH, bytes).await;
        Ok(true)
    }

    /// Publish the newest version on the Homeserver once the switch accepted it (Switch spec
    /// 4.3: deliver first, publish after).
    async fn publish(&mut self) -> Result<()> {
        let Some(newest) = self.state.newest.clone() else {
            return Ok(());
        };
        if newest.published || self.state.managed_by.is_some() {
            return Ok(());
        }
        // A take-over's first version waits for its backup (Switch wire 3.12).
        if self.state.publish_after_backup && self.state.backup_owed {
            return Ok(());
        }
        // A publication may come after a crash, once another install has signed and published
        // since: it goes out only while this install still signs and the Homeserver holds
        // nothing newer (Switch spec 4.3).
        self.switch_at_mark().await?;
        let mine = IdentityDoc::verify(&newest.doc, &self.state.identity)?;
        let already = self.judge_homeserver(&mine).await?;
        // A recovery's version, the one version delivered while an alarm may be held, waits
        // for the user to clear it, as a publication over another body does (Switch spec 12.6
        // step 1): only the switch's alarms go with the lost service.
        if !already && gate::held_alarm(&self.state).is_some() {
            return Ok(());
        }
        if !already {
            let bytes =
                serde_json::to_vec(&newest.doc).map_err(|e| SignerError::Records(e.to_string()))?;
            self.env
                .homeserver
                .put(IDENTITY_PATH, bytes)
                .await
                .map_err(SignerError::Homeserver)?;
        }
        let mut state = self.state.clone();
        state.newest = Some(Newest {
            published: true,
            ..newest
        });
        state.homeserver_other = None;
        state.republish_over = None;
        state.ever_published = true;
        self.commit(state, self.flow.clone()).await
    }
}

/// What a copy of `identity.json` is, next to the high-water mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// The mark's own version.
    AtMark,
    /// Strictly newer, or any copy before there is a mark.
    Newer,
}

/// One body a version must fit in, measured (Switch wire 3.7, 7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Measure {
    /// The body.
    pub(super) body: SizedBody,
    /// Its size with the version in it, in bytes.
    pub(super) bytes: usize,
    /// Its cap, in bytes.
    pub(super) limit: usize,
}

/// Every body the version `body`, built on `prev`, must later fit in, for the records
/// `state`, each with its own cap (Switch wire 3.7, 7.1): its delivery, `PUT /identity`, and
/// a move's enrollment carrying it, `POST /enroll`, with every App ID revoked, those of
/// `state` and of the version's `removed`, and those of the apps it lists, as if revoked
/// already, at the longest origin a switch may have, since the one a move goes to isn't known
/// yet. The one measure both the check before signing and the near-limit alert use. The
/// delivery is measured as sent, byte for byte; the enrollment is an upper bound, above a
/// real move's by the listed apps' IDs, so removing an app, or a tombstone committed before
/// the version that removes it, never grows it. The version's signed form is measured from
/// its body, with a signature of the length every signature has: nothing is signed to
/// measure it.
pub(super) fn measures(
    state: &SignerState,
    body: &IdentityBody,
    prev: Option<[u8; 32]>,
) -> Result<Vec<Measure>> {
    // A signed form of `json`, as long as a signed one: every signature is 64 bytes.
    let carried = |json: &[u8]| SignedDoc {
        body: pubky_switch_core::enc::b64(json),
        sig: pubky_switch_core::enc::b64(&[0; 64]),
    };
    let doc = carried(&body.to_json()?);
    let mut measured = Vec::new();
    if let Some(limit) = identity_limit() {
        let delivery = IdentityDelivery {
            identity: doc.clone(),
            prev,
        };
        measured.push(Measure {
            body: SizedBody::Delivery,
            bytes: delivery.to_json().len(),
            limit,
        });
    }
    if let Some(limit) = enrollment_limit() {
        let mut revoked = state.tombstones.clone();
        revoked.extend(body.removed.iter().map(|removed| removed.app_id));
        // And every app the version lists, as if revoked already: a later removal moves its
        // App ID into `revoked_apps`, which an enrollment carries whatever the version
        // shrinks to, and a tombstone committed before its removal is signed, as a revocation
        // commits it, adds nothing then. So the measure is an upper bound, by these IDs.
        revoked.extend(body.apps.iter().map(|listed| listed.app_id));
        revoked.sort_unstable();
        revoked.dedup();
        let enrollment = EnrollmentBody {
            identity: state.identity,
            origin: "a".repeat(pubky_switch_core::net::MAX_ORIGIN_LEN),
            nonce: [0; 16],
            policy: body.policy,
            identity_doc: Some(doc),
            revoked_apps: (!revoked.is_empty()).then_some(revoked),
        };
        // The request's body: `{"enrollment":<signed enrollment>}` (Switch wire 7.4.1).
        let request = serde_json::json!({ "enrollment": carried(&enrollment.to_json()?) });
        measured.push(Measure {
            body: SizedBody::Enrollment,
            bytes: request.to_string().len(),
            limit,
        });
    }
    Ok(measured)
}

/// The measure of the version signed as `doc`, built on `prev`, that comes nearest its cap,
/// for the near-limit alert ([`measures`]). A document that doesn't verify, which no caller
/// passes, is measured as its delivery alone: the alert never stops a delivery from being
/// recorded.
pub(super) fn version_size(
    state: &SignerState,
    doc: &SignedDoc,
    prev: Option<[u8; 32]>,
) -> Result<Measure> {
    let Ok(verified) = IdentityDoc::verify(doc, &state.identity) else {
        let delivery = IdentityDelivery {
            identity: doc.clone(),
            prev,
        };
        return Ok(Measure {
            body: SizedBody::Delivery,
            bytes: delivery.to_json().len(),
            limit: identity_limit().unwrap_or(usize::MAX),
        });
    };
    measures(state, verified.body(), prev)?
        .into_iter()
        // The larger share of its cap, compared without division.
        .max_by(|a, b| {
            a.bytes
                .saturating_mul(b.limit)
                .cmp(&b.bytes.saturating_mul(a.limit))
        })
        .ok_or_else(|| SignerError::Records("no body to measure the version in".into()))
}

/// Room kept under the cap for what a later version adds to one measured now without any
/// change of content: a digit more of `version`, and of `data_epoch` in a rotation, as each
/// rolls over (99 to 100), and the closing's own `version`. A few bytes once encoded (Switch
/// wire 2.2); without it, a version signed at the cap leaves its closing over it, and an owed
/// reduction closing then blocks every signing step.
const CAP_HEADROOM: usize = 16;

/// The most certificates one call renews by itself, the soonest to expire first: the rest are
/// renewed at the next run, which half a lifetime leaves months for (design note, section
/// 4.5). Each renewal is a few requests: its read, its `cert.put` and key bundle parts, its
/// delivery and its publication.
pub(crate) const RENEWALS_PER_RUN: usize = 4;

/// The most full-bundle requests one call answers, the oldest first: the rest are answered at
/// the next run, and an app asking again goes behind the others (design note, section 4.5).
pub(crate) const FULL_BUNDLES_PER_RUN: usize = 4;

/// The most removed apps' records one call deletes from the Homeserver, each one request: the
/// rest stay owed, deleted at the next run (design note, section 4.5).
pub(crate) const RECORD_DELETIONS_PER_RUN: usize = 32;

/// Empties the call's budget when dropped ([`Signer::budget`]).
pub(crate) struct BudgetGuard(Arc<Mutex<Option<Allowance>>>);

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

/// What one run, or one call outside a run, may still do (design note, section 4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Allowance {
    /// Certificates renewed by themselves.
    pub(crate) renewals: usize,
    /// Full-bundle requests answered.
    pub(crate) full_bundles: usize,
    /// Removed apps' records deleted, or tried.
    pub(crate) deletions: usize,
    /// Owed deletions checked, or tried.
    pub(crate) checks: usize,
}

impl Allowance {
    /// One run's.
    pub(crate) const RUN: Self = Self {
        renewals: RENEWALS_PER_RUN,
        full_bundles: FULL_BUNDLES_PER_RUN,
        deletions: RECORD_DELETIONS_PER_RUN,
        checks: DELETION_CHECKS_PER_RUN,
    };
}

/// The most owed deletions one run checks on the Homeserver, each one request: the rest at
/// the next run (design note, section 4.5).
pub(crate) const DELETION_CHECKS_PER_RUN: usize = 32;

/// How long, on the device clock, [`Signer::run_due`] goes on starting its later steps: once
/// this has passed since the run began, it starts none, and they come at the next run. The
/// step in progress finishes its unit of work; each step's own work is bounded too.
pub(crate) const RUN_DUE_STEPS_MS: u64 = 30_000;

/// How much room a version must leave under the cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Room {
    /// A version that adds content keeps [`CAP_HEADROOM`].
    Headroom,
    /// A version that only closes or completes what is signed already may use the headroom.
    Cap,
}

/// Whether a delivery of `bytes` is too close to the cap `limit` to sign: over it, or, for a
/// version that adds content, within [`CAP_HEADROOM`] of it (Switch wire 7.1).
fn over_cap(bytes: usize, limit: usize, room: Room) -> bool {
    let headroom = match room {
        Room::Headroom => CAP_HEADROOM,
        Room::Cap => 0,
    };
    bytes.saturating_add(headroom) > limit
}

/// The body cap of `PUT /identity` (Switch wire 7.1).
pub(crate) fn identity_limit() -> Option<usize> {
    pubky_switch_core::http::body_cap("PUT", "/v1/id/identity")
}

/// The body cap of `POST /enroll` (Switch wire 3.7, 7.1).
fn enrollment_limit() -> Option<usize> {
    pubky_switch_core::http::body_cap("POST", "/v1/enroll")
}

fn stale_without_copy() -> SignerError {
    SignerError::InvalidData(pubky_switch_core::Error::Invalid(
        "Switch wire 7.4.2: stale_identity without a newer copy than the one built on".into(),
    ))
}

/// A `GET /apps` answer whose copy of `identity.json` a check confirmed, and the device clock
/// when it arrived. A step that judges the device clock against the answer's `server_time`
/// uses `device_ms`, not the clock after the reads that followed it, so a slow read can't
/// widen the clock tolerance (Switch spec 10.1).
pub(crate) struct SwitchRead {
    /// The answer.
    pub(crate) answer: AppsAnswer,
    /// The device clock when the answer arrived.
    pub(crate) device_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_cap_keeps_its_headroom() {
        let limit = identity_limit().unwrap();
        assert!(!over_cap(limit - CAP_HEADROOM, limit, Room::Headroom));
        assert!(over_cap(limit - CAP_HEADROOM + 1, limit, Room::Headroom));
        assert!(over_cap(limit, limit, Room::Headroom));
        // A closing may use the headroom, not more.
        assert!(!over_cap(limit, limit, Room::Cap));
        assert!(over_cap(limit + 1, limit, Room::Cap));
    }

    #[test]
    fn test_identity_headroom_holds_a_roll_over() {
        // A version measured at 99, data epoch 99, its renewal open; its closing at version
        // 100, data epoch 100 in a rotation: the delivery grows, by no more than the
        // headroom kept for it.
        let key = pubky_switch_core::keys::IdentityKey::from_secret([3; 32]);
        let mut body = IdentityBody::first(
            key.public(),
            [4; 16],
            Inbox {
                url: "https://switch.example".into(),
                service_key: [5; 32],
            },
            IdentityPolicy::default(),
        );
        body.renewed.push(pubky_switch_core::records::RenewedCert {
            app_id: [6; 16],
            cert: [7; 32],
            until: Some(0),
        });
        let measure = |version: u64, epoch: u64| {
            let mut at = body.clone();
            at.version = version;
            at.data_epoch = epoch;
            let state = SignerState::new(key.public(), [4; 16]);
            measures(&state, &at, Some([8; 32])).unwrap()
        };
        for (before, after) in [(9, 10), (99, 100), (999, 1000), (9_999, 10_000)] {
            for (measured, closing) in measure(before, before)
                .into_iter()
                .zip(measure(after, after))
            {
                assert!(closing.bytes > measured.bytes);
                assert!(
                    closing.bytes - measured.bytes <= CAP_HEADROOM,
                    "{before}: {measured:?} to {closing:?}"
                );
            }
        }
    }

    #[test]
    fn test_identity_measures_are_the_bodies_as_sent() {
        // The sizes `next_version` checks before signing: the delivery's, byte for byte, and a
        // move's enrollment's at the longest origin a switch may have, with every App ID
        // revoked, those of the records and of `removed`, and those of the listed apps, as if
        // revoked already. So it is never below a real move's, and above it by those IDs.
        let key = pubky_switch_core::keys::IdentityKey::from_secret([3; 32]);
        let mut body = IdentityBody::first(
            key.public(),
            [4; 16],
            Inbox {
                url: "https://switch.example".into(),
                service_key: [5; 32],
            },
            IdentityPolicy::default(),
        );
        // A departed app the records don't hold yet, beside one they do.
        for app_id in [[9; 16], [11; 16]] {
            body.removed.push(pubky_switch_core::records::RemovedApp {
                app_id,
                distrust_from: 0,
            });
        }
        body.apps.push(pubky_switch_core::records::ListedApp {
            app_id: [12; 16],
            cert: [13; 32],
        });
        let mut state = SignerState::new(key.public(), [4; 16]);
        state.tombstones = vec![[9; 16], [10; 16]];
        let doc = IdentityDoc::sign(&key, body.clone()).unwrap();
        let delivery = IdentityDelivery {
            identity: doc.signed().clone(),
            prev: Some([6; 32]),
        };
        let host = format!(
            "{}.example",
            "a".repeat(pubky_switch_core::net::MAX_DOMAIN_LEN - 8)
        );
        let origin = format!("https://{host}:65535");
        assert_eq!(origin.len(), pubky_switch_core::net::MAX_ORIGIN_LEN);
        let request = |revoked: Vec<[u8; 16]>| {
            let enrollment = pubky_switch_core::records::Enrollment::sign(
                &key,
                EnrollmentBody {
                    identity: key.public(),
                    origin: origin.clone(),
                    nonce: [1; 16],
                    policy: body.policy,
                    identity_doc: Some(doc.signed().clone()),
                    revoked_apps: Some(revoked),
                },
            )
            .unwrap();
            serde_json::json!({ "enrollment": enrollment.signed() }).to_string()
        };
        let real = request(vec![[9; 16], [10; 16], [11; 16]]);
        let request = request(vec![[9; 16], [10; 16], [11; 16], [12; 16]]);
        let measured = measures(&state, &body, Some([6; 32])).unwrap();
        assert!(measured[1].bytes > real.len());
        assert_eq!(
            measured,
            [
                Measure {
                    body: SizedBody::Delivery,
                    bytes: delivery.to_json().len(),
                    limit: identity_limit().unwrap(),
                },
                Measure {
                    body: SizedBody::Enrollment,
                    bytes: request.len(),
                    limit: enrollment_limit().unwrap(),
                },
            ]
        );
    }

    #[test]
    fn test_status_follows_the_signing_gate() {
        let mut state = SignerState::new([1; 32], [2; 16]);
        assert_eq!(status_of(&state), SignerStatus::Enrolling);
        // A held alarm reads as one also once a delivery confirmed the switch.
        state.alert(Alert::Equivocation {
            source: Source::Homeserver,
            version: 2,
        });
        assert_eq!(status_of(&state), SignerStatus::Alarm);
        state.alerts.clear();
        state.switch_unconfirmed = true;
        assert_eq!(status_of(&state), SignerStatus::Alarm);
        state.records_behind = Some(9);
        assert_eq!(
            status_of(&state),
            SignerStatus::RecordsBehind { version: 9 }
        );
        state.managed_by = Some([7; 16]);
        assert_eq!(
            status_of(&state),
            SignerStatus::ManagedBy { install: [7; 16] }
        );
        let mut state = SignerState::new([1; 32], [2; 16]);
        state.taking_over = true;
        assert_eq!(status_of(&state), SignerStatus::TakingOver);
    }
}
