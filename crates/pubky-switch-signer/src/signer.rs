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
//!    mark means that install took over, and this one stops. One that doesn't open, or none
//!    where this signer wrote one, stops it too, unless the switch still holds the high-water
//!    version;
//! 4. write the backup holding the new version; a failed write stops the delivery;
//! 5. deliver it with `PUT /identity`, naming the version it builds on;
//! 6. take the answer: success moves the high-water mark; `409 stale_identity` carries the
//!    switch's copy, which is adopted only when it is strictly newer, and raises an alarm when
//!    it is older or another body at the high-water version;
//! 7. publish it on the Homeserver.

use std::sync::Arc;

use pubky_switch_client::clock::Clock;
use pubky_switch_client::store::StoreHandle;
use pubky_switch_client::transport::Transport;
use pubky_switch_client::{ClientError, Credentials, StoreError, SwitchClient};
use pubky_switch_core::enc::{pubky_id, random_bytes};
use pubky_switch_core::http::{ErrorCode, IdentityDelivery};
use pubky_switch_core::keys::IdentityKey;
use pubky_switch_core::records::{
    AppCert, ConnectRequests, Enrollment, EnrollmentBody, IDENTITY_PATH, IdentityBody, IdentityDoc,
    IdentityPolicy, Inbox, SIGNER_BACKUP_PATH, SignerBackup, SignerRecords, taken_over,
};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::signing::Signs;
use serde_json::Value;

use crate::alert::{Alert, Source};
use crate::error::{Refusal, Result, SignerError};
use crate::homeserver::Homeserver;
use crate::key::{ExportReason, IdentityKeyring};
use crate::protocol::Protocols;
use crate::state::{self, DeliverStep, Flow, Newest, Service, SignerState};

mod approval;

pub use approval::{AppReview, ApprovedRequest};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        if state::load(&env.store, &identity).await?.is_some() {
            return Err(Refusal::AlreadySetUp.into());
        }
        let install = random_bytes::<16>()?;
        let policy = IdentityPolicy::default();
        let enrollment = {
            let key = keyring.unlock()?;
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
        let state = SignerState::new(identity, install);
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
        Ok(Self {
            env,
            keyring,
            state,
            flow,
            unsure: false,
        })
    }

    /// Finish the flow in progress, resending what it signed, then publish the newest version
    /// if it isn't published yet. A call that fails leaves the flow to the next one.
    ///
    /// # Errors
    ///
    /// The error of the step that failed: a switch, Homeserver, store or key error;
    /// [`SignerError::NotNamed`] when another install took over; [`SignerError::Alarm`] for a
    /// rollback or an equivocation; [`Refusal::Superseded`] when the switch holds a newer
    /// version that this install adopted instead of its own.
    pub async fn resume(&mut self) -> Result<()> {
        self.refresh().await?;
        while let Some(flow) = self.flow.clone() {
            match flow {
                Flow::Enroll {
                    origin,
                    enrollment,
                    policy,
                } => self.enroll(&origin, &enrollment, policy).await?,
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
        self.publish().await
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
        match (self.state.managed_by, &self.state.newest) {
            (Some(install), _) => SignerStatus::ManagedBy { install },
            (None, None) => SignerStatus::Enrolling,
            (None, Some(_)) => SignerStatus::Signing,
        }
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

    /// Clear `alert`, once the user has seen it and dealt with it. A rollback or equivocation
    /// alert holds back every approval's claim until it is cleared.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn clear_alert(&mut self, alert: &Alert) -> Result<()> {
        self.refresh().await?;
        if !self.state.alerts.contains(alert) {
            return Ok(());
        }
        let mut state = self.state.clone();
        state.alerts.retain(|held| held != alert);
        self.commit(state, self.flow.clone()).await
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
        let key = self.keyring.unlock()?;
        let (doc, flow) = self.next_version(&key, change)?;
        drop(key);
        let mut state = self.state.clone();
        state.signed_through = doc.version();
        self.commit(state, Some(flow)).await?;
        self.resume().await?;
        Ok(doc)
    }

    /// Ready for a new signing call: the store read again if a commit left it unsure, this
    /// install named, and no flow in progress.
    pub(crate) async fn ready(&mut self) -> Result<()> {
        self.refresh().await?;
        self.check_named()?;
        if self.flow.is_some() {
            return Err(Refusal::FlowInProgress.into());
        }
        Ok(())
    }

    /// The next version, built from the newest with `change` and signed with `key`, and the
    /// flow that delivers it. Nothing is committed.
    pub(crate) fn next_version(
        &self,
        key: &IdentityKey,
        change: impl FnOnce(&mut IdentityBody),
    ) -> Result<(IdentityDoc, Flow)> {
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let version = newest
            .version()
            .max(self.state.signed_through)
            .checked_add(1)
            .ok_or_else(|| SignerError::Records("the version can't go higher".into()))?;
        let mut body = newest.body().clone();
        body.version = version;
        body.signer = self.state.install;
        change(&mut body);
        let doc = IdentityDoc::sign(key, body)?;
        let flow = Flow::Deliver {
            doc: doc.signed().clone(),
            prev: Some(newest.hash()),
            backup: None,
            step: DeliverStep::Signed,
        };
        Ok((doc, flow))
    }

    /// Refuse every signing call while another install is the signer (Switch spec 4.3).
    fn check_named(&self) -> Result<()> {
        match self.state.managed_by {
            Some(install) => Err(SignerError::NotNamed { install }),
            None => Ok(()),
        }
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
        if !self.unsure {
            return Ok(());
        }
        let (state, flow) = state::load(&self.env.store, &self.state.identity)
            .await?
            .ok_or(Refusal::NotSetUp)?;
        self.state = state;
        self.flow = flow;
        self.unsure = false;
        Ok(())
    }

    fn service(&self) -> Result<Service> {
        self.state
            .service
            .clone()
            .ok_or_else(|| SignerError::Records("no switch before the enrollment".into()))
    }

    /// A client for this step, signing with the identity key (Switch wire 7.2).
    fn client(
        &self,
        origin: &str,
        pinned: Option<[u8; 32]>,
        key: Arc<IdentityKey>,
    ) -> Result<SwitchClient> {
        let key: Arc<dyn Signs + Send + Sync> = key;
        Ok(SwitchClient::new(
            origin,
            self.state.identity,
            Credentials::Signer {
                identity: self.state.identity,
                key,
            },
            pinned,
            Arc::clone(&self.env.transport),
            Arc::clone(&self.env.clock),
        )?)
    }

    /// A client of the switch the identity is enrolled at.
    fn service_client(&self) -> Result<SwitchClient> {
        let service = self.service()?;
        let key = self.keyring.unlock()?;
        self.client(&service.origin, Some(service.service_key), key)
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
        let key = self.keyring.unlock()?;
        let answer = self
            .client(origin, None, Arc::clone(&key))?
            .enroll(&enrollment)
            .await?;
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
    /// without writing. So does a backup that doesn't open, or none where this signer has
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
        let found = self
            .env
            .homeserver
            .get(SIGNER_BACKUP_PATH)
            .await
            .map_err(SignerError::Homeserver)?;
        let mut state = self.state.clone();
        match found {
            Some(bytes) => match self.open_backup(&bytes)? {
                Some(found) => {
                    let newest = self.high_water().map_or(0, |h| h.version);
                    if taken_over(&found, &self.state.install, newest) {
                        let install = found.identity_doc().body().signer;
                        return self.managed_by(install).await;
                    }
                }
                None if self.state.newest.is_none() => {
                    // No mark yet, so no copy of the switch to judge: a staged account shows
                    // none. The backup may be another install's, so nothing is written.
                    return self.unreadable_before_mark().await;
                }
                None => {
                    self.switch_at_mark().await?;
                    state.alert(Alert::BackupUnreadable);
                }
            },
            None if self.state.newest.is_some() => {
                self.switch_at_mark().await?;
                state.alert(Alert::BackupMissing);
            }
            None => {}
        }
        let backup = match backup {
            Some(backup) => backup,
            None => {
                // Sealed once and kept, so a retry writes the same bytes.
                let backup = self.seal_backup(doc, prev)?;
                let flow = Flow::Deliver {
                    doc: doc.clone(),
                    prev,
                    backup: Some(backup.clone()),
                    step: DeliverStep::Signed,
                };
                self.commit(state.clone(), Some(flow)).await?;
                backup
            }
        };
        let bytes = serde_json::to_vec(&backup).map_err(|e| SignerError::Records(e.to_string()))?;
        self.env
            .homeserver
            .put(SIGNER_BACKUP_PATH, bytes)
            .await
            .map_err(SignerError::Homeserver)?;
        let flow = Flow::Deliver {
            doc: doc.clone(),
            prev,
            backup: Some(backup),
            step: DeliverStep::BackupWritten,
        };
        self.commit(state, Some(flow)).await
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
    /// [`Signer::judge_copy`] says.
    async fn switch_at_mark(&mut self) -> Result<()> {
        let held = self.service_client()?.apps().await?.identity;
        let copy = match held {
            Some(signed) => Some(IdentityDoc::verify(&signed, &self.state.identity)?),
            None => None,
        };
        match self.judge_copy(copy.as_ref()) {
            Ok(Verdict::AtMark) => Ok(()),
            Ok(Verdict::Newer) => match copy {
                Some(copy) => self.adopt(copy).await,
                None => Ok(()),
            },
            Err(alert) => self.alarm(alert).await,
        }
    }

    /// The records a backup holds, opened with the identity key; `None` for one that doesn't
    /// read, open or verify.
    fn open_backup(&self, bytes: &[u8]) -> Result<Option<SignerRecords>> {
        let Ok(backup) = serde_json::from_slice::<SignerBackup>(bytes) else {
            return Ok(None);
        };
        Ok(self.keyring.with_key(|key| backup.open(key).ok())?)
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
        let sealed = self.keyring.for_export(ExportReason::Backup, |_, key| {
            let records = SignerRecords::new(
                key.clone(),
                doc,
                &self.state.tombstones,
                &issued,
                limits,
                &self.state.bundle_parts,
                prev,
            )?;
            SignerBackup::seal(key, &records)
        })??;
        Ok(sealed)
    }

    /// Deliver the new version (Switch wire 7.4.2) and take the answer.
    async fn deliver(&mut self, doc: SignedDoc, prev: Option<[u8; 32]>) -> Result<()> {
        self.check_named()?;
        let delivery = IdentityDelivery {
            identity: doc.clone(),
            prev,
        };
        match self.service_client()?.put_identity(&delivery).await {
            Ok(_) => {
                let mut state = self.state.clone();
                state.newest = Some(Newest {
                    doc,
                    prev,
                    published: false,
                });
                self.commit(state, None).await
            }
            Err(ClientError::Switch {
                code: ErrorCode::StaleIdentity,
                current,
                ..
            }) => self.stale(&current).await,
            Err(error @ ClientError::Switch { status: 400, .. }) => {
                // A definite refusal: the same bytes would be refused again. The version stays
                // spent (`signed_through`).
                self.commit(self.state.clone(), None).await?;
                Err(error.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// `409 stale_identity`: the switch holds another version than the one this delivery
    /// builds on, and its answer carries the copy, or `null` when it holds none (Switch wire
    /// 3.3 "Never back", 7.4.2). The delivery is over whatever the copy is.
    async fn stale(&mut self, current: &Value) -> Result<()> {
        let copy = match current.get("identity") {
            None | Some(Value::Null) => None,
            Some(doc) => {
                let verified = serde_json::from_value::<SignedDoc>(doc.clone())
                    .map_err(|e| pubky_switch_core::Error::Invalid(e.to_string()))
                    .and_then(|signed| IdentityDoc::verify(&signed, &self.state.identity));
                match verified {
                    Ok(copy) => Some(copy),
                    Err(error) => {
                        self.commit(self.state.clone(), None).await?;
                        return Err(error.into());
                    }
                }
            }
        };
        match self.judge_copy(copy.as_ref()) {
            Err(alert) => self.alarm(alert).await,
            Ok(Verdict::Newer) => match copy {
                Some(copy) => self.adopt(copy).await,
                None => {
                    self.commit(self.state.clone(), None).await?;
                    Err(stale_without_copy())
                }
            },
            Ok(Verdict::AtMark) => {
                // The switch holds the version this delivery builds on, yet refused it.
                self.commit(self.state.clone(), None).await?;
                Err(stale_without_copy())
            }
        }
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

    /// Adopt a strictly newer copy, another signer's (Switch spec 4.3), ending the flow. It
    /// isn't this install's to publish.
    async fn adopt(&mut self, copy: IdentityDoc) -> Result<()> {
        let version = copy.version();
        let signer = copy.body().signer;
        let mut state = self.state.clone();
        state.newest = Some(Newest {
            doc: copy.signed().clone(),
            prev: None,
            published: true,
        });
        state.signed_through = state.signed_through.max(version);
        if signer != state.install {
            state.managed_by = Some(signer);
            state.alert(Alert::ManagedByOtherInstall { install: signer });
            self.commit(state, None).await?;
            return Err(SignerError::NotNamed { install: signer });
        }
        self.commit(state, None).await?;
        Err(Refusal::Superseded { version }.into())
    }

    /// Another install is the signer: this one stops signing (Switch spec 4.3, 12.8).
    async fn managed_by(&mut self, install: [u8; 16]) -> Result<()> {
        let mut state = self.state.clone();
        state.managed_by = Some(install);
        state.alert(Alert::ManagedByOtherInstall { install });
        self.commit(state, None).await?;
        Err(SignerError::NotNamed { install })
    }

    /// Keep `alert` and end the flow: the signer doesn't build on what it saw.
    async fn alarm(&mut self, alert: Alert) -> Result<()> {
        let mut state = self.state.clone();
        state.alert(alert.clone());
        self.commit(state, None).await?;
        Err(SignerError::Alarm(alert))
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
        let bytes =
            serde_json::to_vec(&newest.doc).map_err(|e| SignerError::Records(e.to_string()))?;
        self.env
            .homeserver
            .put(IDENTITY_PATH, bytes)
            .await
            .map_err(SignerError::Homeserver)?;
        let mut state = self.state.clone();
        state.newest = Some(Newest {
            published: true,
            ..newest
        });
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

fn stale_without_copy() -> SignerError {
    SignerError::InvalidData(pubky_switch_core::Error::Invalid(
        "Switch wire 7.4.2: stale_identity without a newer copy than the one built on".into(),
    ))
}
