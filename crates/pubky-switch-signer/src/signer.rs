//! The signer of one identity: enrolling it at a switch, signing and delivering its
//! `identity.json` versions with the high-water mark, the one-signer rule, and the backup of
//! its records (Switch spec 4.3, 12.8; Switch wire 3.3, 3.7, 3.13, 7.4.1, 7.4.2).
//!
//! Every network effect follows one rule: sign the artifact and commit it with the flow's
//! next step, send exactly those bytes until there is an answer, then commit the outcome. A
//! crash anywhere is finished by [`Signer::resume`], which resends the bytes kept, so
//! nothing is signed twice (Switch wire 2.1).
//!
//! A new version takes these steps (Switch spec 4.3, Switch wire 3.13):
//!
//! 1. this install must be the one named;
//! 2. sign the version, naming this install as `signer`, and commit it;
//! 3. read the backup on the Homeserver: one naming another install at or past the high-water
//!    mark means that install took over, and this one stops;
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
use pubky_switch_client::{ClientError, Credentials, SwitchClient};
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
        let signer = Self {
            env,
            keyring,
            state: SignerState::new(identity, install),
            flow: Some(Flow::Enroll {
                origin: origin.to_owned(),
                enrollment: enrollment.signed().clone(),
                policy,
            }),
        };
        signer.save().await?;
        Ok(signer)
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

    /// Sign the next version, built from the newest with `change`, and deliver it.
    async fn new_version(&mut self, change: impl FnOnce(&mut IdentityBody)) -> Result<IdentityDoc> {
        self.check_named()?;
        if self.flow.is_some() {
            return Err(Refusal::FlowInProgress.into());
        }
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let mut body = newest.body().clone();
        body.version = body
            .version
            .checked_add(1)
            .ok_or_else(|| SignerError::Records("the version can't go higher".into()))?;
        body.signer = self.state.install;
        change(&mut body);
        let doc = {
            let key = self.keyring.unlock()?;
            IdentityDoc::sign(&key, body)?
        };
        self.flow = Some(Flow::Deliver {
            doc: doc.signed().clone(),
            prev: Some(newest.hash()),
            backup: None,
            step: DeliverStep::Signed,
        });
        self.save().await?;
        self.resume().await?;
        Ok(doc)
    }

    /// Refuse every signing call while another install is the signer (Switch spec 4.3).
    fn check_named(&self) -> Result<()> {
        match self.state.managed_by {
            Some(install) => Err(SignerError::NotNamed { install }),
            None => Ok(()),
        }
    }

    async fn save(&self) -> Result<()> {
        state::save(&self.env.store, &self.state, self.flow.as_ref()).await
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
        let service = Service {
            origin: origin.to_owned(),
            service_key: answer.service_key,
            limits: answer.limits,
        };
        let body = IdentityBody::first(
            identity,
            self.state.install,
            Inbox::new(origin, service.service_key),
            policy,
        );
        let doc = IdentityDoc::sign(&key, body)?;
        self.state.service = Some(service);
        self.flow = Some(Flow::Deliver {
            doc: doc.signed().clone(),
            prev: None,
            backup: None,
            step: DeliverStep::Signed,
        });
        self.save().await
    }

    /// Check the backup the Homeserver holds, then write the one holding the new version
    /// (Switch wire 3.13 "When it is written", "Another install's backup").
    async fn write_backup(
        &mut self,
        doc: &SignedDoc,
        prev: Option<[u8; 32]>,
        backup: Option<SignerBackup>,
    ) -> Result<()> {
        self.check_named()?;
        if let Some(bytes) = self
            .env
            .homeserver
            .get(SIGNER_BACKUP_PATH)
            .await
            .map_err(SignerError::Homeserver)?
        {
            match self.open_backup(&bytes)? {
                Some(found) => {
                    let newest = self.high_water().map_or(0, |h| h.version);
                    if taken_over(&found, &self.state.install, newest) {
                        let install = found.identity_doc().body().signer;
                        return self.managed_by(install).await;
                    }
                }
                None => self.state.alert(Alert::BackupUnreadable),
            }
        }
        let backup = match backup {
            Some(backup) => backup,
            None => {
                // Sealed once and kept, so a retry writes the same bytes.
                let backup = self.seal_backup(doc, prev)?;
                self.flow = Some(Flow::Deliver {
                    doc: doc.clone(),
                    prev,
                    backup: Some(backup.clone()),
                    step: DeliverStep::Signed,
                });
                self.save().await?;
                backup
            }
        };
        let bytes = serde_json::to_vec(&backup).map_err(|e| SignerError::Records(e.to_string()))?;
        self.env
            .homeserver
            .put(SIGNER_BACKUP_PATH, bytes)
            .await
            .map_err(SignerError::Homeserver)?;
        self.flow = Some(Flow::Deliver {
            doc: doc.clone(),
            prev,
            backup: Some(backup),
            step: DeliverStep::BackupWritten,
        });
        self.save().await
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
        let service = self.service()?;
        let key = self.keyring.unlock()?;
        let client = self.client(&service.origin, Some(service.service_key), key)?;
        let delivery = IdentityDelivery {
            identity: doc.clone(),
            prev,
        };
        match client.put_identity(&delivery).await {
            Ok(_) => {
                self.state.newest = Some(Newest {
                    doc,
                    prev,
                    published: false,
                });
                self.flow = None;
                self.save().await
            }
            Err(ClientError::Switch {
                code: ErrorCode::StaleIdentity,
                current,
                ..
            }) => self.stale(&current).await,
            Err(error @ ClientError::Switch { status: 400, .. }) => {
                // A definite refusal: the same bytes would be refused again.
                self.flow = None;
                self.save().await?;
                Err(error.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// `409 stale_identity`: the switch holds another version than the one this delivery
    /// builds on, and its answer carries the copy (Switch wire 3.3 "Never back", 7.4.2).
    async fn stale(&mut self, current: &Value) -> Result<()> {
        // The delivery is over whatever the copy is: its version can't be taken.
        self.flow = None;
        let copy = current
            .get("identity")
            .and_then(|doc| serde_json::from_value::<SignedDoc>(doc.clone()).ok())
            .map(|signed| IdentityDoc::verify(&signed, &self.state.identity));
        let copy = match copy {
            Some(Ok(copy)) => copy,
            Some(Err(error)) => {
                self.save().await?;
                return Err(error.into());
            }
            None => {
                self.save().await?;
                return Err(SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                    "Switch wire 7.4.2: a stale_identity answer without the copy".into(),
                )));
            }
        };
        if let Some(high) = self.high_water() {
            if copy.version() < high.version || copy.generation() < high.generation {
                return self
                    .alarm(Alert::Rollback {
                        source: Source::Switch,
                        version: copy.version(),
                        generation: copy.generation(),
                        high_water_version: high.version,
                    })
                    .await;
            }
            if copy.version() == high.version {
                if copy.body_hash() != high.body_hash {
                    return self
                        .alarm(Alert::Equivocation {
                            source: Source::Switch,
                            version: high.version,
                        })
                        .await;
                }
                self.save().await?;
                return Err(Refusal::Superseded {
                    version: high.version,
                }
                .into());
            }
        }
        // A strictly newer copy, another signer's: adopted (Switch spec 4.3). It isn't this
        // install's to publish.
        let version = copy.version();
        let signer = copy.body().signer;
        self.state.newest = Some(Newest {
            doc: copy.signed().clone(),
            prev: None,
            published: true,
        });
        if signer != self.state.install {
            return self.managed_by(signer).await;
        }
        self.save().await?;
        Err(Refusal::Superseded { version }.into())
    }

    /// Another install is the signer: this one stops signing (Switch spec 4.3, 12.8).
    async fn managed_by(&mut self, install: [u8; 16]) -> Result<()> {
        self.flow = None;
        self.state.managed_by = Some(install);
        self.state.alert(Alert::ManagedByOtherInstall { install });
        self.save().await?;
        Err(SignerError::NotNamed { install })
    }

    /// Keep `alert` and end the flow: the signer doesn't build on what it saw.
    async fn alarm(&mut self, alert: Alert) -> Result<()> {
        self.flow = None;
        self.state.alert(alert.clone());
        self.save().await?;
        Err(SignerError::Alarm(alert))
    }

    /// Publish the newest version on the Homeserver once the switch accepted it (Switch spec
    /// 4.3: deliver first, publish after).
    async fn publish(&mut self) -> Result<()> {
        let Some(newest) = self.state.newest.as_mut() else {
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
        newest.published = true;
        self.save().await
    }
}
