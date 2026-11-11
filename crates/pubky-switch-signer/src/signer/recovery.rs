//! A provider loss (Switch spec 12.6 steps 1 and 2; Switch wire 3.3, 3.7, 7.4.2, 7.4.14): the
//! signer enrolls at a service, the lost one's operator or another, and delivers there the
//! next generation's `identity.json`, which declares the generation it served lost.
//!
//! [`Signer::declare_provider_loss`] checks the copies, commits the declaration as a flow,
//! then:
//!
//! 1. enrolls at the service, naming every App ID it revoked or saw depart that the version
//!    it delivers doesn't list, so the service refuses them from the start although no
//!    export reaches it;
//! 2. signs the version, built on the newest this install signed, one in flight to the lost
//!    service included: the next generation, `recovery_from` the lost one, naming the
//!    service and the key its enrollment answered, at a higher version, with the same
//!    `data_epoch`, every `service_keys` entry of a lost generation left out, and every
//!    reduction whose closing is owed closed at the time it signs, plus the clock tolerance,
//!    since the lost service can't take the closing; cooperative renewals stay open;
//! 3. delivers it with `prev` `null`, as a new account's first document, which a recovery in
//!    place takes too, whatever version the service holds; writes its backup before, and
//!    publishes it after, as every version;
//! 4. completes there every revocation that version still lists the app of, a removal with
//!    its own rotation, as at any service;
//! 5. when none of the apps it lists holds `lists.manage`, ends the staged admission the
//!    recovery started (`POST /recovery/admission`), since no upload could, and reads
//!    `GET /apps` back to see it ended. An app whose certificate this install doesn't hold
//!    may hold it, so then the wait stays, for the user to end
//!    ([`Signer::end_staged_admission`]).
//!
//! Each step is resumed after a failure or a crash, the enrollment and the version sent again
//! with their bytes. Until the service takes the version, the user may declare the loss
//! again, at that service or another: the new declaration replaces the one in progress, and
//! its version is higher. The declaration is allowed while an alarm is held, at an erased
//! account, and during an erasure, which it ends, the lost account counting as erased: a
//! provider loss is the way out of each. It is refused while the records are behind, while
//! another install signs, and during a hand-over or a take-over.

use pubky_switch_core::records::{
    CLOCK_TOLERANCE_MS, Enrollment, EnrollmentBody, IdentityBody, IdentityDoc, Inbox,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;

use super::clients::{RequestClient, Target};
use super::erasure::withdraw_reminders;
use super::revocation::UserConfirmed;
use super::{Room, Signer, gate};
use crate::alert::{Alert, Source};
use crate::error::{Refusal, Result, SignerError};
use crate::state::{DeliverStep, Flow, Service, SignerState};

impl Signer {
    /// Declare the service the identity is enrolled at lost, and recover at the service at
    /// `origin`: the same operator's or another's (Switch spec 12.6 step 1). Shown and
    /// confirmed by the user, since apps then rebuild their state there. Returns the version
    /// that starts the new generation, once delivered and published.
    ///
    /// Declaring it again before the service takes that version, at the same service or
    /// another, replaces the recovery in progress: for an origin that never answers, or a
    /// service that refused the version ([`crate::SignerStatus::RecoveryRefused`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::NotSetUp`] before the first version; [`SignerError::NotNamed`],
    /// [`Refusal::RecordsBehind`], [`Refusal::HandingOver`] and [`Refusal::TakingOver`], as
    /// the spec's "who may declare it" asks, also when the signer backup or the Homeserver's
    /// `identity.json` shows one of them; [`Refusal::FlowInProgress`] during a first
    /// enrollment or a take-over; [`Refusal::IdentityTooLarge`] for a version naming
    /// `origin` that the cap can't take; an origin that isn't a switch origin; otherwise as
    /// [`Signer::resume`], with the recovery kept and resumed there.
    pub async fn declare_provider_loss(
        &mut self,
        origin: &str,
        _confirmed: UserConfirmed,
    ) -> Result<IdentityDoc> {
        self.refresh().await?;
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        // Who may declare it: the recovery's gate, before anything is read or signed.
        if let Some(refused) = gate::recovery_refusal(&self.state) {
            return Err(refused);
        }
        if matches!(
            self.flow,
            Some(Flow::Enroll { .. } | Flow::TakingOver { .. })
        ) {
            return Err(Refusal::FlowInProgress.into());
        }
        // Taken before the checks below, which may end a flow in progress.
        let base = self.recovery_base()?;
        // The copies the lost service can't be asked about: the backup and the Homeserver's
        // `identity.json` show another install that took over, or records behind (Switch
        // spec 4.3). Another body there at the mark is an alarm, which the recovery passes,
        // and its version waits for the user to clear it before it is published.
        self.check_backup_copy().await?;
        match self.judge_homeserver(&newest).await {
            Ok(_) | Err(SignerError::Alarm(_)) => {}
            Err(error) => return Err(error),
        }
        // The App IDs to refuse from the start, but those the version still lists: a
        // revocation not signed into a version yet is completed at the service once it
        // took the recovery's version, which can't also rotate (Switch spec 12.6 step 1).
        let mut revoked: Vec<[u8; 16]> = self
            .state
            .tombstones
            .iter()
            .copied()
            .filter(|app| base.listed_cert(app).is_none())
            .collect();
        revoked.sort_unstable();
        revoked.dedup();
        // A version the cap can't take is refused before anything is sent: the origin is in
        // it, and the service's key is as long whatever it is.
        let lost = self.lost_generation(&base);
        let until = self.env.clock.now_ms().saturating_add(CLOCK_TOLERANCE_MS);
        self.recovery_body(&base, lost, origin, [0; 32], until)?;
        let identity = self.state.identity;
        let key = gate::recovery_key(&self.keyring, &self.state)?;
        let body = EnrollmentBody {
            identity,
            origin: origin.to_owned(),
            nonce: pubky_switch_core::enc::random_bytes()?,
            policy: newest.body().policy,
            identity_doc: None,
            revoked_apps: Some(revoked),
        };
        let enrollment = Enrollment::sign(&key, body)?;
        drop(key);
        // The enrollment's own check refuses an origin that isn't a switch origin.
        Enrollment::verify(enrollment.signed(), &identity, origin)?;
        let mut state = self.state.clone();
        // An erasure ends: the account at the lost service counts as gone, and its reminders
        // for apps still listed are withdrawn (Switch spec 12.7). So are those of an erased
        // account's, enrolled again with those apps (Switch spec 12.7 step 4).
        self.end_erasure_in(&mut state)?;
        if state.erased {
            let reminded = state.grant_reminded.clone();
            withdraw_reminders(&mut state, &reminded)?;
        }
        state.erased = false;
        state.recovering = true;
        state.recovery_base = Some(base.signed().clone());
        state.lost_generation = Some(lost);
        let flow = Flow::Recover {
            origin: origin.to_owned(),
            enrollment: enrollment.signed().clone(),
        };
        self.commit(state, Some(flow)).await?;
        self.resume().await?;
        self.complete_listed_revocations().await?;
        self.state
            .newest_doc()?
            .ok_or_else(|| SignerError::Records("the recovery's version is gone".into()))
    }

    /// End the staged admission a recovery started at the service (Switch spec 12.6 step 2;
    /// wire 7.4.14), on the user's word: for example once the app that manages contacts is
    /// gone for good. Owed until `GET /apps` shows the wait ended, and sent again at every
    /// run; `GET /apps` is read first, so a wait that isn't staged, or no recovery, changes
    /// nothing and sends nothing.
    ///
    /// # Errors
    ///
    /// [`Refusal::FlowInProgress`] while a flow is in progress; [`Refusal::Recovering`]
    /// before the recovery's version is delivered; a switch error, the call kept owed for the
    /// next run.
    pub async fn end_staged_admission(&mut self) -> Result<()> {
        self.refresh().await?;
        self.check_named()?;
        if self.flow.is_some() {
            return Err(Refusal::FlowInProgress.into());
        }
        if self.state.recovering {
            return Err(Refusal::Recovering.into());
        }
        let mut state = self.state.clone();
        state.admission_owed = true;
        self.commit(state, None).await?;
        self.end_owed_admission().await
    }

    /// The document the recovery builds on: the one kept for a recovery declared already,
    /// else the newest this install signed, the version of a delivery or a renewal in flight
    /// to the lost service included, since that service may have taken it and apps seen it.
    fn recovery_base(&self) -> Result<IdentityDoc> {
        let identity = self.state.identity;
        if self.state.recovering
            && let Some(base) = &self.state.recovery_base
        {
            return Ok(IdentityDoc::verify(base, &identity)?);
        }
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let in_flight = match &self.flow {
            Some(Flow::Deliver { doc, .. } | Flow::Renew { doc, .. }) => {
                Some(IdentityDoc::verify(doc, &identity)?)
            }
            _ => None,
        };
        Ok(in_flight
            .filter(|doc| {
                doc.generation() == newest.generation() && doc.version() > newest.version()
            })
            .unwrap_or(newest))
    }

    /// The generation the recovery declares lost: the one kept for a recovery declared
    /// already, else `base`'s.
    fn lost_generation(&self, base: &IdentityDoc) -> u64 {
        self.state
            .lost_generation
            .filter(|_| self.state.recovering)
            .unwrap_or_else(|| base.generation())
    }

    /// The body of the recovery's version on `base`, declaring generation `lost` lost and
    /// naming the service at `origin` and its key `service_key`, with owed reductions closed
    /// at `until` (the module's doc, step 2), measured against the cap. Nothing is signed.
    fn recovery_body(
        &self,
        base: &IdentityDoc,
        lost: u64,
        origin: &str,
        service_key: [u8; 32],
        until: u64,
    ) -> Result<IdentityBody> {
        let generation = lost
            .checked_add(1)
            .ok_or_else(|| SignerError::Records("the generation can't go higher".into()))?;
        let owed = self.owed_in(base)?;
        self.next_body_on(
            base,
            |body| {
                body.generation = generation;
                body.recovery_from = Some(lost);
                body.inbox = Inbox::new(origin, service_key);
                // Every lost generation's key is left out (wire 3.3): nothing resolves it.
                body.service_keys.retain(|entry| entry.generation > lost);
                for app in &owed {
                    body.close_renewals(app, until);
                }
            },
            Room::Cap,
        )
    }

    /// Enroll at the service at `origin` with `signed`, then sign the version that recovers
    /// there and commit its delivery (the module's doc, steps 1 and 2).
    pub(super) async fn recover(&mut self, origin: &str, signed: &SignedDoc) -> Result<()> {
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
        let base = self.recovery_base()?;
        let lost = self.lost_generation(&base);
        let until = self.env.clock.now_ms().saturating_add(CLOCK_TOLERANCE_MS);
        // The enrollment names no App ID this version lists: both come from `base`.
        let body = self.recovery_body(&base, lost, origin, answer.service_key, until)?;
        let key = gate::recovery_key(&self.keyring, &self.state)?;
        let doc = IdentityDoc::sign(&key, body)?;
        drop(key);
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

    /// Complete at the new service every revocation the recovery's version still lists the
    /// app of (the module's doc, step 4). One that fails stays pending with its alert, and is
    /// completed as any pending revocation is: the recovery itself is done.
    async fn complete_listed_revocations(&mut self) -> Result<()> {
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let pending: Vec<[u8; 16]> = self
            .state
            .revoking
            .iter()
            .map(|r| r.app_id)
            .filter(|app| newest.listed_cert(app).is_some())
            .collect();
        if pending.is_empty() || self.complete_removals().await.is_ok() {
            return Ok(());
        }
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let mut state = self.state.clone();
        for app_id in pending {
            if newest.listed_cert(&app_id).is_some() {
                let at_switch = state.revoking.iter().any(|r| r.app_id == app_id && r.taken);
                state.alert(Alert::RevocationPending { app_id, at_switch });
            }
        }
        self.commit(state, self.flow.clone()).await
    }

    /// Whether an app `doc` lists may hold `lists.manage`: its certificate grants it, or
    /// this install doesn't hold its certificate, so it can't tell.
    pub(super) fn listed_may_manage_lists(&self, doc: &IdentityDoc) -> Result<bool> {
        let certs = self.held_certs()?;
        Ok(doc.body().apps.iter().any(|listed| {
            certs
                .iter()
                .find(|cert| cert.hash() == listed.cert)
                .is_none_or(|cert| cert.has_permission(Permission::ListsManage))
        }))
    }

    /// The recovery's version `doc` is delivered (Switch spec 12.6 step 1): the account
    /// served from here is the new service's, and what the lost one held against this install
    /// goes, its alarms, an unconfirmed switch and the revocations it took among them, which
    /// are sent to the new service again. An alert for a revocation `doc` completed goes.
    pub(super) fn recovered_in(state: &mut SignerState, doc: &IdentityDoc) {
        state.recovering = false;
        state.recovery_base = None;
        state.lost_generation = None;
        state.switch_unconfirmed = false;
        for revoking in &mut state.revoking {
            revoking.taken = false;
        }
        state.alerts.retain(|alert| match alert {
            Alert::Rollback {
                source: Source::Switch,
                ..
            }
            | Alert::Equivocation {
                source: Source::Switch,
                ..
            }
            | Alert::AccountNotHosted => false,
            Alert::RevocationPending { app_id, .. } | Alert::RevocationUnconfirmed { app_id } => {
                doc.listed_cert(app_id).is_some()
            }
            _ => true,
        });
    }

    /// End staged admission, owed after a recovery or asked for by the user, and read it back
    /// (the module's doc, step 5). `GET /apps` is read first, so a wait that ended or a
    /// service with no recovery sends nothing and owes nothing more.
    pub(super) async fn end_owed_admission(&mut self) -> Result<()> {
        let staged = |read: &super::SwitchRead| {
            read.answer
                .recovery
                .as_ref()
                .is_some_and(|r| r.admission_staged)
        };
        if !staged(&self.read_apps().await?) {
            return Ok(());
        }
        self.service_client()?.recovery_admission().await?;
        if staged(&self.read_apps().await?) {
            return Err(SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                "Switch wire 7.4.14: admission is still staged after its end".into(),
            )));
        }
        Ok(())
    }
}
