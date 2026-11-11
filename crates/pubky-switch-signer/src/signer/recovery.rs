//! A provider loss (Switch spec 12.6 steps 1 and 2; Switch wire 3.3, 3.7, 7.4.2, 7.4.14): the
//! signer enrolls at a service, the lost one's operator or another, and delivers there the
//! next generation's `identity.json`, which declares the generation it served lost.
//!
//! [`Signer::declare_provider_loss`] commits the declaration as a flow, then:
//!
//! 1. enrolls at the service, naming every App ID it revoked or saw depart, so the service
//!    refuses them from the start although no export reaches it;
//! 2. signs the version: the next generation, `recovery_from` the lost one, naming the
//!    service and the key its enrollment answered, at a higher version, with the same
//!    `data_epoch`, every `service_keys` entry of a lost generation left out, and every
//!    reduction whose closing is owed closed at the time it signs, plus the clock tolerance,
//!    since the lost service can't take the closing; cooperative renewals stay open;
//! 3. delivers it with `prev` `null`, as a new account's first document, which a recovery in
//!    place takes too, whatever version the service holds; writes its backup before, and
//!    publishes it after, as every version;
//! 4. when none of the apps it lists holds `lists.manage`, ends the staged admission the
//!    recovery started (`POST /recovery/admission`), since no upload could, and reads
//!    `GET /apps` back to see it ended. An app whose certificate this install doesn't hold
//!    may hold it, so then the wait stays, for the user to end
//!    ([`Signer::end_staged_admission`]).
//!
//! Each step is resumed after a failure or a crash, the enrollment and the version sent again
//! with their bytes. The declaration is allowed while an alarm is held, at an erased account,
//! and during an erasure, which it ends, the lost account counting as erased: a provider loss
//! is the way out of each. It is refused while the records are behind, while another install
//! signs, and during a hand-over or a take-over.

use pubky_switch_core::records::{
    CLOCK_TOLERANCE_MS, Enrollment, EnrollmentBody, IdentityDoc, Inbox,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;

use super::clients::{RequestClient, Target};
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
    /// # Errors
    ///
    /// [`Refusal::NotSetUp`] before the first version; [`SignerError::NotNamed`],
    /// [`Refusal::RecordsBehind`], [`Refusal::HandingOver`] and [`Refusal::TakingOver`], as
    /// the spec's "who may declare it" asks; [`Refusal::FlowInProgress`] while a recovery is
    /// in progress, or a flow other than a delivery, a renewal or an erasure, which the
    /// recovery supersedes; an origin that isn't a switch origin; otherwise as
    /// [`Signer::resume`], with the recovery kept and resumed there.
    pub async fn declare_provider_loss(
        &mut self,
        origin: &str,
        _confirmed: UserConfirmed,
    ) -> Result<IdentityDoc> {
        self.refresh().await?;
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        // Who may declare it: the recovery's gate, before anything is signed.
        let key = gate::recovery_key(&self.keyring, &self.state)?;
        // A version in flight to the lost service, a renewal's or an erasure's steps there,
        // are superseded: their versions stay spent, and the recovery's is higher.
        if self.state.recovering
            || matches!(
                self.flow,
                Some(Flow::Recover { .. } | Flow::Enroll { .. } | Flow::TakingOver { .. })
            )
        {
            return Err(Refusal::FlowInProgress.into());
        }
        let identity = self.state.identity;
        let mut revoked = self.state.tombstones.clone();
        revoked.sort_unstable();
        revoked.dedup();
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
        // for apps still listed are withdrawn (Switch spec 12.7).
        self.end_erasure_in(&mut state)?;
        state.erased = false;
        state.recovering = true;
        let flow = Flow::Recover {
            origin: origin.to_owned(),
            enrollment: enrollment.signed().clone(),
        };
        self.commit(state, Some(flow)).await?;
        self.resume().await?;
        self.state
            .newest_doc()?
            .ok_or_else(|| SignerError::Records("the recovery's version is gone".into()))
    }

    /// End the staged admission a recovery started at the service (Switch spec 12.6 step 2;
    /// wire 7.4.14), on the user's word: for example once the app that manages contacts is
    /// gone for good. Sent again at every run until `GET /apps` shows it ended; ending a wait
    /// that isn't staged changes nothing.
    ///
    /// # Errors
    ///
    /// [`Refusal::FlowInProgress`] while a flow is in progress; a switch error, the call kept
    /// owed for the next run.
    pub async fn end_staged_admission(&mut self) -> Result<()> {
        self.refresh().await?;
        self.check_named()?;
        if self.flow.is_some() {
            return Err(Refusal::FlowInProgress.into());
        }
        let mut state = self.state.clone();
        state.admission_owed = true;
        self.commit(state, None).await?;
        self.end_owed_admission().await
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
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let lost = newest.generation();
        let generation = lost
            .checked_add(1)
            .ok_or_else(|| SignerError::Records("the generation can't go higher".into()))?;
        let until = self.env.clock.now_ms().saturating_add(CLOCK_TOLERANCE_MS);
        let owed = self.owed()?;
        let key = gate::recovery_key(&self.keyring, &self.state)?;
        let install = self.state.install;
        let (doc, _) = self.next_version_in(
            &key,
            |body| {
                body.generation = generation;
                body.recovery_from = Some(lost);
                body.signer = install;
                body.inbox = Inbox::new(origin, answer.service_key);
                // Every lost generation's key is left out (wire 3.3): nothing resolves it.
                body.service_keys.retain(|entry| entry.generation > lost);
                for app in &owed {
                    body.close_renewals(app, until);
                }
            },
            Room::Cap,
        )?;
        drop(key);
        let mut state = self.state.clone();
        state.admission_owed = !self.listed_may_manage_lists(&doc)?;
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

    /// Whether an app `doc` lists may hold `lists.manage`: its certificate grants it, or
    /// this install doesn't hold its certificate, so it can't tell.
    fn listed_may_manage_lists(&self, doc: &IdentityDoc) -> Result<bool> {
        let certs = self.held_certs()?;
        Ok(doc.body().apps.iter().any(|listed| {
            certs
                .iter()
                .find(|cert| cert.hash() == listed.cert)
                .is_none_or(|cert| cert.has_permission(Permission::ListsManage))
        }))
    }

    /// The recovery's version is delivered (Switch spec 12.6 step 1): the account served
    /// from here is the new service's, and what the lost one held against this install goes,
    /// its alarms and an unconfirmed switch among them.
    pub(super) fn recovered_in(state: &mut SignerState) {
        state.recovering = false;
        state.switch_unconfirmed = false;
        state.alerts.retain(|alert| {
            !matches!(
                alert,
                Alert::Rollback {
                    source: Source::Switch,
                    ..
                } | Alert::Equivocation {
                    source: Source::Switch,
                    ..
                } | Alert::AccountNotHosted
            )
        });
    }

    /// End staged admission, owed after a recovery or asked for by the user, and read it back
    /// (the module's doc, step 4).
    pub(super) async fn end_owed_admission(&mut self) -> Result<()> {
        let client = self.service_client()?;
        client.recovery_admission().await?;
        let answer = client.apps().await?;
        if answer.recovery.as_ref().is_some_and(|r| r.admission_staged) {
            return Err(SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                "Switch wire 7.4.14: admission is still staged after its end".into(),
            )));
        }
        let mut state = self.state.clone();
        state.admission_owed = false;
        self.commit(state, self.flow.clone()).await
    }
}
