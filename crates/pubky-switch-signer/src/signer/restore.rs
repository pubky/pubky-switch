//! Restoring the signer from its backup (Switch spec 12.8; Switch wire 3.13).
//!
//! On the user's confirmation, an install reads the backup on the Homeserver, opens it with the
//! identity key, and checks it as wire 3.13 "Restoring" says:
//!
//! - the switch's copy of `identity.json` is the backup's version, or the version it builds on
//!   (`prev`), as when the signer stopped between writing the backup and delivering: that
//!   version is then delivered first. A switch with no copy counts only under a backup of the
//!   account's first version. Any other copy makes the backup stale, and the restore is
//!   refused;
//! - the Homeserver's copy is neither newer than the backup's version nor another document at
//!   it.
//!
//! The install then takes the backup's records as its own, with these additions: the App IDs
//! `GET /apps` shows revoked or departed join the tombstones; the epoch floor is the highest
//! epoch whose keys the records or the switch show were sent; and a removed app whose record
//! is still on the Homeserver gets its deletion owed again, with its grant reminder raised once
//! more. It delivers the next version naming this install as the signer, publishes it, and
//! writes its own backup once that delivery has won (wire 3.13 "When it is written"). Records
//! behind their own newer version, or an install another took over from, are restored in
//! place this way.

use pubky_switch_core::records::{IDENTITY_PATH, IdentityDoc, SIGNER_BACKUP_PATH, app_record_path};
use pubky_switch_core::sig::SignedDoc;

use super::Signer;
use super::SignerEnv;
use super::clients::{RequestClient, Target};
use super::revocation::UserConfirmed;
use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::key::IdentityKeyring;
use crate::state::{self, DeliverStep, Flow, Newest, Service, SignerState};

impl Signer {
    /// Set up this install from the signer backup on the Homeserver, for an identity whose
    /// key `keyring` holds and whose records this store doesn't hold, as on a new device
    /// (Switch spec 12.8, Switch wire 3.13). This install gets a signer ID of its own.
    ///
    /// # Errors
    ///
    /// [`Refusal::AlreadySetUp`] when the store holds records for this identity; otherwise as
    /// [`Signer::restore`].
    pub async fn restore_new(
        env: SignerEnv,
        keyring: IdentityKeyring,
        confirmed: UserConfirmed,
    ) -> Result<Self> {
        let identity = keyring.public_key();
        if state::load(&env.store, &identity).await?.is_some() {
            return Err(Refusal::AlreadySetUp.into());
        }
        let install = pubky_switch_core::enc::random_bytes::<16>()?;
        let mut signer = Self {
            env,
            keyring,
            state: SignerState::new(identity, install),
            flow: None,
            unsure: false,
        };
        signer.restore_records(confirmed).await?;
        Ok(signer)
    }

    /// Restore this install's records from the signer backup on the Homeserver, in place:
    /// when they are behind a newer version of its own ([`Alert::RecordsBehind`]), or when
    /// another install signs and the user has this one take over (Switch spec 12.8, Switch
    /// wire 3.13). Returns the version this install delivers as the signer.
    ///
    /// # Errors
    ///
    /// [`Refusal::FlowInProgress`] while a flow is in progress; [`Refusal::NoBackup`] when the
    /// Homeserver holds none; [`Refusal::UnreadableBackup`] for one that doesn't open or
    /// verify; [`Refusal::StaleBackup`] when the switch's or the Homeserver's copy is past it;
    /// otherwise as [`Signer::resume`].
    pub async fn restore(&mut self, confirmed: UserConfirmed) -> Result<IdentityDoc> {
        self.refresh().await?;
        if self.flow.is_some() {
            return Err(Refusal::FlowInProgress.into());
        }
        self.restore_records(confirmed).await
    }

    async fn restore_records(&mut self, _confirmed: UserConfirmed) -> Result<IdentityDoc> {
        let identity = self.state.identity;
        let bytes = self
            .env
            .homeserver
            .get(SIGNER_BACKUP_PATH)
            .await
            .map_err(SignerError::Homeserver)?
            .ok_or(Refusal::NoBackup)?;
        let view = self.open_backup(&bytes)?.ok_or(Refusal::UnreadableBackup)?;
        let doc = view.identity_doc.clone();
        let service = Service {
            origin: doc.inbox().url.clone(),
            service_key: doc.inbox().service_key,
            limits: view.limits,
        };
        let target = Target {
            origin: &service.origin,
            pinned: Some(service.service_key),
            identity,
        };
        let answer = RequestClient::new(&self.env, &target, &self.keyring)?
            .apps()
            .await?;
        // Check 3: the switch's copy is the backup's version, or the one it builds on.
        let held = answer
            .identity
            .as_ref()
            .map(|signed| IdentityDoc::verify(signed, &identity))
            .transpose()?;
        let first = match (&held, view.prev) {
            (Some(copy), _) if copy.hash() == doc.hash() => None,
            (Some(copy), Some(prev)) if copy.hash() == prev => Some(view.prev),
            (None, None) => Some(None),
            _ => return Err(Refusal::StaleBackup.into()),
        };
        // And the Homeserver's copy isn't past it.
        if let Some(copy) = self
            .env
            .homeserver
            .get(IDENTITY_PATH)
            .await
            .map_err(SignerError::Homeserver)?
            .and_then(|bytes| serde_json::from_slice::<SignedDoc>(&bytes).ok())
            .and_then(|signed| IdentityDoc::verify(&signed, &identity).ok())
        {
            let past = copy.version() > doc.version()
                || copy.generation() > doc.generation()
                || (copy.version() == doc.version() && copy.hash() != doc.hash());
            if past {
                return Err(Refusal::StaleBackup.into());
            }
        }

        let mut state = SignerState::new(identity, self.state.install);
        // The versions this install spent stay spent, and the user's other alerts stay; those
        // about the records restored over go, and so do alarms, which the checks above
        // answer for the restored records.
        state.signed_through = self.state.signed_through.max(doc.version());
        state.alerts = self
            .state
            .alerts
            .iter()
            .filter(|a| {
                !matches!(
                    a,
                    Alert::RecordsBehind { .. }
                        | Alert::ManagedByOtherInstall { .. }
                        | Alert::Rollback { .. }
                        | Alert::Equivocation { .. }
                )
            })
            .cloned()
            .collect();
        state.service = Some(service);
        state.certs = view.certs.iter().map(|c| c.signed().clone()).collect();
        state.bundle_parts = view.bundle_parts.clone();
        // Revoked for good: the backup's, `identity_doc`'s `removed`, and what the switch shows.
        let mut tombstones = view.revoked_apps.clone();
        tombstones.extend(doc.body().removed.iter().map(|r| r.app_id));
        tombstones.extend(
            answer
                .apps
                .iter()
                .filter(|s| s.revoked_at.is_some() || s.departed_at.is_some())
                .map(|s| s.app_id),
        );
        tombstones.sort_unstable();
        tombstones.dedup();
        // The epoch floor: the highest epoch whose keys were sent, by the records or as the
        // switch shows (Switch spec 3.2, 3.5).
        state.epoch_through = view
            .bundle_parts
            .iter()
            .map(|p| p.last_epoch)
            .chain(answer.apps.iter().filter_map(|s| s.keys_through))
            .chain(
                answer
                    .apps
                    .iter()
                    .flat_map(|s| s.bundle_ranges.iter().map(|r| r.last)),
            )
            .fold(doc.data_epoch(), u64::max);
        // A removed app whose record is still on the Homeserver owes its deletion again; its
        // grant reminder is raised once more, since this install can't tell it was seen.
        for app_id in &tombstones {
            if doc.listed_cert(app_id).is_none()
                && self
                    .env
                    .homeserver
                    .get(&app_record_path(app_id))
                    .await
                    .map_err(SignerError::Homeserver)?
                    .is_some()
            {
                state.cleanup.push(*app_id);
            }
        }
        state.tombstones = tombstones;
        state.newest = Some(Newest {
            doc: doc.signed().clone(),
            prev: view.prev,
            published: false,
            delivered_at: None,
        });
        // The version the backup holds goes first when the switch is at the one before.
        let deliver_first = first.map(|prev| Flow::Deliver {
            doc: doc.signed().clone(),
            prev,
            backup: None,
            step: DeliverStep::BackupWritten,
        });
        self.commit(state, deliver_first).await?;
        self.finish_flow().await?;

        // The next version, naming this install as the signer. It races any other signer, so
        // its backup is written once it has won (Switch wire 3.13).
        let key = self.signing_key()?;
        let (next, flow) = self.next_version(&key, |_| {})?;
        drop(key);
        let Flow::Deliver {
            doc: signed, prev, ..
        } = flow
        else {
            return Err(SignerError::Records(
                "a version without its delivery".into(),
            ));
        };
        let mut state = self.state.clone();
        state.signed_through = next.version();
        let flow = Flow::Deliver {
            doc: signed,
            prev,
            backup: None,
            step: DeliverStep::BackupWritten,
        };
        self.commit(state, Some(flow)).await?;
        self.resume().await?;
        self.write_backup_after_win().await?;
        Ok(next)
    }

    /// Write the backup holding the newest version, after a delivery that raced another
    /// signer has won (Switch wire 3.13). A write that fails leaves an alert, and the next
    /// version's backup write repairs it.
    async fn write_backup_after_win(&mut self) -> Result<()> {
        let Some(newest) = self.state.newest.clone() else {
            return Ok(());
        };
        let backup = self.seal_backup(&newest.doc, newest.prev)?;
        let bytes = serde_json::to_vec(&backup).map_err(|e| SignerError::Records(e.to_string()))?;
        if self
            .env
            .homeserver
            .put(SIGNER_BACKUP_PATH, bytes)
            .await
            .is_err()
        {
            let mut state = self.state.clone();
            state.alert(Alert::BackupNotWritten);
            self.commit(state, self.flow.clone()).await?;
        }
        Ok(())
    }
}
