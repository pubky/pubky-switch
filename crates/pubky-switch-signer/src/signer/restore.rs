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
//! In place, the install's own records are checked too: no alarm stands, since a restore never
//! clears one, and the backup isn't below the mark (wire 3.3 "Never back").
//!
//! The install then takes the backup's records as its own, with these additions:
//! - the App IDs `GET /apps` shows revoked or departed join the tombstones, and, in place, so
//!   do this install's own, with the revocations it asked for and the deletions it owes;
//! - the epoch floor is the highest epoch whose keys the records or the switch show were
//!   sent, at most one past `data_epoch`;
//! - the removed apps are left for the routine run to check, whose record still on the
//!   Homeserver owes its deletion again, with its grant reminder raised once more.
//!
//! It delivers the next version naming this install as the signer, publishes it, and owes its
//! own backup, which `resume` writes once that delivery has won (wire 3.13 "When it is
//! written"). Records behind their own newer version, or an install another took over from,
//! are restored in place this way.

use pubky_switch_client::client::answers::AppsAnswer;
use pubky_switch_core::records::{IDENTITY_PATH, IdentityDoc, SIGNER_BACKUP_PATH, app_record_path};
use pubky_switch_core::sig::SignedDoc;

use super::SignerEnv;
use super::clients::{RequestClient, Target};
use super::revocation::UserConfirmed;
use super::{Signer, gate};
use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::key::{BackupView, IdentityKeyring};
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
        if state::set_up(&env.store, &identity).await? {
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
        signer.restore_records(false, confirmed).await?;
        Ok(signer)
    }

    /// Restore this install's records from the signer backup on the Homeserver, in place:
    /// when they are behind a newer version of its own ([`Alert::RecordsBehind`]), or when
    /// another install signs and the user has this one take over (Switch spec 12.8, Switch
    /// wire 3.13). Returns the version this install delivers as the signer.
    ///
    /// # Errors
    ///
    /// [`Refusal::Erased`] once the account is erased; [`Refusal::FlowInProgress`] while a
    /// flow is in progress; [`Refusal::HandingOver`] or
    /// [`Refusal::TakingOver`] while a hand-over is in progress, which the abort or the
    /// take-over ends; [`Refusal::NoBackup`] when the
    /// Homeserver holds none; [`Refusal::UnreadableBackup`] for one that doesn't open or
    /// verify; [`Refusal::StaleBackup`] when the switch's or the Homeserver's copy is past it;
    /// otherwise as [`Signer::resume`].
    pub async fn restore(&mut self, confirmed: UserConfirmed) -> Result<IdentityDoc> {
        self.refresh().await?;
        // An erased account has no switch to restore at (Switch spec 12.7).
        if self.state.erased {
            return Err(Refusal::Erased.into());
        }
        if self.flow.is_some() {
            return Err(Refusal::FlowInProgress.into());
        }
        // A restore would sign the version after the one handed over, racing the new signer
        // at its own version, and drop the hand-over from the records.
        if let Some(handing) = &self.state.handing_over {
            return Err(Refusal::HandingOver {
                to_app: handing.to_app,
            }
            .into());
        }
        if self.state.taking_over {
            return Err(Refusal::TakingOver.into());
        }
        self.restore_records(true, confirmed).await
    }

    async fn restore_records(
        &mut self,
        in_place: bool,
        _confirmed: UserConfirmed,
    ) -> Result<IdentityDoc> {
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
        let first = self
            .check_restore(&view, answer.identity.as_ref(), in_place)
            .await?;

        // Revoked for good: the backup's, `identity_doc`'s `removed`, what the switch shows,
        // and, in place, this install's own, with the revocations it asked for and the
        // deletions it owes: one whose record is gone already still owes its grant reminder,
        // which `deletion_checks`, finding no record, wouldn't raise.
        let mut tombstones = view.revoked_apps.clone();
        tombstones.extend(doc.body().removed.iter().map(|r| r.app_id));
        tombstones.extend(removed_at_switch(&answer, &doc));
        let cleanup = if in_place {
            tombstones.extend(self.state.tombstones.iter().copied());
            self.state.cleanup.clone()
        } else {
            Vec::new()
        };
        let mut state = self.taken_records(&view, &answer, service, tombstones, cleanup);
        if in_place {
            state.revoking.clone_from(&self.state.revoking);
        }
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
        // its backup is owed, and written by `resume` once the delivery has won (Switch wire
        // 3.13).
        let key = self.signing_key()?;
        let (next, flow) = self.next_version_closing(&key, |_| {})?;
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
        state.backup_owed = true;
        let flow = Flow::Deliver {
            doc: signed,
            prev,
            backup: None,
            step: DeliverStep::BackupWritten,
        };
        self.commit(state, Some(flow)).await?;
        self.resume().await?;
        Ok(next)
    }

    /// The records an install takes from records it received or restored, `view`, and the
    /// switch's `GET /apps` answer `apps` (Switch wire 3.12, 3.13), with `tombstones` the App
    /// IDs revoked for good and `cleanup` the deletions owed already. The versions this
    /// install spent stay spent; of its alerts, those about the records taken over go. The
    /// caller sets `newest`.
    ///
    /// - The apps the document lists get no listing floor for their removal time: the time
    ///   they were first listed is unknown here, and a reported time before it changes
    ///   nothing anyway (Switch spec 12.3).
    /// - The epoch floor is the highest epoch whose keys were sent, by the records or as the
    ///   switch shows, and never more than one past `data_epoch`, since epochs never skip
    ///   (Switch spec 3.2, 3.5).
    /// - A removed app's record may still be on the Homeserver: the routine run checks, a few
    ///   at a time, and owes its deletion with its grant reminder raised once more, since
    ///   this install can't tell the user saw it. Taking over doesn't wait for that.
    pub(super) fn taken_records(
        &self,
        view: &BackupView,
        apps: &AppsAnswer,
        service: Service,
        mut tombstones: Vec<[u8; 16]>,
        cleanup: Vec<[u8; 16]>,
    ) -> SignerState {
        let doc = &view.identity_doc;
        let mut state = SignerState::new(self.state.identity, self.state.install);
        state.signed_through = self.state.signed_through.max(doc.version());
        state.alerts = self
            .state
            .alerts
            .iter()
            .filter(|a| {
                !matches!(
                    a,
                    Alert::RecordsBehind { .. } | Alert::ManagedByOtherInstall { .. }
                )
            })
            .cloned()
            .collect();
        state.service = Some(service);
        state.certs = view.certs.iter().map(|c| c.signed().clone()).collect();
        state.bundle_parts = view.bundle_parts.clone();
        state.cleanup = cleanup;
        tombstones.sort_unstable();
        tombstones.dedup();
        state.listed_at = doc.body().apps.iter().map(|a| (a.app_id, 0)).collect();
        let claimed = view
            .bundle_parts
            .iter()
            .map(|p| p.last_epoch)
            .chain(apps.apps.iter().filter_map(|s| s.keys_through))
            .chain(
                apps.apps
                    .iter()
                    .flat_map(|s| s.bundle_ranges.iter().map(|r| r.last)),
            )
            .fold(doc.data_epoch(), u64::max);
        let most = doc.data_epoch().saturating_add(1);
        if claimed > most {
            state.alert(Alert::EpochFloorBounded {
                claimed,
                kept: most,
            });
        }
        state.epoch_through = claimed.min(most);
        state.deletion_checks = tombstones
            .iter()
            .copied()
            .filter(|app| doc.listed_cert(app).is_none() && !state.cleanup.contains(app))
            .collect();
        state.tombstones = tombstones;
        state
    }

    /// The checks a restore passes before it takes the backup's records (Switch wire 3.13
    /// "Restoring"). They are its only guard: once the records are replaced, the signing gate
    /// passes by construction. Returns, when the backup's own version is to be delivered
    /// first, the `prev` it builds on.
    ///
    /// - In place, the records' own state: no alarm's alert stands, since a restore never
    ///   clears one, and the backup isn't below the mark, by version or generation, nor
    ///   another body at its version, nor below a newer version of this install's own the
    ///   switch showed (`RecordsBehind`) (Switch wire 3.3 "Never back").
    /// - The switch's copy, `held`, is the backup's version, or the one it builds on, or
    ///   none under a backup of the account's first version.
    /// - The Homeserver's copy is neither newer than the backup's version nor another
    ///   document at it.
    async fn check_restore(
        &self,
        view: &BackupView,
        held: Option<&SignedDoc>,
        in_place: bool,
    ) -> Result<Option<Option<[u8; 32]>>> {
        let identity = self.state.identity;
        let doc = &view.identity_doc;
        if in_place {
            if let Some(alarm) = gate::held_alarm(&self.state) {
                return Err(SignerError::Alarm(alarm.clone()));
            }
            // A version of this install's own seen at the switch counts as the mark does:
            // the backup never goes below it either.
            if let Some(seen) = self.state.records_behind
                && doc.version() < seen
            {
                return Err(Refusal::StaleBackup.into());
            }
            if let Some(mark) = self.high_water() {
                let below = doc.version() < mark.version
                    || doc.generation() < mark.generation
                    || (doc.version() == mark.version && doc.body_hash() != mark.body_hash);
                if below {
                    return Err(Refusal::StaleBackup.into());
                }
            }
        }
        let held = held
            .map(|signed| IdentityDoc::verify(signed, &identity))
            .transpose()?;
        let first = match (&held, view.prev) {
            (Some(copy), _) if copy.hash() == doc.hash() => None,
            (Some(copy), Some(prev)) if copy.hash() == prev => Some(view.prev),
            (None, None) => Some(None),
            _ => return Err(Refusal::StaleBackup.into()),
        };
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
        Ok(first)
    }

    /// Write the backup a restore owes, holding the newest version, once its delivery has won
    /// (Switch wire 3.13 "When it is written"). It passes the checks of every backup write
    /// first ([`Signer::check_backup_write`]): a backup there that another install wrote at or
    /// past the mark, or a newer one of this install's own, is never written over, and the
    /// install stops as those checks say. A write, or a check, that fails on the Homeserver or
    /// the switch raises [`Alert::BackupNotWritten`] and stays owed; nothing is held back by
    /// it.
    pub(super) async fn write_owed_backup(&mut self) -> Result<()> {
        if !self.state.backup_owed || self.flow.is_some() || gate::refusal(&self.state).is_some() {
            return Ok(());
        }
        let Some(newest) = self.state.newest.clone() else {
            return Ok(());
        };
        // Sealed before the check, so only the check's read comes before the write.
        let backup = self.seal_backup(&newest.doc, newest.prev)?;
        let bytes = serde_json::to_vec(&backup).map_err(|e| SignerError::Records(e.to_string()))?;
        let raised = match self.check_backup_write().await {
            Ok(raised) => raised,
            Err(SignerError::Homeserver(_) | SignerError::Switch(_)) => {
                let mut state = self.state.clone();
                state.alert(Alert::BackupNotWritten);
                if state != self.state {
                    self.commit(state, None).await?;
                }
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let written = self
            .env
            .homeserver
            .put(SIGNER_BACKUP_PATH, bytes)
            .await
            .is_ok();
        let mut state = self.state.clone();
        if let Some(alert) = raised {
            state.alert(alert);
        }
        if written {
            state.backup_owed = false;
            state.publish_after_backup = false;
            state.alerts.retain(|a| *a != Alert::BackupNotWritten);
        } else {
            state.alert(Alert::BackupNotWritten);
        }
        if state != self.state {
            self.commit(state, None).await?;
        }
        Ok(())
    }

    /// Check, a few at a time, whether the record of a removed app a restore found is still
    /// on the Homeserver, and owe its deletion if it is (Switch spec 12.2 step 4). A read that
    /// fails postpones the rest to the next run.
    pub(super) async fn check_owed_deletions(&mut self) -> Result<()> {
        if self.state.deletion_checks.is_empty() {
            return Ok(());
        }
        let mut state = self.state.clone();
        let batch: Vec<[u8; 16]> = state
            .deletion_checks
            .iter()
            .take(DELETION_CHECKS_PER_RUN)
            .copied()
            .collect();
        for app_id in batch {
            match self.env.homeserver.get(&app_record_path(&app_id)).await {
                Ok(found) => {
                    state.deletion_checks.retain(|a| *a != app_id);
                    if found.is_some() && !state.cleanup.contains(&app_id) {
                        state.cleanup.push(app_id);
                    }
                }
                Err(_) => break,
            }
        }
        if state != self.state {
            self.commit(state, self.flow.clone()).await?;
        }
        Ok(())
    }
}

/// The App IDs `GET /apps` shows revoked or departed, of the apps `version` lists: a removal
/// is taken from the switch only for an app the identity's own version lists, as a routine
/// run takes one. An ID the switch shows for any other app counts for nothing: one the
/// version removed comes from its `removed` and the records, and one no version listed would
/// only grow the records, and a move's enrollment with them, on a switch's word (Switch wire
/// 3.7, 7.4.12).
pub(super) fn removed_at_switch<'a>(
    apps: &'a AppsAnswer,
    version: &'a IdentityDoc,
) -> impl Iterator<Item = [u8; 16]> + 'a {
    apps.apps
        .iter()
        .filter(|s| s.revoked_at.is_some() || s.departed_at.is_some())
        .map(|s| s.app_id)
        .filter(|id| version.listed_cert(id).is_some())
}

/// How many removed apps' records a run checks for.
const DELETION_CHECKS_PER_RUN: usize = 32;
