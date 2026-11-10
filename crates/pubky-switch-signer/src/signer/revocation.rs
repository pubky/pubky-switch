//! Revocations, departures, data-epoch rotations and full-bundle requests (Switch spec 3.5,
//! 12.2, 12.3; Switch wire 3.3, 3.5, 7.4.11, 7.4.12).
//!
//! A revocation runs in this order, each step one idempotent call:
//!
//! 1. The App ID becomes a tombstone, kept for good, and the revocation is recorded as asked
//!    for, in one commit, before anything is sent.
//! 2. The signer revokes the app at the switch (`POST /apps/{app_id}/revoke`), which stops
//!    serving it at once.
//! 3. It stores, for every other current app, its bundle through the next data epoch, with
//!    its own scopes' keys, completing first an epoch a given-up rotation sent keys for.
//! 4. It delivers and publishes the version that moves the app from `apps` to `removed`, with
//!    `distrust_from` the switch's revocation time or an earlier time the user picked, drops
//!    its `renewed` entries, and raises `data_epoch` by one.
//! 5. It deletes the app's Homeserver record. Its Pubky grant can't be revoked through the
//!    Pubky SDK yet, so [`Alert::GrantRevocationOwed`] asks the user to revoke it.
//!
//! A departure, an app's own `leave`, is completed by the same steps 3 to 5 once the signer
//! sees it in `GET /apps`, with the departure time as `distrust_from` (Switch spec 12.3); its
//! App ID becomes a tombstone too. So is a revocation the switch shows that this signer didn't
//! ask for, such as one a crash interrupted. One version removes every such app.
//!
//! A full-bundle request (`POST /apps/{app_id}/keys`) is answered with the parts the app
//! lacks for its listed certificate, from epoch 1 to the current one, with `cert.put` first
//! when the app's record carries another certificate; the backup is written again after
//! them, at the same version, so it lists the parts (Switch wire 3.5 "Full bundles on
//! request").

use pubky_switch_client::ClientError;
use pubky_switch_client::client::answers::AppStatus;
use pubky_switch_core::ops::OpKind;
use pubky_switch_core::records::{
    IdentityDoc, RemovedApp, SIGNER_BACKUP_PATH, app_record_path, seal_bundle_parts,
};

use super::Signer;
use super::clients::Named;
use super::renewal::{Op, keyed, push_parts};
use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::state::{Flow, RefusedRequest, RenewBatch, Revoking};

/// The host's word that it showed the user what a step does and the user confirmed it: a
/// revocation cuts an app off for good (design note, section 5).
#[derive(Clone, Copy, Debug)]
pub struct UserConfirmed(());

impl UserConfirmed {
    /// Made by the host only once the user has seen the consequence and confirmed it.
    #[must_use]
    pub fn shown_and_confirmed() -> Self {
        Self(())
    }
}

impl Signer {
    /// Revoke the listed app `app_id` (Switch spec 12.2): at the switch first, then the
    /// rotation and the version that removes it, delivered and published, then its
    /// Homeserver record. `distrust_from`, when given, is an earlier time than the
    /// revocation from which the app's messages are distrusted, after a compromise; a later
    /// one counts as the revocation time. Returns the version that removes it.
    ///
    /// The App ID is kept for good: it is never approved or listed again.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotListed`] for an app the newest `identity.json` doesn't list; otherwise
    /// as [`Signer::resume`]. A revocation cut short goes on at [`Signer::run_due`]. While an
    /// alarm holds signing back, the app is still revoked at the switch, and the error is the
    /// alarm's: the version that removes it waits until the alarm is cleared.
    pub async fn revoke(
        &mut self,
        app_id: [u8; 16],
        distrust_from: Option<u64>,
        _confirmed: UserConfirmed,
    ) -> Result<IdentityDoc> {
        self.refresh().await?;
        self.check_named()?;
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        if newest.listed_cert(&app_id).is_none() {
            return Err(Refusal::NotListed.into());
        }
        let mut state = self.state.clone();
        if !state.tombstones.contains(&app_id) {
            state.tombstones.push(app_id);
        }
        let revoked_at = state
            .revoking
            .iter()
            .find(|r| r.app_id == app_id)
            .and_then(|r| r.revoked_at);
        state.revoking.retain(|r| r.app_id != app_id);
        state.revoking.push(Revoking {
            app_id,
            distrust_from,
            revoked_at,
        });
        self.commit(state, self.flow.clone()).await?;
        let completed = self.remove_now().await;
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        if newest.listed_cert(&app_id).is_none() {
            return Ok(newest);
        }
        // Never reported done while a version still lists the app: the user is told it is
        // pending, and whether the switch serves it no more.
        let (failures, error) = match completed {
            Ok((_, failures)) => (failures, None),
            Err(error) => (Vec::new(), Some(error)),
        };
        let own = failures.into_iter().find(|(app, _)| *app == app_id);
        let mut state = self.state.clone();
        state.alert(Alert::RevocationPending {
            app_id,
            at_switch: own.is_none(),
        });
        self.commit(state, self.flow.clone()).await?;
        Err(match (own, error) {
            (Some((_, failed)), _) => failed,
            (None, Some(error)) => error,
            (None, None) => SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                "Switch wire 7.4.12: the switch took the revocation but gave no time for it".into(),
            )),
        })
    }

    /// Remove every app that is revoked or departed and still listed, in one version with a
    /// rotation (Switch spec 12.2 steps 2 to 4, 12.3). The revocations asked for are sent to
    /// the switch first, also while an alarm holds signing back, since they sign nothing new.
    /// Returns whether a version was delivered.
    ///
    /// # Errors
    ///
    /// As [`Signer::resume`].
    ///
    /// A revocation the switch can't be reached for, or refuses, stays pending with
    /// [`Alert::RevocationPending`]; it doesn't hold back the other removals, nor the rest of
    /// [`Signer::run_due`].
    pub async fn complete_removals(&mut self) -> Result<bool> {
        Ok(self.remove_now().await?.0)
    }

    /// [`Signer::complete_removals`], with the revocations the switch didn't take and why.
    async fn remove_now(&mut self) -> Result<(bool, Vec<([u8; 16], SignerError)>)> {
        self.refresh().await?;
        self.check_named()?;
        let failures = self.revoke_at_switch().await?;
        self.ready().await?;
        let mut newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let (mut statuses, mut answered_at) = self.switch_apps_at().await?;
        let found = self.removals(&newest, &statuses, answered_at);
        if !found.unconfirmed.is_empty() {
            let mut state = self.state.clone();
            for app_id in &found.unconfirmed {
                state.alert(Alert::RevocationUnconfirmed { app_id: *app_id });
            }
            self.commit(state, None).await?;
        }
        if found.apps.is_empty() {
            self.drop_revoked_requests().await?;
            return Ok((false, failures));
        }
        // A rotation goes to the epoch after the newest version's, completing first an
        // epoch a given-up rotation sent keys for (Switch spec 3.2, 3.5).
        if self.state.epoch_through > newest.data_epoch() {
            self.complete_epoch(&statuses).await?;
            newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
            (statuses, answered_at) = self.switch_apps_at().await?;
        }
        let found = self.removals(&newest, &statuses, answered_at);
        let removing = found.apps;
        let last = newest
            .data_epoch()
            .checked_add(1)
            .ok_or_else(|| SignerError::Records("the data epoch can't go higher".into()))?;
        let key = self.signing_key()?;
        // The apps removed get no part, whatever the switch shows of them.
        let cut: Vec<[u8; 16]> = removing.iter().map(|r| r.app_id).collect();
        let (ops, mut alerts) = self.catch_up(&key, &newest, &statuses, &cut, last)?;
        alerts.extend(found.alerts);
        let batches = self.sign_batches(&key, newest.generation(), ops)?;
        let (doc, flow) = self.next_version(&key, |body| {
            for removed in &removing {
                body.apps.retain(|a| a.app_id != removed.app_id);
                body.renewed.retain(|r| r.app_id != removed.app_id);
                body.removed.push(*removed);
            }
            body.data_epoch = last;
        })?;
        drop(key);
        let mut state = self.state.clone();
        state.epoch_through = state.epoch_through.max(last);
        state.alerts.retain(|a| {
            !matches!(a, Alert::RevocationUnconfirmed { app_id }
                | Alert::RevocationPending { app_id, .. } if cut.contains(app_id))
        });
        for removed in &removing {
            if !state.tombstones.contains(&removed.app_id) {
                state.tombstones.push(removed.app_id);
            }
            if !state.cleanup.contains(&removed.app_id) {
                state.cleanup.push(removed.app_id);
            }
        }
        self.commit_batches(state, &newest, &statuses, alerts, batches, &doc, flow)
            .await?;
        self.resume().await?;
        Ok((true, failures))
    }

    /// Send the revocations asked for to the switch, as [`Signer::send_revocations`] does, and
    /// raise [`Alert::RevocationPending`] for each it didn't take. [`Signer::run_due`] runs it
    /// also when an alarm stops the rest, since it signs nothing new and cutting an app off is
    /// the safe step.
    pub(super) async fn revoke_at_switch(&mut self) -> Result<Vec<([u8; 16], SignerError)>> {
        let failures = self.send_revocations().await?;
        if !failures.is_empty() {
            let mut state = self.state.clone();
            for (app_id, _) in &failures {
                state.alert(Alert::RevocationPending {
                    app_id: *app_id,
                    at_switch: false,
                });
            }
            self.commit(state, self.flow.clone()).await?;
        }
        Ok(failures)
    }

    /// Check that this install is still the signer before a revocation goes to the switch:
    /// named in the records, and neither the switch's copy nor the backup shows another
    /// install that took over or a newer version of this install's own (Switch spec 4.3,
    /// 12.8; Switch wire 3.13). A rollback or an equivocation the copy shows doesn't stop
    /// it: a revocation signs nothing new, and goes out while an alarm holds signing back.
    async fn named_for_revoking(&mut self) -> Result<Named> {
        self.check_named()?;
        let held = self.service_client()?.apps().await?.identity;
        match self.confirm_copy(held.as_ref()).await {
            Ok(()) | Err(SignerError::Alarm(_)) => {}
            Err(error) => return Err(error),
        }
        let found = self
            .env
            .homeserver
            .get(SIGNER_BACKUP_PATH)
            .await
            .map_err(SignerError::Homeserver)?;
        if let Some(found) = found.and_then(|bytes| self.open_backup(&bytes).transpose()) {
            self.judge_backup(&found?).await?;
        }
        Named::check(&self.state)
    }

    /// Revoke at the switch every app a revocation was asked for that the newest version
    /// still lists (Switch spec 12.2 step 1). It is a request and signs nothing new; the
    /// switch answers a revocation sent again with no proof (Switch wire 7.4.12).
    async fn send_revocations(&mut self) -> Result<Vec<([u8; 16], SignerError)>> {
        let Some(newest) = self.state.newest_doc()? else {
            return Ok(Vec::new());
        };
        let pending: Vec<[u8; 16]> = self
            .state
            .revoking
            .iter()
            .map(|r| r.app_id)
            .filter(|app| newest.listed_cert(app).is_some())
            .collect();
        if pending.is_empty() {
            return Ok(Vec::new());
        }
        let named = self.named_for_revoking().await?;
        let client = self.service_client()?;
        let mut failures = Vec::new();
        for app_id in &pending {
            let answer = match client.revoke(&named, app_id).await {
                Ok(answer) => answer,
                Err(error) => {
                    failures.push((*app_id, error.into()));
                    continue;
                }
            };
            // The proof the client verified dates the revocation; one sent again gets none.
            let at = answer
                .proofs
                .first()
                .and_then(|proof| proof.body().chain.open().ok())
                .map(|envelope| envelope.server_time);
            if let Some(at) = at {
                let mut state = self.state.clone();
                for revoking in state.revoking.iter_mut().filter(|r| &r.app_id == app_id) {
                    revoking.revoked_at.get_or_insert(at);
                }
                if state.revoking != self.state.revoking {
                    self.commit(state, self.flow.clone()).await?;
                }
            }
        }
        Ok(failures)
    }

    /// The listed apps to remove, each with its `distrust_from`, the alerts that go with
    /// them, and the revocations asked for that have no time yet (Switch spec 12.2, 12.3).
    ///
    /// A revocation this signer asked for is dated by its proof, else by the switch's
    /// `revoked_at`. One the switch reports, or a departure, is dated by the earlier of
    /// `revoked_at` and `departed_at`, with [`Alert::RemovedAtSwitch`], bounded on both sides,
    /// with [`Alert::RemovalTimeBounded`]: never before the service time at which the switch
    /// took the first version listing the app, which it can't have left before, and never
    /// after `answered_at`, the service time of the verified answer reporting it, so a faulty
    /// switch can't keep the removed app's later messages counting. The user's earlier
    /// pick, after a compromise, reaches back as far as they chose.
    fn removals(&self, newest: &IdentityDoc, statuses: &[AppStatus], answered_at: u64) -> Removals {
        let mut found = Removals::default();
        for listed in &newest.body().apps {
            let app_id = listed.app_id;
            let status = statuses.iter().find(|s| s.app_id == app_id);
            let asked = self.state.revoking.iter().find(|r| r.app_id == app_id);
            let reported = status.and_then(|s| reported_time(s.revoked_at, s.departed_at));
            let at = match (asked.and_then(|r| r.revoked_at), reported) {
                (Some(own), _) => own,
                (None, Some(reported)) => {
                    let first_listed = self
                        .state
                        .listed_at
                        .iter()
                        .find(|(id, _)| *id == app_id)
                        .map(|(_, at)| *at);
                    let bounded = bounded_time(reported, first_listed, answered_at);
                    if bounded != reported {
                        found.alerts.push(Alert::RemovalTimeBounded {
                            app_id,
                            reported,
                            distrust_from: bounded,
                        });
                    }
                    bounded
                }
                (None, None) => {
                    if asked.is_some() && status.is_some_and(|s| !s.current) {
                        found.unconfirmed.push(app_id);
                    }
                    continue;
                }
            };
            if asked.is_none() {
                found.alerts.push(Alert::RemovedAtSwitch {
                    app_id,
                    left: status.is_some_and(|s| s.revoked_at.is_none()),
                });
            }
            let picked = asked.and_then(|r| r.distrust_from);
            found.apps.push(RemovedApp {
                app_id,
                distrust_from: picked.map_or(at, |picked| picked.min(at)),
            });
        }
        found
    }

    /// Forget the revocations asked for whose app the newest version no longer lists.
    async fn drop_revoked_requests(&mut self) -> Result<()> {
        let Some(newest) = self.state.newest_doc()? else {
            return Ok(());
        };
        let mut state = self.state.clone();
        state
            .revoking
            .retain(|r| newest.listed_cert(&r.app_id).is_some());
        if state.revoking != self.state.revoking {
            self.commit(state, self.flow.clone()).await?;
        }
        Ok(())
    }

    /// Delete the Homeserver record of each app the newest version removed, and ask the
    /// user to revoke its grant (Switch spec 12.2 step 4; design note, decision 4).
    pub(super) async fn clean_up_removed(&mut self) -> Result<()> {
        let Some(newest) = self.state.newest_doc()? else {
            return Ok(());
        };
        let done: Vec<[u8; 16]> = self
            .state
            .cleanup
            .iter()
            .copied()
            // Once no version lists the app: removed, or purged from `removed` since.
            .filter(|app| newest.listed_cert(app).is_none())
            .collect();
        for app_id in done {
            self.env
                .homeserver
                .delete(&app_record_path(&app_id))
                .await
                .map_err(SignerError::Homeserver)?;
            let mut state = self.state.clone();
            state.cleanup.retain(|a| *a != app_id);
            state.revoking.retain(|r| r.app_id != app_id);
            state.alert(Alert::GrantRevocationOwed { app_id });
            self.commit(state, self.flow.clone()).await?;
        }
        Ok(())
    }

    /// Purge the removed app `app_id` from `removed`, in a new version, once no more
    /// messages carrying its certificate are expected (Switch wire 3.3 "Purging"). Its App
    /// ID stays a tombstone, and the switch keeps it too. Returns that version.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotRemoved`] for an App ID the newest version doesn't list as removed;
    /// otherwise as [`Signer::resume`].
    pub async fn purge_removed(&mut self, app_id: [u8; 16]) -> Result<IdentityDoc> {
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        if !newest.body().removed.iter().any(|r| r.app_id == app_id) {
            return Err(Refusal::NotRemoved.into());
        }
        self.new_version(|body| body.removed.retain(|r| r.app_id != app_id))
            .await
    }

    /// Answer every pending full-bundle request of a current app (Switch wire 3.5 "Full
    /// bundles on request", 7.4.11): the parts for the epochs from 1 to the current one that
    /// the parts stored for its listed certificate don't cover, with `cert.put` first when
    /// its record carries another certificate. Then the backup is written again, at the same
    /// version. Returns the apps answered.
    ///
    /// An app whose certificate holds a scope no registered protocol owns gets nothing, with
    /// [`Alert::RotationSkipped`] (design note, decision 2).
    ///
    /// # Errors
    ///
    /// As [`Signer::resume`].
    pub async fn serve_full_bundles(&mut self) -> Result<Vec<[u8; 16]>> {
        self.ready().await?;
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let statuses = self.switch_apps().await?;
        let certs = self.held_certs()?;
        let now = self.env.clock.now_ms();
        let current = newest.data_epoch();
        let protocols = self.env.protocols.clone();
        let keyed = keyed(&protocols);
        let key = self.signing_key()?;
        // One flow for each app, so a refused one doesn't hold back the others.
        let mut requests: Vec<(RefusedRequest, Vec<Op>)> = Vec::new();
        let mut alerts = Vec::new();
        for listed in &newest.body().apps {
            let Some(status) = statuses.iter().find(|s| s.app_id == listed.app_id) else {
                continue;
            };
            let Some(requested) = status.full_bundle_requested else {
                continue;
            };
            let request = RefusedRequest {
                app_id: listed.app_id,
                requested,
            };
            let served = status.current
                && status.record_cert.is_some()
                && status.cert_expires_at.is_none_or(|at| at > now);
            if !served
                || self.cut_off(&listed.app_id)
                || self.state.refused_requests.contains(&request)
            {
                continue;
            }
            let Some(cert) = certs.iter().find(|c| c.hash() == listed.cert) else {
                return Err(SignerError::Records(
                    "a listed certificate isn't held".into(),
                ));
            };
            let unowned = protocols.unowned(cert.scopes());
            if !unowned.is_empty() {
                alerts.push(Alert::RotationSkipped {
                    app_id: listed.app_id,
                    scopes: unowned,
                });
                continue;
            }
            // The ranges stored for the listed certificate that the switch still shows; a
            // range whose part names another certificate, or that the signer can't tell,
            // counts as missing (Switch wire 3.5).
            let covered: Vec<(u64, u64)> = self
                .state
                .bundle_parts
                .iter()
                .filter(|p| p.app_id == listed.app_id && p.cert == listed.cert)
                .map(|p| (p.first_epoch, p.last_epoch))
                .filter(|range| {
                    status
                        .bundle_ranges
                        .iter()
                        .any(|r| (r.first, r.last) == *range)
                })
                .collect();
            let missing = missing_ranges(&covered, current);
            if missing.is_empty() {
                continue;
            }
            let mut ops: Vec<Op> = Vec::new();
            if status.record_cert != Some(listed.cert) {
                ops.push((
                    OpKind::CertPut {
                        target_app_id: listed.app_id,
                        cert: cert.signed().clone(),
                    },
                    None,
                ));
            }
            for (first, last) in missing {
                let sealed = seal_bundle_parts(&key, cert, first, last, &keyed)?;
                push_parts(&mut ops, listed.app_id, listed.cert, sealed);
            }
            requests.push((request, ops));
        }
        let signed: Vec<(RefusedRequest, Vec<RenewBatch>)> = requests
            .into_iter()
            .map(|(request, ops)| Ok((request, self.sign_batches(&key, newest.generation(), ops)?)))
            .collect::<Result<_>>()?;
        drop(key);
        let mut state = self.state.clone();
        for alert in alerts {
            state.alert(alert);
        }
        // A refused request is tried again once the app asks anew.
        state.refused_requests.retain(|refused| {
            statuses.iter().any(|s| {
                s.app_id == refused.app_id && s.full_bundle_requested == Some(refused.requested)
            })
        });
        if state != self.state {
            self.commit(state, None).await?;
        }
        let mut answered = Vec::new();
        for (request, batches) in signed {
            let held = self.state.newest.clone().ok_or(Refusal::NotSetUp)?;
            // After the parts, the newest version again: its backup lists them, and its
            // delivery is a retry the switch answers with its proof (Switch wire 3.13, 7.4.2).
            let flow = Flow::Renew {
                batches,
                sent: 0,
                doc: held.doc,
                prev: held.prev,
            };
            self.commit(self.state.clone(), Some(flow)).await?;
            match self.resume().await {
                Ok(()) => answered.push(request.app_id),
                Err(SignerError::Switch(ClientError::Switch { status, .. }))
                    if (400..500).contains(&status) && status != 408 && status != 429 =>
                {
                    let mut state = self.state.clone();
                    state.refused_requests.push(request);
                    state.alert(Alert::FullBundleRefused {
                        app_id: request.app_id,
                    });
                    self.commit(state, self.flow.clone()).await?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(answered)
    }
}

/// What [`Signer::removals`] finds.
#[derive(Default)]
struct Removals {
    /// The apps to remove.
    apps: Vec<RemovedApp>,
    /// The alerts that go with them.
    alerts: Vec<Alert>,
    /// The revocations asked for that the switch took without a time.
    unconfirmed: Vec<[u8; 16]>,
}

/// The time a switch reports for a removal: the earlier of a revocation and a departure,
/// should it show both, which an honest service never does, since an app that left can't be
/// revoked again (Switch wire 7.4.12).
fn reported_time(revoked_at: Option<u64>, departed_at: Option<u64>) -> Option<u64> {
    match (revoked_at, departed_at) {
        (Some(revoked), Some(left)) => Some(revoked.min(left)),
        (revoked, left) => revoked.or(left),
    }
}

/// A removal time the switch reported, kept between `first_listed`, when it took the first
/// version listing the app, and `answered_at`, when it signed the answer reporting it.
fn bounded_time(reported: u64, first_listed: Option<u64>, answered_at: u64) -> u64 {
    let floor = first_listed.unwrap_or(0);
    reported.max(floor).min(answered_at.max(floor))
}

/// The ranges of epochs from 1 to `current` that `covered` leaves out, in order.
fn missing_ranges(covered: &[(u64, u64)], current: u64) -> Vec<(u64, u64)> {
    let mut covered = covered.to_vec();
    covered.sort_unstable();
    let mut missing = Vec::new();
    let mut next = 1u64;
    for (first, last) in covered {
        if first > next {
            missing.push((next, first.saturating_sub(1).min(current)));
        }
        next = next.max(last.saturating_add(1));
        if next > current {
            break;
        }
    }
    if next <= current {
        missing.push((next, current));
    }
    missing.retain(|(first, last)| first <= last);
    missing
}

#[cfg(test)]
mod tests {
    use super::{bounded_time, missing_ranges, reported_time};

    #[test]
    fn test_bounded_time_stays_between_the_listing_and_the_answer() {
        assert_eq!(bounded_time(5, Some(3), 9), 5);
        assert_eq!(bounded_time(1, Some(3), 9), 3);
        assert_eq!(bounded_time(12, Some(3), 9), 9);
        assert_eq!(bounded_time(1, None, 9), 1);
    }

    #[test]
    fn test_reported_time_is_the_earlier_of_a_revocation_and_a_departure() {
        assert_eq!(reported_time(None, None), None);
        assert_eq!(reported_time(Some(5), None), Some(5));
        assert_eq!(reported_time(None, Some(7)), Some(7));
        assert_eq!(reported_time(Some(9), Some(7)), Some(7));
        assert_eq!(reported_time(Some(3), Some(7)), Some(3));
    }

    #[test]
    fn test_missing_ranges_fill_every_gap_up_to_the_current_epoch() {
        assert_eq!(missing_ranges(&[], 3), [(1, 3)]);
        assert_eq!(missing_ranges(&[(1, 3)], 3), []);
        assert_eq!(missing_ranges(&[(2, 2)], 4), [(1, 1), (3, 4)]);
        assert_eq!(missing_ranges(&[(3, 4), (1, 1)], 5), [(2, 2), (5, 5)]);
        assert_eq!(missing_ranges(&[(1, 9)], 3), []);
    }
}
