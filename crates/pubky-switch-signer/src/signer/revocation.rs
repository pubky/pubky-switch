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

use pubky_switch_client::client::answers::AppStatus;
use pubky_switch_core::ops::OpKind;
use pubky_switch_core::records::{IdentityDoc, RemovedApp, app_record_path, seal_bundle_parts};

use super::Signer;
use super::renewal::{Op, keyed, push_parts};
use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::state::{Flow, Revoking};

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
    /// as [`Signer::resume`]. A revocation cut short goes on at [`Signer::run_due`].
    pub async fn revoke(
        &mut self,
        app_id: [u8; 16],
        distrust_from: Option<u64>,
        _confirmed: UserConfirmed,
    ) -> Result<IdentityDoc> {
        self.ready().await?;
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        if newest.listed_cert(&app_id).is_none() {
            return Err(Refusal::NotListed.into());
        }
        let mut state = self.state.clone();
        if !state.tombstones.contains(&app_id) {
            state.tombstones.push(app_id);
        }
        state.revoking.retain(|r| r.app_id != app_id);
        state.revoking.push(Revoking {
            app_id,
            distrust_from,
        });
        self.commit(state, None).await?;
        self.complete_removals().await?;
        self.state
            .newest_doc()?
            .ok_or_else(|| Refusal::NotSetUp.into())
    }

    /// Remove every app that is revoked or departed and still listed, in one version with a
    /// rotation (Switch spec 12.2 steps 2 to 4, 12.3). Revocations asked for are sent to the switch first. Returns whether a
    /// version was delivered.
    ///
    /// # Errors
    ///
    /// As [`Signer::resume`].
    pub async fn complete_removals(&mut self) -> Result<bool> {
        self.ready().await?;
        let mut newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let mut statuses = self.switch_apps().await?;
        // Step 2, for the revocations asked for that the switch doesn't show yet.
        let unsent: Vec<[u8; 16]> = self
            .state
            .revoking
            .iter()
            .filter(|r| newest.listed_cert(&r.app_id).is_some())
            .filter(|r| {
                !statuses
                    .iter()
                    .any(|s| s.app_id == r.app_id && s.revoked_at.is_some())
            })
            .map(|r| r.app_id)
            .collect();
        if !unsent.is_empty() {
            let client = self.service_client()?;
            for app_id in &unsent {
                client.revoke(app_id).await?;
            }
            statuses = self.switch_apps().await?;
        }
        if self.removals(&newest, &statuses).is_empty() {
            self.drop_revoked_requests().await?;
            return Ok(false);
        }
        // A rotation goes to the epoch after the newest version's, completing first an
        // epoch a given-up rotation sent keys for (Switch spec 3.2, 3.5).
        if self.state.epoch_through > newest.data_epoch() {
            self.complete_epoch(&statuses).await?;
            newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
            statuses = self.switch_apps().await?;
        }
        let removing = self.removals(&newest, &statuses);
        let last = newest
            .data_epoch()
            .checked_add(1)
            .ok_or_else(|| SignerError::Records("the data epoch can't go higher".into()))?;
        let key = self.keyring.unlock()?;
        // The apps the switch no longer serves get no part, the removed ones among them.
        let (ops, alerts) = self.catch_up(&key, &newest, &statuses, None, last)?;
        let batches = self.sign_batches(newest.generation(), ops)?;
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
        Ok(true)
    }

    /// The listed apps the switch shows revoked or departed, each with its `distrust_from`:
    /// the revocation or departure time, or the earlier one the user picked.
    fn removals(&self, newest: &IdentityDoc, statuses: &[AppStatus]) -> Vec<RemovedApp> {
        newest
            .body()
            .apps
            .iter()
            .filter_map(|listed| {
                let status = statuses.iter().find(|s| s.app_id == listed.app_id)?;
                let at = status.revoked_at.or(status.departed_at)?;
                let picked = self
                    .state
                    .revoking
                    .iter()
                    .find(|r| r.app_id == listed.app_id)
                    .and_then(|r| r.distrust_from);
                Some(RemovedApp {
                    app_id: listed.app_id,
                    distrust_from: picked.map_or(at, |picked| picked.min(at)),
                })
            })
            .collect()
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
            .filter(|app| newest.body().removed.iter().any(|r| &r.app_id == app))
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
        let key = self.keyring.unlock()?;
        let mut ops: Vec<Op> = Vec::new();
        let mut alerts = Vec::new();
        let mut answered = Vec::new();
        for listed in &newest.body().apps {
            let Some(status) = statuses.iter().find(|s| s.app_id == listed.app_id) else {
                continue;
            };
            let served = status.current
                && status.record_cert.is_some()
                && status.cert_expires_at.is_none_or(|at| at > now);
            if status.full_bundle_requested.is_none() || !served {
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
            answered.push(listed.app_id);
        }
        drop(key);
        let mut state = self.state.clone();
        for alert in alerts {
            state.alert(alert);
        }
        if ops.is_empty() {
            if state.alerts != self.state.alerts {
                self.commit(state, None).await?;
            }
            return Ok(answered);
        }
        let batches = self.sign_batches(newest.generation(), ops)?;
        let held = self.state.newest.clone().ok_or(Refusal::NotSetUp)?;
        // After the parts, the newest version again: its backup lists them, and its delivery
        // is a retry the switch answers with its proof (Switch wire 3.13, 7.4.2).
        let flow = Flow::Renew {
            batches,
            sent: 0,
            doc: held.doc,
            prev: held.prev,
        };
        self.commit(state, Some(flow)).await?;
        self.resume().await?;
        Ok(answered)
    }
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
    use super::missing_ranges;

    #[test]
    fn test_missing_ranges_fill_every_gap_up_to_the_current_epoch() {
        assert_eq!(missing_ranges(&[], 3), [(1, 3)]);
        assert_eq!(missing_ranges(&[(1, 3)], 3), []);
        assert_eq!(missing_ranges(&[(2, 2)], 4), [(1, 1), (3, 4)]);
        assert_eq!(missing_ranges(&[(3, 4), (1, 1)], 5), [(2, 2), (5, 5)]);
        assert_eq!(missing_ranges(&[(1, 9)], 3), []);
    }
}
