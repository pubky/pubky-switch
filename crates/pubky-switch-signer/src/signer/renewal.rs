//! Renewals and reductions (Switch spec 3.2, 12.2; Switch wire 3.5, 3.8).
//!
//! A renewal gives a listed app a new certificate with the same App ID, signing key and
//! bundle key, and a later `issued_at`; its scopes, switch permissions and expiry may change.
//! [`Signer::renew`] signs, sign once, and commits together:
//!
//! 1. the new certificate, stored with `cert.put` in the batch of the first part of a full key
//!    bundle made for it (Switch wire 3.8 step 1);
//! 2. when the new certificate lacks a scope with keys, the rotation to the next data epoch:
//!    the full bundle runs through it, and every other current app gets its bundle for it,
//!    holding its own scopes' keys (Switch wire 3.8 "A removed scope's keys rotate");
//! 3. the renewing `identity.json`, listing the new certificate's hash, the earlier one in
//!    `renewed` with `until: null`, and the raised `data_epoch` of a rotation (step 2).
//!
//! It sends the batches in order, recording the parts each stores once the switch took it, then
//! delivers and publishes the version.
//!
//! A rotation goes to the epoch after the newest version's `data_epoch`. When a rotation that was
//! given up had sent keys of a later epoch, that epoch is completed first, in a version of its
//! own: every current app holding each keyed scope gets its keys through it, the app whose
//! reduction was given up included, and the version raises `data_epoch` to it. So no app holds
//! the new epoch's keys early, and no epoch is skipped (Switch spec 3.2, 3.5).
//!
//! A scope no registered protocol owns may be removed, never kept, and removing one rotates. A
//! rotation gives an app whose certificate holds one no part, with [`Alert::RotationSkipped`]
//! (design note, decision 2).
//!
//! A renewal that removes a scope or a switch permission, or expires earlier, is a reduction.
//! It closes at once: the next version sets `until` of the app's open renewals to the service
//! time at which the switch took the renewing version, plus the clock tolerance. That closing
//! delivery comes before any other, also when a crash came between the two (Switch wire 3.8
//! "A closing delivery owed"). If the switch never gives that time, the closing uses the next
//! delivery's, never the signer's own clock. Any other renewal closes once the switch holds the app's record
//! carrying the new certificate ([`Signer::complete_renewals`]).
//!
//! The signer writes only `key_bundle.put` and `cert.put` (Switch spec 13.5).

use pubky_switch_client::ClientError;
use pubky_switch_client::client::Batch;
use pubky_switch_client::client::answers::AppStatus;
use pubky_switch_core::keys::IdentityKey;
use pubky_switch_core::ops::{KeyBundlePut, OpKind};
use pubky_switch_core::records::{
    AppCert, AppCertBody, BundlePart, CLOCK_TOLERANCE_MS, IdentityDoc, MAX_CERT_LIFETIME_MS,
    RenewedCert, StoredPart, incremental_first_epoch, is_reduction, owed_closings,
    reduction_rotates, seal_bundle_parts,
};
use pubky_switch_core::sig::SignedDoc;

use super::Signer;
use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::protocol::Protocols;
use crate::state::{Bytes, DeliverStep, Flow, RenewBatch, SignerState};

/// The most signed operations in one batch (Switch wire 6.4).
const MAX_OPS: usize = 8;

/// What a renewal changes. What it leaves `None` stays as it is, but the expiry, which a
/// renewal always sets: by default, the certificate lifetime from now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertChange {
    /// The new scopes; their switch permissions come from the registered protocols' tables.
    pub scopes: Option<Vec<String>>,
    /// The new expiry, in Unix milliseconds.
    pub expires_at: Option<u64>,
}

impl Signer {
    /// Renew the certificate of the listed app `app_id` with `change` (Switch spec 3.2,
    /// Switch wire 3.8), then deliver and publish the renewing version. A reduction's
    /// closing version follows at once. Returns the renewing version.
    ///
    /// The new scopes must all be owned by registered protocols, so a scope none owns can be
    /// removed but never kept; removing one rotates, as its keys can't be judged (design
    /// note, decision 2).
    ///
    /// # Errors
    ///
    /// [`Refusal::NotListed`] for an app the newest `identity.json` doesn't list; the scope
    /// refusals of [`crate::Protocols::terms`] for new scopes; [`SignerError::InvalidData`]
    /// for an expiry the certificate rules refuse; otherwise as [`Signer::resume`].
    pub async fn renew(&mut self, app_id: [u8; 16], change: CertChange) -> Result<IdentityDoc> {
        self.ready().await?;
        let identity = self.state.identity;
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let listed = newest.listed_cert(&app_id).ok_or(Refusal::NotListed)?;
        let old = self
            .held_certs()?
            .into_iter()
            .find(|cert| cert.hash() == listed)
            .ok_or_else(|| SignerError::Records("the listed certificate isn't held".into()))?;
        let scopes = change.scopes.unwrap_or_else(|| old.scopes().to_vec());
        let terms = self.env.protocols.terms(&scopes)?;
        let now = self.env.clock.now_ms();
        let issued = now.max(old.issued_at().saturating_add(1));
        let expires = change
            .expires_at
            .unwrap_or_else(|| issued.saturating_add(self.state.cert_lifetime_ms))
            .min(issued.saturating_add(MAX_CERT_LIFETIME_MS));
        // The switch's view, read before anything is signed: this install still signs, and
        // the app has joined.
        let statuses = self.switch_apps().await?;
        let joined = statuses
            .iter()
            .any(|s| s.app_id == app_id && s.record_cert.is_some());
        if !joined {
            return Err(Refusal::NotJoined.into());
        }

        let key = self.keyring.unlock()?;
        let new = AppCert::issue(
            &key,
            AppCertBody::new(
                identity,
                old.signing_key(),
                old.bundle_key(),
                scopes,
                &terms.permissions,
                issued,
                expires,
            ),
        )?;
        drop(key);
        let protocols = self.env.protocols.clone();
        let keyed = keyed(&protocols);
        let rotates = reduction_rotates(&old, &new, &keyed);
        // A rotation goes to the epoch after the newest version's. When a rotation that was
        // given up sent keys above that one, the epoch it sent is completed first, so no app
        // holds the new epoch's keys early and no epoch is skipped (Switch spec 3.2, 3.5).
        let (newest, statuses) = if rotates && self.state.epoch_through > newest.data_epoch() {
            self.complete_epoch(&statuses).await?;
            let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
            if newest.listed_cert(&app_id) != Some(listed) {
                return Err(Refusal::Superseded {
                    version: newest.version(),
                }
                .into());
            }
            (newest, self.switch_apps().await?)
        } else {
            (newest, statuses)
        };
        let current = newest.data_epoch();
        let last = if rotates {
            current
                .checked_add(1)
                .ok_or_else(|| SignerError::Records("the data epoch can't go higher".into()))?
        } else {
            current
        };

        let key = self.keyring.unlock()?;
        // The full bundle for the new certificate, the cert.put in its first batch.
        let mut ops = vec![(
            OpKind::CertPut {
                target_app_id: app_id,
                cert: new.signed().clone(),
            },
            None,
        )];
        let full = seal_bundle_parts(&key, &new, 1, last, &keyed)?;
        push_parts(&mut ops, app_id, new.hash(), full);
        // A rotation: every other current app's bundle through the new epoch.
        let mut alerts = Vec::new();
        if rotates {
            let (more, skipped) = self.catch_up(&key, &newest, &statuses, Some(app_id), last)?;
            ops.extend(more);
            alerts = skipped;
        }
        let batches = self.sign_batches(newest.generation(), ops)?;
        let (doc, flow) = self.next_version(&key, |body| {
            if let Some(listed) = body.apps.iter_mut().find(|a| a.app_id == app_id) {
                listed.cert = new.hash();
            }
            body.renewed.push(RenewedCert {
                app_id,
                cert: old.hash(),
                until: None,
            });
            body.data_epoch = last;
        })?;
        drop(key);
        let mut state = self.state.clone();
        state.certs.push(new.signed().clone());
        state.epoch_through = state.epoch_through.max(last);
        self.commit_batches(state, &newest, &statuses, alerts, batches, &doc, flow)
            .await?;
        self.resume().await?;
        Ok(doc)
    }

    /// Complete the epoch `epoch_through`, above the newest version's `data_epoch`: give every
    /// current app holding each keyed scope its keys through it, the app of a given-up
    /// reduction included, as it still holds its scopes, then deliver a version raising
    /// `data_epoch` to it (Switch spec 3.2, 3.5; Switch wire 3.8). `statuses` is the switch's
    /// view, read once its copy was confirmed.
    async fn complete_epoch(&mut self, statuses: &[AppStatus]) -> Result<()> {
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let through = self.state.epoch_through;
        let key = self.keyring.unlock()?;
        let (ops, alerts) = self.catch_up(&key, &newest, statuses, None, through)?;
        let batches = self.sign_batches(newest.generation(), ops)?;
        let (doc, flow) = self.next_version(&key, |body| body.data_epoch = through)?;
        drop(key);
        let state = self.state.clone();
        self.commit_batches(state, &newest, statuses, alerts, batches, &doc, flow)
            .await?;
        self.resume().await
    }

    /// The bundles that bring every current app the newest version lists, but `except`,
    /// through epoch `last`, each with its own scopes' keys for the epochs it lacks, and the
    /// alerts for the apps left out (Switch wire 3.5, 3.8).
    ///
    /// An app the switch doesn't serve now, one not current, not joined or expired, gets no
    /// part, nor does one whose certificate holds a scope no registered protocol owns, with
    /// [`Alert::RotationSkipped`]. Either gets the epochs it lacks from its next bundle, which
    /// starts after `keys_through`.
    fn catch_up(
        &self,
        key: &IdentityKey,
        newest: &IdentityDoc,
        statuses: &[AppStatus],
        except: Option<[u8; 16]>,
        last: u64,
    ) -> Result<(Vec<Op>, Vec<Alert>)> {
        let certs = self.held_certs()?;
        let now = self.env.clock.now_ms();
        let keyed = keyed(&self.env.protocols);
        let mut ops = Vec::new();
        let mut alerts = Vec::new();
        for listed in &newest.body().apps {
            if Some(listed.app_id) == except {
                continue;
            }
            let Some(status) = statuses.iter().find(|s| s.app_id == listed.app_id) else {
                continue;
            };
            let served = status.current
                && status.record_cert.is_some()
                && status.cert_expires_at.is_none_or(|at| at > now);
            if !served {
                continue;
            }
            let Some(cert) = certs.iter().find(|c| c.hash() == listed.cert) else {
                return Err(SignerError::Records(
                    "a listed certificate isn't held".into(),
                ));
            };
            let unowned = self.env.protocols.unowned(cert.scopes());
            if !unowned.is_empty() {
                alerts.push(Alert::RotationSkipped {
                    app_id: listed.app_id,
                    scopes: unowned,
                });
                continue;
            }
            // A part made for another certificate, as a given-up renewal leaves, counts as
            // missing: the app skips it, so its bundle starts at epoch 1 (Switch wire 3.5
            // "Full bundles on request").
            let foreign = self
                .state
                .bundle_parts
                .iter()
                .any(|p| p.app_id == listed.app_id && p.cert != listed.cert);
            let first = if foreign {
                1
            } else {
                incremental_first_epoch(status.keys_through, status.full_bundle_requested.is_some())
            };
            if first > last {
                continue;
            }
            let sealed = seal_bundle_parts(key, cert, first, last, &keyed)?;
            push_parts(&mut ops, listed.app_id, listed.cert, sealed);
        }
        Ok((ops, alerts))
    }

    /// Sign `ops` in batches at `generation`, each with the parts it stores.
    fn sign_batches(&self, generation: u64, ops: Vec<Op>) -> Result<Vec<RenewBatch>> {
        let client = self.service_client()?;
        ops.chunks(MAX_OPS)
            .map(|chunk| {
                let entries = chunk
                    .iter()
                    .map(|(op, _)| (Vec::new(), op.clone()))
                    .collect();
                let batch = client.sign_batch(generation, entries, None)?;
                Ok(RenewBatch {
                    bytes: Bytes(batch.body().to_vec()),
                    parts: chunk.iter().filter_map(|(_, part)| *part).collect(),
                })
            })
            .collect()
    }

    /// Commit `state` with the flow that sends `batches` and then delivers `doc`, the
    /// version `flow` delivers, built on `newest`; `alerts` are added. Parts the switch no
    /// longer keeps go: those of apps `newest` doesn't list, and those made for the listed
    /// certificate that an app has passed, which the switch may drop (Switch wire 3.5,
    /// 7.4.12).
    #[allow(clippy::too_many_arguments)]
    async fn commit_batches(
        &mut self,
        mut state: SignerState,
        newest: &IdentityDoc,
        statuses: &[AppStatus],
        alerts: Vec<Alert>,
        batches: Vec<RenewBatch>,
        doc: &IdentityDoc,
        flow: Flow,
    ) -> Result<()> {
        let Flow::Deliver { prev, .. } = flow else {
            return Err(SignerError::Records(
                "a version without its delivery".into(),
            ));
        };
        state.signed_through = doc.version();
        for alert in alerts {
            state.alert(alert);
        }
        state.bundle_parts.retain(|held| {
            let Some(listed) = newest.listed_cert(&held.app_id) else {
                return false;
            };
            // A part made for another certificate stays until a part for the listed one
            // replaces it: the app skipped it, so `keys_through`, which counts the parts the
            // app's cursor passed, says nothing of the keys it holds (Switch wire 3.5).
            held.cert != listed
                || statuses
                    .iter()
                    .find(|s| s.app_id == held.app_id)
                    .and_then(|s| s.keys_through)
                    .is_none_or(|through| held.last_epoch > through)
        });
        let flow = Flow::Renew {
            batches,
            sent: 0,
            doc: doc.signed().clone(),
            prev,
        };
        self.commit(state, Some(flow)).await
    }

    /// The switch's apps, once its copy is confirmed as this install's mark.
    async fn switch_apps(&mut self) -> Result<Vec<AppStatus>> {
        let answer = self.service_client()?.apps().await?;
        self.confirm_copy(answer.identity.as_ref()).await?;
        Ok(answer.apps)
    }

    /// Send a renewal's or an epoch completion's batches from `sent` on, each with its signed
    /// bytes, recording the parts each stores once the switch took it, then go on to the
    /// version's delivery. Before the first batch it sends, a resumed one included, it checks
    /// that this install still signs: the switch's copy is its mark, and no other install's
    /// backup took over (Switch spec 4.3, 12.8).
    pub(super) async fn send_renewal(
        &mut self,
        batches: &[RenewBatch],
        sent: usize,
        doc: SignedDoc,
        prev: Option<[u8; 32]>,
    ) -> Result<()> {
        if sent < batches.len() {
            self.ensure_signer().await?;
        }
        let client = self.service_client()?;
        for (index, batch) in batches.iter().enumerate().skip(sent) {
            let signed = Batch::from_body(batch.bytes.0.clone())?;
            match client.submit(&signed).await {
                Ok(_) => {
                    // Each stored part replaces those whose range it overlaps (Switch wire
                    // 6.2 `key_bundle.put`).
                    let mut state = self.state.clone();
                    for part in &batch.parts {
                        state.bundle_parts.retain(|held| {
                            held.app_id != part.app_id
                                || held.last_epoch < part.first_epoch
                                || part.last_epoch < held.first_epoch
                        });
                        state.bundle_parts.push(*part);
                    }
                    let flow = Flow::Renew {
                        batches: batches.to_vec(),
                        sent: index.saturating_add(1),
                        doc: doc.clone(),
                        prev,
                    };
                    self.commit(state, Some(flow)).await?;
                }
                Err(error @ ClientError::Switch { status, .. })
                    if (400..500).contains(&status) && status != 408 && status != 429 =>
                {
                    // A definite refusal: the flow ends, its version and its epochs stay
                    // spent, and the parts already stored stay recorded.
                    self.commit(self.state.clone(), None).await?;
                    return Err(error.into());
                }
                Err(error) => return Err(error.into()),
            }
        }
        let deliver = Flow::Deliver {
            doc,
            prev,
            backup: None,
            step: DeliverStep::Signed,
        };
        self.commit(self.state.clone(), Some(deliver)).await
    }

    /// Every certificate the signer holds, verified.
    fn held_certs(&self) -> Result<Vec<AppCert>> {
        let identity = self.state.identity;
        Ok(self
            .state
            .certs
            .iter()
            .map(|cert| AppCert::verify(cert, &identity))
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// The apps whose closing delivery the signer owes: open renewals in the newest version
    /// that were reductions (Switch wire 3.8).
    pub(super) fn owed(&self) -> Result<Vec<[u8; 16]>> {
        let Some(doc) = self.state.newest_doc()? else {
            return Ok(Vec::new());
        };
        let certs = self.held_certs()?;
        Ok(owed_closings(&doc, |hash| {
            certs.iter().find(|cert| &cert.hash() == hash)
        }))
    }

    /// Whether the newest version is one whose delivery, retried, gave no service time: the
    /// closing it owes waits for a later version's delivery.
    fn closing_stalled(&self) -> bool {
        self.state.closing_unavailable.is_some()
            && self.state.closing_unavailable == self.high_water().map(|h| h.version)
    }

    /// Whether a closing delivery is owed and can be made now.
    pub(super) fn owes_closing(&self) -> Result<bool> {
        Ok(self.state.managed_by.is_none() && !self.closing_stalled() && !self.owed()?.is_empty())
    }

    /// When a closing delivery is owed and no flow is in progress, commit it as the next
    /// flow and say so (Switch wire 3.8, 7.4.2). The cutoff is the service time at which the
    /// switch took the newest version, plus the clock tolerance: the renewing version's
    /// time, or, when the switch never gave that one, the time of a later delivery, which
    /// cuts off later but never on the signer's own clock. Without the newest version's
    /// time, as after a crash before the answer was kept, that version is delivered again,
    /// a retry, whose answer carries its delivery's proof. [`Alert::ReductionNotClosed`]
    /// is shown while a retry gave no time, and goes once the renewals are closed.
    pub(super) async fn queue_owed_closing(&mut self) -> Result<bool> {
        if self.flow.is_some() || self.state.managed_by.is_some() {
            return Ok(false);
        }
        let owed = self.owed()?;
        let stalled = self.closing_stalled();
        let mut state = self.state.clone();
        state
            .alerts
            .retain(|a| !matches!(a, Alert::ReductionNotClosed { .. }) || !owed.is_empty());
        for alert in &mut state.alerts {
            if let Alert::ReductionNotClosed { apps } = alert {
                apps.clone_from(&owed);
            }
        }
        if stalled && !owed.is_empty() {
            state.alert(Alert::ReductionNotClosed { apps: owed.clone() });
        }
        if state.alerts != self.state.alerts {
            self.commit(state, None).await?;
        }
        if owed.is_empty() || stalled {
            return Ok(false);
        }
        let Some(newest) = self.state.newest.clone() else {
            return Ok(false);
        };
        let version = self.high_water().map_or(0, |h| h.version);
        let Some(delivered_at) = newest.delivered_at else {
            let mut state = self.state.clone();
            if self.state.time_asked == Some(version) {
                // The retry's answer carried no proof either (Switch wire 7.4.2): the closing
                // waits for the next delivery's service time, and the user is told.
                state.closing_unavailable = Some(version);
                state.alert(Alert::ReductionNotClosed { apps: owed });
                self.commit(state, None).await?;
                return Err(SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                    "Switch wire 7.4.2: the delivery's retry carried no proof, so the \
                     reduction has no cutoff time yet"
                        .into(),
                )));
            }
            state.time_asked = Some(version);
            let again = Flow::Deliver {
                doc: newest.doc,
                prev: newest.prev,
                backup: None,
                step: DeliverStep::BackupWritten,
            };
            self.commit(state, Some(again)).await?;
            return Ok(true);
        };
        let until = delivered_at.saturating_add(CLOCK_TOLERANCE_MS);
        let key = self.keyring.unlock()?;
        let (doc, flow) = self.next_version(&key, |body| {
            for app in &owed {
                body.close_renewals(app, until);
            }
        })?;
        drop(key);
        let mut state = self.state.clone();
        state.signed_through = doc.version();
        self.commit(state, Some(flow)).await?;
        Ok(true)
    }

    /// Close every cooperative renewal whose app the switch now holds a record of carrying
    /// the new certificate: `until` is the time the switch took that record plus the clock
    /// tolerance (Switch spec 3.2 step 4, Switch wire 3.8 step 4). Returns the apps closed.
    ///
    /// # Errors
    ///
    /// As [`Signer::resume`].
    pub async fn complete_renewals(&mut self) -> Result<Vec<[u8; 16]>> {
        self.ready().await?;
        let Some(doc) = self.state.newest_doc()? else {
            return Ok(Vec::new());
        };
        let certs = self.held_certs()?;
        let open: Vec<_> = doc
            .body()
            .renewed
            .iter()
            .filter(|entry| entry.until.is_none())
            .filter(|entry| {
                // Reductions close on their own.
                let old = certs.iter().find(|c| c.hash() == entry.cert);
                let new = doc
                    .listed_cert(&entry.app_id)
                    .and_then(|h| certs.iter().find(|c| c.hash() == h));
                matches!((old, new), (Some(old), Some(new)) if !is_reduction(old, new))
            })
            .map(|entry| entry.app_id)
            .collect();
        if open.is_empty() {
            return Ok(Vec::new());
        }
        let statuses = self.service_client()?.apps().await?.apps;
        let mut closing: Vec<([u8; 16], u64)> = Vec::new();
        for app in open {
            let status = statuses.iter().find(|s| s.app_id == app);
            let carries = status.is_some_and(|s| s.record_cert == doc.listed_cert(&app));
            if let (true, Some(at)) = (carries, status.and_then(|s| s.record_at))
                && !closing.iter().any(|(id, _)| *id == app)
            {
                closing.push((app, at.saturating_add(CLOCK_TOLERANCE_MS)));
            }
        }
        if closing.is_empty() {
            return Ok(Vec::new());
        }
        let key = self.keyring.unlock()?;
        let (next, flow) = self.next_version(&key, |body| {
            for (app, until) in &closing {
                body.close_renewals(app, *until);
            }
        })?;
        drop(key);
        let mut state = self.state.clone();
        state.signed_through = next.version();
        self.commit(state, Some(flow)).await?;
        self.resume().await?;
        Ok(closing.into_iter().map(|(app, _)| app).collect())
    }

    /// What is due at each start, in order (Switch wire 3.8): finish the flow in progress and
    /// any closing delivery owed, then close the cooperative renewals whose apps took their new
    /// certificate.
    ///
    /// # Errors
    ///
    /// As [`Signer::resume`].
    pub async fn run_due(&mut self) -> Result<()> {
        // A publication that failed doesn't hold back the closings owed at the switch.
        let resumed = self.resume().await;
        if let Err(error) = &resumed
            && (self.flow.is_some() || !matches!(error, SignerError::Homeserver(_)))
        {
            return resumed;
        }
        self.complete_renewals().await?;
        resumed
    }
}

/// A batch operation, with the key bundle part it stores, if any.
type Op = (OpKind, Option<StoredPart>);

/// Whether a scope has keys, for a rotation: one no registered protocol owns counts as keyed,
/// so removing it rotates, as its keys can't be judged (design note, decision 2).
fn keyed(protocols: &Protocols) -> impl Fn(&str) -> bool + '_ {
    |scope| protocols.has_keys(scope) || !protocols.knows_scope(scope)
}

/// Add `sealed`'s parts for `app_id`, made for the certificate `cert`, to the operations.
fn push_parts(ops: &mut Vec<Op>, app_id: [u8; 16], cert: [u8; 32], sealed: Vec<BundlePart>) {
    for part in sealed {
        let stored = StoredPart {
            app_id,
            first_epoch: part.first_epoch,
            last_epoch: part.last_epoch,
            cert,
        };
        ops.push((
            OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: app_id,
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }),
            Some(stored),
        ));
    }
}
