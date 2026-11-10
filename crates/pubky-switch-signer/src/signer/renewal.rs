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
//! It sends the batches in order, then delivers and publishes the version.
//!
//! A renewal that removes a scope or a switch permission, or expires earlier, is a reduction.
//! It closes at once: the next version sets `until` of the app's open renewals to the service
//! time at which the switch took the renewing version, plus the clock tolerance. That closing
//! delivery comes before any other, also when a crash came between the two (Switch wire 3.8
//! "A closing delivery owed"). Any other renewal closes once the switch holds the app's record
//! carrying the new certificate ([`Signer::complete_renewals`]).
//!
//! The signer writes only `key_bundle.put` and `cert.put` (Switch spec 13.5).

use pubky_switch_client::ClientError;
use pubky_switch_client::client::Batch;
use pubky_switch_core::ops::{KeyBundlePut, OpKind};
use pubky_switch_core::records::{
    AppCert, AppCertBody, BundlePart, CLOCK_TOLERANCE_MS, IdentityDoc, MAX_CERT_LIFETIME_MS,
    RenewedCert, StoredPart, incremental_first_epoch, is_reduction, owed_closings,
    reduction_rotates, seal_bundle_parts,
};

use super::Signer;
use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::state::{Bytes, DeliverStep, Flow};

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
        let certs = self.held_certs()?;
        let old = certs
            .iter()
            .find(|cert| cert.hash() == listed)
            .ok_or_else(|| SignerError::Records("the listed certificate isn't held".into()))?
            .clone();
        // A scope no registered protocol owns can't be judged for keys (design note,
        // decision 2): the renewal stops rather than guess.
        self.require_owned(old.scopes())?;
        let scopes = change.scopes.unwrap_or_else(|| old.scopes().to_vec());
        let terms = self.env.protocols.terms(&scopes)?;
        let now = self.env.clock.now_ms();
        let issued = now.max(old.issued_at().saturating_add(1));
        let expires = change
            .expires_at
            .unwrap_or_else(|| issued.saturating_add(self.state.cert_lifetime_ms))
            .min(issued.saturating_add(MAX_CERT_LIFETIME_MS));
        let protocols = self.env.protocols.clone();
        let has_keys = |scope: &str| protocols.has_keys(scope);
        // The switch's view, read before anything is signed: this install still signs, the app
        // has joined, and the other apps' holdings, for a rotation's bundles.
        let answer = self.service_client()?.apps().await?;
        self.confirm_copy(answer.identity.as_ref()).await?;
        let statuses = answer.apps;
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
        let rotates = reduction_rotates(&old, &new, has_keys);
        // A rotation goes above every epoch whose keys were ever sent, also by a rotation that
        // was given up, so no app holds the new epoch's keys early (Switch spec 3.2, 3.5).
        // `data_epoch` only increases, so it may skip (Switch wire 3.3).
        let current = newest.data_epoch();
        let last = if rotates {
            current
                .max(self.state.epoch_through)
                .checked_add(1)
                .ok_or_else(|| SignerError::Records("the data epoch can't go higher".into()))?
        } else {
            current
        };

        // The full bundle for the new certificate, the cert.put in its first batch.
        let mut ops = vec![OpKind::CertPut {
            target_app_id: app_id,
            cert: new.signed().clone(),
        }];
        let mut parts: Vec<StoredPart> = Vec::new();
        let full = seal_bundle_parts(&key, &new, 1, last, &has_keys)?;
        push_parts(&mut ops, &mut parts, app_id, new.hash(), full);
        // A rotation: every other current app's bundle through the new epoch. An app the
        // switch doesn't serve now, one not current, not joined or expired, gets no part: it
        // gets the epochs it lacks from its next bundle, which starts after `keys_through`
        // (Switch wire 3.5).
        if rotates {
            for other in &newest.body().apps {
                if other.app_id == app_id {
                    continue;
                }
                let Some(status) = statuses.iter().find(|s| s.app_id == other.app_id) else {
                    continue;
                };
                let served = status.current
                    && status.record_cert.is_some()
                    && status.cert_expires_at.is_none_or(|at| at > now);
                if !served {
                    continue;
                }
                let Some(cert) = certs.iter().find(|c| c.hash() == other.cert) else {
                    return Err(SignerError::Records(
                        "a listed certificate isn't held".into(),
                    ));
                };
                self.require_owned(cert.scopes())?;
                let first = incremental_first_epoch(
                    status.keys_through,
                    status.full_bundle_requested.is_some(),
                );
                let sealed = seal_bundle_parts(&key, cert, first.min(last), last, &has_keys)?;
                push_parts(&mut ops, &mut parts, other.app_id, other.cert, sealed);
            }
        }
        let client = self.service_client()?;
        let generation = newest.generation();
        let mut batches = Vec::new();
        for chunk in ops.chunks(MAX_OPS) {
            let entries = chunk.iter().map(|op| (Vec::new(), op.clone())).collect();
            let batch = client.sign_batch(generation, entries, None)?;
            batches.push(Bytes(batch.body().to_vec()));
        }
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
        let Flow::Deliver { prev, .. } = flow else {
            return Err(SignerError::Records(
                "a version without its delivery".into(),
            ));
        };
        let mut state = self.state.clone();
        state.signed_through = doc.version();
        state.epoch_through = state.epoch_through.max(last);
        state.certs.push(new.signed().clone());
        // Parts the switch no longer keeps go: those of apps the newest version doesn't list,
        // and those an app has passed, which the switch may drop (Switch wire 3.5, 7.4.12).
        state.bundle_parts.retain(|held| {
            newest.listed_cert(&held.app_id).is_some()
                && statuses
                    .iter()
                    .find(|s| s.app_id == held.app_id)
                    .and_then(|s| s.keys_through)
                    .is_none_or(|through| held.last_epoch > through)
        });
        let renew = Flow::Renew {
            app_id,
            batches,
            sent: 0,
            parts,
            doc: doc.signed().clone(),
            prev,
        };
        self.commit(state, Some(renew)).await?;
        self.resume().await?;
        Ok(doc)
    }

    /// Refuse scopes no registered protocol owns (design note, decision 2).
    fn require_owned(&self, scopes: &[String]) -> Result<()> {
        let unknown = self.env.protocols.unowned(scopes);
        if unknown.is_empty() {
            Ok(())
        } else {
            Err(Refusal::UnknownScopes { scopes: unknown }.into())
        }
    }

    /// Send a renewal's batches from `sent` on, each with its signed bytes, then go on to
    /// the renewing version's delivery. Before the first batch it sends, a resumed one
    /// included, it checks that this install still signs: the switch's copy is its mark, and
    /// no other install's backup took over (Switch spec 4.3, 12.8).
    pub(super) async fn send_renewal(
        &mut self,
        app_id: [u8; 16],
        batches: &[Bytes],
        sent: usize,
        parts: &[StoredPart],
        doc: pubky_switch_core::sig::SignedDoc,
        prev: Option<[u8; 32]>,
    ) -> Result<()> {
        if sent < batches.len() {
            self.ensure_signer().await?;
        }
        let client = self.service_client()?;
        for (index, bytes) in batches.iter().enumerate().skip(sent) {
            let batch = Batch::from_body(bytes.0.clone())?;
            match client.submit(&batch).await {
                Ok(_) => {
                    let flow = Flow::Renew {
                        app_id,
                        batches: batches.to_vec(),
                        sent: index.saturating_add(1),
                        parts: parts.to_vec(),
                        doc: doc.clone(),
                        prev,
                    };
                    self.commit(self.state.clone(), Some(flow)).await?;
                }
                Err(error @ ClientError::Switch { status, .. })
                    if (400..500).contains(&status) && status != 408 && status != 429 =>
                {
                    // A definite refusal: the renewal ends, its version and its epochs stay
                    // spent.
                    self.commit(self.state.clone(), None).await?;
                    return Err(error.into());
                }
                Err(error) => return Err(error.into()),
            }
        }
        // The parts are stored: they replace the ones they overlap (Switch wire 3.5).
        let mut state = self.state.clone();
        state.bundle_parts.retain(|held| {
            !parts.iter().any(|new| {
                new.app_id == held.app_id
                    && (new.app_id == app_id
                        || (held.first_epoch <= new.last_epoch
                            && new.first_epoch <= held.last_epoch))
            })
        });
        state.bundle_parts.extend_from_slice(parts);
        let deliver = Flow::Deliver {
            doc,
            prev,
            backup: None,
            step: DeliverStep::Signed,
        };
        self.commit(state, Some(deliver)).await
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
    fn owed(&self) -> Result<Vec<[u8; 16]>> {
        let Some(doc) = self.state.newest_doc()? else {
            return Ok(Vec::new());
        };
        let certs = self.held_certs()?;
        Ok(owed_closings(&doc, |hash| {
            certs.iter().find(|cert| &cert.hash() == hash)
        }))
    }

    /// Whether a closing delivery is owed.
    pub(super) fn owes_closing(&self) -> Result<bool> {
        Ok(self.state.managed_by.is_none()
            && !self.state.closing_unavailable
            && !self.owed()?.is_empty())
    }

    /// When a closing delivery is owed and no flow is in progress, commit it as the next
    /// flow and say so. The cutoff is the service time of the renewing delivery plus the
    /// clock tolerance; without that time, as after a crash before the answer was kept, the
    /// renewing version is delivered again, a retry, whose answer carries that delivery's
    /// proof (Switch wire 3.8, 7.4.2).
    pub(super) async fn queue_owed_closing(&mut self) -> Result<bool> {
        if self.flow.is_some() || !self.owes_closing()? {
            return Ok(false);
        }
        let Some(newest) = self.state.newest.clone() else {
            return Ok(false);
        };
        let Some(delivered_at) = newest.delivered_at else {
            if self.state.time_asked {
                // The retry's answer carried no proof either (Switch wire 7.4.2): there is no
                // service time to cut off at, and the signer never uses its own clock. The
                // closing stays owed and the user is told.
                let apps = self.owed()?;
                let mut state = self.state.clone();
                state.alert(Alert::ReductionNotClosed { apps });
                state.closing_unavailable = true;
                self.commit(state, None).await?;
                return Err(SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                    "Switch wire 7.4.2: the delivery's retry carried no proof, so the \
                     reduction has no cutoff time"
                        .into(),
                )));
            }
            let mut state = self.state.clone();
            state.time_asked = true;
            let again = Flow::Deliver {
                doc: newest.doc,
                prev: newest.prev,
                backup: None,
                step: DeliverStep::BackupWritten,
            };
            self.commit(state, Some(again)).await?;
            return Ok(true);
        };
        let owed = self.owed()?;
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
        self.resume().await?;
        self.complete_renewals().await?;
        Ok(())
    }
}

/// Add `sealed`'s parts for `app_id`, made for the certificate `cert`, to the operations and
/// to the parts the renewal stores.
fn push_parts(
    ops: &mut Vec<OpKind>,
    parts: &mut Vec<StoredPart>,
    app_id: [u8; 16],
    cert: [u8; 32],
    sealed: Vec<BundlePart>,
) {
    for part in sealed {
        parts.push(StoredPart {
            app_id,
            first_epoch: part.first_epoch,
            last_epoch: part.last_epoch,
            cert,
        });
        ops.push(OpKind::KeyBundlePut(KeyBundlePut {
            target_app_id: app_id,
            bundle: part.bundle,
            first_epoch: part.first_epoch,
            last_epoch: part.last_epoch,
        }));
    }
}
