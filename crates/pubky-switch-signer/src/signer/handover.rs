//! Handing the identity over to another signer, aborting it, and taking it back: the old
//! signer's side (Switch spec 12.8; Switch wire 3.12, 7.4.17).
//!
//! On the user's confirmation, the old signer seals its records, the identity secret in them,
//! to the certified bundle key of an app its newest `identity.json` lists and the switch shows
//! current with a certificate that hasn't expired, and stores the hand-over at the switch
//! (`PUT /handover`), again only while the switch still holds the version handed over. It
//! hands over only the newest version the switch accepted from it, with no closing delivery
//! owed. From then on it signs nothing for the identity but an abort or a take-back: the
//! signing gate refuses every routine step ([`crate::Refusal::HandingOver`]), the routine run
//! keeps the work it owes for later, and it writes nothing to the Homeserver until its abort
//! or take-back has won, so it never republishes the switch's copy. No revocation is owed
//! when it starts, nor asked for meanwhile: the hand-over carries the records as sealed, not
//! a revocation in progress. The user aborts first, then revokes.
//!
//! How it ends:
//!
//! - **It takes effect.** The new signer delivers the version handed over plus 1, naming its
//!   own install, and once it has won stores the key, writes its backup, then publishes. The
//!   old signer deletes the key, then its records, only on proof that another install holds
//!   the identity:
//!   - the switch's copy, from `GET /apps` or a `409 stale_identity` answering its abort or
//!     take-back, is newer than the version handed over, verifies, names another install, and
//!     is neither its abort nor its take-back;
//!   - the signer backup on the Homeserver opens with the identity's backup key, verifies, and
//!     holds a newer version naming that same install.
//!
//!   Only a holder of the key makes that backup, and the new signer writes it only once its
//!   key is stored, so neither the switch nor the Homeserver, alone or together, can make
//!   both installs delete the key. The deletion is committed first, so a crash between the
//!   key and the records leaves marked records, which the next open deletes and a new set-up
//!   replaces. A newer copy without the proof stops this install as one that isn't named
//!   ([`crate::Refusal::SuccessorUnproven`]): it keeps the key and the hand-over, and looks
//!   again at each run. Answers that decide nothing delete nothing.
//! - **It is aborted.** Only while the switch still holds the version handed over, the old
//!   signer signs it again, at its version plus 2 so it never shares a version with the new
//!   signer's first one, built on the same hash, and delivers it. Once it has won, it writes
//!   its backup and publishes, as after a restore (Switch wire 3.13 "When it is written").
//! - **It is taken back.** When the switch shows another install's version just after the
//!   one handed over and no proof follows, the new signer lost before it stored the key or
//!   wrote its backup, the user can have the old signer take the identity back
//!   ([`Signer::take_back`]): that copy's content naming this install, built on it, above
//!   every version it signed, its abort included. A new signer still alive that races it
//!   finds itself not named and keeps its key.
//!
//! The old signer's own abort or take-back at the switch means that delivery won, also when
//! its answer was lost. The newer version may come from a third install that restored the new
//! signer's backup: the copy can't tell them apart, so the outcome names the install the copy
//! names.

use pubky_switch_client::ClientError;
use pubky_switch_client::client::answers::StoredHandover;
use pubky_switch_core::records::{AppCert, IdentityDoc, SIGNER_BACKUP_PATH, abort_body, succeeded};

use super::revocation::UserConfirmed;
use super::{Signer, gate};
use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::state::{self, DeliverStep, Flow, HandOverSent, HandingOver, TakeBack};

/// What an abort of a hand-over came to (Switch wire 3.12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbortOutcome {
    /// The abort won: this install signs for the identity again, from this version.
    Aborted {
        /// The abort's version, delivered.
        version: u64,
    },
    /// The hand-over took effect first: the switch holds the version after the one handed
    /// over, naming `install`, so this install deleted the identity key and its records. That
    /// install is the hand-over's target, or one that restored the target's backup meanwhile.
    SucceededBy {
        /// The signer ID the switch's copy names.
        install: [u8; 16],
    },
}

impl Signer {
    /// Hand the identity over to the app `to_app` (Switch spec 12.8, Switch wire 3.12): seal
    /// the records with the identity secret to its certified bundle key, commit the hand-over,
    /// and store it at the switch. From then on this install signs nothing for the identity
    /// but the abort ([`Signer::abort_hand_over`]). [`Signer::resume`] sends it again until the
    /// switch answers, and finds when the hand-over has taken effect.
    ///
    /// The user's prompts, before the hand-over and after it, are the host's.
    ///
    /// # Errors
    ///
    /// As [`Signer::set_record_max_age`] before anything is sealed; [`Refusal::ClosingOwed`]
    /// while a reduction's closing delivery is owed; [`Refusal::RevocationOwed`] while a
    /// revocation's version isn't delivered; [`Refusal::NotListed`] when the newest
    /// version doesn't list the app; [`Refusal::TargetNotCurrent`] when the switch doesn't
    /// show it current, or it is being revoked; then the switch's error, the hand-over kept
    /// and sent again by [`Signer::resume`].
    pub async fn hand_over_to(&mut self, to_app: [u8; 16], confirmed: UserConfirmed) -> Result<()> {
        self.ready().await?;
        // Any closing owed, one waiting for a later version's service time included.
        if !self.owed()?.is_empty() {
            return Err(Refusal::ClosingOwed.into());
        }
        // A revocation whose version isn't delivered: the app is still listed. One that only
        // owes its record's deletion is in the sealed records as a tombstone, and the new
        // signer owes that deletion again from them.
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        if self
            .state
            .revoking
            .iter()
            .any(|r| newest.listed_cert(&r.app_id).is_some())
        {
            return Err(Refusal::RevocationOwed.into());
        }
        let identity = self.state.identity;
        // `ready` checked that the switch holds the newest version, and that this install
        // signed it.
        let newest = self.state.newest.clone().ok_or(Refusal::NotSetUp)?;
        let doc = IdentityDoc::verify(&newest.doc, &identity)?;
        if doc.body().signer != self.state.install {
            return Err(SignerError::NotNamed {
                install: doc.body().signer,
            });
        }
        let cert_hash = doc.listed_cert(&to_app).ok_or(Refusal::NotListed)?;
        let now = self.env.clock.now_ms();
        // Current in spec 3.4's sense, and served: its certificate hasn't expired.
        let target_current = self.service_client()?.apps().await?.apps.iter().any(|s| {
            s.app_id == to_app
                && s.current
                && s.revoked_at.is_none()
                && s.departed_at.is_none()
                && s.cert_expires_at.is_none_or(|at| at > now)
        });
        let revoking = self.state.revoking.iter().any(|r| r.app_id == to_app);
        if !target_current || revoking || self.state.tombstones.contains(&to_app) {
            return Err(Refusal::TargetNotCurrent.into());
        }
        let issued = self
            .state
            .certs
            .iter()
            .map(|cert| AppCert::verify(cert, &identity))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let cert = issued
            .iter()
            .find(|cert| cert.hash() == cert_hash)
            .ok_or_else(|| SignerError::Records("the target's certificate isn't held".into()))?;
        let limits = self.service()?.limits;
        let handover = {
            let key = self.signing_key()?;
            key.seal_hand_over(
                doc,
                &self.state.tombstones,
                &issued,
                limits,
                &self.state.bundle_parts,
                cert,
                &confirmed,
            )?
        };
        let mut state = self.state.clone();
        state.handing_over = Some(HandingOver {
            to_app,
            doc: newest.doc,
            handover,
            sent: HandOverSent::Pending,
            abort: None,
            take_back: None,
        });
        self.commit(state, None).await?;
        self.send_hand_over().await
    }

    /// Abort the hand-over in progress (Switch wire 3.12, Switch spec 12.8): sign the version
    /// handed over again at its version plus 2, built on it, and deliver it. Sent again, the
    /// same bytes, until it is answered; once it has won, the backup is written.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotHandingOver`] when no hand-over is in progress; otherwise as
    /// [`Signer::resume`], the abort kept and sent again.
    pub async fn abort_hand_over(&mut self, _confirmed: UserConfirmed) -> Result<AbortOutcome> {
        self.refresh().await?;
        self.check_named()?;
        let Some(handing) = self.state.handing_over.clone() else {
            return Err(Refusal::NotHandingOver.into());
        };
        // While a hand-over is in progress the only flow is its abort's delivery: one in
        // flight is sent again. Otherwise the abort is signed, and committed with its delivery;
        // signed again, it is the same bytes. It is signed only while the switch still holds
        // the version handed over: once the new signer has moved on, an abort at that version
        // plus 2 would be another body at a version the new signer signed.
        if self.flow.is_none() {
            match self.switch_at_mark().await {
                Err(SignerError::HandedOver { install }) => {
                    return Ok(AbortOutcome::SucceededBy { install });
                }
                other => other?,
            }
            let handed = IdentityDoc::verify(&handing.doc, &self.state.identity)?;
            let (body, prev) = abort_body(&handed)?;
            let doc = {
                let key = gate::hand_over_key(&self.keyring, &self.state)?;
                IdentityDoc::sign(&key, body)?
            };
            let mut state = self.state.clone();
            state.signed_through = state.signed_through.max(doc.version());
            // It races the new signer, so its backup is written once it has won (Switch wire
            // 3.13 "When it is written").
            state.backup_owed = true;
            if let Some(handing) = state.handing_over.as_mut() {
                handing.abort = Some(doc.hash());
            }
            let flow = Flow::Deliver {
                doc: doc.signed().clone(),
                prev: Some(prev),
                backup: None,
                step: DeliverStep::BackupWritten,
            };
            self.commit(state, Some(flow)).await?;
        }
        let abort = self.state.handing_over.as_ref().and_then(|h| h.abort);
        let result = self.resume().await;
        // Once the abort has won, the hand-over is over, whatever came after it: a backup or a
        // publication that failed is the next run's.
        let won = self.state.handing_over.is_none()
            && abort.is_some()
            && self.high_water().map(|h| h.doc_hash) == abort;
        match result {
            _ if won => Ok(AbortOutcome::Aborted {
                version: self.high_water().map_or(0, |h| h.version),
            }),
            Ok(()) => Err(Refusal::HandingOver {
                to_app: handing.to_app,
            }
            .into()),
            Err(SignerError::HandedOver { install }) => Ok(AbortOutcome::SucceededBy { install }),
            Err(error) => Err(error),
        }
    }

    /// The routine step of a hand-over in progress: its `PUT /handover` sent again until it is
    /// answered, unless an abort is signed, then the switch's copy checked, which shows when
    /// the hand-over has taken effect ([`Signer::adopt`]). Nothing routine is signed, and owed
    /// work stays owed.
    pub(super) async fn continue_hand_over(&mut self) -> Result<()> {
        // The switch first: once the hand-over took effect, it isn't stored again.
        self.switch_at_mark().await?;
        self.send_hand_over().await
    }

    /// Send the hand-over's `PUT /handover` while it isn't answered and no abort is signed. A
    /// definite refusal is kept with [`Alert::HandOverRefused`]: an earlier send may be
    /// stored, so the hand-over stays in progress until it takes effect or is aborted.
    async fn send_hand_over(&mut self) -> Result<()> {
        let Some(handing) = self.state.handing_over.clone() else {
            return Ok(());
        };
        if handing.sent != HandOverSent::Pending || handing.abort.is_some() {
            return Ok(());
        }
        let stored = StoredHandover {
            app_id: handing.to_app,
            handover: handing.handover.clone(),
        };
        let answer = {
            let key = gate::hand_over_key(&self.keyring, &self.state)?;
            self.signing_client(&key)?.put_handover(&stored).await
        };
        let sent = match &answer {
            Ok(stored) if stored.app_id == handing.to_app => HandOverSent::Stored,
            Ok(_) => {
                return Err(SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                    "Switch wire 7.4.17: the hand-over is stored for another app".into(),
                )));
            }
            Err(ClientError::Switch { status, .. }) if definite(*status) => HandOverSent::Refused,
            Err(_) => HandOverSent::Pending,
        };
        if sent != HandOverSent::Pending {
            let mut state = self.state.clone();
            if let Some(held) = state.handing_over.as_mut() {
                held.sent = sent;
            }
            if sent == HandOverSent::Refused {
                state.alert(Alert::HandOverRefused {
                    to_app: handing.to_app,
                });
            }
            self.commit(state, self.flow.clone()).await?;
        }
        answer.map(drop).map_err(SignerError::from)
    }

    /// Whether `copy`, from the switch and verified, is another install's version past the
    /// one handed over: newer than it, at no lower generation, naming another install, and
    /// neither this install's abort nor its take-back, documents compared whole (Switch wire
    /// 3.12). Alone it proves nothing; [`Signer::succeeded`] looks for the backup too.
    pub(super) fn succeeded_by(&self, copy: &IdentityDoc) -> bool {
        let Some(handing) = &self.state.handing_over else {
            return false;
        };
        let Ok(handed) = IdentityDoc::verify(&handing.doc, &self.state.identity) else {
            return false;
        };
        let own: Vec<[u8; 32]> = handing
            .abort
            .into_iter()
            .chain(
                handing
                    .take_back
                    .as_ref()
                    .and_then(|t| t.doc.doc_hash().ok()),
            )
            .collect();
        copy.generation() >= handed.generation()
            && copy.body().signer != self.state.install
            && succeeded(&handed, &own, copy.version(), &copy.hash())
    }

    /// Whether `copy`, from the switch, is this install's own abort or take-back: that
    /// delivery won, its answer lost (Switch wire 3.12).
    pub(super) fn own_hand_over_delivery(&self, copy: &IdentityDoc) -> Option<[u8; 32]> {
        let handing = self.state.handing_over.as_ref()?;
        if handing.abort == Some(copy.hash()) {
            return IdentityDoc::verify(&handing.doc, &self.state.identity)
                .ok()
                .map(|handed| handed.hash());
        }
        handing
            .take_back
            .as_ref()
            .filter(|t| &t.doc == copy.signed())
            .map(|t| t.prev)
    }

    /// The switch's `copy` names another install past the version handed over. The key goes
    /// only on proof that it holds the identity: the signer backup on the Homeserver opens
    /// with the identity's backup key, verifies, and holds a newer version than the one handed
    /// over naming that same install (Switch wire 3.12). Only a holder of the key makes that
    /// backup, and the new signer writes it only once its key is stored, so neither the switch
    /// nor the Homeserver can make both installs delete the key. Until then this install signs
    /// nothing, as one that isn't named, keeps the key and the hand-over, and looks again at
    /// each run ([`Refusal::SuccessorUnproven`]).
    pub(super) async fn succeeded(&mut self, copy: &IdentityDoc) -> Result<()> {
        let install = copy.body().signer;
        if self.successor_backed_up(install).await? {
            return self.handed_over(install).await;
        }
        let alert = Alert::ManagedByOtherInstall { install };
        if !self.state.alerts.contains(&alert) {
            let mut state = self.state.clone();
            state.alert(alert);
            self.commit(state, self.flow.clone()).await?;
        }
        Err(Refusal::SuccessorUnproven { install }.into())
    }

    /// Whether the signer backup on the Homeserver proves `install` holds the identity: it
    /// opens with the identity's backup key, verifies, and holds a newer version than the
    /// one handed over naming `install`.
    async fn successor_backed_up(&self, install: [u8; 16]) -> Result<bool> {
        let Some(handing) = &self.state.handing_over else {
            return Ok(false);
        };
        let handed = IdentityDoc::verify(&handing.doc, &self.state.identity)?;
        let Some(bytes) = self
            .env
            .homeserver
            .get(SIGNER_BACKUP_PATH)
            .await
            .map_err(SignerError::Homeserver)?
        else {
            return Ok(false);
        };
        Ok(self.open_backup(&bytes)?.is_some_and(|found| {
            found.identity_doc.version() > handed.version()
                && found.identity_doc.body().signer == install
        }))
    }

    /// Take the identity back from a new signer that is lost, on the user's confirmation
    /// (Switch wire 3.12, spec 12.8): when the switch's copy, verified, is at the version
    /// handed over plus 1 and names another install, and no proof follows. It delivers that
    /// copy's content naming this install, built on it, at a version above that copy's and
    /// above every version this install signed, its abort included; once it has won, it
    /// writes its backup and publishes, and this install is the signer again. Sent again, the
    /// same bytes, after a lost answer. Returns that version.
    ///
    /// A new signer still alive that races it finds itself not named and stops, keeping its
    /// key; [`Alert::TakenBack`] tells the user both installs then hold it.
    ///
    /// # Errors
    ///
    /// [`Refusal::NothingToTakeBack`] when there is nothing to take back;
    /// [`SignerError::HandedOver`] when the proof is there after all, and the key is deleted;
    /// otherwise as [`Signer::resume`], the take-back kept and sent again.
    pub async fn take_back(&mut self, _confirmed: UserConfirmed) -> Result<IdentityDoc> {
        self.refresh().await?;
        self.check_named()?;
        let Some(handing) = self.state.handing_over.clone() else {
            return Err(Refusal::NothingToTakeBack.into());
        };
        if handing.take_back.is_none() || self.flow.is_none() {
            let handed = IdentityDoc::verify(&handing.doc, &self.state.identity)?;
            let held = self.service_client()?.apps().await?.identity;
            let copy = held
                .map(|signed| IdentityDoc::verify(&signed, &self.state.identity))
                .transpose()?
                .ok_or(Refusal::NothingToTakeBack)?;
            let open = copy.version() == handed.version().saturating_add(1)
                && copy.generation() == handed.generation()
                && copy.body().signer != self.state.install
                && handing.abort != Some(copy.hash());
            if !open {
                return Err(Refusal::NothingToTakeBack.into());
            }
            let from = copy.body().signer;
            if self.successor_backed_up(from).await? {
                self.handed_over(from).await?;
            }
            let take_back = match handing.take_back.clone().filter(|t| t.prev == copy.hash()) {
                // Signed already: the same bytes again.
                Some(take_back) => take_back,
                None => {
                    let mut body = copy.body().clone();
                    body.version = copy
                        .version()
                        .max(self.state.signed_through)
                        .checked_add(1)
                        .ok_or_else(|| {
                            SignerError::Records("the version can't go higher".into())
                        })?;
                    body.signer = self.state.install;
                    let doc = {
                        let key = gate::hand_over_key(&self.keyring, &self.state)?;
                        IdentityDoc::sign(&key, body)?
                    };
                    TakeBack {
                        doc: doc.signed().clone(),
                        prev: copy.hash(),
                        from,
                    }
                }
            };
            let version = IdentityDoc::verify(&take_back.doc, &self.state.identity)?.version();
            let mut state = self.state.clone();
            state.signed_through = state.signed_through.max(version);
            // It races the new signer, so its backup is written once it has won (Switch wire
            // 3.13 "When it is written").
            state.backup_owed = true;
            let flow = Flow::Deliver {
                doc: take_back.doc.clone(),
                prev: Some(take_back.prev),
                backup: None,
                step: DeliverStep::BackupWritten,
            };
            if let Some(held) = state.handing_over.as_mut() {
                held.take_back = Some(take_back);
            }
            self.commit(state, Some(flow)).await?;
        }
        let signed = self
            .state
            .handing_over
            .as_ref()
            .and_then(|h| h.take_back.as_ref())
            .map(|t| t.doc.clone());
        let result = self.resume().await;
        let won = signed
            .as_ref()
            .filter(|_| self.state.handing_over.is_none())
            .filter(|doc| self.state.newest.as_ref().is_some_and(|n| &n.doc == *doc));
        match (won, result) {
            (Some(doc), _) => Ok(IdentityDoc::verify(doc, &self.state.identity)?),
            (None, Err(error)) => Err(error),
            (None, Ok(())) => Err(Refusal::NothingToTakeBack.into()),
        }
    }

    /// The hand-over took effect, naming `install`: commit that, then delete the identity
    /// key, then the records and the flow (Switch spec 12.8). A deletion that fails, or a
    /// crash, leaves the marked records, which the next call or open deletes before anything
    /// else, and which count as none for a new set-up.
    async fn handed_over(&mut self, install: [u8; 16]) -> Result<()> {
        let mut state = self.state.clone();
        state.handed_over_to = Some(install);
        state.managed_by = Some(install);
        state.handing_over = None;
        self.commit(state, None).await?;
        self.delete_handed_over(install).await
    }

    /// Delete what is left once the hand-over to `install` took effect: the key, then the
    /// records. Both deletions are idempotent.
    pub(super) async fn delete_handed_over(&mut self, install: [u8; 16]) -> Result<()> {
        self.keyring.destroy()?;
        state::delete(&self.env.store, &self.state.identity).await?;
        self.flow = None;
        Err(SignerError::HandedOver { install })
    }
}

/// Whether a refusal of `PUT /handover` with `status` is for good: the same bytes would be
/// refused again. Refusals of the caller, rate limits and server errors aren't.
fn definite(status: u16) -> bool {
    matches!(status, 400 | 404 | 409 | 410 | 413 | 422)
}
