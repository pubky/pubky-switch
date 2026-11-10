//! Handing the identity over to another signer, and aborting it: the old signer's side
//! (Switch spec 12.8; Switch wire 3.12, 7.4.17).
//!
//! On the user's confirmation, the old signer seals its records, the identity secret in them,
//! to the certified bundle key of an app its newest `identity.json` lists and the switch shows
//! current, and stores the hand-over at the switch (`PUT /handover`). It hands over only the
//! newest version the switch accepted from it, with no closing delivery owed. From then on it
//! signs nothing for the identity but the abort: the signing gate refuses every routine step
//! ([`crate::Refusal::HandingOver`]), and the routine run keeps the work it owes for later. No
//! revocation is owed when it starts, nor asked for meanwhile: the hand-over carries the
//! records as sealed, not a revocation in progress, so one the switch hadn't taken when it took
//! effect would be lost with this install's records. The user aborts first, then revokes.
//!
//! The hand-over ends one of two ways, whichever wins the switch's compare-and-swap on the
//! version handed over:
//!
//! - **It takes effect.** The new signer delivers that version plus 1, naming its own install.
//!   The old signer deletes the identity key, then its records, only on a copy of
//!   `identity.json` that proves another install holds the identity: from the switch, in its
//!   `GET /apps` answer or a `409 stale_identity` answering the abort, both authenticated with
//!   its pinned key; verifying for the identity; at the version handed over plus 1 and the same
//!   generation; naming another install; and not the abort. The switch's copy doesn't carry
//!   the hash it builds on, but the switch took it with the compare-and-swap on the version it
//!   held, which was the one handed over, so it builds on it. And the Homeserver must publish
//!   that version, or a later one of that install: the new signer publishes only once its
//!   delivery has won, so a switch that shows each side the other's version can't make both
//!   delete the key. Until then the key and the hand-over stay. The deletion is committed
//!   first, so a crash between the key and the records leaves marked records, which the next
//!   open deletes and a new set-up replaces. Any other newer copy, such as one
//!   further on, or one only the Homeserver shows, is adopted as any other signer's, and the
//!   key stays. Answers that decide nothing, such as a refusal of the caller, a rate limit or
//!   a copy that doesn't verify, delete nothing.
//! - **It is aborted.** Only while the switch still holds the version handed over, the old
//!   signer signs it again, at its version plus 2 so it never shares a version with the new
//!   signer's, built on the same hash, and delivers it. Once it has won, the hand-over is over and the backup is written, as after a
//!   restore (Switch wire 3.13 "When it is written").
//!
//! The version after the one handed over may come from a third install that restored the new
//! signer's backup before the old signer looked: the switch's copy can't tell the two apart.
//! The identity has another signer either way, so deleting is still right; the outcome names
//! the install the copy names, not the target.

use pubky_switch_client::ClientError;
use pubky_switch_client::client::answers::StoredHandover;
use pubky_switch_core::records::{AppCert, IDENTITY_PATH, IdentityDoc, abort_body, succeeded};
use pubky_switch_core::sig::SignedDoc;

use super::revocation::UserConfirmed;
use super::{Signer, gate};
use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::state::{self, DeliverStep, Flow, HandOverSent, HandingOver};

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
        if !self.state.revoking.is_empty() {
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
        let target_current = self.service_client()?.apps().await?.apps.iter().any(|s| {
            s.app_id == to_app && s.current && s.revoked_at.is_none() && s.departed_at.is_none()
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

    /// Whether `copy`, from the switch, shows that the hand-over in progress took effect: it
    /// is at the version handed over plus 1 and the same generation, names another install,
    /// and isn't this install's abort (Switch wire 3.12; the core's `succeeded`). The switch
    /// took it with its compare-and-swap on the version handed over, so it builds on it.
    pub(super) fn hand_over_took_effect(&self, copy: &IdentityDoc) -> bool {
        let Some(handing) = &self.state.handing_over else {
            return false;
        };
        let Ok(handed) = IdentityDoc::verify(&handing.doc, &self.state.identity) else {
            return false;
        };
        let delivered: Vec<[u8; 32]> = handing.abort.into_iter().collect();
        copy.version() == handed.version().saturating_add(1)
            && copy.generation() == handed.generation()
            && copy.body().signer != self.state.install
            && succeeded(&handed, &delivered, copy.version(), &copy.hash())
    }

    /// The switch's `copy` shows the hand-over took effect. The key goes only once the
    /// Homeserver publishes that version, or a later one of the same install: the new signer
    /// publishes only once its delivery has won, so a switch that shows each side the other's
    /// version can't make both delete the key. Until then this install keeps the key and the
    /// hand-over, and signs nothing ([`Refusal::SuccessorUnpublished`]).
    pub(super) async fn succeeded(&mut self, copy: &IdentityDoc) -> Result<()> {
        let install = copy.body().signer;
        let published = self
            .env
            .homeserver
            .get(IDENTITY_PATH)
            .await
            .map_err(SignerError::Homeserver)?
            .and_then(|bytes| serde_json::from_slice::<SignedDoc>(&bytes).ok())
            .and_then(|signed| IdentityDoc::verify(&signed, &self.state.identity).ok())
            .is_some_and(|held| {
                held.signed() == copy.signed()
                    || (held.body().signer == install
                        && held.generation() == copy.generation()
                        && held.version() > copy.version())
            });
        if !published {
            return Err(Refusal::SuccessorUnpublished { install }.into());
        }
        self.handed_over(install).await
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
