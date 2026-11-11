//! Taking the identity over from a hand-over: the new signer's side (Switch spec 12.8;
//! Switch wire 3.12, 7.4.17).
//!
//! The app the old signer handed over to fetches the hand-over with its own credentials
//! (`GET /handover`), and checks it as wire 3.12 says:
//!
//! 1. the count and the signature over its App ID, and every envelope opens with its bundle
//!    secret into records whose secret is the identity's;
//! 2. `identity_doc` verifies, lists this app, and every certificate it references is held;
//! 3. the switch holds `identity_doc` itself, and the Homeserver nothing newer nor another
//!    document at its version. An older switch copy, or none, fails it too: the switch went
//!    back, and a delivery built on the version handed over would be refused. Nothing has been
//!    sent then, so nothing received is kept, and the hand-over is still at the switch.
//!
//! It commits a take-over flow holding the hand-over as received, sealed to its bundle key,
//! never the opened secret. The secret is opened in memory, from that flow only, to sign and to
//! send ([`crate::IdentityKeyring`]'s received form), at the start and on each resume
//! ([`Signer::resume_take_over`]). Its first delivery is the version handed over plus 1, naming
//! this install, built on it, signed once and sent again with the same bytes:
//!
//! - **It won**, a `2xx`, or a `409 stale_identity` whose copy is that delivery itself, or a
//!   later version naming this install, as after a lost answer or a resend of stale bytes.
//!   The secret goes into the vault, is read back and checked, and only then is the flow,
//!   with the hand-over, dropped. A vault that fails keeps the flow with
//!   [`crate::Alert::KeyNotInstalled`], and nothing is sent again. The backup is written next,
//!   and the version is published only once it is: the old signer's deletion relies on that
//!   order (Switch wire 3.12). Once it has won, nothing cancels the take-over.
//! - **It lost**, a `409 stale_identity` whose copy verifies for the identity, is at or above
//!   the delivery's version, and names another install: an abort, or another signer, got
//!   ahead. The records and the flow are deleted, and the secret, never in the vault, goes
//!   with the keyring.
//! - Anything else decides nothing and deletes nothing: a refusal of the caller, a rate limit,
//!   a server error, or a `409` whose copy is missing, older or doesn't verify. The delivery
//!   is sent again. A refusal for good, a `400`, a `403` or a `409 conflict`, also raises
//!   [`crate::Alert::TakeOverRefused`]; the old signer's abort is the way out.
//!
//! A refusal or a cancellation deletes only what that hand-over brought, never a key the
//! install held before: an install that signs for the identity refuses another take-over
//! (`AlreadySetUp`), and a vault already holding the key keeps it.
//!
//! It takes the records as a restore does: the tombstones those of the hand-over, its
//! `identity_doc`'s `removed` and the switch's revoked or departed apps; the epoch floor; and
//! the removed apps' records left for the routine run to check.

use std::sync::Arc;

use pubky_switch_client::ClientError;
use pubky_switch_core::http::{ErrorCode, IdentityDelivery};
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{
    AppCert, IDENTITY_PATH, IdentityDoc, SignerRecords, check_handover_copies, revoked_after,
    take_over_body,
};
use pubky_switch_core::sig::SignedDoc;
use serde_json::Value;
use zeroize::Zeroizing;

use super::clients::{AppClient, Target};
use super::restore::removed_at_switch;
use super::{Signer, SignerEnv, gate};
use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::key::{BackupView, IdentityKeyring, SecretVault};
use crate::state::{self, Flow, Newest, Service, SignerState, TakeOverDelivery};

/// The app taking the identity over: its keys and certificate, and the switch it reaches the
/// identity's account at.
pub struct ReceivingApp {
    /// The app's signing and bundle keys.
    pub keys: AppKeys,
    /// The app's certificate, which the newest `identity.json` lists.
    pub cert: AppCert,
    /// The switch's origin, as `identity.json` names it.
    pub origin: String,
    /// The account's service key, as `identity.json` names it.
    pub service_key: [u8; 32],
}

impl std::fmt::Debug for ReceivingApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivingApp")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// What a `409 stale_identity` answering the take-over's delivery shows.
enum Answer409 {
    /// The copy is the delivery itself: it won, and the answer was lost.
    Won,
    /// A verified copy at or above the delivery's version naming another install: the
    /// take-over lost.
    Lost {
        /// The signer ID the copy names.
        install: [u8; 16],
    },
    /// Nothing decided.
    Unsure,
}

impl Signer {
    /// Take the identity over from the hand-over the switch holds for `app` (Switch spec
    /// 12.8, Switch wire 3.12), on an install whose store holds no records for it, with the
    /// host's `vault` for the identity secret, which must be empty. Checks 1 to 3, then the
    /// first delivery; the secret goes into `vault` once it has won.
    ///
    /// The user's prompts, before the take-over and after it, are the host's.
    ///
    /// # Errors
    ///
    /// [`Refusal::AlreadySetUp`] when the store holds records for the identity;
    /// [`crate::KeyError::Occupied`] when `vault` holds another identity's secret;
    /// [`SignerError::InvalidData`] for a hand-over that fails check 1 or 2, or names another
    /// switch; [`Refusal::StaleHandOver`] when check 3 fails; [`Refusal::TakeOverCancelled`]
    /// when the delivery lost; otherwise the switch's, the store's or the vault's error, the
    /// take-over kept for [`Signer::resume_take_over`]. An error after the take-over has won,
    /// from the backup or the publication, leaves it to [`Signer::resume_take_over`] too, or
    /// to [`Signer::open`] with the vault's keyring.
    pub async fn receive_hand_over(
        env: SignerEnv,
        app: &ReceivingApp,
        vault: Arc<dyn SecretVault>,
    ) -> Result<Self> {
        let identity = app.cert.identity();
        let app_id = app.cert.app_id();
        if state::set_up(&env.store, &identity).await? {
            return Err(Refusal::AlreadySetUp.into());
        }
        // A vault that holds another secret could never take this one: found before anything
        // is sent, not once the delivery has won.
        IdentityKeyring::vault_takes(vault.as_ref(), &identity)?;
        let target = Target {
            origin: &app.origin,
            pinned: Some(app.service_key),
            identity,
        };
        let stored = AppClient::new(&env, &target, &app.keys, &app.cert)?
            .get_handover()
            .await?;
        if stored.app_id != app_id {
            return Err(invalid("the switch serves a hand-over for another app"));
        }
        // Checks 1 and 2 before anything is kept.
        let limits = {
            let bundle_secret = Zeroizing::new(app.keys.bundle_secret());
            let records = stored.handover.open(&identity, &app_id, &bundle_secret)?;
            let inbox = records.identity_doc().inbox();
            if inbox.url != app.origin || inbox.service_key != app.service_key {
                return Err(invalid(
                    "the handed-over identity.json names another switch than the one asked",
                ));
            }
            *records.limits()
        };
        let install = pubky_switch_core::enc::random_bytes::<16>()?;
        let mut state = SignerState::new(identity, install);
        state.taking_over = true;
        state.service = Some(Service {
            origin: app.origin.clone(),
            service_key: app.service_key,
            limits,
        });
        let flow = Flow::TakingOver {
            handover: stored.handover,
            app_id,
            delivery: None,
        };
        state::save(&env.store, &state, Some(&flow)).await?;
        let (mut signer, records) = Self::taking_over(env, state, flow, vault, &app.keys)?;
        signer.prepare_take_over(records).await?;
        signer.resume().await?;
        Ok(signer)
    }

    /// The signer of a take-over the store holds in progress for `identity`, the identity
    /// secret opened again from the hand-over it holds with `keys`, the receiving app's,
    /// and its next step taken (Switch wire 3.12). A store with no take-over gives none. A
    /// take-over that has won, whose secret is in `vault`, is opened with the vault's keyring
    /// and resumed, as [`Signer::open`] would.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotSetUp`] when the store holds no records for the identity,
    /// [`Refusal::NotTakingOver`] when it holds no take-over; otherwise as
    /// [`Signer::receive_hand_over`].
    pub async fn resume_take_over(
        env: SignerEnv,
        identity: [u8; 32],
        keys: &AppKeys,
        vault: Arc<dyn SecretVault>,
    ) -> Result<Self> {
        let (state, flow) = state::load(&env.store, &identity)
            .await?
            .ok_or(Refusal::NotSetUp)?;
        let Some(flow @ Flow::TakingOver { .. }) = flow else {
            // Won already: the secret is in the vault, and the routine steps go on.
            if state.taking_over || state.handed_over_to.is_some() {
                return Err(Refusal::NotTakingOver.into());
            }
            let keyring = IdentityKeyring::open(vault)?;
            let mut signer = Self::open(env, keyring).await?;
            signer.resume().await?;
            return Ok(signer);
        };
        let (mut signer, records) = Self::taking_over(env, state, flow, vault, keys)?;
        let unsigned = matches!(signer.flow, Some(Flow::TakingOver { delivery: None, .. }));
        if unsigned {
            signer.prepare_take_over(records).await?;
        } else {
            drop(records);
        }
        signer.resume().await?;
        Ok(signer)
    }

    /// The signer of the take-over `flow`, with the received keyring opened from its
    /// hand-over, and the records it carries.
    fn taking_over(
        env: SignerEnv,
        state: SignerState,
        flow: Flow,
        vault: Arc<dyn SecretVault>,
        keys: &AppKeys,
    ) -> Result<(Self, SignerRecords)> {
        let Flow::TakingOver {
            handover, app_id, ..
        } = &flow
        else {
            return Err(Refusal::NotTakingOver.into());
        };
        let bundle_secret = Zeroizing::new(keys.bundle_secret());
        let (keyring, records) =
            IdentityKeyring::received(vault, handover, &state.identity, app_id, &bundle_secret)?;
        let signer = Self {
            env,
            keyring,
            state,
            flow: Some(flow),
            unsure: false,
        };
        Ok((signer, records))
    }

    /// Check 3, then take the records and sign the first delivery with the received key,
    /// committed with the flow. Check 3 failing deletes what was received.
    async fn prepare_take_over(&mut self, records: SignerRecords) -> Result<()> {
        let identity = self.state.identity;
        let handed = records.identity_doc().clone();
        let answer = self.service_client()?.apps().await?;
        let switch_copy = answer
            .identity
            .as_ref()
            .map(|signed| IdentityDoc::verify(signed, &identity))
            .transpose()?;
        let homeserver_copy = self
            .env
            .homeserver
            .get(IDENTITY_PATH)
            .await
            .map_err(SignerError::Homeserver)?
            .and_then(|bytes| serde_json::from_slice::<SignedDoc>(&bytes).ok())
            .and_then(|signed| IdentityDoc::verify(&signed, &identity).ok());
        let at_handed = switch_copy
            .as_ref()
            .is_some_and(|copy| copy.signed() == handed.signed());
        let copies: Vec<&IdentityDoc> = switch_copy.iter().chain(homeserver_copy.iter()).collect();
        if !at_handed || check_handover_copies(&records, &copies).is_err() {
            // Nothing was sent: the old signer still holds the identity.
            drop(records);
            self.keyring.forget_held();
            state::delete(&self.env.store, &identity).await?;
            self.flow = None;
            self.state.taking_over = false;
            return Err(Refusal::StaleHandOver.into());
        }
        let switch_removed: Vec<[u8; 16]> = removed_at_switch(&answer).collect();
        let tombstones = revoked_after(&records, &switch_removed);
        let view = BackupView::of(&records);
        let mut state = self.taken_records(&view, &answer, self.service()?, tombstones, Vec::new());
        state.taking_over = true;
        // The old signer's version, published already: this install's own replaces it.
        state.newest = Some(Newest {
            doc: handed.signed().clone(),
            prev: None,
            published: true,
            delivered_at: None,
        });
        let (body, prev) = take_over_body(&records, self.state.install)?;
        drop(records);
        let doc = {
            let key = gate::taking_over_key(&self.keyring, &state)?;
            IdentityDoc::sign(&key, body)?
        };
        state.signed_through = doc.version();
        let Some(Flow::TakingOver {
            handover, app_id, ..
        }) = self.flow.clone()
        else {
            return Err(Refusal::NotTakingOver.into());
        };
        let flow = Flow::TakingOver {
            handover,
            app_id,
            delivery: Some(TakeOverDelivery {
                doc: doc.signed().clone(),
                prev,
                won: false,
            }),
        };
        self.commit(state, Some(flow)).await
    }

    /// The take-over flow's next step: its first delivery sent until it is decided, then,
    /// once it won, the secret put in the vault and the flow dropped.
    pub(super) async fn take_over(&mut self, delivery: Option<TakeOverDelivery>) -> Result<()> {
        let Some(delivery) = delivery else {
            // Only the received form signs the first delivery, from the flow's hand-over.
            return Err(Refusal::NotTakingOver.into());
        };
        let mut delivered_at = None;
        if !delivery.won {
            let sent = IdentityDelivery {
                identity: delivery.doc.clone(),
                prev: Some(delivery.prev),
            };
            match self.service_client()?.put_identity(&sent).await {
                Ok(answer) => {
                    delivered_at = answer
                        .proofs
                        .first()
                        .and_then(|proof| proof.body().chain.open().ok())
                        .map(|envelope| envelope.server_time);
                }
                Err(ClientError::Switch {
                    code: ErrorCode::StaleIdentity,
                    current,
                    ..
                }) => match self.read_409(&current, &delivery.doc) {
                    Answer409::Won => {}
                    Answer409::Lost { install } => return self.take_over_lost(install).await,
                    Answer409::Unsure => {
                        return Err(invalid(
                            "Switch wire 7.4.2: stale_identity without a copy that decides the take-over",
                        ));
                    }
                },
                Err(error) => {
                    // A refusal for good decides nothing either; the user is told.
                    if let ClientError::Switch {
                        status: 400 | 403 | 409,
                        ..
                    } = &error
                        && !self.state.alerts.contains(&Alert::TakeOverRefused)
                    {
                        let mut state = self.state.clone();
                        state.alert(Alert::TakeOverRefused);
                        self.commit(state, self.flow.clone()).await?;
                    }
                    return Err(error.into());
                }
            }
            let mut flow = self.flow.clone();
            if let Some(Flow::TakingOver {
                delivery: Some(held),
                ..
            }) = flow.as_mut()
            {
                held.won = true;
            }
            self.commit(self.state.clone(), flow).await?;
        }
        // Into the vault, read back and checked, and only then the hand-over dropped.
        if let Err(error) = self.keyring.install_held() {
            let mut state = self.state.clone();
            state.alert(Alert::KeyNotInstalled);
            self.commit(state, self.flow.clone()).await?;
            return Err(error.into());
        }
        let mut state = self.state.clone();
        state.taking_over = false;
        state.alerts.retain(|a| *a != Alert::KeyNotInstalled);
        // An identity taken over near the size a delivery may carry is told at once (Switch
        // wire 3.7, 7.1). Only an alert: a measure that fails never holds back the win.
        if let Ok(nearest) = super::version_size(&state, &delivery.doc, Some(delivery.prev)) {
            state.note_size(nearest.bytes, nearest.limit);
        }
        state.newest = Some(Newest {
            doc: delivery.doc,
            prev: Some(delivery.prev),
            published: false,
            delivered_at,
        });
        state.switch_unconfirmed = false;
        // It raced the old signer, so its backup is written now it has won (Switch wire 3.13),
        // and the version is published only once it is (Switch wire 3.12).
        state.backup_owed = true;
        state.publish_after_backup = true;
        state.alerts.retain(|a| *a != Alert::TakeOverRefused);
        self.commit(state, None).await
    }

    /// Judge the `current` of a `409 stale_identity` answering the delivery `own`.
    fn read_409(&self, current: &Value, own: &SignedDoc) -> Answer409 {
        let Some(copy) = current
            .get("identity")
            .and_then(|doc| serde_json::from_value::<SignedDoc>(doc.clone()).ok())
            .and_then(|signed| IdentityDoc::verify(&signed, &self.state.identity).ok())
        else {
            return Answer409::Unsure;
        };
        if copy.signed() == own {
            return Answer409::Won;
        }
        let own_version =
            IdentityDoc::verify(own, &self.state.identity).map_or(u64::MAX, |doc| doc.version());
        if copy.version() < own_version {
            return Answer409::Unsure;
        }
        // At or above the delivery's version: another install's got ahead; this install's own
        // means its delivery won earlier and it signed on, as after a resend of stale bytes.
        if copy.body().signer == self.state.install {
            return Answer409::Won;
        }
        Answer409::Lost {
            install: copy.body().signer,
        }
    }

    /// The take-over lost to `install`'s version: delete the records and the flow, with the
    /// hand-over, and drop the received secret, never in the vault.
    async fn take_over_lost(&mut self, install: [u8; 16]) -> Result<()> {
        state::delete(&self.env.store, &self.state.identity).await?;
        self.keyring.forget_held();
        self.flow = None;
        self.state.taking_over = false;
        self.state.managed_by = Some(install);
        Err(Refusal::TakeOverCancelled.into())
    }
}

fn invalid(why: &str) -> SignerError {
    SignerError::InvalidData(pubky_switch_core::Error::Invalid(format!(
        "Switch wire 3.12: {why}"
    )))
}
