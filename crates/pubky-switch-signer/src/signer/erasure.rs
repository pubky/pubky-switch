//! Erasing the identity's account at its switch, when the user stops using the Switch (Switch
//! spec 12.7; Switch wire 7.4.16).
//!
//! [`Signer::close_account`] commits the erasure as a flow, then:
//!
//! 1. deletes `identity.json` and every app record it knows of from the Homeserver, so
//!    counterparties find no identity on the Switch instead of one whose switch doesn't
//!    answer, and asks the user to revoke each app's Pubky grant
//!    ([`Alert::GrantRevocationOwed`]), since the Pubky SDK offers no call for it yet (design
//!    note, decision 4);
//! 2. sends `POST /v1/{id}/erase` naming the pinned service key, again until it is answered.
//!    A `200` confirms the erasure; so does the operator's `404` on a retry, which a lost `200`
//!    leaves, since the service then hosts no account for the identity. A `409 conflict` is the
//!    switch refusing it: nothing was erased, and `identity.json` is published again.
//!
//! Once erased, the records stay (Switch spec 12.7 step 4): the App IDs revoked for good among
//! them, which a later enrollment names again. Nothing more is signed for the erased account.
//! The signer backup on the Homeserver stays, with the identity secret sealed to the identity's
//! own backup key. Enrolling again after an erasure starts the account as after a provider loss
//! (Switch wire 7.4.16), which this signer doesn't do yet.

use pubky_switch_client::ClientError;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::records::{IDENTITY_PATH, app_record_path};

use super::Signer;
use super::revocation::UserConfirmed;
use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::state::Flow;

impl Signer {
    /// Erase the identity's account at its switch, once the user has confirmed it (Switch spec
    /// 12.7 step 5): `identity.json` and the app records leave the Homeserver, the user is
    /// asked to revoke the apps' grants, then the switch erases the account.
    ///
    /// For the identity's apps this is a provider loss, and lookups of `identity.json` fail
    /// closed (Switch spec 12.7 step 5): the host shows the user that before asking.
    ///
    /// # Errors
    ///
    /// The signing gate's refusals, as before every signing step: another install signs, an
    /// alarm is held, a hand-over or a take-over is in progress, a flow is in progress, or the
    /// account is erased already ([`Refusal::Erased`]). [`Refusal::ErasureRefused`] when the
    /// switch refuses it. Otherwise the Homeserver's, the switch's or the store's error, the
    /// erasure kept and finished by [`Signer::resume`].
    pub async fn close_account(&mut self, _confirmed: UserConfirmed) -> Result<()> {
        self.ready().await?;
        self.commit(self.state.clone(), Some(Flow::Erase { unpublished: false }))
            .await?;
        self.resume().await
    }

    /// The erasure's next step: the Homeserver's files unless `unpublished`, then the
    /// erasure at the switch.
    pub(super) async fn erase(&mut self, unpublished: bool) -> Result<()> {
        if !unpublished {
            self.unpublish().await?;
        }
        // Through the signing gate, as every signing step: the erasure is the identity's
        // to ask for only while this install signs.
        let answer = {
            let key = self.signing_key()?;
            let client = self.signing_client(&key)?;
            drop(key);
            client.erase().await
        };
        match answer {
            // A `404` signed with the operator's key: the service hosts no account for the
            // identity, as after a `200` that was lost (Switch wire 7.4.16).
            Ok(()) | Err(ClientError::BadServiceSignature { status: 404 }) => {
                let mut state = self.state.clone();
                state.erased = true;
                self.commit(state, None).await
            }
            Err(ClientError::Switch {
                code: ErrorCode::Conflict,
                ..
            }) => {
                // Nothing was erased. `identity.json` is unpublished, so the next run
                // publishes it again.
                self.commit(self.state.clone(), None).await?;
                Err(Refusal::ErasureRefused.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Delete `identity.json` and every app record the signer knows of from the Homeserver,
    /// and ask the user to revoke each listed app's grant (Switch spec 12.7 step 5).
    async fn unpublish(&mut self) -> Result<()> {
        let newest = self.state.newest_doc()?;
        let listed: Vec<[u8; 16]> = newest
            .iter()
            .flat_map(|doc| doc.body().apps.iter().map(|a| a.app_id))
            .collect();
        let homeserver = &self.env.homeserver;
        homeserver
            .delete(IDENTITY_PATH)
            .await
            .map_err(SignerError::Homeserver)?;
        let records = listed
            .iter()
            .chain(&self.state.cleanup)
            .chain(&self.state.deletion_checks);
        for app_id in records {
            homeserver
                .delete(&app_record_path(app_id))
                .await
                .map_err(SignerError::Homeserver)?;
        }
        let mut state = self.state.clone();
        for app_id in listed {
            if !state.grant_reminded.contains(&app_id) {
                state.alert(Alert::GrantRevocationOwed { app_id });
                state.grant_reminded.push(app_id);
            }
        }
        state.cleanup.clear();
        state.deletion_checks.clear();
        if let Some(newest) = state.newest.as_mut() {
            newest.published = false;
        }
        self.commit(state, Some(Flow::Erase { unpublished: true }))
            .await
    }
}
