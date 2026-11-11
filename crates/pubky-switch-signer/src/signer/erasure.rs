//! Erasing the identity's account at its switch, when the user stops using the Switch (Switch
//! spec 12.7; Switch wire 7.4.16).
//!
//! [`Signer::close_account`] commits the erasure as a flow, then:
//!
//! 1. deletes `identity.json` and every app record it knows of from the Homeserver, so
//!    counterparties find no identity on the Switch instead of one whose switch doesn't
//!    answer, and asks the user to revoke the Pubky grant of each app, listed or removed,
//!    whose reminder isn't raised yet ([`Alert::GrantRevocationOwed`]), since the Pubky SDK
//!    offers no call for it (design note, decision 4);
//! 2. sends `POST /v1/{id}/erase` naming the pinned service key, again until it is answered,
//!    marking before each request that it may land. A `200` confirms the erasure. So does an
//!    unsigned `404`, the operator's, but only after a request that may have landed, as a
//!    lost `200` leaves it (Switch wire 7.4.16). A `404` is never itself a lost answer: with
//!    no request in doubt it is an error, and the mark goes back. No answer, or another
//!    answer the pinned key didn't sign, such as a gateway's `503`, keeps the mark; only an
//!    answer the pinned key signed shows the account still exists, and clears it.
//!
//! A `409 conflict` is the switch refusing it, as during a move: the erasure ends without
//! erasing, `identity.json` is published again, and the grant reminders it raised for apps
//! still listed are withdrawn; a removed app's stays. [`Signer::abort_erasure`] ends it the same way on the user's word, while no
//! request may have landed. The app records it deleted stay deleted until each app writes its
//! own again.
//!
//! Once erased, the records stay (Switch spec 12.7 step 4): the App IDs revoked for good among
//! them, which a later enrollment names again. What only the erased account could settle is
//! dropped: the alerts of revocations not yet sent there and of an owed closing, and an owed
//! backup. Nothing
//! more is signed for the account, and a revocation or a restore is refused. The signer backup
//! on the Homeserver stays, with the identity secret sealed to the identity's own backup key,
//! naming the erased switch. Enrolling again after an erasure starts the account as after a
//! provider loss (Switch wire 7.4.16), which this signer doesn't do yet.

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
        let flow = Flow::Erase {
            unpublished: false,
            reminded: Vec::new(),
            unanswered: false,
        };
        // Unpublished from the first deletion on: an erasure that ends without erasing, after
        // any part of the Homeserver's files went, has `identity.json` published again.
        let mut state = self.state.clone();
        if let Some(newest) = state.newest.as_mut() {
            newest.published = false;
        }
        self.commit(state, Some(flow)).await?;
        self.resume().await
    }

    /// End the erasure in progress without erasing, on the user's word: `identity.json` is
    /// published again, and the grant reminders the erasure raised are withdrawn. The app
    /// records it deleted stay deleted until each app writes its own again.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotErasing`] when no erasure is in progress; [`Refusal::ErasureUnanswered`]
    /// when a request of it went unanswered and may have erased the account, which
    /// [`Signer::resume`] finds out; otherwise as [`Signer::resume`].
    pub async fn abort_erasure(&mut self) -> Result<()> {
        self.refresh().await?;
        let Some(Flow::Erase {
            reminded,
            unanswered,
            ..
        }) = self.flow.clone()
        else {
            return Err(Refusal::NotErasing.into());
        };
        if unanswered {
            return Err(Refusal::ErasureUnanswered.into());
        }
        self.end_erasure(&reminded).await?;
        self.resume().await
    }

    /// The erasure's next step: the Homeserver's files unless `unpublished`, then the
    /// erasure at the switch.
    pub(super) async fn erase(
        &mut self,
        unpublished: bool,
        reminded: Vec<[u8; 16]>,
        unanswered: bool,
    ) -> Result<()> {
        if !unpublished {
            return self.unpublish().await;
        }
        // Before the request: it may land, however its answer goes.
        if !unanswered {
            let flow = Flow::Erase {
                unpublished,
                reminded: reminded.clone(),
                unanswered: true,
            };
            self.commit(self.state.clone(), Some(flow)).await?;
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
            Ok(()) => self.erased().await,
            // A `404` signed with the operator's key, after a request that went unanswered:
            // the service hosts no account for the identity, as after a lost `200` (Switch
            // wire 7.4.16).
            Err(ClientError::BadServiceSignature { status: 404 }) if unanswered => {
                self.erased().await
            }
            // A `404` is never a lost answer: the operator's means the switch hosted no account
            // when it answered, an intermediary's that the request wasn't routed. With no
            // request in doubt before, it erased nothing, and it never sets the doubt itself.
            Err(error @ ClientError::BadServiceSignature { status: 404 }) => {
                let flow = Flow::Erase {
                    unpublished,
                    reminded,
                    unanswered: false,
                };
                self.commit(self.state.clone(), Some(flow)).await?;
                Err(error.into())
            }
            // No answer, or another answer the pinned key didn't sign, such as a gateway's
            // `502`, `503` or `504`, which can hide a forwarded request: the request may have
            // landed, and the mark stays.
            Err(error @ (ClientError::Transport(_) | ClientError::BadServiceSignature { .. })) => {
                Err(error.into())
            }
            Err(ClientError::Switch {
                code: ErrorCode::Conflict,
                ..
            }) => {
                self.end_erasure(&reminded).await?;
                Err(Refusal::ErasureRefused.into())
            }
            // An answer the pinned key signed, which the account still exists to sign: the
            // erasure didn't land, and the next request is a first one again.
            Err(error @ (ClientError::Switch { .. } | ClientError::InvalidResponse(_))) => {
                let flow = Flow::Erase {
                    unpublished,
                    reminded,
                    unanswered: false,
                };
                self.commit(self.state.clone(), Some(flow)).await?;
                Err(error.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// The account is erased: what only it could settle goes, and the records stay.
    async fn erased(&mut self) -> Result<()> {
        let mut state = self.state.clone();
        state.erased = true;
        state.backup_owed = false;
        state.alerts.retain(|alert| {
            !matches!(
                alert,
                Alert::ReductionNotClosed { .. }
                    | Alert::RevocationPending { .. }
                    | Alert::RevocationUnconfirmed { .. }
                    | Alert::BackupNotWritten
            )
        });
        self.commit(state, None).await
    }

    /// End the erasure without erasing: withdraw the grant reminders it raised for apps the
    /// newest version still lists, and leave `identity.json` unpublished, which the next run
    /// publishes again. A removed app's reminder stays: its grant's revocation is owed whether
    /// or not the account is erased (Switch spec 12.2 step 1).
    async fn end_erasure(&mut self, reminded: &[[u8; 16]]) -> Result<()> {
        let newest = self.state.newest_doc()?;
        let reminded: Vec<[u8; 16]> = reminded
            .iter()
            .copied()
            .filter(|app| {
                newest
                    .as_ref()
                    .is_some_and(|doc| doc.listed_cert(app).is_some())
            })
            .collect();
        let reminded = reminded.as_slice();
        let mut state = self.state.clone();
        state.alerts.retain(|alert| {
            !matches!(alert, Alert::GrantRevocationOwed { app_id } if reminded.contains(app_id))
        });
        state
            .grant_reminded
            .retain(|app_id| !reminded.contains(app_id));
        self.commit(state, None).await
    }

    /// Delete `identity.json` and every app record the signer knows of from the Homeserver,
    /// and ask the user to revoke the grant of each app, listed or removed, not reminded yet
    /// (Switch spec 12.2 step 1, 12.7 step 5).
    async fn unpublish(&mut self) -> Result<()> {
        let newest = self.state.newest_doc()?;
        let apps: Vec<[u8; 16]> = newest
            .iter()
            .flat_map(|doc| doc.body().apps.iter().map(|a| a.app_id))
            .chain(self.state.cleanup.iter().copied())
            .chain(self.state.deletion_checks.iter().copied())
            .collect();
        let homeserver = &self.env.homeserver;
        homeserver
            .delete(IDENTITY_PATH)
            .await
            .map_err(SignerError::Homeserver)?;
        for app_id in &apps {
            homeserver
                .delete(&app_record_path(app_id))
                .await
                .map_err(SignerError::Homeserver)?;
        }
        let mut state = self.state.clone();
        let mut reminded = Vec::new();
        for app_id in apps {
            if !state.grant_reminded.contains(&app_id) {
                state.alert(Alert::GrantRevocationOwed { app_id });
                state.grant_reminded.push(app_id);
                reminded.push(app_id);
            }
        }
        state.cleanup.clear();
        state.deletion_checks.clear();
        if let Some(newest) = state.newest.as_mut() {
            newest.published = false;
        }
        let flow = Flow::Erase {
            unpublished: true,
            reminded,
            unanswered: false,
        };
        self.commit(state, Some(flow)).await
    }
}
