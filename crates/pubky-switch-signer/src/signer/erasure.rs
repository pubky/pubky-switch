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
//! 2. sends `POST /v1/{id}/erase` naming the pinned service key, again until it is answered
//!    or, after a request in doubt, the check's read meets the operator's `404`, marking
//!    before each request that it may land. A `200` confirms the erasure. So does an
//!    unsigned `404`, the operator's, but only after a request that may have landed, as a
//!    lost `200` leaves it, and only once every check has met it for 24 hours: until then
//!    the account is erased but unconfirmed ([`Refusal::ErasureUnconfirmed`]), the time of
//!    the first `404` kept in the flow, and an answer the pinned key signs ends the wait
//!    (Switch wire 7.4.16, spec 12.7 step 5). A `404` is never itself a lost answer: with
//!    no request in doubt it is an error, and the mark goes back. No answer, or another
//!    answer the pinned key didn't sign, such as a gateway's `503`, keeps the mark; only an
//!    answer the pinned key signed shows the account still exists, and clears it.
//!
//! Every deletion and every request comes after a fresh check that this install still signs,
//! since the flow may be resumed much later: every copy, as before a delivery
//! ([`Signer::check_copies`]), before the first deletion and each request, and the switch's
//! copy and the Homeserver's `identity.json` before each later deletion; then the signing
//! gate. Another install found signing ends the erasure without erasing, with nothing more
//! deleted, sent or published by this install; an alarm or records behind keep it in
//! progress, with nothing deleted or sent while the alarm is held; a copy that can't be read
//! takes no step. After a request in doubt, an unsigned `404` to the check, with every other
//! copy clean, is taken as the erasure done once it has held for 24 hours, and no other
//! request goes out meanwhile.
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

use super::revocation::UserConfirmed;
use super::{Signer, gate};
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
            first_404_ms: None,
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
        first_404_ms: Option<u64>,
    ) -> Result<()> {
        if !unpublished {
            return self.unpublish().await;
        }
        // A request in doubt, then the switch's `404` and every other copy clean: erased
        // already, once it has held for 24 hours, and no other request goes out without an
        // ownership read.
        if self.still_erasing(unanswered, true).await? == Checked::ErasedAlready {
            return self.erased_after_doubt(reminded, first_404_ms).await;
        }
        // An answer the pinned key signed: the account is there, and the wait for the `404`
        // to hold starts again, if it ever comes (Switch wire 7.4.16).
        if first_404_ms.is_some() {
            let flow = Flow::Erase {
                unpublished,
                reminded: reminded.clone(),
                unanswered,
                first_404_ms: None,
            };
            self.commit(self.state.clone(), Some(flow)).await?;
        }
        // Before the request: it may land, however its answer goes.
        if !unanswered {
            let flow = Flow::Erase {
                unpublished,
                reminded: reminded.clone(),
                unanswered: true,
                first_404_ms: None,
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
                self.erased_after_doubt(reminded, None).await
            }
            // A `404` is never a lost answer: the operator's means the switch hosted no account
            // when it answered, an intermediary's that the request wasn't routed. With no
            // request in doubt before, it erased nothing, and it never sets the doubt itself.
            Err(error @ ClientError::BadServiceSignature { status: 404 }) => {
                let flow = Flow::Erase {
                    unpublished,
                    reminded,
                    unanswered: false,
                    first_404_ms: None,
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
                    first_404_ms: None,
                };
                self.commit(self.state.clone(), Some(flow)).await?;
                Err(error.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Before each step of an erasure that deletes or asks to erase, a fresh check that this
    /// install still signs, as before a delivery (Switch spec 4.3, Switch wire 3.13). In `full`,
    /// every copy ([`Signer::check_copies`]): it is named, the switch's copy is its mark, the
    /// signer backup names no other install that took over, and the Homeserver holds nothing
    /// newer. Otherwise the switch's copy, where a take-over shows first, since an install that
    /// takes over delivers there before it writes its backup or publishes (wire 3.13), and the
    /// Homeserver's `identity.json`, a defence against a switch read that lags or lies. A check
    /// that can't read a copy fails, and nothing is deleted or sent: the flow stays, and
    /// [`Signer::resume`] tries again. A passing check then meets the signing gate
    /// ([`gate::refusal`]), as at every signing step: while an alarm is held, nothing is
    /// deleted or sent either.
    ///
    /// Another install found signing ends the erasure without erasing, in the commit that
    /// records it ([`Signer::end_erasure_in`]), and nothing is published by this install, which
    /// no longer signs. An alarm keeps the erasure in progress, nothing deleted or sent: it
    /// goes on once the user has cleared it, or is aborted while no request is in doubt.
    /// Records behind keep it too, nothing deleted, sent or published, but the switch's copy is
    /// still read: another install's version there ends the erasure, and after a request in
    /// doubt the operator's `404` shows it erased. A user who wants the account back restores
    /// on a new install, which takes over; this install then finds it and ends its erasure.
    ///
    /// With a request in doubt, `unanswered`, an unsigned `404` to the switch's read may be the
    /// operator's after the erasure. The signer backup and the Homeserver are still judged; if
    /// they show no other install, the account is taken as erased already, on the same
    /// unauthenticated evidence wire 7.4.16 accepts for a retry's `404`, and no other request
    /// goes out: an install that delivered behind a proxy answering `404` is never erased.
    async fn still_erasing(&mut self, unanswered: bool, full: bool) -> Result<Checked> {
        // Records behind block every step that deletes or sends, not the read-only check of
        // the switch's copy, nor a conclusion drawn from it: another install's version there
        // ends the erasure, and the operator's `404` after a request in doubt shows it done.
        // Only that refusal of `check_named` is passed for the read; every other stops here.
        let behind = matches!(
            self.check_named(),
            Err(SignerError::Refused(Refusal::RecordsBehind { .. }))
        );
        let checked = if behind {
            self.switch_at_mark().await.map(drop)
        } else if full {
            self.check_copies().await.map(drop)
        } else {
            self.switch_and_homeserver().await
        };
        let checked = match checked {
            Err(SignerError::Switch(ClientError::BadServiceSignature { status: 404 }))
                if unanswered =>
            {
                self.copies_but_the_switch()
                    .await
                    .map(|()| Checked::ErasedAlready)
            }
            checked => checked.map(|()| Checked::Signing),
        };
        // An alarm or records behind keep the erasure in the commit that records them
        // (`Signer::erasure_kept`); another install found signing ends it in its own.
        let checked = checked?;
        // The gate holds back a deletion or a request, not the conclusion that the account is
        // erased already: wire 7.4.16 takes the operator's `404` after a request in doubt as
        // done whatever alarm is held, and `erased` keeps the alarm's alerts. Records still
        // behind after the read, as when the switch holds this install's own newer version or
        // the mark, are among the gate's refusals: no step.
        if checked == Checked::Signing
            && let Some(refused) = gate::refusal(&self.state)
        {
            return Err(refused);
        }
        Ok(checked)
    }

    /// The switch's copy and the Homeserver's `identity.json`, as before each later deletion.
    async fn switch_and_homeserver(&mut self) -> Result<()> {
        self.check_named()?;
        self.switch_at_mark().await?;
        if let Some(newest) = self.state.newest_doc()? {
            self.judge_homeserver(&newest).await?;
        }
        Ok(())
    }

    /// The copies but the switch's, after a request in doubt and an unsigned `404` from the
    /// switch: the signer backup and the Homeserver's `identity.json`, judged for another
    /// install signing, which stops it. This install's own newer version there, records behind,
    /// doesn't: the account is gone at the switch whatever this install's records say (Switch
    /// wire 7.4.16).
    async fn copies_but_the_switch(&mut self) -> Result<()> {
        let own_newer = |checked: Result<()>| match checked {
            Err(SignerError::Refused(Refusal::RecordsBehind { .. })) => Ok(()),
            checked => checked,
        };
        own_newer(self.check_named())?;
        own_newer(self.check_backup_copy().await)?;
        if let Some(newest) = self.state.newest_doc()? {
            own_newer(self.judge_homeserver(&newest).await.map(drop))?;
        }
        Ok(())
    }

    /// The operator's `404` after a request in doubt, at a run of the erasure: how a landed
    /// erasure looks, taken as one only once every check has met it for 24 hours, as an app
    /// takes an erasure (Switch wire 7.4.16, spec 12.7 step 5). `first_404_ms` is when a check
    /// first met it, kept durably in the flow.
    ///
    /// The time is the device clock's, the only one there is: the `404` carries no time
    /// anyone can authenticate. The wait ends at the first run 24 hours after the first `404`,
    /// so it takes two runs a day apart. A device clock set back below the first `404` starts
    /// the wait again from then; one set forward shortens it, and a jump of a day ends it at
    /// the next run, the user's own doing.
    async fn erased_after_doubt(
        &mut self,
        reminded: Vec<[u8; 16]>,
        first_404_ms: Option<u64>,
    ) -> Result<()> {
        let now = self.env.clock.now_ms();
        let since_ms = first_404_ms.filter(|at| *at <= now).unwrap_or(now);
        if now.saturating_sub(since_ms) >= ERASURE_CONFIRMATION_MS {
            return self.erased().await;
        }
        if first_404_ms != Some(since_ms) {
            let flow = Flow::Erase {
                unpublished: true,
                reminded,
                unanswered: true,
                first_404_ms: Some(since_ms),
            };
            self.commit(self.state.clone(), Some(flow)).await?;
        }
        Err(Refusal::ErasureUnconfirmed { since_ms }.into())
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
        let mut state = self.state.clone();
        withdraw_reminders(&mut state, reminded)?;
        self.commit(state, None).await
    }

    /// End the erasure in progress, if any, without erasing, in `state`, which the caller
    /// commits with no flow: as [`Signer::end_erasure`], when another install is found signing.
    /// Its newest version may be that install's now.
    pub(super) fn end_erasure_in(&self, state: &mut crate::state::SignerState) -> Result<()> {
        if let Some(Flow::Erase { reminded, .. }) = &self.flow {
            withdraw_reminders(state, reminded)?;
        }
        Ok(())
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
        // Each deletion only after a fresh check: another install may take over between two
        // of them, and its files are never this install's to delete. The first after the
        // full check, each later one after the switch's copy, where a take-over shows first.
        for (index, path) in std::iter::once(IDENTITY_PATH.to_owned())
            .chain(apps.iter().map(app_record_path))
            .enumerate()
        {
            // With no request in doubt, the check never takes the account as erased.
            self.still_erasing(false, index == 0).await?;
            self.env
                .homeserver
                .delete(&path)
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
            first_404_ms: None,
        };
        self.commit(state, Some(flow)).await
    }
}

/// Withdraw from `state` the grant reminders an erasure raised, `reminded`, for apps its newest
/// version still lists. A removed app's reminder stays: its grant's revocation is owed whether
/// or not the account is erased (Switch spec 12.2 step 1).
fn withdraw_reminders(state: &mut crate::state::SignerState, reminded: &[[u8; 16]]) -> Result<()> {
    let newest = state.newest_doc()?;
    let listed: Vec<[u8; 16]> = reminded
        .iter()
        .copied()
        .filter(|app| {
            newest
                .as_ref()
                .is_some_and(|doc| doc.listed_cert(app).is_some())
        })
        .collect();
    state.alerts.retain(
        |alert| !matches!(alert, Alert::GrantRevocationOwed { app_id } if listed.contains(app_id)),
    );
    state
        .grant_reminded
        .retain(|app_id| !listed.contains(app_id));
    Ok(())
}

/// How long every check must meet the operator's `404` after a request in doubt before the
/// erasure is taken as done: 24 hours, as for an app (Switch spec 12.7 step 5).
const ERASURE_CONFIRMATION_MS: u64 = 24 * 60 * 60 * 1000;

/// What a passing check before an erasure step found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Checked {
    /// This install still signs: the step goes on.
    Signing,
    /// The account is erased already: a request in doubt, then the switch's `404`, with no
    /// other install anywhere.
    ErasedAlready,
}
