//! Approving an app (Switch spec 3.2, 3.5, 12.1; Switch wire 3.9, 3.10).
//!
//! [`Signer::review`] checks an app request the way Switch wire 3.9 orders it and returns what
//! the user is shown. [`Signer::approve`] then signs everything at once, sign once:
//!
//! - the certificate, with the scopes asked for and the switch permissions the registered
//!   protocols' tables give them (Switch spec 3.2);
//! - the next `identity.json`, listing the app;
//! - the approval, holding the certificate, that document and the app's full key bundle
//!   sealed to its certified bundle key (Switch wire 3.10);
//! - its companion claim, bound to the auth request.
//!
//! It commits them together, then delivers and publishes the version as every version is
//! delivered. The claim is released to the host only once the switch has taken that version,
//! so a claim never names a document the switch refused. The auth request's secret is used to
//! sign the claim and isn't kept.
//!
//! A request from an app listed already, naming exactly the keys it is listed with, is a
//! renewal (Switch wire 3.9 step 5): [`AppReview::renews`] says so, for the user to see, and
//! [`Signer::approve`] renews the certificate with the scopes asked for, as [`Signer::renew`]
//! does (Switch wire 3.8). Its approval and claim hold the renewed certificate and the
//! renewing version, committed with it and released the same way. A listed App ID with
//! other keys is refused.
//!
//! # What the host does, in this order
//!
//! The relay and the Pubky grant are Pubky's transport, so they are the host's, through its
//! Pubky client.
//!
//! 1. **Review.** Call [`Signer::review`] with the app request and the auth request parsed from
//!    the app's `pubkyauth://` URL, and show the user the App ID, the scopes, the switch
//!    permissions, the capabilities and each grant path with what it is for (Switch spec
//!    12.1 step 1). A refusal ends the approval.
//! 2. **Approve.** On the user's yes, call [`Signer::approve`]. When it fails, the approval may
//!    still finish: call [`Signer::resume`] later, then [`Signer::approved`].
//! 3. **Deliver the claim.** Once [`Signer::approve`] or [`Signer::approved`] returns an
//!    [`ApprovedRequest`], deliver its `claim` bytes, exactly as given, to the auth request's
//!    relay as the companion claim under `x-pubky-switch-claim=pubky-switch.v1.approval`:
//!    encrypted with the auth secret to the claim's relay channel, as the companion claims
//!    spec says. They are already signed by the identity key; don't sign them again. When the
//!    delivery fails, deliver the same bytes again.
//! 4. **Approve the grant.** Only after the relay accepted the claim, approve the Pubky grant
//!    of the auth request, for exactly `caps`, which the review checked: the app's own paths
//!    and the grant paths shown. When the grant fails, try the grant again; the claim on the
//!    relay authorizes nothing by itself.
//! 5. **Report.** Call [`Signer::claim_delivered`], and the signer drops the claim.
//!
//! The host never:
//!
//! - approves the grant, or delivers anything, before [`Signer::approved`] returns the claim:
//!   until then the switch hasn't taken the version that lists the app;
//! - approves the grant before the claim is on the relay (the companion claims spec's order);
//! - grants capabilities other than `caps`, and above all one that covers `identity.json` or
//!   the signer's backup (Switch spec 3.4);
//! - delivers a claim [`Signer::approved`] doesn't return, such as the one of an approval whose
//!   delivery the switch refused;
//! - logs the claim, the auth URL or its secret.

use pubky_switch_core::records::{
    AppCert, AppCertBody, AppRequest, Approval, ApprovalClaim, Approve, AuthRequest, ListedApp,
    SignerView, check_app_request,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;

use super::Signer;
use super::renewal::{Answering, CertChange, clock_agrees};
use crate::alert::Alert;
use crate::error::{Refusal, Result, SignerError};
use crate::protocol::GrantPath;
use crate::state::PendingClaim;

/// An app request, checked, with what the user is shown before approving it (Switch spec
/// 12.1 step 1, Switch wire 3.9).
#[derive(Clone)]
pub struct AppReview {
    /// The App ID, derived from the request's signing key.
    pub app_id: [u8; 16],
    /// The scopes asked for.
    pub scopes: Vec<String>,
    /// The switch permissions the certificate will carry, from the registered protocols'
    /// tables (Switch spec 3.2).
    pub permissions: Vec<Permission>,
    /// The scopes that have Shared Data Keys, which the approval's key bundle carries.
    pub keyed: Vec<String>,
    /// The Pubky capabilities asked for, exactly as the auth request carries them.
    pub caps: String,
    /// The paths the protocols add to the app's grant, with what each is for.
    pub grant_paths: Vec<GrantPath>,
    /// The App ID is listed already, with exactly the keys this request names: approving it
    /// renews the app's certificate with the scopes asked for (Switch wire 3.9 step 5, 3.8).
    pub renews: bool,
    request: AppRequest,
    auth: AuthRequest,
}

impl std::fmt::Debug for AppReview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppReview")
            .field(
                "app_id",
                &pubky_switch_core::enc::zbase32_encode(&self.app_id),
            )
            .field("scopes", &self.scopes)
            .field("permissions", &self.permissions)
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

impl AppReview {
    /// The document hash of the app request.
    pub fn request_hash(&self) -> [u8; 32] {
        self.request.hash()
    }
}

/// An approval ready for the host to send: the companion claim to deliver to the auth
/// request's relay, then the Pubky grant to approve for `caps` (Switch wire 3.10).
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovedRequest {
    /// The document hash of the app request it answers.
    pub request: [u8; 32],
    /// The approved app.
    pub app_id: [u8; 16],
    /// The capabilities the Pubky grant covers, exactly as checked.
    pub caps: String,
    /// The companion claim's plaintext: the approval's JSON bytes, then the identity key's
    /// 64-byte signature, under the claim identifiers `x-pubky-switch-claim` and
    /// `pubky-switch.v1.approval`. The host encrypts it to the relay as the companion claims
    /// spec says; it holds no key a reader of the relay could use.
    pub claim: Vec<u8>,
}

impl std::fmt::Debug for ApprovedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovedRequest")
            .field(
                "app_id",
                &pubky_switch_core::enc::zbase32_encode(&self.app_id),
            )
            .field("caps", &self.caps)
            .field("claim_bytes", &self.claim.len())
            .finish_non_exhaustive()
    }
}

impl Signer {
    /// Check an app request and the auth request it travels with, in the order of Switch wire
    /// 3.9: the request verifies, its scopes follow the scope rule and are owned by registered
    /// protocols, whose own rules they pass (step 1); it binds the auth request (step 2); the
    /// capabilities are exactly the app's own paths and the paths its protocols add (step 3);
    /// the App ID was never revoked or removed (step 4), isn't listed, or is listed with
    /// exactly the keys the request names, which makes it a renewal ([`AppReview::renews`],
    /// step 5), and a new App ID fits the app limit (step 6).
    ///
    /// # Errors
    ///
    /// [`Refusal::Scopes`], [`Refusal::UnknownScopes`] or [`Refusal::ProtocolRule`] for the
    /// scopes; [`Refusal::AppRequest`] naming the step that failed, a listed App ID with other
    /// keys included; [`Refusal::NotSetUp`] before the first version.
    pub fn review(&self, request: &SignedDoc, auth: &AuthRequest) -> Result<AppReview> {
        let identity = self.state.identity;
        let verified = AppRequest::verify(request).map_err(refused)?;
        let body = verified.body();
        let terms = self.env.protocols.terms(&body.scopes)?;
        let grant_paths = self.env.protocols.grant_paths(&body.app_id, &body.scopes)?;
        let extra: Vec<&str> = grant_paths.iter().map(|p| p.path.as_str()).collect();
        let doc = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let listed = self
            .state
            .certs
            .iter()
            .map(|cert| AppCert::verify(cert, &identity))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let knows = |scope: &str| self.env.protocols.knows_scope(scope);
        let view = SignerView {
            revoked: &self.state.tombstones,
            identity: &doc,
            listed: &listed,
            app_limit: self.service()?.limits.app_limit,
            extra_paths: &extra,
            knows_scope: &knows,
        };
        let (request, approve) = check_app_request(request, auth, &view).map_err(refused)?;
        let body = request.body();
        Ok(AppReview {
            app_id: body.app_id,
            scopes: body.scopes.clone(),
            permissions: terms.permissions,
            keyed: terms.keyed,
            caps: body.caps.clone(),
            grant_paths,
            renews: approve == Approve::Renew,
            request: request.clone(),
            auth: auth.clone(),
        })
    }

    /// Approve a reviewed app request the user accepted (Switch spec 12.1 step 1): sign its
    /// certificate, the next `identity.json` listing it, the approval and its companion claim,
    /// commit them, then deliver and publish the version. Returns the claim for the host to
    /// send, once the switch has taken the version.
    ///
    /// The request is checked again first, against the records as they are now. A request
    /// that renews ([`AppReview::renews`]) is a renewal with the scopes asked for and the
    /// default lifetime, as [`Signer::renew`] makes it (Switch wire 3.8): `cert.put` and the
    /// full key bundle at the switch, then the renewing version. The approval answering it
    /// holds the renewed certificate and that version, and its claim is released the same way.
    ///
    /// # Errors
    ///
    /// As [`Signer::review`] and [`Signer::resume`]; for a renewal, as [`Signer::renew`]
    /// too: [`Refusal::NotJoined`] for an app that hasn't delivered its record yet, whose
    /// certificate the switch can't renew (Switch wire 6.2). When the delivery didn't finish, the
    /// claim stays held: [`Signer::approved`] gives it once a later [`Signer::resume`] has
    /// delivered the version.
    pub async fn approve(&mut self, review: AppReview) -> Result<ApprovedRequest> {
        let read = self.ready_and_read().await?;
        let review = self.review(review.request.signed(), &review.auth)?;
        if review.renews {
            let change = CertChange {
                scopes: Some(review.scopes.clone()),
                expires_at: None,
            };
            let answering = Answering {
                request: &review.request,
                auth: &review.auth,
                caps: &review.caps,
            };
            self.renew_listed(review.app_id, change, Some(&answering))
                .await?;
            return self.claim_of(&review.request.hash());
        }
        let identity = self.state.identity;
        let body = review.request.body();
        let now = self.env.clock.now_ms();
        // The certificate is stamped with the device clock: it must agree with the switch's
        // time, from the read that checked its copy.
        let switch_time = match read {
            Some(answer) => answer.server_time,
            None => self.switch_apps_at().await?.1,
        };
        clock_agrees(now, switch_time)?;
        let expires = now.saturating_add(self.state.cert_lifetime_ms);
        let protocols = self.env.protocols.clone();
        let has_keys = |scope: &str| protocols.has_keys(scope);
        let key = self.signing_key()?;
        let cert = AppCert::issue(
            &key,
            AppCertBody::new(
                identity,
                body.signing_key,
                body.bundle_key,
                body.scopes.clone(),
                &review.permissions,
                now,
                expires,
            ),
        )?;
        let listed = ListedApp {
            app_id: cert.app_id(),
            cert: cert.hash(),
        };
        let (doc, flow) = self.next_version(&key, |next| next.apps.push(listed))?;
        let approval =
            Approval::issue(&key, &review.request, cert.clone(), doc.clone(), &has_keys)?;
        let claim = ApprovalClaim::sign(&key, &review.auth, &approval)?;
        drop(key);
        let pending = PendingClaim {
            request: review.request.hash(),
            app_id: cert.app_id(),
            cert: cert.hash(),
            caps: review.caps.clone(),
            plaintext: claim.plaintext(),
        };
        let mut state = self.state.clone();
        state.signed_through = doc.version();
        state.certs.push(cert.signed().clone());
        state.claims.retain(|held| held.request != pending.request);
        state.claims.push(pending);
        self.commit(state, Some(flow)).await?;
        self.resume().await?;
        self.claim_of(&review.request.hash())
    }

    /// The claim of `request` once released, or why it is held.
    fn claim_of(&self, request: &[u8; 32]) -> Result<ApprovedRequest> {
        match self.approved(request)? {
            Some(approved) => Ok(approved),
            None => Err(Refusal::ClaimHeld {
                alert: self
                    .state
                    .alerts
                    .iter()
                    .rev()
                    .find(|a| matches!(a, Alert::Rollback { .. } | Alert::Equivocation { .. }))
                    .cloned(),
            }
            .into()),
        }
    }

    /// The claim of an approval whose version the switch has taken and the Homeserver
    /// publishes, until the host reports it delivered ([`Signer::claim_delivered`]): the
    /// version is delivered, published, then answered (Switch wire 3.9).
    ///
    /// `None` for a request this signer holds no claim for, or whose version isn't the newest
    /// published one listing its certificate; also while another install is the signer, and
    /// after a rollback or an equivocation until a delivery to the switch has succeeded again,
    /// since the switch may not hold that version ([`Signer::clear_alert`]).
    ///
    /// # Errors
    ///
    /// [`SignerError::InvalidData`] when the stored newest document no longer verifies.
    pub fn approved(&self, request: &[u8; 32]) -> Result<Option<ApprovedRequest>> {
        let Some(held) = self.state.claims.iter().find(|c| &c.request == request) else {
            return Ok(None);
        };
        if self.state.switch_unconfirmed
            || self.state.managed_by.is_some()
            || self.state.records_behind.is_some()
        {
            return Ok(None);
        }
        let published = self.state.newest.as_ref().is_some_and(|n| n.published);
        let delivered = published
            && self
                .state
                .newest_doc()?
                .is_some_and(|doc| doc.listed_cert(&held.app_id) == Some(held.cert));
        Ok(delivered.then(|| ApprovedRequest {
            request: held.request,
            app_id: held.app_id,
            caps: held.caps.clone(),
            claim: held.plaintext.clone(),
        }))
    }

    /// The certificates the newest version references, of its apps and of its `renewed`
    /// entries, verified: the ones the signer issued and keeps.
    ///
    /// # Errors
    ///
    /// [`SignerError::InvalidData`] when a stored certificate no longer verifies.
    pub fn certificates(&self) -> Result<Vec<AppCert>> {
        let identity = self.state.identity;
        Ok(self
            .state
            .certs
            .iter()
            .map(|cert| AppCert::verify(cert, &identity))
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// The host delivered the claim of `request` and approved its grant: the signer drops
    /// the claim.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn claim_delivered(&mut self, request: &[u8; 32]) -> Result<()> {
        self.refresh().await?;
        if !self.state.claims.iter().any(|c| &c.request == request) {
            return Ok(());
        }
        let mut state = self.state.clone();
        state.claims.retain(|held| &held.request != request);
        self.commit(state, self.flow.clone()).await
    }
}

/// A core check's failure, as the refusal of the app request.
fn refused(error: pubky_switch_core::Error) -> SignerError {
    Refusal::AppRequest(error.to_string()).into()
}
