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
//! 2. **Declines.** The user may decline any of [`AppReview::grant_paths`], the paths a
//!    protocol added to the grant that the app asks for. [`AppReview::decline`] takes the
//!    whole set the user declines and says at once whether the protocols allow it, with the
//!    rule's reason when they don't, such as two paths that go only together. The
//!    certificate, its scopes and keys are the same whatever is declined (Switch spec 3.4).
//!    For a request that renews a listed app ([`AppReview::renews`]), a decline only keeps
//!    the path out of this request's grant: a grant an earlier approval made still covers
//!    what it covered, until it expires or the app is revoked, so don't tell the user the
//!    path was taken away.
//! 3. **Approve.** On the user's yes, call [`Signer::approve`]. When it fails, the approval may
//!    still finish: call [`Signer::resume`] later, then [`Signer::approved`]. `approve` takes
//!    the review, and a fresh review declines nothing, so keep a clone of the review, or its
//!    [`AppReview::declined`] set to decline again, until the claim is released: when
//!    `approve` failed before it committed, [`Signer::approved`] gives nothing, and the host
//!    approves the kept review again.
//! 4. **Deliver the claim.** Once [`Signer::approve`] or [`Signer::approved`] returns an
//!    [`ApprovedRequest`], deliver its `claim` bytes, exactly as given, to the auth request's
//!    relay as the companion claim under `x-pubky-switch-claim=pubky-switch.v1.approval`:
//!    encrypted with the auth secret to the claim's relay channel, as the companion claims
//!    spec says. They are already signed by the identity key; don't sign them again. When the
//!    delivery fails, deliver the same bytes again. Deliver the claim by itself: a
//!    companion-claims helper that also approves the grant approves the auth request's own
//!    capabilities, the declined paths included. The grant is approved separately, at the
//!    next step.
//! 5. **Approve the grant.** Only after the relay accepted the claim, approve the Pubky grant
//!    of the auth request for exactly [`ApprovedRequest::caps`]: the capabilities the auth
//!    request asks for, less the paths the user declined. That can be fewer than the
//!    `pubkyauth://` URL names, so approve it with the Pubky SDK's
//!    `PubkySigner::approve_auth_with_capabilities`, never with `approve_auth`, which grants
//!    what the URL asks for, nor with a helper that delivers the claim and grants together.
//!    Pass it `ApprovedRequest::caps` parsed with `str::parse` into `pubky::Capabilities`,
//!    which keeps their order; `Capabilities::builder().finish()` would normalize them. When
//!    the grant fails, try the grant again; the claim on the relay authorizes nothing by
//!    itself.
//! 6. **Report.** Call [`Signer::claim_delivered`], and the signer drops the claim.
//!
//! The host never:
//!
//! - approves the grant, or delivers anything, before [`Signer::approved`] returns the claim:
//!   until then the switch hasn't taken the version that lists the app;
//! - approves the grant before the claim is on the relay (the companion claims spec's order);
//! - grants capabilities other than [`ApprovedRequest::caps`], such as the auth request's own,
//!   which still name the paths the user declined, and above all one that covers
//!   `identity.json` or the signer's backup (Switch spec 3.4);
//! - delivers a claim [`Signer::approved`] doesn't return, such as the one of an approval whose
//!   delivery the switch refused;
//! - logs the claim, the auth URL or its secret.
//!
//! The app learns which paths it holds from its Pubky session, which lists the capabilities
//! the Homeserver granted it (`PubkySession::info().capabilities()` in the Pubky SDK): a path
//! it asked for and lacks was declined (Switch wire 3.10). To ask for it again, the app sends
//! a new auth request naming it, which renews its certificate (Switch wire 3.9 step 5) and
//! can be declined again. A path a later request leaves out isn't declined: that grant covers
//! only what the request names (Switch spec 3.4).

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
use crate::protocol::{GrantPath, Protocols};
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
    /// The Pubky capabilities the auth request asks for, exactly as it carries them, to show
    /// the user. Never the capabilities to grant: those are [`ApprovedRequest::caps`], which
    /// leave out the paths the user declined.
    pub asked_caps: String,
    /// The paths the protocols added to the app's grant that the app asks for, with what each
    /// is for: the ones the user may decline ([`AppReview::decline`]).
    pub grant_paths: Vec<GrantPath>,
    /// The App ID is listed already, with exactly the keys this request names: approving it
    /// renews the app's certificate with the scopes asked for (Switch wire 3.9 step 5, 3.8).
    pub renews: bool,
    /// The paths the user declines, of `grant_paths`.
    declined: Vec<String>,
    request: AppRequest,
    auth: AuthRequest,
    protocols: Protocols,
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
            .field("asked_caps", &self.asked_caps)
            .field("declined", &self.declined)
            .finish_non_exhaustive()
    }
}

impl AppReview {
    /// The document hash of the app request.
    pub fn request_hash(&self) -> [u8; 32] {
        self.request.hash()
    }

    /// Set the paths the user declines to `paths`, in place of any set before, checked at
    /// once (Switch spec 3.4, Switch wire 3.9): each must be one of
    /// [`AppReview::grant_paths`], and the paths left must pass each protocol's rule on its
    /// grant paths. An empty set declines none. On a refusal the set stays as it was, so a
    /// host can try a set to learn whether it is allowed. [`Signer::approve`] grants the
    /// capabilities asked for less these paths, and issues the certificate as asked.
    ///
    /// At a request that renews the app ([`AppReview::renews`]), a decline keeps the path
    /// out of this request's grant only: a grant an earlier approval made stands until it
    /// expires or the app is revoked, so a decline takes nothing away.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotDeclinable`] for a path that isn't one of `grant_paths`, the app's record
    /// and backup paths included; [`Refusal::ProtocolRule`] with the protocol's reason when
    /// the paths left break its rule.
    pub fn decline(&mut self, paths: &[&str]) -> Result<()> {
        let mut declined: Vec<String> = Vec::new();
        for path in paths {
            if !self.grant_paths.iter().any(|p| p.path == *path) {
                return Err(Refusal::NotDeclinable {
                    path: (*path).to_owned(),
                }
                .into());
            }
            if !declined.iter().any(|d| d == path) {
                declined.push((*path).to_owned());
            }
        }
        let left: Vec<&str> = asked_paths(&self.asked_caps)
            .filter(|path| !declined.iter().any(|d| d == path))
            .collect();
        let body = self.request.body();
        self.protocols
            .check_grant_paths(&body.app_id, &body.scopes, &left)?;
        self.declined = declined;
        Ok(())
    }

    /// The paths the user declines, in the order they were given.
    pub fn declined(&self) -> &[String] {
        &self.declined
    }

    /// The capabilities to grant: those asked for, in their order, less the declined paths.
    fn granted_caps(&self) -> String {
        self.asked_caps
            .split(',')
            .filter(|cap| {
                let path = cap.strip_suffix(":rw").unwrap_or(cap);
                !self.declined.iter().any(|d| d == path)
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// The paths `caps` names, each `path:rw` joined by `,` (Switch wire 3.9 step 3).
fn asked_paths(caps: &str) -> impl Iterator<Item = &str> {
    caps.split(',')
        .map(|cap| cap.strip_suffix(":rw").unwrap_or(cap))
}

/// An approval ready for the host to send: the companion claim to deliver to the auth
/// request's relay, then the Pubky grant to approve for `caps` (Switch wire 3.10).
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovedRequest {
    /// The document hash of the app request it answers.
    pub request: [u8; 32],
    /// The approved app.
    pub app_id: [u8; 16],
    /// The capabilities to approve the Pubky grant for, and the only ones: those the auth
    /// request asks for, in its order, less the paths the user declined
    /// ([`AppReview::decline`]). They can be fewer than the auth request's own, so the host
    /// never grants those (see the module's host steps).
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
    /// step 5), and a new App ID fits the app limit (step 6). The grant paths it asks for
    /// pass their protocols' rules, and the review declines none of them.
    ///
    /// # Errors
    ///
    /// [`Refusal::Scopes`], [`Refusal::UnknownScopes`] or [`Refusal::ProtocolRule`] for the
    /// scopes, and [`Refusal::ProtocolRule`] for grant paths a protocol's rule refuses;
    /// [`Refusal::AppRequest`] naming the step that failed, a listed App ID with other
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
        let asked: Vec<&str> = asked_paths(&body.caps).collect();
        let grant_paths: Vec<GrantPath> = grant_paths
            .into_iter()
            .filter(|p| asked.contains(&p.path.as_str()))
            .collect();
        let protocols = self.env.protocols.clone();
        protocols.check_grant_paths(&body.app_id, &body.scopes, &asked)?;
        Ok(AppReview {
            app_id: body.app_id,
            scopes: body.scopes.clone(),
            permissions: terms.permissions,
            keyed: terms.keyed,
            asked_caps: body.caps.clone(),
            grant_paths,
            renews: approve == Approve::Renew,
            declined: Vec::new(),
            request: request.clone(),
            auth: auth.clone(),
            protocols,
        })
    }

    /// Approve a reviewed app request the user accepted (Switch spec 12.1 step 1): sign its
    /// certificate, the next `identity.json` listing it, the approval and its companion claim,
    /// commit them, then deliver and publish the version. Returns the claim for the host to
    /// send, once the switch has taken the version, with the capabilities to grant:
    /// [`ApprovedRequest::caps`], the ones asked for less the paths the user declined. The
    /// host grants those and no others, never [`AppReview::asked_caps`] or the auth request's.
    ///
    /// The request is checked again first, against the records as they are now, and the
    /// review's declines again with it. A request
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
        let declined = review.declined;
        let mut review = self.review(review.request.signed(), &review.auth)?;
        review.decline(&declined.iter().map(String::as_str).collect::<Vec<_>>())?;
        let caps = review.granted_caps();
        if review.renews {
            let change = CertChange {
                scopes: Some(review.scopes.clone()),
                expires_at: None,
            };
            let answering = Answering {
                request: &review.request,
                auth: &review.auth,
                caps: &caps,
            };
            // The user approved it: the count of untaken automatic renewals starts again.
            self.renew_listed(
                review.app_id,
                change,
                Some(&answering),
                super::renewal::RenewedBy::User,
            )
            .await?;
            return self.claim_of(&review.request.hash());
        }
        let identity = self.state.identity;
        let body = review.request.body();
        let now = self.env.clock.now_ms();
        // The certificate is stamped with the device clock: it must agree with the switch's
        // time, from the read that checked its copy, against the device clock when that
        // answer came, not after the backup and Homeserver reads since (Switch spec 10.1).
        let (device_ms, switch_time) = match read {
            Some(read) => (read.device_ms, read.answer.server_time),
            None => (now, self.switch_apps_at().await?.1),
        };
        clock_agrees(device_ms, switch_time)?;
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
            caps,
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

// The futures a host awaits here are `Send`, so a host can run them on a multi-threaded
// runtime: this stops compiling if one isn't.
#[allow(dead_code)]
fn approval_futures_are_send(signer: &mut Signer, review: AppReview, request: &[u8; 32]) {
    fn send<T: Send>(_: T) {}
    send(signer.approve(review));
    send(signer.claim_delivered(request));
}

/// A core check's failure, as the refusal of the app request.
fn refused(error: pubky_switch_core::Error) -> SignerError {
    Refusal::AppRequest(error.to_string()).into()
}
