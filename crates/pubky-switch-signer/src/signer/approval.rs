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
//! so a claim never names a document the switch refused. The host then delivers the claim to
//! the auth request's relay, and only after that approves the Pubky grant for exactly the
//! capabilities checked (`specs/pubky-auth-companion-claims.md`, Switch spec 3.4). The auth
//! request's secret is used to sign the claim and isn't kept.

use pubky_switch_core::records::{
    AppCert, AppCertBody, AppRequest, Approval, ApprovalClaim, Approve, AuthRequest, ListedApp,
    SignerView, check_app_request,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;

use super::Signer;
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
    /// the App ID was never revoked or removed (step 4), isn't listed (step 5), and fits the
    /// app limit (step 6).
    ///
    /// # Errors
    ///
    /// [`Refusal::Scopes`], [`Refusal::UnknownScopes`] or [`Refusal::ProtocolRule`] for the
    /// scopes; [`Refusal::AppRequest`] naming the step that failed; [`Refusal::AlreadyListed`]
    /// for an App ID listed with the same keys; [`Refusal::NotSetUp`] before the first version.
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
        if approve == Approve::Renew {
            return Err(Refusal::AlreadyListed.into());
        }
        let body = request.body();
        Ok(AppReview {
            app_id: body.app_id,
            scopes: body.scopes.clone(),
            permissions: terms.permissions,
            keyed: terms.keyed,
            caps: body.caps.clone(),
            grant_paths,
            request: request.clone(),
            auth: auth.clone(),
        })
    }

    /// Approve a reviewed app request the user accepted (Switch spec 12.1 step 1): sign its
    /// certificate, the next `identity.json` listing it, the approval and its companion claim,
    /// commit them, then deliver and publish the version. Returns the claim for the host to
    /// send, once the switch has taken the version.
    ///
    /// The request is checked again first, against the records as they are now.
    ///
    /// # Errors
    ///
    /// As [`Signer::review`] and [`Signer::resume`]. When the delivery didn't finish, the
    /// claim stays held: [`Signer::approved`] gives it once a later [`Signer::resume`] has
    /// delivered the version.
    pub async fn approve(&mut self, review: AppReview) -> Result<ApprovedRequest> {
        self.ready().await?;
        let review = self.review(review.request.signed(), &review.auth)?;
        let identity = self.state.identity;
        let body = review.request.body();
        let now = self.env.clock.now_ms();
        let expires = now.saturating_add(self.state.cert_lifetime_ms);
        let protocols = self.env.protocols.clone();
        let has_keys = |scope: &str| protocols.has_keys(scope);
        let key = self.keyring.unlock()?;
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
        self.approved(&review.request.hash())?
            .ok_or_else(|| SignerError::Records("the approved version isn't the newest".into()))
    }

    /// The claim of an approval whose version the switch has taken, until the host reports
    /// it delivered ([`Signer::claim_delivered`]); `None` for a request this signer holds no
    /// claim for, or whose version isn't delivered.
    ///
    /// # Errors
    ///
    /// [`SignerError::InvalidData`] when the stored newest document no longer verifies.
    pub fn approved(&self, request: &[u8; 32]) -> Result<Option<ApprovedRequest>> {
        let Some(held) = self.state.claims.iter().find(|c| &c.request == request) else {
            return Ok(None);
        };
        let delivered = self
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
