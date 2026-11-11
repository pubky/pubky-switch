//! What the parties of a flow share: a neutral protocol, and the step between a signer's
//! approval and an app's join that a host carries out.

use std::sync::Arc;

use pubky_switch_client::app::JoinRequest;
use pubky_switch_client::testing::{ProtocolSpec, TestProtocol};
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{
    AppRequest, AppRequestBody, ApprovalClaim, AuthRequest, app_record_path,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_signer::{ApprovedRequest, GrantPath, Protocol, ScopeDef};

use crate::HarnessError;

/// The scope of the [`Notes`] protocol, which has Shared Data Keys.
pub const NOTES: &str = "notes";

/// The message kind the notes apps accept.
pub const NOTE_KIND: &str = "example.note";

/// A protocol with one neutral scope, [`NOTES`], which has keys: the signer's side of it.
/// Its apps change the lists and write claims. They don't hold `lists.read`: an app that
/// does reads `GET /allow` when it joins, a call the flows don't cover yet.
#[derive(Clone, Copy, Debug, Default)]
pub struct Notes;

impl Protocol for Notes {
    fn name(&self) -> &str {
        "notes"
    }

    fn scopes(&self) -> Vec<ScopeDef> {
        vec![ScopeDef::keyed(NOTES)]
    }

    fn check_scopes(&self, _: &[&str]) -> Result<(), String> {
        Ok(())
    }

    fn permissions(&self, _: &[&str]) -> Vec<Permission> {
        vec![
            Permission::ClaimsRead,
            Permission::ClaimsWrite,
            Permission::ListsManage,
            Permission::ConversationAdd,
        ]
    }

    fn grant_paths(&self, _: &[u8; 16], _: &[&str]) -> Vec<GrantPath> {
        Vec::new()
    }
}

/// The app's side of the [`Notes`] protocol: a protocol that records what it receives.
pub fn notes_protocol() -> Arc<TestProtocol> {
    Arc::new(TestProtocol::new(ProtocolSpec {
        keyed_scopes: vec![NOTES.to_owned()],
        accepts: vec![NOTE_KIND.to_owned()],
        ..ProtocolSpec::default()
    }))
}

/// An app that asks to be approved: its keys, its request for the [`NOTES`] scope, and the
/// auth request the request binds (Switch wire 3.9).
#[derive(Clone, Debug)]
pub struct Asking {
    /// The app's keys.
    pub keys: AppKeys,
    /// The Pubky auth request its app request travels with.
    pub auth: AuthRequest,
    /// The app request.
    pub request: AppRequest,
}

impl Asking {
    /// The request of the app with `keys` for the [`NOTES`] scope and the grant of its own
    /// record's path.
    ///
    /// # Errors
    ///
    /// When the request doesn't sign.
    pub fn new(keys: AppKeys) -> Result<Self, HarnessError> {
        let auth = AuthRequest {
            client_id: "app.example".into(),
            client_key: [8; 32],
            caps: format!("{}:rw", app_record_path(&keys.app_id_bytes())),
            secret: [9; 32],
        };
        let body = AppRequestBody::new(&keys, vec![NOTES.to_owned()], &auth);
        let request = AppRequest::sign(&keys, body)
            .map_err(|error| HarnessError::Setup(error.to_string()))?;
        Ok(Self {
            keys,
            auth,
            request,
        })
    }

    /// What the app joins with once `identity`'s signer approved it: the host's step of
    /// reading the companion claim and checking its signature (Switch wire 3.10).
    ///
    /// # Errors
    ///
    /// When the claim doesn't read or verify.
    pub fn join_request(
        &self,
        identity: [u8; 32],
        approved: &ApprovedRequest,
    ) -> Result<JoinRequest, HarnessError> {
        let failed = |error: pubky_switch_core::Error| HarnessError::Setup(error.to_string());
        let claim = ApprovalClaim::from_plaintext(&approved.claim).map_err(failed)?;
        let approval = claim.verify(&identity, &self.auth).map_err(failed)?;
        Ok(JoinRequest {
            identity,
            keys: self.keys.clone(),
            request: self.request.clone(),
            approval: approval.to_vec(),
        })
    }
}
