//! The signer's two kinds of switch client, which the compiler keeps apart (Switch spec 4.3).
//!
//! A [`RequestClient`] signs nothing but its requests' `Switch-Signature`: it reads, and
//! delivers what the signing gate let sign already, a version, a batch or the enrollment. A
//! [`SigningClient`] is made from the gated key ([`crate::key::SigningKey`]): only it signs
//! operations, and a mutating signer-only call that signs nothing in its body, such as a
//! freeze, an unfreeze, an erasure or a hand-over, belongs on it. Each has only the calls its
//! kind may make. An [`AppClient`] is a new signer's, before it holds the identity key: it
//! fetches the hand-over and nothing else (Switch wire 7.4.17).

use std::sync::Arc;

use pubky_switch_client::client::answers::{
    AppsAnswer, HandoverStored, StoredHandover, WriteAnswer,
};
use pubky_switch_client::client::{Batch, Submitted};
use pubky_switch_client::{ClientError, Credentials, SwitchClient};
use pubky_switch_core::http::IdentityDelivery;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::ops::{Condition, OpKind, Position};
use pubky_switch_core::records::{AppCert, Enrollment, EnrollmentAnswer};
use pubky_switch_core::signing::Signs;

use super::SignerEnv;
use crate::error::{Refusal, Result, SignerError};
use crate::key::{IdentityKeyring, SigningKey};
use crate::state::SignerState;

/// Where a client of the identity goes: the switch's origin, its pinned service key if known,
/// and the identity.
pub(crate) struct Target<'a> {
    /// The switch's origin.
    pub(crate) origin: &'a str,
    /// The pinned service key; `None` before the enrollment answers.
    pub(crate) pinned: Option<[u8; 32]>,
    /// The identity.
    pub(crate) identity: [u8; 32],
}

/// A client for `target`, signing with `key` (Switch wire 7.2). Private: each client type
/// makes its own, from the key its kind may hold.
fn client(
    env: &SignerEnv,
    target: &Target<'_>,
    key: Arc<dyn Signs + Send + Sync>,
) -> Result<SwitchClient> {
    let credentials = Credentials::Signer {
        identity: target.identity,
        key,
    };
    client_with(env, target, credentials)
}

/// A client for `target` with `credentials`: the one place a switch client is made.
fn client_with(
    env: &SignerEnv,
    target: &Target<'_>,
    credentials: Credentials,
) -> Result<SwitchClient> {
    Ok(SwitchClient::new(
        target.origin,
        target.identity,
        credentials,
        target.pinned,
        Arc::clone(&env.transport),
        Arc::clone(&env.clock),
    )?)
}

/// That this install is the one named and its records aren't behind: only [`Named::check`]
/// makes one. A revocation at the switch takes it instead of the full signing gate, so an
/// app can be cut off while an alarm holds signing back, but never by an install that isn't
/// the signer (Switch spec 4.3, 12.2).
pub(crate) struct Named(());

impl Named {
    /// Check the records `state`.
    ///
    /// # Errors
    ///
    /// [`Refusal::Erased`] once the account is erased, [`SignerError::NotNamed`] while another
    /// install is the signer, and [`Refusal::RecordsBehind`] while the records are behind its
    /// own newer version.
    pub(crate) fn check(state: &SignerState) -> Result<Self> {
        if state.erased {
            return Err(Refusal::Erased.into());
        }
        if let Some(install) = state.managed_by {
            return Err(SignerError::NotNamed { install });
        }
        if let Some(version) = state.records_behind {
            return Err(Refusal::RecordsBehind { version }.into());
        }
        Ok(Self(()))
    }
}

/// A switch client whose credentials sign requests only.
pub(crate) struct RequestClient(SwitchClient);

impl RequestClient {
    /// A client for `target` whose credentials sign requests only
    /// ([`IdentityKeyring::request_signer`]).
    pub(crate) fn new(
        env: &SignerEnv,
        target: &Target<'_>,
        keyring: &IdentityKeyring,
    ) -> Result<Self> {
        Ok(Self(client(env, target, keyring.request_signer()?)?))
    }

    /// `GET /apps` (Switch wire 7.4.12).
    pub(crate) async fn apps(&self) -> std::result::Result<AppsAnswer, ClientError> {
        self.0.apps().await
    }

    /// `PUT /identity` (Switch wire 7.4.2): a version signed already.
    pub(crate) async fn put_identity(
        &self,
        delivery: &IdentityDelivery,
    ) -> std::result::Result<WriteAnswer, ClientError> {
        self.0.put_identity(delivery).await
    }

    /// `POST /ops` (Switch wire 6.4): a batch signed already, sent again with its bytes.
    pub(crate) async fn submit(
        &self,
        batch: &Batch,
    ) -> std::result::Result<Submitted, ClientError> {
        self.0.submit(batch).await
    }

    /// `POST /apps/{app_id}/revoke` (Switch wire 7.4.12): the one mutating signer-only call
    /// a request-only client makes, as this install is the one `named`. It signs nothing new,
    /// so it goes out also while an alarm holds signing back.
    pub(crate) async fn revoke(
        &self,
        _named: &Named,
        app_id: &[u8; 16],
    ) -> std::result::Result<WriteAnswer, ClientError> {
        self.0.revoke(app_id).await
    }

    /// `POST /v1/enroll` (Switch wire 7.4.1): the enrollment signed already.
    pub(crate) async fn enroll(
        &self,
        enrollment: &Enrollment,
    ) -> std::result::Result<EnrollmentAnswer, ClientError> {
        self.0.enroll(enrollment).await
    }
}

/// A switch client made from the gated key.
pub(crate) struct SigningClient(SwitchClient);

impl SigningClient {
    /// A client for `target` that signs with `key`, which only the signing gate hands out.
    pub(crate) fn new(env: &SignerEnv, target: &Target<'_>, key: &SigningKey) -> Result<Self> {
        Ok(Self(client(env, target, key.signer())?))
    }

    /// Sign `ops` as one batch at `generation` (Switch wire 6.4).
    pub(crate) fn sign_batch(
        &self,
        generation: u64,
        ops: Vec<(Vec<Condition>, OpKind)>,
        cursor: Option<Position>,
    ) -> std::result::Result<Batch, ClientError> {
        self.0.sign_batch(generation, ops, cursor)
    }

    /// `PUT /handover` (Switch wire 7.4.17): store the hand-over for its target app, sealed
    /// and signed already, and sent again with the same bytes.
    pub(crate) async fn put_handover(
        &self,
        stored: &StoredHandover,
    ) -> std::result::Result<HandoverStored, ClientError> {
        self.0.put_handover(stored).await
    }

    /// `POST /erase` (Switch wire 7.4.16): erase the identity's account, naming the pinned
    /// service key. Only the gated key's client sends it.
    pub(crate) async fn erase(&self) -> std::result::Result<(), ClientError> {
        self.0.erase().await
    }
}

/// A switch client with an app's credentials: a new signer's before it holds the identity
/// key. It fetches the hand-over held for it, and makes no other call.
pub(crate) struct AppClient(SwitchClient);

impl AppClient {
    /// A client for `target` with the credentials of the app whose keys are `keys` and whose
    /// certificate is `cert`.
    pub(crate) fn new(
        env: &SignerEnv,
        target: &Target<'_>,
        keys: &AppKeys,
        cert: &AppCert,
    ) -> Result<Self> {
        let credentials = Credentials::App {
            identity: target.identity,
            keys: keys.clone(),
            cert: cert.clone(),
        };
        Ok(Self(client_with(env, target, credentials)?))
    }

    /// `GET /handover` (Switch wire 7.4.17): the hand-over the switch holds for this app.
    pub(crate) async fn get_handover(&self) -> std::result::Result<StoredHandover, ClientError> {
        self.0.get_handover().await
    }
}
