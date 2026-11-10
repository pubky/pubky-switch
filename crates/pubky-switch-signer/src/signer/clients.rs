//! The signer's two kinds of switch client, which the compiler keeps apart (Switch spec 4.3).
//!
//! A [`RequestClient`] signs nothing but its requests' `Switch-Signature`: it reads, and
//! delivers what the signing gate let sign already, a version, a batch or the enrollment. A
//! [`SigningClient`] is made from the gated key ([`crate::key::SigningKey`]): only it signs
//! operations, and a mutating signer-only call that signs nothing in its body, such as a
//! freeze, an unfreeze, an erasure or a hand-over, belongs on it. Each has only the calls its
//! kind may make.

use pubky_switch_client::client::answers::{AppsAnswer, WriteAnswer};
use pubky_switch_client::client::{Batch, Submitted};
use pubky_switch_client::{ClientError, SwitchClient};
use pubky_switch_core::http::IdentityDelivery;
use pubky_switch_core::ops::{Condition, OpKind, Position};
use pubky_switch_core::records::{Enrollment, EnrollmentAnswer};

/// A switch client whose credentials sign requests only.
pub(crate) struct RequestClient(pub(super) SwitchClient);

impl RequestClient {
    /// `GET /apps` (Switch wire 7.4.12).
    pub(crate) async fn apps(&self) -> Result<AppsAnswer, ClientError> {
        self.0.apps().await
    }

    /// `PUT /identity` (Switch wire 7.4.2): a version signed already.
    pub(crate) async fn put_identity(
        &self,
        delivery: &IdentityDelivery,
    ) -> Result<WriteAnswer, ClientError> {
        self.0.put_identity(delivery).await
    }

    /// `POST /ops` (Switch wire 6.4): a batch signed already, sent again with its bytes.
    pub(crate) async fn submit(&self, batch: &Batch) -> Result<Submitted, ClientError> {
        self.0.submit(batch).await
    }

    /// `POST /v1/enroll` (Switch wire 7.4.1): the enrollment signed already.
    pub(crate) async fn enroll(
        &self,
        enrollment: &Enrollment,
    ) -> Result<EnrollmentAnswer, ClientError> {
        self.0.enroll(enrollment).await
    }
}

/// A switch client made from the gated key.
pub(crate) struct SigningClient(pub(super) SwitchClient);

impl SigningClient {
    /// Sign `ops` as one batch at `generation` (Switch wire 6.4).
    pub(crate) fn sign_batch(
        &self,
        generation: u64,
        ops: Vec<(Vec<Condition>, OpKind)>,
        cursor: Option<Position>,
    ) -> Result<Batch, ClientError> {
        self.0.sign_batch(generation, ops, cursor)
    }
}
