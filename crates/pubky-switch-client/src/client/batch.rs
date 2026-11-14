//! Batches: signed once, resent byte for byte, and their answers bound to them (Switch wire
//! 2.1, 6.4, 6.5).

use pubky_switch_core::chain::{SignedHead, TransitionProof, bind_answer};
use pubky_switch_core::json::Doc;
use pubky_switch_core::ops::{
    Condition, Entry, MAX_BATCH_ENTRIES, OpKind, OpsRequest, Position, SignedOp, check_batch,
    random_batch_id, sign_batch,
};

use super::read::{self, Obj};
use super::{Auth, Body, Credentials, DynSigner, SwitchClient, verify_head};
use crate::error::ClientError;
use crate::transport::TimeoutClass;

/// A batch for `POST /v1/{id}/ops` (Switch wire 6.4): its signed operations, its cursor move
/// and the exact request body.
///
/// Its operations are signed once, when it is made, and the body is kept: a retry, the
/// binding of the answer and a batch read back from storage all use the very bytes sent, by
/// which the service recognizes a retry (Switch wire 2.1 "Sign once", 6.4 step 5). A host
/// that must survive a crash stores [`Batch::body`] before it first sends it and resumes with
/// [`Batch::from_body`].
#[derive(Clone, Debug, PartialEq)]
pub struct Batch {
    ops: Vec<SignedOp>,
    cursor: Option<Position>,
    body: Vec<u8>,
}

impl Batch {
    /// A batch of signed operations, then the cursor move if any.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for no entry, more than 8 entries with the cursor, or
    /// operations that break the batch rules (Switch wire 6.4 step 4).
    pub fn new(ops: Vec<SignedOp>, cursor: Option<Position>) -> Result<Self, ClientError> {
        let entries = ops.len().saturating_add(usize::from(cursor.is_some()));
        if !(1..=MAX_BATCH_ENTRIES).contains(&entries) {
            return Err(ClientError::Usage(
                "Switch wire 6.4: a batch has 1 to 8 entries".into(),
            ));
        }
        check_batch(&ops).map_err(|refusal| ClientError::Usage(refusal.to_string()))?;
        let body = OpsRequest::new(&ops, cursor).to_json();
        Ok(Self { ops, cursor, body })
    }

    /// A batch of only a cursor move: no batch ID, no `seq`, applied again on every retry
    /// (Switch wire 6.4).
    pub fn cursor_only(position: Position) -> Self {
        Self {
            ops: Vec::new(),
            cursor: Some(position),
            body: OpsRequest::new(&[], Some(position)).to_json(),
        }
    }

    /// A batch read back from the exact body it was first sent with, as a host resumes one
    /// after a restart. The operations are read, not verified; their bytes are the ones
    /// sent.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for a body that isn't a batch of Switch wire 6.4.
    pub fn from_body(body: Vec<u8>) -> Result<Self, ClientError> {
        let request =
            OpsRequest::parse(&body).map_err(|refusal| ClientError::Usage(refusal.to_string()))?;
        let mut ops = Vec::new();
        let mut cursor = None;
        for entry in &request.entries {
            match entry {
                Entry::Signed(signed) => ops.push(
                    SignedOp::peek(signed)
                        .map_err(|refusal| ClientError::Usage(refusal.to_string()))?,
                ),
                Entry::Cursor(position) => cursor = Some(*position),
            }
        }
        check_batch(&ops).map_err(|refusal| ClientError::Usage(refusal.to_string()))?;
        Ok(Self { ops, cursor, body })
    }

    /// The signed operations, in order.
    pub fn ops(&self) -> &[SignedOp] {
        &self.ops
    }

    /// The cursor move, if any.
    pub fn cursor(&self) -> Option<Position> {
        self.cursor
    }

    /// How long the batch's call may take: a batch that writes a shared record may be
    /// answered `409 conflict` with the record's view, up to about a mebibyte (Switch wire
    /// 7.6, 7.1 "Answer sizes"), on its first send and on every resend of the same bytes;
    /// any other batch's answer is small.
    pub(crate) fn timeout(&self) -> TimeoutClass {
        let writes_a_record = self
            .ops
            .iter()
            .any(|op| matches!(op.body().kind, OpKind::RecordPut(_)));
        if writes_a_record {
            TimeoutClass::Bulk
        } else {
            TimeoutClass::Ordinary
        }
    }

    /// The exact request body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The batch ID; `None` for a batch of only a cursor move.
    pub fn id(&self) -> Option<[u8; 16]> {
        self.ops.first().map(|op| op.body().batch.id)
    }
}

/// The verified answer of a batch (Switch wire 6.4, 6.5): one proof per signed operation, in
/// order, each bound to its operation, or none for an unchanged batch; and the newest head.
#[derive(Clone, Debug, PartialEq)]
pub struct Submitted {
    /// The transition proofs, verified with the pinned key and bound to the operations.
    pub proofs: Vec<TransitionProof>,
    /// The newest head, verified with the pinned key.
    pub head: SignedHead,
}

impl SwitchClient {
    /// Sign a batch with these credentials for the account's `generation`, with a fresh
    /// random batch ID (Switch wire 6.1, 6.4).
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for the next service's credentials, or at another identity's
    /// account; [`ClientError::Core`] when the generator fails or an operation can't be
    /// signed; otherwise as [`Batch::new`].
    pub fn sign_batch(
        &self,
        generation: u64,
        ops: Vec<(Vec<Condition>, OpKind)>,
        cursor: Option<Position>,
    ) -> Result<Batch, ClientError> {
        self.sign_batch_with_id(generation, random_batch_id()?, ops, cursor)
    }

    /// [`SwitchClient::sign_batch`] with a given batch ID.
    ///
    /// # Errors
    ///
    /// As [`SwitchClient::sign_batch`].
    pub fn sign_batch_with_id(
        &self,
        generation: u64,
        batch_id: [u8; 16],
        ops: Vec<(Vec<Condition>, OpKind)>,
        cursor: Option<Position>,
    ) -> Result<Batch, ClientError> {
        if self.is_foreign() {
            return Err(ClientError::Usage(
                "Switch wire 6.4: operations are written only at the caller's own account".into(),
            ));
        }
        let account = self.account();
        let signed = match self.credentials() {
            Credentials::App { keys, .. } => sign_batch(
                keys,
                &account,
                Some(keys.app_id_bytes()),
                generation,
                batch_id,
                ops,
            )?,
            Credentials::Signer { key, .. } => sign_batch(
                &DynSigner(key.as_ref()),
                &account,
                None,
                generation,
                batch_id,
                ops,
            )?,
            Credentials::NextService { .. } => {
                return Err(ClientError::Usage(
                    "the next service writes no operations".into(),
                ));
            }
        };
        Batch::new(signed, cursor)
    }

    /// `POST /v1/{id}/ops` (Switch wire 6.4): send the batch's exact body, then bind the
    /// answer to it with the pinned key (Switch wire 6.5 "Binding"). Sending the same batch
    /// again sends the same bytes, as a retry must.
    ///
    /// # Errors
    ///
    /// [`ClientError::Chain`] for proofs that don't bind the batch: missing, extra,
    /// reordered, of other operations, or not signed by the pinned key, and for a head the
    /// key didn't sign. Nothing in such an answer is acted on; as a signed contradiction it
    /// is misbehaviour (Switch spec 10.1). Otherwise as every call.
    pub async fn submit(&self, batch: &Batch) -> Result<Submitted, ClientError> {
        let key = self.pinned_key().ok_or(ClientError::Unpinned)?;
        self.submit_proved_by(batch, &key).await
    }

    /// [`SwitchClient::submit`], with the proofs checked with `proof_key`: the key of the
    /// generation a kept batch was signed for, whose original proofs a key change in place
    /// keeps and a resend returns (Switch wire 6.4 step 6). The head is checked with the
    /// pinned key.
    pub(crate) async fn submit_proved_by(
        &self,
        batch: &Batch,
        proof_key: &[u8; 32],
    ) -> Result<Submitted, ClientError> {
        let checked = self
            .call(
                "POST",
                &self.path("ops"),
                batch.body.clone(),
                Body::Json,
                Auth {
                    timeout: batch.timeout(),
                    ..Auth::default()
                },
            )
            .await?;
        let (value, what) =
            read::body(&checked.body, Doc::Plain, "Switch wire 6.4: a batch answer")?;
        let o = Obj::of(&value, what)?;
        let key = self.pinned_key().ok_or(ClientError::Unpinned)?;
        let head = o.head("head")?;
        verify_head(&head, &key, &self.account())?;
        let docs = o.required_each("proofs", read::doc)?;
        let proofs = bind_answer(&batch.ops, &docs, proof_key, &self.account())?;
        Ok(Submitted { proofs, head })
    }
}
