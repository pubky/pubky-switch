//! The state a transition proof shows for an operation (Switch wire 6.5).

use crate::chain::ProofState;
use crate::claims::ClaimView;
use crate::error::{Result, invalid};
use crate::shared::RecordState;

use super::{OpKind, RecordVersion};

/// The state after an operation that its proof shows, where the operation alone doesn't give
/// it (Switch wire 6.5).
#[derive(Clone, Debug, PartialEq)]
pub enum StateAfter {
    /// `record.put`: the record's new version, the write's (generation, `seq`).
    Record(RecordVersion),
    /// A claim entry: the claim's view after it, as [`crate::claims::Claim::view`] gives it.
    Claim(ClaimView),
    /// `app.put`: the calling app.
    App {
        /// Its App ID.
        app_id: [u8; 16],
    },
    /// `receive_key.put`: the receive key the app holds after it: the new one, or, for an
    /// unchanged put, the current one (Switch wire 6.4 "No-ops").
    ReceiveKey {
        /// The registration number.
        n: u64,
        /// The kid.
        kid: [u8; 8],
    },
    /// `key_bundle.put`: the `seq` the part is stored at: this operation's, or, for an
    /// unchanged part, the one it was stored at.
    KeyBundle {
        /// The stored part's `seq`.
        bundle_seq: u64,
    },
    /// Every other operation: its state follows from the operation alone.
    Op,
}

/// The state the proof of `op` shows, given the state after it (Switch wire 6.5).
///
/// # Errors
///
/// [`crate::Error::Invalid`] if `after` isn't the kind the operation needs, or a
/// `cert.put`'s certificate doesn't decode.
pub fn proof_state(op: &OpKind, after: &StateAfter) -> Result<ProofState> {
    Ok(match (op, after) {
        (OpKind::RecordPut(put), StateAfter::Record(version)) => {
            // The record the switch holds after the write decides `deleted`, so the proof
            // and the record can't disagree (Switch wire 6.2).
            let record = RecordState::after(put, version.generation, version.version);
            ProofState::Record {
                version: record.version,
                deleted: record.deleted,
            }
        }
        (OpKind::Claim(_), StateAfter::Claim(view)) => ProofState::Claim(view.to_value()),
        (OpKind::AllowPut { kind, .. }, StateAfter::Op) => ProofState::Allow {
            kind: *kind,
            present: true,
        },
        (OpKind::AllowDelete { kind, .. }, StateAfter::Op) => ProofState::Allow {
            kind: *kind,
            present: false,
        },
        (OpKind::DenyPut { .. }, StateAfter::Op) => ProofState::Deny { denied: true },
        (OpKind::DenyDelete { .. }, StateAfter::Op) => ProofState::Deny { denied: false },
        (OpKind::InviteCodePut(put), StateAfter::Op) => ProofState::InviteCodePut {
            max_uses: put.max_uses,
        },
        (OpKind::InviteCodeDelete { .. }, StateAfter::Op) => ProofState::InviteCodeDelete,
        (OpKind::AppPut { .. }, StateAfter::App { app_id }) => ProofState::App { app_id: *app_id },
        (OpKind::ReceiveKeyPut { .. }, StateAfter::ReceiveKey { n, kid }) => {
            ProofState::ReceiveKey { n: *n, kid: *kid }
        }
        (OpKind::KeyBundlePut(_), StateAfter::KeyBundle { bundle_seq }) => ProofState::KeyBundle {
            bundle_seq: *bundle_seq,
        },
        (OpKind::CertPut { cert, .. }, StateAfter::Op) => ProofState::Cert {
            cert: cert.doc_hash()?,
        },
        _ => return invalid("Switch wire 6.5: the state after doesn't fit the operation"),
    })
}
