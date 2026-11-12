//! The body of a recovery upload after a provider loss, and the checks of each uploaded item
//! (Switch wire 7.4.14): what the service and the scripted switch both merge.
//!
//! [`UploadBody::parse`] reads the body (`400` for one that doesn't read), and
//! [`UploadBody::check_permissions`] the caller's list permissions (`403` for the whole
//! upload). [`check_upload`] then judges every item, refusing none: an item that fails a
//! check is counted and left out, and what counted is returned for the merge.

use std::collections::{BTreeMap, HashMap};

use serde_json::Value;

use super::{EntryProof, UploadVersion, UploadedEntry, UploadedRecord, removed_app_counts};
use crate::chain::{ItemType, SignedHead, TransitionProof};
use crate::claims::{ClaimStatus, ClaimView};
use crate::http::ErrorCode;
use crate::ops::{
    OpKind, RecordPut, RecordVersion, Refusal, SignedOp, Writer, check_permission, check_shape,
};
use crate::records::{AppCert, IdentityDoc, RemovedApp};
use crate::scopes::Permission;
use crate::sig::SignedDoc;

/// An uploaded operation (Switch wire 7.4.14): the signed operation, its writer's
/// certificate, and the lost service's transition proof when the app kept it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadedOp {
    /// The signed operation, with its sealed value.
    pub op: SignedDoc,
    /// Its writer's certificate.
    pub cert: SignedDoc,
    /// The lost service's transition proof of it.
    pub proof: Option<SignedDoc>,
}

/// The `lists` of an upload. A member the body leaves out is `None`: `contacts`, an empty
/// array included, ends staged admission (Switch spec 12.6 step 2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UploadLists {
    /// Contacts.
    pub contacts: Option<Vec<[u8; 32]>>,
    /// Deny entries.
    pub deny: Option<Vec<[u8; 32]>>,
}

/// The body of `POST /recovery/upload` after a provider loss (Switch wire 7.4.14). A
/// missing member counts as empty, and `lists` as absent.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UploadBody {
    /// An `identity.json` of the lost generation.
    pub lost_identity: Option<SignedDoc>,
    /// `record.put` operations.
    pub records: Vec<UploadedOp>,
    /// Claim entries.
    pub claims: Vec<UploadedOp>,
    /// The lost service's heads.
    pub heads: Vec<SignedHead>,
    /// The lost service's transition proofs.
    pub proofs: Vec<SignedDoc>,
    /// The admission lists.
    pub lists: Option<UploadLists>,
}

fn malformed(why: &str) -> Refusal {
    Refusal::bad_request(format!("Switch wire 7.4.14: {why}"))
}

fn array<'a>(body: &'a Value, member: &str) -> Result<&'a [Value], Refusal> {
    match body.get(member) {
        None => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(malformed("a member isn't an array")),
    }
}

fn signed(value: &Value) -> Result<SignedDoc, Refusal> {
    SignedDoc::from_strict_value(value).map_err(|_| malformed("a signed document doesn't read"))
}

fn uploaded_op(value: &Value) -> Result<UploadedOp, Refusal> {
    crate::json::reject_unknown_members(value, &["op", "cert", "proof"], "an uploaded op")
        .map_err(|_| malformed("an uploaded op has another member"))?;
    let member = |name: &str| {
        value
            .get(name)
            .ok_or_else(|| malformed("an uploaded op lacks op or cert"))
    };
    Ok(UploadedOp {
        op: signed(member("op")?)?,
        cert: signed(member("cert")?)?,
        proof: value.get("proof").map(signed).transpose()?,
    })
}

fn pubkys(lists: &Value, member: &str) -> Result<Option<Vec<[u8; 32]>>, Refusal> {
    let Some(items) = lists.get(member) else {
        return Ok(None);
    };
    let Value::Array(items) = items else {
        return Err(malformed("a list isn't an array"));
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .and_then(|id| crate::enc::pubky_key(id).ok())
                .ok_or_else(|| malformed("a list entry isn't a Pubky ID"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

impl UploadBody {
    /// Read the body (Switch wire 7.4.14): every member optional, none other allowed.
    ///
    /// # Errors
    ///
    /// `400 bad_request` for a body that doesn't read as the table of Switch wire 7.4.14.
    pub fn parse(bytes: &[u8]) -> Result<Self, Refusal> {
        let body: Value =
            crate::json::parse_json(bytes).map_err(|_| malformed("the body isn't JSON"))?;
        if !body.is_object() {
            return Err(malformed("the body isn't an object"));
        }
        let members = [
            "lost_identity",
            "records",
            "claims",
            "heads",
            "proofs",
            "lists",
        ];
        crate::json::reject_unknown_members(&body, &members, "an upload")
            .map_err(|_| malformed("the body has another member"))?;
        let lists = match body.get("lists") {
            None => None,
            Some(lists) => {
                crate::json::reject_unknown_members(lists, &["contacts", "deny"], "lists")
                    .map_err(|_| malformed("lists has another member"))?;
                Some(UploadLists {
                    contacts: pubkys(lists, "contacts")?,
                    deny: pubkys(lists, "deny")?,
                })
            }
        };
        Ok(Self {
            lost_identity: body.get("lost_identity").map(signed).transpose()?,
            records: array(&body, "records")?
                .iter()
                .map(uploaded_op)
                .collect::<Result<_, _>>()?,
            claims: array(&body, "claims")?
                .iter()
                .map(uploaded_op)
                .collect::<Result<_, _>>()?,
            heads: array(&body, "heads")?
                .iter()
                .map(|head| {
                    SignedHead::from_value(head).map_err(|_| malformed("a head doesn't read"))
                })
                .collect::<Result<_, _>>()?,
            proofs: array(&body, "proofs")?
                .iter()
                .map(signed)
                .collect::<Result<_, _>>()?,
            lists,
        })
    }

    /// The caller's permission for its `lists` (Switch wire 7.4.14): `contacts` needs
    /// `lists.manage`, `deny` `lists.read` or `lists.manage`. The permission is the caller's,
    /// not an item's, so nothing of the upload merges without it.
    ///
    /// # Errors
    ///
    /// `403 permission_missing` for the whole upload.
    pub fn check_permissions(&self, caller: &AppCert) -> Result<(), Refusal> {
        let Some(lists) = &self.lists else {
            return Ok(());
        };
        let manage = caller.has_permission(Permission::ListsManage);
        let read = caller.has_permission(Permission::ListsRead);
        if lists.contacts.is_some() && !manage {
            return Err(Refusal::new(
                ErrorCode::PermissionMissing,
                "Switch wire 7.4.14: contacts need lists.manage",
            ));
        }
        if lists.deny.is_some() && !(manage || read) {
            return Err(Refusal::new(
                ErrorCode::PermissionMissing,
                "Switch wire 7.4.14: deny entries need lists.read or lists.manage",
            ));
        }
        Ok(())
    }

    /// Whether the upload ends staged admission once it is accepted: it carries `contacts`,
    /// an empty array included, from `caller`, which holds `lists.manage` (Switch spec 12.6
    /// step 2). A deny-only upload doesn't.
    pub fn ends_staged_admission(&self, caller: &AppCert) -> bool {
        self.lists.as_ref().is_some_and(|l| l.contacts.is_some())
            && caller.has_permission(Permission::ListsManage)
    }
}

/// What the account knows that an upload is checked against.
#[derive(Clone, Copy, Debug)]
pub struct UploadContext<'a> {
    /// The account's identity key.
    pub identity: &'a [u8; 32],
    /// The generation declared lost, the `recovery` transition's `recovery_from`.
    pub recovery_from: u64,
    /// The apps the account's newest `identity.json` lists as removed.
    pub removed: &'a [RemovedApp],
}

/// An uploaded `record.put` that counted.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedRecord {
    /// Its members.
    pub put: RecordPut,
    /// The signed operation.
    pub op: SignedDoc,
    /// The writer's certificate it came with.
    pub cert: SignedDoc,
    /// The App ID that signed it.
    pub writer: [u8; 16],
    /// How the merge compares it.
    pub uploaded: UploadedRecord,
}

/// What counted in an upload, and the counts of what didn't (Switch wire 7.4.14 "Answer").
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CheckedUpload {
    /// The record operations that counted, in upload order.
    pub records: Vec<CheckedRecord>,
    /// The claim entries that counted, by claim key.
    pub claims: BTreeMap<[u8; 32], Vec<UploadedEntry>>,
    /// The SETTLED claim views among the verified `proofs`, by claim key, the one at the
    /// highest step for each, with its proof's service time: each rebuilds the tombstone of
    /// an obligation the service holds nothing for.
    pub settled: BTreeMap<[u8; 32], (ClaimView, u64)>,
    /// Uploaded items that count for nothing.
    pub unverified: u64,
    /// Operations of removed apps that no proof dates before their `distrust_from`.
    pub distrusted: u64,
    /// The heads that verified.
    pub heads: u64,
    /// The `proofs` entries that verified: the transition's `proofs`.
    pub proofs: u64,
}

/// The lost generation's service key: the `inbox.service_key` of `lost_identity`, when it
/// verifies for the identity and is of the lost generation (Switch wire 7.4.14 "Members by
/// stage").
fn lost_key(body: &UploadBody, cx: &UploadContext<'_>) -> Option<[u8; 32]> {
    let doc = IdentityDoc::verify(body.lost_identity.as_ref()?, cx.identity).ok()?;
    (doc.body().generation == cx.recovery_from).then_some(doc.body().inbox.service_key)
}

/// The version a record proof gives `put`, an operation of `op_generation`: only one of the
/// operation's own generation and above its `expected_version`, as every service applies a
/// write (Switch wire 6.2 step 6). Any other counts as no proof.
pub fn proved_version(
    proof: &TransitionProof,
    op_generation: u64,
    built_on: RecordVersion,
) -> Option<RecordVersion> {
    let state = &proof.body().state;
    let version = RecordVersion::new(
        state.get("generation")?.as_u64()?,
        state.get("version")?.as_u64()?,
    );
    (version.generation == op_generation && version > built_on).then_some(version)
}

/// The writer's `distrust_from`, for an app `removed` lists.
fn distrust_from(removed: &[RemovedApp], writer: &[u8; 16]) -> Option<u64> {
    removed
        .iter()
        .find(|r| &r.app_id == writer)
        .map(|r| r.distrust_from)
}

/// An uploaded operation that verified for the identity, with its certificate (Switch wire
/// 7.4.14 `unverified`): its certificate verifies, the operation verifies with it, has a
/// shape every service takes (6.4 step 9), its certificate holds what its kind needs, and it
/// is of the lost generation or an earlier one. The caller checks its type.
fn verified_op(uploaded: &UploadedOp, cx: &UploadContext<'_>) -> Option<(SignedOp, AppCert)> {
    let cert = AppCert::verify(&uploaded.cert, cx.identity).ok()?;
    let op = SignedOp::verify_with_cert(&uploaded.op, &cert, cx.identity).ok()?;
    let body = op.body();
    let counts = check_shape(body).is_ok()
        && check_permission(&body.kind, Writer::App(&cert)).is_ok()
        && body.generation <= cx.recovery_from;
    counts.then_some((op, cert))
}

/// A proof that verifies with `key` and binds `op`.
fn bound_proof(
    signed: &SignedDoc,
    key: &[u8; 32],
    identity: &[u8; 32],
    op: &SignedOp,
) -> Option<TransitionProof> {
    let proof = TransitionProof::verify(signed, key, identity).ok()?;
    proof.check_binds(op).is_ok().then_some(proof)
}

/// Judge every item of `body` (Switch wire 7.4.14): what counted for the merge, and the
/// counts of what didn't. Nothing here is refused.
pub fn check_upload(body: &UploadBody, cx: &UploadContext<'_>) -> CheckedUpload {
    let mut out = CheckedUpload::default();
    let key = lost_key(body, cx);
    // Heads and `proofs` entries count only with the lost generation's key.
    let mut proofs_by_item: HashMap<[u8; 32], TransitionProof> = HashMap::new();
    for head in &body.heads {
        if key.is_some_and(|key| head.verify(&key, cx.identity).is_ok()) {
            out.heads += 1;
        } else {
            out.unverified += 1;
        }
    }
    for signed in &body.proofs {
        let Some(proof) =
            key.and_then(|key| TransitionProof::verify(signed, &key, cx.identity).ok())
        else {
            out.unverified += 1;
            continue;
        };
        out.proofs += 1;
        if proof.envelope().item_type != ItemType::Op {
            continue;
        }
        if let Ok(view) = ClaimView::from_value(&proof.body().state)
            && view.status == ClaimStatus::Settled
        {
            let at = proof.envelope().server_time;
            let newer = out
                .settled
                .get(&view.claim_key)
                .is_none_or(|(held, _)| view.step > held.step);
            if newer {
                out.settled.insert(view.claim_key, (view, at));
            }
        }
        proofs_by_item.insert(proof.envelope().item_hash, proof);
    }

    for uploaded in &body.records {
        let Some((op, cert)) = verified_op(uploaded, cx) else {
            out.unverified += 1;
            continue;
        };
        let OpKind::RecordPut(put) = &op.body().kind else {
            out.unverified += 1;
            continue;
        };
        let generation = op.body().generation;
        // An operation built on a later generation than its own no service applies.
        let (Some(bound), Ok(op_hash), Ok(item)) = (
            UploadVersion::bound(generation, put.expected_version),
            uploaded.op.doc_hash(),
            op.item_hash(),
        ) else {
            out.unverified += 1;
            continue;
        };
        let proof = key.and_then(|key| {
            uploaded
                .proof
                .as_ref()
                .and_then(|signed| bound_proof(signed, &key, cx.identity, &op))
                .or_else(|| {
                    proofs_by_item
                        .get(&item)
                        .filter(|proof| proof.check_binds(&op).is_ok())
                        .cloned()
                })
                .and_then(|proof| {
                    let version = proved_version(&proof, generation, put.expected_version)?;
                    Some((version, proof.envelope().server_time))
                })
        });
        let writer = cert.app_id();
        if let Some(from) = distrust_from(cx.removed, &writer)
            && !removed_app_counts(proof.map(|(_, at)| at), from)
        {
            out.distrusted += 1;
            continue;
        }
        out.records.push(CheckedRecord {
            put: put.clone(),
            op: uploaded.op.clone(),
            cert: uploaded.cert.clone(),
            writer,
            uploaded: UploadedRecord {
                op_hash,
                built_on: put.expected_version,
                version: proof.map_or(bound, |(version, _)| UploadVersion::proved(version)),
            },
        });
    }

    for uploaded in &body.claims {
        let Some((op, cert)) = verified_op(uploaded, cx) else {
            out.unverified += 1;
            continue;
        };
        let OpKind::Claim(fields) = &op.body().kind else {
            out.unverified += 1;
            continue;
        };
        let Ok(entry) = fields.check() else {
            out.unverified += 1;
            continue;
        };
        let proof = key
            .zip(uploaded.proof.as_ref())
            .and_then(|(key, signed)| bound_proof(signed, &key, cx.identity, &op))
            .and_then(|proof| {
                Some(EntryProof {
                    at: proof.envelope().server_time,
                    view: ClaimView::from_value(&proof.body().state).ok()?,
                })
            });
        let writer = cert.app_id();
        if let Some(from) = distrust_from(cx.removed, &writer)
            && !removed_app_counts(proof.as_ref().map(|p| p.at), from)
        {
            out.distrusted += 1;
            continue;
        }
        out.claims
            .entry(entry.claim_key)
            .or_default()
            .push(UploadedEntry {
                entry,
                writer,
                proof,
            });
    }
    out
}

#[cfg(test)]
mod tests;
