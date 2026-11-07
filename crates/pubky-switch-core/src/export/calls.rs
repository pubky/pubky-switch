//! The export and import calls' bodies and their pure checks (Switch wire 10.3, 10.4, 10.5
//! and 10.6). The services keep the state these checks compare with and pass it in.

use serde_json::Value;

use super::manifest::{ChunkRef, Manifest};
use super::{bad, bad_signature, conflict, doc_refusal};
use crate::chain::SignedHead;
use crate::enc::{b64, unb64, unb64_array};
use crate::error::{Error, Result, invalid};
use crate::http::ErrorCode;
use crate::json::{MAX_INT, parse_json};
use crate::labels;
use crate::ops::Refusal;
use crate::ops::body::{Obj, carrying, string_array};
use crate::records::{ExportTransfer, Freeze, IdentityDoc, Inbox, Unfreeze};
use crate::sig::{self, SignedDoc};

/// Who calls `GET /export` or `GET /export/chunks/{chunk_id}` (Switch wire 10.3).
#[derive(Clone, Copy, Debug)]
pub enum ExportCaller<'a> {
    /// The signer, authenticated with the identity key.
    Signer,
    /// The next service, under the signer's export transfer, which the caller verified with
    /// the identity key, its request signature included (Switch wire 3.11, 7.2).
    NextService(&'a ExportTransfer),
    /// Any other caller.
    Other,
}

/// What the old service holds that the export calls' checks compare with (Switch wire 10.3).
#[derive(Clone, Copy, Debug)]
pub struct ExportRead<'a> {
    /// Who calls.
    pub caller: ExportCaller<'a>,
    /// The freeze the account is frozen with, `None` while it isn't frozen.
    pub frozen_with: Option<&'a Freeze>,
    /// Whether the service holds an `identity.json` for the account.
    pub has_identity: bool,
    /// This service's origin.
    pub origin: &'a str,
    /// The account's service key here.
    pub service_key: &'a [u8; 32],
}

impl ExportRead<'_> {
    fn check_account(&self) -> std::result::Result<(), Refusal> {
        if self.frozen_with.is_none() {
            return Err(conflict("Switch wire 10.3: the account isn't frozen"));
        }
        if !self.has_identity {
            return Err(Refusal::new(
                ErrorCode::NotFound,
                "Switch wire 10.3: no identity.json",
            ));
        }
        Ok(())
    }

    /// The checks of `GET /v1/{id}/export` (Switch wire 10.3): the signer only (`403
    /// permission_missing`), a frozen account (`409 conflict`) with an `identity.json` (`404`).
    ///
    /// # Errors
    ///
    /// As above.
    pub fn check_manifest(&self) -> std::result::Result<(), Refusal> {
        if !matches!(self.caller, ExportCaller::Signer) {
            return Err(Refusal::new(
                ErrorCode::PermissionMissing,
                "Switch wire 10.3: the export is the signer's",
            ));
        }
        self.check_account()
    }

    /// The checks of `GET /v1/{id}/export/chunks/{chunk_id}` (Switch wire 10.3): the signer
    /// or the next service under the export transfer (`403 permission_missing` for another
    /// caller); the checks of `GET /export`; a chunk the manifest lists (`404`); and for the
    /// next service, a transfer that names this export (Switch wire 3.11, `403
    /// not_admitted`). Returns the chunk's reference.
    ///
    /// # Errors
    ///
    /// As above.
    pub fn check_chunk<'m>(
        &self,
        manifest: &'m Manifest,
        chunk_id: &str,
    ) -> std::result::Result<&'m ChunkRef, Refusal> {
        if matches!(self.caller, ExportCaller::Other) {
            return Err(Refusal::new(
                ErrorCode::PermissionMissing,
                "Switch wire 10.3: the chunks are the signer's or the next service's",
            ));
        }
        self.check_account()?;
        let Some((_, chunk)) = manifest.chunk(chunk_id) else {
            return Err(Refusal::new(
                ErrorCode::NotFound,
                "Switch wire 10.3: the manifest doesn't list the chunk",
            ));
        };
        if let (ExportCaller::NextService(transfer), Some(freeze)) = (self.caller, self.frozen_with)
        {
            transfer
                .check_names(freeze, self.origin, self.service_key, &manifest.hash())
                .map_err(|e| Refusal::new(ErrorCode::NotAdmitted, super::reason(e)))?;
        }
        Ok(chunk)
    }
}

/// The answer of `GET /export/chunks/{chunk_id}` (Switch wire 10.3): `{ "id", "data" }`,
/// `data` the exact chunk bytes in base64url.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkAnswer {
    /// The chunk ID.
    pub id: String,
    /// The exact chunk bytes.
    pub data: Vec<u8>,
}

impl ChunkAnswer {
    /// The answer's JSON bytes.
    pub fn to_json(&self) -> Vec<u8> {
        let mut o = Obj::new();
        o.str("id", &self.id).str("data", &b64(&self.data));
        o.finish()
    }

    /// Read an answer.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if it doesn't read.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v: Value = parse_json(bytes)?;
        let text = |member: &str| {
            v.get(member).and_then(Value::as_str).ok_or_else(|| {
                Error::Invalid(format!("Switch wire 10.3: a chunk answer's {member}"))
            })
        };
        Ok(Self {
            id: text("id")?.to_owned(),
            data: unb64(text("data")?)?,
        })
    }
}

/// The body of `POST /v1/{id}/import` (Switch wire 10.4): the manifest, the signed freeze
/// and, optionally, the export transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportStart {
    /// The signed manifest.
    pub manifest: SignedDoc,
    /// The signed freeze.
    pub freeze: SignedDoc,
    /// The signed export transfer, if the next service is to fetch the chunks itself.
    pub transfer: Option<SignedDoc>,
}

/// What the next service holds that `POST /import` compares with (Switch wire 10.4).
pub struct StartChecks<'a> {
    /// The account's identity.
    pub identity: &'a [u8; 32],
    /// The `identity.json` the account was enrolled with, if any.
    pub held: Option<&'a IdentityDoc>,
    /// This service's origin.
    pub origin: &'a str,
    /// The account's service key here.
    pub service_key: &'a [u8; 32],
    /// Whether an abort here cancelled the freeze with this hash (Switch wire 10.6).
    pub cancelled: &'a dyn Fn(&[u8; 32]) -> bool,
    /// `max_import_bytes`.
    pub max_import_bytes: u64,
    /// The import in progress, if any.
    pub current: Option<CurrentImport>,
}

/// The import in progress at the next service, as step 4 of `POST /import` compares with it
/// (Switch wire 10.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentImport {
    /// Its manifest hash.
    pub manifest_hash: [u8; 32],
    /// Whether it is activated.
    pub activated: bool,
    /// The `issued_at` of the freeze it is bound to.
    pub freeze_issued_at: u64,
}

/// A start whose every check passed (Switch wire 10.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartedImport {
    /// The verified manifest.
    pub manifest: Manifest,
    /// The verified freeze.
    pub freeze: Freeze,
    /// The verified export transfer, if one came.
    pub transfer: Option<ExportTransfer>,
}

/// What `POST /import` does (Switch wire 10.4 step 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartDecision {
    /// The same manifest as the import in progress: answer with its status. A transfer that
    /// came with it, checked as step 7 checks one, replaces the one the import keeps.
    Status(Option<Box<ExportTransfer>>),
    /// A new import, or one bound to a newer freeze that replaces a partial import.
    Begin(Box<StartedImport>),
}

/// Step 4 of `POST /import` (Switch wire 10.4): the same manifest hash returns the import's
/// status; another manifest is refused while the import is activated or bound to a freeze
/// at least as new; a manifest bound to a newer freeze replaces a partial import. Returns
/// whether the start begins an import.
///
/// # Errors
///
/// `409 conflict` for a manifest the import in progress keeps out.
pub fn decide_start(
    current: Option<CurrentImport>,
    manifest_hash: &[u8; 32],
    freeze_issued_at: u64,
) -> std::result::Result<bool, Refusal> {
    match current {
        None => Ok(true),
        Some(c) if &c.manifest_hash == manifest_hash => Ok(false),
        Some(c) if c.activated || c.freeze_issued_at >= freeze_issued_at => Err(conflict(
            "Switch wire 10.4 step 4: another import is activated or bound to a freeze as new",
        )),
        Some(_) => Ok(true),
    }
}

impl ImportStart {
    /// The body's JSON bytes: `manifest`, `freeze` and, when present, `transfer`.
    pub fn to_json(&self) -> Vec<u8> {
        let mut o = Obj::new();
        o.raw("manifest", &carrying(&self.manifest))
            .raw("freeze", &carrying(&self.freeze));
        if let Some(transfer) = &self.transfer {
            o.raw("transfer", &carrying(transfer));
        }
        o.finish()
    }

    /// Read a body.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if it doesn't read.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v: Value = parse_json(bytes)?;
        let doc = |member: &str| -> Result<Option<SignedDoc>> {
            match v.get(member) {
                None | Some(Value::Null) => Ok(None),
                Some(d) => Ok(Some(serde_json::from_value(d.clone())?)),
            }
        };
        let (Some(manifest), Some(freeze)) = (doc("manifest")?, doc("freeze")?) else {
            return invalid("Switch wire 10.4: the start needs the manifest and the freeze");
        };
        Ok(Self {
            manifest,
            freeze,
            transfer: doc("transfer")?,
        })
    }

    /// The checks of `POST /import` after the caller's (step 1), in the order of Switch wire
    /// 10.4: the freeze verifies and names this identity, origin and key, and no abort here
    /// cancelled it (step 2); the manifest verifies with the service key of the held
    /// `identity.json` (step 3); the import in progress (step 4, [`decide_start`]); the
    /// manifest is bound to this move (step 5) and its chunk list well formed (step 6); and a
    /// transfer verifies and is for this move (step 7).
    ///
    /// # Errors
    ///
    /// `401 bad_signature`, `400 bad_request`, `409 conflict` or `413 too_large`, by the step
    /// that fails.
    pub fn check(&self, cx: &StartChecks<'_>) -> std::result::Result<StartDecision, Refusal> {
        let freeze = Freeze::verify(&self.freeze, cx.identity).map_err(doc_refusal)?;
        if freeze.next() != &Inbox::new(cx.origin, *cx.service_key) {
            return Err(bad(
                "Switch wire 10.4 step 2: the freeze names another service or key",
            ));
        }
        if (cx.cancelled)(&freeze.hash()) {
            return Err(conflict(
                "Switch wire 10.4 step 2: an abort here cancelled the freeze",
            ));
        }
        let Some(held) = cx.held else {
            return Err(conflict(
                "Switch wire 10.4 step 3: no identity.json to verify the manifest with",
            ));
        };
        let manifest = Manifest::verify(&self.manifest, &held.inbox().service_key, cx.identity)
            .map_err(doc_refusal)?;
        let begins = decide_start(cx.current, &manifest.hash(), freeze.body().issued_at)?;
        if begins {
            manifest.check_binding(cx.identity, &freeze, held)?;
            manifest.check_chunks(cx.max_import_bytes)?;
        }
        let transfer = self
            .transfer
            .as_ref()
            .map(|t| check_transfer(t, cx, &freeze, &manifest, held))
            .transpose()?;
        Ok(if begins {
            StartDecision::Begin(Box::new(StartedImport {
                manifest,
                freeze,
                transfer,
            }))
        } else {
            StartDecision::Status(transfer.map(Box::new))
        })
    }
}

/// Step 7 of `POST /import` (Switch wire 10.4): the transfer verifies with the identity key
/// (`401`), and names this move: the freeze's and the manifest's hashes, the old service as
/// the held `identity.json` names it, and this service and the account's key here (`400`).
fn check_transfer(
    signed: &SignedDoc,
    cx: &StartChecks<'_>,
    freeze: &Freeze,
    manifest: &Manifest,
    held: &IdentityDoc,
) -> std::result::Result<ExportTransfer, Refusal> {
    let transfer = ExportTransfer::verify(signed, cx.identity).map_err(doc_refusal)?;
    let b = transfer.body();
    if b.freeze_hash != freeze.hash()
        || b.manifest_hash != manifest.hash()
        || &b.from != held.inbox()
        || b.to != Inbox::new(cx.origin, *cx.service_key)
    {
        return Err(bad(
            "Switch wire 10.4 step 7: the transfer isn't for this move",
        ));
    }
    Ok(transfer)
}

/// The import status (Switch wire 10.4): the answer of `POST /import` and `PUT
/// /import/chunks`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportStatus {
    /// The manifest hash.
    pub manifest: [u8; 32],
    /// The number of chunks in the manifest.
    pub chunks: u64,
    /// The IDs of the chunks the next service doesn't hold yet, in manifest order.
    pub missing: Vec<String>,
    /// Whether the import is activated.
    pub activated: bool,
    /// How many chunks the next service fetched under the transfer.
    pub pulled: u64,
    /// Which chunk the last fetch stopped at and why, when it stopped.
    pub pull_error: Option<String>,
}

impl ImportStatus {
    /// The status's JSON bytes; `pull_error` only when present.
    pub fn to_json(&self) -> Vec<u8> {
        let mut o = Obj::new();
        o.str("manifest", &b64(&self.manifest))
            .int("chunks", self.chunks)
            .raw("missing", &string_array(&self.missing))
            .raw("activated", if self.activated { b"true" } else { b"false" })
            .int("pulled", self.pulled);
        if let Some(error) = &self.pull_error {
            o.str("pull_error", error);
        }
        o.finish()
    }

    /// Read a status.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if a member is missing or doesn't read.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v: Value = parse_json(bytes)?;
        let fail =
            |member: &str| Error::Invalid(format!("Switch wire 10.4: the status's {member}"));
        let int = |member: &str| {
            v.get(member)
                .and_then(Value::as_u64)
                .filter(|n| *n <= MAX_INT)
                .ok_or_else(|| fail(member))
        };
        let missing = v
            .get("missing")
            .and_then(Value::as_array)
            .ok_or_else(|| fail("missing"))?
            .iter()
            .map(|id| {
                id.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| fail("missing"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            manifest: v
                .get("manifest")
                .and_then(Value::as_str)
                .and_then(|m| unb64_array::<32>(m).ok())
                .ok_or_else(|| fail("manifest"))?,
            chunks: int("chunks")?,
            missing,
            activated: v
                .get("activated")
                .and_then(Value::as_bool)
                .ok_or_else(|| fail("activated"))?,
            pulled: int("pulled")?,
            pull_error: match v.get("pull_error") {
                None | Some(Value::Null) => None,
                Some(e) => Some(e.as_str().ok_or_else(|| fail("pull_error"))?.to_owned()),
            },
        })
    }
}

/// The body of `POST /v1/{id}/import/activate` (Switch wire 10.5): `{ "manifest" }`, the
/// manifest hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivateRequest {
    /// The manifest hash.
    pub manifest: [u8; 32],
}

impl ActivateRequest {
    /// The body's JSON bytes.
    pub fn to_json(&self) -> Vec<u8> {
        let mut o = Obj::new();
        o.str("manifest", &b64(&self.manifest));
        o.finish()
    }

    /// Read a body.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if it doesn't read.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v: Value = parse_json(bytes)?;
        let manifest = v
            .get("manifest")
            .and_then(Value::as_str)
            .and_then(|m| unb64_array::<32>(m).ok())
            .ok_or_else(|| Error::Invalid("Switch wire 10.5: manifest isn't b64(32)".into()))?;
        Ok(Self { manifest })
    }

    /// Step 1 of the activation (Switch wire 10.5): an import is in progress and is for this
    /// manifest.
    ///
    /// # Errors
    ///
    /// `409 conflict` otherwise.
    pub fn check(&self, current: Option<&[u8; 32]>) -> std::result::Result<(), Refusal> {
        if current != Some(&self.manifest) {
            return Err(conflict(
                "Switch wire 10.5 step 1: no import in progress for that manifest",
            ));
        }
        Ok(())
    }
}

/// The answer of `POST /import/activate` (Switch wire 10.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivateAnswer {
    /// The manifest hash.
    pub activated: [u8; 32],
    /// The last `seq` imported.
    pub imported: u64,
    /// The next service's head over the imported chain, under its own key (generation g).
    pub head: SignedHead,
}

impl ActivateAnswer {
    /// The answer's JSON bytes.
    pub fn to_json(&self) -> Vec<u8> {
        let mut o = Obj::new();
        o.str("activated", &b64(&self.activated))
            .int("imported", self.imported)
            .raw("head", &self.head.to_json());
        o.finish()
    }

    /// Read an answer.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if it doesn't read.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v: Value = parse_json(bytes)?;
        let fail =
            |member: &str| Error::Invalid(format!("Switch wire 10.5: the answer's {member}"));
        Ok(Self {
            activated: v
                .get("activated")
                .and_then(Value::as_str)
                .and_then(|m| unb64_array::<32>(m).ok())
                .ok_or_else(|| fail("activated"))?,
            imported: v
                .get("imported")
                .and_then(Value::as_u64)
                .filter(|n| *n <= MAX_INT)
                .ok_or_else(|| fail("imported"))?,
            head: SignedHead::from_value(v.get("head").ok_or_else(|| fail("head"))?)?,
        })
    }
}

/// The next service's checks of an abort, the unfreeze of Switch wire 3.6 sent to it first
/// (Switch wire 10.6): it verifies with the identity key and carries no discard answer
/// (`401 bad_signature`, `400`); the next service isn't named yet (`409 conflict`, the move is
/// published); and an import here belongs to the freeze it names (`409 conflict`). Returns
/// the freeze hash, which the discard answer signs ([`crate::records::DiscardAnswer`]).
///
/// - `named`: whether the next service holds an `identity.json` naming it.
/// - `import_freeze`: the hash of the freeze the import here is bound to, if any.
///
/// # Errors
///
/// As above.
pub fn check_abort_at_next(
    unfreeze: &Unfreeze,
    identity: &[u8; 32],
    named: bool,
    import_freeze: Option<&[u8; 32]>,
) -> std::result::Result<[u8; 32], Refusal> {
    sig::verify(
        identity,
        labels::sig::UNFREEZE,
        &[identity, &unfreeze.freeze_hash],
        &unfreeze.sig,
    )
    .map_err(|e| bad_signature(super::reason(e)))?;
    if unfreeze.discarded.is_some() {
        return Err(bad(
            "Switch wire 3.6: the unfreeze sent to the next service carries an answer",
        ));
    }
    if named {
        return Err(conflict(
            "Switch wire 10.6: the move is published, so it can't be cancelled here",
        ));
    }
    if import_freeze.is_some_and(|h| h != &unfreeze.freeze_hash) {
        return Err(conflict(
            "Switch wire 10.6: the import here belongs to another freeze",
        ));
    }
    Ok(unfreeze.freeze_hash)
}
