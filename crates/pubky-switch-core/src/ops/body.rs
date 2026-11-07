//! Operation bodies (Switch wire 6.1, 6.2, 6.3): their members, written in the wire format's
//! order and read strictly.

use serde_json::Value;

use super::Refusal;
use super::read::{
    app_id, nullable_time, only, opt, req, req_app_id, req_b64, req_b64n, req_int, req_pubky,
    req_str, req_time, text,
};
use crate::claims::ClaimFields;
use crate::enc::{app_id_bytes, b64, lp, pubky_id, zbase32_encode};
use crate::error::{Error, Result, invalid};
use crate::ident::Policy;
use crate::json::{Doc, parse_json_as};
use crate::labels;
use crate::records::KeyBundle;
use crate::sealed::SealedValue;
use crate::sig::SignedDoc;
use crate::signing::Signs;
use crate::time::rfc3339;

/// The largest signed operation, in its compact carrying form: 512 KiB, else `413 too_large`
/// (Switch wire 6.1, 6.4 step 2).
pub const MAX_OP_BYTES: usize = 524_288;

/// The bytes a signed operation takes in its compact carrying form `{"body":"<body>",
/// "sig":"<sig>"}` without whitespace: 20 bytes plus its two base64url texts (Switch wire
/// 6.1), whatever whitespace or escapes the request itself uses.
pub fn carrying_len(body_b64: &str, sig_b64: &str) -> usize {
    r#"{"body":"","sig":""}"#.len().saturating_add(body_b64.len()).saturating_add(sig_b64.len())
}

/// A compact JSON object written member by member, in the order the writer gives, so that
/// the bytes follow the wire format's tables (Switch wire 1.1).
pub(crate) struct Obj {
    out: Vec<u8>,
    first: bool,
}

/// A JSON string, escaped as JSON escapes it.
pub(crate) fn quote(text: &str) -> String {
    Value::String(text.to_owned()).to_string()
}

impl Obj {
    /// An empty object.
    pub(crate) fn new() -> Self {
        Self {
            out: vec![b'{'],
            first: true,
        }
    }

    fn key(&mut self, name: &str) {
        if !self.first {
            self.out.push(b',');
        }
        self.first = false;
        self.out.extend_from_slice(quote(name).as_bytes());
        self.out.push(b':');
    }

    /// A string member.
    pub(crate) fn str(&mut self, name: &str, value: &str) -> &mut Self {
        self.key(name);
        self.out.extend_from_slice(quote(value).as_bytes());
        self
    }

    /// An integer member.
    pub(crate) fn int(&mut self, name: &str, value: u64) -> &mut Self {
        self.key(name);
        self.out.extend_from_slice(value.to_string().as_bytes());
        self
    }

    /// A `null` member.
    pub(crate) fn null(&mut self, name: &str) -> &mut Self {
        self.key(name);
        self.out.extend_from_slice(b"null");
        self
    }

    /// A member whose value is JSON text already written.
    pub(crate) fn raw(&mut self, name: &str, json: &[u8]) -> &mut Self {
        self.key(name);
        self.out.extend_from_slice(json);
        self
    }

    /// The object's bytes.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        self.out.push(b'}');
        self.out
    }
}

/// A JSON array of values already written.
pub(crate) fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![b'['];
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(item);
    }
    out.push(b']');
    out
}

/// A JSON array of strings.
pub(crate) fn string_array(items: &[String]) -> Vec<u8> {
    let quoted: Vec<Vec<u8>> = items.iter().map(|s| quote(s).into_bytes()).collect();
    array(&quoted)
}

/// A signed document's carrying form `{"body":...,"sig":...}` (Switch wire 2.2).
pub(crate) fn carrying(doc: &SignedDoc) -> Vec<u8> {
    let mut o = Obj::new();
    o.str("body", &doc.body).str("sig", &doc.sig);
    o.finish()
}

/// A record version (Switch wire 1.7, 6.2): the (generation, `seq`) of the write that
/// produced it, given by the service. Versions are ordered by generation, then `seq`, so they
/// only grow across the account, whoever writes. `{0, 0}` names no record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordVersion {
    /// The generation of the write.
    pub generation: u64,
    /// The `seq` of the write in its generation.
    pub version: u64,
}

impl RecordVersion {
    /// `{0, 0}`: no record, as a create's `expected_version` names it.
    pub const NONE: RecordVersion = RecordVersion {
        generation: 0,
        version: 0,
    };

    /// The version `(generation, version)`.
    pub fn new(generation: u64, version: u64) -> Self {
        Self {
            generation,
            version,
        }
    }

    /// Whether this is `{0, 0}`.
    pub fn is_none(&self) -> bool {
        *self == Self::NONE
    }

    pub(crate) fn to_json(self) -> Vec<u8> {
        let mut o = Obj::new();
        o.int("generation", self.generation)
            .int("version", self.version);
        o.finish()
    }

    fn read(value: &Value, what: &str) -> Result<Self> {
        only(value, &["generation", "version"], what)?;
        Ok(Self {
            generation: req_int(value, "generation", what)?,
            version: req_int(value, "version", what)?,
        })
    }
}

/// The batch an operation names: its random ID and the number of signed operations in it,
/// the same in every operation of the batch (Switch wire 6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BatchRef {
    /// The batch ID, 16 random bytes.
    pub id: [u8; 16],
    /// The number of signed operations in the batch; `cursor.set` isn't counted.
    pub count: u64,
}

impl BatchRef {
    fn to_json(self) -> Vec<u8> {
        let mut o = Obj::new();
        o.str("id", &b64(&self.id)).int("count", self.count);
        o.finish()
    }

    fn read(value: &Value) -> Result<Self> {
        let what = "batch";
        only(value, &["id", "count"], what)?;
        Ok(Self {
            id: req_b64n::<16>(value, "id", what)?,
            count: req_int(value, "count", what)?,
        })
    }
}

/// A condition, checked against the state before the batch (Switch wire 6.3, Switch spec
/// 10.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    /// The record's current version is `version`; a record that doesn't exist, or whose key
    /// the service forgot, is at version 0, and `version: 0` holds only then.
    RecordVersion {
        /// The record key.
        key: [u8; 32],
        /// The version named.
        version: RecordVersion,
    },
    /// The claim's step is `step`, 0 when the service holds nothing for it.
    ClaimStep {
        /// The claim key.
        claim_key: [u8; 32],
        /// The step named.
        step: u64,
    },
    /// The service's time when it applies the batch is in `[start, end)`; a `None` bound is
    /// open.
    ServerTimeIn {
        /// The first instant, in Unix milliseconds.
        start: Option<u64>,
        /// The first instant after the range, in Unix milliseconds.
        end: Option<u64>,
    },
}

impl Condition {
    pub(crate) fn to_json(self) -> Vec<u8> {
        let mut outer = Obj::new();
        match self {
            Condition::RecordVersion { key, version } => {
                let mut o = Obj::new();
                o.str("key", &b64(&key))
                    .int("generation", version.generation)
                    .int("version", version.version);
                outer.raw("record_version", &o.finish());
            }
            Condition::ClaimStep { claim_key, step } => {
                let mut o = Obj::new();
                o.str("claim_key", &b64(&claim_key)).int("step", step);
                outer.raw("claim_step", &o.finish());
            }
            Condition::ServerTimeIn { start, end } => {
                let mut o = Obj::new();
                for (name, bound) in [("start", start), ("end", end)] {
                    match bound {
                        Some(ms) => o.str(name, &rfc3339(ms)),
                        None => o.null(name),
                    };
                }
                outer.raw("server_time_in", &o.finish());
            }
        }
        outer.finish()
    }

    /// Read one condition: an object with one member, whose inner object has only that
    /// condition's members (Switch wire 1.1, 6.3).
    fn read(value: &Value) -> Result<Self> {
        let what = "a condition";
        only(
            value,
            &["record_version", "claim_step", "server_time_in"],
            what,
        )?;
        let Some(object) = value.as_object() else {
            return invalid("Switch wire 6.3: a condition isn't an object");
        };
        if object.len() != 1 {
            return invalid("Switch wire 6.3: a condition has exactly one member");
        }
        if let Some(inner) = value.get("record_version") {
            let what = "record_version";
            only(inner, &["key", "generation", "version"], what)?;
            return Ok(Condition::RecordVersion {
                key: req_b64n::<32>(inner, "key", what)?,
                version: RecordVersion::new(
                    req_int(inner, "generation", what)?,
                    req_int(inner, "version", what)?,
                ),
            });
        }
        if let Some(inner) = value.get("claim_step") {
            let what = "claim_step";
            only(inner, &["claim_key", "step"], what)?;
            return Ok(Condition::ClaimStep {
                claim_key: req_b64n::<32>(inner, "claim_key", what)?,
                step: req_int(inner, "step", what)?,
            });
        }
        let inner = req(value, "server_time_in", what)?;
        let what = "server_time_in";
        only(inner, &["start", "end"], what)?;
        Ok(Condition::ServerTimeIn {
            start: nullable_time(inner, "start", what)?,
            end: nullable_time(inner, "end", what)?,
        })
    }
}

/// The kind of an allowlist entry (Switch spec 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AllowKind {
    /// `contact`: added and removed with `lists.manage`.
    Contact,
    /// `conversation`: added with `conversation.add`, removed with `lists.manage`.
    Conversation,
}

impl AllowKind {
    /// The kind as the wire writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            AllowKind::Contact => "contact",
            AllowKind::Conversation => "conversation",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "contact" => Ok(AllowKind::Contact),
            "conversation" => Ok(AllowKind::Conversation),
            _ => invalid("Switch wire 6.2: allow kind isn't contact or conversation"),
        }
    }
}

/// The blinded inputs a creating `record.put` carries, from which the service recomputes the
/// record key (Switch wire 1.5, 6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdInputs {
    /// The collection name, a protocol's opaque string.
    pub collection: String,
    /// The blinded natural key, `blind(natural key)`.
    pub blinded_key: [u8; 32],
}

/// The members of a `record.put` (Switch wire 6.2, Switch spec 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordPut {
    /// The record key (Switch wire 1.5).
    pub key: [u8; 32],
    /// The collection ID (Switch wire 1.5), not the name.
    pub collection: [u8; 32],
    /// The policy: `read_scope` and `write_scopes`, fixed at creation.
    pub policy: Policy,
    /// The version the writer read, or `{0, 0}` to create.
    pub expected_version: RecordVersion,
    /// The sealed value; a sealed empty plaintext is a delete.
    pub value_sealed: SealedValue,
    /// The blinded inputs of the key, on a create, and only then.
    pub id_inputs: Option<IdInputs>,
}

/// The members of an `invite_code.put` (Switch wire 6.2, Switch spec 7).
#[derive(Clone, Debug, PartialEq)]
pub struct InviteCodePut {
    /// `hash(code bytes)` (Switch wire 1.7).
    pub code_hash: [u8; 32],
    /// When the code expires, in Unix milliseconds.
    pub expires_at: u64,
    /// How many appends the code admits.
    pub max_uses: u64,
    /// Any JSON: an opaque reference the service stores and shows in the clear, never
    /// personal data (Switch spec 7, 15).
    pub context: Value,
}

/// The carrying form of a key bundle inside an operation body (Switch wire 3.5, 6.2):
/// `{ "envelope", "sig" }`, written in that order.
fn key_bundle_json(bundle: &KeyBundle) -> Vec<u8> {
    let mut o = Obj::new();
    o.str("envelope", &b64(bundle.envelope()))
        .str("sig", &b64(&bundle.sig()));
    o.finish()
}

/// Read a key bundle's carrying form inside an operation body, refusing unknown members
/// (Switch wire 1.1, 6.1): unlike a key bundle read elsewhere, the form in a signed operation
/// is strict.
fn read_key_bundle(value: &Value) -> Result<KeyBundle> {
    let what = "bundle";
    only(value, &["envelope", "sig"], what)?;
    Ok(KeyBundle::from_parts(
        req_b64(value, "envelope", what)?,
        req_b64n::<64>(value, "sig", what)?,
    ))
}

/// The members of a `key_bundle.put` (Switch wire 6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBundlePut {
    /// The app the bundle is for.
    pub target_app_id: [u8; 16],
    /// The bundle, or one part of it, as it travels (Switch wire 3.5).
    pub bundle: KeyBundle,
    /// The first data epoch the sealed bundle holds, repeated in the clear.
    pub first_epoch: u64,
    /// The last data epoch the sealed bundle holds, repeated in the clear.
    pub last_epoch: u64,
}

/// An operation's type and the members of that type (Switch wire 6.2).
#[derive(Clone, Debug, PartialEq)]
pub enum OpKind {
    /// `claim` (Switch spec 10.2): a claim entry.
    Claim(ClaimFields),
    /// `record.put` (Switch spec 10.3): a shared record write.
    RecordPut(RecordPut),
    /// `allow.put`: add a contact or conversation entry.
    AllowPut {
        /// The Pubky ID allowed.
        pubky: [u8; 32],
        /// The entry's kind.
        kind: AllowKind,
    },
    /// `allow.delete`: remove a contact or conversation entry.
    AllowDelete {
        /// The Pubky ID removed.
        pubky: [u8; 32],
        /// The entry's kind.
        kind: AllowKind,
    },
    /// `deny.put`: deny a Pubky ID.
    DenyPut {
        /// The Pubky ID denied.
        pubky: [u8; 32],
    },
    /// `deny.delete`: remove a deny list entry.
    DenyDelete {
        /// The Pubky ID no longer denied.
        pubky: [u8; 32],
    },
    /// `invite_code.put`: register an invite code.
    InviteCodePut(InviteCodePut),
    /// `invite_code.delete`: withdraw an invite code.
    InviteCodeDelete {
        /// The code's hash.
        code_hash: [u8; 32],
    },
    /// `app.put`: the calling app's signed record (Switch spec 4.2, 12.1).
    AppPut {
        /// The signed app record, in its carrying form.
        record: SignedDoc,
    },
    /// `receive_key.put`: the calling app's signed receive key record (Switch spec 3.6).
    ReceiveKeyPut {
        /// The signed receive key record, in its carrying form.
        record: SignedDoc,
    },
    /// `key_bundle.put`: a key bundle, or a part, for an app (signer only).
    KeyBundlePut(KeyBundlePut),
    /// `cert.put`: an app's renewed certificate (signer only).
    CertPut {
        /// The app renewed.
        target_app_id: [u8; 16],
        /// The renewed certificate, in its carrying form.
        cert: SignedDoc,
    },
}

/// Each type's members besides the common ones (Switch wire 6.1, 6.2).
fn type_members(op: &str) -> Option<&'static [&'static str]> {
    Some(match op {
        "claim" => &[
            "claim_key",
            "type",
            "expected_step",
            "attempt_id",
            "orphan_after",
            "deadline",
            "basis",
            "evidence_ref",
        ],
        "record.put" => &[
            "key",
            "collection",
            "read_scope",
            "write_scopes",
            "expected_version",
            "value_sealed",
            "id_inputs",
        ],
        "allow.put" | "allow.delete" => &["pubky", "kind"],
        "deny.put" | "deny.delete" => &["pubky"],
        "invite_code.put" => &["code_hash", "expires_at", "max_uses", "context"],
        "invite_code.delete" => &["code_hash"],
        "app.put" | "receive_key.put" => &["record"],
        "key_bundle.put" => &["target_app_id", "bundle", "first_epoch", "last_epoch"],
        "cert.put" => &["target_app_id", "cert"],
        _ => return None,
    })
}

/// The members every signed operation may carry (Switch wire 6.1).
const COMMON: [&str; 6] = [
    "op",
    "identity",
    "app_id",
    "generation",
    "batch",
    "conditions",
];

/// The members of a sealed value (Switch wire 6.2).
const SEALED_MEMBERS: [&str; 4] = ["data_epoch", "scope", "nonce", "ct"];

impl OpKind {
    /// The type's name, as `op` carries it.
    pub fn name(&self) -> &'static str {
        match self {
            OpKind::Claim(_) => "claim",
            OpKind::RecordPut(_) => "record.put",
            OpKind::AllowPut { .. } => "allow.put",
            OpKind::AllowDelete { .. } => "allow.delete",
            OpKind::DenyPut { .. } => "deny.put",
            OpKind::DenyDelete { .. } => "deny.delete",
            OpKind::InviteCodePut(_) => "invite_code.put",
            OpKind::InviteCodeDelete { .. } => "invite_code.delete",
            OpKind::AppPut { .. } => "app.put",
            OpKind::ReceiveKeyPut { .. } => "receive_key.put",
            OpKind::KeyBundlePut(_) => "key_bundle.put",
            OpKind::CertPut { .. } => "cert.put",
        }
    }

    /// The object a transition proof of this operation names (Switch wire 6.5): the claim
    /// key, the record key, the Pubky ID, the code hash, or the App ID of the calling or
    /// target app. `app_id` is the operation's own.
    pub fn proof_object(&self, app_id: Option<&[u8; 16]>) -> Option<String> {
        Some(match self {
            OpKind::Claim(fields) => b64(&fields.claim_key),
            OpKind::RecordPut(put) => b64(&put.key),
            OpKind::AllowPut { pubky, .. }
            | OpKind::AllowDelete { pubky, .. }
            | OpKind::DenyPut { pubky }
            | OpKind::DenyDelete { pubky } => pubky_id(pubky),
            OpKind::InviteCodePut(put) => b64(&put.code_hash),
            OpKind::InviteCodeDelete { code_hash } => b64(code_hash),
            OpKind::AppPut { .. } | OpKind::ReceiveKeyPut { .. } => zbase32_encode(app_id?),
            OpKind::KeyBundlePut(put) => zbase32_encode(&put.target_app_id),
            OpKind::CertPut { target_app_id, .. } => zbase32_encode(target_app_id),
        })
    }

    /// Whether the type can be unchanged, so that a batch of it alone is a no-op (Switch wire
    /// 6.4 "No-ops", 6.5 "Binding"): `app.put`, `receive_key.put`, `key_bundle.put` and
    /// `cert.put`.
    pub fn can_be_unchanged(&self) -> bool {
        matches!(
            self,
            OpKind::AppPut { .. }
                | OpKind::ReceiveKeyPut { .. }
                | OpKind::KeyBundlePut(_)
                | OpKind::CertPut { .. }
        )
    }

    fn write(&self, o: &mut Obj) -> Result<()> {
        match self {
            OpKind::Claim(fields) => fields.write(o),
            OpKind::RecordPut(put) => {
                o.str("key", &b64(&put.key))
                    .str("collection", &b64(&put.collection))
                    .str("read_scope", &put.policy.read_scope)
                    .raw("write_scopes", &string_array(&put.policy.write_scopes))
                    .raw("expected_version", &put.expected_version.to_json());
                let sealed = &put.value_sealed;
                let mut s = Obj::new();
                s.int("data_epoch", sealed.data_epoch)
                    .str("scope", &sealed.scope)
                    .str("nonce", &b64(&sealed.nonce))
                    .str("ct", &b64(&sealed.ct));
                o.raw("value_sealed", &s.finish());
                if let Some(inputs) = &put.id_inputs {
                    let mut i = Obj::new();
                    i.str("collection", &inputs.collection)
                        .str("blinded_key", &b64(&inputs.blinded_key));
                    o.raw("id_inputs", &i.finish());
                }
            }
            OpKind::AllowPut { pubky, kind } | OpKind::AllowDelete { pubky, kind } => {
                o.str("pubky", &pubky_id(pubky)).str("kind", kind.as_str());
            }
            OpKind::DenyPut { pubky } | OpKind::DenyDelete { pubky } => {
                o.str("pubky", &pubky_id(pubky));
            }
            OpKind::InviteCodePut(put) => {
                let context = serde_json::to_vec(&put.context).map_err(|_| {
                    Error::Invalid("Switch wire 6.2: the invite context can't be written".into())
                })?;
                o.str("code_hash", &b64(&put.code_hash))
                    .str("expires_at", &rfc3339(put.expires_at))
                    .int("max_uses", put.max_uses)
                    .raw("context", &context);
            }
            OpKind::InviteCodeDelete { code_hash } => {
                o.str("code_hash", &b64(code_hash));
            }
            OpKind::AppPut { record } | OpKind::ReceiveKeyPut { record } => {
                o.raw("record", &carrying(record));
            }
            OpKind::KeyBundlePut(put) => {
                o.str("target_app_id", &zbase32_encode(&put.target_app_id))
                    .raw("bundle", &key_bundle_json(&put.bundle))
                    .int("first_epoch", put.first_epoch)
                    .int("last_epoch", put.last_epoch);
            }
            OpKind::CertPut {
                target_app_id,
                cert,
            } => {
                o.str("target_app_id", &zbase32_encode(target_app_id))
                    .raw("cert", &carrying(cert));
            }
        }
        Ok(())
    }

    fn read(op: &str, v: &Value) -> Result<Self> {
        let what = op;
        Ok(match op {
            "claim" => OpKind::Claim(ClaimFields::read(v)?),
            "record.put" => OpKind::RecordPut(read_record_put(v)?),
            "allow.put" | "allow.delete" => {
                let pubky = req_pubky(v, "pubky", what)?;
                let kind = AllowKind::parse(req_str(v, "kind", what)?)?;
                if op == "allow.put" {
                    OpKind::AllowPut { pubky, kind }
                } else {
                    OpKind::AllowDelete { pubky, kind }
                }
            }
            "deny.put" => OpKind::DenyPut {
                pubky: req_pubky(v, "pubky", what)?,
            },
            "deny.delete" => OpKind::DenyDelete {
                pubky: req_pubky(v, "pubky", what)?,
            },
            "invite_code.put" => {
                let Some(context) = v.get("context") else {
                    return invalid("Switch wire 6.2: invite_code.put: context is missing");
                };
                OpKind::InviteCodePut(InviteCodePut {
                    code_hash: req_b64n::<32>(v, "code_hash", what)?,
                    expires_at: req_time(v, "expires_at", what)?,
                    max_uses: req_int(v, "max_uses", what)?,
                    context: context.clone(),
                })
            }
            "invite_code.delete" => OpKind::InviteCodeDelete {
                code_hash: req_b64n::<32>(v, "code_hash", what)?,
            },
            "app.put" => OpKind::AppPut {
                record: SignedDoc::from_strict_value(req(v, "record", what)?)?,
            },
            "receive_key.put" => OpKind::ReceiveKeyPut {
                record: SignedDoc::from_strict_value(req(v, "record", what)?)?,
            },
            "key_bundle.put" => OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: req_app_id(v, "target_app_id", what)?,
                bundle: read_key_bundle(req(v, "bundle", what)?)?,
                first_epoch: req_int(v, "first_epoch", what)?,
                last_epoch: req_int(v, "last_epoch", what)?,
            }),
            "cert.put" => OpKind::CertPut {
                target_app_id: req_app_id(v, "target_app_id", what)?,
                cert: SignedDoc::from_strict_value(req(v, "cert", what)?)?,
            },
            _ => return invalid("Switch wire 6.2: an unknown operation type"),
        })
    }
}

/// Read a `record.put`'s members, refusing unknown members in its nested objects (Switch
/// wire 1.1, 6.2). Its shape rules come later (6.4 step 9).
fn read_record_put(v: &Value) -> Result<RecordPut> {
    let what = "record.put";
    let write_scopes = match req(v, "write_scopes", what)?.as_array() {
        Some(items) => items
            .iter()
            .map(|s| text(s, "write_scopes", what).map(str::to_owned))
            .collect::<Result<Vec<_>>>()?,
        None => return invalid("Switch wire 6.2: record.put: write_scopes isn't an array"),
    };
    let sealed = req(v, "value_sealed", what)?;
    only(sealed, &SEALED_MEMBERS, "value_sealed")?;
    let value_sealed: SealedValue = serde_json::from_value(sealed.clone())?;
    let id_inputs = match opt(v, "id_inputs") {
        None => None,
        Some(inputs) => {
            let what = "id_inputs";
            only(inputs, &["collection", "blinded_key"], what)?;
            Some(IdInputs {
                collection: req_str(inputs, "collection", what)?.to_owned(),
                blinded_key: req_b64n::<32>(inputs, "blinded_key", what)?,
            })
        }
    };
    Ok(RecordPut {
        key: req_b64n::<32>(v, "key", what)?,
        collection: req_b64n::<32>(v, "collection", what)?,
        policy: Policy {
            read_scope: req_str(v, "read_scope", what)?.to_owned(),
            write_scopes,
        },
        expected_version: RecordVersion::read(req(v, "expected_version", what)?, what)?,
        value_sealed,
        id_inputs,
    })
}

/// A signed operation's body (Switch wire 6.1): the members every operation carries and its
/// type's own.
#[derive(Clone, Debug, PartialEq)]
pub struct OpBody {
    /// The account's identity.
    pub identity: [u8; 32],
    /// The calling app; `None` for the signer.
    pub app_id: Option<[u8; 16]>,
    /// The account's current generation.
    pub generation: u64,
    /// The batch the operation is in.
    pub batch: BatchRef,
    /// The operation's conditions; omitted from the body when empty.
    pub conditions: Vec<Condition>,
    /// The type and its members.
    pub kind: OpKind,
}

impl OpBody {
    /// The body's exact JSON bytes, as writers produce them: `identity`, `app_id`,
    /// `generation`, `batch`, `conditions` (when any), `op`, then the type's members in the
    /// order of Switch wire 6.2.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if the invite context can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut o = Obj::new();
        o.str("identity", &pubky_id(&self.identity));
        match &self.app_id {
            Some(app) => o.str("app_id", &zbase32_encode(app)),
            None => o.null("app_id"),
        };
        o.int("generation", self.generation)
            .raw("batch", &self.batch.to_json());
        if !self.conditions.is_empty() {
            let conditions: Vec<Vec<u8>> = self.conditions.iter().map(|c| c.to_json()).collect();
            o.raw("conditions", &array(&conditions));
        }
        o.str("op", self.kind.name());
        self.kind.write(&mut o)?;
        Ok(o.finish())
    }

    /// Read a body strictly (Switch wire 1.1, 6.1): strict JSON with the integer rule, the
    /// opaque `context` of `invite_code.put` excepted; no unknown members at any depth; and
    /// every member of its type decoded. The type's shape rules of Switch wire 6.4 step 9
    /// come after the caller's permission ([`super::check_shape`]).
    ///
    /// # Errors
    ///
    /// A `400 bad_request` [`Refusal`] naming the rule that failed.
    pub fn parse(bytes: &[u8]) -> std::result::Result<Self, Refusal> {
        Self::read(bytes).map_err(Refusal::from)
    }

    fn read(bytes: &[u8]) -> Result<Self> {
        let v: Value = parse_json_as(bytes, Doc::Op)?;
        let what = "an operation";
        let op = req_str(&v, "op", what)?;
        let Some(members) = type_members(op) else {
            return invalid("Switch wire 6.1: op isn't a type of 6.2");
        };
        let allowed: Vec<&str> = COMMON.iter().chain(members).copied().collect();
        only(&v, &allowed, what)?;
        let identity = req_pubky(&v, "identity", what)?;
        let app = match v.get("app_id") {
            None => return invalid("Switch wire 6.1: app_id is missing"),
            Some(Value::Null) => None,
            Some(id) => Some(app_id(id, "app_id", what)?),
        };
        let generation = req_int(&v, "generation", what)?;
        let batch = BatchRef::read(req(&v, "batch", what)?)?;
        let conditions = match opt(&v, "conditions") {
            None => Vec::new(),
            Some(list) => match list.as_array() {
                Some(items) => items
                    .iter()
                    .map(Condition::read)
                    .collect::<Result<Vec<_>>>()?,
                None => return invalid("Switch wire 6.3: conditions isn't an array"),
            },
        };
        let kind = OpKind::read(op, &v)?;
        Ok(Self {
            identity,
            app_id: app,
            generation,
            batch,
            conditions,
            kind,
        })
    }

    /// The body's `int` members never exceed 2^53 - 1 (Switch wire 1.1); a writer checks it
    /// before signing.
    fn check_ints(&self) -> Result<()> {
        let mut ints = vec![self.generation, self.batch.count];
        for c in &self.conditions {
            match c {
                Condition::RecordVersion { version, .. } => {
                    ints.extend([version.generation, version.version]);
                }
                Condition::ClaimStep { step, .. } => ints.push(*step),
                Condition::ServerTimeIn { .. } => {}
            }
        }
        match &self.kind {
            OpKind::Claim(f) => {
                ints.push(f.expected_step);
                ints.extend(f.orphan_after);
            }
            OpKind::RecordPut(p) => ints.extend([
                p.expected_version.generation,
                p.expected_version.version,
                p.value_sealed.data_epoch,
            ]),
            OpKind::InviteCodePut(p) => ints.push(p.max_uses),
            OpKind::KeyBundlePut(p) => ints.extend([p.first_epoch, p.last_epoch]),
            _ => {}
        }
        if ints.iter().any(|n| *n > crate::json::MAX_INT) {
            return invalid("Switch wire 1.1: an integer above 2^53 - 1");
        }
        Ok(())
    }
}

/// A signed operation (Switch wire 6.1): its body, the exact bytes the writer signed, and
/// the signed document in its carrying form.
///
/// Only [`SignedOp::sign`] and the readers below make one, so its body always matches its
/// bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedOp {
    body: OpBody,
    signed: SignedDoc,
}

impl SignedOp {
    /// Sign a body with its writer's key: an app with its signing key, the signer with the
    /// identity key (Switch wire 6.1).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if `app_id` isn't the writer's (the App ID of its key, or `None`
    /// for the identity key), an integer is out of range, or the operation is over 512 KiB in
    /// its carrying form.
    pub fn sign(writer: &impl Signs, body: OpBody) -> Result<Self> {
        let key = writer.public_key();
        let writer_ok = match &body.app_id {
            Some(app) => *app == app_id_bytes(&key),
            None => key == body.identity,
        };
        if !writer_ok {
            return invalid("Switch wire 6.1: app_id isn't the writer's");
        }
        body.check_ints()?;
        let bytes = body.to_json()?;
        let sig = writer.sign_fields(labels::sig::OP, &[&body.identity, &bytes]);
        let signed = SignedDoc::from_parts(&bytes, &sig);
        if carrying_len(&signed.body, &signed.sig) > MAX_OP_BYTES {
            return invalid("Switch wire 6.1: a signed operation over 512 KiB");
        }
        Ok(Self { body, signed })
    }

    /// Verify a signed operation for the caller, in the order of Switch wire 6.4 step 3: its
    /// signature with the caller's key over `lp("pubky-switch/v1/op", identity, body)`, then
    /// the body strictly, its `identity` the account's and its `app_id` the caller's (`None`
    /// for the signer).
    ///
    /// # Errors
    ///
    /// `401 bad_signature` for a signature that doesn't verify, `400 bad_request` for the
    /// other rules.
    pub fn verify(
        signed: &SignedDoc,
        writer_key: &[u8; 32],
        identity: &[u8; 32],
        app_id: Option<&[u8; 16]>,
    ) -> std::result::Result<Self, Refusal> {
        // A signature that doesn't decode doesn't verify: `401` like one that fails.
        signed.sig_bytes().map_err(|_| {
            Refusal::new(
                crate::http::ErrorCode::BadSignature,
                "Switch wire 2.2: the signature isn't b64(64)",
            )
        })?;
        let bytes = signed.verify(writer_key, labels::sig::OP, &[identity])?;
        let body = OpBody::parse(&bytes)?;
        if &body.identity != identity {
            return Err(Refusal::bad_request(
                "Switch wire 6.1: identity isn't the account's",
            ));
        }
        if body.app_id.as_ref() != app_id {
            return Err(Refusal::bad_request(
                "Switch wire 6.1: app_id isn't the calling app",
            ));
        }
        Ok(Self {
            body,
            signed: signed.clone(),
        })
    }

    /// Read a signed operation without verifying its signature, as an app reads one the
    /// chain vouches for by its item hash, or to find the writer whose key verifies it.
    ///
    /// # Errors
    ///
    /// `400 bad_request` if the body doesn't read.
    pub fn peek(signed: &SignedDoc) -> std::result::Result<Self, Refusal> {
        let body = OpBody::parse(&signed.body_bytes()?)?;
        Ok(Self {
            body,
            signed: signed.clone(),
        })
    }

    /// The body.
    pub fn body(&self) -> &OpBody {
        &self.body
    }

    /// The signed document, in its exact bytes.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// The signed document bytes, `lp(body, sig)` (Switch wire 2.2), the chain item's bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if a member doesn't decode, which can't happen for an operation
    /// this type made.
    pub fn doc_bytes(&self) -> Result<Vec<u8>> {
        Ok(lp(&[&self.signed.body_bytes()?, &self.signed.sig_bytes()?]))
    }

    /// The chain item hash of the operation (Switch wire 6.6).
    ///
    /// # Errors
    ///
    /// As [`SignedOp::doc_bytes`].
    pub fn item_hash(&self) -> Result<[u8; 32]> {
        Ok(crate::chain::item_hash(
            crate::chain::ItemType::Op,
            &self.doc_bytes()?,
        ))
    }

    /// The size of the compact carrying form (Switch wire 6.1).
    pub fn carrying_len(&self) -> usize {
        carrying_len(&self.signed.body, &self.signed.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::{Basis, ClaimType};
    use crate::keys::{AppKeys, IdentityKey};

    pub(crate) fn identity() -> IdentityKey {
        IdentityKey::from_secret([1; 32])
    }

    pub(crate) fn app() -> AppKeys {
        AppKeys::from_secrets([2; 32], [3; 32])
    }

    pub(crate) fn body(kind: OpKind) -> OpBody {
        OpBody {
            identity: identity().public(),
            app_id: Some(app().app_id_bytes()),
            generation: 1,
            batch: BatchRef {
                id: [7; 16],
                count: 1,
            },
            conditions: Vec::new(),
            kind,
        }
    }

    fn attempt() -> OpKind {
        OpKind::Claim(ClaimFields {
            claim_key: vec![9; 32],
            kind: ClaimType::Attempt,
            expected_step: 0,
            attempt_id: vec![8; 16],
            orphan_after: Some(60),
            deadline: Some(1_767_225_600_001),
            basis: None,
            evidence_ref: None,
        })
    }

    #[test]
    fn test_op_body_writes_members_in_wire_order() {
        let mut b = body(attempt());
        b.conditions.push(Condition::ClaimStep {
            claim_key: [9; 32],
            step: 0,
        });
        let json = String::from_utf8(b.to_json().unwrap()).unwrap();
        let order = [
            "\"identity\"",
            "\"app_id\"",
            "\"generation\"",
            "\"batch\"",
            "\"conditions\"",
            "\"op\"",
            "\"claim_key\"",
            "\"type\"",
            "\"expected_step\"",
            "\"attempt_id\"",
            "\"orphan_after\"",
            "\"deadline\"",
        ];
        let mut from = 0;
        for key in order {
            let at = json[from..]
                .find(key)
                .unwrap_or_else(|| panic!("{key} in {json}"));
            from += at + key.len();
        }
        assert_eq!(OpBody::parse(json.as_bytes()).unwrap(), b);
    }

    #[test]
    fn test_op_body_round_trips_every_type() {
        let pubky = identity().public();
        let kinds = vec![
            attempt(),
            OpKind::AllowPut {
                pubky,
                kind: AllowKind::Conversation,
            },
            OpKind::AllowDelete {
                pubky,
                kind: AllowKind::Contact,
            },
            OpKind::DenyPut { pubky },
            OpKind::DenyDelete { pubky },
            OpKind::InviteCodePut(InviteCodePut {
                code_hash: [4; 32],
                expires_at: 1_767_225_600_000,
                max_uses: 1,
                context: serde_json::json!({"ref": 1.5}),
            }),
            OpKind::InviteCodeDelete { code_hash: [4; 32] },
            OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: [5; 16],
                bundle: KeyBundle::from_parts(vec![1, 2, 3], [6; 64]),
                first_epoch: 1,
                last_epoch: 2,
            }),
            OpKind::CertPut {
                target_app_id: [5; 16],
                cert: SignedDoc::from_parts(b"{}", &[1; 64]),
            },
            OpKind::AppPut {
                record: SignedDoc::from_parts(b"{}", &[1; 64]),
            },
        ];
        for kind in kinds {
            let b = body(kind);
            let json = b.to_json().unwrap();
            assert_eq!(OpBody::parse(&json).unwrap(), b);
        }
    }

    #[test]
    fn test_op_body_refuses_unknown_members_at_every_depth() {
        let b = body(attempt());
        let mut v: Value = serde_json::from_slice(&b.to_json().unwrap()).unwrap();
        assert!(OpBody::parse(&serde_json::to_vec(&v).unwrap()).is_ok());
        v["extra"] = 1.into();
        assert_eq!(
            OpBody::parse(&serde_json::to_vec(&v).unwrap())
                .unwrap_err()
                .status(),
            400
        );
        let mut v: Value = serde_json::from_slice(&b.to_json().unwrap()).unwrap();
        v["batch"]["extra"] = 1.into();
        assert!(OpBody::parse(&serde_json::to_vec(&v).unwrap()).is_err());
        let mut v: Value = serde_json::from_slice(&b.to_json().unwrap()).unwrap();
        v["conditions"] =
            serde_json::json!([{"claim_step": {"claim_key": b64(&[1; 32]), "step": 0, "x": 1}}]);
        assert!(OpBody::parse(&serde_json::to_vec(&v).unwrap()).is_err());
        v["conditions"] =
            serde_json::json!([{"claim_step": {"claim_key": b64(&[1; 32]), "step": 0}, "x": 1}]);
        assert!(OpBody::parse(&serde_json::to_vec(&v).unwrap()).is_err());
        v["conditions"] =
            serde_json::json!([{"claim_step": {"claim_key": b64(&[1; 32]), "step": 0}}]);
        assert!(OpBody::parse(&serde_json::to_vec(&v).unwrap()).is_ok());
    }

    #[test]
    fn test_op_body_key_bundle_form_is_strict() {
        let b = body(OpKind::KeyBundlePut(KeyBundlePut {
            target_app_id: [5; 16],
            bundle: KeyBundle::from_parts(vec![1, 2, 3], [6; 64]),
            first_epoch: 1,
            last_epoch: 1,
        }));
        let v: Value = serde_json::from_slice(&b.to_json().unwrap()).unwrap();
        assert_eq!(
            v["bundle"],
            serde_json::json!({"envelope": "AQID", "sig": b64(&[6; 64])})
        );
        assert_eq!(OpBody::parse(&b.to_json().unwrap()).unwrap(), b);
        // Read elsewhere a key bundle ignores unknown members; inside an operation it doesn't.
        let mut extra = v.clone();
        extra["bundle"]["future"] = 1.into();
        assert!(serde_json::from_value::<KeyBundle>(extra["bundle"].clone()).is_ok());
        let refused = OpBody::parse(&serde_json::to_vec(&extra).unwrap()).unwrap_err();
        assert_eq!(refused.status(), 400);
        let mut short = v;
        short["bundle"]["sig"] = b64(&[6; 63]).into();
        assert!(OpBody::parse(&serde_json::to_vec(&short).unwrap()).is_err());
    }

    #[test]
    fn test_op_body_invite_context_is_opaque() {
        let b = body(OpKind::InviteCodePut(InviteCodePut {
            code_hash: [4; 32],
            expires_at: 1_767_225_600_000,
            max_uses: 1,
            context: serde_json::json!({"rate": -2.5, "extra": {"n": 1e30}}),
        }));
        assert!(OpBody::parse(&b.to_json().unwrap()).is_ok());
        // A fraction elsewhere is refused before any field is read.
        let text = String::from_utf8(body(attempt()).to_json().unwrap())
            .unwrap()
            .replace("\"orphan_after\":60", "\"orphan_after\":60.0");
        assert!(OpBody::parse(text.as_bytes()).is_err());
    }

    #[test]
    fn test_op_body_refuses_unknown_types_and_missing_members() {
        let text = String::from_utf8(body(attempt()).to_json().unwrap()).unwrap();
        assert!(OpBody::parse(text.replace("\"claim\"", "\"claim.x\"").as_bytes()).is_err());
        let no_app = text.replacen(
            &format!("\"app_id\":\"{}\",", zbase32_encode(&app().app_id_bytes())),
            "",
            1,
        );
        assert!(OpBody::parse(no_app.as_bytes()).is_err());
        let done = OpKind::Claim(ClaimFields {
            claim_key: vec![9; 32],
            kind: ClaimType::Done,
            expected_step: 1,
            attempt_id: vec![8; 16],
            orphan_after: None,
            deadline: None,
            basis: Some(Basis::Owner),
            evidence_ref: None,
        });
        assert!(OpBody::parse(&body(done).to_json().unwrap()).is_ok());
    }

    #[test]
    fn test_signed_op_signs_and_verifies_for_its_writer() {
        let app = app();
        let id = identity().public();
        let op = SignedOp::sign(&app, body(attempt())).unwrap();
        let app_id = app.app_id_bytes();
        let checked =
            SignedOp::verify(op.signed(), &app.signing_public(), &id, Some(&app_id)).unwrap();
        assert_eq!(checked.body(), op.body());
        // Another key, identity or caller.
        let other = AppKeys::from_secrets([4; 32], [5; 32]);
        let refused = SignedOp::verify(op.signed(), &other.signing_public(), &id, Some(&app_id));
        assert_eq!(refused.unwrap_err().status(), 401);
        let refused = SignedOp::verify(op.signed(), &app.signing_public(), &id, None);
        assert_eq!(refused.unwrap_err().status(), 400);
        // A writer signing for another app.
        assert!(SignedOp::sign(&other, body(attempt())).is_err());
        // The signer signs with the identity key and app_id null.
        let mut signer_body = body(attempt());
        signer_body.app_id = None;
        let signed = SignedOp::sign(&identity(), signer_body).unwrap();
        assert!(SignedOp::verify(signed.signed(), &id, &id, None).is_ok());
    }

    #[test]
    fn test_carrying_len_counts_the_compact_form() {
        assert_eq!(carrying_len("", ""), 20);
        let op = SignedOp::sign(&app(), body(attempt())).unwrap();
        let compact = format!(
            r#"{{"body":"{}","sig":"{}"}}"#,
            op.signed().body,
            op.signed().sig
        );
        assert_eq!(op.carrying_len(), compact.len());
    }

    #[test]
    fn test_record_version_orders_by_generation_then_seq() {
        assert!(RecordVersion::new(2, 1) > RecordVersion::new(1, 900));
        assert!(RecordVersion::new(1, 8) > RecordVersion::new(1, 6));
        assert!(RecordVersion::NONE.is_none());
        assert!(!RecordVersion::new(0, 1).is_none());
    }

    #[test]
    fn test_condition_requires_one_member_and_both_bounds() {
        let ok = serde_json::json!({"server_time_in": {"start": null, "end": "2026-01-01T00:00:00.000Z"}});
        assert_eq!(
            Condition::read(&ok).unwrap(),
            Condition::ServerTimeIn {
                start: None,
                end: Some(1_767_225_600_000)
            }
        );
        let missing = serde_json::json!({"server_time_in": {"start": null}});
        assert!(Condition::read(&missing).is_err());
        let two = serde_json::json!({"claim_step": {"claim_key": b64(&[1; 32]), "step": 0}, "server_time_in": {"start": null, "end": null}});
        assert!(Condition::read(&two).is_err());
        assert!(Condition::read(&serde_json::json!({})).is_err());
    }
}
