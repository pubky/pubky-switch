//! The chain (Switch wire 6.5 to 6.7, Switch spec 8.3, 10.1 and 13.6): service transitions,
//! transition proofs, chain envelopes, item and chain hashes, stubs, signed heads, and the
//! checks an app makes on them.
//!
//! Every signed operation, every `identity.json` delivery and every service transition is a
//! chain item. The service writes each one a chain envelope, kept as exact bytes, whose chain
//! hash links it to the previous item, and answers with a transition proof and a signed head.
//! An app keeps the newest head it has seen and verifies with [`Verifier`] that the stubs and
//! heads it reads extend it, so that a service that rolls back or forks its history is caught
//! while the app can verify continuity (Switch spec 10.1).

use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value, json};

use crate::enc::{b64, hash, lp, pubky_id, u64be, unb64, zbase32_encode};
use crate::error::{Error, Result, invalid};
use crate::labels;
use crate::ops::body::{Obj, quote};
use crate::ops::read::{opt, req, req_app_id, req_b64n, req_int, req_pubky, req_str, req_time};
use crate::ops::{BatchRef, RecordVersion, SignedOp};
use crate::records::Inbox;
use crate::sig::{self, SignedDoc};
use crate::signing::Signs;
use crate::time::rfc3339;

/// The chain version of this wire format (Switch wire 6.6, 6.7).
pub const CHAIN_VERSION: u64 = 1;

/// The `prev_chain_hash` of a chain's first item, and a head's chain hash before any item:
/// 32 zero bytes (Switch wire 6.6, 6.7).
pub const ZERO_HASH: [u8; 32] = [0; 32];

/// How far back an app compares a new batch's ID: 30 days, exactly 2,592,000,000 ms, by the
/// `server_time` of each batch's first stub (Switch wire 6.6). A new batch is a repeat when
/// its ID is an earlier batch's and `t_new - t_old` is less than this.
pub const BATCH_ID_WINDOW_MS: u64 = 2_592_000_000;

/// The type of a chain item (Switch wire 6.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ItemType {
    /// A signed operation.
    Op,
    /// An `identity.json` delivery.
    Identity,
    /// A service transition.
    Service,
}

impl ItemType {
    /// The type as the envelope writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            ItemType::Op => "op",
            ItemType::Identity => "identity",
            ItemType::Service => "service",
        }
    }

    pub(crate) fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "op" => ItemType::Op,
            "identity" => ItemType::Identity,
            "service" => ItemType::Service,
            _ => return invalid("Switch wire 6.6: item_type isn't op, identity or service"),
        })
    }
}

/// An item hash: `hash(lp("pubky-switch/v1/item", item type, item bytes))`, the item bytes
/// being the signed document bytes (Switch wire 6.6).
pub fn item_hash(item_type: ItemType, item_bytes: &[u8]) -> [u8; 32] {
    hash(&lp(&[
        labels::derive::ITEM.as_bytes(),
        item_type.as_str().as_bytes(),
        item_bytes,
    ]))
}

/// A chain hash: `hash(lp("pubky-switch/v1/chain", prev_chain_hash, envelope bytes))` (Switch
/// wire 6.6).
pub fn chain_hash(prev_chain_hash: &[u8; 32], envelope: &[u8]) -> [u8; 32] {
    hash(&lp(&[
        labels::derive::CHAIN.as_bytes(),
        prev_chain_hash,
        envelope,
    ]))
}

/// A chain envelope (Switch wire 6.6), written by the service and kept as exact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainEnvelope {
    /// The chain version, 1.
    pub chain_version: u64,
    /// The generation.
    pub generation: u64,
    /// The item's position in the sequence.
    pub seq: u64,
    /// The previous chain item's chain hash; [`ZERO_HASH`] before the first.
    pub prev_chain_hash: [u8; 32],
    /// When the service applied the item, in Unix milliseconds.
    pub server_time: u64,
    /// The item's type.
    pub item_type: ItemType,
    /// The item hash.
    pub item_hash: [u8; 32],
    /// The batch, for operations only.
    pub batch: Option<BatchRef>,
}

impl ChainEnvelope {
    /// The envelope's exact JSON bytes, in the order of Switch wire 6.6.
    pub fn to_json(&self) -> Vec<u8> {
        let mut o = Obj::new();
        o.int("chain_version", self.chain_version)
            .int("generation", self.generation)
            .int("seq", self.seq)
            .str("prev_chain_hash", &b64(&self.prev_chain_hash))
            .str("server_time", &rfc3339(self.server_time))
            .str("item_type", self.item_type.as_str())
            .str("item_hash", &b64(&self.item_hash));
        if let Some(batch) = self.batch {
            o.str("batch_id", &b64(&batch.id))
                .int("batch_count", batch.count);
        }
        o.finish()
    }

    /// Read an envelope's bytes (Switch wire 6.6): the batch members together, and for
    /// operations only.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] naming the rule.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v: Value = crate::json::parse_json(bytes)?;
        let what = "a chain envelope";
        let item_type = ItemType::parse(req_str(&v, "item_type", what)?)?;
        let batch = match (opt(&v, "batch_id"), opt(&v, "batch_count")) {
            (None, None) => None,
            (Some(_), Some(_)) => Some(BatchRef {
                id: req_b64n::<16>(&v, "batch_id", what)?,
                count: req_int(&v, "batch_count", what)?,
            }),
            _ => return invalid("Switch wire 6.6: batch_id and batch_count go together"),
        };
        if batch.is_some() != (item_type == ItemType::Op) {
            return invalid("Switch wire 6.6: the batch members are for operations only");
        }
        Ok(Self {
            chain_version: req_int(&v, "chain_version", what)?,
            generation: req_int(&v, "generation", what)?,
            seq: req_int(&v, "seq", what)?,
            prev_chain_hash: req_b64n::<32>(&v, "prev_chain_hash", what)?,
            server_time: req_time(&v, "server_time", what)?,
            item_type,
            item_hash: req_b64n::<32>(&v, "item_hash", what)?,
            batch,
        })
    }
}

/// A chain stub (Switch wire 6.6): the exact envelope bytes and the chain hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Stub {
    /// The envelope's exact bytes.
    pub envelope: Vec<u8>,
    /// The chain hash.
    pub chain_hash: [u8; 32],
}

impl Stub {
    /// The stub of an envelope, as the service writes it.
    pub fn of(envelope: &ChainEnvelope) -> Self {
        let bytes = envelope.to_json();
        Self {
            chain_hash: chain_hash(&envelope.prev_chain_hash, &bytes),
            envelope: bytes,
        }
    }

    /// The stub's JSON: `{ "envelope": "<base64url of the envelope bytes>", "chain_hash" }`.
    pub fn to_json(&self) -> Vec<u8> {
        let mut o = Obj::new();
        o.str("envelope", &b64(&self.envelope))
            .str("chain_hash", &b64(&self.chain_hash));
        o.finish()
    }

    /// The stub as a JSON value.
    pub fn to_value(&self) -> Value {
        json!({ "envelope": b64(&self.envelope), "chain_hash": b64(&self.chain_hash) })
    }

    /// Read a stub from its JSON value.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if a member is missing or malformed.
    pub fn from_value(v: &Value) -> Result<Self> {
        let what = "a stub";
        let envelope = unb64(req_str(v, "envelope", what)?).map_err(|_| {
            Error::Invalid("Switch wire 6.6: a stub's envelope isn't base64url".into())
        })?;
        Ok(Self {
            envelope,
            chain_hash: req_b64n::<32>(v, "chain_hash", what)?,
        })
    }

    /// The envelope, read and checked: its chain hash follows from it (Switch wire 6.6).
    ///
    /// # Errors
    ///
    /// [`ChainError::Malformed`] for an envelope that doesn't read, and
    /// [`ChainError::ChainHash`] for a chain hash that doesn't follow.
    pub fn open(&self) -> std::result::Result<ChainEnvelope, ChainError> {
        let envelope =
            ChainEnvelope::parse(&self.envelope).map_err(|e| ChainError::Malformed(reason(e)))?;
        if chain_hash(&envelope.prev_chain_hash, &self.envelope) != self.chain_hash {
            return Err(ChainError::ChainHash { seq: envelope.seq });
        }
        Ok(envelope)
    }
}

/// Where a chain ends, as the service keeps it to write the next item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainTip {
    /// The generation.
    pub generation: u64,
    /// The newest chain item's `seq`, 0 before any.
    pub seq: u64,
    /// Its chain hash, [`ZERO_HASH`] before any, or a checkpoint's.
    pub chain_hash: [u8; 32],
}

impl ChainTip {
    /// The stub of the next chain item, at `seq` (above the tip's: inbox entries and cursor
    /// moves take `seq`s too, so chain `seq`s may have gaps), and the tip after it.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if `seq` isn't above the tip's, or the batch is given for an item
    /// that isn't an operation or missing for one.
    pub fn append(
        &self,
        seq: u64,
        server_time: u64,
        item_type: ItemType,
        item_hash: [u8; 32],
        batch: Option<BatchRef>,
    ) -> Result<(Stub, ChainTip)> {
        if seq <= self.seq {
            return invalid("Switch wire 6.6: a chain item's seq is above the last one");
        }
        if batch.is_some() != (item_type == ItemType::Op) {
            return invalid("Switch wire 6.6: the batch members are for operations only");
        }
        let stub = Stub::of(&ChainEnvelope {
            chain_version: CHAIN_VERSION,
            generation: self.generation,
            seq,
            prev_chain_hash: self.chain_hash,
            server_time,
            item_type,
            item_hash,
            batch,
        });
        let tip = ChainTip {
            generation: self.generation,
            seq,
            chain_hash: stub.chain_hash,
        };
        Ok((stub, tip))
    }
}

/// A signed head (Switch wire 6.7): not a signed document, but a JSON object whose `sig` is
/// the service key's over `lp("pubky-switch/v1/head", identity, u64(chain_version),
/// u64(generation), u64(seq), chain hash)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignedHead {
    /// The chain version, 1.
    pub chain_version: u64,
    /// The generation.
    pub generation: u64,
    /// The newest chain item's `seq`, 0 before any.
    pub seq: u64,
    /// Its chain hash, [`ZERO_HASH`] before any.
    pub chain_hash: [u8; 32],
    /// The service key's signature.
    pub sig: [u8; 64],
}

impl SignedHead {
    fn fields(
        identity: &[u8; 32],
        chain_version: u64,
        generation: u64,
        seq: u64,
        chain_hash: &[u8; 32],
    ) -> [Vec<u8>; 5] {
        [
            identity.to_vec(),
            u64be(chain_version).to_vec(),
            u64be(generation).to_vec(),
            u64be(seq).to_vec(),
            chain_hash.to_vec(),
        ]
    }

    /// Sign the head at a chain tip with the service key.
    pub fn sign(service_key: &impl Signs, identity: &[u8; 32], tip: &ChainTip) -> Self {
        let fields = Self::fields(
            identity,
            CHAIN_VERSION,
            tip.generation,
            tip.seq,
            &tip.chain_hash,
        );
        let parts: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        Self {
            chain_version: CHAIN_VERSION,
            generation: tip.generation,
            seq: tip.seq,
            chain_hash: tip.chain_hash,
            sig: service_key.sign_fields(labels::sig::HEAD, &parts),
        }
    }

    /// Verify the head with the service key (Switch wire 6.7).
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if it doesn't verify, [`Error::Invalid`] for a chain version
    /// other than 1.
    pub fn verify(&self, service_key: &[u8; 32], identity: &[u8; 32]) -> Result<()> {
        if self.chain_version != CHAIN_VERSION {
            return invalid("Switch wire 6.7: a head of a chain version other than 1");
        }
        let fields = Self::fields(
            identity,
            self.chain_version,
            self.generation,
            self.seq,
            &self.chain_hash,
        );
        let parts: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        sig::verify(service_key, labels::sig::HEAD, &parts, &self.sig)
    }

    /// The head's JSON bytes, as an answer and the `Switch-Head` header carry it:
    /// `chain_version`, `generation`, `seq`, `chain_hash`, `sig`.
    pub fn to_json(&self) -> Vec<u8> {
        let mut o = Obj::new();
        o.int("chain_version", self.chain_version)
            .int("generation", self.generation)
            .int("seq", self.seq)
            .str("chain_hash", &b64(&self.chain_hash))
            .str("sig", &b64(&self.sig));
        o.finish()
    }

    /// The head as a JSON value.
    pub fn to_value(&self) -> Value {
        json!({
            "chain_version": self.chain_version,
            "generation": self.generation,
            "seq": self.seq,
            "chain_hash": b64(&self.chain_hash),
            "sig": b64(&self.sig),
        })
    }

    /// Read a head from its JSON value.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if a member is missing or malformed.
    pub fn from_value(v: &Value) -> Result<Self> {
        let what = "a signed head";
        Ok(Self {
            chain_version: req_int(v, "chain_version", what)?,
            generation: req_int(v, "generation", what)?,
            seq: req_int(v, "seq", what)?,
            chain_hash: req_b64n::<32>(v, "chain_hash", what)?,
            sig: req_b64n::<64>(v, "sig", what)?,
        })
    }

    /// The `Switch-Head` header: base64url of the head's JSON bytes (Switch wire 6.7).
    pub fn to_header(&self) -> String {
        b64(&self.to_json())
    }

    /// Read a `Switch-Head` header (Switch wire 6.7).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if it isn't base64url of a head's JSON.
    pub fn from_header(text: &str) -> Result<Self> {
        let v: Value = crate::json::parse_json(&unb64(text)?)?;
        Self::from_value(&v)
    }
}

/// A service transition (Switch wire 6.5): a chain item of type `service` that the service
/// writes itself. Its body's members are written sorted by name.
#[derive(Clone, Debug, PartialEq)]
pub enum ServiceTransition {
    /// `revoke`: `POST /apps/{app_id}/revoke`.
    Revoke {
        /// The app revoked.
        app_id: [u8; 16],
        /// When.
        at: u64,
    },
    /// `leave`: `POST /apps/{app_id}/leave`.
    Leave {
        /// The app that left.
        app_id: [u8; 16],
        /// When.
        at: u64,
    },
    /// `freeze`: `POST /freeze`.
    Freeze {
        /// The freeze's document hash.
        freeze_hash: [u8; 32],
        /// The generation at the next service.
        next_generation: u64,
        /// The next service.
        inbox: Inbox,
        /// When.
        at: u64,
    },
    /// `unfreeze`: `POST /unfreeze`.
    Unfreeze {
        /// The freeze's document hash.
        freeze_hash: [u8; 32],
        /// When.
        at: u64,
    },
    /// `recovery`: the first item at a new account after a provider loss.
    Recovery {
        /// The generation declared lost.
        recovery_from: u64,
        /// When.
        at: u64,
    },
    /// `admission`: `POST /recovery/admission`, by the signer.
    Admission {
        /// When.
        at: u64,
    },
    /// `upload`: `POST /recovery/upload`.
    Upload {
        /// The uploading app.
        by: [u8; 16],
        /// What the upload changed (Switch wire 7.4.14).
        changes: Value,
        /// How many proofs it carried.
        proofs: u64,
        /// When.
        at: u64,
    },
    /// `conversation.add`: the first append an invite code admitted. No proof is returned.
    ConversationAdd {
        /// The sender.
        pubky: [u8; 32],
        /// The code's hash.
        code_hash: [u8; 32],
        /// The code's opaque context.
        context: Value,
        /// When.
        at: u64,
    },
}

impl ServiceTransition {
    /// The transition's `type`.
    pub fn type_name(&self) -> &'static str {
        match self {
            ServiceTransition::Revoke { .. } => "revoke",
            ServiceTransition::Leave { .. } => "leave",
            ServiceTransition::Freeze { .. } => "freeze",
            ServiceTransition::Unfreeze { .. } => "unfreeze",
            ServiceTransition::Recovery { .. } => "recovery",
            ServiceTransition::Admission { .. } => "admission",
            ServiceTransition::Upload { .. } => "upload",
            ServiceTransition::ConversationAdd { .. } => "conversation.add",
        }
    }

    /// The object a proof of the transition names (Switch wire 6.5); `None` for
    /// `conversation.add`, which gets no proof.
    pub fn proof_object(&self) -> Option<String> {
        Some(match self {
            ServiceTransition::Revoke { app_id, .. } | ServiceTransition::Leave { app_id, .. } => {
                zbase32_encode(app_id)
            }
            ServiceTransition::ConversationAdd { .. } => return None,
            other => other.type_name().to_owned(),
        })
    }

    /// The body as a JSON value, members sorted by name.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("type".into(), self.type_name().into());
        let at = match self {
            ServiceTransition::Revoke { app_id, at } | ServiceTransition::Leave { app_id, at } => {
                m.insert("app_id".into(), zbase32_encode(app_id).into());
                at
            }
            ServiceTransition::Freeze {
                freeze_hash,
                next_generation,
                inbox,
                at,
            } => {
                m.insert("freeze_hash".into(), b64(freeze_hash).into());
                m.insert("next_generation".into(), (*next_generation).into());
                m.insert(
                    "inbox".into(),
                    json!({ "url": inbox.url, "service_key": b64(&inbox.service_key) }),
                );
                at
            }
            ServiceTransition::Unfreeze { freeze_hash, at } => {
                m.insert("freeze_hash".into(), b64(freeze_hash).into());
                at
            }
            ServiceTransition::Recovery { recovery_from, at } => {
                m.insert("recovery_from".into(), (*recovery_from).into());
                at
            }
            ServiceTransition::Admission { at } => {
                m.insert("by".into(), "signer".into());
                at
            }
            ServiceTransition::Upload {
                by,
                changes,
                proofs,
                at,
            } => {
                m.insert("by".into(), zbase32_encode(by).into());
                m.insert("changes".into(), changes.clone());
                m.insert("proofs".into(), (*proofs).into());
                at
            }
            ServiceTransition::ConversationAdd {
                pubky,
                code_hash,
                context,
                at,
            } => {
                m.insert("pubky".into(), pubky_id(pubky).into());
                m.insert("code_hash".into(), b64(code_hash).into());
                m.insert("context".into(), context.clone());
                at
            }
        };
        m.insert("at".into(), rfc3339(*at).into());
        Value::Object(m)
    }

    /// The body's exact JSON bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if an opaque member can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.to_value())
            .map_err(|_| Error::Invalid("Switch wire 6.5: the transition can't be written".into()))
    }

    /// Read a transition body.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an unknown type or a malformed member.
    pub fn from_value(v: &Value) -> Result<Self> {
        let what = "a service transition";
        let at = req_time(v, "at", what)?;
        Ok(match req_str(v, "type", what)? {
            "revoke" => ServiceTransition::Revoke {
                app_id: req_app_id(v, "app_id", what)?,
                at,
            },
            "leave" => ServiceTransition::Leave {
                app_id: req_app_id(v, "app_id", what)?,
                at,
            },
            "freeze" => {
                let inbox = req(v, "inbox", what)?;
                ServiceTransition::Freeze {
                    freeze_hash: req_b64n::<32>(v, "freeze_hash", what)?,
                    next_generation: req_int(v, "next_generation", what)?,
                    inbox: Inbox::new(
                        req_str(inbox, "url", what)?,
                        req_b64n::<32>(inbox, "service_key", what)?,
                    ),
                    at,
                }
            }
            "unfreeze" => ServiceTransition::Unfreeze {
                freeze_hash: req_b64n::<32>(v, "freeze_hash", what)?,
                at,
            },
            "recovery" => ServiceTransition::Recovery {
                recovery_from: req_int(v, "recovery_from", what)?,
                at,
            },
            "admission" => {
                if req_str(v, "by", what)? != "signer" {
                    return invalid("Switch wire 6.5: an admission is by the signer");
                }
                ServiceTransition::Admission { at }
            }
            "upload" => ServiceTransition::Upload {
                by: req_app_id(v, "by", what)?,
                changes: req(v, "changes", what)?.clone(),
                proofs: req_int(v, "proofs", what)?,
                at,
            },
            "conversation.add" => ServiceTransition::ConversationAdd {
                pubky: req_pubky(v, "pubky", what)?,
                code_hash: req_b64n::<32>(v, "code_hash", what)?,
                context: v.get("context").cloned().unwrap_or(Value::Null),
                at,
            },
            _ => return invalid("Switch wire 6.5: an unknown service transition type"),
        })
    }

    /// Sign the transition with the service key over `lp("pubky-switch/v1/service-op",
    /// identity, body)` (Switch wire 6.5).
    ///
    /// # Errors
    ///
    /// As [`ServiceTransition::to_json`].
    pub fn sign(&self, service_key: &impl Signs, identity: &[u8; 32]) -> Result<SignedDoc> {
        let body = self.to_json()?;
        let sig = service_key.sign_fields(labels::sig::SERVICE_OP, &[identity, &body]);
        Ok(SignedDoc::from_parts(&body, &sig))
    }

    /// Verify a signed transition with the service key and read it (Switch wire 6.5).
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if it doesn't verify, [`Error::Invalid`] if it doesn't read.
    pub fn verify(signed: &SignedDoc, service_key: &[u8; 32], identity: &[u8; 32]) -> Result<Self> {
        let v: Value = signed.open(service_key, labels::sig::SERVICE_OP, &[identity])?;
        Self::from_value(&v)
    }
}

/// The resulting state a transition proof shows, by item (Switch wire 6.5).
#[derive(Clone, Debug, PartialEq)]
pub enum ProofState {
    /// `claim`: the claim view; `step` is the claim's step after the entry.
    Claim(Value),
    /// `record.put`: the record's new version, and whether the write deletes.
    Record {
        /// The new version, the write's (generation, `seq`).
        version: RecordVersion,
        /// The write is a delete.
        deleted: bool,
    },
    /// `allow.put`, `allow.delete`.
    Allow {
        /// The entry's kind.
        kind: crate::ops::AllowKind,
        /// Whether the entry is present after the operation.
        present: bool,
    },
    /// `deny.put`, `deny.delete`.
    Deny {
        /// Whether the Pubky ID is denied after the operation.
        denied: bool,
    },
    /// `invite_code.put`.
    InviteCodePut {
        /// The code's uses.
        max_uses: u64,
    },
    /// `invite_code.delete`.
    InviteCodeDelete,
    /// `app.put`.
    App {
        /// The App ID.
        app_id: [u8; 16],
    },
    /// `receive_key.put`: `version` is `n`.
    ReceiveKey {
        /// The registration number.
        n: u64,
        /// The kid.
        kid: [u8; 8],
    },
    /// `key_bundle.put`.
    KeyBundle {
        /// The stored part's number.
        bundle_seq: u64,
    },
    /// `cert.put`: the renewed certificate's document hash.
    Cert {
        /// The document hash.
        cert: [u8; 32],
    },
    /// An `identity.json` delivery: `version` is the document's.
    Identity {
        /// The document's version.
        version: u64,
        /// Its generation.
        generation: u64,
        /// Its data epoch.
        data_epoch: u64,
    },
    /// A service transition: its body.
    Service(Value),
}

impl ProofState {
    /// The proof's `state`, members sorted by name.
    pub fn to_value(&self) -> Value {
        match self {
            ProofState::Claim(view) => view.clone(),
            ProofState::Record { version, deleted } => json!({
                "generation": version.generation,
                "version": version.version,
                "deleted": deleted,
            }),
            ProofState::Allow { kind, present } => {
                json!({ "kind": kind.as_str(), "present": present })
            }
            ProofState::Deny { denied } => json!({ "denied": denied }),
            ProofState::InviteCodePut { max_uses } => json!({ "max_uses": max_uses, "uses": 0 }),
            ProofState::InviteCodeDelete => json!({ "withdrawn": true }),
            ProofState::App { app_id } => json!({ "app_id": zbase32_encode(app_id) }),
            ProofState::ReceiveKey { n, kid } => json!({ "n": n, "kid": b64(kid) }),
            ProofState::KeyBundle { bundle_seq } => json!({ "bundle_seq": bundle_seq }),
            ProofState::Cert { cert } => json!({ "cert": b64(cert) }),
            ProofState::Identity {
                version,
                generation,
                data_epoch,
            } => json!({ "version": version, "generation": generation, "data_epoch": data_epoch }),
            ProofState::Service(body) => body.clone(),
        }
    }

    /// The proof's `step` (claims) and `version` (records, receive keys, `identity.json`).
    pub fn step_and_version(&self) -> (Option<u64>, Option<u64>) {
        match self {
            ProofState::Claim(view) => (view.get("step").and_then(Value::as_u64), None),
            ProofState::Record { version, .. } => (None, Some(version.version)),
            ProofState::ReceiveKey { n, .. } => (None, Some(*n)),
            ProofState::Identity { version, .. } => (None, Some(*version)),
            _ => (None, None),
        }
    }
}

/// A transition proof's body (Switch wire 6.5).
#[derive(Clone, Debug, PartialEq)]
pub struct ProofBody {
    /// The item's chain stub.
    pub chain: Stub,
    /// The object the item changed.
    pub object: String,
    /// Claims: the claim's step after the entry.
    pub step: Option<u64>,
    /// The record's new version, the receive key's `n` or the document's version.
    pub version: Option<u64>,
    /// The resulting state.
    pub state: Value,
}

impl ProofBody {
    /// The body of a proof for the item at `chain`.
    pub fn new(chain: Stub, object: String, state: &ProofState) -> Self {
        let (step, version) = state.step_and_version();
        Self {
            chain,
            object,
            step,
            version,
            state: state.to_value(),
        }
    }

    /// The body's exact JSON bytes: `chain`, `object`, `step`, `version`, `state`, the
    /// state's members sorted by name.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if the state can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let state = serde_json::to_vec(&self.state)
            .map_err(|_| Error::Invalid("Switch wire 6.5: the state can't be written".into()))?;
        let mut o = Obj::new();
        o.raw("chain", &self.chain.to_json())
            .raw("object", quote(&self.object).as_bytes());
        if let Some(step) = self.step {
            o.int("step", step);
        }
        if let Some(version) = self.version {
            o.int("version", version);
        }
        o.raw("state", &state);
        Ok(o.finish())
    }

    fn from_value(v: &Value) -> Result<Self> {
        let what = "a transition proof";
        Ok(Self {
            chain: Stub::from_value(req(v, "chain", what)?)?,
            object: req_str(v, "object", what)?.to_owned(),
            step: crate::ops::read::opt_int(v, "step", what)?,
            version: crate::ops::read::opt_int(v, "version", what)?,
            state: req(v, "state", what)?.clone(),
        })
    }
}

/// A transition proof (Switch wire 6.5): a signed document of the service key over
/// `lp("pubky-switch/v1/proof", identity, body)`, whose stub has been read and whose chain
/// hash follows from its envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct TransitionProof {
    body: ProofBody,
    envelope: ChainEnvelope,
    signed: SignedDoc,
}

impl TransitionProof {
    /// Sign a proof with the service key.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if the stub doesn't read or the body can't be written.
    pub fn sign(service_key: &impl Signs, identity: &[u8; 32], body: ProofBody) -> Result<Self> {
        let envelope = body
            .chain
            .open()
            .map_err(|e| Error::Invalid(e.to_string()))?;
        let bytes = body.to_json()?;
        let sig = service_key.sign_fields(labels::sig::PROOF, &[identity, &bytes]);
        Ok(Self {
            body,
            envelope,
            signed: SignedDoc::from_parts(&bytes, &sig),
        })
    }

    /// Verify a proof with a service key and read it.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if it doesn't verify with the key, [`Error::Invalid`] if it
    /// doesn't read or its stub's chain hash doesn't follow.
    pub fn verify(signed: &SignedDoc, service_key: &[u8; 32], identity: &[u8; 32]) -> Result<Self> {
        let v: Value = signed.open(service_key, labels::sig::PROOF, &[identity])?;
        Self::read(signed, &v)
    }

    /// Read a proof without verifying its signature, as an app does to find the generation
    /// whose service key verifies it (Switch wire 6.2 step 2).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if it doesn't read.
    pub fn peek(signed: &SignedDoc) -> Result<Self> {
        let v: Value = signed.peek()?;
        Self::read(signed, &v)
    }

    fn read(signed: &SignedDoc, v: &Value) -> Result<Self> {
        let body = ProofBody::from_value(v)?;
        let envelope = body
            .chain
            .open()
            .map_err(|e| Error::Invalid(e.to_string()))?;
        Ok(Self {
            body,
            envelope,
            signed: signed.clone(),
        })
    }

    /// The body.
    pub fn body(&self) -> &ProofBody {
        &self.body
    }

    /// The stub's envelope.
    pub fn envelope(&self) -> &ChainEnvelope {
        &self.envelope
    }

    /// The signed document, in its exact bytes.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// Check that the proof is the given operation's (Switch wire 6.5 "Binding"): its stub's
    /// `item_hash` is the operation's, the stub is an operation's in the operation's batch
    /// and generation, and its `object` is the operation's.
    ///
    /// # Errors
    ///
    /// [`ChainError::Proof`] naming the mismatch, which is signed misbehaviour.
    pub fn check_binds(&self, op: &SignedOp) -> std::result::Result<(), ChainError> {
        let body = op.body();
        let item = op.item_hash().map_err(|e| ChainError::Proof(reason(e)))?;
        let env = &self.envelope;
        if env.item_type != ItemType::Op || env.item_hash != item {
            return Err(ChainError::Proof(
                "Switch wire 6.5: the proof's stub isn't the operation's".into(),
            ));
        }
        if env.batch != Some(body.batch) || env.generation != body.generation {
            return Err(ChainError::Proof(
                "Switch wire 6.6: the proof's stub isn't in the operation's batch".into(),
            ));
        }
        if body.kind.proof_object(body.app_id.as_ref()).as_deref()
            != Some(self.body.object.as_str())
        {
            return Err(ChainError::Proof(
                "Switch wire 6.5: the proof names another object".into(),
            ));
        }
        Ok(())
    }
}

/// Check the proofs of a `POST /ops` answer against the batch sent (Switch wire 6.5
/// "Binding"): one proof per signed operation, in order, or none for an unchanged batch,
/// whose every operation is of a type that can be unchanged; each verifies with the service
/// key and binds its operation. An answer without proofs is taken only for such a batch; the
/// writer, which knows what it delivered before, judges whether its operations were in fact
/// unchanged.
///
/// # Errors
///
/// [`ChainError::Proof`] or [`ChainError::Signature`]: the answer is unverified, so nothing
/// is acted on, and as a signed contradiction it is misbehaviour, handled as a rollback.
pub fn bind_answer(
    ops: &[SignedOp],
    proofs: &[SignedDoc],
    service_key: &[u8; 32],
    identity: &[u8; 32],
) -> std::result::Result<Vec<TransitionProof>, ChainError> {
    if proofs.is_empty() && !ops.is_empty() && ops.iter().all(|o| o.body().kind.can_be_unchanged())
    {
        return Ok(Vec::new());
    }
    if proofs.len() != ops.len() {
        return Err(ChainError::Proof(
            "Switch wire 6.5: one proof per signed operation".into(),
        ));
    }
    ops.iter()
        .zip(proofs)
        .map(|(op, signed)| {
            let proof = TransitionProof::verify(signed, service_key, identity)
                .map_err(|e| ChainError::Signature(reason(e)))?;
            proof.check_binds(op)?;
            Ok(proof)
        })
        .collect()
}

/// The checks before acting on an `attempt` (Switch wire 6.5 "Binding"): its proof, which
/// [`bind_answer`] bound, shows the claim's step one more than `expected_step`, a claim view
/// `ATTEMPTING` with the app's own owner and attempt, that attempt open, and a stub of the
/// generation the app's own `identity.json` names, stamped before the attempt's deadline.
///
/// # Errors
///
/// [`ChainError::Proof`]: the app writes the attempt `failed` when the proof binds the
/// operation but shows another state, and treats a stub stamped at or after the deadline as
/// misbehaviour (Switch wire 6.8 "Deadline").
pub fn check_attempt_proof(
    proof: &TransitionProof,
    entry: &crate::claims::ClaimEntry,
    app_id: &[u8; 16],
    generation: u64,
) -> std::result::Result<crate::claims::ClaimView, ChainError> {
    use crate::claims::{ClaimStatus, ClaimView, EntryKind, Outcome};
    let fail = |why: &str| Err(ChainError::Proof(format!("Switch wire 6.5: {why}")));
    if proof.envelope.generation != generation {
        return fail("the attempt's stub isn't of the identity's generation");
    }
    if let EntryKind::Attempt {
        deadline: Some(deadline),
        ..
    } = entry.kind
        && proof.envelope.server_time >= deadline
    {
        return fail("the attempt is stamped at or after its deadline");
    }
    if proof.body.step != entry.expected_step.checked_add(1) {
        return fail("the proof's step isn't one more than expected_step");
    }
    let view =
        ClaimView::from_value(&proof.body.state).map_err(|e| ChainError::Proof(reason(e)))?;
    let open = view
        .attempt(&entry.attempt_id)
        .is_some_and(|a| a.outcome == Outcome::Open && &a.owner == app_id);
    if view.status != ClaimStatus::Attempting
        || view.owner.as_ref() != Some(app_id)
        || view.attempt_id != Some(entry.attempt_id)
        || !open
        || view.claim_key != entry.claim_key
    {
        return fail("the claim view isn't the app's open attempt");
    }
    Ok(view)
}

/// A rule of the chain that a stub, a head or a proof broke (Switch wire 6.5 to 6.7). Every
/// one is evidence of a rollback or a fork, outside a declared provider loss (Switch spec
/// 10.1).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// A stub, head or proof that doesn't read.
    #[error("malformed: {0}")]
    Malformed(String),
    /// A chain version other than 1.
    #[error("Switch wire 6.6: chain version isn't 1 at seq {seq}")]
    ChainVersion {
        /// The stub's `seq`.
        seq: u64,
    },
    /// The chain hash doesn't follow from the envelope.
    #[error("Switch wire 6.6: the chain hash at seq {seq} doesn't follow from its envelope")]
    ChainHash {
        /// The stub's `seq`.
        seq: u64,
    },
    /// The `seq` isn't above the last one.
    #[error("Switch wire 6.6: seq {seq} isn't above the last one")]
    Seq {
        /// The stub's `seq`.
        seq: u64,
    },
    /// The stub doesn't extend the previous chain hash: a gap or a fork.
    #[error("Switch wire 6.6: seq {seq} doesn't extend the previous chain hash")]
    Link {
        /// The stub's `seq`.
        seq: u64,
    },
    /// The generation went back.
    #[error("Switch wire 6.6: the generation went back at seq {seq}")]
    Generation {
        /// The stub's `seq`.
        seq: u64,
    },
    /// A stub stamped earlier than the previous one.
    #[error("Switch wire 6.6: seq {seq} is stamped before the previous stub")]
    Stamp {
        /// The stub's `seq`.
        seq: u64,
    },
    /// A batch interrupted before its count: a partial batch.
    #[error("Switch wire 6.4: seq {seq} interrupts a batch before its count")]
    PartialBatch {
        /// The interrupting stub's `seq`.
        seq: u64,
        /// The batch interrupted.
        batch_id: [u8; 16],
    },
    /// A batch whose count is 0.
    #[error("Switch wire 6.6: a batch count of 0 at seq {seq}")]
    BatchCount {
        /// The stub's `seq`.
        seq: u64,
    },
    /// A new batch's ID repeats an earlier batch's within 30 days.
    #[error("Switch wire 6.6: a batch ID repeats within 30 days, at seq {seq}")]
    RepeatedBatchId {
        /// The stub's `seq`.
        seq: u64,
        /// The repeated ID.
        batch_id: [u8; 16],
    },
    /// The feed ends inside a batch.
    #[error("Switch wire 7.4.4: the feed ends inside a batch")]
    FeedEndsInBatch {
        /// The open batch.
        batch_id: [u8; 16],
    },
    /// A head with another chain hash than the chain at its `seq`.
    #[error("Switch wire 6.7: the head at seq {seq} doesn't match the chain")]
    Head {
        /// The head's `seq`.
        seq: u64,
    },
    /// A read that reached the end of the feed didn't reach a head the app has seen.
    #[error("Switch wire 6.7: a head is beyond the chain at the end of the feed")]
    HeadBeyondFeed {
        /// The head's `seq`.
        seq: u64,
    },
    /// A full item that doesn't match its stub's type and hash.
    #[error("Switch wire 6.6: the item at seq {seq} doesn't match its stub")]
    Item {
        /// The stub's `seq`.
        seq: u64,
    },
    /// A checkpoint that doesn't match the chain, or lies behind an accepted one.
    #[error("Switch wire 7.4.4: the checkpoint at seq {seq} doesn't match the chain")]
    Checkpoint {
        /// The checkpoint's `seq`.
        seq: u64,
    },
    /// A transition proof that doesn't bind what it answers.
    #[error("proof: {0}")]
    Proof(String),
    /// A signature of the service key that doesn't verify.
    #[error("signature: {0}")]
    Signature(String),
}

fn reason(error: Error) -> String {
    match error {
        Error::Invalid(why) | Error::Signature(why) | Error::Crypto(why) => why,
    }
}

/// The checks an app makes on the chain (Switch wire 6.6, 6.7, 7.4.4), stub by stub in feed
/// order, against the newest head it keeps.
///
/// It keeps the chain hash at each verified `seq` from the latest checkpoint on, the batch IDs
/// of the last 30 days of the chain by the stubs' service time, and the heads beyond the
/// verified chain until the stubs reach them.
#[derive(Clone, Debug, Default)]
pub struct Verifier {
    generation: u64,
    last_seq: u64,
    last_hash: [u8; 32],
    /// The previous stub's `server_time`; none right after continuing from a checkpoint.
    last_time: Option<u64>,
    /// The open batch: its ID, count and the items seen.
    open_batch: Option<(BatchRef, u64)>,
    /// The batch IDs within the window, each with its first stub's `server_time`.
    batches: HashMap<[u8; 16], u64>,
    /// The chain hash at each verified `seq` from the latest checkpoint on.
    at: BTreeMap<u64, [u8; 32]>,
    /// Heads beyond the verified chain.
    pending_heads: Vec<SignedHead>,
    /// The latest checkpoint accepted from the current service, 0 for none.
    checkpoint_seq: u64,
    /// The newest checkpoint accepted from any service, 0 for none: no chain hash is kept
    /// behind it.
    pruned_seq: u64,
    /// A checkpoint beyond the verified chain, accepted once the stubs reach it.
    pending_checkpoint: Option<SignedHead>,
    /// The highest `server_time` verified.
    highest_time: Option<u64>,
}

impl Verifier {
    /// A verifier for a chain of `generation` from its first item, after 32 zero bytes.
    pub fn new(generation: u64) -> Self {
        let mut v = Self {
            generation,
            ..Self::default()
        };
        v.at.insert(0, ZERO_HASH);
        v
    }

    /// A verifier that continues from a checkpoint head's `seq` and chain hash (Switch wire
    /// 7.4.4): there is no previous time, so the next stub's isn't compared. An app takes it
    /// only as an explicit recovery decision, in reconcile mode, or before its first read.
    pub fn from_checkpoint(checkpoint: &SignedHead) -> Self {
        let mut v = Self {
            generation: checkpoint.generation,
            last_seq: checkpoint.seq,
            last_hash: checkpoint.chain_hash,
            checkpoint_seq: checkpoint.seq,
            pruned_seq: checkpoint.seq,
            ..Self::default()
        };
        v.at.insert(checkpoint.seq, checkpoint.chain_hash);
        v
    }

    /// The generation followed.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The last verified `seq` and its chain hash.
    pub fn last(&self) -> (u64, [u8; 32]) {
        (self.last_seq, self.last_hash)
    }

    /// The highest service time verified, if any.
    pub fn highest_time(&self) -> Option<u64> {
        self.highest_time
    }

    /// The chain hash verified at `seq`, if the verifier keeps it.
    pub fn chain_hash_at(&self, seq: u64) -> Option<[u8; 32]> {
        self.at.get(&seq).copied()
    }

    /// Whether the verifier holds a batch ID in its window.
    pub fn holds_batch(&self, id: &[u8; 16]) -> bool {
        self.batches.contains_key(id)
    }

    /// The app follows a cooperative move to the next service (Switch wire 7.4.4): it
    /// compares checkpoints only with those it accepted from that service from now on. The
    /// chain, its hashes and the batch IDs go on.
    pub fn switch_service(&mut self) {
        self.checkpoint_seq = 0;
    }

    /// Check the next stub of the feed, in the order of Switch wire 6.6: its chain hash
    /// follows from its envelope; its `seq` is above the last one; its `prev_chain_hash` is
    /// the last chain hash; the generation doesn't go back; its `server_time` isn't before the
    /// previous stub's; a batch's items have consecutive `seq`s with one ID and count until
    /// `count` items are seen; and a new batch's ID isn't an earlier batch's whose first stub
    /// is less than 30 days older. Heads waiting for this `seq` are checked against it.
    ///
    /// # Errors
    ///
    /// The [`ChainError`] of the first rule that fails.
    pub fn push(&mut self, stub: &Stub) -> std::result::Result<ChainEnvelope, ChainError> {
        let env = stub.open()?;
        let seq = env.seq;
        if env.chain_version != CHAIN_VERSION {
            return Err(ChainError::ChainVersion { seq });
        }
        if seq <= self.last_seq {
            return Err(ChainError::Seq { seq });
        }
        if env.prev_chain_hash != self.last_hash {
            return Err(ChainError::Link { seq });
        }
        if env.generation < self.generation {
            return Err(ChainError::Generation { seq });
        }
        if self.last_time.is_some_and(|prev| env.server_time < prev) {
            return Err(ChainError::Stamp { seq });
        }
        match (self.open_batch, env.batch) {
            (Some((open, seen)), Some(batch))
                if open == batch && self.last_seq.checked_add(1) == Some(seq) =>
            {
                let seen = seen.saturating_add(1);
                self.open_batch = (seen < open.count).then_some((open, seen));
            }
            (Some((open, _)), _) => {
                return Err(ChainError::PartialBatch {
                    seq,
                    batch_id: open.id,
                });
            }
            (None, Some(batch)) => {
                let t = env.server_time;
                // Stamps never go back, so an ID the window has passed is beyond the window of
                // every later batch too: forget it.
                self.batches
                    .retain(|_, first| t.saturating_sub(*first) < BATCH_ID_WINDOW_MS);
                if self.batches.contains_key(&batch.id) {
                    return Err(ChainError::RepeatedBatchId {
                        seq,
                        batch_id: batch.id,
                    });
                }
                if batch.count == 0 {
                    return Err(ChainError::BatchCount { seq });
                }
                self.batches.insert(batch.id, t);
                if batch.count > 1 {
                    self.open_batch = Some((batch, 1));
                }
            }
            (None, None) => {}
        }
        self.generation = env.generation;
        self.last_seq = seq;
        self.last_hash = stub.chain_hash;
        self.last_time = Some(env.server_time);
        self.highest_time = Some(
            self.highest_time
                .map_or(env.server_time, |h| h.max(env.server_time)),
        );
        self.at.insert(seq, stub.chain_hash);
        if let Some(checkpoint) = self.pending_checkpoint.take() {
            if seq < checkpoint.seq {
                self.pending_checkpoint = Some(checkpoint);
            } else if seq == checkpoint.seq && stub.chain_hash == checkpoint.chain_hash {
                self.accept_checkpoint(checkpoint.seq);
            } else {
                return Err(ChainError::Checkpoint {
                    seq: checkpoint.seq,
                });
            }
        }
        for head in std::mem::take(&mut self.pending_heads) {
            self.head(head)?;
        }
        Ok(env)
    }

    /// Check a full item against its stub's envelope (Switch wire 6.6): the same item type
    /// and item hash, else it is a rollback and the app doesn't act on it.
    ///
    /// # Errors
    ///
    /// [`ChainError::Item`].
    pub fn check_item(
        envelope: &ChainEnvelope,
        item_type: ItemType,
        item_bytes: &[u8],
    ) -> std::result::Result<(), ChainError> {
        if envelope.item_type != item_type || item_hash(item_type, item_bytes) != envelope.item_hash
        {
            return Err(ChainError::Item { seq: envelope.seq });
        }
        Ok(())
    }

    /// Take a head whose signature the caller verified (Switch wire 6.7): one at or before the
    /// verified chain must match its chain hash there; one beyond waits for the stubs. Heads
    /// at or before an accepted checkpoint are no longer compared.
    ///
    /// # Errors
    ///
    /// [`ChainError::Head`] for a head that doesn't match the chain: a rollback or a fork.
    pub fn head(&mut self, head: SignedHead) -> std::result::Result<(), ChainError> {
        if self.pruned_seq > 0 && head.seq <= self.pruned_seq {
            return Ok(());
        }
        if head.seq <= self.last_seq {
            if self.at.get(&head.seq) != Some(&head.chain_hash) {
                return Err(ChainError::Head { seq: head.seq });
            }
        } else if !self.pending_heads.contains(&head) {
            self.pending_heads.push(head);
        }
        Ok(())
    }

    /// A read that reached the end of the feed (Switch wire 6.7, 7.4.4): a batch still open
    /// or a head beyond the chain is a rollback.
    ///
    /// # Errors
    ///
    /// [`ChainError::FeedEndsInBatch`] or [`ChainError::HeadBeyondFeed`].
    pub fn end_of_feed(&self) -> std::result::Result<(), ChainError> {
        if let Some((open, _)) = self.open_batch {
            return Err(ChainError::FeedEndsInBatch { batch_id: open.id });
        }
        if let Some(head) = self.pending_heads.first() {
            return Err(ChainError::HeadBeyondFeed { seq: head.seq });
        }
        Ok(())
    }

    /// Take a checkpoint whose signature the caller verified, from a feed page (Switch wire
    /// 7.4.4): behind the one accepted before from the same service it is a rollback; at or
    /// behind the verified chain it must match the chain hash there, unless it lies behind a
    /// checkpoint accepted from an earlier service, where no hash is kept; beyond it, it waits
    /// until the stubs reach its `seq`. Accepting one drops the chain hashes behind it; batch
    /// IDs don't follow checkpoints.
    ///
    /// What an app does when the stubs never reach a checkpoint beyond its position is its
    /// recovery decision (Switch wire 7.4.4), which this verifier doesn't make.
    ///
    /// # Errors
    ///
    /// [`ChainError::Checkpoint`].
    pub fn checkpoint(&mut self, checkpoint: SignedHead) -> std::result::Result<(), ChainError> {
        let seq = checkpoint.seq;
        if seq < self.checkpoint_seq {
            return Err(ChainError::Checkpoint { seq });
        }
        if seq <= self.last_seq {
            if seq < self.pruned_seq {
                self.checkpoint_seq = seq;
                return Ok(());
            }
            if self.at.get(&seq) != Some(&checkpoint.chain_hash) {
                return Err(ChainError::Checkpoint { seq });
            }
            self.accept_checkpoint(seq);
        } else {
            self.pending_checkpoint = Some(checkpoint);
        }
        Ok(())
    }

    fn accept_checkpoint(&mut self, seq: u64) {
        self.checkpoint_seq = seq;
        self.pruned_seq = seq;
        self.at = self.at.split_off(&seq);
        self.pending_heads.retain(|h| h.seq > seq);
    }

    /// The verifier's whole state, as plain data an app persists between runs, so that
    /// rollback detection survives a restart (Switch spec 10.1).
    pub fn state(&self) -> VerifierState {
        VerifierState {
            generation: self.generation,
            last_seq: self.last_seq,
            last_hash: self.last_hash,
            last_time: self.last_time,
            open_batch: self.open_batch,
            batches: self.batches.iter().map(|(id, t)| (*id, *t)).collect(),
            at: self.at.clone(),
            pending_heads: self.pending_heads.clone(),
            checkpoint_seq: self.checkpoint_seq,
            pruned_seq: self.pruned_seq,
            pending_checkpoint: self.pending_checkpoint,
            highest_time: self.highest_time,
        }
    }

    /// A verifier with a state [`Verifier::state`] gave, as an app reloads it. A state the
    /// app builds itself, such as an anchor at its own first registration (Switch spec
    /// 8.3), is taken as given: where it starts verifying is the app's own decision.
    pub fn from_state(state: VerifierState) -> Self {
        Self {
            generation: state.generation,
            last_seq: state.last_seq,
            last_hash: state.last_hash,
            last_time: state.last_time,
            open_batch: state.open_batch,
            batches: state.batches.into_iter().collect(),
            at: state.at,
            pending_heads: state.pending_heads,
            checkpoint_seq: state.checkpoint_seq,
            pruned_seq: state.pruned_seq,
            pending_checkpoint: state.pending_checkpoint,
            highest_time: state.highest_time,
        }
    }
}

/// The state of a [`Verifier`] as plain data (Switch wire 6.6, 6.7, 7.4.4), for an app to
/// persist and reload. It holds no secret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifierState {
    /// The generation followed.
    pub generation: u64,
    /// The last verified `seq`.
    pub last_seq: u64,
    /// Its chain hash.
    pub last_hash: [u8; 32],
    /// The last verified stub's `server_time`; `None` right after continuing from a
    /// checkpoint or an anchor.
    pub last_time: Option<u64>,
    /// The open batch and the number of its items seen.
    pub open_batch: Option<(BatchRef, u64)>,
    /// The batch IDs within the 30-day window, each with its first stub's `server_time`.
    pub batches: BTreeMap<[u8; 16], u64>,
    /// The chain hash at each verified `seq` from the latest checkpoint on.
    pub at: BTreeMap<u64, [u8; 32]>,
    /// Heads beyond the verified chain, waiting for the stubs to reach them.
    pub pending_heads: Vec<SignedHead>,
    /// The latest checkpoint accepted from the current service, 0 for none.
    pub checkpoint_seq: u64,
    /// The newest checkpoint accepted from any service, 0 for none: no chain hash is kept
    /// behind it.
    pub pruned_seq: u64,
    /// A checkpoint beyond the verified chain, accepted once the stubs reach it.
    pub pending_checkpoint: Option<SignedHead>,
    /// The highest `server_time` verified.
    pub highest_time: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKey;
    use ed25519_dalek::SigningKey;

    const START: u64 = 1_767_225_600_000;

    fn service() -> SigningKey {
        SigningKey::from_bytes(&[5; 32])
    }

    fn identity() -> [u8; 32] {
        IdentityKey::from_secret([1; 32]).public()
    }

    /// A chain of items, each a batch of `counts[i]` operations or an identity delivery for
    /// `None`, at the given times and batch IDs.
    /// A batch's ID and count, or `None` for an identity delivery, and the item's time.
    type Item = (Option<([u8; 16], u64)>, u64);

    fn chain(items: &[Item]) -> (Vec<Stub>, ChainTip) {
        let mut tip = ChainTip {
            generation: 1,
            seq: 0,
            chain_hash: ZERO_HASH,
        };
        let mut stubs = Vec::new();
        let mut seq = 0;
        for (batch, time) in items {
            match batch {
                None => {
                    seq += 1;
                    let (stub, next) = tip
                        .append(seq, *time, ItemType::Identity, [seq as u8; 32], None)
                        .unwrap();
                    stubs.push(stub);
                    tip = next;
                }
                Some((id, count)) => {
                    for _ in 0..*count {
                        seq += 1;
                        let batch = BatchRef {
                            id: *id,
                            count: *count,
                        };
                        let (stub, next) = tip
                            .append(seq, *time, ItemType::Op, [seq as u8; 32], Some(batch))
                            .unwrap();
                        stubs.push(stub);
                        tip = next;
                    }
                }
            }
        }
        (stubs, tip)
    }

    #[test]
    fn test_chain_envelope_round_trips_in_wire_order() {
        let env = ChainEnvelope {
            chain_version: 1,
            generation: 1,
            seq: 7,
            prev_chain_hash: [1; 32],
            server_time: START,
            item_type: ItemType::Op,
            item_hash: [2; 32],
            batch: Some(BatchRef {
                id: [3; 16],
                count: 2,
            }),
        };
        let text = String::from_utf8(env.to_json()).unwrap();
        assert!(
            text.starts_with("{\"chain_version\":1,\"generation\":1,\"seq\":7,\"prev_chain_hash\"")
        );
        assert!(text.ends_with("\"batch_count\":2}"));
        assert_eq!(ChainEnvelope::parse(text.as_bytes()).unwrap(), env);
        let no_batch = ChainEnvelope { batch: None, ..env };
        assert!(
            ChainEnvelope::parse(&no_batch.to_json()).is_err(),
            "an op needs its batch"
        );
        let identity_item = ChainEnvelope {
            item_type: ItemType::Identity,
            ..env
        };
        assert!(ChainEnvelope::parse(&identity_item.to_json()).is_err());
    }

    #[test]
    fn test_chain_tip_links_and_refuses_a_seq_not_above() {
        let (stubs, tip) = chain(&[(None, START), (Some(([1; 16], 2)), START)]);
        assert_eq!(tip.seq, 3);
        let second = stubs[1].open().unwrap();
        assert_eq!(second.prev_chain_hash, stubs[0].chain_hash);
        assert!(
            tip.append(3, START, ItemType::Identity, [0; 32], None)
                .is_err()
        );
        assert!(tip.append(4, START, ItemType::Op, [0; 32], None).is_err());
        let mut forged = stubs[0].clone();
        forged.chain_hash[0] ^= 1;
        assert_eq!(forged.open().unwrap_err(), ChainError::ChainHash { seq: 1 });
    }

    #[test]
    fn test_signed_head_signs_verifies_and_travels_as_a_header() {
        let (_, tip) = chain(&[(None, START)]);
        let head = SignedHead::sign(&service(), &identity(), &tip);
        let key = service().verifying_key().to_bytes();
        head.verify(&key, &identity()).unwrap();
        assert_eq!(SignedHead::from_header(&head.to_header()).unwrap(), head);
        let mut forged = head;
        forged.seq += 1;
        assert!(forged.verify(&key, &identity()).is_err());
        let other = IdentityKey::from_secret([2; 32]).public();
        assert!(head.verify(&key, &other).is_err());
    }

    #[test]
    fn test_verifier_takes_an_honest_chain_with_a_gap_in_seqs() {
        let (mut stubs, _) = chain(&[(None, START), (Some(([1; 16], 2)), START + 1)]);
        // A gap in seqs (an inbox entry) is fine when the link holds.
        let env = stubs[2].open().unwrap();
        let mut tip = ChainTip {
            generation: 1,
            seq: env.seq,
            chain_hash: stubs[2].chain_hash,
        };
        let (late, next) = tip
            .append(5, START + 2, ItemType::Identity, [9; 32], None)
            .unwrap();
        tip = next;
        stubs.push(late);
        let mut v = Verifier::new(1);
        for s in &stubs {
            v.push(s).unwrap();
        }
        v.end_of_feed().unwrap();
        assert_eq!(v.last(), (5, tip.chain_hash));
        assert_eq!(v.highest_time(), Some(START + 2));
    }

    #[test]
    fn test_verifier_refuses_a_broken_link() {
        let (stubs, _) = chain(&[(None, START), (None, START), (None, START)]);
        let mut v = Verifier::new(1);
        v.push(&stubs[0]).unwrap();
        assert_eq!(v.push(&stubs[2]).unwrap_err(), ChainError::Link { seq: 3 });
        let mut again = Verifier::new(1);
        again.push(&stubs[0]).unwrap();
        assert_eq!(
            again.push(&stubs[0]).unwrap_err(),
            ChainError::Seq { seq: 1 }
        );
    }

    #[test]
    fn test_verifier_refuses_a_stub_stamped_earlier() {
        let (stubs, _) = chain(&[(None, START + 5), (None, START)]);
        let mut v = Verifier::new(1);
        v.push(&stubs[0]).unwrap();
        assert_eq!(v.push(&stubs[1]).unwrap_err(), ChainError::Stamp { seq: 2 });
    }

    #[test]
    fn test_verifier_refuses_partial_and_cut_off_batches() {
        // A batch of 3 whose third item never comes: an identity item interrupts it.
        let tip = ChainTip {
            generation: 1,
            seq: 0,
            chain_hash: ZERO_HASH,
        };
        let batch = Some(BatchRef {
            id: [1; 16],
            count: 3,
        });
        let (a, tip) = tip.append(1, START, ItemType::Op, [1; 32], batch).unwrap();
        let (b, tip) = tip.append(2, START, ItemType::Op, [2; 32], batch).unwrap();
        let (c, _) = tip
            .append(3, START, ItemType::Identity, [3; 32], None)
            .unwrap();
        let mut v = Verifier::new(1);
        v.push(&a).unwrap();
        v.push(&b).unwrap();
        assert_eq!(
            v.end_of_feed().unwrap_err(),
            ChainError::FeedEndsInBatch { batch_id: [1; 16] }
        );
        assert!(matches!(
            v.push(&c).unwrap_err(),
            ChainError::PartialBatch { seq: 3, .. }
        ));
    }

    #[test]
    fn test_verifier_batch_id_window_is_thirty_days_by_server_time() {
        let id = [4u8; 16];
        let at = |gap: u64| {
            let (stubs, _) = chain(&[(Some((id, 1)), START), (Some((id, 1)), START + gap)]);
            let mut v = Verifier::new(1);
            v.push(&stubs[0]).unwrap();
            v.push(&stubs[1])
        };
        assert!(matches!(
            at(BATCH_ID_WINDOW_MS - 1).unwrap_err(),
            ChainError::RepeatedBatchId { .. }
        ));
        assert!(at(BATCH_ID_WINDOW_MS).is_ok());
        assert!(at(BATCH_ID_WINDOW_MS + 1).is_ok());
    }

    #[test]
    fn test_verifier_heads_must_match_or_wait() {
        let (stubs, tip) = chain(&[(None, START), (None, START)]);
        let key = service();
        let mut v = Verifier::new(1);
        v.push(&stubs[0]).unwrap();
        // A head beyond the chain waits, and is a rollback if the feed ends before it.
        let ahead = SignedHead::sign(&key, &identity(), &tip);
        v.head(ahead).unwrap();
        assert_eq!(
            v.end_of_feed().unwrap_err(),
            ChainError::HeadBeyondFeed { seq: 2 }
        );
        v.push(&stubs[1]).unwrap();
        v.end_of_feed().unwrap();
        // A head at a verified seq with another hash is a fork.
        let forked = SignedHead::sign(
            &key,
            &identity(),
            &ChainTip {
                generation: 1,
                seq: 1,
                chain_hash: [7; 32],
            },
        );
        assert_eq!(v.head(forked).unwrap_err(), ChainError::Head { seq: 1 });
        // A head beyond that the stubs pass with another hash is refused when they reach it.
        let mut w = Verifier::new(1);
        w.push(&stubs[0]).unwrap();
        let wrong = SignedHead::sign(
            &key,
            &identity(),
            &ChainTip {
                generation: 1,
                seq: 2,
                chain_hash: [7; 32],
            },
        );
        w.head(wrong).unwrap();
        assert_eq!(w.push(&stubs[1]).unwrap_err(), ChainError::Head { seq: 2 });
        // The head before any item is the zero hash.
        let zero = SignedHead::sign(
            &key,
            &identity(),
            &ChainTip {
                generation: 1,
                seq: 0,
                chain_hash: ZERO_HASH,
            },
        );
        assert!(Verifier::new(1).head(zero).is_ok());
    }

    #[test]
    fn test_verifier_checkpoints() {
        let (stubs, _) = chain(&[(None, START), (None, START), (None, START), (None, START)]);
        let key = service();
        let at = |seq: u64, hash: [u8; 32]| {
            SignedHead::sign(
                &key,
                &identity(),
                &ChainTip {
                    generation: 1,
                    seq,
                    chain_hash: hash,
                },
            )
        };
        let mut v = Verifier::new(1);
        v.push(&stubs[0]).unwrap();
        v.push(&stubs[1]).unwrap();
        v.checkpoint(at(2, stubs[1].chain_hash)).unwrap();
        assert_eq!(v.chain_hash_at(1), None, "hashes behind it are dropped");
        assert_eq!(
            v.checkpoint(at(1, stubs[0].chain_hash)).unwrap_err(),
            ChainError::Checkpoint { seq: 1 }
        );
        // Beyond the verified chain: accepted once the stubs reach it with its hash.
        v.checkpoint(at(4, stubs[3].chain_hash)).unwrap();
        v.push(&stubs[2]).unwrap();
        v.push(&stubs[3]).unwrap();
        assert_eq!(v.chain_hash_at(3), None);
        // Continuing from a checkpoint compares no time for the next stub.
        let mut c = Verifier::from_checkpoint(&at(2, stubs[1].chain_hash));
        c.push(&stubs[2]).unwrap();
        let mut wrong = Verifier::new(1);
        wrong.push(&stubs[0]).unwrap();
        assert!(wrong.checkpoint(at(1, [9; 32])).is_err());
    }

    #[test]
    fn test_check_item_matches_its_stub() {
        let env = ChainEnvelope {
            chain_version: 1,
            generation: 1,
            seq: 1,
            prev_chain_hash: ZERO_HASH,
            server_time: START,
            item_type: ItemType::Identity,
            item_hash: item_hash(ItemType::Identity, b"doc"),
            batch: None,
        };
        assert!(Verifier::check_item(&env, ItemType::Identity, b"doc").is_ok());
        assert!(Verifier::check_item(&env, ItemType::Identity, b"other").is_err());
        assert!(Verifier::check_item(&env, ItemType::Service, b"doc").is_err());
    }

    #[test]
    fn test_service_transition_round_trips_sorted() {
        let t = ServiceTransition::Revoke {
            app_id: [1; 16],
            at: START,
        };
        let json = String::from_utf8(t.to_json().unwrap()).unwrap();
        assert!(json.starts_with("{\"app_id\":"), "{json}");
        assert!(json.ends_with("\"type\":\"revoke\"}"), "{json}");
        let signed = t.sign(&service(), &identity()).unwrap();
        let key = service().verifying_key().to_bytes();
        assert_eq!(
            ServiceTransition::verify(&signed, &key, &identity()).unwrap(),
            t
        );
        assert_eq!(t.proof_object(), Some(zbase32_encode(&[1; 16])));
        let add = ServiceTransition::ConversationAdd {
            pubky: identity(),
            code_hash: [2; 32],
            context: json!({"rate": 1.5}),
            at: START,
        };
        let signed = add.sign(&service(), &identity()).unwrap();
        assert_eq!(
            ServiceTransition::verify(&signed, &key, &identity()).unwrap(),
            add
        );
        assert_eq!(add.proof_object(), None);
        let admission = ServiceTransition::Admission { at: START };
        assert_eq!(admission.proof_object().as_deref(), Some("admission"));
        let mut odd = admission.to_value();
        odd["by"] = "app".into();
        assert!(ServiceTransition::from_value(&odd).is_err());
    }

    /// An attempt signed by the app, chained at seq 1, and its proof.
    fn attempt_and_proof(
        deadline: Option<u64>,
        stamped: u64,
    ) -> (SignedOp, TransitionProof, crate::claims::ClaimEntry) {
        use crate::claims::{
            ClaimEntry, ClaimLimits, ClaimTally, EntryContext, EntryKind, apply_entry,
        };
        use crate::keys::AppKeys;
        use crate::ops::{OpBody, OpKind};
        let app = AppKeys::from_secrets([2; 32], [3; 32]);
        let entry = ClaimEntry {
            claim_key: [8; 32],
            attempt_id: [9; 16],
            expected_step: 0,
            kind: EntryKind::Attempt {
                orphan_after: 60,
                deadline,
            },
        };
        let body = OpBody {
            identity: identity(),
            app_id: Some(app.app_id_bytes()),
            generation: 1,
            batch: BatchRef {
                id: [3; 16],
                count: 1,
            },
            conditions: Vec::new(),
            kind: OpKind::Claim(entry.fields()),
        };
        let op = SignedOp::sign(&app, body).unwrap();
        let tip = ChainTip {
            generation: 1,
            seq: 0,
            chain_hash: ZERO_HASH,
        };
        let (stub, _) = tip
            .append(
                1,
                stamped,
                ItemType::Op,
                op.item_hash().unwrap(),
                Some(op.body().batch),
            )
            .unwrap();
        let current = |_: &[u8; 16]| true;
        let cx = EntryContext {
            writer: app.app_id_bytes(),
            now: stamped,
            can_read: true,
            is_current: &current,
            limits: ClaimLimits::default(),
            tally: ClaimTally::default(),
        };
        let view = apply_entry(None, &entry, &cx)
            .map(|c| c.view(&entry.claim_key, stamped, &current).to_value())
            .unwrap_or(Value::Null);
        let object = op
            .body()
            .kind
            .proof_object(op.body().app_id.as_ref())
            .unwrap();
        let proof = TransitionProof::sign(
            &service(),
            &identity(),
            ProofBody::new(stub, object, &ProofState::Claim(view)),
        )
        .unwrap();
        (op, proof, entry)
    }

    #[test]
    fn test_bind_answer_needs_one_bound_proof_per_operation() {
        let key = service().verifying_key().to_bytes();
        let (op, proof, _) = attempt_and_proof(None, START);
        let ops = vec![op.clone()];
        assert_eq!(
            bind_answer(&ops, &[proof.signed().clone()], &key, &identity())
                .unwrap()
                .len(),
            1
        );
        assert!(
            bind_answer(&ops, &[], &key, &identity()).is_err(),
            "an attempt is never unchanged"
        );
        let other = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
        assert!(matches!(
            bind_answer(&ops, &[proof.signed().clone()], &other, &identity()),
            Err(ChainError::Signature(_))
        ));
        // A proof of another operation doesn't bind.
        let (later, later_proof, _) = attempt_and_proof(Some(START + 5), START);
        assert!(later_proof.check_binds(&later).is_ok());
        assert!(matches!(
            proof.check_binds(&later),
            Err(ChainError::Proof(_))
        ));
    }

    #[test]
    fn test_check_attempt_proof_before_acting() {
        let app = crate::keys::AppKeys::from_secrets([2; 32], [3; 32]).app_id_bytes();
        let (_, proof, entry) = attempt_and_proof(Some(START + 10), START);
        let view = check_attempt_proof(&proof, &entry, &app, 1).unwrap();
        assert_eq!(view.owner, Some(app));
        // Another generation, another app, a stale step or a stamp at the deadline.
        assert!(check_attempt_proof(&proof, &entry, &app, 2).is_err());
        assert!(check_attempt_proof(&proof, &entry, &[0; 16], 1).is_err());
        let mut stale = entry;
        stale.expected_step = 1;
        assert!(check_attempt_proof(&proof, &stale, &app, 1).is_err());
        let (_, late, entry) = attempt_and_proof(Some(START), START);
        assert!(check_attempt_proof(&late, &entry, &app, 1).is_err());
    }

    #[test]
    fn test_verifier_state_round_trips_and_keeps_checking() {
        let id = [4; 16];
        let (stubs, _) = chain(&[(None, START), (Some((id, 2)), START + 1)]);
        let mut v = Verifier::new(1);
        v.push(&stubs[0]).unwrap();
        v.push(&stubs[1]).unwrap();
        // Saved inside the open batch: the reloaded verifier still needs its last item.
        let reloaded = Verifier::from_state(v.state());
        assert_eq!(reloaded.state(), v.state());
        assert!(reloaded.holds_batch(&id));
        assert!(reloaded.end_of_feed().is_err());
        let mut reloaded = reloaded;
        reloaded.push(&stubs[2]).unwrap();
        assert!(reloaded.end_of_feed().is_ok());
        // A reloaded verifier refuses what the original refuses: the same stub again.
        assert!(matches!(
            reloaded.push(&stubs[2]),
            Err(ChainError::Seq { .. })
        ));
    }

    #[test]
    fn test_transition_proof_signs_verifies_and_writes_its_order() {
        let (stubs, _) = chain(&[(None, START)]);
        let state = ProofState::Identity {
            version: 1,
            generation: 1,
            data_epoch: 1,
        };
        let body = ProofBody::new(stubs[0].clone(), "identity".into(), &state);
        let proof = TransitionProof::sign(&service(), &identity(), body).unwrap();
        let text = String::from_utf8(proof.signed().body_bytes().unwrap()).unwrap();
        assert!(
            text.contains("\"object\":\"identity\",\"version\":1,\"state\":{\"data_epoch\":1"),
            "{text}"
        );
        let key = service().verifying_key().to_bytes();
        let read = TransitionProof::verify(proof.signed(), &key, &identity()).unwrap();
        assert_eq!(read.envelope().seq, 1);
        let other = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
        assert!(TransitionProof::verify(proof.signed(), &other, &identity()).is_err());
        assert!(TransitionProof::peek(proof.signed()).is_ok());
    }
}
