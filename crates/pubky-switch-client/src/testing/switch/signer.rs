//! The signer's calls at the scripted switch: enrollment (Switch wire 3.7, 7.4.1), the
//! `identity.json` delivery (Switch wire 3.3, 7.4.2) and the app list (Switch wire 7.4.12).
//! The delivery is judged by the core's `check_delivery`, the rule the service applies.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use pubky_switch_core::chain::{ItemType, ProofState, item_hash};
use pubky_switch_core::enc::{b64, zbase32_encode};
use pubky_switch_core::http::{ErrorCode, IdentityDelivery};
use pubky_switch_core::json::parse_json;
use pubky_switch_core::records::{
    AccountView, Delivery, DeliveryRefusal, Enrollment, EnrollmentAnswer, IdentityDoc, KeptProofs,
    Limits, check_delivery, needed_generations,
};
use pubky_switch_core::sig::SignedDoc;
use serde_json::{Value, json};

use super::{Answer, Inner, SWITCH_ORIGIN, ScriptedSwitch, bad};
use crate::clock::TestClock;
use crate::testing::ScriptError;

/// A generation and the service key that verifies its proofs (Switch wire 3.3).
type GenerationKey = (u64, [u8; 32]);

/// What an enrolled account holds of its enrollments (Switch wire 3.7).
#[derive(Clone, Debug, Default)]
pub(crate) struct Enrolled {
    /// The limits the answers announce.
    pub(crate) limits: Limits,
    /// The answer to each enrollment taken, by enrollment hash, so the same enrollment again
    /// gets the same answer.
    pub(crate) answers: HashMap<[u8; 32], Value>,
}

impl ScriptedSwitch {
    /// A switch at [`SWITCH_ORIGIN`] where `identity` has no account yet: every call is the
    /// operator's `404` until the signer enrolls (Switch wire 3.7, 7.4.1). The enrollment makes
    /// the account, staged, with the service key from `service_secret`.
    pub fn unenrolled(
        identity: &pubky_switch_core::keys::IdentityKey,
        service_secret: [u8; 32],
        clock: Arc<TestClock>,
    ) -> Arc<Self> {
        let switch = Self::new(identity, service_secret, clock);
        {
            let mut inner = switch.lock();
            inner.enrolled = None;
            inner.staged = true;
        }
        switch
    }

    /// The epoch ranges of the key bundle parts the switch holds for `app`, in order.
    pub fn bundles_of(&self, app: &[u8; 16]) -> Vec<(u64, u64)> {
        self.lock()
            .bundles
            .get(app)
            .map(|parts| {
                parts
                    .iter()
                    .map(|(part, _)| (part.first_epoch, part.last_epoch))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Forget the transition proof of the newest delivery, so a retry of it answers with no
    /// proof, as for a version the service took by enrollment or import (Switch wire 7.4.2).
    pub fn forget_delivery_proof(&self) {
        self.lock().delivery_proof = None;
    }

    /// The key bundle parts the switch holds for `app`, in order.
    pub fn bundle_parts_of(&self, app: &[u8; 16]) -> Vec<pubky_switch_core::ops::KeyBundlePut> {
        self.lock()
            .bundles
            .get(app)
            .map(|parts| parts.iter().map(|(part, _)| part.clone()).collect())
            .unwrap_or_default()
    }

    /// Announce `limits` at the enrollment that makes the account, in place of the defaults.
    pub fn set_enroll_limits(&self, limits: Limits) {
        self.lock().enroll_limits = limits;
    }

    /// The App IDs the account keeps for good from the enrollment that made it.
    pub fn kept_app_ids(&self) -> Vec<[u8; 16]> {
        self.lock().kept_app_ids.clone()
    }
}

impl Inner {
    /// `POST /v1/enroll` (Switch wire 3.7, 7.4.1).
    pub(super) fn enroll(
        &mut self,
        request: &crate::transport::Request,
    ) -> Result<Answer, ScriptError> {
        let identity = self.identity.public();
        let body: Value = match parse_json(&request.body) {
            Ok(value) => value,
            Err(_) => return Ok(bad(ErrorCode::BadRequest, "malformed body", json!(null))),
        };
        let Some(signed) = body
            .get("enrollment")
            .and_then(|e| serde_json::from_value::<SignedDoc>(e.clone()).ok())
        else {
            return Ok(bad(ErrorCode::BadRequest, "no enrollment", json!(null)));
        };
        let enrollment = match Enrollment::verify(&signed, &identity, SWITCH_ORIGIN) {
            Ok(enrollment) => enrollment,
            Err(_) => return Ok(bad(ErrorCode::BadRequest, "bad enrollment", json!(null))),
        };
        if self.enrolled.is_some() && self.doc.is_some() && !self.staged {
            // A serving account answers a pending key for the next generation (Switch wire
            // 3.7); the scripted switch doesn't change generations this way.
            return Ok(bad(
                ErrorCode::BadRequest,
                "scripted: no pending key at a serving account",
                json!(null),
            ));
        }
        let creating = self.enrolled.is_none();
        let limits = self.enroll_limits;
        let enrolled = self.enrolled.get_or_insert_with(|| Enrolled {
            limits,
            answers: HashMap::new(),
        });
        if let Some(answer) = enrolled.answers.get(&enrollment.hash()) {
            return Ok((200, answer.clone()));
        }
        let service_key = self.service.verifying_key().to_bytes();
        let answer = EnrollmentAnswer::new(&enrollment, service_key, enrolled.limits);
        let value: Value = serde_json::from_slice(&answer.to_json()?)?;
        enrolled.answers.insert(enrollment.hash(), value.clone());
        // The enrollment that makes the account names the App IDs it keeps for good; another
        // enrollment for an existing account changes nothing (Switch wire 3.7).
        if creating {
            let kept: BTreeSet<[u8; 16]> = enrollment.revoked_apps().iter().copied().collect();
            self.kept_app_ids = kept.into_iter().collect();
        }
        Ok((200, value))
    }

    /// Chain a delivered `identity.json` and hold it; returns the delivery's transition
    /// proof. A document naming this switch's service key makes a staged switch serve, and
    /// one at a later generation moves the chain on to it (Switch wire 6.5 "Import").
    pub(super) fn chain_identity(&mut self, doc: &IdentityDoc) -> Result<SignedDoc, ScriptError> {
        if doc.generation() > self.tip.generation {
            self.tip.generation = doc.generation();
        }
        if doc.inbox().service_key == self.service.verifying_key().to_bytes() {
            self.staged = false;
        }
        let bytes = doc.signed().doc_bytes()?;
        let hash = item_hash(ItemType::Identity, &bytes);
        let state = ProofState::Identity {
            version: doc.version(),
            generation: doc.generation(),
            data_epoch: doc.data_epoch(),
        };
        let proof = self.chain_item(
            ItemType::Identity,
            doc.signed().clone(),
            hash,
            None,
            "identity",
            &state,
            None,
        )?;
        for app in &doc.body().apps {
            self.listed_at_epoch
                .entry(app.app_id)
                .or_insert(doc.data_epoch());
        }
        self.doc = Some(doc.clone());
        self.delivery_proof = Some(proof.clone());
        self.directory_version += 1;
        Ok(proof)
    }

    /// `PUT /v1/{id}/identity` from the signer, judged by the core's rules (Switch wire 3.3,
    /// 7.4.2).
    pub(super) fn put_identity(&mut self, body: &[u8]) -> Result<Answer, ScriptError> {
        let Ok(delivery) = IdentityDelivery::parse(body) else {
            return Ok(bad(
                ErrorCode::BadRequest,
                "malformed delivery",
                json!(null),
            ));
        };
        let Ok(doc) = IdentityDoc::verify(&delivery.identity, &self.identity.public()) else {
            return Ok(bad(
                ErrorCode::BadRequest,
                "the document doesn't verify",
                json!(null),
            ));
        };
        let app_limit = self.enrolled.as_ref().map_or(0, |e| e.limits.app_limit);
        let kept = self.kept_app_ids.clone();
        let (records, claim_entries) = self.kept_proof_keys();
        let view = AccountView {
            held: self.doc.as_ref(),
            app_limit,
            staged: self.staged,
            origin: SWITCH_ORIGIN,
            pending_key: None,
            kept_app_ids: &kept,
            kept_proofs: KeptProofs {
                records: &records,
                claim_entries: &claim_entries,
            },
        };
        match check_delivery(&view, &doc, delivery.prev.as_ref()) {
            Ok(Delivery::New(_)) => {
                let proof = self.chain_identity(&doc)?;
                Ok((
                    200,
                    json!({ "proofs": [proof], "head": self.head().to_value() }),
                ))
            }
            Ok(Delivery::Retry) => {
                let proofs: Vec<&SignedDoc> = self.delivery_proof.iter().collect();
                Ok((
                    200,
                    json!({ "proofs": proofs, "head": self.head().to_value() }),
                ))
            }
            Err(DeliveryRefusal::BadRequest(why)) => {
                Ok(bad(ErrorCode::BadRequest, why, json!(null)))
            }
            Err(DeliveryRefusal::StaleIdentity(why)) => {
                let current = self.doc.as_ref().map_or(json!(null), |held| {
                    json!({ "version": held.version(), "generation": held.generation(),
                            "hash": b64(&held.hash()), "identity": held.signed() })
                });
                Ok(bad(ErrorCode::StaleIdentity, why, current))
            }
            Err(DeliveryRefusal::Conflict { proof_generations }) => Ok(bad(
                ErrorCode::Conflict,
                "a needed service key is left out",
                json!({ "proof_generations": proof_generations }),
            )),
        }
    }

    /// The newest data epoch through which `app` holds every key (Switch wire 7.4.12): the
    /// epoch of the first version that listed it, raised by each stored part that continues
    /// it, as if the app had fetched every part; `None` for an app never listed.
    fn keys_through(&self, app: &[u8; 16]) -> Option<u64> {
        let mut held = *self.listed_at_epoch.get(app)?;
        let mut ranges: Vec<(u64, u64)> = self
            .bundles
            .get(app)
            .map(|parts| {
                parts
                    .iter()
                    .map(|(p, _)| (p.first_epoch, p.last_epoch))
                    .collect()
            })
            .unwrap_or_default();
        ranges.sort_unstable();
        for (first, last) in ranges {
            if first <= held.saturating_add(1) {
                held = held.max(last);
            }
        }
        Some(held)
    }

    /// The kept proofs' generations, each with the key that verifies its proofs: an earlier
    /// generation's an import carried, else this switch's own (Switch wire 3.3 "Service
    /// keys"); held records' first, then live claims' entries'.
    fn kept_proof_keys(&self) -> (Vec<GenerationKey>, Vec<GenerationKey>) {
        let own = self.service.verifying_key().to_bytes();
        let keyed = |generations: Vec<u64>| -> Vec<GenerationKey> {
            generations
                .into_iter()
                .map(|g| (g, self.proof_keys.get(&g).copied().unwrap_or(own)))
                .collect()
        };
        let (records, entries) = self.shared.kept_proof_generations();
        (keyed(records), keyed(entries))
    }

    /// `GET /v1/{id}/apps` (Switch wire 7.4.12): every app the switch holds or the newest
    /// `identity.json` lists, the recovery in progress, the newest document, and the
    /// generations the kept proofs name but those the newest document declares lost. The
    /// scripted switch reports no last-seen times.
    pub(super) fn apps_answer(&self) -> Answer {
        let mut ids: BTreeSet<[u8; 16]> = self.apps.keys().copied().collect();
        if let Some(doc) = &self.doc {
            ids.extend(doc.body().apps.iter().map(|a| a.app_id));
        }
        let apps: Vec<Value> = ids
            .iter()
            .map(|id| {
                let held = self.apps.get(id);
                let departed = held.is_some_and(|a| a.departed);
                let listed = self
                    .doc
                    .as_ref()
                    .is_some_and(|d| d.listed_cert(id).is_some());
                let ranges: Vec<Value> = self
                    .bundles
                    .get(id)
                    .map(|parts| {
                        parts
                            .iter()
                            .map(|(part, _)| json!([part.first_epoch, part.last_epoch]))
                            .collect()
                    })
                    .unwrap_or_default();
                json!({
                    "app_id": zbase32_encode(id),
                    "current": listed && !departed,
                    "last_seen": null,
                    "revoked_at": null,
                    "departed_at": null,
                    "awaiting_rotation": false,
                    "open_attempts": [],
                    "unread_entries": 0,
                    "sole_target_unread": 0,
                    "record_cert": held.and_then(|a| a.cert.as_ref()).map(|c| b64(&c.hash())),
                    "record_at": held.and_then(|a| a.record_at).map(pubky_switch_core::time::rfc3339),
                    "lagging": false,
                    "keys_through": self.keys_through(id),
                    "full_bundle_requested": null,
                    "bundle_ranges": ranges,
                    "cert_expires_at": self
                        .checked_cert(id)
                        .map(|cert| pubky_switch_core::time::rfc3339(cert.expires_at())),
                })
            })
            .collect();
        let recovery = self.recovery_from.map(|from| {
            let declared_at = self.recovery_declared_at.unwrap_or_default();
            json!({ "recovery_from": from,
                    "declared_at": pubky_switch_core::time::rfc3339(declared_at),
                    "admission_staged": false })
        });
        let (records, entries) = self.shared.kept_proof_generations();
        let recovery_from = self.doc.as_ref().and_then(|d| d.body().recovery_from);
        let proof_generations = needed_generations(&records, &entries, recovery_from);
        let identity = self
            .doc
            .as_ref()
            .and_then(|doc| serde_json::to_value(doc.signed()).ok())
            .unwrap_or(Value::Null);
        (
            200,
            json!({ "apps": apps, "identity": identity, "recovery": recovery,
                    "proof_generations": proof_generations }),
        )
    }
}
