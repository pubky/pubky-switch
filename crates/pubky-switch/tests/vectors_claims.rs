//! `claims.json`, replayed on the service (Switch wire 6.4, 6.8, 7.4.8, 7.4.12, 9.3): every
//! row of the claim rules through `POST /ops`, `GET /claims` as the apps read it, the
//! revocation of two apps, the deletion of claims once their time has passed (7.3 step 4),
//! no-op batches with and without `cursor.set`, and the per-app claim limits on a switch of
//! their own.
//!
//! The account's `identity.json` names the service key the account draws, so it is built
//! here as the file describes, and the proofs aren't compared: the claim views and the error
//! answers are. Set `PUBKY_SWITCH_TEST_DATABASE_URL` to run them; see `store::testing`.

// Test helpers fail the test on any error.
#![allow(clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use pubky_switch::{http::Handler, limits::Limits};
use pubky_switch_core::{
    enc::{app_id_bytes, b64, pubky_id, unb64_array},
    http::IdentityDelivery,
    keys::IdentityKey,
    ops::{OpBody, OpsRequest, SignedOp},
    records::{Enrollment, EnrollmentBody, IdentityBody, IdentityDoc, Inbox, ListedApp},
    sig::SignedDoc,
};
use serde_json::{Value, json};
use support::*;

/// An app of `claims.json`.
struct ClaimsApp {
    id: String,
    key: SigningKey,
}

/// alice's stand-in: the account `claims.json` names, its apps, and the service's clock.
struct Account {
    id: String,
    key: SigningKey,
    apps: BTreeMap<String, ClaimsApp>,
    now: u64,
}

fn signed(value: &Value) -> SignedDoc {
    match value.as_str() {
        Some(text) => serde_json::from_str(text).expect("signed"),
        None => serde_json::from_value(value.clone()).expect("signed"),
    }
}

fn first16(seed: [u8; 32]) -> [u8; 16] {
    seed[..16].try_into().expect("16 bytes")
}

impl Account {
    fn path(&self, rest: &str) -> String {
        format!("/v1/{}/{rest}", self.id)
    }

    /// A request from app `name`, signed at the service's time.
    fn app_request(
        &self,
        name: &str,
        method: &str,
        path: &str,
        body: Vec<u8>,
    ) -> pubky_switch::http::SwitchRequest {
        let app = &self.apps[name];
        signed_request(
            &app.key,
            &self.id,
            Some(&app.id),
            method,
            path,
            body,
            self.now,
        )
    }

    /// One `claim` operation of `fields`, in a batch of its own with batch ID `batch_id`.
    fn claim_batch(&self, name: &str, fields: &Value, batch_id: [u8; 16]) -> Vec<u8> {
        let app = &self.apps[name];
        let mut body = json!({
            "identity": self.id,
            "app_id": app.id,
            "generation": 1,
            "batch": { "id": b64(&batch_id), "count": 1 },
            "op": "claim",
        });
        for (member, value) in fields.as_object().expect("op") {
            body[member] = value.clone();
        }
        let body = OpBody::parse(&serde_json::to_vec(&body).expect("json")).expect("op body");
        let op = SignedOp::sign(&app.key, body).expect("sign");
        OpsRequest::new(&[op], None).to_json()
    }
}

/// Enroll the account at `start_time`, deliver its `identity.json` listing apps A to E, and
/// register each app with its record and receive key.
async fn set_up(replay: &Replay, claims: &Value) -> Account {
    let identity =
        IdentityKey::from_secret(seed(claims["identity_seed_label"].as_str().expect("label")));
    let key = SigningKey::from_bytes(&seed(
        claims["identity_seed_label"].as_str().expect("label"),
    ));
    let id = pubky_id(&key.verifying_key().to_bytes());
    assert_eq!(id, claims["identity"].as_str().expect("identity"));
    let mut account = Account {
        id,
        key,
        apps: BTreeMap::new(),
        now: ms(claims["start_time"].as_str().expect("start")),
    };
    replay.clock.set_wall_ms(account.now);
    for (name, app) in claims["apps"].as_object().expect("apps") {
        let key = SigningKey::from_bytes(&seed(app["signing_seed_label"].as_str().expect("label")));
        let app_id = app_id_bytes(&key.verifying_key().to_bytes());
        assert_eq!(
            pubky_switch_core::enc::zbase32_encode(&app_id),
            app["app_id"].as_str().expect("app id"),
            "{name}'s signing seed"
        );
        account.apps.insert(
            name.clone(),
            ClaimsApp {
                id: app["app_id"].as_str().expect("id").to_string(),
                key,
            },
        );
    }

    // The enrollment, with the policy of the vectors' enrollment.
    let http = vectors("http.json");
    let vector = named(&http["requests"], "signer: enrollment");
    let template: Value = serde_json::from_slice(
        &pubky_switch_core::enc::unb64(vector["body_b64"].as_str().expect("body")).expect("b64"),
    )
    .expect("json");
    let template = signed(&template["enrollment"]);
    let mut fields: EnrollmentBody =
        serde_json::from_slice(&template.body_bytes().expect("body")).expect("enrollment");
    let identity_key = account.key.verifying_key().to_bytes();
    fields.identity = identity_key;
    fields.nonce = first16(seed("claims/enrollment/nonce"));
    fields.identity_doc = None;
    fields.revoked_apps = None;
    let policy = fields.policy;
    let enrollment = Enrollment::sign(&identity, fields).expect("enrollment");
    let body = serde_json::to_vec(&json!({ "enrollment": enrollment.signed() })).expect("json");
    let answer = replay
        .service
        .handle(signed_request(
            &account.key,
            &account.id,
            None,
            "POST",
            "/v1/enroll",
            body,
            account.now,
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "enrolled: {}",
        String::from_utf8_lossy(&answer.body)
    );
    let enrolled: Value = serde_json::from_slice(&answer.body).expect("json");
    let service_key =
        unb64_array::<32>(enrolled["service_key"].as_str().expect("key")).expect("key");

    // Version 1, listing A to E with their certificates, naming the drawn key.
    let mut body = IdentityBody::first(
        identity_key,
        first16(seed("claims/signer")),
        Inbox {
            url: ORIGIN.into(),
            service_key,
        },
        policy,
    );
    for app in claims["apps"].as_object().expect("apps").values() {
        let cert = signed(&app["cert"]);
        body.apps.push(ListedApp {
            app_id: pubky_switch_core::enc::app_id_decode(app["app_id"].as_str().expect("id"))
                .expect("app id"),
            cert: cert.doc_hash().expect("hash"),
        });
    }
    body.apps
        .sort_by_key(|app| pubky_switch_core::enc::zbase32_encode(&app.app_id));
    let doc = IdentityDoc::sign(&identity, body).expect("identity.json");
    let delivery = IdentityDelivery {
        identity: doc.signed().clone(),
        prev: None,
    }
    .to_json();
    let path = account.path("identity");
    let answer = replay
        .service
        .handle(signed_request(
            &account.key,
            &account.id,
            None,
            "PUT",
            &path,
            delivery,
            account.now,
        ))
        .await;
    assert_eq!(
        answer.status,
        200,
        "delivered: {}",
        String::from_utf8_lossy(&answer.body)
    );

    // Each app's registration batch.
    for (name, app) in claims["apps"].as_object().expect("apps") {
        let me = &account.apps[name];
        let batch_id = first16(seed(&format!("claims/register/{name}")));
        let ops = pubky_switch_core::ops::sign_batch(
            &me.key,
            &identity_key,
            Some(pubky_switch_core::enc::app_id_decode(&me.id).expect("id")),
            1,
            batch_id,
            vec![
                (
                    Vec::new(),
                    pubky_switch_core::ops::OpKind::AppPut {
                        record: signed(&app["registered_record"]),
                    },
                ),
                (
                    Vec::new(),
                    pubky_switch_core::ops::OpKind::ReceiveKeyPut {
                        record: signed(&app["registered_receive_key"]),
                    },
                ),
            ],
        )
        .expect("registration");
        let body = OpsRequest::new(&ops, None).to_json();
        let answer = replay
            .service
            .handle(account.app_request(name, "POST", &account.path("ops"), body))
            .await;
        assert_eq!(
            answer.status,
            200,
            "{name} registered: {}",
            String::from_utf8_lossy(&answer.body)
        );
    }
    account
}

fn json_of(answer: &pubky_switch::http::SwitchResponse) -> Value {
    serde_json::from_slice(&answer.body).unwrap_or(Value::Null)
}

/// An error answer as the vectors give it: status, code and `current`.
fn assert_error(step: &Value, answer: &pubky_switch::http::SwitchResponse) {
    let n = &step["n"];
    let expect = &step["expect"];
    let body = json_of(answer);
    assert_eq!(
        u64::from(answer.status),
        expect["status"].as_u64().expect("status"),
        "step {n}: {body}"
    );
    assert_eq!(body["code"], expect["code"], "step {n}: code");
    assert_eq!(body["current"], expect["current"], "step {n}: current");
}

/// `GET /claims/{claim_key}` as `reader` sees it, against the step's `expect`.
async fn assert_claim(
    replay: &Replay,
    account: &Account,
    reader: &str,
    claim_key: &str,
    step: &Value,
) {
    let path = account.path(&format!("claims/{claim_key}"));
    let answer = replay
        .service
        .handle(account.app_request(reader, "GET", &path, Vec::new()))
        .await;
    let expect = &step["expect"];
    if expect["status"] == 200 {
        let body = json_of(&answer);
        assert_eq!(answer.status, 200, "step {}: {body}", step["n"]);
        assert_eq!(
            body["claim"], expect["claim"],
            "step {}: the claim",
            step["n"]
        );
    } else {
        assert_error(step, &answer);
    }
}

/// Run `steps` on `account`, batch IDs from `batch_seed` and the step's number.
async fn run(
    replay: &Replay,
    claims: &Value,
    account: &mut Account,
    steps: &Value,
    batch_seed: impl Fn(u64) -> String,
) {
    let keys = &claims["claim_keys"];
    for step in steps.as_array().expect("steps") {
        let n = step["n"].as_u64().expect("n");
        match step["action"].as_str().expect("action") {
            "write" => {
                let name = step["app"].as_str().expect("app");
                let body = account.claim_batch(name, &step["op"], first16(seed(&batch_seed(n))));
                let answer = replay
                    .service
                    .handle(account.app_request(name, "POST", &account.path("ops"), body))
                    .await;
                if step["expect"]["status"] == 200 {
                    assert_eq!(
                        answer.status,
                        200,
                        "step {n}: {}",
                        String::from_utf8_lossy(&answer.body)
                    );
                    let claim_key = step["op"]["claim_key"].as_str().expect("claim key");
                    assert_claim(replay, account, "A", claim_key, step).await;
                } else {
                    assert_error(step, &answer);
                }
            }
            "read" => {
                let name = step["claim_key"].as_str().expect("claim");
                let claim_key = keys[name].as_str().expect("claim key");
                assert_claim(
                    replay,
                    account,
                    step["app"].as_str().expect("app"),
                    claim_key,
                    step,
                )
                .await;
            }
            "advance" => {
                account.now += step["seconds"].as_u64().expect("seconds") * 1000;
                replay.clock.set_wall_ms(account.now);
            }
            "revoke" => {
                let app = &account.apps[step["app"].as_str().expect("app")].id;
                let path = account.path(&format!("apps/{app}/revoke"));
                let answer = replay
                    .service
                    .handle(signed_request(
                        &account.key,
                        &account.id,
                        None,
                        "POST",
                        &path,
                        Vec::new(),
                        account.now,
                    ))
                    .await;
                assert_eq!(
                    u64::from(answer.status),
                    step["expect"]["status"].as_u64().expect("status"),
                    "step {n}: {}",
                    String::from_utf8_lossy(&answer.body)
                );
            }
            "noop_batch" | "app_put" => {
                let name = step["app"].as_str().expect("app");
                let body = step["request_body"]
                    .as_str()
                    .expect("body")
                    .as_bytes()
                    .to_vec();
                let answer = replay
                    .service
                    .handle(account.app_request(name, "POST", &account.path("ops"), body))
                    .await;
                if step["expect"]["status"] == 200 {
                    let body = json_of(&answer);
                    assert_eq!(answer.status, 200, "step {n}: {body}");
                    assert_eq!(
                        body["proofs"].as_array().map(Vec::len),
                        step["expect"]["proofs"]
                            .as_u64()
                            .map(|p| usize::try_from(p).expect("count")),
                        "step {n}: proofs"
                    );
                } else {
                    assert_error(step, &answer);
                }
            }
            other => panic!("step {n}: unknown action {other}"),
        }
    }
}

#[tokio::test]
async fn test_vectors_claims_replay() {
    let Some(replay) = replay().await else { return };
    let claims = vectors("claims.json");
    let mut account = set_up(&replay, &claims).await;
    run(&replay, &claims, &mut account, &claims["steps"], |n| {
        format!("claims/write/{n}")
    })
    .await;
    replay.db.drop_database().await.expect("drop");
}

#[tokio::test]
async fn test_vectors_claims_quota() {
    let claims = vectors("claims.json");
    let quota = &claims["quota"];
    let limits = Limits {
        max_claims: quota["limits"]["max_claims"].as_u64().expect("max_claims"),
        open_attempts_per_app: quota["limits"]["open_attempts_per_app"]
            .as_u64()
            .expect("open_attempts_per_app"),
        claim_share_percent: u8::try_from(
            quota["limits"]["claim_share_percent"]
                .as_u64()
                .expect("claim_share_percent"),
        )
        .expect("percent"),
        ..Limits::default()
    };
    let Some(replay) = replay_with(limits).await else {
        return;
    };
    let mut account = set_up(&replay, &claims).await;
    // The quota sequence names its own claim keys and attempts.
    let mut named_claims = claims.clone();
    named_claims["claim_keys"] = quota["claim_keys"].clone();
    run(&replay, &named_claims, &mut account, &quota["steps"], |n| {
        format!("claims/quota/batch/{}", n - 1)
    })
    .await;
    replay.db.drop_database().await.expect("drop");
}
