//! Shared and app record writes and conflicts through signed requests (Switch wire 6.1 and 7.6).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use pubky_switch_client::TransportError;
use pubky_switch_client::app::{App, AppConfig, ClaimOp, Protocol, RecordTarget};
use pubky_switch_client::client::{Batch, CheckedResponse, Credentials, SwitchClient};
use pubky_switch_client::error::ClientError;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::TestIdentity;
use pubky_switch_client::transport::{BoxFuture, Request, Response, TimeoutClass, Transport};
use pubky_switch_core::chain::{TransitionProof, bind_answer};
use pubky_switch_core::enc::{b64, pubky_id};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ident::{NamingKey, Policy, collection_id, record_key_from_blinded};
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::ops::{
    Condition, IdInputs, OpKind, OpsRequest, RecordPut, RecordVersion, SignedOp, sign_batch,
};
use pubky_switch_core::records::{AppRecord, AppRecordBody};
use pubky_switch_core::sealed::SealedValue;
use pubky_switch_core::shared::ApplicationRef;
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_harness::parties::{
    Asking, NOTES, notes_collection, notes_protocol, notes_protocol_with_records,
};
use pubky_switch_harness::{Backend, World};
use pubky_switch_signer::{Signer, UserConfirmed};
use serde_json::{Value, json};

const ORIGIN: &str = "https://switch.example";
const COLLECTION: &str = "example.items";

struct Writer {
    who: TestIdentity,
    keys: AppKeys,
    client: SwitchClient,
    epoch: u64,
    generation: u64,
    service_key: [u8; 32],
    signer: Signer,
    app: App,
}

async fn writer(world: &World) -> Writer {
    writer_with(world, notes_protocol()).await
}

async fn writer_with(world: &World, protocol: Arc<dyn Protocol>) -> Writer {
    let who = world.identity("alice").unwrap();
    world.add_switch(ORIGIN, &[&who]).await.unwrap();
    let mut signer = Box::pin(Signer::create(
        world
            .signer_env(&who, Arc::new(MemoryStore::new()))
            .unwrap(),
        world.keyring(&who).unwrap(),
        ORIGIN,
    ))
    .await
    .unwrap();
    Box::pin(signer.resume()).await.unwrap();
    let asking = Asking::new(world.app_keys(&who, "wallet").unwrap()).unwrap();
    let checked = signer
        .review(asking.request.signed(), &asking.auth)
        .unwrap();
    let approved = Box::pin(signer.approve(checked)).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    let mut app = Box::pin(App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        protocol,
        AppConfig::default(),
        asking.join_request(who.public(), &approved).unwrap(),
    ))
    .await
    .unwrap();
    Box::pin(app.receive(None)).await.unwrap();
    let service_key = app.own_identity().inbox().service_key;
    let client = SwitchClient::new(
        ORIGIN,
        who.public(),
        Credentials::App {
            identity: who.public(),
            keys: asking.keys.clone(),
            cert: app.cert().clone(),
        },
        Some(service_key),
        world.transport(),
        world.clock().clone(),
    )
    .unwrap();
    Writer {
        who,
        keys: asking.keys,
        client,
        epoch: app.data_epoch(),
        generation: app.own_identity().generation(),
        service_key,
        signer,
        app,
    }
}

impl Writer {
    fn put(&self, natural: &[u8], expected: RecordVersion, value: &[u8]) -> RecordPut {
        let identity = self.who.key();
        let naming = NamingKey::from_root(&identity.switch_root());
        let blinded_key = naming.blind(natural);
        let policy = Policy::new(NOTES, &[NOTES]);
        let key = record_key_from_blinded(COLLECTION, &blinded_key, &policy.hash().unwrap());
        RecordPut {
            key,
            collection: collection_id(COLLECTION, &self.who.public()),
            policy,
            expected_version: expected,
            value_sealed: SealedValue::seal(
                &identity.scope_key(self.epoch, NOTES),
                &self.who.public(),
                self.epoch,
                NOTES,
                &key,
                value,
            )
            .unwrap(),
            id_inputs: IdInputs {
                collection: COLLECTION.into(),
                blinded_key,
            },
        }
    }

    fn batch(&self, id: u8, entries: Vec<(Vec<Condition>, OpKind)>) -> Vec<SignedOp> {
        sign_batch(
            &self.keys,
            &self.who.public(),
            Some(self.keys.app_id_bytes()),
            self.generation,
            [id; 16],
            entries,
        )
        .unwrap()
    }

    async fn post(&self, ops: &[SignedOp]) -> Result<CheckedResponse, ClientError> {
        let path = format!("/v1/{}/ops", pubky_id(&self.who.public()));
        let request = self
            .client
            .sign_request(
                "POST",
                &path,
                OpsRequest::new(ops, None).to_json(),
                None,
                TimeoutClass::Bulk,
            )
            .unwrap();
        self.client.send(request).await
    }

    async fn get(&self, key: &[u8; 32]) -> CheckedResponse {
        let path = format!("/v1/{}/records/{}", pubky_id(&self.who.public()), b64(key));
        self.client
            .send(
                self.client
                    .sign_request("GET", &path, Vec::new(), None, TimeoutClass::Bulk)
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    fn proofs(&self, ops: &[SignedOp], answer: &CheckedResponse) -> Vec<ApplicationRef> {
        let proofs: Vec<SignedDoc> =
            serde_json::from_value(body(answer)["proofs"].clone()).unwrap();
        bind_answer(ops, &proofs, &self.service_key, &self.who.public())
            .unwrap()
            .into_iter()
            .map(|p| p.record_revision().unwrap())
            .collect()
    }

    async fn write(&self, id: u8, natural: &[u8], expected: RecordVersion, value: &[u8]) -> Value {
        let put = self.put(natural, expected, value);
        let key = put.key;
        let ops = self.batch(id, vec![(Vec::new(), OpKind::RecordPut(put))]);
        let answer = self.post(&ops).await.unwrap();
        let revision = self.proofs(&ops, &answer)[0];
        assert_eq!(revision.item_hash, ops[0].item_hash().unwrap());
        let view = body(&self.get(&key).await);
        assert_eq!(current(&view), revision);
        assert_eq!(view["deleted"], value.is_empty());
        view
    }
}

fn body(answer: &CheckedResponse) -> Value {
    serde_json::from_slice(&answer.body).unwrap()
}
fn current(view: &Value) -> ApplicationRef {
    ApplicationRef::parse(&serde_json::to_vec(&view["revision"]).unwrap()).unwrap()
}
fn version(view: &Value) -> RecordVersion {
    RecordVersion::new(
        view["generation"].as_u64().unwrap(),
        view["version"].as_u64().unwrap(),
    )
}
fn guard(key: [u8; 32], view: &Value) -> Condition {
    Condition::RecordCurrent {
        key,
        revision: current(view),
        deleted: view["deleted"].as_bool().unwrap(),
    }
}
fn conflict<T: std::fmt::Debug>(result: Result<T, ClientError>) -> Value {
    match result {
        Err(ClientError::Switch {
            status: 409,
            code: ErrorCode::Conflict,
            current,
            ..
        }) => current,
        other => panic!("expected authenticated conflict, got {other:?}"),
    }
}

async fn delete_repair(world: &World) {
    let w = Box::pin(writer(world)).await;
    let first = w.write(1, b"repair", RecordVersion::NONE, b"{}").await;
    let a = w.write(2, b"repair", version(&first), b"").await;
    let b = w.write(3, b"repair", version(&a), b"").await;
    let put = w.put(b"repair", version(&b), b"{\"repaired\":true}");
    let key = put.key;
    let before = w.get(&key).await;
    let stale = w.batch(
        4,
        vec![(vec![guard(key, &a)], OpKind::RecordPut(put.clone()))],
    );
    assert_eq!(conflict(w.post(&stale).await), json!({"record_view": b}));
    let refused = w.get(&key).await;
    assert_eq!(body(&refused), body(&before));
    assert_eq!(refused.head, before.head);
    let fresh = w.batch(5, vec![(vec![guard(key, &b)], OpKind::RecordPut(put))]);
    let applied = w.post(&fresh).await.unwrap();
    let reference = w.proofs(&fresh, &applied)[0];
    assert_eq!(reference.item_hash, fresh[0].item_hash().unwrap());
    assert_eq!(current(&body(&w.get(&key).await)), reference);
}

async fn pre_batch_and_atomicity(world: &World) {
    let w = Box::pin(writer(world)).await;
    let before = w.write(1, b"atomic", RecordVersion::NONE, b"{}").await;
    let put = w.put(b"atomic", version(&before), b"{\"n\":2}");
    let key = put.key;
    let ops = w.batch(
        2,
        vec![
            (Vec::new(), OpKind::RecordPut(put)),
            (
                vec![guard(key, &before)],
                OpKind::DenyPut { pubky: [30; 32] },
            ),
        ],
    );
    w.post(&ops).await.unwrap();
    let applied = w.get(&key).await;
    let view = body(&applied);
    assert_eq!(current(&view).item_hash, ops[0].item_hash().unwrap());
    let ops = w.batch(
        3,
        vec![
            (
                vec![guard(key, &view)],
                OpKind::RecordPut(w.put(b"atomic", version(&view), b"{\"n\":3}")),
            ),
            (
                Vec::new(),
                OpKind::RecordPut(w.put(b"missing", RecordVersion::new(w.generation, 99), b"{}")),
            ),
        ],
    );
    conflict(w.post(&ops).await);
    let refused = w.get(&key).await;
    assert_eq!(body(&refused), view);
    assert_eq!(refused.head, applied.head);
}

async fn retry_and_race(world: &World) {
    let w = Box::pin(writer(world)).await;
    let initial = w.write(1, b"retry", RecordVersion::NONE, b"{}").await;
    let put = w.put(b"retry", version(&initial), b"{\"n\":2}");
    let key = put.key;
    let a = w.batch(
        2,
        vec![(vec![guard(key, &initial)], OpKind::RecordPut(put.clone()))],
    );
    let b = w.batch(
        3,
        vec![(vec![guard(key, &initial)], OpKind::RecordPut(put))],
    );
    let (left, right) = tokio::join!(w.post(&a), w.post(&b));
    let (ops, original) = match (left, right) {
        (Ok(answer), refusal) => {
            conflict(refusal);
            (a, answer)
        }
        (refusal, Ok(answer)) => {
            conflict(refusal);
            (b, answer)
        }
        other => panic!("one guarded application must win: {other:?}"),
    };
    let won = body(&w.get(&key).await);
    assert_eq!(current(&won), w.proofs(&ops, &original)[0]);
    let later = w.write(4, b"retry", version(&won), b"{\"n\":3}").await;
    let before_retry = w.get(&key).await;
    let retry = w.post(&ops).await.unwrap();
    assert_eq!(body(&retry)["proofs"], body(&original)["proofs"]);
    assert_eq!(retry.head, before_retry.head);
    let after_retry = w.get(&key).await;
    assert_eq!(body(&after_retry), later);
    assert_eq!(after_retry.head, before_retry.head);
    let mut fresh = ops[0].body().clone();
    fresh.batch.id = [5; 16];
    conflict(w.post(&[SignedOp::sign(&w.keys, fresh).unwrap()]).await);
}

async fn lost_answer(world: &World) {
    let w = Box::pin(writer(world)).await;
    let initial = w.write(1, b"lost answer", RecordVersion::NONE, b"{}").await;
    let put = w.put(b"lost answer", version(&initial), b"{\"n\":2}");
    let key = put.key;
    let ops = w.batch(
        2,
        vec![(vec![guard(key, &initial)], OpKind::RecordPut(put))],
    );
    world.lose_answer("POST", "/ops");
    assert!(matches!(w.post(&ops).await, Err(ClientError::Transport(_))));
    assert_eq!(world.faults_left(), 0);
    let committed = w.get(&key).await;
    assert_eq!(
        current(&body(&committed)).item_hash,
        ops[0].item_hash().unwrap()
    );
    let retry = w.post(&ops).await.unwrap();
    assert_eq!(w.proofs(&ops, &retry)[0], current(&body(&committed)));
    assert_eq!(retry.head, committed.head);
    assert_eq!(body(&w.get(&key).await), body(&committed));
}

async fn upload(world: &World) {
    let mut w = Box::pin(writer(world)).await;
    let mut source = w.write(1, b"upload", RecordVersion::NONE, b"{}").await;
    for n in 2..=8 {
        source = w.write(n, b"upload", version(&source), b"{}").await;
    }
    let op: SignedOp =
        SignedOp::peek(&serde_json::from_value(source["op"].clone()).unwrap()).unwrap();
    let OpKind::RecordPut(put) = &op.body().kind else {
        panic!("record put")
    };
    let key = put.key;
    let lost = w.app.own_identity().signed().clone();
    let uploaded = json!({"op": op.signed(), "cert": w.app.cert().signed()});
    let old_version = version(&source);
    assert_ne!(op.item_hash().unwrap(), op.signed().doc_hash().unwrap());
    world.lose_switch(ORIGIN);
    let origin = "https://recovery.example";
    world.add_switch(origin, &[&w.who]).await.unwrap();
    Box::pin(
        w.signer
            .declare_provider_loss(origin, UserConfirmed::shown_and_confirmed()),
    )
    .await
    .unwrap();
    Box::pin(w.signer.end_staged_admission()).await.unwrap();
    Box::pin(w.app.refresh_identity()).await.unwrap();
    Box::pin(w.app.follow_provider()).await.unwrap();
    w.generation = w.app.own_identity().generation();
    w.epoch = w.app.data_epoch();
    w.service_key = w.app.own_identity().inbox().service_key;
    w.client = SwitchClient::new(
        origin,
        w.who.public(),
        Credentials::App {
            identity: w.who.public(),
            keys: w.keys.clone(),
            cert: w.app.cert().clone(),
        },
        Some(w.service_key),
        world.transport(),
        world.clock().clone(),
    )
    .unwrap();
    let path = format!("/v1/{}/recovery/upload", pubky_id(&w.who.public()));
    let send = |record: Value| {
        w.client
            .sign_request(
                "POST",
                &path,
                serde_json::to_vec(&json!({"lost_identity": lost, "records": [record]})).unwrap(),
                None,
                TimeoutClass::Bulk,
            )
            .unwrap()
    };
    // First the source alone supplies its lower bound; then the proof makes it exact.
    let first = w.client.send(send(uploaded.clone())).await.unwrap();
    let view = body(&w.get(&key).await);
    let transition: SignedDoc = serde_json::from_value(body(&first)["proof"].clone()).unwrap();
    let proof = TransitionProof::verify(&transition, &w.service_key, &w.who.public()).unwrap();
    assert_eq!(
        current(&view),
        ApplicationRef {
            generation: w.generation,
            seq: proof.envelope().seq,
            item_hash: op.item_hash().unwrap()
        }
    );
    assert_eq!(version(&view), old_version);
    assert_ne!(current(&view).generation, old_version.generation);
    assert_ne!(current(&view).seq, old_version.version);
    assert!(view.get("proof").is_none());
    let mut exact = uploaded.clone();
    exact["proof"] = source["proof"].clone();
    let answer = w.client.send(send(exact.clone())).await.unwrap();
    let made_exact = body(&w.get(&key).await);
    assert_eq!(current(&made_exact).seq, answer.head.as_ref().unwrap().seq);
    assert_ne!(current(&made_exact), current(&view));
    assert_eq!(version(&made_exact), old_version);
    // An unchanged upload still makes its own transition, but no record application.
    let again = w.client.send(send(exact)).await.unwrap();
    assert!(
        body(&again)["result"]["records"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(body(&w.get(&key).await), made_exact);
    let mut other = op.body().clone();
    other.batch.id = [65; 16];
    let other = SignedOp::sign(&w.keys, other).unwrap();
    assert_ne!(other.item_hash().unwrap(), op.item_hash().unwrap());
    let mut divergent = uploaded.clone();
    divergent["op"] = json!(other.signed());
    let answer = w.client.send(send(divergent)).await.unwrap();
    assert_eq!(body(&answer)["result"]["divergent"], json!([b64(&key)]));
    assert_eq!(current(&body(&w.get(&key).await)), current(&made_exact));
    let mut invalid = uploaded;
    invalid["op"]["sig"] = json!(b64(&[0; 64]));
    let answer = w.client.send(send(invalid)).await.unwrap();
    assert_eq!(body(&answer)["result"]["unverified"], 1);
    assert_eq!(current(&body(&w.get(&key).await)), current(&made_exact));
    // Over a record taken from an upload a write names it exactly: a bare version is
    // refused, since two uploads can share one.
    let held = body(&w.get(&key).await);
    let bare = w.batch(
        9,
        vec![(
            Vec::new(),
            OpKind::RecordPut(w.put(b"upload", old_version, b"{\"new\":true}")),
        )],
    );
    assert_eq!(
        conflict(w.post(&bare).await)["record"]["version"],
        held["version"]
    );
    let named = w.batch(
        10,
        vec![(
            vec![guard(key, &held)],
            OpKind::RecordPut(w.put(b"upload", old_version, b"{\"new\":true}")),
        )],
    );
    w.post(&named).await.unwrap();
    let own = body(&w.get(&key).await);
    assert_eq!(current(&own).generation, w.generation);
    assert_eq!(current(&own).seq, version(&own).version);
    assert_ne!(current(&own).item_hash, current(&made_exact).item_hash);
}

/// Capture what reaches the transport while the selected switch handles and signs the answer.
struct BatchTransport {
    inner: Arc<dyn Transport>,
    sent: Mutex<Vec<(TimeoutClass, Vec<u8>)>>,
}

impl Transport for BatchTransport {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        self.sent
            .lock()
            .unwrap()
            .push((request.timeout, request.body.clone()));
        self.inner.send(request)
    }
}

fn recording_client(world: &World, w: &Writer) -> (SwitchClient, Arc<BatchTransport>) {
    let transport = Arc::new(BatchTransport {
        inner: world.transport(),
        sent: Mutex::default(),
    });
    let client = SwitchClient::new(
        ORIGIN,
        w.who.public(),
        Credentials::App {
            identity: w.who.public(),
            keys: w.keys.clone(),
            cert: w.app.cert().clone(),
        },
        Some(w.service_key),
        transport.clone(),
        world.clock().clone(),
    )
    .unwrap();
    (client, transport)
}

async fn app_record_timeouts(world: &World) {
    let w = Box::pin(writer(world)).await;
    let (client, transport) = recording_client(world, &w);
    let record =
        |time| AppRecord::sign(&w.keys, AppRecordBody::new(w.app.cert(), vec![], time)).unwrap();
    let put = |record: &AppRecord| {
        (
            vec![],
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )
    };
    let stale = record(world.now_ms());
    world.advance_ms(1000);
    let held = record(world.now_ms());
    let publish = client
        .sign_batch(w.generation, vec![put(&held)], None)
        .unwrap();
    client.submit(&publish).await.unwrap();

    let list = (vec![], OpKind::DenyPut { pubky: [7; 32] });
    let small = client
        .sign_batch(w.generation, vec![list.clone()], None)
        .unwrap();
    client.submit(&small).await.unwrap();
    let mut expected = vec![
        (TimeoutClass::Bulk, publish.body().to_vec()),
        (TimeoutClass::Ordinary, small.body().to_vec()),
    ];
    for entries in [vec![put(&stale)], vec![list, put(&stale)]] {
        let batch = client.sign_batch(w.generation, entries, None).unwrap();
        let saved = batch.body().to_vec();
        let retry = Batch::from_body(saved.clone()).unwrap();
        for send in [&batch, &retry] {
            assert_eq!(
                conflict(client.submit(send).await),
                json!({"record": held.signed()})
            );
            expected.push((TimeoutClass::Bulk, saved.clone()));
        }
    }
    assert_eq!(*transport.sent.lock().unwrap(), expected);
}

async fn claim_and_receive_key_timeouts(world: &World) {
    let w = Box::pin(writer(world)).await;
    let (client, transport) = recording_client(world, &w);
    let claims = (1u8..=8)
        .map(|id| {
            (
                vec![],
                ClaimOp::attempt([id; 32], 0, [id; 16], 3600, None).kind(),
            )
        })
        .collect();
    let batch = client.sign_batch(w.generation, claims, None).unwrap();
    let first = client.submit(&batch).await.unwrap();
    assert_eq!(first.proofs.len(), 8);
    let retry = Batch::from_body(batch.body().to_vec()).unwrap();
    assert_eq!(client.submit(&retry).await.unwrap().proofs, first.proofs);

    // A different operation can ask about a claim. Its refusal returns the held view.
    let condition = Condition::ClaimStep {
        claim_key: [1; 32],
        step: 0,
    };
    let checked = client
        .sign_batch(
            w.generation,
            vec![(vec![condition], OpKind::DenyDelete { pubky: [7; 32] })],
            None,
        )
        .unwrap();
    for send in [
        &checked,
        &Batch::from_body(checked.body().to_vec()).unwrap(),
    ] {
        let current = conflict(client.submit(send).await);
        assert_eq!(current["claim_step"]["step"], 1);
        assert_eq!(current["claim"]["attempts"].as_array().unwrap().len(), 1);
    }

    let key = w
        .client
        .directory(None)
        .await
        .unwrap()
        .apps
        .into_iter()
        .find(|app| app.app_id == w.keys.app_id_bytes())
        .unwrap()
        .receive_key
        .unwrap();
    let registration = client
        .sign_batch(
            w.generation,
            vec![(
                vec![],
                OpKind::ReceiveKeyPut {
                    record: key.signed().clone(),
                },
            )],
            None,
        )
        .unwrap();
    for send in [
        &registration,
        &Batch::from_body(registration.body().to_vec()).unwrap(),
    ] {
        assert!(client.submit(send).await.unwrap().proofs.is_empty());
    }
    let sent = transport.sent.lock().unwrap();
    assert_eq!(sent.len(), 6);
    for ((timeout, bytes), expected) in sent.iter().zip([
        &batch,
        &batch,
        &checked,
        &checked,
        &registration,
        &registration,
    ]) {
        assert_eq!(*timeout, TimeoutClass::Bulk);
        assert_eq!(bytes, expected.body());
    }
}

async fn list_condition_timeouts(world: &World) {
    let w = Box::pin(writer(world)).await;
    let old = w.write(1, b"notes", RecordVersion::NONE, b"{}").await;
    let held = w
        .write(2, b"notes", version(&old), br#"{"updated":true}"#)
        .await;
    let key = pubky_switch_core::enc::unb64_array(old["key"].as_str().unwrap()).unwrap();
    let (client, transport) = recording_client(world, &w);
    let mut expected = Vec::new();
    for (condition, timeout, refusal) in [
        (
            guard(key, &old),
            TimeoutClass::Bulk,
            json!({"record_view": held}),
        ),
        (
            Condition::RecordVersion {
                key,
                version: version(&old),
            },
            TimeoutClass::Ordinary,
            json!({"record_version": {"key": held["key"], "generation": held["generation"], "version": held["version"]}}),
        ),
    ] {
        let list = OpKind::DenyPut { pubky: [7; 32] };
        let batch = client
            .sign_batch(w.generation, vec![(vec![condition], list)], None)
            .unwrap();
        let saved = batch.body().to_vec();
        let retry = Batch::from_body(saved.clone()).unwrap();
        for send in [&batch, &retry] {
            assert_eq!(conflict(client.submit(send).await), refusal);
            expected.push((timeout, saved.clone()));
        }
    }
    assert_eq!(*transport.sent.lock().unwrap(), expected);
}

async fn current_collection(world: &World) {
    let mut wallet = writer_with(world, notes_protocol_with_records()).await;
    let collection = notes_collection();
    wallet
        .write(1, b"first", RecordVersion::NONE, br#"{"v":1}"#)
        .await;
    let report = Box::pin(wallet.app.receive(None)).await.unwrap();
    let current = wallet
        .app
        .current_collection(&collection, &report)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.identity, wallet.who.public());
    assert_eq!(current.live.len(), 1);
    assert!(current.uncertain_keys.is_empty());
    let target = RecordTarget::new(collection.clone(), b"second");
    Box::pin(wallet.app.put_record(&target, br#"{"v":2}"#, vec![]))
        .await
        .unwrap();
    let current = wallet
        .app
        .current_collection(&collection, &report)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.live.len(), 2);
    assert!(current.uncertain_keys.is_empty());
    Box::pin(wallet.app.delete_record(&target, vec![]))
        .await
        .unwrap();
    let current = wallet
        .app
        .current_collection(&collection, &report)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.live.len(), 1);
    assert!(current.uncertain_keys.is_empty());
}

macro_rules! backend_test {
    ($name:ident, $backend:expr, $flow:ident) => {
        #[tokio::test]
        async fn $name() {
            let Some(world) = World::start($backend).unwrap() else {
                return;
            };
            // The flow runs on this test's native stack, with no larger harness thread.
            Box::pin($flow(&world)).await;
            world.close().await.unwrap();
        }
    };
}

backend_test!(
    test_current_collection_service,
    Backend::Service,
    current_collection
);
backend_test!(
    test_current_collection_scripted,
    Backend::Scripted,
    current_collection
);

backend_test!(
    test_record_current_delete_repair_service,
    Backend::Service,
    delete_repair
);
backend_test!(
    test_record_current_delete_repair_scripted,
    Backend::Scripted,
    delete_repair
);
backend_test!(
    test_record_current_pre_batch_atomicity_service,
    Backend::Service,
    pre_batch_and_atomicity
);
backend_test!(
    test_record_current_pre_batch_atomicity_scripted,
    Backend::Scripted,
    pre_batch_and_atomicity
);
backend_test!(
    test_record_current_retry_race_service,
    Backend::Service,
    retry_and_race
);
backend_test!(
    test_record_current_retry_race_scripted,
    Backend::Scripted,
    retry_and_race
);

backend_test!(
    test_record_current_lost_answer_service,
    Backend::Service,
    lost_answer
);
backend_test!(
    test_record_current_lost_answer_scripted,
    Backend::Scripted,
    lost_answer
);
backend_test!(test_record_current_upload_service, Backend::Service, upload);
backend_test!(
    test_record_current_upload_scripted,
    Backend::Scripted,
    upload
);

backend_test!(
    test_app_record_conflict_timeout_service,
    Backend::Service,
    app_record_timeouts
);
backend_test!(
    test_app_record_conflict_timeout_scripted,
    Backend::Scripted,
    app_record_timeouts
);

backend_test!(
    test_claim_and_receive_key_batch_timeouts_scripted,
    Backend::Scripted,
    claim_and_receive_key_timeouts
);
backend_test!(
    test_claim_and_receive_key_batch_timeouts_service,
    Backend::Service,
    claim_and_receive_key_timeouts
);

backend_test!(
    test_list_condition_timeouts_scripted,
    Backend::Scripted,
    list_condition_timeouts
);
backend_test!(
    test_list_condition_timeouts_service,
    Backend::Service,
    list_condition_timeouts
);
