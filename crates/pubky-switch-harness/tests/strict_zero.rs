//! Version 0 names only a key the service holds nothing for (Switch spec 10.3, Switch wire
//! 6.2, 6.3), and a write over a record taken from a recovery upload names it exactly
//! (Switch spec 12.6 step 3), on the service and on the scripted switch alike.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use pubky_switch_client::app::{App, AppConfig, RecordTarget};
use pubky_switch_client::client::{CheckedResponse, Credentials, SwitchClient};
use pubky_switch_client::error::ClientError;
use pubky_switch_client::store::MemoryStore;
use pubky_switch_client::testing::TestIdentity;
use pubky_switch_client::transport::TimeoutClass;
use pubky_switch_core::enc::{b64, pubky_id};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ident::{NamingKey, Policy, collection_id, record_key_from_blinded};
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::ops::{
    Condition, IdInputs, OpKind, OpsRequest, RecordPut, RecordVersion, SignedOp, sign_batch,
};
use pubky_switch_core::sealed::SealedValue;
use pubky_switch_core::shared::ApplicationRef;
use pubky_switch_harness::parties::{
    Asking, NOTES, NOTES_LISTS, NOTES_READER, notes_collection, notes_protocol_with_records,
};
use pubky_switch_harness::{Backend, World};
use pubky_switch_signer::{Signer, UserConfirmed};
use serde_json::{Value, json};

const ORIGIN: &str = "https://switch.example";
const RECOVERY: &str = "https://recovery.example";
const COLLECTION: &str = "example.items";

/// An app of alice's, with its keys, and a client that signs requests as it.
struct Writer {
    who: TestIdentity,
    keys: AppKeys,
    client: SwitchClient,
    epoch: u64,
    generation: u64,
    app: App,
}

/// alice enrolled at [`ORIGIN`], with her signer.
async fn enrolled(world: &World) -> (TestIdentity, Signer) {
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
    (who, signer)
}

/// The app `name` of alice, approved by `signer`, at `origin`.
async fn joined(
    world: &World,
    who: &TestIdentity,
    signer: &mut Signer,
    name: &str,
    origin: &str,
) -> Writer {
    joined_with_scopes(world, who, signer, name, origin, &[NOTES]).await
}

async fn joined_with_scopes(
    world: &World,
    who: &TestIdentity,
    signer: &mut Signer,
    name: &str,
    origin: &str,
    scopes: &[&str],
) -> Writer {
    let asking = Asking::for_scopes(world.app_keys(who, name).unwrap(), scopes).unwrap();
    let checked = signer
        .review(asking.request.signed(), &asking.auth)
        .unwrap();
    let approved = Box::pin(signer.approve(checked)).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    let mut app = Box::pin(App::join(
        world.app_env(Arc::new(MemoryStore::new())),
        notes_protocol_with_records(),
        AppConfig::default(),
        asking.join_request(who.public(), &approved).unwrap(),
    ))
    .await
    .unwrap();
    Box::pin(app.receive(None)).await.unwrap();
    let client = client_at(world, who, &asking.keys, &app, origin);
    Writer {
        who: world.identity("alice").unwrap(),
        keys: asking.keys,
        client,
        epoch: app.data_epoch(),
        generation: app.own_identity().generation(),
        app,
    }
}

fn client_at(
    world: &World,
    who: &TestIdentity,
    keys: &AppKeys,
    app: &App,
    origin: &str,
) -> SwitchClient {
    SwitchClient::new(
        origin,
        who.public(),
        Credentials::App {
            identity: who.public(),
            keys: keys.clone(),
            cert: app.cert().clone(),
        },
        Some(app.own_identity().inbox().service_key),
        world.transport(),
        world.clock().clone(),
    )
    .unwrap()
}

impl Writer {
    fn put(&self, natural: &[u8], expected: RecordVersion, value: &[u8]) -> RecordPut {
        self.put_at(natural, expected, value, Policy::new(NOTES, &[NOTES]))
    }

    fn put_at(
        &self,
        natural: &[u8],
        expected: RecordVersion,
        value: &[u8],
        policy: Policy,
    ) -> RecordPut {
        let identity = self.who.key();
        let naming = NamingKey::from_root(&identity.switch_root());
        let blinded_key = naming.blind(natural);
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

    async fn post(
        &self,
        id: u8,
        conditions: Vec<Condition>,
        put: RecordPut,
    ) -> Result<CheckedResponse, ClientError> {
        let ops = sign_batch(
            &self.keys,
            &self.who.public(),
            Some(self.keys.app_id_bytes()),
            self.generation,
            [id; 16],
            vec![(conditions, OpKind::RecordPut(put))],
        )
        .unwrap();
        let path = format!("/v1/{}/ops", pubky_id(&self.who.public()));
        let request = self
            .client
            .sign_request(
                "POST",
                &path,
                OpsRequest::new(&ops, None).to_json(),
                None,
                TimeoutClass::Bulk,
            )
            .unwrap();
        self.client.send(request).await
    }

    async fn get(&self, key: &[u8; 32]) -> Value {
        let path = format!("/v1/{}/records/{}", pubky_id(&self.who.public()), b64(key));
        let answer = self
            .client
            .send(
                self.client
                    .sign_request("GET", &path, Vec::new(), None, TimeoutClass::Bulk)
                    .unwrap(),
            )
            .await
            .unwrap();
        serde_json::from_slice(&answer.body).unwrap()
    }

    /// Write `value` at `natural` on `expected`, which must apply; the record's view after.
    async fn write(&self, id: u8, natural: &[u8], expected: RecordVersion, value: &[u8]) -> Value {
        let put = self.put(natural, expected, value);
        let key = put.key;
        self.post(id, Vec::new(), put).await.unwrap();
        self.get(&key).await
    }
}

fn version(view: &Value) -> RecordVersion {
    RecordVersion::new(
        view["generation"].as_u64().unwrap(),
        view["version"].as_u64().unwrap(),
    )
}

fn revision(view: &Value) -> ApplicationRef {
    ApplicationRef::parse(&serde_json::to_vec(&view["revision"]).unwrap()).unwrap()
}

fn conflict(result: Result<CheckedResponse, ClientError>) -> Value {
    match result {
        Err(ClientError::Switch {
            status: 409,
            current,
            ..
        }) => current,
        other => panic!("expected 409 conflict, got {other:?}"),
    }
}

/// A create at a key whose delete the service keeps is refused with that delete as current;
/// a write naming the delete applies. A write or a `record_current` naming a key the
/// service never held shows version 0, with no view. Without the rule the create applies
/// over the delete.
async fn create_against_a_retained_delete(world: &World) {
    let (who, mut signer) = enrolled(world).await;
    let w = joined(world, &who, &mut signer, "wallet", ORIGIN).await;
    let created = w.write(1, b"kept", RecordVersion::NONE, b"{}").await;
    let deleted = w.write(2, b"kept", version(&created), b"").await;
    assert_eq!(deleted["deleted"], true);
    let create = w.put(b"kept", RecordVersion::NONE, b"{\"n\":1}");
    let key = create.key;
    let current = conflict(w.post(3, Vec::new(), create).await);
    assert_eq!(current["record"]["version"], deleted["version"]);
    assert_eq!(current["record_view"], deleted);
    let named = w.write(4, b"kept", version(&deleted), b"{\"n\":1}").await;
    assert_eq!(named["deleted"], false);
    assert!(version(&named) > version(&deleted));
    // Nothing held: version 0 is current, to name the absence.
    let never = w.put(b"never", RecordVersion::new(w.generation, 3), b"{}");
    let never_key = never.key;
    assert_eq!(
        conflict(w.post(5, Vec::new(), never).await),
        json!({
            "record": {"key": b64(&never_key), "generation": 0, "version": 0},
            "record_view": null,
        })
    );
    assert_ne!(never_key, key);
    // A `record_current` there fails with version 0 current too.
    let named = Condition::RecordCurrent {
        key: never_key,
        revision: revision(&deleted),
        deleted: true,
    };
    let guarded = w.put(b"other", RecordVersion::NONE, b"{}");
    assert_eq!(
        conflict(w.post(6, vec![named], guarded).await),
        json!({"record_version": {"key": b64(&never_key), "generation": 0, "version": 0}})
    );
}

/// A delete at v, a put-back naming v, and a third writer's create at `{0, 0}`: the create
/// is refused and the put-back applies; without the rule the create applies first and the
/// put-back fails. Two creates racing at a fresh key: one wins, the other sees its write.
async fn creates_race_at_zero(world: &World) {
    let (who, mut signer) = enrolled(world).await;
    let w = joined(world, &who, &mut signer, "wallet", ORIGIN).await;
    let created = w.write(1, b"race", RecordVersion::NONE, b"{}").await;
    let deleted = w.write(2, b"race", version(&created), b"").await;
    let put_back = w.put(b"race", version(&deleted), b"{\"back\":true}");
    let third = w.put(b"race", RecordVersion::NONE, b"{\"third\":true}");
    let key = put_back.key;
    conflict(w.post(3, Vec::new(), third).await);
    w.post(4, Vec::new(), put_back).await.unwrap();
    let held = w.get(&key).await;
    assert!(version(&held) > version(&deleted));
    assert_eq!(held["deleted"], false);

    let left = w.put(b"fresh", RecordVersion::NONE, b"{\"left\":true}");
    let right = w.put(b"fresh", RecordVersion::NONE, b"{\"right\":true}");
    let fresh = left.key;
    let (a, b) = tokio::join!(w.post(5, Vec::new(), left), w.post(6, Vec::new(), right));
    let lost = match (a, b) {
        (Ok(_), lost) | (lost, Ok(_)) => conflict(lost),
        other => panic!("one create must win: {other:?}"),
    };
    let won = w.get(&fresh).await;
    assert_eq!(lost["record"]["version"], won["version"]);
    assert_eq!(lost["record_view"], won);
}

/// A put-back prepared for one delete, D1, misses a later one, D2: naming D1 it is refused
/// with D2 as current, and so is one built on `{0, 0}`, which without the rule would apply
/// over D2.
async fn put_back_for_one_delete_misses_another(world: &World) {
    let (who, mut signer) = enrolled(world).await;
    let w = joined(world, &who, &mut signer, "wallet", ORIGIN).await;
    let created = w.write(1, b"twice", RecordVersion::NONE, b"{}").await;
    let first = w.write(2, b"twice", version(&created), b"").await;
    let put_back = w.put(b"twice", version(&first), b"{\"back\":1}");
    let key = put_back.key;
    let again = w.write(3, b"twice", version(&first), b"{\"n\":2}").await;
    let second = w.write(4, b"twice", version(&again), b"").await;
    let current = conflict(w.post(5, Vec::new(), put_back).await);
    assert_eq!(current["record"]["version"], second["version"]);
    assert_eq!(current["record_view"], second);
    let zero = w.put(b"twice", RecordVersion::NONE, b"{\"back\":1}");
    assert_eq!(conflict(w.post(6, Vec::new(), zero).await), current);
    assert_eq!(w.get(&key).await, second);
}

/// After a provider loss two uploads share a version: the phone's B, without a proof, and
/// the wallet's own pre-loss write A, with its proof, kept divergent behind B. The wallet's
/// first write names A exactly and is refused; it then follows B, and its next write names
/// B exactly and applies. Without the rule a bare version would apply over B.
async fn two_uploads_at_one_version(world: &World) {
    let (who, mut signer) = enrolled(world).await;
    let mut wallet = joined(world, &who, &mut signer, "wallet", ORIGIN).await;
    let mut phone = joined(world, &who, &mut signer, "phone", ORIGIN).await;
    let target = RecordTarget::new(notes_collection(), b"shared");
    let key = wallet.app.record_key(&target).unwrap();
    wallet
        .app
        .put_record(&target, br#"{"n":1}"#, Vec::new())
        .await
        .unwrap();
    let a = wallet
        .app
        .put_record(&target, br#"{"n":2}"#, Vec::new())
        .await
        .unwrap();
    let held = wallet.app.shared_record(&key).await.unwrap().unwrap();
    assert!(!held.different_write_at_held_version);
    let a_view = wallet.get(&key).await;
    let a_op = SignedOp::peek(&serde_json::from_value(a_view["op"].clone()).unwrap()).unwrap();
    // B: the phone's operation on the same base as A, so one version with it at N.
    let mut b_body = a_op.body().clone();
    b_body.batch.id = [70; 16];
    b_body.app_id = Some(phone.keys.app_id_bytes());
    let OpKind::RecordPut(b_put) = &mut b_body.kind else {
        panic!("a record write")
    };
    b_put.expected_version = RecordVersion::new(a.version.generation, a.version.version - 1);
    let b_op = SignedOp::sign(&phone.keys, b_body).unwrap();
    let lost = wallet.app.own_identity().signed().clone();

    world.lose_switch(ORIGIN);
    world.add_switch(RECOVERY, &[&who]).await.unwrap();
    Box::pin(signer.declare_provider_loss(RECOVERY, UserConfirmed::shown_and_confirmed()))
        .await
        .unwrap();
    Box::pin(signer.end_staged_admission()).await.unwrap();
    Box::pin(phone.app.refresh_identity()).await.unwrap();
    Box::pin(phone.app.follow_provider()).await.unwrap();
    phone.client = client_at(world, &who, &phone.keys, &phone.app, RECOVERY);
    let path = format!("/v1/{}/recovery/upload", pubky_id(&who.public()));
    let upload = json!({
        "lost_identity": lost,
        "records": [{"op": b_op.signed(), "cert": phone.app.cert().signed()}],
    });
    let request = phone
        .client
        .sign_request(
            "POST",
            &path,
            serde_json::to_vec(&upload).unwrap(),
            None,
            TimeoutClass::Bulk,
        )
        .unwrap();
    phone.client.send(request).await.unwrap();
    Box::pin(wallet.app.refresh_identity()).await.unwrap();
    Box::pin(wallet.app.follow_provider()).await.unwrap();
    wallet.client = client_at(world, &who, &wallet.keys, &wallet.app, RECOVERY);
    let at_n = wallet.get(&key).await;
    assert_eq!(version(&at_n), a.version, "B shares A's version");
    assert_eq!(revision(&at_n).item_hash, b_op.item_hash().unwrap());

    let first = wallet
        .app
        .put_record(&target, br#"{"n":3}"#, Vec::new())
        .await;
    assert_eq!(
        first.as_ref().err().and_then(|e| e.code()),
        Some(ErrorCode::Conflict),
        "naming A over B: {first:?}"
    );
    let held = wallet.app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(held.version, a.version);
    assert!(held.different_write_at_held_version);
    wallet
        .app
        .put_record(&target, br#"{"n":3}"#, Vec::new())
        .await
        .unwrap();
    let held = wallet.app.shared_record(&key).await.unwrap().unwrap();
    assert!(!held.different_write_at_held_version);
    let written = wallet.get(&key).await;
    let op = SignedOp::peek(&serde_json::from_value(written["op"].clone()).unwrap()).unwrap();
    assert!(op.body().conditions.contains(&Condition::RecordCurrent {
        key,
        revision: revision(&at_n),
        deleted: false,
    }));
    let OpKind::RecordPut(put) = &op.body().kind else {
        panic!("a record write")
    };
    assert_eq!(put.expected_version, a.version);
}

async fn record_create_scope(world: &World) {
    let (who, mut signer) = enrolled(world).await;
    let creator = Box::pin(joined_with_scopes(
        world,
        &who,
        &mut signer,
        "creator",
        ORIGIN,
        &[NOTES, NOTES_LISTS],
    ))
    .await;
    let mut editor = Box::pin(joined_with_scopes(
        world,
        &who,
        &mut signer,
        "editor",
        ORIGIN,
        &[NOTES, NOTES_READER],
    ))
    .await;
    let policy = Policy::new(NOTES, &[NOTES_READER])
        .with_create_scope(NOTES_LISTS)
        .permanent(None);
    let put = |writer: &Writer, expected, value: &[u8]| {
        writer.put_at(b"roles", expected, value, policy.clone())
    };
    let create = put(&creator, RecordVersion::NONE, b"{}");
    let key = create.key;
    let denied = editor
        .post(1, vec![], put(&editor, RecordVersion::NONE, b"{}"))
        .await;
    assert!(matches!(
        denied,
        Err(ClientError::Switch { status: 403, .. })
    ));
    creator.post(2, vec![], create).await.unwrap();
    let original = creator.get(&key).await;
    let base = version(&original);
    let denied = creator.post(3, vec![], put(&creator, base, b"{}")).await;
    assert!(matches!(
        denied,
        Err(ClientError::Switch { status: 403, .. })
    ));
    assert_eq!(editor.get(&key).await, original);
    editor
        .post(4, vec![], put(&editor, base, br#"{"done":true}"#))
        .await
        .unwrap();
    let updated = creator.get(&key).await;
    assert!(version(&updated) > base);
    assert_eq!(updated["key"], original["key"]);
    let deleted = editor
        .post(5, vec![], put(&editor, version(&updated), b""))
        .await;
    assert!(matches!(
        deleted,
        Err(ClientError::Switch { status: 400, .. })
    ));
    assert_eq!(creator.get(&key).await, updated);

    // Carry only the current signed successor and its writer certificate to each service.
    let mut kept = updated;
    for (old_origin, next_origin) in [(ORIGIN, RECOVERY), (RECOVERY, "https://second.example")] {
        world.lose_switch(old_origin);
        world.add_switch(next_origin, &[&who]).await.unwrap();
        Box::pin(signer.declare_provider_loss(next_origin, UserConfirmed::shown_and_confirmed()))
            .await
            .unwrap();
        Box::pin(signer.end_staged_admission()).await.unwrap();
        Box::pin(editor.app.refresh_identity()).await.unwrap();
        Box::pin(editor.app.follow_provider()).await.unwrap();
        editor.client = client_at(world, &who, &editor.keys, &editor.app, next_origin);
        let upload = json!({"records": [{"op": kept["op"], "cert": kept["cert"]}]});
        let request = editor
            .client
            .sign_request(
                "POST",
                &format!("/v1/{}/recovery/upload", pubky_id(&who.public())),
                serde_json::to_vec(&upload).unwrap(),
                None,
                TimeoutClass::Bulk,
            )
            .unwrap();
        let answer = editor.client.send(request).await.unwrap();
        let body: Value = serde_json::from_slice(&answer.body).unwrap();
        assert_eq!(body["result"]["records"], json!([b64(&key)]));
        assert_eq!(body["result"]["unverified"], 0);
        let recovered = editor.get(&key).await;
        assert_eq!(recovered["op"], kept["op"]);
        assert_eq!(recovered["cert"], kept["cert"]);
        kept = recovered;
    }
}

macro_rules! backend_test {
    ($name:ident, $backend:expr, $flow:ident) => {
        #[tokio::test]
        async fn $name() {
            let Some(world) = World::start($backend).unwrap() else {
                return;
            };
            Box::pin($flow(&world)).await;
            world.close().await.unwrap();
        }
    };
}

backend_test!(
    test_strict_zero_create_against_a_retained_delete_service,
    Backend::Service,
    create_against_a_retained_delete
);
backend_test!(
    test_strict_zero_create_against_a_retained_delete_scripted,
    Backend::Scripted,
    create_against_a_retained_delete
);
backend_test!(
    test_strict_zero_creates_race_at_zero_service,
    Backend::Service,
    creates_race_at_zero
);
backend_test!(
    test_strict_zero_creates_race_at_zero_scripted,
    Backend::Scripted,
    creates_race_at_zero
);
backend_test!(
    test_strict_zero_put_back_for_one_delete_misses_another_service,
    Backend::Service,
    put_back_for_one_delete_misses_another
);
backend_test!(
    test_strict_zero_put_back_for_one_delete_misses_another_scripted,
    Backend::Scripted,
    put_back_for_one_delete_misses_another
);
backend_test!(
    test_strict_zero_two_uploads_at_one_version_service,
    Backend::Service,
    two_uploads_at_one_version
);
backend_test!(
    test_strict_zero_two_uploads_at_one_version_scripted,
    Backend::Scripted,
    two_uploads_at_one_version
);

backend_test!(
    test_record_create_scope_service,
    Backend::Service,
    record_create_scope
);
backend_test!(
    test_record_create_scope_scripted,
    Backend::Scripted,
    record_create_scope
);
