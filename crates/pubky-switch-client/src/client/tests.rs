//! Unit tests of the client against a scripted switch.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use pubky_switch_core::chain::{
    ChainTip, ItemType, ProofBody, ProofState, TransitionProof, item_hash,
};
use pubky_switch_core::enc::{b64, pubky_id};
use pubky_switch_core::http::{self, ErrorCode, IdentityDelivery, header, sign_response};
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::ops::{AllowKind, Condition, OpKind, OpsRequest, Position, SignedOp};
use pubky_switch_core::records::{
    AccountObservationBody, AppCert, AppCertBody, DEFAULT_CERT_LIFETIME_MS, Enrollment,
    EnrollmentAnswer, EnrollmentBody, EnrollmentIntent, IdentityBody, IdentityDoc, IdentityPolicy,
    Inbox, Limits,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::rfc3339;
use serde_json::{Value, json};

use super::answers::{FeedItem, FeedPage};
use super::read::Obj;
use super::*;
use crate::clock::TestClock;
use crate::transport::MockTransport;

const ORIGIN: &str = "https://switch.example";
const NOW: u64 = 1_767_225_900_000;

fn identity() -> IdentityKey {
    IdentityKey::from_secret([1; 32])
}

fn service_key() -> SigningKey {
    SigningKey::from_bytes(&[5; 32])
}

fn service_public() -> [u8; 32] {
    service_key().verifying_key().to_bytes()
}

fn app_keys() -> AppKeys {
    AppKeys::from_secrets([2; 32], [3; 32])
}

fn cert_of(identity: &IdentityKey, keys: &AppKeys) -> AppCert {
    let body = AppCertBody::new(
        identity.public(),
        keys.signing_public(),
        keys.bundle_public(),
        vec!["sample".into()],
        &[Permission::ListsRead],
        NOW,
        NOW + DEFAULT_CERT_LIFETIME_MS,
    );
    AppCert::issue(identity, body).unwrap()
}

fn signer() -> Credentials {
    Credentials::Signer {
        identity: identity().public(),
        key: Arc::new(identity()),
    }
}

/// The identity key behind a request-only interface, as the signer's request credential
/// holds it.
struct RequestsOnly(IdentityKey);

impl pubky_switch_core::signing::SignsRequests for RequestsOnly {
    fn public_key(&self) -> [u8; 32] {
        self.0.public()
    }

    fn sign_request_fields(&self, fields: &[&[u8]]) -> [u8; 64] {
        self.0.sign(pubky_switch_core::labels::sig::HTTP, fields)
    }
}

fn signer_requests() -> Credentials {
    Credentials::SignerRequests {
        identity: identity().public(),
        key: Arc::new(RequestsOnly(identity())),
    }
}

fn app() -> Credentials {
    Credentials::App {
        identity: identity().public(),
        keys: app_keys(),
        cert: cert_of(&identity(), &app_keys()),
    }
}

fn client_with(
    credentials: Credentials,
    pinned: Option<[u8; 32]>,
    transport: Arc<MockTransport>,
) -> SwitchClient {
    let signer = matches!(
        credentials,
        Credentials::Signer { .. } | Credentials::SignerRequests { .. }
    );
    let client = SwitchClient::new(
        ORIGIN,
        identity().public(),
        credentials,
        pinned,
        transport,
        Arc::new(TestClock::new(NOW)),
    )
    .unwrap();
    if signer {
        client.with_account_created(0).unwrap()
    } else {
        client
    }
}

/// A response to `request`, signed with `key` as the switch signs it (Switch wire 7.1).
fn respond(key: &SigningKey, request: &Request, status: u16, body: &[u8]) -> Response {
    respond_with_head(key, request, status, body, None)
}

/// A response to `request` carrying `head` as its `Switch-Head`, signed with `key` as the
/// switch signs it (Switch wire 7.1).
fn respond_with_head(
    key: &SigningKey,
    request: &Request,
    status: u16,
    body: &[u8],
    head: Option<&str>,
) -> Response {
    let server_time = rfc3339(NOW);
    let sent = SentRequest::of(request);
    let signature = sign_response(
        key,
        &http::ResponseParts {
            status,
            request: sent.received(true),
            server_time: &server_time,
            head,
            body,
        },
    );
    let mut headers = vec![
        Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
        Header::new(header::SERVER_TIME, &server_time),
        Header::new("content-type", "application/json"),
    ];
    if let Some(head) = head {
        headers.push(Header::new(header::HEAD, head));
    }
    Response {
        status,
        headers,
        body: body.to_vec(),
    }
}

/// A switch that answers every request with `status` and `body`, signed with `key`.
fn fixed(key: SigningKey, status: u16, body: Value) -> Arc<MockTransport> {
    let bytes = body.to_string().into_bytes();
    Arc::new(MockTransport::with_handler(move |request| {
        Ok(respond(&key, request, status, &bytes))
    }))
}

/// The proofs a switch writes for the batch in `body`, each a `deny.put` or `allow.put`
/// chained after `seq` 4, signed with `key`, and the head after them.
fn proofs_for(key: &SigningKey, body: &[u8]) -> (Vec<SignedDoc>, SignedHead) {
    let request = OpsRequest::parse(body).unwrap();
    let account = identity().public();
    let mut tip = ChainTip {
        generation: 1,
        seq: 4,
        chain_hash: [9; 32],
    };
    let mut proofs = Vec::new();
    for signed in request.signed() {
        let op = SignedOp::peek(signed).unwrap();
        let (stub, next) = tip
            .append(
                tip.seq + 1,
                NOW,
                ItemType::Op,
                op.item_hash().unwrap(),
                Some(op.body().batch),
            )
            .unwrap();
        tip = next;
        let state = match &op.body().kind {
            OpKind::DenyPut { .. } => ProofState::Deny { denied: true },
            OpKind::AllowPut { kind, .. } => ProofState::Allow {
                kind: *kind,
                present: true,
            },
            _ => unreachable!("the tests write lists only"),
        };
        let object = op
            .body()
            .kind
            .proof_object(op.body().app_id.as_ref())
            .unwrap();
        let proof =
            TransitionProof::sign(key, &account, ProofBody::new(stub, object, &state)).unwrap();
        proofs.push(proof.signed().clone());
    }
    (proofs, SignedHead::sign(key, &account, &tip))
}

/// A switch that answers `POST /ops` with the batch's proofs, passed through `edit`.
fn ops_switch(edit: fn(&mut Vec<SignedDoc>)) -> Arc<MockTransport> {
    ops_switch_with(edit, |_| {})
}

/// [`ops_switch`], with the answer's body then passed through `edit_body`.
fn ops_switch_with(edit: fn(&mut Vec<SignedDoc>), edit_body: fn(&mut Value)) -> Arc<MockTransport> {
    let key = service_key();
    Arc::new(MockTransport::with_handler(move |request| {
        let (mut proofs, head) = proofs_for(&key, &request.body);
        edit(&mut proofs);
        let mut body = json!({ "proofs": proofs, "head": head.to_value() });
        edit_body(&mut body);
        Ok(respond(&key, request, 200, body.to_string().as_bytes()))
    }))
}

/// The two edits that leave out an answer's `proofs`: missing, and `null`.
const WITHOUT_PROOFS: [fn(&mut Value); 2] = [
    |body| {
        body.as_object_mut().unwrap().remove("proofs");
    },
    |body| body["proofs"] = Value::Null,
];

fn two_lists() -> Vec<(Vec<Condition>, OpKind)> {
    vec![
        (Vec::new(), OpKind::DenyPut { pubky: [7; 32] }),
        (
            Vec::new(),
            OpKind::AllowPut {
                pubky: [8; 32],
                kind: AllowKind::Contact,
            },
        ),
    ]
}

fn enrollment(nonce: [u8; 16]) -> Enrollment {
    Enrollment::sign(
        &identity(),
        EnrollmentBody {
            identity: identity().public(),
            origin: ORIGIN.into(),
            nonce,
            intent: EnrollmentIntent::Existing { created: 0 },
            policy: IdentityPolicy::default(),
            identity_doc: None,
            revoked_apps: None,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn test_unpinned_client_sends_nothing() {
    let transport = fixed(service_key(), 200, json!({}));
    let client = client_with(app(), None, Arc::clone(&transport));
    assert_eq!(client.allow().await.unwrap_err(), ClientError::Unpinned);
    let batch = client.sign_batch(1, two_lists(), None).unwrap();
    assert_eq!(
        client.submit(&batch).await.unwrap_err(),
        ClientError::Unpinned
    );
    let signed = client
        .sign_request("GET", "/v1/x/feed", Vec::new(), None, TimeoutClass::Bulk)
        .unwrap();
    assert_eq!(
        client.send(signed).await.unwrap_err(),
        ClientError::Unpinned
    );
    assert!(transport.requests().is_empty(), "nothing went out");
}

#[tokio::test]
async fn test_unpinned_signer_enrolls_and_pins_the_answers_key() {
    let enrollment = enrollment([4; 16]);
    let answer = EnrollmentAnswer::new(&enrollment, service_public(), Limits::default(), 0);
    let body = answer.to_json().unwrap();
    let key = service_key();
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        Ok(respond(&key, request, 200, &body))
    }));
    let client = client_with(signer(), None, Arc::clone(&transport));
    assert_eq!(client.enroll(&enrollment).await.unwrap(), answer);
    assert_eq!(client.pinned_key(), Some(service_public()));
    // The enrollment carries no Switch-App.
    let sent = transport.last_request().unwrap();
    assert_eq!(sent.path_and_query, "/v1/enroll");
    assert!(sent.header(header::APP).is_none());

    // A client that holds a key keeps it: after a service key change the answer names the
    // new key, pinned only once the delivery naming it is accepted.
    let pending = SigningKey::from_bytes(&[6; 32]);
    let answer = EnrollmentAnswer::new(
        &enrollment,
        pending.verifying_key().to_bytes(),
        Limits::default(),
        0,
    );
    let body = answer.to_json().unwrap();
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        Ok(respond(&pending, request, 200, &body))
    }));
    let client = client_with(signer(), Some(service_public()), transport);
    client.enroll(&enrollment).await.unwrap();
    assert_eq!(client.pinned_key(), Some(service_public()));
}

#[tokio::test]
async fn test_enrollment_answer_signed_by_another_key_is_refused() {
    let enrollment = enrollment([4; 16]);
    let answer = EnrollmentAnswer::new(&enrollment, service_public(), Limits::default(), 0);
    let other = SigningKey::from_bytes(&[6; 32]);
    let body = answer.to_json().unwrap();
    let forged = Arc::new(MockTransport::with_handler(move |request| {
        Ok(respond(&other, request, 200, &body))
    }));
    let client = client_with(signer(), None, forged);
    assert_eq!(
        client.enroll(&enrollment).await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
    assert_eq!(client.pinned_key(), None);
    // An error to an enrollment, before the client has pinned a key, is unauthenticated:
    // only the enrollment answer names the key to pin.
    let client = client_with(
        signer(),
        None,
        fixed(
            service_key(),
            400,
            json!({ "code": "bad_request", "message": "m" }),
        ),
    );
    assert_eq!(
        client.enroll(&enrollment).await.unwrap_err(),
        ClientError::BadServiceSignature { status: 400 }
    );
}

#[tokio::test]
async fn test_enrollment_unreadable_signed_header_fails_authentication() {
    for pin in [None, Some(service_public())] {
        for status in [200, 503] {
            let transport = Arc::new(MockTransport::new());
            transport.push_error(TransportError::UnreadableSignedHeader { status });
            let client = client_with(signer(), pin, transport);
            assert_eq!(
                client.enroll(&enrollment([4; 16])).await.unwrap_err(),
                ClientError::BadServiceSignature { status }
            );
            assert_eq!(client.pinned_key(), pin);
        }
    }
}

#[tokio::test]
async fn test_enrollment_answer_for_another_enrollment_is_refused() {
    let sent = enrollment([4; 16]);
    let other = enrollment([5; 16]);
    let answer = EnrollmentAnswer::new(&other, service_public(), Limits::default(), 0);
    let transport = fixed(
        service_key(),
        200,
        serde_json::from_slice(&answer.to_json().unwrap()).unwrap(),
    );
    let client = client_with(signer(), None, transport);
    assert!(matches!(
        client.enroll(&sent).await.unwrap_err(),
        ClientError::Core(_)
    ));
    assert_eq!(client.pinned_key(), None);
    // Only the signer enrolls.
    let app_client = client_with(app(), None, fixed(service_key(), 200, json!({})));
    assert!(matches!(
        app_client.enroll(&sent).await.unwrap_err(),
        ClientError::Usage(_)
    ));
}

#[tokio::test]
async fn test_answer_checked_with_the_pinned_key() {
    let body = json!({ "pending": true, "known_version": 3 });
    let client = client_with(
        app(),
        Some(service_public()),
        fixed(service_key(), 200, body.clone()),
    );
    let answer = client.connect().await.unwrap();
    assert_eq!(answer.known_version, Some(3));

    // Pinned to another key, the same answer is refused.
    let client = client_with(app(), Some([3; 32]), fixed(service_key(), 200, body));
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
}

#[tokio::test]
async fn test_answer_with_a_bad_or_missing_signature_is_refused() {
    let key = service_key();
    let tampered = Arc::new(MockTransport::with_handler(move |request| {
        let mut response = respond(&key, request, 200, br#"{"pending":true}"#);
        response.body = br#"{"pending":false}"#.to_vec();
        Ok(response)
    }));
    let client = client_with(app(), Some(service_public()), tampered);
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
    let key = service_key();
    let unsigned = Arc::new(MockTransport::with_handler(move |request| {
        let mut response = respond(&key, request, 200, br#"{"pending":true}"#);
        response
            .headers
            .retain(|h| h.name != header::SERVICE_SIGNATURE);
        Ok(response)
    }));
    let client = client_with(app(), Some(service_public()), unsigned);
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
}

/// A request the client sent, as the response signature covers it.
fn sent_request(method: &str, path_and_query: &str, headers: &[(&str, &str)]) -> SentRequest {
    SentRequest::of(&Request {
        method: method.into(),
        origin: "https://switch.example".into(),
        path_and_query: path_and_query.into(),
        headers: headers
            .iter()
            .map(|(name, value)| Header::new(name, value))
            .collect(),
        body: Vec::new(),
        timeout: TimeoutClass::Ordinary,
    })
}

/// The request the head tests' answers are checked against.
fn head_request() -> SentRequest {
    sent_request(
        "GET",
        &format!("/v1/{}/apps", pubky_id(&identity().public())),
        &[(header::SIGNATURE, &b64(&[9; 64]))],
    )
}

/// A `200` to [`head_request`] carrying `head`, signed with the service key.
fn head_response(head: &str) -> Response {
    let bytes = br#"{"pending":true}"#;
    let server_time = rfc3339(NOW);
    let sent = head_request();
    let signature = sign_response(
        &service_key(),
        &http::ResponseParts {
            status: 200,
            request: sent.received(true),
            server_time: &server_time,
            head: Some(head),
            body: bytes,
        },
    );
    Response {
        status: 200,
        headers: vec![
            Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
            Header::new(header::SERVER_TIME, &server_time),
            Header::new(header::HEAD, head),
        ],
        body: bytes.to_vec(),
    }
}

#[tokio::test]
async fn test_head_header_is_verified() {
    let account = identity().public();
    let tip = ChainTip {
        generation: 1,
        seq: 3,
        chain_hash: [2; 32],
    };
    let good = SignedHead::sign(&service_key(), &account, &tip);
    let key = service_key();
    let header_value = good.to_header();
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        Ok(respond_with_head(
            &key,
            request,
            200,
            br#"{"pending":true}"#,
            Some(&header_value),
        ))
    }));
    let client = client_with(app(), Some(service_public()), transport);
    client.connect().await.unwrap();
    // The head is kept only when it verifies with the service key.
    let checked = check_response(
        &service_public(),
        &account,
        &head_request(),
        &head_response(&good.to_header()),
    );
    assert_eq!(checked.unwrap().head, Some(good));
}

#[tokio::test]
async fn test_head_header_that_fails_fails_the_response() {
    // A head the response signature covers but that doesn't verify as a head for the
    // account, or doesn't read, fails the response as a signature that doesn't verify, so
    // a head the client reads is always the account's (Switch wire 6.7, 7.1).
    let account = identity().public();
    let tip = ChainTip {
        generation: 1,
        seq: 3,
        chain_hash: [2; 32],
    };
    let forged = SignedHead::sign(&SigningKey::from_bytes(&[6; 32]), &account, &tip);
    for head in [forged.to_header(), "not a head".to_owned()] {
        let key = service_key();
        let header_value = head.clone();
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            Ok(respond_with_head(
                &key,
                request,
                200,
                br#"{"pending":true}"#,
                Some(&header_value),
            ))
        }));
        let client = client_with(app(), Some(service_public()), transport);
        assert_eq!(
            client.connect().await.unwrap_err(),
            ClientError::BadServiceSignature { status: 200 },
            "{head}"
        );
        assert_eq!(
            check_response(
                &service_public(),
                &account,
                &head_request(),
                &head_response(&head),
            )
            .unwrap_err(),
            ClientError::BadServiceSignature { status: 200 }
        );
    }
}

#[tokio::test]
async fn test_head_header_moved_or_added_fails_the_signature() {
    // The response signature covers the head field, so a head added, dropped or
    // changed on the way fails it (Switch wire 7.1).
    let account = identity().public();
    let tip = ChainTip {
        generation: 1,
        seq: 3,
        chain_hash: [2; 32],
    };
    let good = SignedHead::sign(&service_key(), &account, &tip);
    let key = service_key();
    let header_value = good.to_header();
    let added = Arc::new(MockTransport::with_handler(move |request| {
        let mut response = respond(&key, request, 200, br#"{"pending":true}"#);
        response
            .headers
            .push(Header::new(header::HEAD, &header_value));
        Ok(response)
    }));
    let client = client_with(app(), Some(service_public()), added);
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
    let mut dropped = head_response(&good.to_header());
    dropped.headers.retain(|h| h.name != header::HEAD);
    assert_eq!(
        check_response(&service_public(), &account, &head_request(), &dropped).unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
    // An empty head added to a headless answer fails it (Switch wire 7.1).
    let key = service_key();
    let emptied = Arc::new(MockTransport::with_handler(move |request| {
        let mut response = respond(
            &key,
            request,
            403,
            br#"{"code":"not_current","message":"m"}"#,
        );
        response.headers.push(Header::new(header::HEAD, ""));
        Ok(response)
    }));
    let client = client_with(app(), Some(service_public()), emptied);
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 403 }
    );
    // A request other than the one sent fails it too: another method, path, query, origin,
    // or a signed header added or sent twice.
    let response = head_response(&good.to_header());
    let path = format!("/v1/{}/apps", pubky_id(&identity().public()));
    let signature = b64(&[9; 64]);
    let twice = SentRequest::of(&Request {
        method: "GET".into(),
        origin: "https://switch.example".into(),
        path_and_query: path.clone(),
        headers: vec![
            Header::new(header::SIGNATURE, &signature),
            Header::new(header::SIGNATURE, &signature),
        ],
        body: Vec::new(),
        timeout: TimeoutClass::Bulk,
    });
    let other_origin = SentRequest::of(&Request {
        method: "GET".into(),
        origin: "https://other.example".into(),
        path_and_query: path.clone(),
        headers: vec![Header::new(header::SIGNATURE, &signature)],
        body: Vec::new(),
        timeout: TimeoutClass::Bulk,
    });
    for sent in [
        sent_request("POST", &path, &[(header::SIGNATURE, &signature)]),
        sent_request("get", &path, &[(header::SIGNATURE, &signature)]),
        sent_request(
            "GET",
            &format!("/v1/{}/apps", pubky_id(&[7; 32])),
            &[(header::SIGNATURE, &signature)],
        ),
        sent_request(
            "GET",
            &format!("{path}?x=1"),
            &[(header::SIGNATURE, &signature)],
        ),
        sent_request(
            "GET",
            &path,
            &[(header::SIGNATURE, &signature), (header::INVITE_CODE, "")],
        ),
        sent_request("GET", &path, &[]),
        twice,
        other_origin,
    ] {
        assert_eq!(
            check_response(&service_public(), &account, &sent, &response).unwrap_err(),
            ClientError::BadServiceSignature { status: 200 }
        );
    }
}

#[tokio::test]
async fn test_error_bodies_parse_for_every_code() {
    for code in ErrorCode::ALL {
        let mut body = json!({ "code": code.as_str(), "message": "m" });
        match code {
            ErrorCode::RateLimited => body["retry_after"] = json!(37),
            ErrorCode::IdentityNeeded => {
                body["current"] = json!({ "version": 2 });
                body["known_version"] = json!(2);
            }
            ErrorCode::Conflict => body["current"] = json!({ "server_time": "x" }),
            _ => {}
        }
        let client = client_with(
            app(),
            Some(service_public()),
            fixed(service_key(), code.status(), body),
        );
        let error = client.connect().await.unwrap_err();
        let ClientError::Switch {
            status,
            code: parsed,
            message,
            current,
            known_version,
            retry_after,
        } = &error
        else {
            panic!("{code}: {error:?}");
        };
        assert_eq!((*status, *parsed), (code.status(), code), "{code}");
        assert_eq!(message, "m");
        assert_eq!(error.retry(), Some(code.retry()), "{code}");
        assert_eq!(retry_after.is_some(), code == ErrorCode::RateLimited);
        assert_eq!(*known_version == Some(2), code == ErrorCode::IdentityNeeded);
        assert_eq!(
            current.is_null(),
            !matches!(code, ErrorCode::IdentityNeeded | ErrorCode::Conflict)
        );
    }
}

#[tokio::test]
async fn test_error_bodies_that_dont_read_are_refused() {
    for (status, body) in [
        (409, json!({ "code": "teapot", "message": "m" })),
        (400, json!({ "code": "stale_key", "message": "m" })),
        (409, json!({ "message": "m" })),
        (409, json!({ "code": "conflict" })),
    ] {
        let client = client_with(
            app(),
            Some(service_public()),
            fixed(service_key(), status, body),
        );
        assert!(
            matches!(
                client.connect().await.unwrap_err(),
                ClientError::InvalidResponse(_)
            ),
            "{status}"
        );
    }
}

#[tokio::test]
async fn test_batch_retry_resends_the_same_bytes() {
    let transport = ops_switch(|_| {});
    let clock = Arc::new(TestClock::new(NOW));
    let client = SwitchClient::new(
        ORIGIN,
        identity().public(),
        app(),
        Some(service_public()),
        Arc::clone(&transport) as Arc<dyn Transport>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .unwrap();
    let cursor = Position {
        generation: 1,
        seq: 4,
    };
    let batch = client.sign_batch(1, two_lists(), Some(cursor)).unwrap();
    let first = client.submit(&batch).await.unwrap();
    assert_eq!(first.proofs.len(), 2);
    clock.advance_ms(2_000);
    // Read back from its stored body, the batch is the same batch.
    let resumed = Batch::from_body(batch.body().to_vec()).unwrap();
    assert_eq!(resumed, batch);
    let second = client.submit(&resumed).await.unwrap();
    assert_eq!(second, first);
    let sent = transport.requests();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].body, sent[1].body, "the same body bytes");
    assert_eq!(sent[0].body, batch.body());
    assert_ne!(
        sent[0].header(header::SIGNATURE),
        sent[1].header(header::SIGNATURE),
        "a new request signature with a new timestamp"
    );
}

#[tokio::test]
async fn test_batch_answer_binding_refuses_missing_and_reordered_proofs() {
    let edits: [fn(&mut Vec<SignedDoc>); 4] = [
        |proofs| {
            proofs.pop();
        },
        |proofs| proofs.reverse(),
        |proofs| {
            let first = proofs[0].clone();
            proofs.push(first);
        },
        |proofs| proofs.clear(),
    ];
    for edit in edits {
        let client = client_with(app(), Some(service_public()), ops_switch(edit));
        let batch = client.sign_batch(1, two_lists(), None).unwrap();
        assert!(
            matches!(
                client.submit(&batch).await.unwrap_err(),
                ClientError::Chain(_)
            ),
            "an answer that doesn't bind the batch"
        );
    }
}

#[tokio::test]
async fn test_batch_answer_signed_by_another_key_is_refused() {
    let other = SigningKey::from_bytes(&[6; 32]);
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        // The proofs and the head are another key's; the response is the pinned key's.
        let (proofs, head) = proofs_for(&other, &request.body);
        let body = json!({ "proofs": proofs, "head": head.to_value() });
        Ok(respond(
            &service_key(),
            request,
            200,
            body.to_string().as_bytes(),
        ))
    }));
    let client = client_with(app(), Some(service_public()), transport);
    let batch = client.sign_batch(1, two_lists(), None).unwrap();
    assert!(matches!(
        client.submit(&batch).await.unwrap_err(),
        ClientError::Chain(_)
    ));
}

#[tokio::test]
async fn test_cursor_only_batch_takes_no_proofs() {
    let client = client_with(app(), Some(service_public()), ops_switch(|_| {}));
    let batch = Batch::cursor_only(Position {
        generation: 1,
        seq: 9,
    });
    assert_eq!(batch.id(), None);
    let answer = client.submit(&batch).await.unwrap();
    assert!(answer.proofs.is_empty());
}

#[tokio::test]
async fn test_batch_answer_requires_proofs() {
    // A cursor-only batch is answered `{ "proofs": [], "head" }`, so a missing list would
    // read as that answer.
    let batch = Batch::cursor_only(Position {
        generation: 1,
        seq: 9,
    });
    for edit in WITHOUT_PROOFS {
        let switch = ops_switch_with(|_| {}, edit);
        let client = client_with(app(), Some(service_public()), switch);
        let error = client.submit(&batch).await.unwrap_err();
        assert!(
            matches!(error, ClientError::InvalidResponse(_)),
            "{error:?}"
        );
    }
}

#[test]
fn test_batch_refuses_too_many_entries() {
    let client = client_with(
        app(),
        Some(service_public()),
        fixed(service_key(), 200, json!({})),
    );
    let deny = |n: u8| (Vec::new(), OpKind::DenyPut { pubky: [n; 32] });
    assert!(
        client
            .sign_batch(1, (0..9).map(deny).collect(), None)
            .is_err()
    );
    let ops = client
        .sign_batch(1, (0..8).map(deny).collect(), None)
        .unwrap()
        .ops()
        .to_vec();
    // Eight operations and a cursor are nine entries.
    assert!(matches!(
        Batch::new(ops, Some(Position::default())),
        Err(ClientError::Usage(_))
    ));
    assert!(Batch::from_body(b"{\"ops\":[]}".to_vec()).is_err());
}

#[test]
fn test_requests_carry_the_cert_only_to_another_identity() {
    let transport = fixed(service_key(), 200, json!({}));
    let own = client_with(app(), Some(service_public()), Arc::clone(&transport));
    let request = own
        .sign_request("GET", "/v1/x/feed", Vec::new(), None, TimeoutClass::Bulk)
        .unwrap();
    assert!(request.request.header(header::CERT).is_none());
    assert!(request.request.header(header::APP).is_some());

    let other = IdentityKey::from_secret([9; 32]);
    let foreign = SwitchClient::new(
        ORIGIN,
        other.public(),
        app(),
        Some(service_public()),
        transport,
        Arc::new(TestClock::new(NOW)),
    )
    .unwrap();
    assert!(foreign.is_foreign());
    let code = "IRrC78oNIjZ4hcet2fYnJQ";
    let request = foreign
        .sign_request(
            "GET",
            "/v1/x/directory",
            Vec::new(),
            Some(code),
            TimeoutClass::Bulk,
        )
        .unwrap();
    let cert = request.request.header(header::CERT).unwrap();
    assert_eq!(cert, cert_of(&identity(), &app_keys()).signed().compact());
    assert_eq!(request.request.header(header::INVITE_CODE), Some(code));
    // An invite code that isn't a token isn't sent, an empty one included, which the service
    // would refuse at routing (Switch wire 7.1 "Each header once, as text").
    for code in ["a b", ""] {
        assert!(
            matches!(
                foreign.sign_request(
                    "GET",
                    "/v1/x/directory",
                    Vec::new(),
                    Some(code),
                    TimeoutClass::Bulk
                ),
                Err(ClientError::Usage(_))
            ),
            "{code:?}"
        );
    }
    // Every request it builds keeps the header rule the service checks at routing.
    for (client, code) in [(&own, None), (&foreign, Some(code))] {
        let request = client
            .sign_request(
                "POST",
                "/v1/x/ops",
                b"{}".to_vec(),
                code,
                TimeoutClass::Ordinary,
            )
            .unwrap()
            .request;
        let received = http::ReceivedHeaders::of(
            request
                .headers
                .iter()
                .map(|header| (header.name.as_str(), header.value.as_bytes())),
        );
        assert_eq!(received.broken_rule(), None);
    }
    // Operations are written only at the caller's own account.
    assert!(foreign.sign_batch(1, two_lists(), None).is_err());
}

#[test]
fn test_credentials_must_match_their_keys() {
    let transport: Arc<dyn Transport> = fixed(service_key(), 200, json!({}));
    let wrong_signer = Credentials::Signer {
        identity: [1; 32],
        key: Arc::new(identity()),
    };
    let new = |credentials| {
        SwitchClient::new(
            ORIGIN,
            identity().public(),
            credentials,
            None,
            Arc::clone(&transport),
            Arc::new(TestClock::new(NOW)),
        )
    };
    assert!(matches!(new(wrong_signer), Err(ClientError::Usage(_))));
    let wrong_app = Credentials::App {
        identity: identity().public(),
        keys: AppKeys::from_secrets([8; 32], [9; 32]),
        cert: cert_of(&identity(), &app_keys()),
    };
    assert!(matches!(new(wrong_app), Err(ClientError::Usage(_))));
    assert!(new(app()).is_ok());
    assert!(new(signer()).is_ok());
    assert!(new(signer_requests()).is_ok());
    let wrong_requests = Credentials::SignerRequests {
        identity: [1; 32],
        key: Arc::new(RequestsOnly(identity())),
    };
    assert!(matches!(new(wrong_requests), Err(ClientError::Usage(_))));
}

#[test]
fn test_signer_requests_credential_signs_a_request_that_verifies() {
    let transport = fixed(service_key(), 200, json!({}));
    let requests = client_with(
        signer_requests(),
        Some(service_public()),
        Arc::clone(&transport),
    );
    requests.signer_only().unwrap();
    let signed = requests
        .sign_request("GET", "/v1/x/apps", Vec::new(), None, TimeoutClass::Bulk)
        .unwrap();
    let signature =
        http::decode_signature(signed.request.header(header::SIGNATURE).unwrap()).unwrap();
    let target = http::RequestTarget {
        method: "GET",
        path_and_query: "/v1/x/apps",
        body: &[],
        origin: ORIGIN,
    };
    let headers = http::RequestHeaders {
        timestamp: pubky_switch_core::time::rfc3339_seconds(NOW),
        identity: pubky_id(&identity().public()),
        created: Some(rfc3339(0)),
        ..http::RequestHeaders::default()
    };
    http::verify_request(&identity().public(), &target, &headers, &signature).unwrap();
    // The same request, headers and signature as the signer's full credential gives.
    let full = client_with(signer(), Some(service_public()), transport);
    assert_eq!(
        full.sign_request("GET", "/v1/x/apps", Vec::new(), None, TimeoutClass::Bulk)
            .unwrap(),
        signed
    );
}

#[test]
fn test_signer_requests_credential_signs_no_batch() {
    let transport = fixed(service_key(), 200, json!({}));
    let requests = client_with(signer_requests(), Some(service_public()), transport);
    let refused = requests.sign_batch(1, two_lists(), None).unwrap_err();
    assert!(
        matches!(&refused, ClientError::Usage(why) if why.contains("requests only")),
        "{refused:?}"
    );
}

#[test]
fn test_credentials_debug_shows_no_key() {
    let text = format!("{:?} {:?} {:?}", signer(), signer_requests(), app());
    assert!(text.contains(&pubky_id(&identity().public())), "{text}");
    for secret in [[1u8; 32], [2; 32], [3; 32]] {
        assert!(!text.contains(&b64(&secret)), "{text}");
        assert!(!text.contains(&format!("{secret:?}")), "{text}");
    }
}

#[tokio::test]
async fn test_public_read_unreadable_signed_header_fails_authentication() {
    let pin = Some(service_public());
    for status in [200, 503] {
        let transport = Arc::new(MockTransport::new());
        transport.push_error(TransportError::UnreadableSignedHeader { status });
        let client = client_with(app(), pin, transport);
        assert_eq!(
            client.public_identity().await.unwrap_err(),
            ClientError::BadServiceSignature { status }
        );
        assert_eq!(client.pinned_key(), pin);
        assert_eq!(client.last_server_time(), None);
    }
}

#[tokio::test]
async fn test_public_read_signed_time_window() {
    let window = http::PUBLIC_READ_CACHE_MS + 2 * pubky_switch_core::records::CLOCK_TOLERANCE_MS;
    let doc = IdentityDoc::sign(
        &identity(),
        IdentityBody::first(
            identity().public(),
            [0; 16],
            Inbox::new(ORIGIN, service_public()),
            IdentityPolicy::default(),
        ),
    )
    .unwrap();
    for (offset, accepted) in [(0, true), (window, true), (window + 1, false)] {
        for at in [NOW - offset, NOW + offset] {
            for status in [200, 503] {
                let body = if status == 200 {
                    json!({ "identity": doc.signed() })
                } else {
                    json!({ "code": "staged", "message": "waiting" })
                };
                let transport = Arc::new(MockTransport::with_handler(move |request| {
                    Ok(timed_response(request, status, body.clone(), None, at))
                }));
                let client = client_with(app(), Some(service_public()), transport);
                let answer = client.public_identity().await;
                if !accepted {
                    assert_eq!(
                        answer.unwrap_err(),
                        ClientError::StaleAnswer { server_time_ms: at }
                    );
                } else if status == 200 {
                    let public = answer.unwrap();
                    assert_eq!(public.identity.version(), doc.version());
                    assert_eq!(public.server_time_ms(), at);
                } else {
                    assert!(matches!(
                        answer,
                        Err(ClientError::Switch {
                            code: ErrorCode::Staged,
                            ..
                        })
                    ));
                }
            }
        }
    }
}

#[tokio::test]
async fn test_public_read_requires_a_pin_before_sending() {
    let transport = Arc::new(MockTransport::new());
    let client = client_with(app(), None, Arc::clone(&transport));
    assert_eq!(
        client.public_identity().await.unwrap_err(),
        ClientError::Unpinned
    );
    assert!(transport.last_request().is_none());
}

/// A delivery of the account's `identity.json` naming `named` as its service key here.
fn delivery_naming(named: [u8; 32]) -> IdentityDelivery {
    let mut body = IdentityBody::first(
        identity().public(),
        [0; 16],
        Inbox::new(ORIGIN, named),
        IdentityPolicy::default(),
    );
    body.generation = 2;
    body.version = 2;
    IdentityDelivery {
        identity: IdentityDoc::sign(&identity(), body)
            .unwrap()
            .signed()
            .clone(),
        prev: Some([4; 32]),
    }
}

/// A switch that answers a delivery `200` with its proof, signed with `key`.
fn delivery_switch(key: SigningKey) -> Arc<MockTransport> {
    Arc::new(MockTransport::with_handler(move |request| {
        let delivery = IdentityDelivery::parse(&request.body).unwrap();
        let doc = IdentityDoc::verify(&delivery.identity, &identity().public()).unwrap();
        let tip = ChainTip {
            generation: 2,
            seq: 4,
            chain_hash: [9; 32],
        };
        let bytes = delivery.identity.doc_bytes().unwrap();
        let (stub, next) = tip
            .append(
                5,
                NOW,
                ItemType::Identity,
                item_hash(ItemType::Identity, &bytes),
                None,
            )
            .unwrap();
        let state = ProofState::Identity {
            version: doc.version(),
            generation: doc.generation(),
            data_epoch: doc.data_epoch(),
        };
        let account = identity().public();
        let proof = TransitionProof::sign(
            &key,
            &account,
            ProofBody::new(stub, "identity".into(), &state),
        )
        .unwrap();
        let head = SignedHead::sign(&key, &account, &next);
        let body = json!({ "proofs": [proof.signed()], "head": head.to_value() });
        Ok(respond(&key, request, 200, body.to_string().as_bytes()))
    }))
}

#[tokio::test]
async fn test_put_identity_starting_a_generation_pins_the_named_service_key() {
    let pending = SigningKey::from_bytes(&[6; 32]);
    let pending_public = pending.verifying_key().to_bytes();
    let transport = delivery_switch(pending);
    let client = client_with(signer(), Some(service_public()), transport);
    let answer = client
        .put_identity(&delivery_naming(pending_public))
        .await
        .unwrap();
    assert_eq!(answer.proofs.len(), 1);
    assert_eq!(client.pinned_key(), Some(pending_public));
}

#[tokio::test]
async fn test_put_identity_starting_a_generation_keeps_the_pin_on_errors() {
    let pending = SigningKey::from_bytes(&[6; 32]);
    let pending_public = pending.verifying_key().to_bytes();
    // A refusal comes under the old key, and keeps its pin.
    let refusal = fixed(
        service_key(),
        409,
        json!({ "code": "conflict", "message": "m" }),
    );
    let client = client_with(signer(), Some(service_public()), refusal);
    let error = client
        .put_identity(&delivery_naming(pending_public))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict));
    assert_eq!(client.pinned_key(), Some(service_public()));
    // A refusal signed with the new key doesn't verify: it is checked with the pinned one.
    let refusal = fixed(
        pending.clone(),
        409,
        json!({ "code": "conflict", "message": "m" }),
    );
    let client = client_with(signer(), Some(service_public()), refusal);
    let error = client
        .put_identity(&delivery_naming(pending_public))
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::BadServiceSignature { .. }));
    // A `200` signed with the old key doesn't verify either.
    let client = client_with(
        signer(),
        Some(service_public()),
        delivery_switch(service_key()),
    );
    let error = client
        .put_identity(&delivery_naming(pending_public))
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::BadServiceSignature { .. }));
    assert_eq!(client.pinned_key(), Some(service_public()));
}

/// A feed page holding `items`, with a head, as the client reads it.
fn feed_page_with(items: Value) -> Result<FeedPage, ClientError> {
    let head = SignedHead::sign(
        &service_key(),
        &identity().public(),
        &ChainTip {
            generation: 1,
            seq: 9,
            chain_hash: [9; 32],
        },
    );
    let value = json!({ "items": items, "next": "1:9", "scanned_through": 9, "more": false,
                        "cursor": 0, "head": head.to_value() });
    FeedPage::read(
        Obj::of(&value, "a feed page").unwrap(),
        &identity().public(),
        NOW,
        service_public(),
    )
}

#[test]
fn test_feed_item_of_an_unknown_type_is_skipped_and_its_stub_kept() {
    let tip = ChainTip {
        generation: 1,
        seq: 4,
        chain_hash: [9; 32],
    };
    let (stub, _) = tip
        .append(5, NOW, ItemType::Service, [3; 32], None)
        .unwrap();
    let page = feed_page_with(json!([
        { "type": "later_kind", "seq": 5, "stub": stub.to_value(), "extra": 1 },
        { "type": "later_kind", "seq": 6 },
        { "type": "stub", "seq": 7, "stub": stub.to_value() },
    ]))
    .unwrap();
    assert_eq!(
        page.items,
        vec![
            FeedItem::Stub {
                seq: 5,
                stub: stub.clone()
            },
            FeedItem::Stub { seq: 7, stub },
        ]
    );
}

#[test]
fn test_feed_item_of_an_unknown_type_with_a_bad_stub_is_refused() {
    let items = json!([{ "type": "later_kind", "seq": 5, "stub": "not a stub" }]);
    let error = feed_page_with(items).unwrap_err();
    assert!(
        matches!(error, ClientError::InvalidResponse(_)),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_public_read_sends_no_switch_header() {
    let transport = fixed(
        service_key(),
        404,
        json!({ "code": "not_found", "message": "m" }),
    );
    let client = client_with(app(), Some(service_public()), Arc::clone(&transport));
    let error = client.public_identity().await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotFound));
    let sent = transport.last_request().unwrap();
    assert!(sent.headers.iter().all(|h| !h.name.starts_with("switch-")));
}

#[tokio::test]
async fn test_client_404_signed_with_an_unpinned_key_reads_as_unauthenticated() {
    // A `404` signed with a key the client doesn't pin, an intermediary's or another
    // switch's, is no answer of its switch.
    let other = SigningKey::from_bytes(&[42; 32]);
    let client = client_with(
        signer(),
        Some(service_public()),
        fixed(
            other,
            404,
            json!({ "code": "not_found", "message": "no such account" }),
        ),
    );
    assert_eq!(
        client.erase(Some(0), None).await.unwrap_err(),
        ClientError::BadServiceSignature { status: 404 }
    );
}

#[tokio::test]
async fn test_signer_and_app_calls_refuse_the_other_caller() {
    let transport = fixed(service_key(), 200, json!({}));
    let client = client_with(app(), Some(service_public()), Arc::clone(&transport));
    assert!(matches!(client.apps().await, Err(ClientError::Usage(_))));
    assert!(matches!(
        client.erase(Some(0), None).await,
        Err(ClientError::Usage(_))
    ));
    let client = client_with(signer(), Some(service_public()), Arc::clone(&transport));
    assert!(matches!(client.keys().await, Err(ClientError::Usage(_))));
    assert!(matches!(client.leave().await, Err(ClientError::Usage(_))));
    assert!(matches!(
        client.export_chunk("../x").await,
        Err(ClientError::Usage(_))
    ));
    assert!(transport.requests().is_empty());
}

/// A switch that answers a leave with a proof naming `object`, or the caller's App ID.
fn leave_switch(object: Option<&'static str>) -> Arc<MockTransport> {
    leave_switch_with(object, |_| {})
}

/// [`leave_switch`], with the answer's body passed through `edit_body`.
fn leave_switch_with(
    object: Option<&'static str>,
    edit_body: fn(&mut Value),
) -> Arc<MockTransport> {
    let key = service_key();
    let account = identity().public();
    Arc::new(MockTransport::with_handler(move |request| {
        let tip = ChainTip {
            generation: 1,
            seq: 1,
            chain_hash: [0; 32],
        };
        let (stub, tip) = tip
            .append(2, NOW, ItemType::Service, [3; 32], None)
            .unwrap();
        // `/v1/{id}/apps/{app_id}/leave`
        let app = request.path_and_query.split('/').nth(4).unwrap().to_owned();
        let object = object.map_or(app, str::to_owned);
        let state = ProofState::Service(json!({ "type": "leave" }));
        let proof =
            TransitionProof::sign(&key, &account, ProofBody::new(stub, object, &state)).unwrap();
        let mut body = json!({
            "proofs": [proof.signed()],
            "head": SignedHead::sign(&key, &account, &tip).to_value(),
        });
        edit_body(&mut body);
        Ok(respond(&key, request, 200, body.to_string().as_bytes()))
    }))
}

#[tokio::test]
async fn test_write_answer_requires_proofs() {
    // A revoke of a revoked app is answered `{ "proofs": [], "head" }`, so a missing list
    // would read as a write that wrote nothing.
    for edit in WITHOUT_PROOFS {
        let client = client_with(app(), Some(service_public()), leave_switch_with(None, edit));
        let error = client.leave().await.unwrap_err();
        assert!(
            matches!(error, ClientError::InvalidResponse(_)),
            "{error:?}"
        );
    }
}

#[tokio::test]
async fn test_write_answer_proof_must_be_the_transition_written() {
    let client = client_with(app(), Some(service_public()), leave_switch(None));
    let answer = client.leave().await.unwrap();
    assert_eq!(answer.proofs.len(), 1);
    assert_eq!(answer.head.seq, 2);
    // A proof of another app's leave doesn't answer this one.
    let client = client_with(app(), Some(service_public()), leave_switch(Some("other")));
    assert!(matches!(
        client.leave().await.unwrap_err(),
        ClientError::Chain(_)
    ));
}

#[tokio::test]
async fn test_compared_time_leaves_out_exactly_the_time_base_answers() {
    // Every answer checked with the pinned key counts in the comparison of service times,
    // refusals without the head included, but the notice, every `503 unavailable`, the
    // not-hosted `404`, an answer that verifies only with the empty body field, and every
    // answer to the enrollment, the erasure and the public read (Switch wire 7.1 Timestamp,
    // spec 10.1).
    let error = |code: &str, current: Value| {
        let mut body = json!({ "code": code, "message": "m" });
        if !current.is_null() {
            body["current"] = current;
        }
        body
    };
    let notice = json!({ "generation": 1, "reason": "behind", "permanent": false });
    for (status, body, compared) in [
        (
            200,
            json!({ "contacts": [], "conversations": [], "deny": [], "flagged": [],
                      "invite_codes": [] }),
            true,
        ),
        (401, error("bad_signature", Value::Null), true),
        (
            401,
            error("stale_timestamp", json!({ "server_time": rfc3339(NOW) })),
            true,
        ),
        (403, error("not_current", Value::Null), true),
        (429, error("rate_limited", Value::Null), true),
        (503, error("staged", Value::Null), true),
        (409, error("conflict", Value::Null), true),
        (503, error("unavailable", Value::Null), false),
        (404, error("not_found", Value::Null), true),
        (404, error("not_found", json!({ "hosted": true })), true),
        (404, error("not_found", http::not_hosted_current()), false),
        (503, error("recovery_required", notice.clone()), false),
    ] {
        let client = client_with(
            app(),
            Some(service_public()),
            fixed(service_key(), status, body.clone()),
        );
        let _ = client.allow().await;
        assert_eq!(
            client.latest_compared_time(),
            compared.then_some(NOW),
            "{status} {body}"
        );
    }
    // Given before the body was read: a `413`, which verifies only with the empty body field.
    let key = service_key();
    let unread = Arc::new(MockTransport::with_handler(move |request| {
        let body = error("too_large", Value::Null).to_string().into_bytes();
        let server_time = rfc3339(NOW);
        let signature = sign_response(
            &key,
            &http::ResponseParts {
                status: 413,
                request: SentRequest::of(request).received(false),
                server_time: &server_time,
                head: None,
                body: &body,
            },
        );
        Ok(Response {
            status: 413,
            headers: vec![
                Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
                Header::new(header::SERVER_TIME, &server_time),
            ],
            body,
        })
    }));
    let client = client_with(app(), Some(service_public()), unread);
    assert!(matches!(
        client.allow().await,
        Err(ClientError::BodyUnread { status: 413, .. })
    ));
    assert_eq!(client.latest_compared_time(), None);
    // Every answer to the public read, which binds no request, a success included; the
    // same answer to a signed read counts.
    let client = client_with(
        app(),
        Some(service_public()),
        fixed(service_key(), 429, error("rate_limited", Value::Null)),
    );
    let _ = client.public_identity().await;
    assert_eq!(client.latest_compared_time(), None, "public read");
    // Every answer to the erasure, a refusal and a success.
    for (status, body) in [
        (429, error("rate_limited", Value::Null)),
        (409, error("conflict", json!({ "created": rfc3339(NOW) }))),
        (200, json!({ "erased": true })),
    ] {
        let client = client_with(
            signer(),
            Some(service_public()),
            fixed(service_key(), status, body.clone()),
        );
        let _ = client.erase(Some(0), None).await;
        assert_eq!(
            client.latest_compared_time(),
            None,
            "erasure {status} {body}"
        );
    }
    // The same refusal to a signed read counts.
    let client = client_with(
        signer(),
        Some(service_public()),
        fixed(service_key(), 429, error("rate_limited", Value::Null)),
    );
    let _ = client.apps().await;
    assert_eq!(client.latest_compared_time(), Some(NOW), "a signed read");
    // An enrollment's answer: the latest call's times are forgotten, not kept from an
    // earlier one.
    let client = client_with(
        signer(),
        Some(service_public()),
        fixed(service_key(), 429, error("rate_limited", Value::Null)),
    );
    let _ = client.apps().await;
    assert_eq!(client.latest_compared_time(), Some(NOW));
    let _ = client.enroll(&enrollment([1; 16])).await;
    assert_eq!(client.latest_compared_time(), None, "enrollment");
}

#[tokio::test]
async fn test_last_server_time_follows_checked_answers_only() {
    let transport = fixed(
        service_key(),
        200,
        json!({ "contacts": [], "conversations": [], "deny": [], "flagged": [],
                "invite_codes": [] }),
    );
    let client = client_with(app(), Some(service_public()), Arc::clone(&transport));
    assert_eq!(client.last_server_time(), None);
    client.allow().await.unwrap();
    assert_eq!(client.last_server_time(), Some(NOW));
    // An answer the pinned key didn't sign leaves the time as it was.
    let other = SigningKey::from_bytes(&[6; 32]);
    let forged = fixed(other, 200, json!({}));
    let client = client_with(app(), Some(service_public()), forged);
    assert!(client.allow().await.is_err());
    assert_eq!(client.last_server_time(), None);
    // A refusal answered before the request verified, without a head, carries no stamped
    // time (Switch wire 7.1).
    let early = fixed(
        service_key(),
        401,
        json!({ "code": "bad_signature", "message": "7.2" }),
    );
    let client = client_with(app(), Some(service_public()), early);
    assert!(client.allow().await.is_err());
    assert_eq!(client.last_server_time(), None);
    assert_eq!(client.latest_server_time(), None);
}

#[tokio::test]
async fn test_last_server_time_ignores_the_public_read() {
    // The public read binds no request, so its answer may be an earlier one sent again
    // (Switch wire 7.1 "Identical requests"): its time is no latest time.
    let doc = IdentityDoc::sign(
        &identity(),
        IdentityBody::first(
            identity().public(),
            [0; 16],
            Inbox::new(ORIGIN, service_public()),
            IdentityPolicy::default(),
        ),
    )
    .unwrap();
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        Ok(
            if http::is_public_read(&request.method, &request.path_and_query) {
                let body = json!({ "identity": doc.signed() });
                timed_response(request, 200, body, None, NOW - 600_000)
            } else {
                let body = json!({ "contacts": [], "conversations": [], "deny": [],
                                   "flagged": [], "invite_codes": [] });
                timed_response(request, 200, body, None, NOW)
            },
        )
    }));
    let client = client_with(app(), Some(service_public()), transport);
    client.allow().await.unwrap();
    client.public_identity().await.unwrap();
    assert_eq!(client.last_server_time(), Some(NOW));
    assert_eq!(client.latest_server_time(), None);
}

/// A batch of one shared record write.
fn record_write() -> Vec<(Vec<Condition>, OpKind)> {
    use pubky_switch_core::ident::{Policy, collection_id, record_key_from_blinded};
    use pubky_switch_core::ops::{IdInputs, RecordPut, RecordVersion};
    use pubky_switch_core::sealed::SealedValue;
    let identity = identity().public();
    let policy = Policy::new("sample", &["sample"]);
    let blinded_key = [2; 32];
    let key = record_key_from_blinded("sample.items", &blinded_key, &policy.hash().unwrap());
    let put = RecordPut {
        key,
        collection: collection_id("sample.items", &identity),
        policy,
        expected_version: RecordVersion::new(1, 4),
        value_sealed: SealedValue::seal(&[3; 32], &identity, 1, "sample", &key, b"{}").unwrap(),
        id_inputs: IdInputs {
            collection: "sample.items".into(),
            blinded_key,
        },
    };
    vec![(Vec::new(), OpKind::RecordPut(put))]
}

#[tokio::test]
async fn test_calls_pick_their_timeout_class() {
    // A switch whose answers don't read: every call fails, after its request went.
    let transport = fixed(service_key(), 200, json!({}));
    let client = client_with(app(), Some(service_public()), Arc::clone(&transport));
    // The class of the `n`th request, which the call just made must have sent.
    let class = |n: usize| {
        let sent = transport.requests();
        assert_eq!(sent.len(), n, "the call sent no request");
        sent[n - 1].timeout
    };
    let feed = |limit, wait| answers::FeedQuery {
        after: None,
        limit,
        wait,
    };
    // A feed page with no items, the read of the service time, is small.
    let _ = client.feed(feed(Some(0), None)).await;
    assert_eq!(class(1), TimeoutClass::Ordinary);
    // A page is bulk, and a long poll carries its wait.
    let _ = client.feed(feed(Some(100), None)).await;
    assert_eq!(class(2), TimeoutClass::Bulk);
    let _ = client.feed(feed(None, Some(0))).await;
    assert_eq!(class(3), TimeoutClass::Bulk);
    let _ = client.feed(feed(Some(1), Some(25))).await;
    assert_eq!(class(4), TimeoutClass::LongPoll { wait_s: 25 });
    // Listings, a record's view and an append are bulk.
    let _ = client.directory(None).await;
    assert_eq!(class(5), TimeoutClass::Bulk);
    let _ = client.allow().await;
    assert_eq!(class(6), TimeoutClass::Bulk);
    let _ = client.record(&[1; 32]).await;
    assert_eq!(class(7), TimeoutClass::Bulk);
    let _ = client.claim(&[1; 32]).await;
    assert_eq!(class(8), TimeoutClass::Bulk);
    let _ = client.append(vec![0; 16], 1, None).await;
    assert_eq!(class(9), TimeoutClass::Bulk);
    // A connect write is small. A public identity read can return the full document.
    let _ = client.connect().await;
    assert_eq!(class(10), TimeoutClass::Ordinary);
    let _ = client.public_identity().await;
    assert_eq!(class(11), TimeoutClass::Bulk);
    // Unconditional list changes have small answers.
    let lists = client.sign_batch(1, two_lists(), None).unwrap();
    let _ = client.submit(&lists).await;
    assert_eq!(class(12), TimeoutClass::Ordinary);
    // One that writes a shared record is bulk, on its first send and read back from its
    // kept body for a resend: its refusal can carry the record's view.
    let record = client.sign_batch(1, record_write(), None).unwrap();
    let _ = client.submit(&record).await;
    assert_eq!(class(13), TimeoutClass::Bulk);
    let kept = Batch::from_body(record.body().to_vec()).unwrap();
    let _ = client.submit(&kept).await;
    assert_eq!(class(14), TimeoutClass::Bulk);
    // A list change with an exact current-record condition can receive a whole view.
    let mut ops = two_lists();
    ops[1].0.push(Condition::RecordCurrent {
        key: [3; 32],
        revision: pubky_switch_core::shared::ApplicationRef {
            generation: 1,
            seq: 4,
            item_hash: [5; 32],
        },
        deleted: false,
    });
    let conditional = client.sign_batch(1, ops, None).unwrap();
    let _ = client.submit(&conditional).await;
    assert_eq!(class(15), TimeoutClass::Bulk);
    let kept = Batch::from_body(conditional.body().to_vec()).unwrap();
    let _ = client.submit(&kept).await;
    assert_eq!(class(16), TimeoutClass::Bulk);
    // These calls can return a pending list or a held identity document.
    let delivery = delivery_naming(service_public());
    let _ = client.connect_requests().await;
    assert_eq!(class(17), TimeoutClass::Bulk);
    let _ = client.put_peers(&delivery.identity, None).await;
    assert_eq!(class(18), TimeoutClass::Bulk);
    let signer_client = client_with(signer(), Some(service_public()), Arc::clone(&transport));
    let _ = signer_client.put_identity(&delivery).await;
    assert_eq!(class(19), TimeoutClass::Bulk);
    let _ = signer_client.erase(Some(0), None).await;
    assert_eq!(class(20), TimeoutClass::Bulk);
    let _ = signer_client.observe_account().await;
    assert_eq!(class(21), TimeoutClass::Ordinary);
    // The raw caller supplies the transport class as part of constructing the request.
    let signed = client
        .sign_request(
            "GET",
            "/v1/x/feed?wait=12",
            Vec::new(),
            None,
            TimeoutClass::LongPoll { wait_s: 12 },
        )
        .unwrap();
    assert_eq!(
        signed.request.timeout,
        TimeoutClass::LongPoll { wait_s: 12 }
    );
}

/// A response to `request` signed with `key` over the empty body field, as the service
/// signs an answer it gives before it reads the body (Switch wire 7.1).
fn respond_unread(
    key: &SigningKey,
    request: &Request,
    status: u16,
    body: &[u8],
    head: Option<&str>,
) -> Response {
    let mut response = respond_with_head(key, request, status, body, head);
    let server_time = rfc3339(NOW);
    let signature = sign_response(
        key,
        &http::ResponseParts {
            status,
            request: SentRequest::of(request).received(false),
            server_time: &server_time,
            head,
            body,
        },
    );
    for header in &mut response.headers {
        if header.name == header::SERVICE_SIGNATURE {
            header.value = b64(&signature);
        }
    }
    response
}

#[tokio::test]
async fn test_response_before_the_body_is_read_is_final_for_nothing() {
    // A `413`, a `429` and a `404` that verify only with the empty body field may answer a
    // request whose length was changed on the way: verified, but final for nothing (Switch
    // wire 7.1).
    for (status, code) in [
        (413, ErrorCode::TooLarge),
        (429, ErrorCode::RateLimited),
        (404, ErrorCode::NotFound),
    ] {
        let body = json!({ "code": code.as_str(), "message": "m", "retry_after": 5 })
            .to_string()
            .into_bytes();
        let key = service_key();
        let unread = body.clone();
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            Ok(respond_unread(&key, request, status, &unread, None))
        }));
        let client = client_with(app(), Some(service_public()), transport);
        let error = client.connect().await.unwrap_err();
        assert_eq!(
            error,
            ClientError::BodyUnread {
                status,
                code,
                retry_after: Some(5),
            }
        );
        assert_eq!(error.code(), None);
        assert_eq!(error.retry(), None);
        // Signed over the body, the same answer is the service's refusal of these bytes.
        let key = service_key();
        let read = body.clone();
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            Ok(respond(&key, request, status, &read))
        }));
        let client = client_with(app(), Some(service_public()), transport);
        assert_eq!(client.connect().await.unwrap_err().code(), Some(code));
    }
}

#[tokio::test]
async fn test_response_with_the_empty_body_field_fails_unless_before_the_body() {
    // Any other answer that verifies only with the empty body field, a `200` above all,
    // fails as a signature that doesn't verify, and so does one of those three with a head
    // (Switch wire 7.1).
    let account = identity().public();
    let tip = ChainTip {
        generation: 1,
        seq: 3,
        chain_hash: [2; 32],
    };
    let head = SignedHead::sign(&service_key(), &account, &tip).to_header();
    for (status, body, head) in [
        (200, json!({ "pending": true }), None),
        (
            401,
            json!({ "code": "bad_signature", "message": "m" }),
            None,
        ),
        (403, json!({ "code": "not_current", "message": "m" }), None),
        (
            413,
            json!({ "code": "too_large", "message": "m" }),
            Some(head.clone()),
        ),
        (
            404,
            json!({ "code": "not_found", "message": "m" }),
            Some(head.clone()),
        ),
    ] {
        let key = service_key();
        let bytes = body.to_string().into_bytes();
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            Ok(respond_unread(
                &key,
                request,
                status,
                &bytes,
                head.as_deref(),
            ))
        }));
        let client = client_with(app(), Some(service_public()), transport);
        assert_eq!(
            client.connect().await.unwrap_err(),
            ClientError::BadServiceSignature { status },
            "{status}"
        );
    }
}

#[tokio::test]
async fn test_response_with_a_repeated_signed_header_fails() {
    // `Switch-Service-Signature`, `Switch-Server-Time` and `Switch-Head` each come once
    // (Switch wire 7.1).
    let account = identity().public();
    let tip = ChainTip {
        generation: 1,
        seq: 3,
        chain_hash: [2; 32],
    };
    let head = SignedHead::sign(&service_key(), &account, &tip).to_header();
    let good = head_response(&head);
    assert!(check_response(&service_public(), &account, &head_request(), &good).is_ok());
    for name in [header::SERVICE_SIGNATURE, header::SERVER_TIME, header::HEAD] {
        let mut repeated = good.clone();
        let copy = repeated
            .headers
            .iter()
            .find(|h| h.name == name)
            .unwrap()
            .clone();
        repeated
            .headers
            .push(Header::new(&name.to_uppercase(), &copy.value));
        assert_eq!(
            check_response(&service_public(), &account, &head_request(), &repeated).unwrap_err(),
            ClientError::BadServiceSignature { status: 200 },
            "{name}"
        );
    }
    // A head sent twice on a headless answer fails it too, rather than reading as no head.
    let key = service_key();
    let doubled = Arc::new(MockTransport::with_handler(move |request| {
        let mut response = respond(&key, request, 200, br#"{"pending":true}"#);
        response.headers.push(Header::new(header::HEAD, &head));
        response.headers.push(Header::new(header::HEAD, &head));
        Ok(response)
    }));
    let client = client_with(app(), Some(service_public()), doubled);
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
}

#[tokio::test]
async fn test_response_replayed_as_the_answer_to_another_call_fails() {
    // A verified answer to one call, sent back as the answer to another, or to the same
    // call signed a second later, fails: it binds the request it answered (Switch wire 7.1).
    let key = service_key();
    let recorded: Arc<std::sync::Mutex<Option<Response>>> = Arc::default();
    let held = recorded.clone();
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        let mut held = held.lock().unwrap();
        Ok(held
            .get_or_insert_with(|| respond(&key, request, 200, br#"{"pending":true}"#))
            .clone())
    }));
    let clock = Arc::new(TestClock::new(NOW));
    let client = SwitchClient::new(
        ORIGIN,
        identity().public(),
        app(),
        Some(service_public()),
        transport,
        clock.clone(),
    )
    .unwrap();
    client.connect().await.unwrap();
    // The same call within the same second is the same request (Switch wire 7.1).
    client.connect().await.unwrap();
    assert!(matches!(
        client.connect_requests().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    ));
    clock.advance_ms(1_000);
    assert_eq!(
        client.connect().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 200 }
    );
    assert!(recorded.lock().unwrap().is_some());
}

#[tokio::test]
async fn test_body_over_its_cap_is_never_sent() {
    // A body over its call's cap is refused before it is sent, for good: the service would
    // answer it before reading it, an answer final for nothing (Switch wire 7.1 Body caps).
    let transport = Arc::new(MockTransport::new());
    let client = client_with(app(), Some(service_public()), transport.clone());
    assert_eq!(
        client.append(vec![0; 65_537], 1, None).await.unwrap_err(),
        ClientError::BodyOverCap { cap: 65_536 }
    );
    assert!(transport.last_request().is_none(), "nothing was sent");
}

fn raw_request(method: &str, path: &str, bytes: usize) -> SignedRequest {
    sign_raw_request(Request {
        method: method.into(),
        origin: ORIGIN.into(),
        path_and_query: path.into(),
        headers: Vec::new(),
        body: if method == "POST" && path == "/v1/enroll" {
            let mut body =
                serde_json::to_vec(&json!({ "enrollment": enrollment([4; 16]).signed() })).unwrap();
            body.resize(bytes, b' ');
            body
        } else {
            vec![0; bytes]
        },
        timeout: TimeoutClass::Ordinary,
    })
}

fn sign_raw_request(mut request: Request) -> SignedRequest {
    let headers = RequestHeaders {
        timestamp: rfc3339(NOW),
        identity: identity().id(),
        created: Some(rfc3339(0)),
        ..RequestHeaders::default()
    };
    let target = RequestTarget {
        method: &request.method,
        origin: &request.origin,
        path_and_query: &request.path_and_query,
        body: &request.body,
    };
    let signature = http::sign_request(&identity(), &target, &headers);
    http::verify_request(&identity().public(), &target, &headers, &signature).unwrap();
    request.headers = vec![
        Header::new(header::IDENTITY, &headers.identity),
        Header::new(header::TIMESTAMP, &headers.timestamp),
        Header::new(header::SIGNATURE, &b64(&signature)),
        Header::new(header::CREATED, &rfc3339(0)),
    ];
    SignedRequest { request }
}

#[tokio::test]
async fn test_raw_send_over_cap_is_never_sent() {
    let transport = fixed(service_key(), 200, json!({}));
    let client = client_with(signer(), Some(service_public()), transport.clone());
    let inbox = format!("/v1/{}/inbox", identity().id());
    let public = format!("/v1/{}/identity", identity().id());
    let mut results = Vec::new();
    for (method, path, cap) in [
        ("POST", inbox.as_str(), 65_536),
        ("POST", "/v1/enroll", 256 << 10),
        ("GET", public.as_str(), 0),
    ] {
        let request = raw_request(method, path, cap + 1);
        results.push((client.send(request).await, cap));
    }
    assert!(transport.last_request().is_none(), "nothing was sent");
    for (result, cap) in results {
        assert_eq!(result.unwrap_err(), ClientError::BodyOverCap { cap });
    }
}

#[tokio::test]
async fn test_raw_send_mutated_request_uses_current_cap() {
    let transport = fixed(service_key(), 200, json!({}));
    let client = client_with(signer(), Some(service_public()), transport.clone());
    let inbox = format!("/v1/{}/inbox", identity().id());
    let ops = format!("/v1/{}/ops", identity().id());
    let public = format!("/v1/{}/identity", identity().id());
    let mut body = client
        .sign_request("POST", &inbox, vec![0; 65_536], None, TimeoutClass::Bulk)
        .unwrap()
        .request;
    body.body.push(0);
    let mut route = client
        .sign_request("POST", &ops, vec![0; 65_537], None, TimeoutClass::Bulk)
        .unwrap()
        .request;
    route.path_and_query = inbox;
    let mut method = client
        .sign_request("PUT", &public, vec![0; 1], None, TimeoutClass::Bulk)
        .unwrap()
        .request;
    method.method = "GET".into();
    let mut results = Vec::new();
    for (request, cap) in [(body, 65_536), (route, 65_536), (method, 0)] {
        // The final bytes are signed again: rejection cannot depend on a stale signature.
        results.push((client.send(sign_raw_request(request)).await, cap));
    }
    assert!(transport.last_request().is_none(), "nothing was sent");
    for (result, cap) in results {
        assert_eq!(result.unwrap_err(), ClientError::BodyOverCap { cap });
    }
}

#[tokio::test]
async fn test_raw_send_at_cap_reaches_transport() {
    let transport = fixed(service_key(), 200, json!({}));
    let client = client_with(signer(), Some(service_public()), transport.clone());
    let inbox = format!("/v1/{}/inbox", identity().id());
    let public = format!("/v1/{}/identity", identity().id());
    for (method, path, cap) in [
        ("POST", inbox.as_str(), 65_536),
        ("POST", "/v1/enroll", 256 << 10),
        ("GET", public.as_str(), 0),
    ] {
        let signed = raw_request(method, path, cap);
        let request = signed.request.clone();
        let response = client.send(signed).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{}");
        assert_eq!(transport.last_request(), Some(request));
    }
}

#[test]
fn test_response_malformed_time_preserves_binding_rejections() {
    let key = service_key();
    let request = Request {
        method: "POST".into(),
        origin: ORIGIN.into(),
        path_and_query: format!("/v1/{}/erase", identity().id()),
        headers: Vec::new(),
        body: b"{}".to_vec(),
        timeout: TimeoutClass::Bulk,
    };
    let sent = SentRequest::of(&request);
    let valid_head = SignedHead::sign(
        &key,
        &identity().public(),
        &ChainTip {
            generation: 1,
            seq: 0,
            chain_hash: [0; 32],
        },
    )
    .to_header();
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (read, status, code, head) in [
        (true, 200, None, None),
        (true, 200, None, Some(valid_head.as_str())),
        (true, 200, None, Some("not a head")),
        (false, 200, None, None),
        (false, 413, Some("too_large"), None),
        (false, 429, Some("rate_limited"), None),
        (false, 404, Some("not_found"), None),
        (false, 413, Some("too_large"), Some(valid_head.as_str())),
        (false, 413, Some("too_large"), Some("not a head")),
    ] {
        for time in [rfc3339(NOW), "not-a-time".into()] {
            let body = match code {
                Some(code) => json!({"code": code, "message": "m"})
                    .to_string()
                    .into_bytes(),
                None => b"{}".to_vec(),
            };
            let signature = sign_response(
                &key,
                &http::ResponseParts {
                    status,
                    request: sent.received(read),
                    server_time: &time,
                    head,
                    body: &body,
                },
            );
            let mut headers = vec![
                Header::new(header::SERVER_TIME, &time),
                Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
            ];
            if let Some(head) = head {
                headers.push(Header::new(header::HEAD, head));
            }
            let response = Response {
                status,
                headers,
                body,
            };
            let checked = check_response(&service_public(), &identity().public(), &sent, &response);
            let observed = match checked {
                Ok(_) => "accepted",
                Err(ClientError::BadServiceSignature { .. }) => "unauthenticated",
                Err(error @ ClientError::BodyUnread { .. }) => {
                    assert_eq!((error.code(), error.retry()), (None, None));
                    "unread"
                }
                Err(ClientError::InvalidResponse(_)) => "authenticated malformed",
                other => panic!("unexpected result: {other:?}"),
            };
            actual.push(observed);
            expected.push(
                if head == Some("not a head") || (!read && (status == 200 || head.is_some())) {
                    "unauthenticated"
                } else if !read {
                    "unread"
                } else if time == "not-a-time" {
                    "authenticated malformed"
                } else {
                    "accepted"
                },
            );
        }
    }
    assert_eq!(actual, expected, "all binding, head and time combinations");
}

fn unbound_signer(transport: Arc<MockTransport>, pin: Option<[u8; 32]>) -> SwitchClient {
    SwitchClient::new(
        ORIGIN,
        identity().public(),
        signer(),
        pin,
        transport,
        Arc::new(TestClock::new(NOW)),
    )
    .unwrap()
}

fn observation(created: Option<u64>) -> AccountObservationBody {
    AccountObservationBody {
        identity: identity().public(),
        origin: ORIGIN.into(),
        service_key: service_public(),
        store_id: [7; 16],
        association: if created.is_some() {
            pubky_switch_core::records::AccountAssociation::Account
        } else {
            pubky_switch_core::records::AccountAssociation::Absent
        },
        created,
        erased_at: None,
        observed_at: NOW,
        expires_at: NOW + 300_000,
    }
}

fn observation_reply(request: &Request, body: &AccountObservationBody) -> Response {
    let json: Value = serde_json::from_slice(&body.to_json().unwrap()).unwrap();
    respond(
        &service_key(),
        request,
        200,
        &serde_json::to_vec_pretty(&json).unwrap(),
    )
}

fn sign_current_headers(mut request: Request) -> SignedRequest {
    let headers = RequestHeaders {
        timestamp: request.header(header::TIMESTAMP).unwrap().into(),
        identity: request.header(header::IDENTITY).unwrap().into(),
        created: request.header(header::CREATED).map(str::to_owned),
        ..RequestHeaders::default()
    };
    let signature = http::sign_request(
        &identity(),
        &RequestTarget {
            method: &request.method,
            path_and_query: &request.path_and_query,
            body: &request.body,
            origin: &request.origin,
        },
        &headers,
    );
    request.headers.retain(|h| h.name != header::SIGNATURE);
    request
        .headers
        .push(Header::new(header::SIGNATURE, &b64(&signature)));
    SignedRequest { request }
}

#[test]
fn test_account_creation_is_fixed_for_signer_calls() {
    let transport = Arc::new(MockTransport::new());
    let client = unbound_signer(transport.clone(), Some(service_public()));
    let path = client.path("apps");
    assert!(matches!(
        client.sign_request("GET", &path, Vec::new(), None, TimeoutClass::Bulk),
        Err(ClientError::Usage(_))
    ));
    let client = client.with_account_created(17).unwrap();
    let signed = client
        .sign_request("GET", &path, Vec::new(), None, TimeoutClass::Bulk)
        .unwrap();
    assert_eq!(
        signed.request.header(header::CREATED),
        Some(rfc3339(17).as_str())
    );
    let headers = RequestHeaders {
        timestamp: signed.request.header(header::TIMESTAMP).unwrap().into(),
        identity: identity().id(),
        created: Some(rfc3339(17)),
        ..RequestHeaders::default()
    };
    let target = RequestTarget {
        method: "GET",
        path_and_query: &path,
        body: &[],
        origin: ORIGIN,
    };
    let signature =
        http::decode_signature(signed.request.header(header::SIGNATURE).unwrap()).unwrap();
    http::verify_request(&identity().public(), &target, &headers, &signature).unwrap();
    assert!(
        http::verify_request(
            &identity().public(),
            &target,
            &RequestHeaders {
                created: Some(rfc3339(18)),
                ..headers
            },
            &signature
        )
        .is_err()
    );
    assert!(matches!(
        client.with_account_created(17),
        Err(ClientError::Usage(_))
    ));
    assert!(matches!(
        unbound_signer(transport.clone(), None).with_account_created(MAX_TIME_MS + 1),
        Err(ClientError::Usage(_))
    ));
    assert!(matches!(
        client_with(app(), None, transport.clone()).with_account_created(17),
        Err(ClientError::Usage(_))
    ));
    assert!(transport.requests().is_empty());
}

#[tokio::test]
async fn test_raw_requests_keep_the_account_creation() {
    let transport = fixed(service_key(), 200, json!({}));
    let client = client_with(signer(), Some(service_public()), transport.clone());
    let original = client
        .sign_request(
            "GET",
            &client.path("apps"),
            Vec::new(),
            None,
            TimeoutClass::Bulk,
        )
        .unwrap()
        .request;
    for value in [
        None,
        Some(rfc3339(1)),
        Some(String::new()),
        Some("1970-01-01T00:00:00Z".into()),
    ] {
        let mut request = original.clone();
        request.headers.retain(|h| h.name != header::CREATED);
        if let Some(value) = value {
            request.headers.push(Header::new(header::CREATED, &value));
        }
        assert!(client.send(sign_current_headers(request)).await.is_err());
    }
    let mut duplicate = original.clone();
    duplicate
        .headers
        .push(Header::new(header::CREATED, &rfc3339(0)));
    assert!(client.send(sign_current_headers(duplicate)).await.is_err());
    let mut other_origin = original.clone();
    other_origin.origin = "https://other.example".into();
    assert!(
        client
            .send(sign_current_headers(other_origin))
            .await
            .is_err()
    );
    assert!(transport.requests().is_empty());
    client.send(sign_current_headers(original)).await.unwrap();
    assert_eq!(transport.requests().len(), 1);
}

#[tokio::test]
async fn test_account_discovery_preserves_authenticated_bytes() {
    let body = observation(Some(42));
    let expected = body.clone();
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        Ok(observation_reply(request, &body))
    }));
    for pin in [None, Some(service_public())] {
        let client = unbound_signer(transport.clone(), pin)
            .with_account_created(17)
            .unwrap();
        let found = client.observe_account().await.unwrap();
        let sent = transport.last_request().unwrap();
        let response = observation_reply(&sent, &expected);
        assert_eq!(found.body(), &expected);
        assert_eq!(found.carried().body, response.body);
        assert_eq!(
            found.carried().request_timestamp,
            sent.header(header::TIMESTAMP).unwrap()
        );
        assert_eq!(
            b64(&found.carried().request_signature),
            sent.header(header::SIGNATURE).unwrap()
        );
        assert_eq!(
            b64(&found.carried().sig),
            response.header(header::SERVICE_SIGNATURE).unwrap()
        );
        assert_eq!(
            found
                .carried()
                .verify(&identity().public(), ORIGIN)
                .unwrap(),
            found
        );
        assert_eq!(
            sent.path_and_query,
            format!("/v1/{}/account", identity().id())
        );
        assert!(sent.body.is_empty());
        for name in [
            header::CREATED,
            header::APP,
            header::CERT,
            header::TRANSFER,
            header::INVITE_CODE,
        ] {
            assert!(sent.header(name).is_none());
        }
        assert_eq!(client.pinned_key(), pin);
        assert_eq!(client.last_server_time(), None);
        assert_eq!(client.latest_server_time(), None);
        assert_eq!(client.latest_compared_time(), None);
        assert_eq!(
            client
                .sign_request(
                    "GET",
                    &client.path("apps"),
                    Vec::new(),
                    None,
                    TimeoutClass::Bulk
                )
                .unwrap()
                .request
                .header(header::CREATED),
            Some(rfc3339(17).as_str())
        );
    }
}

#[tokio::test]
async fn test_account_discovery_refuses_other_response_contexts() {
    for case in [
        "identity",
        "origin",
        "time",
        "status",
        "head",
        "pin",
        "signature",
    ] {
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            let mut body = observation(None);
            match case {
                "identity" => body.identity = IdentityKey::from_secret([9; 32]).public(),
                "origin" => body.origin = "https://other.example".into(),
                "time" => {
                    body.observed_at += 1;
                    body.expires_at += 1;
                }
                _ => {}
            }
            let bytes = body.to_json().unwrap();
            let mut response = if case == "head" {
                let head = SignedHead::sign(
                    &service_key(),
                    &identity().public(),
                    &ChainTip {
                        generation: 1,
                        seq: 1,
                        chain_hash: [3; 32],
                    },
                );
                respond_with_head(
                    &service_key(),
                    request,
                    200,
                    &bytes,
                    Some(&head.to_header()),
                )
            } else {
                respond(
                    &service_key(),
                    request,
                    if case == "status" { 201 } else { 200 },
                    &bytes,
                )
            };
            if case == "signature" {
                response
                    .headers
                    .retain(|h| h.name != header::SERVICE_SIGNATURE);
            }
            Ok(response)
        }));
        let pin = if case == "pin" {
            SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes()
        } else {
            service_public()
        };
        let client = unbound_signer(transport, Some(pin));
        assert!(client.observe_account().await.is_err(), "{case}");
        assert_eq!(client.pinned_key(), Some(pin));
        assert_eq!(client.last_server_time(), None);
    }
}

#[tokio::test]
async fn test_discovery_is_only_the_canonical_signer_read() {
    let transport = Arc::new(MockTransport::new());
    let client = client_with(app(), None, transport.clone());
    assert!(matches!(
        client.observe_account().await,
        Err(ClientError::Usage(_))
    ));
    let client = unbound_signer(transport.clone(), Some(service_public()));
    let path = client.path("account");
    for (method, path, body, invite) in [
        ("POST", path.clone(), Vec::new(), None),
        ("GET", format!("{path}?x=1"), Vec::new(), None),
        ("GET", path.clone(), Vec::new(), Some("invite")),
    ] {
        assert!(matches!(
            client.sign_request(method, &path, body, invite, TimeoutClass::Ordinary),
            Err(ClientError::Usage(_))
        ));
    }
    assert!(matches!(
        client.sign_request("GET", &path, vec![b'x'], None, TimeoutClass::Ordinary),
        Err(ClientError::BodyOverCap { cap: 0 })
    ));
    let signed = client
        .sign_request("GET", &path, Vec::new(), None, TimeoutClass::Ordinary)
        .unwrap();
    for name in [
        header::CREATED,
        header::APP,
        header::CERT,
        header::TRANSFER,
        header::INVITE_CODE,
    ] {
        let mut request = signed.request.clone();
        request.headers.push(Header::new(
            name,
            if name == header::CREATED {
                "1970-01-01T00:00:00.000Z"
            } else {
                "value"
            },
        ));
        assert!(
            client.send(SignedRequest { request }).await.is_err(),
            "{name}"
        );
    }
    assert!(transport.requests().is_empty());
}

#[tokio::test]
async fn test_account_discovery_timestamp_retry_keeps_original_authentication() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = calls.clone();
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            Ok(respond(&service_key(), request, 401, &serde_json::to_vec(&json!({ "code": "stale_timestamp", "message": "stale", "current": { "server_time": rfc3339(NOW + 600_000) } })).unwrap()))
        } else {
            Ok(observation_reply(request, &observation(None)))
        }
    }));
    let client = unbound_signer(transport.clone(), Some(service_public()));
    let found = client.observe_account().await.unwrap();
    let requests = transport.requests();
    assert_eq!(requests.len(), 2);
    assert_ne!(
        requests[0].header(header::TIMESTAMP),
        requests[1].header(header::TIMESTAMP)
    );
    assert_eq!(
        found.carried().request_timestamp,
        requests[1].header(header::TIMESTAMP).unwrap()
    );
    assert_eq!(
        found.carried().request_signature,
        http::decode_signature(requests[1].header(header::SIGNATURE).unwrap()).unwrap()
    );
    found
        .carried()
        .verify(&identity().public(), ORIGIN)
        .unwrap();
    assert_eq!(client.last_server_time(), None);
    assert_eq!(client.latest_compared_time(), None);
}

#[tokio::test]
async fn test_enrollment_timestamp_retry_keeps_the_signed_intent() {
    for kind in ["create", "existing", "takeover"] {
        let discovery = Arc::new(MockTransport::with_handler(move |request| {
            let mut body = observation((kind != "create").then_some(0));
            if kind == "takeover" {
                body.association = pubky_switch_core::records::AccountAssociation::Mark;
            }
            Ok(observation_reply(request, &body))
        }));
        let found = unbound_signer(discovery, Some(service_public()))
            .observe_account()
            .await
            .unwrap();
        let intent = match kind {
            "create" => EnrollmentIntent::Create {
                observation: found.carried().clone(),
            },
            "takeover" => EnrollmentIntent::Takeover {
                created: 0,
                observation: found.carried().clone(),
            },
            _ => EnrollmentIntent::Existing { created: 0 },
        };
        let mut body = enrollment([4; 16]).body().clone();
        body.intent = intent;
        let enrollment = Enrollment::sign(&identity(), body).unwrap();
        let created = if kind == "existing" { 0 } else { 42 };
        let answer =
            EnrollmentAnswer::new(&enrollment, service_public(), Limits::default(), created);
        let bytes = answer.to_json().unwrap();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Ok(respond(&service_key(), request, 401, &serde_json::to_vec(&json!({ "code": "stale_timestamp", "message": "stale", "current": { "server_time": rfc3339(NOW + 600_000) } })).unwrap()))
            } else {
                Ok(respond(&service_key(), request, 200, &bytes))
            }
        }));
        let client = unbound_signer(transport.clone(), Some(service_public()));
        assert_eq!(client.enroll(&enrollment).await.unwrap(), answer);
        let sent = transport.requests();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].body, sent[1].body);
        assert_ne!(
            sent[0].header(header::TIMESTAMP),
            sent[1].header(header::TIMESTAMP)
        );
        for request in &sent {
            assert_eq!(
                request.header(header::CREATED),
                (kind != "create").then(|| rfc3339(0)).as_deref()
            );
            let value: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(
                read::doc(&value["enrollment"]).unwrap(),
                *enrollment.signed()
            );
        }
        assert_eq!(client.last_server_time(), None);
        assert_eq!(client.latest_compared_time(), None);
    }
}

#[tokio::test]
async fn test_enrollment_and_erasure_require_the_original_creation() {
    let transport = fixed(service_key(), 200, json!({ "erased": true }));
    let client = client_with(signer(), Some(service_public()), transport.clone());
    let mut body = enrollment([4; 16]).body().clone();
    body.intent = EnrollmentIntent::Existing { created: 1 };
    let other = Enrollment::sign(&identity(), body).unwrap();
    assert!(matches!(
        client.enroll(&other).await,
        Err(ClientError::Usage(_))
    ));
    let body = serde_json::to_vec(&json!({ "enrollment": other.signed() })).unwrap();
    let raw = sign_raw_request(Request {
        method: "POST".into(),
        origin: ORIGIN.into(),
        path_and_query: "/v1/enroll".into(),
        headers: Vec::new(),
        body,
        timeout: TimeoutClass::Ordinary,
    });
    assert!(matches!(client.send(raw).await, Err(ClientError::Usage(_))));
    for created in [None, Some(1)] {
        assert!(matches!(
            client.erase(created, None).await,
            Err(ClientError::Usage(_))
        ));
    }
    assert!(transport.requests().is_empty());
    client.erase(Some(0), None).await.unwrap();
    let sent = transport.last_request().unwrap();
    assert_eq!(sent.header(header::CREATED), Some(rfc3339(0).as_str()));
    let value: Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(value["created"], rfc3339(0));
}

fn timed_response(
    request: &Request,
    status: u16,
    body: Value,
    head: Option<&str>,
    time: u64,
) -> Response {
    let body = serde_json::to_vec(&body).unwrap();
    let server_time = rfc3339(time);
    let sig = sign_response(
        &service_key(),
        &http::ResponseParts {
            status,
            request: SentRequest::of(request).received(true),
            server_time: &server_time,
            head,
            body: &body,
        },
    );
    let mut headers = vec![
        Header::new(header::SERVER_TIME, &server_time),
        Header::new(header::SERVICE_SIGNATURE, &b64(&sig)),
    ];
    if let Some(head) = head {
        headers.push(Header::new(header::HEAD, head));
    }
    Response {
        status,
        headers,
        body,
    }
}

#[tokio::test]
async fn test_creation_conflict_preserves_time_evidence() {
    for time in [NOW - 600_000, NOW + 600_000] {
        for (current, excluded) in [
            (json!({ "created": rfc3339(1) }), true),
            (json!({ "created": rfc3339(1), "other": true }), false),
            (json!({ "created": "1970-01-01T00:00:00Z" }), false),
            (json!({ "binding": "changed" }), false),
        ] {
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let transport = Arc::new(MockTransport::with_handler(move |request| {
                Ok(
                    match calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                        0 => timed_response(request, 200, json!({}), None, NOW),
                        1 => timed_response(
                            request,
                            409,
                            json!({ "code": "conflict", "message": "different account", "current": current }),
                            None,
                            time,
                        ),
                        _ => timed_response(request, 200, json!({}), None, NOW - 1),
                    },
                )
            }));
            let client = client_with(signer(), Some(service_public()), transport.clone());
            let request = || {
                client
                    .sign_request(
                        "GET",
                        &client.path("apps"),
                        Vec::new(),
                        None,
                        TimeoutClass::Bulk,
                    )
                    .unwrap()
            };
            client.send(request()).await.unwrap();
            let prior = client.latest_compared_time().unwrap();
            assert_eq!(prior, NOW);
            assert!(matches!(
                client.send(request()).await,
                Err(ClientError::Switch {
                    code: ErrorCode::Conflict,
                    ..
                })
            ));
            assert_eq!(client.latest_compared_time(), (!excluded).then_some(time));
            assert_eq!(
                client.compared_times().map(|t| t.highest),
                (!excluded).then_some(time)
            );
            assert_eq!(client.latest_server_time(), None);
            assert_eq!(client.last_server_time(), Some(prior));
            assert_eq!(client.pinned_key(), Some(service_public()));
            client.send(request()).await.unwrap();
            assert_eq!(client.latest_compared_time(), Some(prior - 1));
            assert_eq!(client.latest_server_time(), Some(prior - 1));
            assert!(
                transport
                    .requests()
                    .iter()
                    .all(|r| r.header(header::CREATED) == Some(rfc3339(0).as_str()))
            );
        }
    }
}

#[tokio::test]
async fn test_creation_conflict_requires_absent_raw_head() {
    let head = SignedHead::sign(
        &service_key(),
        &identity().public(),
        &ChainTip {
            generation: 1,
            seq: 1,
            chain_hash: [3; 32],
        },
    )
    .to_header();
    for (head, valid) in [
        (head, true),
        (String::new(), false),
        ("unparseable".into(), false),
    ] {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Ok(timed_response(request, 200, json!({}), None, NOW))
            } else {
                Ok(timed_response(
                    request,
                    409,
                    json!({ "code": "conflict", "message": "different account", "current": { "created": rfc3339(1) } }),
                    Some(&head),
                    NOW + 600_000,
                ))
            }
        }));
        let client = client_with(signer(), Some(service_public()), transport);
        let request = || {
            client
                .sign_request(
                    "GET",
                    &client.path("apps"),
                    Vec::new(),
                    None,
                    TimeoutClass::Bulk,
                )
                .unwrap()
        };
        client.send(request()).await.unwrap();
        let result = client.send(request()).await;
        if valid {
            assert!(matches!(
                result,
                Err(ClientError::Switch {
                    code: ErrorCode::Conflict,
                    ..
                })
            ));
            assert_eq!(client.latest_compared_time(), Some(NOW + 600_000));
            assert_eq!(client.latest_server_time(), Some(NOW + 600_000));
            assert_eq!(client.last_server_time(), Some(NOW + 600_000));
        } else {
            assert!(matches!(
                result,
                Err(ClientError::BadServiceSignature { status: 409 })
            ));
            assert_eq!(client.latest_compared_time(), None);
            assert!(client.compared_times().is_none());
            assert_eq!(client.latest_server_time(), None);
            assert_eq!(client.last_server_time(), Some(NOW));
        }
    }
}

#[tokio::test]
async fn test_raw_discovery_preserves_time_evidence() {
    for time in [NOW - 600_000, NOW + 600_000] {
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            if request.path_and_query.ends_with("/account") {
                let mut body = observation(Some(0));
                body.observed_at = time;
                body.expires_at = time + 300_000;
                Ok(timed_response(
                    request,
                    200,
                    serde_json::from_slice(&body.to_json().unwrap()).unwrap(),
                    None,
                    time,
                ))
            } else {
                Ok(timed_response(request, 200, json!({}), None, NOW))
            }
        }));
        let client = client_with(signer(), Some(service_public()), transport);
        let request = |rest, timeout| {
            client
                .sign_request("GET", &client.path(rest), Vec::new(), None, timeout)
                .unwrap()
        };
        client
            .send(request("apps", TimeoutClass::Bulk))
            .await
            .unwrap();
        client
            .send(request("account", TimeoutClass::Ordinary))
            .await
            .unwrap();
        assert_eq!(client.last_server_time(), Some(NOW));
        assert_eq!(client.latest_server_time(), None);
        assert_eq!(client.latest_compared_time(), None);
        assert!(client.compared_times().is_none());
        assert_eq!(client.pinned_key(), Some(service_public()));
    }
}
