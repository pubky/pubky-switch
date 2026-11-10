//! Unit tests of the client against a scripted switch.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use pubky_switch_core::chain::{ChainTip, ItemType, ProofBody, ProofState, TransitionProof};
use pubky_switch_core::enc::{b64, pubky_id};
use pubky_switch_core::http::{self, ErrorCode, header, sign_response};
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::ops::{AllowKind, Condition, OpKind, OpsRequest, Position, SignedOp};
use pubky_switch_core::records::{
    AppCert, AppCertBody, DEFAULT_CERT_LIFETIME_MS, Enrollment, EnrollmentAnswer, EnrollmentBody,
    IdentityBody, IdentityDoc, IdentityPolicy, Inbox, Limits,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::rfc3339;
use serde_json::{Value, json};

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
    SwitchClient::new(
        ORIGIN,
        identity().public(),
        credentials,
        pinned,
        transport,
        Arc::new(TestClock::new(NOW)),
    )
    .unwrap()
}

/// A response to `request`, signed with `key` as the switch signs it (Switch wire 7.1).
fn respond(key: &SigningKey, request: &Request, status: u16, body: &[u8]) -> Response {
    let server_time = rfc3339(NOW);
    let request_signature = http::request_signature_of(request.header(header::SIGNATURE));
    let signature = sign_response(key, status, request_signature.as_ref(), &server_time, body);
    Response {
        status,
        headers: vec![
            Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
            Header::new(header::SERVER_TIME, &server_time),
            Header::new("content-type", "application/json"),
        ],
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
    let key = service_key();
    Arc::new(MockTransport::with_handler(move |request| {
        let (mut proofs, head) = proofs_for(&key, &request.body);
        edit(&mut proofs);
        let body = json!({ "proofs": proofs, "head": head.to_value() });
        Ok(respond(&key, request, 200, body.to_string().as_bytes()))
    }))
}

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
        .sign_request("GET", "/v1/x/feed", Vec::new(), None)
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
    let answer = EnrollmentAnswer::new(&enrollment, service_public(), Limits::default());
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

    // A client that holds a key keeps it: the answer may name a pending key.
    let pending = SigningKey::from_bytes(&[6; 32]);
    let answer = EnrollmentAnswer::new(
        &enrollment,
        pending.verifying_key().to_bytes(),
        Limits::default(),
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
    let answer = EnrollmentAnswer::new(&enrollment, service_public(), Limits::default());
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
    // An operator-signed error before the account exists is unauthenticated.
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
async fn test_enrollment_answer_for_another_enrollment_is_refused() {
    let sent = enrollment([4; 16]);
    let other = enrollment([5; 16]);
    let answer = EnrollmentAnswer::new(&other, service_public(), Limits::default());
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
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        let mut response = respond(&key, request, 200, br#"{"pending":true}"#);
        response
            .headers
            .push(Header::new(header::HEAD, &good.to_header()));
        Ok(response)
    }));
    let client = client_with(app(), Some(service_public()), transport);
    client.connect().await.unwrap();
    // The head is kept only when it verifies with the service key.
    let response = |head: &str| {
        let bytes = br#"{"pending":true}"#;
        let server_time = rfc3339(NOW);
        let signature = sign_response(&service_key(), 200, None, &server_time, bytes);
        Response {
            status: 200,
            headers: vec![
                Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
                Header::new(header::SERVER_TIME, &server_time),
                Header::new(header::HEAD, head),
            ],
            body: bytes.to_vec(),
        }
    };
    let checked = check_response(
        &service_public(),
        &account,
        None,
        &response(&good.to_header()),
    );
    assert_eq!(checked.unwrap().head, Some(good));
}

#[tokio::test]
async fn test_head_header_that_fails_is_ignored() {
    // The response signature doesn't cover `Switch-Head` (Switch wire 7.1): a proxy may add
    // or change one, so a head that doesn't verify or doesn't read is ignored, never an
    // error the app could take as evidence against the service.
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
            let mut response = respond(&key, request, 200, br#"{"pending":true}"#);
            response
                .headers
                .push(Header::new(header::HEAD, &header_value));
            Ok(response)
        }));
        let client = client_with(app(), Some(service_public()), transport);
        let result = client.connect().await;
        assert!(result.is_ok(), "{head}: {result:?}");
        let bytes = br#"{"pending":true}"#;
        let server_time = rfc3339(NOW);
        let signature = sign_response(&service_key(), 200, None, &server_time, bytes);
        let response = Response {
            status: 200,
            headers: vec![
                Header::new(header::SERVICE_SIGNATURE, &b64(&signature)),
                Header::new(header::SERVER_TIME, &server_time),
                Header::new(header::HEAD, &head),
            ],
            body: bytes.to_vec(),
        };
        let checked = check_response(&service_public(), &account, None, &response).unwrap();
        assert_eq!(checked.head, None);
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
        .sign_request("GET", "/v1/x/feed", Vec::new(), None)
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
        .sign_request("GET", "/v1/x/directory", Vec::new(), Some(code))
        .unwrap();
    let cert = request.request.header(header::CERT).unwrap();
    assert_eq!(cert, cert_of(&identity(), &app_keys()).signed().compact());
    assert_eq!(request.request.header(header::INVITE_CODE), Some(code));
    // An invite code that isn't a token isn't sent.
    assert!(matches!(
        foreign.sign_request("GET", "/v1/x/directory", Vec::new(), Some("a b")),
        Err(ClientError::Usage(_))
    ));
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
}

#[test]
fn test_credentials_debug_shows_no_key() {
    let text = format!("{:?} {:?}", signer(), app());
    assert!(text.contains(&pubky_id(&identity().public())), "{text}");
    for secret in [[1u8; 32], [2; 32], [3; 32]] {
        assert!(!text.contains(&b64(&secret)), "{text}");
        assert!(!text.contains(&format!("{secret:?}")), "{text}");
    }
}

/// A public-read answer holding the account's `identity.json`, naming `origin` and
/// `named` as its inbox, signed by `signing` as the switch signs it.
fn public_read_switch(origin: &str, named: [u8; 32], signing: SigningKey) -> Arc<MockTransport> {
    let body = IdentityBody::first(
        identity().public(),
        [0; 16],
        Inbox::new(origin, named),
        IdentityPolicy::default(),
    );
    let doc = IdentityDoc::sign(&identity(), body).unwrap();
    fixed(signing, 200, json!({ "identity": doc.signed() }))
}

#[tokio::test]
async fn test_public_read_unpinned_pins_the_named_key() {
    let transport = public_read_switch(ORIGIN, service_public(), service_key());
    let client = client_with(app(), None, Arc::clone(&transport));
    let public = client.public_identity().await.unwrap();
    assert_eq!(public.identity.inbox().service_key, service_public());
    assert_eq!(client.pinned_key(), Some(service_public()));
    let sent = transport.last_request().unwrap();
    assert!(sent.headers.iter().all(|h| !h.name.starts_with("switch-")));
}

#[tokio::test]
async fn test_public_read_unpinned_refuses_what_it_cant_check() {
    let other = SigningKey::from_bytes(&[6; 32]);
    let cases = [
        // Signed with another key than the document names.
        public_read_switch(ORIGIN, service_public(), other.clone()),
        // A document naming another origin.
        public_read_switch("https://other.example", service_public(), service_key()),
        // An error answer: nothing names a key.
        fixed(
            service_key(),
            404,
            json!({ "code": "not_found", "message": "m" }),
        ),
    ];
    for transport in cases {
        let client = client_with(app(), None, Arc::clone(&transport));
        let error = client.public_identity().await.unwrap_err();
        assert!(
            matches!(error, ClientError::BadServiceSignature { .. }),
            "{error:?}"
        );
        assert_eq!(client.pinned_key(), None);
        assert_eq!(client.last_server_time(), None);
    }
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
async fn test_operator_signed_404_reads_as_unauthenticated() {
    // A key no client knows signs answers for accounts the service doesn't host.
    let operator = SigningKey::from_bytes(&[42; 32]);
    let client = client_with(
        signer(),
        Some(service_public()),
        fixed(
            operator,
            404,
            json!({ "code": "not_found", "message": "no such account" }),
        ),
    );
    assert_eq!(
        client.erase().await.unwrap_err(),
        ClientError::BadServiceSignature { status: 404 }
    );
}

#[tokio::test]
async fn test_signer_and_app_calls_refuse_the_other_caller() {
    let transport = fixed(service_key(), 200, json!({}));
    let client = client_with(app(), Some(service_public()), Arc::clone(&transport));
    assert!(matches!(client.apps().await, Err(ClientError::Usage(_))));
    assert!(matches!(client.erase().await, Err(ClientError::Usage(_))));
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
        let body = json!({
            "proofs": [proof.signed()],
            "head": SignedHead::sign(&key, &account, &tip).to_value(),
        });
        Ok(respond(&key, request, 200, body.to_string().as_bytes()))
    }))
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
async fn test_last_server_time_follows_checked_answers_only() {
    let transport = fixed(
        service_key(),
        200,
        json!({ "contacts": [], "conversations": [], "deny": [] }),
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
