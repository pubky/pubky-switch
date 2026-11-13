//! `http.json`: request and response signatures of every caller kind, and the push webhook
//! (Switch wire 7.1, 7.2, 8.2).

use pubky_switch_core::http::{self, RequestHeaders, RequestTarget, TransferHeaders};
use pubky_switch_core::records::{Enrollment, EnrollmentAnswer, IdentityDoc, SignerHandover};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::{labels, sig};
use serde_json::Value;

use crate::common::*;

fn header<'a>(v: &'a Value, name: &str) -> Option<&'a str> {
    v["headers"].get(name).and_then(Value::as_str)
}

fn handover_of(v: &Value) -> SignerHandover {
    let envelopes = arr(v, "envelopes")
        .iter()
        .map(|e| b64(e.as_str().unwrap()))
        .collect();
    SignerHandover::from_parts(envelopes, b64n::<64>(st(v, "sig")))
}

fn fields_of(v: &Value) -> Vec<Vec<u8>> {
    arr(v, "fields").iter().map(|f| hx(st(f, "hex"))).collect()
}

fn refs(fields: &[Vec<u8>]) -> Vec<&[u8]> {
    fields.iter().map(Vec::as_slice).collect()
}

/// The names of a request's signed fields and of a response's (Switch wire 7.1), as the
/// files write them.
const REQUEST_FIELDS: [&str; 9] = [
    "method",
    "path and query",
    "BLAKE3(body)",
    "Switch-Timestamp",
    "switch origin",
    "Switch-Identity",
    "Switch-App",
    "Switch-Cert",
    "Switch-Invite-Code",
];
const RESPONSE_FIELDS: [&str; 4] = [
    "u64(status)",
    "BLAKE3(request signature)",
    "server time",
    "BLAKE3(body)",
];

fn named_fields(names: &[&str], fields: &[Vec<u8>]) -> Value {
    assert_eq!(names.len(), fields.len());
    names
        .iter()
        .zip(fields)
        .map(|(name, field)| serde_json::json!({ "hex": hex::encode(field), "name": name }))
        .collect()
}

/// The erasures naming the `identity.json` they follow (Switch wire 7.4.16), which
/// `pubky-switch-core` generates (README "How the files were generated"): one naming the hash
/// of alice's version 3, the version her account holds, answered `{"erased":true}`, and one
/// naming her version 1, refused `409 conflict`. Each is signed with her identity key, and
/// each answer with her account's fixed service key, without a head.
fn conditional_erasures(keys: &Keys) {
    use pubky_switch_core::enc;
    let alice = keys.identity("alice");
    let alice_id = enc::pubky_id(&alice);
    let identity = ed25519_dalek::SigningKey::from_bytes(&keys.identity_secrets[&alice]);
    let service = keys.service_key(&alice_id);
    let service_key = ed25519_dalek::SigningKey::from_bytes(&keys.secret(&service).unwrap());
    let origin = "https://inbox.example";
    let timestamp = "2026-01-01T00:07:00Z";
    let server_time = "2026-01-01T00:07:00.030Z";
    let refused: &[u8] =
        br#"{"code":"conflict","message":"7.4.16: the account holds another identity.json"}"#;
    let cases = [
        (
            "signer: account erasure, naming the account's service key and the identity.json it follows",
            "alice identity.json",
            200,
            http::ERASED_BODY,
            "signer: account erasure answer to the request naming its identity.json, signed with the account's key, no head",
        ),
        (
            "signer: account erasure naming an identity.json the account doesn't hold",
            "alice identity.json, first delivery (version 1)",
            409,
            refused,
            "signer: account erasure refused, the account holds another identity.json, 409 conflict, no head",
        ),
    ];
    let mut generated_cases = Vec::new();
    for (name, document_name, status, answer, answer_name) in cases {
        let hash = document(document_name).doc_hash().unwrap();
        let body = http::erase_body(&service, Some(&hash));
        let path = format!("/v1/{alice_id}/erase");
        let target = RequestTarget {
            method: "POST",
            path_and_query: &path,
            body: &body,
            origin,
        };
        let headers = RequestHeaders {
            timestamp: timestamp.to_owned(),
            identity: alice_id.clone(),
            ..RequestHeaders::default()
        };
        let fields = http::request_fields(&target, &headers);
        let signature = sig::sign(&identity, labels::sig::HTTP, &refs(&fields));
        generated_cases.push((
            Place::Case("/requests"),
            serde_json::json!({
                "body_b64": enc::b64(&body),
                "fields": named_fields(&REQUEST_FIELDS, &fields),
                "headers": {
                    "switch-identity": alice_id,
                    "switch-signature": enc::b64(&signature),
                    "switch-timestamp": timestamp,
                },
                "label": labels::sig::HTTP,
                "method": "POST",
                "name": name,
                "origin": origin,
                "path": path,
                "public_key": enc::b64(&alice),
                "signature": enc::b64(&signature),
                "signed_bytes_hex": hex::encode(sig::signed_bytes(labels::sig::HTTP, &refs(&fields))),
                "signer": name,
            }),
        ));
        let fields = http::response_fields(status, Some(&signature), server_time, answer);
        let answer_signature = sig::sign(&service_key, labels::sig::HTTP_RESPONSE, &refs(&fields));
        generated_cases.push((
            Place::Case("/responses"),
            serde_json::json!({
                "body": std::str::from_utf8(answer).unwrap(),
                "fields": named_fields(&RESPONSE_FIELDS, &fields),
                "headers": {
                    "switch-server-time": server_time,
                    "switch-service-signature": enc::b64(&answer_signature),
                },
                "label": labels::sig::HTTP_RESPONSE,
                "name": answer_name,
                "public_key": enc::b64(&service),
                "request_signature": enc::b64(&signature),
                "signature": enc::b64(&answer_signature),
                "signed_bytes_hex": hex::encode(sig::signed_bytes(labels::sig::HTTP_RESPONSE, &refs(&fields))),
                "signer": "service key",
                "status": status,
            }),
        ));
    }
    generated("http.json", &generated_cases);
}

/// The page `body` with each record write that a later write of the same key in the page
/// supersedes shown as its stub (Switch wire 7.5, "Feed items and visibility"): the item
/// `{"type":"stub","seq":<seq>,"stub":<its stub>}`, the stub's bytes as the page held them.
fn superseded_as_stubs(body: &str) -> String {
    let page: Value = serde_json::from_str(body).unwrap();
    let writes: Vec<(u64, String)> = arr(&page, "items")
        .iter()
        .filter(|item| item["type"] == "chain" && item["item_type"] == "op")
        .filter_map(|item| {
            let op: Value = serde_json::from_slice(&b64(st(&item["item"], "body"))).unwrap();
            (op["op"] == "record.put")
                .then(|| (item["seq"].as_u64().unwrap(), st(&op, "key").to_owned()))
        })
        .collect();
    let mut out = body.to_owned();
    for (seq, key) in &writes {
        if !writes.iter().any(|(later, k)| later > seq && k == key) {
            continue;
        }
        let start = out
            .find(&format!("{{\"type\":\"chain\",\"seq\":{seq},"))
            .unwrap();
        let end = start
            + out[start..]
                .find(",{\"type\":")
                .or_else(|| out[start..].find("],\"next\""))
                .unwrap();
        let item = &out[start..end];
        let stub_at = item.find("\"stub\":").unwrap() + "\"stub\":".len();
        let stub_end = item.find(",\"item_type\":").unwrap();
        let stub_item = format!(
            "{{\"type\":\"stub\",\"seq\":{seq},\"stub\":{}}}",
            &item[stub_at..stub_end]
        );
        out.replace_range(start..end, &stub_item);
    }
    out
}

/// The `cursor` of the two feed pages (Switch wire 7.4.4), which `pubky-switch-core` added to
/// the prototype's pages (README "How the files were generated"): alice's wallet after `1:4`,
/// before its first cursor move, holds 0, and the long-poll's page at `1:41` an app whose
/// cursor is at the head. Each page holds the member before its `head`, and a record write
/// that a later write in the page supersedes shows as its stub ([`superseded_as_stubs`]).
/// Its answer is signed again with her account's fixed service key, at the page's own request
/// signature and server time.
fn feed_page_cursors(keys: &Keys) {
    use pubky_switch_core::enc;
    let alice_id = enc::pubky_id(&keys.identity("alice"));
    let service = keys.service_key(&alice_id);
    let service_key = ed25519_dalek::SigningKey::from_bytes(&keys.secret(&service).unwrap());
    let file = load("http.json");
    let mut generated_cases = Vec::new();
    let mut signature_case = None;
    for (name, cursor) in [
        ("own app: feed page with an entry and chain items", 0),
        ("own app: feed page, with the head header", 41),
    ] {
        let mut case = arr(&file, "responses")
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("{name}"))
            .clone();
        assert_eq!(st(&case, "public_key"), enc::b64(&service), "{name}");
        // The page as the prototype wrote it, then with the member before its `head`, the
        // last `"head":` of the body, since a page's items come before it.
        let held = st(&case, "body");
        let page = match held.find("\"cursor\":") {
            Some(start) => {
                let end = start + held[start..].find(',').unwrap() + 1;
                format!("{}{}", &held[..start], &held[end..])
            }
            None => held.to_owned(),
        };
        let page = superseded_as_stubs(&page);
        let at = page.rfind("\"head\":{").unwrap();
        let body = format!("{}\"cursor\":{cursor},{}", &page[..at], &page[at..]);
        let request_signature = b64n::<64>(st(&case, "request_signature"));
        let server_time = header(&case, http::header::SERVER_TIME).unwrap().to_owned();
        let fields =
            http::response_fields(200, Some(&request_signature), &server_time, body.as_bytes());
        let signature = sig::sign(&service_key, labels::sig::HTTP_RESPONSE, &refs(&fields));
        case["body"] = Value::String(body);
        case["fields"] = named_fields(&RESPONSE_FIELDS, &fields);
        case["headers"][http::header::SERVICE_SIGNATURE] = Value::String(enc::b64(&signature));
        case["signature"] = Value::String(enc::b64(&signature));
        case["signed_bytes_hex"] = Value::String(hex::encode(sig::signed_bytes(
            labels::sig::HTTP_RESPONSE,
            &refs(&fields),
        )));
        if cursor == 41 {
            signature_case = Some(serde_json::json!({
                "fields": named_fields(&RESPONSE_FIELDS, &fields),
                "label": labels::sig::HTTP_RESPONSE,
                "public_key": enc::b64(&service),
                "signature": enc::b64(&signature),
                "signed_bytes_hex": case["signed_bytes_hex"].clone(),
                "signer": "service key",
            }));
        }
        generated_cases.push((Place::Case("/responses"), case));
    }
    generated("http.json", &generated_cases);
    // `signatures.json`'s one response signature is the long-poll page's.
    let signatures = load("signatures.json");
    let index = arr(&signatures, "signatures")
        .iter()
        .position(|c| c["label"] == labels::sig::HTTP_RESPONSE)
        .unwrap();
    let pointer = format!("/signatures/{index}");
    generated(
        "signatures.json",
        &[(Place::Element(&pointer), signature_case.unwrap())],
    );
}

#[test]
fn test_vectors_http() {
    let keys = keys();
    conditional_erasures(&keys);
    feed_page_cursors(&keys);
    let v = load("http.json");
    let mut transfer_requests = 0;
    for r in arr(&v, "requests") {
        let name = st(r, "name");
        let body = b64(st(r, "body_b64"));
        let target = RequestTarget {
            method: st(r, "method"),
            path_and_query: st(r, "path"),
            body: &body,
            origin: st(r, "origin"),
        };
        let signature =
            http::decode_signature(header(r, http::header::SIGNATURE).unwrap()).unwrap();
        assert_eq!(b64n::<64>(st(r, "signature")), signature, "{name}");
        let public = b64n::<32>(st(r, "public_key"));
        let label = st(r, "label");
        let fields = if let Some(transfer) = header(r, http::header::TRANSFER) {
            transfer_requests += 1;
            assert_eq!(label, labels::sig::TRANSFER_REQUEST, "{name}");
            assert!(
                header(r, http::header::APP).is_none(),
                "{name}: no Switch-App"
            );
            let headers = TransferHeaders {
                timestamp: header(r, http::header::TIMESTAMP).unwrap().to_owned(),
                identity: header(r, http::header::IDENTITY).unwrap().to_owned(),
                transfer: transfer.to_owned(),
            };
            http::verify_transfer_request(&public, &target, &headers, &signature)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            // Under the label of an ordinary request it doesn't verify.
            let ordinary = RequestHeaders {
                timestamp: headers.timestamp.clone(),
                identity: headers.identity.clone(),
                ..RequestHeaders::default()
            };
            assert!(http::verify_request(&public, &target, &ordinary, &signature).is_err());
            http::transfer_request_fields(&target, &headers)
        } else {
            assert_eq!(label, labels::sig::HTTP, "{name}");
            let headers = RequestHeaders {
                timestamp: header(r, http::header::TIMESTAMP).unwrap().to_owned(),
                identity: header(r, http::header::IDENTITY).unwrap().to_owned(),
                app: header(r, http::header::APP).map(str::to_owned),
                cert: header(r, http::header::CERT).map(str::to_owned),
                invite_code: header(r, http::header::INVITE_CODE).map(str::to_owned),
            };
            http::verify_request(&public, &target, &headers, &signature)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            // Another body, path or origin breaks it.
            let other_body = RequestTarget {
                body: b"x",
                ..target
            };
            assert!(http::verify_request(&public, &other_body, &headers, &signature).is_err());
            let other_origin = RequestTarget {
                origin: "https://other.example",
                ..target
            };
            assert!(http::verify_request(&public, &other_origin, &headers, &signature).is_err());
            // A signer call carries no Switch-App; an app's does.
            assert_eq!(
                headers.app.is_some(),
                !name.starts_with("signer"),
                "{name}: Switch-App"
            );
            http::request_fields(&target, &headers)
        };
        assert_eq!(fields, fields_of(r), "{name}: fields");
        assert_eq!(
            hex::encode(sig::signed_bytes(label, &refs(&fields))),
            st(r, "signed_bytes_hex"),
            "{name}: signed bytes"
        );
        assert!(
            reproduce(&keys, &public, label, &refs(&fields), &signature),
            "{name}: no fixed key for the signer"
        );
        // The timestamp is written to the second (Switch wire 1.6).
        let timestamp = header(r, http::header::TIMESTAMP).unwrap();
        let ms = pubky_switch_core::time::parse_rfc3339(timestamp).unwrap();
        assert_eq!(
            pubky_switch_core::time::rfc3339_seconds(ms),
            timestamp,
            "{name}"
        );
        // Every body fits its call's cap.
        let cap = http::body_cap(target.method, target.path_and_query)
            .unwrap_or_else(|| panic!("{name}: a call of the cap table"));
        assert!(body.len() <= cap, "{name}: body over its cap");
    }
    assert_eq!(transfer_requests, 1);

    // What the bodies carry, read through the records' API.
    let alice = keys.identity("alice");
    let alice_id = pubky_switch_core::enc::pubky_id(&alice);
    let mut enrollment = None;
    for r in arr(&v, "requests") {
        let name = st(r, "name");
        let body = b64(st(r, "body_b64"));
        let path = st(r, "path");
        let call = path.split('?').next().unwrap();
        if call == "/v1/enroll" {
            let value: Value = serde_json::from_slice(&body).unwrap();
            let signed: SignedDoc = serde_json::from_value(value["enrollment"].clone()).unwrap();
            enrollment = Some(
                Enrollment::verify(&signed, &alice, st(r, "origin"))
                    .unwrap_or_else(|e| panic!("{name}: {e}")),
            );
        } else if call.ends_with("/identity") && st(r, "method") == "PUT" {
            let delivery = http::IdentityDelivery::parse(&body).unwrap();
            assert_eq!(delivery.to_json(), body, "{name}: the body as written");
            let doc = IdentityDoc::verify(&delivery.identity, &alice)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            // The account's first delivery builds on nothing.
            assert_eq!(delivery.prev.is_none(), doc.version() == 1, "{name}: prev");
        } else if call.ends_with("/peers") {
            // A peer copy is the signed document itself.
            let signed: SignedDoc = serde_json::from_slice(&body).unwrap();
            let doc =
                IdentityDoc::verify(&signed, &alice).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(doc.version(), 3, "{name}");
        } else if call.ends_with("/handover") && st(r, "method") == "PUT" {
            // The hand-over the signer stores for its target app (Switch wire 7.4.17).
            let value: Value = serde_json::from_slice(&body).unwrap();
            let target = keys.app_by_id(st(&value, "app_id"));
            let handover = handover_of(&value["handover"]);
            let target_id = pubky_switch_core::enc::app_id_decode(&target.app_id).unwrap();
            handover
                .check_stored(&alice, &target_id, &target.bundle_public)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            // Stored for another app, it fails.
            let other = keys.app("wallet");
            let other_id = pubky_switch_core::enc::app_id_decode(&other.app_id).unwrap();
            assert!(
                handover
                    .check_stored(&alice, &other_id, &other.bundle_public)
                    .is_err()
            );
        } else if call.ends_with("/erase") {
            let parsed = http::parse_erase_body(&body).unwrap();
            assert_eq!(parsed.service_key, keys.service_key(&alice_id), "{name}");
            // The body as written, the hash, when named, after the key.
            assert_eq!(
                http::erase_body(&parsed.service_key, parsed.identity_hash.as_ref()),
                body,
                "{name}"
            );
        }
    }
    let enrollment = enrollment.expect("an enrollment request");

    for r in arr(&v, "responses") {
        let name = st(r, "name");
        let status = u16::try_from(int(r, "status")).unwrap();
        let body = st(r, "body").as_bytes();
        let server_time = header(r, http::header::SERVER_TIME).unwrap();
        let request_signature = r["request_signature"].as_str().map(b64n::<64>);
        let signature =
            http::decode_signature(header(r, http::header::SERVICE_SIGNATURE).unwrap()).unwrap();
        assert_eq!(b64n::<64>(st(r, "signature")), signature, "{name}");
        let public = b64n::<32>(st(r, "public_key"));
        assert_eq!(st(r, "label"), labels::sig::HTTP_RESPONSE);
        let fields = http::response_fields(status, request_signature.as_ref(), server_time, body);
        assert_eq!(fields, fields_of(r), "{name}: fields");
        assert_eq!(
            hex::encode(sig::signed_bytes(
                labels::sig::HTTP_RESPONSE,
                &refs(&fields)
            )),
            st(r, "signed_bytes_hex")
        );
        http::verify_response(
            &public,
            status,
            request_signature.as_ref(),
            server_time,
            body,
            &signature,
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        // Another status, server time or request signature breaks it.
        assert!(
            http::verify_response(
                &public,
                status + 1,
                request_signature.as_ref(),
                server_time,
                body,
                &signature
            )
            .is_err()
        );
        assert!(
            http::verify_response(
                &public,
                status,
                Some(&[0; 64]),
                server_time,
                body,
                &signature
            )
            .is_err()
        );
        assert!(
            http::verify_response(
                &public,
                status,
                request_signature.as_ref(),
                "2000-01-01T00:00:00.000Z",
                body,
                &signature
            )
            .is_err()
        );
        // Signed by the account's service key, except the operator-signed answer to a
        // request the service can't tie to an account, whose key no client knows.
        let account_key =
            keys.service.values().any(|k| *k == public) || keys.secret(&public).is_some();
        if request_signature.is_none() && status == 404 {
            assert!(!account_key, "{name}: an operator key");
        } else {
            assert!(
                reproduce(
                    &keys,
                    &public,
                    labels::sig::HTTP_RESPONSE,
                    &refs(&fields),
                    &signature
                ),
                "{name}: no fixed key for the service"
            );
        }
        if name.starts_with("signer: enrollment answer") {
            let answer = EnrollmentAnswer::from_json(body).unwrap();
            answer
                .check(&enrollment)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                answer.to_json().unwrap(),
                body,
                "{name}: the answer as written"
            );
        }
        if name.starts_with("own app: the hand-over the switch stores") {
            // The fetch answers the stored body as it was put.
            let value: Value = serde_json::from_slice(body).unwrap();
            let target = keys.app_by_id(st(&value, "app_id"));
            let target_id = pubky_switch_core::enc::app_id_decode(&target.app_id).unwrap();
            handover_of(&value["handover"])
                .verify(&alice, &target_id)
                .unwrap();
        }
        if name.starts_with("signer: account erasure answer") {
            assert_eq!(body, http::ERASED_BODY);
        }
        // No answer to an enrollment or an erasure carries a head (Switch wire 7.1).
        if name.starts_with("signer: enrollment answer")
            || name.starts_with("signer: account erasure")
        {
            assert!(header(r, http::header::HEAD).is_none(), "{name}: no head");
        }
        // Errors name a code of the table with its status.
        if status >= 400 {
            let parsed: Value = serde_json::from_slice(body).unwrap();
            let code = http::ErrorCode::parse(st(&parsed, "code"))
                .unwrap_or_else(|| panic!("{name}: an unknown code"));
            assert_eq!(code.status(), status, "{name}");
            if code == http::ErrorCode::RateLimited {
                // The body repeats the wait that `Retry-After` carries (Switch wire 7.1).
                assert!(parsed["retry_after"].is_u64(), "{name}: retry_after");
            }
        }
    }

    let w = &v["webhook"];
    let relay_url = st(w, "relay_url");
    assert_eq!(
        http::relay_origin(relay_url).unwrap(),
        st(w, "relay_origin")
    );
    let body = st(w, "body").as_bytes();
    let signature = http::decode_signature(header(w, http::header::SIGNATURE).unwrap()).unwrap();
    let key = b64n::<32>(st(w, "service_key"));
    http::verify_webhook(&key, relay_url, body, &signature).unwrap();
    let origin = http::relay_origin(relay_url).unwrap();
    assert!(reproduce(
        &keys,
        &key,
        labels::sig::PUSH,
        &[origin.as_bytes(), body],
        &signature
    ));
    // The body as the switch writes it, from its handle, time and nonce.
    let parsed: Value = serde_json::from_slice(body).unwrap();
    let rebuilt = http::webhook_body(
        st(&parsed, "handle"),
        pubky_switch_core::time::parse_rfc3339(st(&parsed, "ts")).unwrap(),
        &b64n::<16>(st(&parsed, "nonce")),
    );
    assert_eq!(rebuilt, body);
    assert!(
        http::verify_webhook(&key, "https://elsewhere.example/v1/hook", body, &signature).is_err()
    );
}
