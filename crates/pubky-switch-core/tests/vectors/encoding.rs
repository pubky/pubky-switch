//! `encoding.json`: `lp()`, `u64`, `derive()`, base64url, z-base-32, strict JSON and RFC 3339
//! times (Switch wire 1).

use pubky_switch_core::enc::{self, b64, lp, unb64, zbase32_decode, zbase32_encode};
use pubky_switch_core::json::{self, Doc, OpaqueMember};
use pubky_switch_core::time;
use serde_json::Value;

use crate::common::*;

/// The opaque members of the sample protocol's message bodies that the `read_as: message`
/// cases rely on: `metadata` in every body, and `proof` in the body of the kind whose case
/// holds a non-integer there. The kind is read from the vectors, not named here.
fn sample_message_rules(cases: &[Value]) -> (String, String) {
    let messages: Vec<Value> = cases
        .iter()
        .filter(|c| c.get("read_as").and_then(Value::as_str) == Some("message"))
        .map(|c| serde_json::from_str(st(c, "json")).expect("a JSON case"))
        .collect();
    let proof_kind = messages
        .iter()
        .find(|m| m["body"].get("proof").is_some() && m["body"].get("metadata").is_none())
        .map(|m| st(m, "kind").to_owned())
        .expect("a case with a proof");
    let other_kind = messages
        .iter()
        .map(|m| st(m, "kind").to_owned())
        .find(|k| *k != proof_kind)
        .expect("a case of another kind");
    (proof_kind, other_kind)
}

#[test]
fn test_vectors_encoding() {
    let e = load("encoding.json");
    for c in arr(&e, "lp") {
        let parts: Vec<Vec<u8>> = arr(c, "parts_hex")
            .iter()
            .map(|p| hx(p.as_str().unwrap()))
            .collect();
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let bytes = lp(&refs);
        assert_eq!(hex::encode(&bytes), st(c, "output_hex"));
        assert_eq!(enc::split_lp(&bytes), Some(parts));
    }
    for c in arr(&e, "u64_be") {
        let value = match &c["value"] {
            Value::String(s) => s.parse::<u64>().unwrap(),
            n => n.as_u64().unwrap(),
        };
        assert_eq!(hex::encode(enc::u64be(value)), st(c, "hex"));
        // Values beyond the JSON integers are written as strings.
        assert_eq!(c["value"].is_number(), value <= json::MAX_INT, "{c}");
    }
    for c in arr(&e, "derive") {
        let parts: Vec<Vec<u8>> = arr(c, "parts_hex")
            .iter()
            .map(|p| hx(p.as_str().unwrap()))
            .collect();
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        assert_eq!(hex::encode(lp(&refs)), st(c, "key_material_hex"));
        assert_eq!(
            hex::encode(enc::derive(st(c, "label"), &refs)),
            st(c, "output_hex")
        );
    }
    for c in arr(&e["base64url"], "valid") {
        assert_eq!(
            hex::encode(unb64(st(c, "base64url")).unwrap()),
            st(c, "hex")
        );
        assert_eq!(b64(&hx(st(c, "hex"))), st(c, "base64url"));
    }
    for c in arr(&e["base64url"], "invalid") {
        assert!(unb64(st(c, "base64url")).is_err(), "accepted {c}");
    }
    for c in arr(&e["zbase32"], "valid") {
        let bytes = hx(st(c, "hex"));
        assert_eq!(zbase32_encode(&bytes), st(c, "zbase32"));
        let decoded = match bytes.len() {
            16 => zbase32_decode::<16>(st(c, "zbase32")).unwrap().to_vec(),
            32 => zbase32_decode::<32>(st(c, "zbase32")).unwrap().to_vec(),
            n => panic!("no z-base-32 case of {n} bytes expected"),
        };
        assert_eq!(decoded, bytes);
    }
    for c in arr(&e["zbase32"], "invalid") {
        assert!(
            zbase32_decode::<32>(st(c, "zbase32")).is_err(),
            "accepted {c}"
        );
    }

    // Strict JSON. A case with `read_as` is read as that document, whose opaque members
    // are named by path; the others have none.
    let cases = arr(&e, "json");
    let (proof_kind, _) = sample_message_rules(cases);
    let rules = [
        OpaqueMember {
            kind: None,
            member: "metadata",
        },
        OpaqueMember {
            kind: Some(&proof_kind),
            member: "proof",
        },
    ];
    let all_docs = [
        Doc::Plain,
        Doc::Message(&rules),
        Doc::Op,
        Doc::ServiceOp,
        Doc::SignedBody,
        Doc::FeedPage,
        Doc::AllowList,
        Doc::ExportChunk,
    ];
    let mut read_as = 0;
    for c in cases {
        let bytes = match c.get("json_hex") {
            Some(h) => hx(h.as_str().unwrap()),
            None => st(c, "json").as_bytes().to_vec(),
        };
        let valid = c["valid"].as_bool().unwrap();
        let doc = match c.get("read_as").and_then(Value::as_str) {
            None => Doc::Plain,
            Some("message") => Doc::Message(&rules),
            Some("operation") => Doc::Op,
            Some(other) => panic!("read_as {other:?}"),
        };
        assert_eq!(
            json::check_json_as(&bytes, doc).is_ok(),
            valid,
            "JSON case {c}"
        );
        if doc == Doc::Plain {
            // No opaque members, whichever document it is read as.
            for d in all_docs {
                assert_eq!(
                    json::check_json_as(&bytes, d).is_ok(),
                    valid,
                    "{c} as {d:?}"
                );
            }
            continue;
        }
        read_as += 1;
        // The path decides: read as another document, the opaque numbers are refused.
        for d in all_docs.iter().filter(|d| **d != doc) {
            if *d == Doc::SignedBody && doc == Doc::Op {
                continue; // A signed body has an operation's opaque members.
            }
            assert!(json::check_json_as(&bytes, *d).is_err(), "{c} as {d:?}");
        }
    }
    assert_eq!(read_as, 4);

    // The integer rule at every depth outside the opaque members.
    for (number, ok) in [
        ("0", true),
        ("9007199254740991", true),
        ("9007199254740992", false),
        ("18446744073709551616", false),
        ("1.0", false),
        ("1e2", false),
        ("1E2", false),
        ("-1", false),
        ("-0", false),
    ] {
        let flat = format!("{{\"v\":{number}}}");
        assert_eq!(json::check_json(flat.as_bytes()).is_ok(), ok, "{flat}");
        let nested = format!("{{\"a\":[{{\"b\":{{\"c\":{number}}}}}]}}");
        assert_eq!(json::check_json(nested.as_bytes()).is_ok(), ok, "{nested}");
        for (doc, opaque) in [
            (
                Doc::Op,
                format!("{{\"op\":\"invite_code.put\",\"context\":{number}}}"),
            ),
            (
                Doc::ServiceOp,
                format!("{{\"type\":\"conversation.add\",\"context\":{{\"k\":{number}}}}}"),
            ),
            (
                Doc::AllowList,
                format!("{{\"conversations\":[{{\"pubky\":\"x\",\"context\":{number}}}]}}"),
            ),
            (
                Doc::FeedPage,
                format!(
                    "{{\"items\":[{{\"type\":\"entry\",\"context\":{number}}},{{\"type\":\"chain\",\"context\":[{number}]}}]}}"
                ),
            ),
            (
                Doc::ExportChunk,
                format!(
                    "{{\"parts\":[{{\"part\":\"chain\",\"context\":{number}}},{{\"part\":\"invite_code\",\"context\":{{\"a\":{number}}}}}]}}"
                ),
            ),
        ] {
            json::check_json_as(opaque.as_bytes(), doc).unwrap_or_else(|e| panic!("{opaque}: {e}"));
            assert_eq!(
                json::check_json(opaque.as_bytes()).is_ok(),
                ok,
                "{opaque} as Plain"
            );
        }
        for (doc, checked) in [
            (
                Doc::Op,
                format!("{{\"op\":\"allow.put\",\"context\":{number}}}"),
            ),
            (
                Doc::Op,
                format!("{{\"op\":\"invite_code.put\",\"x\":{{\"context\":{number}}}}}"),
            ),
            (
                Doc::ServiceOp,
                format!("{{\"type\":\"revoke\",\"context\":{number}}}"),
            ),
            (Doc::AllowList, format!("{{\"context\":{number}}}")),
            (
                Doc::FeedPage,
                format!("{{\"items\":[{{\"type\":\"stub\",\"context\":{number}}}]}}"),
            ),
            (
                Doc::ExportChunk,
                format!("{{\"parts\":[{{\"part\":\"app\",\"context\":{number}}}]}}"),
            ),
            (
                Doc::ExportChunk,
                format!("{{\"parts\":[{{\"part\":\"chain\",\"doc\":{{\"context\":{number}}}}}]}}"),
            ),
            (
                Doc::Message(&rules),
                format!("{{\"metadata\":{{\"rate\":{number}}}}}"),
            ),
            (
                Doc::Message(&rules),
                format!("{{\"kind\":\"x.y\",\"body\":{{\"proof\":{{\"n\":{number}}}}}}}"),
            ),
            (
                Doc::Message(&rules),
                format!("{{\"body\":{{\"x\":[{{\"metadata\":{number}}}]}}}}"),
            ),
        ] {
            assert_eq!(
                json::check_json_as(checked.as_bytes(), doc).is_ok(),
                ok,
                "{checked} as {doc:?}"
            );
        }
    }

    // Times.
    let r = &e["rfc3339"];
    for c in arr(r, "parse") {
        assert_eq!(
            time::parse_rfc3339(st(c, "text")).unwrap(),
            int(c, "unix_ms"),
            "{c}"
        );
    }
    for c in arr(r, "format") {
        let ms = int(c, "unix_ms");
        assert_eq!(time::rfc3339(ms), st(c, "text"));
        assert_eq!(time::parse_rfc3339(st(c, "text")).unwrap(), ms);
    }
    for c in arr(r, "invalid") {
        assert!(time::parse_rfc3339(st(c, "text")).is_err(), "accepted {c}");
    }
    // Forms outside the grammar that some readers allow; this reader refuses them, which
    // Switch wire 1.6 leaves to each reader.
    for c in arr(r, "lenient_reader_only") {
        assert!(time::parse_rfc3339(st(c, "text")).is_err(), "accepted {c}");
    }
}
