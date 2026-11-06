//! `signatures.json`: one signature per Switch label, and the signatures a verifier refuses
//! or must take (Switch wire 2.1, 2.3).

use pubky_switch_core::enc::split_lp;
use pubky_switch_core::{Error, labels, sig};
use serde_json::Value;

use crate::common::*;

/// Every signature label of Switch wire 2.3.
const LABELS: [&str; 23] = [
    labels::sig::APP_CERT,
    labels::sig::APP_RECORD,
    labels::sig::RECEIVE_KEY,
    labels::sig::IDENTITY,
    labels::sig::KEY_BUNDLE,
    labels::sig::FREEZE,
    labels::sig::UNFREEZE,
    labels::sig::DISCARDED,
    labels::sig::EXPORT_MANIFEST,
    labels::sig::ENROLL,
    labels::sig::MSG,
    labels::sig::HTTP,
    labels::sig::HTTP_RESPONSE,
    labels::sig::OP,
    labels::sig::SERVICE_OP,
    labels::sig::PROOF,
    labels::sig::HEAD,
    labels::sig::PUSH,
    labels::sig::APP_REQUEST,
    labels::sig::EXPORT_TRANSFER,
    labels::sig::TRANSFER_REQUEST,
    labels::sig::SIGNER_HANDOVER,
    labels::sig::SIGNER_BACKUP,
];

/// The step of Switch wire 2.1 an error of [`sig::verify`] names.
fn refusing_step(error: &Error) -> u8 {
    let Error::Signature(why) = error else {
        panic!("not a signature error: {error}");
    };
    if why.contains("S isn't below the group order") {
        1
    } else if why.contains("not canonical") || why.contains("is invalid") {
        2
    } else if why.contains("small order") {
        3
    } else if why.contains("the equation doesn't hold") {
        4
    } else {
        panic!("no step named in {why}")
    }
}

/// The step the vector's `reason` names, or for the first cases, which name none, the step
/// their construction targets.
fn expected_step(case: &Value) -> u8 {
    match (st(case, "name"), case.get("reason").and_then(Value::as_str)) {
        ("non-canonical S", None) => 1,
        ("small-order public key", None) => 3,
        ("another label", None) => 4,
        (_, Some("the equation doesn't hold")) => 4,
        (_, Some("small-order R" | "small-order public key")) => 3,
        (_, Some("non-canonical or invalid R" | "non-canonical or invalid public key")) => 2,
        (name, reason) => panic!("unknown rejection {name} ({reason:?})"),
    }
}

/// Split signed bytes `lp(label, fields...)` back into the label and the fields.
fn label_and_fields(signed: &[u8]) -> (String, Vec<Vec<u8>>) {
    let mut parts = split_lp(signed).expect("lp() bytes");
    let label = String::from_utf8(parts.remove(0)).expect("a UTF-8 label");
    (label, parts)
}

/// Whether ed25519-dalek's non-strict `verify` takes the signature.
fn lenient_accepts(public: &[u8; 32], signed: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::Verifier as _;
    ed25519_dalek::VerifyingKey::from_bytes(public).is_ok_and(|key| {
        key.verify(signed, &ed25519_dalek::Signature::from_bytes(signature))
            .is_ok()
    })
}

#[test]
fn test_vectors_signatures() {
    let keys = keys();
    let v = load("signatures.json");
    let mut seen = Vec::new();
    for c in arr(&v, "signatures") {
        let label = st(c, "label");
        seen.push(label.to_owned());
        let fields: Vec<Vec<u8>> = arr(c, "fields").iter().map(|f| hx(st(f, "hex"))).collect();
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        assert_eq!(
            hex::encode(sig::signed_bytes(label, &refs)),
            st(c, "signed_bytes_hex"),
            "{label}: signed bytes"
        );
        let public = b64n::<32>(st(c, "public_key"));
        let signature = b64n::<64>(st(c, "signature"));
        sig::verify(&public, label, &refs, &signature).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(
            reproduce(&keys, &public, label, &refs, &signature),
            "{label}: no fixed key for the signer"
        );
        // Another byte in a field, or another label, fails.
        let mut longer = fields.clone();
        longer[0].push(0);
        let longer: Vec<&[u8]> = longer.iter().map(Vec::as_slice).collect();
        assert!(sig::verify(&public, label, &longer, &signature).is_err());
        let other = if label == labels::sig::APP_CERT {
            labels::sig::APP_RECORD
        } else {
            labels::sig::APP_CERT
        };
        assert!(sig::verify(&public, other, &refs, &signature).is_err());
    }
    // One case per label, all of them the Switch's.
    assert_eq!(seen.len(), LABELS.len());
    for label in LABELS {
        assert!(seen.iter().any(|s| s == label), "no vector for {label}");
    }
    assert!(seen.iter().all(|s| s.starts_with("pubky-switch/v1/")));

    // Rejections: each refused at the step of Switch wire 2.1 it names.
    let wallet_cert = arr(&v, "signatures")
        .iter()
        .find(|c| st(c, "label") == labels::sig::APP_CERT)
        .expect("a certificate signature");
    let cert_signature = b64n::<64>(st(wallet_cert, "signature"));
    for r in arr(&v, "rejections") {
        let name = st(r, "name");
        let signed = hx(st(r, "signed_bytes_hex"));
        let public = b64n::<32>(st(r, "public_key"));
        let signature = b64n::<64>(st(r, "signature"));
        let (label, fields) = label_and_fields(&signed);
        assert_eq!(label, st(r, "label"));
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        let error = sig::verify(&public, &label, &refs, &signature)
            .expect_err(&format!("{name}: accepted"));
        assert_eq!(refusing_step(&error), expected_step(r), "{name}: {error}");
        assert_eq!(
            lenient_accepts(&public, &signed, &signature),
            r["lenient_accepts"].as_bool().unwrap(),
            "{name}: the non-strict verifier"
        );
        match name {
            // The certificate's signature with S + L, or checked under another label.
            "non-canonical S" => {
                assert_eq!(signature[..32], cert_signature[..32]);
                assert_ne!(signature[32..], cert_signature[32..]);
            }
            "another label" => assert_eq!(signature, cert_signature),
            _ => {}
        }
    }
    // `accepted`: the mixed-order key, which step 3 lets through.
    let [accepted] = &arr(&v, "accepted")[..] else {
        panic!("one accepted case");
    };
    let signed = hx(st(accepted, "signed_bytes_hex"));
    let (label, fields) = label_and_fields(&signed);
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    sig::verify(
        &b64n::<32>(st(accepted, "public_key")),
        &label,
        &refs,
        &b64n::<64>(st(accepted, "signature")),
    )
    .expect("the mixed-order key is taken");
}
