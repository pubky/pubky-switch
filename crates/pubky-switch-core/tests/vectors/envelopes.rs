//! `envelopes.json`: envelopes to one and three recipients in every bucket, with every input
//! and intermediate value, the bucket boundaries, and envelopes to refuse (Switch wire 4,
//! 5.1).
//!
//! The members built on key bundles, hand-overs and backups need the record types of Switch
//! wire 3 and are checked with them: see [`LEFT_FOR_RECORDS`].

use pubky_switch_core::enc::{app_id_decode, zbase32_encode};
use pubky_switch_core::envelope::{self, Recipient};
use pubky_switch_core::keys::{AppKeys as SigningApp, ReceiveKey};
use pubky_switch_core::message::{Message, MessagePlaintext, VerifiedSender, message_hash};
use serde_json::Value;

use crate::common::*;

/// The members this test covers.
const COVERED: [&str; 4] = ["description", "cases", "bucket_fit", "rejections"];

/// The members that need the records of Switch wire 3 (3.5, 3.12, 3.13).
const LEFT_FOR_RECORDS: [&str; 6] = [
    "key_bundle",
    "key_bundle_rejections",
    "reduction_key_bundle",
    "signer_handover",
    "signer_handover_rejections",
    "signer_backup",
];

/// A case's envelope, by name.
fn case<'a>(v: &'a Value, name: &str) -> &'a Value {
    arr(v, "cases")
        .iter()
        .find(|c| st(c, "name") == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

/// The step of Switch wire 4.3 an opening error names.
fn refusing_step(error: &pubky_switch_core::Error) -> u8 {
    let text = error.to_string();
    (1..=6)
        .find(|step| text.contains(&format!("Switch wire 4.3 step {step}:")))
        .unwrap_or_else(|| panic!("no step named in {text}"))
}

/// The app of `keys.json` whose App ID bytes these are.
fn app_of<'a>(keys: &'a Keys, app_id: &[u8; 16]) -> &'a AppKeys {
    keys.app_by_id(&zbase32_encode(app_id))
}

#[test]
fn test_vectors_envelopes() {
    let keys = keys();
    let v = load("envelopes.json");
    let members: Vec<&str> = v
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    for member in &members {
        assert!(
            COVERED.contains(member) || LEFT_FOR_RECORDS.contains(member),
            "a member this test doesn't know: {member}"
        );
    }

    for c in arr(&v, "cases") {
        check_case(&keys, c);
    }
    check_bucket_fit(&v);
    check_rejections(&keys, &v);
}

/// One case: every value rebuilt byte for byte, and the envelope opened by each recipient
/// to its message.
fn check_case(keys: &Keys, c: &Value) {
    let name = st(c, "name");
    let bytes = b64(st(c, "envelope"));
    assert_eq!(bytes.len() as u64, int(c, "envelope_len"), "{name}: length");
    let identity = hx32(st(c, "recipient_identity_hex"));
    let content_key = hx32(st(c, "cek_hex"));
    assert_eq!(
        hex::encode(envelope::key_commitment(&content_key)),
        st(c, "key_commitment_hex"),
        "{name}: key commitment"
    );
    let nonce: [u8; 24] = hx(st(c, "nonce_hex")).try_into().expect("24 bytes");
    let plaintext = hx(st(c, "plaintext_hex"));
    assert_eq!(plaintext.len() as u64, int(c, "plaintext_len"), "{name}");
    let notify = c["notify"].as_bool().expect("notify");
    let wraps = arr(c, "recipients");
    assert_eq!(
        envelope::bucket_for(wraps.len(), plaintext.len()),
        Some(bytes.len()),
        "{name}: the smallest bucket"
    );

    // Per recipient: its key, kid, HPKE info, ikmE, skE and enc.
    let mut recipients = Vec::new();
    let mut ikm_e = Vec::new();
    for r in wraps {
        let app = keys.app(st(r, "app"));
        assert_eq!(
            app.identity, identity,
            "{name}: an app of the recipient identity"
        );
        let public = b64n::<32>(st(r, "receive_public"));
        assert_eq!(public, app.receive_public, "{name}: receive key");
        assert_eq!(hx32(st(r, "receive_secret_hex")), app.receive_secret);
        assert_eq!(
            ReceiveKey::from_secret(0, app.receive_secret).public,
            public,
            "{name}: the receive secret's key"
        );
        let recipient = Recipient::new(public);
        assert_eq!(recipient.kid(), b64n::<8>(st(r, "kid")), "{name}: kid");
        assert_eq!(recipient.kid(), app.receive_kid, "{name}: kid");
        let info = envelope::hpke_info(&identity, &recipient.kid());
        assert_eq!(info.len(), 72);
        assert_eq!(hex::encode(&info), st(r, "hpke_info_hex"), "{name}: info");
        let ikm = hx32(st(r, "ikm_e_hex"));
        let (sk_e, enc) = envelope::ephemeral_key(&ikm);
        assert_eq!(hex::encode(sk_e), st(r, "sk_e_hex"), "{name}: skE");
        assert_eq!(hex::encode(enc), st(r, "enc_hex"), "{name}: enc");
        recipients.push(recipient);
        ikm_e.push(ikm);
    }

    // Sealed again with the fixed randomness, byte for byte.
    let sealed = envelope::seal_with(
        &identity,
        &recipients,
        &plaintext,
        notify,
        &content_key,
        &nonce,
        &ikm_e,
    )
    .unwrap();
    assert!(sealed == bytes, "{name}: the envelope isn't rebuilt");

    // The header as the inbox reads it.
    let header = envelope::check_at_inbox(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(hex::encode(&bytes[..header.len()]), st(c, "header_hex"));
    assert_eq!(hex::encode(&bytes[..40]), st(c, "hpke_aad_hex"));
    assert_eq!(header.notify, notify, "{name}: notify");
    assert_eq!(header.nonce, nonce, "{name}: nonce");
    assert_eq!(
        hex::encode(header.key_commitment),
        st(c, "key_commitment_hex")
    );
    assert_eq!(header.wraps.len(), wraps.len());
    for (wrap, r) in header.wraps.iter().zip(wraps) {
        assert_eq!(wrap.kid, b64n::<8>(st(r, "kid")));
        assert_eq!(hex::encode(wrap.enc), st(r, "enc_hex"), "{name}: enc");
        assert_eq!(
            hex::encode(wrap.wrapped_key),
            st(r, "wrapped_cek_hex"),
            "{name}: wrapped key"
        );
    }

    // Every recipient opens the same plaintext, padded with zeros.
    let padded_len = bytes.len() - header.len() - 24 - 16;
    for r in wraps {
        let app = keys.app(st(r, "app"));
        let secret = app.receive_secret;
        assert_eq!(
            envelope::content_key_of(&bytes, &identity, &secret).unwrap(),
            content_key,
            "{name}: content key"
        );
        let opened = envelope::open(&bytes, &identity, &secret)
            .unwrap_or_else(|e| panic!("{name}, {}: {e}", app.name));
        assert_eq!(opened.len(), padded_len, "{name}: padded length");
        assert_eq!(&opened[..plaintext.len()], plaintext.as_slice(), "{name}");
        assert!(opened[plaintext.len()..].iter().all(|b| *b == 0));
        check_message(keys, name, &bytes, &identity, &secret, &plaintext);
    }
}

/// The opened message passes the checks of Switch wire 5.1 that need no records, and is
/// rebuilt byte for byte: its JSON, its signature and its plaintext.
fn check_message(
    keys: &Keys,
    name: &str,
    bytes: &[u8],
    identity: &[u8; 32],
    secret: &[u8; 32],
    plaintext: &[u8],
) {
    let opened = MessagePlaintext::open(bytes, identity, secret).unwrap();
    assert_eq!(opened.encode(), plaintext, "{name}: plaintext");
    let sender = app_of(keys, &opened.sender_app_id());
    let verified = VerifiedSender {
        identity: sender.identity,
        app_id: app_id_decode(&sender.app_id).unwrap(),
        signing_key: sender.signing_public,
    };
    let message = opened
        .check(identity, &sender.identity, &verified, &[])
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(
        &message.to, identity,
        "{name}: to is the envelope's identity"
    );
    assert_eq!(message.from.identity, sender.identity);
    assert!(!message.is_from_own_app());
    assert_eq!(message_hash(opened.json()), opened.hash());
    // The parsed fields write the same bytes, and the sender's key signs them the same way.
    assert!(message.to_json().unwrap() == opened.json(), "{name}: JSON");
    let signer = SigningApp::from_secrets(sender.signing_secret, sender.bundle_secret);
    assert_eq!(message.sign(&signer).unwrap(), opened, "{name}: signature");
    assert_eq!(
        Message::parse(opened.json(), &[]).unwrap(),
        message,
        "{name}"
    );
    // Addressed to the identity it is sealed to, and no other.
    let bob = keys.identity("bob");
    assert!(
        opened
            .check(&bob, &sender.identity, &verified, &[])
            .is_err()
    );
}

/// `bucket_fit`: the smallest bucket for a plaintext length and a recipient count, or none;
/// each sealed with fresh randomness to that length, or refused.
fn check_bucket_fit(v: &Value) {
    let identity = [0x42; 32];
    for b in arr(v, "bucket_fit") {
        let count = int(b, "recipients") as usize;
        let len = int(b, "plaintext_len") as usize;
        let want = b["bucket"].as_u64().map(|x| x as usize);
        assert_eq!(envelope::bucket_for(count, len), want, "bucket fit {b}");
        let keys: Vec<ReceiveKey> = (0..count)
            .map(|i| ReceiveKey::from_secret(0, *blake3::hash(&i.to_be_bytes()).as_bytes()))
            .collect();
        let recipients: Vec<Recipient> = keys.iter().map(|k| Recipient::new(k.public)).collect();
        let plaintext = vec![0x5a; len];
        match want {
            Some(bucket) => {
                let sealed = envelope::seal(&identity, &recipients, &plaintext, false).unwrap();
                assert_eq!(sealed.len(), bucket, "bucket fit {b}");
                let last = keys.last().expect("a recipient");
                let opened = envelope::open(&sealed, &identity, &last.secret()).unwrap();
                assert_eq!(&opened[..len], plaintext.as_slice());
            }
            None => assert!(envelope::seal(&identity, &recipients, &plaintext, false).is_err()),
        }
    }
}

/// `rejections`: each envelope refused for its rule.
fn check_rejections(keys: &Keys, v: &Value) {
    let alice = keys.identity("alice");
    let bob = keys.identity("bob");
    for r in arr(v, "rejections") {
        let change = r.get("change").and_then(Value::as_str);
        let name = r.get("name").and_then(Value::as_str);
        match (change, name) {
            (Some(change), None) if change.contains("notify") => {
                // The notify bit flipped: the header still parses, and the HPKE AAD and the
                // body's AAD no longer match, so no recipient opens it.
                let base = case(v, st(r, "case"));
                let honest = b64(st(base, "envelope"));
                let flipped = b64(st(r, "envelope"));
                assert_eq!(flipped.len(), honest.len());
                for (index, (a, b)) in flipped.iter().zip(&honest).enumerate() {
                    assert_eq!(index == 6, a != b, "only the flags byte differs");
                }
                let header = envelope::check_at_inbox(&flipped).unwrap();
                assert_ne!(header.notify, base["notify"].as_bool().unwrap());
                for w in arr(base, "recipients") {
                    let secret = keys.app(st(w, "app")).receive_secret;
                    let error = envelope::open(&flipped, &alice, &secret).unwrap_err();
                    assert_eq!(refusing_step(&error), 3, "{change}: {error}");
                }
            }
            (Some(change), None) if change.contains("identity") => {
                // Opened with another identity in the HPKE info: the wrap doesn't open.
                let base = case(v, st(r, "case"));
                let honest = b64(st(base, "envelope"));
                for w in arr(base, "recipients") {
                    let secret = keys.app(st(w, "app")).receive_secret;
                    let error = envelope::open(&honest, &bob, &secret).unwrap_err();
                    assert_eq!(refusing_step(&error), 3, "{change}: {error}");
                    assert!(envelope::open(&honest, &alice, &secret).is_ok());
                }
            }
            (None, Some(name)) => {
                // A wrap carrying another content key under the honest header: its holder
                // refuses it at the key commitment, while the others open it.
                let forged = b64(st(r, "envelope"));
                let identity = hx32(st(r, "recipient_identity_hex"));
                envelope::check_at_inbox(&forged).unwrap();
                let opens: Vec<&str> = arr(r, "opens_for")
                    .iter()
                    .map(|a| a.as_str().expect("an app name"))
                    .collect();
                assert!(!opens.is_empty(), "{name}");
                for app in &opens {
                    let secret = keys.app(app).receive_secret;
                    envelope::open(&forged, &identity, &secret)
                        .unwrap_or_else(|e| panic!("{name}, {app}: {e}"));
                }
                let refused = arr(r, "rejected_by");
                assert!(!refused.is_empty(), "{name}");
                for rejecting in refused {
                    let app = keys.app(st(rejecting, "app"));
                    let secret = hx32(st(rejecting, "receive_secret_hex"));
                    assert_eq!(secret, app.receive_secret);
                    let error = envelope::open(&forged, &identity, &secret).unwrap_err();
                    assert_eq!(refusing_step(&error), 4, "{name}: {error}");
                    // The vector's reason is informative; it names the same rule.
                    assert!(st(rejecting, "reason").contains("key commitment"));
                }
            }
            _ => panic!("an envelope rejection this test doesn't know: {r}"),
        }
    }
}
