//! `envelopes.json`: envelopes to one and three recipients in every bucket, with every input
//! and intermediate value, the bucket boundaries, envelopes to refuse, and the envelopes of
//! key bundles, the signer hand-over and the signer backup, with the parts and hand-overs to
//! refuse (Switch wire 3.5, 3.8, 3.12, 3.13, 4, 5.1).

use pubky_switch_core::enc::{app_id_decode, kid, zbase32_encode};
use pubky_switch_core::envelope::{self, Recipient};
use pubky_switch_core::keys::{AppKeys as SigningApp, IdentityKey, ReceiveKey};
use pubky_switch_core::labels;
use pubky_switch_core::message::{Message, MessagePlaintext, VerifiedSender, message_hash};
use pubky_switch_core::records::{
    self, AppCert, BundlePart, IdentityDoc, KeyBundle, KeyBundleContents, Limits, PartReader,
    RestoreStart, SignerBackup, SignerHandover, SignerRecords, SkipReason, StoredPart,
};
use pubky_switch_core::{Error, ident};
use serde_json::Value;

use crate::common::*;

/// The members this test covers.
const COVERED: [&str; 10] = [
    "description",
    "cases",
    "bucket_fit",
    "rejections",
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
            COVERED.contains(member),
            "a member this test doesn't know: {member}"
        );
    }

    for c in arr(&v, "cases") {
        check_case(&keys, c);
    }
    check_bucket_fit(&v);
    check_rejections(&keys, &v);
    let keyed = keyed_scopes();
    let has_keys = |scope: &str| keyed.contains(scope);
    check_key_bundle(&keys, &v["key_bundle"], &has_keys);
    check_key_bundle_rejections(&keys, &v, &has_keys);
    check_reduction_bundle(&keys, &v["reduction_key_bundle"], &has_keys);
    check_signer_handover(
        &keys,
        &v["signer_handover"],
        &v["signer_handover_rejections"],
    );
    check_signer_backup(&keys, &v["signer_backup"]);
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

fn identity_key(keys: &Keys, public: &[u8; 32]) -> IdentityKey {
    IdentityKey::from_secret(keys.identity_secrets[public])
}

fn cert_named(name: &str, identity: &[u8; 32]) -> AppCert {
    AppCert::verify(&document(name), identity).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn identity_named(name: &str, identity: &[u8; 32]) -> IdentityDoc {
    IdentityDoc::verify(&document(name), identity).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn bundle_of(value: &Value) -> KeyBundle {
    serde_json::from_value(value.clone()).unwrap()
}

/// A part with its range in the clear, as `key_bundle.put` names it.
fn part(bundle: &KeyBundle, first_epoch: u64, last_epoch: u64) -> BundlePart {
    BundlePart {
        bundle: bundle.clone(),
        first_epoch,
        last_epoch,
    }
}

/// The app's bundle key in the vector: its kid and secret are `keys.json`'s.
fn check_bundle_key(app: &AppKeys, kid_text: &str, secret_hex: &str) {
    assert_eq!(kid(&app.bundle_public), b64n::<8>(kid_text), "{}", app.name);
    assert_eq!(hx32(secret_hex), app.bundle_secret, "{}", app.name);
}

/// `key_bundle` (Switch wire 3.5): the executor's incremental part at data epoch 2, verified,
/// opened, read, and rebuilt byte for byte from the fixed keys and randomness.
fn check_key_bundle(keys: &Keys, kb: &Value, has_keys: &dyn Fn(&str) -> bool) {
    let app = keys.app(st(kb, "app"));
    let alice = app.identity;
    let app_id = app_id_decode(&app.app_id).unwrap();
    check_bundle_key(app, st(kb, "bundle_kid"), st(kb, "bundle_secret_hex"));
    let bundle = bundle_of(&kb["bundle"]);
    assert_eq!(bundle.envelope().len() as u64, int(kb, "envelope_len"));
    bundle.verify(&alice, &app_id).unwrap();
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::KEY_BUNDLE,
        &[&alice, &app_id, bundle.envelope()],
        &bundle.sig()
    ));
    let json = st(kb, "plaintext_json").as_bytes();
    assert_eq!(
        hex::encode(envelope::frame(json).unwrap()),
        st(kb, "framed_hex"),
        "framed plaintext"
    );
    assert_eq!(
        envelope::content_key_of(bundle.envelope(), &alice, &app.bundle_secret).unwrap(),
        hx32(st(kb, "cek_hex"))
    );
    let (sk_e, _) = envelope::ephemeral_key(&hx32(st(kb, "ikm_e_hex")));
    assert_eq!(hex::encode(sk_e), st(kb, "sk_e_hex"));

    // Opened, it is the plaintext; written again, the same bytes.
    let contents = bundle.open(&alice, &app_id, &app.bundle_secret).unwrap();
    assert!(
        *contents.to_json().unwrap() == *json,
        "the plaintext written again"
    );
    assert_eq!(contents.naming_key, keys.naming(&alice));
    // Made for the executor's certificate, whose keyed scopes it holds over epoch 2: derived
    // again from the identity key, the same plaintext.
    let cert = cert_named("executor certificate", &alice);
    assert_eq!(
        contents.cert,
        cert.hash(),
        "names the executor's certificate"
    );
    let key = identity_key(keys, &alice);
    let derived = KeyBundleContents::derive(&key, &cert, 2, 2, has_keys).unwrap();
    assert!(*derived.to_json().unwrap() == *json, "derived again");
    records::check_bundle_keys(&contents, &cert, has_keys).unwrap();
    let root = keys.root(&alice);
    for k in &contents.keys.keys {
        assert_eq!(k.key, ident::key_of_scope(&root, k.data_epoch, &k.scope));
    }
    // Sealed and signed again with the fixed randomness, byte for byte.
    let randomness = fixed(st(kb, "cek_hex"), st(kb, "nonce_hex"), st(kb, "ikm_e_hex"));
    let again =
        KeyBundle::seal_json_with(&key, &app_id, &app.bundle_public, json, &randomness).unwrap();
    assert!(again == bundle, "the key bundle rebuilt");

    // Read as the executor reads its parts, with alice's version 3 (data epoch 2).
    let newest = identity_named("alice identity.json", &alice);
    let certs = [&cert];
    let reader = PartReader {
        identity: alice,
        app_id,
        bundle_secret: &app.bundle_secret,
        newest_epoch: newest.data_epoch(),
        certs: &certs,
        has_keys,
    };
    let reading = reader.read(&[part(&bundle, 2, 2)], None).unwrap();
    assert_eq!(reading.taken, [(2, 2)]);
    assert!(reading.skipped.is_empty());
    // Relabelled in the clear, it is skipped.
    let relabelled = reader.read(&[part(&bundle, 1, 2)], None).unwrap();
    assert_eq!(relabelled.skipped[0].reason, SkipReason::Relabelled);
    // Not for another app, nor another bundle secret.
    let phone = keys.app("phone");
    let phone_id = app_id_decode(&phone.app_id).unwrap();
    assert!(bundle.open(&alice, &phone_id, &app.bundle_secret).is_err());
    assert!(bundle.open(&alice, &app_id, &phone.bundle_secret).is_err());
}

/// `key_bundle_rejections` (Switch wire 3.5 "Reading"): parts the executor skips although
/// each verifies and opens, each rebuilt byte for byte and refused for its rule.
fn check_key_bundle_rejections(keys: &Keys, v: &Value, has_keys: &dyn Fn(&str) -> bool) {
    let kb = &v["key_bundle"];
    let app = keys.app(st(kb, "app"));
    let alice = app.identity;
    let app_id = app_id_decode(&app.app_id).unwrap();
    let key = identity_key(keys, &alice);
    let cert = cert_named("executor certificate", &alice);
    let certs = [&cert];
    let reader = PartReader {
        identity: alice,
        app_id,
        bundle_secret: &app.bundle_secret,
        newest_epoch: identity_named("alice identity.json", &alice).data_epoch(),
        certs: &certs,
        has_keys,
    };
    let cases = arr(&v["key_bundle_rejections"], "cases");
    assert!(!cases.is_empty());
    for (index, case) in cases.iter().enumerate() {
        let name = st(case, "name");
        let bundle = bundle_of(&case["bundle"]);
        let json = st(case, "plaintext_json").as_bytes();
        // It verifies and opens to its plaintext.
        bundle.verify(&alice, &app_id).unwrap();
        let opened = envelope::open_framed(bundle.envelope(), &alice, &app.bundle_secret).unwrap();
        assert!(*opened == *json, "{name}: the plaintext");
        let randomness = fixed_from_seeds(&format!("key-bundle/reject/{index}"));
        let again = KeyBundle::seal_json_with(&key, &app_id, &app.bundle_public, json, &randomness)
            .unwrap();
        assert!(again == bundle, "{name}: rebuilt");
        // Skipped for its rule.
        let p = part(&bundle, int(case, "first_epoch"), int(case, "last_epoch"));
        let reason = reader.open_part(&p).unwrap_err();
        let rule = match name {
            "extra scope" => Some("doesn't hold"),
            "duplicate pair" => Some("two keys"),
            "missing pair" => Some("lacks"),
            "unknown certificate" => None,
            _ => panic!("a key bundle rejection this test doesn't know: {name}"),
        };
        match (rule, &reason) {
            (Some(rule), SkipReason::WrongKeys(why)) => {
                assert!(why.contains(rule), "{name}: {why}")
            }
            (None, SkipReason::UnknownCert) => {}
            _ => panic!("{name}: skipped for {reason:?}"),
        }
        let reading = reader.read(&[p], None).unwrap();
        assert!(
            reading.taken.is_empty() && reading.keys.keys.is_empty(),
            "{name}"
        );
    }
}

/// `reduction_key_bundle` (Switch wire 3.5, 3.8 "Reductions"): the wallet's full bundle made
/// for its renewed certificate, epochs 1 to 3, without the removed scope's keys.
fn check_reduction_bundle(keys: &Keys, r: &Value, has_keys: &dyn Fn(&str) -> bool) {
    let app = keys.app(st(r, "app"));
    let alice = app.identity;
    let app_id = app_id_decode(&app.app_id).unwrap();
    check_bundle_key(app, st(r, "bundle_kid"), st(r, "bundle_secret_hex"));
    let key = identity_key(keys, &alice);
    let original = cert_named("wallet certificate", &alice);
    let renewed = cert_named("wallet certificate, renewed", &alice);
    let removed = st(r, "removed_scope");
    assert!(records::is_reduction(&original, &renewed));
    assert!(records::reduction_rotates(&original, &renewed, has_keys));
    assert!(original.holds_scope(removed) && !renewed.holds_scope(removed));
    let renewing = identity_named("alice identity.json, wallet renewal in progress", &alice);
    let (last, data_epoch) = records::renewal_epochs(true, 2).unwrap();
    assert_eq!((last, data_epoch), (3, renewing.data_epoch()));
    let (first_epoch, last_epoch) = (int(r, "first_epoch"), int(r, "last_epoch"));
    assert_eq!((first_epoch, last_epoch), (1, last));

    let bundle = bundle_of(&r["bundle"]);
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::KEY_BUNDLE,
        &[&alice, &app_id, bundle.envelope()],
        &bundle.sig()
    ));
    let json = st(r, "plaintext_json").as_bytes();
    let contents = bundle.open(&alice, &app_id, &app.bundle_secret).unwrap();
    assert_eq!(
        contents.cert,
        renewed.hash(),
        "made for the renewed certificate"
    );
    assert!(contents.keys.keys.iter().all(|k| k.scope != removed));
    let derived =
        KeyBundleContents::derive(&key, &renewed, first_epoch, last_epoch, has_keys).unwrap();
    assert!(*derived.to_json().unwrap() == *json, "derived again");
    let randomness = fixed(st(r, "cek_hex"), st(r, "nonce_hex"), st(r, "ikm_e_hex"));
    let again =
        KeyBundle::seal_json_with(&key, &app_id, &app.bundle_public, json, &randomness).unwrap();
    assert!(again == bundle, "the reduction bundle rebuilt");
    // The signer's own split makes the same one part.
    let parts = records::seal_bundle_parts(&key, &renewed, 1, last, has_keys).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(
        parts[0]
            .bundle
            .open(&alice, &app_id, &app.bundle_secret)
            .unwrap(),
        contents
    );

    // The wallet takes it once its newest identity.json lists the renewal, which it holds.
    let held = [renewed.clone()];
    let p = part(&bundle, first_epoch, last_epoch);
    let read_with = |newest: &IdentityDoc| {
        let certs = records::reader_certs(&original, &held, newest);
        let reader = PartReader {
            identity: alice,
            app_id,
            bundle_secret: &app.bundle_secret,
            newest_epoch: newest.data_epoch(),
            certs: &certs,
            has_keys,
        };
        reader.read(std::slice::from_ref(&p), None).unwrap()
    };
    let reading = read_with(&renewing);
    assert_eq!(reading.taken, [(1, 3)]);
    assert!(
        records::missing_keys(&reading.keys, &renewed, has_keys, 3).is_empty(),
        "every key of the renewed certificate, epochs 1 to 3"
    );
    // Under version 3, which doesn't list the renewal, it is skipped like a stale part.
    let before = read_with(&identity_named("alice identity.json", &alice));
    assert_eq!(before.skipped[0].reason, SkipReason::UnknownCert);
}

/// The signer records of alice's version 3, as `documents.json` has them, with `prev`.
fn alice_records(keys: &Keys, plaintext: &Value, prev: Option<[u8; 32]>) -> SignerRecords {
    let alice = keys.identity("alice");
    let issued: Vec<AppCert> = [
        "wallet certificate",
        "phone certificate",
        "executor certificate",
    ]
    .iter()
    .map(|name| cert_named(name, &alice))
    .collect();
    let revoked: Vec<[u8; 16]> = arr(plaintext, "revoked_apps")
        .iter()
        .map(|id| app_id_decode(id.as_str().unwrap()).unwrap())
        .collect();
    let limits: Limits = serde_json::from_value(plaintext["limits"].clone()).unwrap();
    let parts: Vec<StoredPart> = serde_json::from_value(plaintext["bundle_parts"].clone()).unwrap();
    SignerRecords::new(
        identity_key(keys, &alice),
        identity_named("alice identity.json", &alice),
        &revoked,
        &issued,
        limits,
        &parts,
        prev,
    )
    .unwrap()
}

/// `signer_handover` and `signer_handover_rejections` (Switch wire 3.12): alice's hand-over
/// to her phone in two parts, opened, checked and rebuilt byte for byte; its take-over and
/// abort; and the hand-overs refused at check 1.
fn check_signer_handover(keys: &Keys, h: &Value, rejections: &Value) {
    let app = keys.app(st(h, "app"));
    let alice = app.identity;
    let app_id = app_id_decode(st(h, "app_id")).unwrap();
    assert_eq!(st(h, "app_id"), app.app_id);
    check_bundle_key(app, st(h, "bundle_kid"), st(h, "bundle_secret_hex"));
    let handover: SignerHandover = serde_json::from_value(h["handover"].clone()).unwrap();
    assert_eq!(serde_json::to_value(&handover).unwrap(), h["handover"]);
    let json = st(h, "plaintext_json").as_bytes();
    let plaintext: Value = serde_json::from_slice(json).unwrap();

    // Its two parts: the JSON split at its middle byte, each in a 4 KiB envelope.
    let parts = arr(h, "parts");
    assert_eq!(parts.len(), handover.envelopes().len());
    let joined: String = parts.iter().map(|p| st(p, "part")).collect();
    assert_eq!(joined.as_bytes(), json);
    let (first, second) = json.split_at(json.len() / 2);
    assert_eq!(st(&parts[0], "part").as_bytes(), first);
    assert_eq!(st(&parts[1], "part").as_bytes(), second);
    for (p, env) in parts.iter().zip(handover.envelopes()) {
        assert_eq!(env.len() as u64, int(p, "envelope_len"));
        let (sk_e, _) = envelope::ephemeral_key(&hx32(st(p, "ikm_e_hex")));
        assert_eq!(hex::encode(sk_e), st(p, "sk_e_hex"));
        assert_eq!(
            envelope::content_key_of(env, &alice, &app.bundle_secret).unwrap(),
            hx32(st(p, "cek_hex"))
        );
    }
    let count = 2u32.to_be_bytes();
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::SIGNER_HANDOVER,
        &[
            &alice,
            &app_id,
            &count,
            &handover.envelopes()[0],
            &handover.envelopes()[1]
        ],
        &handover.sig()
    ));

    // The phone opens it: checks 1 and 2.
    let records = handover.open(&alice, &app_id, &app.bundle_secret).unwrap();
    assert!(
        *records.to_json().unwrap() == *json,
        "the records written again"
    );
    assert_eq!(
        records.identity_doc().signed(),
        &document("alice identity.json")
    );
    assert_eq!(records.key().public(), alice);
    assert_eq!(
        records.revoked_apps(),
        [app_id_decode(st(&load("keys.json")["removed_app"], "app_id")).unwrap()]
    );
    let executor = keys.app("executor");
    let executor_cert = cert_named("executor certificate", &alice);
    assert_eq!(
        records.bundle_parts(),
        [StoredPart {
            app_id: app_id_decode(&executor.app_id).unwrap(),
            first_epoch: 2,
            last_epoch: 2,
            cert: executor_cert.hash(),
        }],
        "the executor's part of key_bundle"
    );
    assert!(records.prev().is_none());
    // The switch stores it for the phone, its envelopes for the phone's bundle key alone.
    let phone_cert = cert_named("phone certificate", &alice);
    handover
        .check_stored(&alice, &app_id, &phone_cert.bundle_key())
        .unwrap();
    let wallet_id = app_id_decode(&keys.app("wallet").app_id).unwrap();
    assert!(
        handover
            .open(&alice, &wallet_id, &keys.app("wallet").bundle_secret)
            .is_err()
    );

    // Rebuilt from the documents, byte for byte.
    let rebuilt = alice_records(keys, &plaintext, None);
    assert!(*rebuilt.to_json().unwrap() == *json, "the records rebuilt");
    let randomness: Vec<_> = parts
        .iter()
        .map(|p| fixed(st(p, "cek_hex"), st(p, "nonce_hex"), st(p, "ikm_e_hex")))
        .collect();
    let key = identity_key(keys, &alice);
    let again = SignerHandover::seal_parts_with(
        &key,
        &app_id,
        &phone_cert.bundle_key(),
        &[first, second],
        &randomness,
    )
    .unwrap();
    assert!(again == handover, "the hand-over rebuilt");
    // The signer's own split fits one envelope.
    let own = SignerHandover::seal(&key, &phone_cert, &rebuilt).unwrap();
    assert_eq!(own.envelopes().len(), 1);
    assert!(
        *own.open(&alice, &app_id, &app.bundle_secret)
            .unwrap()
            .to_json()
            .unwrap()
            == *json
    );

    // Check 3, the take-over and the abort (documents.json's version 5).
    let v3 = records.identity_doc().clone();
    records::check_handover_copies(&records, &[&v3]).unwrap();
    let (abort, prev) = records::abort_body(&v3).unwrap();
    assert_eq!(prev, v3.hash());
    let abort = IdentityDoc::sign(&key, abort).unwrap();
    assert_eq!(
        abort.signed(),
        &document("alice identity.json, hand-over abort (version 5)"),
        "the abort rebuilt"
    );
    assert!(
        records::check_handover_copies(&records, &[&abort]).is_err(),
        "an abort that won"
    );
    let (take_over, prev) = records::take_over_body(&records, [0x55; 16]).unwrap();
    assert_eq!(
        (take_over.version, take_over.signer, prev),
        (4, [0x55; 16], v3.hash())
    );
    assert!(!records::succeeded(
        &v3,
        &[abort.hash()],
        abort.version(),
        &abort.hash()
    ));
    let take_over = IdentityDoc::sign(&key, take_over).unwrap();
    assert!(records::succeeded(
        &v3,
        &[abort.hash()],
        4,
        &take_over.hash()
    ));

    // The rejections, each refused at check 1 by its signature.
    let cases = arr(rejections, "cases");
    assert!(!cases.is_empty());
    for case in cases {
        let name = st(case, "name");
        let bad: SignerHandover = serde_json::from_value(case["handover"].clone()).unwrap();
        let error = bad.open(&alice, &app_id, &app.bundle_secret).unwrap_err();
        assert!(matches!(error, Error::Signature(_)), "{name}: {error}");
        assert!(error.to_string().contains("check 1"), "{name}: {error}");
        if bad.sig() != handover.sig() {
            // A signature whose count isn't the parts': rebuilt from the identity key.
            let n = u32::try_from(bad.envelopes().len() + 1)
                .unwrap()
                .to_be_bytes();
            let mut fields: Vec<&[u8]> = vec![&alice, &app_id, &n];
            fields.extend(bad.envelopes().iter().map(Vec::as_slice));
            assert!(
                reproduce(
                    keys,
                    &alice,
                    labels::sig::SIGNER_HANDOVER,
                    &fields,
                    &bad.sig()
                ),
                "{name}"
            );
        }
    }
}

/// `signer_backup` (Switch wire 3.13): alice's backup in one part, opened with her key,
/// rebuilt byte for byte, and checked for a restore.
fn check_signer_backup(keys: &Keys, b: &Value) {
    let alice = keys.identity("alice");
    let key = identity_key(keys, &alice);
    assert_eq!(kid(&key.backup_public()), b64n::<8>(st(b, "backup_kid")));
    assert_eq!(key.backup_secret(), hx32(st(b, "backup_secret_hex")));
    assert_eq!(st(b, "path"), records::SIGNER_BACKUP_PATH);
    let backup: SignerBackup = serde_json::from_value(b["backup"].clone()).unwrap();
    assert_eq!(backup.envelopes().len(), 1);
    let env = &backup.envelopes()[0];
    assert_eq!(env.len() as u64, int(b, "envelope_len"));
    let (sk_e, _) = envelope::ephemeral_key(&hx32(st(b, "ikm_e_hex")));
    assert_eq!(hex::encode(sk_e), st(b, "sk_e_hex"));
    let count = 1u32.to_be_bytes();
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::SIGNER_BACKUP,
        &[&alice, &count, env],
        &backup.sig()
    ));

    let json = st(b, "plaintext_json").as_bytes();
    let records = backup.open(&key).unwrap();
    assert!(
        *records.to_json().unwrap() == *json,
        "the records written again"
    );
    let v1 = identity_named("alice identity.json, first delivery (version 1)", &alice);
    assert_eq!(records.prev(), Some(v1.hash()), "prev names version 1");
    let plaintext: Value = serde_json::from_slice(json).unwrap();
    let rebuilt = alice_records(keys, &plaintext, Some(v1.hash()));
    assert!(*rebuilt.to_json().unwrap() == *json, "the records rebuilt");
    let randomness = fixed(st(b, "cek_hex"), st(b, "nonce_hex"), st(b, "ikm_e_hex"));
    let again = SignerBackup::seal_parts_with(&key, &[json], &[randomness]).unwrap();
    assert!(again == backup, "the backup rebuilt");
    // Only the identity key opens it.
    assert!(backup.open(&IdentityKey::from_secret([7; 32])).is_err());
    let phone = keys.app("phone");
    assert!(envelope::open(env, &alice, &phone.bundle_secret).is_err());

    // The restore's check 3.
    let v3 = records.identity_doc().clone();
    assert_eq!(
        records::check_restore_copies(&records, Some(&v3), Some(&v3)).unwrap(),
        RestoreStart::AtBackup
    );
    assert_eq!(
        records::check_restore_copies(&records, Some(&v1), None).unwrap(),
        RestoreStart::DeliverBackupFirst
    );
    let abort = identity_named("alice identity.json, hand-over abort (version 5)", &alice);
    assert!(records::check_restore_copies(&records, Some(&abort), None).is_err());
    assert!(records::check_restore_copies(&records, Some(&v3), Some(&abort)).is_err());
    assert!(records::check_restore_copies(&records, None, None).is_err());
}
