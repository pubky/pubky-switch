//! `documents.json`: every signed document of Switch wire 3 but the key bundle, the signer
//! hand-over and the signer backup, with the permission and scope rules, the conflict of two
//! app records, the unfreeze and the discard answer, the auth request an app request binds,
//! and the approval with its companion claim (Switch wire 2.2, 3).
//!
//! Every document is checked in its carrying and compact forms, its document bytes and hash,
//! verified, signed again from the fixed keys, read through the records API, and written
//! again from what was read, byte for byte.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use pubky_switch_core::enc::{app_id_decode, b64 as b64e, x25519_low_order};
use pubky_switch_core::keys::{AppKeys as SwitchAppKeys, IdentityKey};
use pubky_switch_core::records::{
    self, AccountView, AppCert, AppRecord, AppRequest, AuthRequest, CLOCK_TOLERANCE_MS, DAY_MS,
    Delivery, DiscardAnswer, Enrollment, ExportTransfer, Freeze, IdentityBody, IdentityDoc,
    ListedApp, ReceiveKeyRecord, RecordOrder, RecordView, RenewedCert, ServiceKeyEntry, SignerView,
    Standing, Unfreeze, UnfreezeAt, VersionOrder,
};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::parse_rfc3339;
use pubky_switch_core::{Error, labels};
use serde_json::{Value, json};

use crate::common::*;

/// The static vectors' start time (README "Times").
const START: &str = "2026-01-01T00:00:00.000Z";

/// One document of `documents`: its entry and its carrying form.
struct Doc {
    entry: Value,
    signed: SignedDoc,
}

fn signed_of(value: &Value) -> SignedDoc {
    serde_json::from_value(value.clone()).unwrap()
}

fn identity_key(keys: &Keys, public: &[u8; 32]) -> IdentityKey {
    IdentityKey::from_secret(keys.identity_secrets[public])
}

fn app_keys(app: &AppKeys) -> SwitchAppKeys {
    let keys = SwitchAppKeys::from_secrets(app.signing_secret, app.bundle_secret);
    assert_eq!(keys.signing_public(), app.signing_public, "{}", app.name);
    assert_eq!(keys.bundle_public(), app.bundle_public, "{}", app.name);
    keys
}

/// The app a document of `documents` is about, by the first word of its name.
fn app_of<'a>(keys: &'a Keys, name: &str) -> &'a AppKeys {
    keys.app(name.split(' ').next().unwrap())
}

/// Sign `value`'s JSON again under `label` with `secret`, for refusals built from a vector.
fn resign(secret: &[u8; 32], label: &str, value: &Value) -> SignedDoc {
    SignedDoc::sign_bytes(
        &SigningKey::from_bytes(secret),
        label,
        &[],
        serde_json::to_vec(value).unwrap(),
    )
}

fn body_value(signed: &SignedDoc) -> Value {
    serde_json::from_slice(&signed.body_bytes().unwrap()).unwrap()
}

#[test]
fn test_vectors_documents() {
    let keys = keys();
    let v = load("documents.json");
    let docs: HashMap<String, Doc> = arr(&v, "documents")
        .iter()
        .map(|entry| {
            let signed = signed_of(&entry["signed"]);
            (
                st(entry, "name").to_owned(),
                Doc {
                    entry: entry.clone(),
                    signed,
                },
            )
        })
        .collect();
    assert_eq!(docs.len(), arr(&v, "documents").len(), "names are unique");
    let doc = |name: &str| -> &SignedDoc {
        &docs
            .get(name)
            .unwrap_or_else(|| panic!("no document {name}"))
            .signed
    };
    let alice = keys.identity("alice");
    let bob = keys.identity("bob");

    // Every document: its forms, bytes and hash, its signature from the fixed keys, and a
    // tampered body refused.
    for entry in arr(&v, "documents") {
        let name = st(entry, "name");
        let label = st(entry, "label");
        let signed = doc(name);
        let body = signed.body_bytes().unwrap();
        assert_eq!(body, st(entry, "body").as_bytes(), "{name}: body");
        assert_eq!(signed.compact(), st(entry, "compact"), "{name}: compact");
        assert_eq!(
            &SignedDoc::from_compact(st(entry, "compact")).unwrap(),
            signed
        );
        assert_eq!(
            serde_json::to_value(signed).unwrap(),
            entry["signed"],
            "{name}"
        );
        assert_eq!(
            hex::encode(signed.doc_bytes().unwrap()),
            st(entry, "doc_bytes_hex"),
            "{name}: document bytes"
        );
        assert_eq!(
            b64e(&signed.doc_hash().unwrap()),
            st(entry, "doc_hash"),
            "{name}"
        );
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let signer = match label {
            labels::sig::APP_RECORD | labels::sig::APP_REQUEST => {
                b64n::<32>(st(&parsed, "signing_key"))
            }
            labels::sig::RECEIVE_KEY => app_of(&keys, name).signing_public,
            _ => pubky(st(&parsed, "identity")),
        };
        assert!(
            reproduce(
                &keys,
                &signer,
                label,
                &[&body],
                &signed.sig_bytes().unwrap()
            ),
            "{name}: no fixed key"
        );
        signed.verify(&signer, label, &[]).unwrap();
        let mut tampered = body.clone();
        tampered[10] ^= 1;
        let tampered = SignedDoc::from_parts(&tampered, &signed.sig_bytes().unwrap());
        assert!(tampered.verify(&signer, label, &[]).is_err(), "{name}");
    }

    let certs = check_certificates(&keys, &v, &docs);
    check_app_records(&keys, &docs, &certs);
    check_receive_keys(&keys, &docs, &certs);
    check_identity_docs(&keys, &docs, &certs);
    check_freeze_and_unfreeze(&keys, &v, doc("alice freeze"));
    check_enrollments(&keys, &docs);
    check_app_request(&keys, &v, &docs, &certs);
    check_export_transfer(&keys, &docs);
    check_permission_rejections(&keys, &v, doc("wallet certificate"));
    check_scope_rule(&keys, &v, doc("wallet certificate"));
    check_app_record_conflict(&keys, &v, &docs);
    check_approval(&keys, &v, &docs, &certs);
    // Bob's documents verify for bob only.
    assert!(AppCert::verify(doc("shop certificate"), &alice).is_err());
    IdentityDoc::verify(doc("bob identity.json"), &bob).unwrap();
}

/// The certificates (Switch wire 3.1): read, issued again byte for byte, and their members
/// checked against `keys.json` and the README's lifetimes.
fn check_certificates(
    keys: &Keys,
    v: &Value,
    docs: &HashMap<String, Doc>,
) -> HashMap<String, AppCert> {
    let start = parse_rfc3339(START).unwrap();
    let mut certs = HashMap::new();
    for entry in arr(v, "documents") {
        if st(entry, "label") != labels::sig::APP_CERT {
            continue;
        }
        let name = st(entry, "name");
        let signed = &docs[name].signed;
        let app = app_of(keys, name);
        let cert = AppCert::verify(signed, &app.identity).unwrap_or_else(|e| panic!("{name}: {e}"));
        let again =
            AppCert::issue(&identity_key(keys, &app.identity), cert.body().clone()).unwrap();
        assert_eq!(again.signed(), signed, "{name}: issued again");
        assert_eq!(cert.hash(), signed.doc_hash().unwrap());
        assert_eq!(cert.app_id(), app_id_decode(&app.app_id).unwrap(), "{name}");
        assert_eq!(cert.signing_key(), app.signing_public, "{name}");
        assert_eq!(cert.bundle_key(), app.bundle_public, "{name}");
        assert!(!x25519_low_order(&cert.bundle_key()));
        assert!(
            cert.body().suite_keys.is_none(),
            "{name}: writers write no suite_keys"
        );
        let permissions: Vec<&str> = cert.permissions().iter().map(|p| p.as_str()).collect();
        if name.contains("renewed") {
            assert!(
                cert.scopes().iter().all(|s| app.scopes.contains(s)),
                "{name}"
            );
        } else {
            assert_eq!(cert.scopes(), app.scopes.as_slice(), "{name}");
            assert_eq!(permissions, app.permissions, "{name}");
        }
        // README "Certificate lifetimes".
        let expires = if name == "phone certificate" {
            start + 365 * DAY_MS
        } else if name.contains("renewed") {
            start + 90 * DAY_MS
        } else {
            assert_eq!(cert.issued_at(), start - 31 * DAY_MS, "{name}: issued_at");
            cert.issued_at() + 365 * DAY_MS
        };
        assert_eq!(cert.expires_at(), expires, "{name}: expires_at");
        assert!(!cert.expired_at(start) && cert.expired_at(expires));
        certs.insert(name.to_owned(), cert);
    }
    // The hierarchy on the vectors' own scopes: a sub-scope's certificate holds only it.
    for cert in certs.values() {
        for scope in cert.scopes() {
            assert!(cert.holds_scope(scope));
            if let Some(name) = pubky_switch_core::scopes::parent(scope) {
                assert!(!cert.holds_scope(name), "{scope} covers nothing but itself");
            } else {
                assert!(
                    cert.holds_scope(&format!("{scope}:any")),
                    "{scope} covers its subs"
                );
            }
        }
    }
    certs
}

/// The app records (Switch wire 3.2): read, signed again byte for byte, carrying their app's
/// certificate, with `expires_at` exactly when there are public endpoints.
fn check_app_records(keys: &Keys, docs: &HashMap<String, Doc>, certs: &HashMap<String, AppCert>) {
    for (name, d) in docs {
        if st(&d.entry, "label") != labels::sig::APP_RECORD {
            continue;
        }
        let app = app_of(keys, name);
        let record =
            AppRecord::verify(&d.signed, &app.identity).unwrap_or_else(|e| panic!("{name}: {e}"));
        let again = AppRecord::sign(&app_keys(app), record.body().clone()).unwrap();
        assert_eq!(again.signed(), &d.signed, "{name}: signed again");
        let cert = certs
            .iter()
            .find(|(n, c)| {
                n.starts_with(&app.name)
                    && !n.contains("renewed")
                    && c.app_id() == record.cert().app_id()
            })
            .map(|(_, c)| c)
            .unwrap_or_else(|| panic!("{name}: no certificate"));
        assert_eq!(record.cert().hash(), cert.hash(), "{name}");
        assert!(record.carries(cert));
        assert!(!record.body().accepts.is_empty());
        for kind in &record.body().accepts {
            assert!(record.accepts(kind));
        }
        if record.body().has_public_endpoints() {
            assert_eq!(
                record.expires_at(),
                Some(record.updated_at() + 30 * DAY_MS),
                "{name}"
            );
            // Without `expires_at`, a record with public endpoints is invalid.
            let mut without = body_value(&d.signed);
            without["expires_at"] = Value::Null;
            let forged = resign(&app.signing_secret, labels::sig::APP_RECORD, &without);
            let error = AppRecord::verify(&forged, &app.identity).unwrap_err();
            assert!(error.to_string().contains("expires_at"), "{name}: {error}");
        } else {
            assert_eq!(record.expires_at(), None, "{name}");
        }
        // A record verifies only for its own identity.
        let other = keys
            .identities
            .values()
            .find(|i| **i != app.identity)
            .unwrap();
        assert!(AppRecord::verify(&d.signed, other).is_err());
    }
    // A renewed certificate of the same app and keys: the wallet's record carries an earlier
    // one, which check 6 of Switch wire 3.8 takes.
    let wallet =
        AppRecord::verify(&docs["wallet app record"].signed, &keys.identity("alice")).unwrap();
    assert!(wallet.carries(&certs["wallet certificate, renewed"]));
    assert!(!wallet.carries(&certs["phone certificate"]));
}

/// The receive key records (Switch wire 3.4): read against their app's certificate, signed
/// again byte for byte, naming the fixed receive keys.
fn check_receive_keys(keys: &Keys, docs: &HashMap<String, Doc>, certs: &HashMap<String, AppCert>) {
    for (name, d) in docs {
        if st(&d.entry, "label") != labels::sig::RECEIVE_KEY {
            continue;
        }
        let app = app_of(keys, name);
        let cert = &certs[&format!("{} certificate", app.name)];
        let record =
            ReceiveKeyRecord::verify(&d.signed, cert).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(record.kid(), app.receive_kid, "{name}");
        assert_eq!(record.x25519(), app.receive_public, "{name}");
        assert_eq!(record.n(), 0, "{name}: its first key");
        assert!(record.follows(None));
        let again = ReceiveKeyRecord::sign(&app_keys(app), cert, record.body().clone()).unwrap();
        assert_eq!(again.signed(), &d.signed, "{name}: signed again");
        // Unknown members are refused here.
        let mut extra = body_value(&d.signed);
        extra["future"] = json!(1);
        let forged = resign(&app.signing_secret, labels::sig::RECEIVE_KEY, &extra);
        assert!(ReceiveKeyRecord::verify(&forged, cert).is_err());
        // Another app's certificate doesn't verify it.
        let other = certs
            .values()
            .find(|c| c.app_id() != cert.app_id())
            .unwrap();
        assert!(ReceiveKeyRecord::verify(&d.signed, other).is_err());
    }
}

/// The `identity.json` documents (Switch wire 3.3, 3.8): read, signed again byte for byte,
/// each rebuilt from alice's version 3 by the change it makes, and the rules of versions,
/// delivery, standing, renewal and equivocation on them.
fn check_identity_docs(keys: &Keys, docs: &HashMap<String, Doc>, certs: &HashMap<String, AppCert>) {
    let alice = keys.identity("alice");
    let alice_key = identity_key(keys, &alice);
    let read = |name: &str| {
        let d = &docs[name];
        let id = pubky(st(&body_value(&d.signed), "identity"));
        let doc = IdentityDoc::verify(&d.signed, &id).unwrap_or_else(|e| panic!("{name}: {e}"));
        let again = IdentityDoc::sign(&identity_key(keys, &id), doc.body().clone()).unwrap();
        assert_eq!(again.signed(), &d.signed, "{name}: signed again");
        assert_eq!(IdentityDoc::verify_named(&d.signed).unwrap(), doc);
        doc
    };
    for (name, d) in docs {
        if st(&d.entry, "label") != labels::sig::IDENTITY {
            continue;
        }
        let doc = read(name);
        let who = if doc.identity() == alice {
            "alice"
        } else {
            "bob"
        };
        assert_eq!(
            doc.body().signer,
            seed(&format!("{who}/signer"))[..16],
            "{name}: signer"
        );
        let account = pubky_switch_core::enc::pubky_id(&doc.identity());
        if name.contains("after the move") {
            continue;
        }
        assert_eq!(
            doc.inbox().service_key,
            keys.service_key(&account),
            "{name}"
        );
        assert!(doc.body().service_keys.is_empty(), "{name}");
    }
    let v1 = read("alice identity.json, first delivery (version 1)");
    let v3 = read("alice identity.json");
    let v4 = read("alice identity.json, wallet renewal in progress");
    let v5 = read("alice identity.json, wallet renewal closed");
    let v6 = read("alice identity.json, record age limit (version 6)");
    let moved = read(
        "alice identity.json after the move to the next service (version 7, generation 2), \
         keeping generation 1's service key in service_keys",
    );
    let abort = read("alice identity.json, hand-over abort (version 5)");
    let sign = |body: IdentityBody| IdentityDoc::sign(&alice_key, body).unwrap();

    // Version 3 lists each app's certificate by its document hash, and the removed app.
    for app in ["wallet", "phone", "executor"] {
        let id = app_id_decode(&keys.app(app).app_id).unwrap();
        assert_eq!(
            v3.listed_cert(&id),
            Some(certs[&format!("{app} certificate")].hash())
        );
        assert_eq!(
            v3.standing(&id, &certs[&format!("{app} certificate")].hash()),
            Standing::Listed
        );
    }
    let removed = app_id_decode(st(&load("keys.json")["removed_app"], "app_id")).unwrap();
    assert!(v3.lists_removed(&removed));
    let distrust = v3.body().removed[0].distrust_from;
    assert!(v3.counts_at(&removed, &[0; 32], distrust - CLOCK_TOLERANCE_MS));
    assert!(!v3.counts_at(&removed, &[0; 32], distrust - CLOCK_TOLERANCE_MS + 1));
    assert!(!v3.current_now(&removed, &[0; 32]));
    let bob = read("bob identity.json");
    let shop = &certs["shop certificate"];
    assert!(bob.current_now(&shop.app_id(), &shop.hash()));
    assert_eq!(
        bob.record_max_age_ms(),
        records::DEFAULT_RECORD_MAX_AGE_S * 1000
    );

    // Each version is version 3 with one change, written again byte for byte.
    let mut b1 = v3.body().clone();
    b1.version = 1;
    b1.data_epoch = 1;
    assert_eq!(sign(b1).signed(), v1.signed(), "version 1");
    let mut b6 = v3.body().clone();
    b6.version = 6;
    b6.record_max_age = Some(30 * 86_400);
    assert_eq!(sign(b6).signed(), v6.signed(), "version 6");
    assert_eq!(v6.record_max_age_ms(), 30 * DAY_MS);
    let mut b5 = v3.body().clone();
    b5.version = 5;
    assert_eq!(sign(b5).signed(), abort.signed(), "the hand-over abort");
    let next = load("keys.json")["next_service_key"].clone();
    let next_key = b64n::<32>(st(&next, "public"));
    let mut b7 = v3.body().clone();
    b7.version = 7;
    b7.generation = 2;
    b7.inbox = records::Inbox::new(st(&next, "origin"), next_key);
    b7.service_keys = vec![ServiceKeyEntry {
        generation: 1,
        key: v3.inbox().service_key,
    }];
    assert_eq!(sign(b7.clone()).signed(), moved.signed(), "after the move");
    assert_eq!(moved.service_key_of(1), Some(v3.inbox().service_key));
    assert_eq!(moved.service_key_of(2), Some(next_key));
    assert_eq!(moved.service_key_of(3), None);
    let (old, new) = (
        &certs["wallet certificate"],
        &certs["wallet certificate, renewed"],
    );
    let wallet = old.app_id();
    let mut b4 = v3.body().clone();
    b4.version = 4;
    b4.data_epoch = 3;
    for app in &mut b4.apps {
        if app.app_id == wallet {
            *app = ListedApp {
                app_id: wallet,
                cert: new.hash(),
            };
        }
    }
    b4.renewed.push(RenewedCert {
        app_id: wallet,
        cert: old.hash(),
        until: None,
    });
    assert_eq!(sign(b4.clone()).signed(), v4.signed(), "version 4");
    let until = v5.body().renewed[0].until.unwrap();
    let mut b5 = b4.clone();
    b5.version = 5;
    assert_eq!(b5.close_renewals(&wallet, until), 1);
    assert_eq!(sign(b5).signed(), v5.signed(), "version 5");

    // The first-document rule, and versions only increasing.
    v1.check_first().unwrap();
    assert!(v3.check_first().is_err());
    for (earlier, later) in [
        (&v1, &v3),
        (&v3, &v4),
        (&v4, &v5),
        (&v3, &v6),
        (&v3, &moved),
    ] {
        earlier.check_successor(later).unwrap();
        assert_eq!(earlier.compare(later), VersionOrder::Newer);
        assert!(later.check_successor(earlier).is_err());
    }
    // Two bodies at version 5: equivocation, for every reader that sees both.
    assert_eq!(v5.compare(&abort), VersionOrder::Equivocation);
    assert!(v5.check_successor(&abort).is_err());
    let mut seen = records::SeenBodies::new();
    seen.see(&v5).unwrap();
    seen.see(&v5).unwrap();
    assert!(seen.see(&abort).is_err());
    assert!(seen.equivocates(&alice));
    assert!(!seen.equivocates(&keys.identity("bob")));

    // Delivery to the own switch: version 1 first, then each building on the one before.
    let origin = v3.inbox().url.clone();
    let view = |held| account_view(held, &origin);
    assert_eq!(
        records::check_delivery(&view(None), &v1, None),
        Ok(Delivery::New(None))
    );
    assert!(
        records::check_delivery(&view(None), &v3, None).is_err(),
        "not a first document"
    );
    for (held, next) in [(&v1, &v3), (&v3, &v4), (&v4, &v5)] {
        assert_eq!(
            records::check_delivery(&view(Some(held)), next, Some(&held.hash())),
            Ok(Delivery::New(None))
        );
        assert!(records::check_delivery(&view(Some(held)), next, None).is_err());
        assert_eq!(
            records::check_delivery(&view(Some(next)), next, None),
            Ok(Delivery::Retry)
        );
    }
    assert!(
        records::check_delivery(&view(Some(&v5)), &abort, Some(&v4.hash())).is_err(),
        "another body at the version held"
    );
    // The move keeps generation 1's service key, which the switch checks.
    records::check_kept_service_keys(&moved, &[(1, v3.inbox().service_key)]).unwrap();
    let mut without = b7.clone();
    without.service_keys.clear();
    assert_eq!(
        records::check_kept_service_keys(&sign(without), &[(1, v3.inbox().service_key)]),
        Err(vec![1])
    );
    assert_eq!(
        records::signer_service_keys(
            Some(&[1, 2]),
            &[],
            ServiceKeyEntry {
                generation: 1,
                key: v3.inbox().service_key,
            },
            &[],
            2,
            None,
        )
        .unwrap(),
        moved.body().service_keys
    );

    // The renewal (Switch wire 3.8): same app and keys, a later issued_at, and a reduction
    // that rotates the data epoch, closed at once at the delivery's time plus the tolerance.
    assert!(records::is_renewal(old, new));
    assert!(records::is_reduction(old, new));
    assert!(records::reduction_rotates(old, new, |_| true));
    assert!(!records::reduction_rotates(old, new, |_| false));
    let (bundle_last, epoch) = records::renewal_epochs(true, v3.data_epoch()).unwrap();
    assert_eq!((bundle_last, epoch), (v4.data_epoch(), v4.data_epoch()));
    let delivered_at = until - CLOCK_TOLERANCE_MS;
    assert_eq!(
        records::closing_until(true, delivered_at, None),
        Some(until)
    );
    let find = |h: &[u8; 32]| certs.values().find(|c| &c.hash() == h);
    assert_eq!(records::owed_closings(&v4, find), vec![wallet]);
    assert!(records::owed_closings(&v5, find).is_empty());
    assert_eq!(v4.standing(&wallet, &new.hash()), Standing::Listed);
    assert_eq!(v4.standing(&wallet, &old.hash()), Standing::RenewedOpen);
    assert!(v4.current_now(&wallet, &old.hash()));
    assert_eq!(
        v5.standing(&wallet, &old.hash()),
        Standing::RenewedClosed { until }
    );
    assert!(!v5.current_now(&wallet, &old.hash()));
    assert!(v5.counts_at(&wallet, &old.hash(), delivered_at - 1));
    assert!(!v5.counts_at(&wallet, &old.hash(), delivered_at));
    assert!(!v5.counts_at(&wallet, &old.hash(), until - 1));
    assert!(v5.counts_at(&wallet, &new.hash(), until + DAY_MS));
}

/// What a switch at `origin` holds for alice's account, holding `held`.
fn account_view<'a>(held: Option<&'a IdentityDoc>, origin: &'a str) -> AccountView<'a> {
    AccountView {
        held,
        app_limit: 32,
        staged: false,
        origin,
        pending_key: None,
        kept_app_ids: &[],
        proof_keys: &[],
    }
}

/// The freeze, the unfreeze and the discard answer (Switch wire 3.6).
fn check_freeze_and_unfreeze(keys: &Keys, v: &Value, signed: &SignedDoc) {
    let alice = keys.identity("alice");
    let alice_key = identity_key(keys, &alice);
    let freeze = Freeze::verify(signed, &alice).unwrap();
    assert_eq!(
        Freeze::sign(&alice_key, freeze.body().clone())
            .unwrap()
            .signed(),
        signed
    );
    let next = load("keys.json")["next_service_key"].clone();
    let next_key = b64n::<32>(st(&next, "public"));
    assert_eq!(freeze.next().service_key, next_key);
    assert_eq!(freeze.next().url, st(&next, "origin"));
    assert_eq!(freeze.body().next_generation, 2);
    assert!(Freeze::verify(signed, &keys.identity("bob")).is_err());

    let unfreeze: Unfreeze = serde_json::from_value(v["unfreeze"].clone()).unwrap();
    assert_eq!(unfreeze.freeze_hash, freeze.hash());
    unfreeze.verify(&alice, &freeze, UnfreezeAt::Next).unwrap();
    assert!(
        unfreeze.verify(&alice, &freeze, UnfreezeAt::Old).is_err(),
        "O needs the answer"
    );
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::UNFREEZE,
        &[&alice, &freeze.hash()],
        &unfreeze.sig
    ));
    assert_eq!(Unfreeze::sign(&alice_key, &freeze.hash()), unfreeze);

    let d = &v["discarded"];
    assert_eq!(b64n::<32>(st(d, "next_service_key")), next_key);
    let answer: DiscardAnswer = serde_json::from_value(d["answer"].clone()).unwrap();
    answer.verify(&alice, &freeze.hash(), &next_key).unwrap();
    assert!(reproduce(
        keys,
        &next_key,
        labels::sig::DISCARDED,
        &[&alice, &freeze.hash()],
        &answer.sig
    ));
    let next_secret = SigningKey::from_bytes(&keys.secret(&next_key).unwrap());
    assert_eq!(
        DiscardAnswer::sign(&next_secret, &alice, &freeze.hash()),
        answer
    );
    let old_key = keys.service_key(&pubky_switch_core::enc::pubky_id(&alice));
    assert!(
        answer.verify(&alice, &freeze.hash(), &old_key).is_err(),
        "only the key the freeze names"
    );
    let at_old: Unfreeze = serde_json::from_value(d["unfreeze_at_old_service"].clone()).unwrap();
    assert_eq!(at_old, unfreeze.clone().with_discarded(answer));
    at_old.verify(&alice, &freeze, UnfreezeAt::Old).unwrap();
    assert!(at_old.verify(&alice, &freeze, UnfreezeAt::Next).is_err());
}

/// The enrollments (Switch wire 3.7): for their origin only, and at the next service with
/// the current `identity.json` and the revoked App ID.
fn check_enrollments(keys: &Keys, docs: &HashMap<String, Doc>) {
    let alice = keys.identity("alice");
    let alice_key = identity_key(keys, &alice);
    let v3 = IdentityDoc::verify(&docs["alice identity.json"].signed, &alice).unwrap();
    let freeze = Freeze::verify(&docs["alice freeze"].signed, &alice).unwrap();
    for (name, origin) in [
        ("alice enrollment", v3.inbox().url.as_str()),
        (
            "alice enrollment at the next service, naming a revoked app",
            freeze.next().url.as_str(),
        ),
    ] {
        let signed = &docs[name].signed;
        let e =
            Enrollment::verify(signed, &alice, origin).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(Enrollment::verify(signed, &alice, "https://other.example").is_err());
        assert_eq!(
            Enrollment::sign(&alice_key, e.body().clone())
                .unwrap()
                .signed(),
            signed
        );
        assert_eq!(e.body().policy, v3.body().policy);
        if name == "alice enrollment" {
            assert!(e.identity_doc().is_none() && e.revoked_apps().is_empty());
        } else {
            assert_eq!(e.identity_doc(), Some(&v3));
            let removed = app_id_decode(st(&load("keys.json")["removed_app"], "app_id")).unwrap();
            assert_eq!(e.revoked_apps(), [removed]);
        }
        // An answer for it, checked as the signer checks it.
        let answer =
            records::EnrollmentAnswer::new(&e, v3.inbox().service_key, records::Limits::default());
        answer.check(&e).unwrap();
    }
}

/// The wallet's app request (Switch wire 3.9) and the auth request it binds.
fn check_app_request(
    keys: &Keys,
    v: &Value,
    docs: &HashMap<String, Doc>,
    certs: &HashMap<String, AppCert>,
) {
    let alice = keys.identity("alice");
    let wallet = keys.app("wallet");
    let signed = &docs["wallet app request"].signed;
    let request = AppRequest::verify(signed).unwrap();
    assert_eq!(
        AppRequest::sign(&app_keys(wallet), request.body().clone())
            .unwrap()
            .signed(),
        signed
    );
    let body = request.body();
    assert_eq!(body.app_id, app_id_decode(&wallet.app_id).unwrap());
    assert_eq!(
        (body.signing_key, body.bundle_key),
        (wallet.signing_public, wallet.bundle_public)
    );
    assert_eq!(body.scopes, wallet.scopes);
    assert!(
        !body_value(signed)
            .as_object()
            .unwrap()
            .contains_key("identity"),
        "it names no identity"
    );

    let a = &v["auth_request"];
    let auth = AuthRequest {
        client_id: st(a, "client_id").to_owned(),
        client_key: b64n(st(a, "client_key")),
        caps: st(a, "caps").to_owned(),
        secret: b64n(st(a, "secret")),
    };
    assert!(request.binds(&auth));
    assert_eq!(body.secret_hash, auth.secret_hash());
    records::check_caps(&body.caps, &body.app_id, &[]).unwrap();

    let v3 = IdentityDoc::verify(&docs["alice identity.json"].signed, &alice).unwrap();
    let mut without = v3.body().clone();
    without.apps.retain(|a| a.app_id != body.app_id);
    let without = IdentityDoc::sign(&identity_key(keys, &alice), without).unwrap();
    let listed: Vec<AppCert> = [
        "wallet certificate",
        "phone certificate",
        "executor certificate",
    ]
    .iter()
    .map(|n| certs[*n].clone())
    .collect();
    let knows = |s: &str| wallet.scopes.iter().any(|w| w == s);
    let check = |identity: &IdentityDoc, auth: &AuthRequest, revoked: &[[u8; 16]]| {
        let view = SignerView {
            revoked,
            identity,
            listed: &listed,
            app_limit: 32,
            extra_paths: &[],
            knows_scope: &knows,
        };
        records::check_app_request(signed, auth, &view).map(|(_, approve)| approve)
    };
    // Listed with exactly these keys, approving renews; unlisted, it is a new app.
    assert_eq!(check(&v3, &auth, &[]).unwrap(), records::Approve::Renew);
    assert_eq!(check(&without, &auth, &[]).unwrap(), records::Approve::New);
    let mut other_secret = auth.clone();
    other_secret.secret[0] ^= 1;
    let error = check(&without, &other_secret, &[]).unwrap_err();
    assert!(error.to_string().contains("step 2"), "{error}");
    let error = check(&without, &auth, &[body.app_id]).unwrap_err();
    assert!(error.to_string().contains("step 4"), "{error}");
}

/// Alice's export transfer (Switch wire 3.11), for `export.json`'s manifest.
fn check_export_transfer(keys: &Keys, docs: &HashMap<String, Doc>) {
    let alice = keys.identity("alice");
    let signed = &docs["alice export transfer, for export.json's manifest"].signed;
    let transfer = ExportTransfer::verify(signed, &alice).unwrap();
    assert_eq!(
        ExportTransfer::sign(&identity_key(keys, &alice), transfer.body().clone())
            .unwrap()
            .signed(),
        signed
    );
    let freeze = Freeze::verify(&docs["alice freeze"].signed, &alice).unwrap();
    let v3 = IdentityDoc::verify(&docs["alice identity.json"].signed, &alice).unwrap();
    let manifest = b64n::<32>(st(&load("export.json")["manifest"], "doc_hash"));
    let (origin, key) = (&v3.inbox().url, v3.inbox().service_key);
    transfer
        .check_names(&freeze, origin, &key, &manifest)
        .unwrap();
    assert!(
        transfer
            .check_names(&freeze, origin, &key, &[1; 32])
            .is_err()
    );
    assert!(
        transfer
            .check_names(&freeze, "https://o.example", &key, &manifest)
            .is_err()
    );
    assert!(
        transfer
            .check_names(&freeze, origin, &freeze.next().service_key, &manifest)
            .is_err()
    );
    assert!(ExportTransfer::verify(signed, &keys.identity("bob")).is_err());
    let secret = keys.identity_secrets[&alice];
    for f in [
        (|b: &mut Value| b["future"] = json!(1)) as fn(&mut Value),
        |b| b["from"]["future"] = json!(1),
        |b| b["kind"] = json!("pubky-switch.export_manifest"),
    ] {
        let mut b = body_value(signed);
        f(&mut b);
        let forged = resign(&secret, labels::sig::EXPORT_TRANSFER, &b);
        assert!(matches!(
            ExportTransfer::verify(&forged, &alice),
            Err(Error::Invalid(_))
        ));
    }
}

/// The rule a vector's `reason` names, as this crate words it.
fn rule_of(reason: &str) -> &'static str {
    if reason.contains("isn't a switch permission") {
        "isn't a switch permission"
    } else if reason.contains("not each once in the fixed order") {
        "not each once in the fixed order"
    } else if reason.contains("isn't a scope name or name:<sub>") {
        "isn't a name or name:<sub>"
    } else if reason.contains("covers every") {
        "beside one of its sub-scopes"
    } else if reason.contains("more than 32 scopes") {
        "more than 32 scopes"
    } else {
        panic!("no rule for {reason}")
    }
}

/// A rejection case: the wallet certificate with `member` changed, signed by alice.
fn check_cert_case(
    keys: &Keys,
    case: &Value,
    base: &SignedDoc,
    member: &str,
) -> pubky_switch_core::Result<AppCert> {
    let alice = keys.identity("alice");
    let name = st(case, "name");
    let signed = signed_of(&case["signed"]);
    assert_eq!(
        signed.body_bytes().unwrap(),
        st(case, "body").as_bytes(),
        "{name}"
    );
    let body = signed.verify(&alice, labels::sig::APP_CERT, &[]).unwrap();
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::APP_CERT,
        &[&body],
        &signed.sig_bytes().unwrap()
    ));
    let mut value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value[member], case[member], "{name}");
    value[member] = body_value(base)[member].clone();
    assert_eq!(
        value,
        body_value(base),
        "{name}: the wallet certificate otherwise"
    );
    AppCert::verify(&signed, &alice)
}

/// `permission_rejections` (Switch wire 3.1): refused, the switch included, for the rule each
/// names.
fn check_permission_rejections(keys: &Keys, v: &Value, base: &SignedDoc) {
    let cases = arr(&v["permission_rejections"], "cases");
    assert!(!cases.is_empty());
    for case in cases {
        let error = check_cert_case(keys, case, base, "permissions")
            .unwrap_err()
            .to_string();
        let rule = rule_of(st(case, "reason"));
        assert!(error.contains(rule), "{}: {error}", st(case, "name"));
    }
}

/// `scope_rule` (Switch wire 3.1): `accepted` taken, `refused` refused for its rule.
fn check_scope_rule(keys: &Keys, v: &Value, base: &SignedDoc) {
    let rule = &v["scope_rule"];
    for case in arr(rule, "accepted") {
        let cert = check_cert_case(keys, case, base, "scopes")
            .unwrap_or_else(|e| panic!("{}: {e}", st(case, "name")));
        assert_eq!(cert.scopes(), strings(&case["scopes"]).as_slice());
    }
    let refused = arr(rule, "refused");
    assert!(!refused.is_empty());
    for case in refused {
        let error = check_cert_case(keys, case, base, "scopes")
            .unwrap_err()
            .to_string();
        let expected = rule_of(st(case, "reason"));
        assert!(error.contains(expected), "{}: {error}", st(case, "name"));
        assert!(
            pubky_switch_core::scopes::check_scopes(&strings(&case["scopes"])).is_err(),
            "{}",
            st(case, "name")
        );
    }
}

/// `app_record_conflict` (Switch wire 3.2, "Equal times"): two records of the wallet at one
/// `updated_at` with different bodies conflict for every reader, which keeps the earlier
/// record it holds until a strictly later one.
fn check_app_record_conflict(keys: &Keys, v: &Value, docs: &HashMap<String, Doc>) {
    let alice = keys.identity("alice");
    let c = &v["app_record_conflict"];
    assert_eq!(c["conflict"], true);
    let kept = AppRecord::verify(&docs[st(c, "kept")].signed, &alice).unwrap();
    let updated_at = parse_rfc3339(st(c, "updated_at")).unwrap();
    let wallet = keys.app("wallet");
    let records: Vec<AppRecord> = arr(c, "records")
        .iter()
        .map(|r| {
            let signed = signed_of(&r["signed"]);
            assert_eq!(signed.body_bytes().unwrap(), st(r, "body").as_bytes());
            let record = AppRecord::verify(&signed, &alice).unwrap();
            assert_eq!(record.cert().app_id(), kept.cert().app_id(), "the wallet's");
            assert_eq!(record.updated_at(), updated_at);
            assert!(reproduce(
                keys,
                &wallet.signing_public,
                labels::sig::APP_RECORD,
                &[&signed.body_bytes().unwrap()],
                &signed.sig_bytes().unwrap()
            ));
            let again = AppRecord::sign(&app_keys(wallet), record.body().clone()).unwrap();
            assert_eq!(again.signed(), &signed);
            record
        })
        .collect();
    let [a, b] = &records[..] else {
        panic!("two records");
    };
    assert!(kept.updated_at() < updated_at, "the kept record is earlier");
    assert_eq!(a.order(b), RecordOrder::Conflict);
    assert_eq!(a.order(a), RecordOrder::Same);
    assert_eq!(a.order(&kept), RecordOrder::Later);
    let now = updated_at + 60_000;
    for (x, y) in [(a, b), (b, a)] {
        let mut view = RecordView::new();
        assert!(!view.see(&kept, now));
        assert!(!view.see(x, now));
        assert_eq!(view.used(), Some(x));
        assert!(!view.see(x, now), "the same body again is one record");
        assert!(view.see(y, now), "a conflict");
        assert_eq!(view.used(), Some(&kept), "the earlier record it holds");
        let mut later_body = x.body().clone();
        later_body.updated_at = updated_at + 1;
        let later = AppRecord::sign(&app_keys(wallet), later_body).unwrap();
        let mut ahead_body = x.body().clone();
        ahead_body.updated_at = now + CLOCK_TOLERANCE_MS + 1;
        let ahead = AppRecord::sign(&app_keys(wallet), ahead_body).unwrap();
        assert!(
            view.see(&ahead, now),
            "too far ahead: no part in the comparison"
        );
        assert!(!view.see(&later, now));
        assert_eq!(view.used(), Some(&later));
    }
    let mut fresh = RecordView::new();
    fresh.see(a, now);
    assert!(fresh.see(b, now));
    assert_eq!(fresh.used(), None, "no earlier record to use");
}

/// `approval` (Switch wire 3.10): the wallet's approval, read by the app's checks, rebuilt
/// byte for byte where it is deterministic, refused at each step, and carried in its
/// companion claim, whose signed bytes come from `auth_request`.
fn check_approval(
    keys: &Keys,
    v: &Value,
    docs: &HashMap<String, Doc>,
    certs: &HashMap<String, AppCert>,
) {
    use pubky_switch_core::records::{
        Approval, ApprovalClaim, BundlePart, KeyBundle, KeyBundleContents,
    };
    use sha2::{Digest as _, Sha256};

    let keyed = keyed_scopes();
    let has_keys = |scope: &str| keyed.contains(scope);
    let alice = keys.identity("alice");
    let wallet = keys.app("wallet");
    let wallet_id = app_id_decode(&wallet.app_id).unwrap();
    let request = AppRequest::verify(&docs["wallet app request"].signed).unwrap();
    let a = &v["auth_request"];
    let auth = AuthRequest {
        client_id: st(a, "client_id").to_owned(),
        client_key: b64n(st(a, "client_key")),
        caps: st(a, "caps").to_owned(),
        secret: b64n(st(a, "secret")),
    };
    let ap = &v["approval"]["approval"];
    let json = serde_json::to_vec(ap).unwrap();
    let read =
        |json: &[u8], secret: &[u8; 32]| Approval::read(json, &request, &alice, secret, &has_keys);

    // The app's checks pass, and it keeps every key of the wallet's keyed scopes.
    let got = read(&json, &wallet.bundle_secret).unwrap();
    let cert = &certs["wallet certificate"];
    assert_eq!(got.cert, *cert);
    assert_eq!(
        st(ap, "request"),
        b64e(&request.hash()),
        "the request's hash"
    );
    assert_eq!(got.identity.signed(), &docs["alice identity.json"].signed);
    assert_eq!(got.naming_key, keys.naming(&alice));
    let keyed_scopes: Vec<&String> = cert.scopes().iter().filter(|s| has_keys(s)).collect();
    assert_eq!(
        got.keys.keys.len(),
        keyed_scopes.len() * got.identity.data_epoch() as usize,
        "every keyed scope, every epoch from 1"
    );
    let root = keys.root(&alice);
    for k in &got.keys.keys {
        assert_eq!(
            k.key,
            pubky_switch_core::ident::key_of_scope(&root, k.data_epoch, &k.scope)
        );
    }
    let text = serde_json::to_string(ap).unwrap();
    for k in &got.keys.keys {
        assert!(!text.contains(&b64e(&k.key)), "no key in the clear");
    }
    assert!(!text.contains(&b64e(&got.naming_key.to_bytes())));

    // Its one part, rebuilt from the identity key and the fixed randomness.
    let parts: Vec<BundlePart> = serde_json::from_value(ap["bundles"].clone()).unwrap();
    assert_eq!(parts.len(), 1);
    let part = &parts[0];
    assert_eq!(part.range(), (1, got.identity.data_epoch()));
    let key = identity_key(keys, &alice);
    let contents =
        KeyBundleContents::derive(&key, cert, 1, got.identity.data_epoch(), &has_keys).unwrap();
    let plaintext = contents.to_json().unwrap();
    let opened = pubky_switch_core::envelope::open_framed(
        part.bundle.envelope(),
        &alice,
        &wallet.bundle_secret,
    )
    .unwrap();
    assert!(*opened == *plaintext, "the part's plaintext derived again");
    let again = KeyBundle::seal_json_with(
        &key,
        &wallet_id,
        &wallet.bundle_public,
        &plaintext,
        &fixed_from_seeds("approval"),
    )
    .unwrap();
    assert!(again == part.bundle, "the part rebuilt");
    assert!(reproduce(
        keys,
        &alice,
        labels::sig::KEY_BUNDLE,
        &[&alice, &wallet_id, part.bundle.envelope()],
        &part.bundle.sig()
    ));
    // The approval rebuilt from its parts: the same JSON value.
    let v3 = IdentityDoc::verify(&docs["alice identity.json"].signed, &alice).unwrap();
    let approval = Approval::new(&request, cert.clone(), v3.clone(), parts.clone()).unwrap();
    let written: Value = serde_json::from_slice(&approval.to_json().unwrap()).unwrap();
    assert_eq!(&written, ap, "the approval rebuilt");

    // The companion claim: the identity key signs the claim prefix, the SHA-256 of the auth
    // request's secret, and the approval's JSON bytes.
    let claim = ApprovalClaim::sign(&key, &auth, &approval).unwrap();
    let signed = records::claim_signed_bytes(&auth.secret, claim.json());
    let prefix = format!(
        "{}|{}|",
        records::CLAIM_PARAMETER,
        records::APPROVAL_CLAIM_TYPE
    );
    assert_eq!(prefix, "x-pubky-switch-claim|pubky-switch.v1.approval|");
    let digest: [u8; 32] = Sha256::digest(auth.secret).into();
    let mut expected = prefix.into_bytes();
    expected.extend_from_slice(&digest);
    expected.extend_from_slice(&approval.to_json().unwrap());
    assert_eq!(signed, expected);
    // The auth secret's hash in the request is BLAKE3; the claim's is SHA-256.
    assert_ne!(digest, request.body().secret_hash);
    let plaintext = claim.plaintext();
    let received = ApprovalClaim::from_plaintext(&plaintext).unwrap();
    let approval_json = received.verify(&alice, &auth).unwrap();
    assert_eq!(read(approval_json, &wallet.bundle_secret).unwrap(), got);
    let signer = SigningKey::from_bytes(&keys.identity_secrets[&alice]);
    assert_eq!(
        ed25519_dalek::Signer::sign(&signer, &expected).to_bytes(),
        received.sig(),
        "deterministic, over exactly those bytes"
    );
    let mut other = auth.clone();
    other.secret[0] ^= 1;
    assert!(
        received.verify(&alice, &other).is_err(),
        "another auth secret"
    );
    assert!(received.verify(&keys.identity("bob"), &auth).is_err());

    // One refusal per step.
    let step = |value: &Value, secret: &[u8; 32]| {
        let error = read(&serde_json::to_vec(value).unwrap(), secret).unwrap_err();
        let text = error.to_string();
        (1..=4)
            .find(|n| text.contains(&format!("Switch wire 3.10 step {n}")))
            .unwrap_or_else(|| panic!("no step in {text}"))
    };
    let changed = |change: &dyn Fn(&mut Value)| {
        let mut value = ap.clone();
        change(&mut value);
        step(&value, &wallet.bundle_secret)
    };
    assert_eq!(changed(&|a| a["request"] = json!(b64e(&[1; 32]))), 1);
    assert_eq!(changed(&|a| a["kind"] = json!("pubky-switch.other")), 1);
    assert_eq!(changed(&|a| a["v"] = json!(2)), 1);
    let phone_cert = serde_json::to_value(&docs["phone certificate"].signed).unwrap();
    assert_eq!(changed(&|a| a["cert"] = phone_cert.clone()), 2);
    let bob_cert = serde_json::to_value(&docs["shop certificate"].signed).unwrap();
    assert_eq!(changed(&|a| a["cert"] = bob_cert.clone()), 2);
    let renewing =
        serde_json::to_value(&docs["alice identity.json, wallet renewal in progress"].signed)
            .unwrap();
    assert_eq!(changed(&|a| a["identity"] = renewing.clone()), 3);
    assert_eq!(changed(&|a| a["bundles"] = json!([])), 4);
    assert_eq!(changed(&|a| a["bundles"][0]["first_epoch"] = json!(2)), 4);
    let mut extra = ap["bundles"][0].clone();
    extra["first_epoch"] = json!(3);
    extra["last_epoch"] = json!(3);
    extra["bundle"]["sig"] = json!(b64e(&[0; 64]));
    assert_eq!(
        changed(&|a| a["bundles"].as_array_mut().unwrap().push(extra.clone())),
        4,
        "every part must be taken"
    );
    assert_eq!(
        step(ap, &keys.app("phone").bundle_secret),
        4,
        "another bundle key"
    );
    // A part made for another certificate, the renewed one, isn't the approval's.
    let renewed = &certs["wallet certificate, renewed"];
    let for_renewed = KeyBundleContents::derive(&key, renewed, 1, 2, &has_keys).unwrap();
    let stale = BundlePart {
        bundle: KeyBundle::seal(&key, renewed, &for_renewed).unwrap(),
        first_epoch: 1,
        last_epoch: 2,
    };
    let stale = serde_json::to_value(vec![stale]).unwrap();
    assert_eq!(changed(&|a| a["bundles"] = stale.clone()), 4);
    // Unknown members are ignored.
    let mut future = ap.clone();
    future["future"] = json!({"x": 1});
    read(&serde_json::to_vec(&future).unwrap(), &wallet.bundle_secret).unwrap();
}
