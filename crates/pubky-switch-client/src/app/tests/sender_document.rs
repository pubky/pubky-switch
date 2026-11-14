//! Check 7 against the sender identity's newest `identity.json` (Switch wire 5.1): a held
//! copy that doesn't list an entry's certificate is read again once before the entry is
//! dropped, at most once per [`SENDER_REREAD_MS`] for one sender. An entry is never dropped
//! on an answer older than its read: within the window a later read holds it, and a copy
//! that can't be read holds it, as an unreachable sender does (Switch spec 8.2).

use pubky_switch_core::records::{AppCert, IdentityDoc, ListedApp};

use super::moves::has;
use super::*;
use crate::app::{AppEvent, SENDER_REREAD_MS};

fn received(events: &[AppEvent], seq: u64) -> bool {
    has(
        events,
        |e| matches!(e, AppEvent::MessageReceived { seq: s, .. } if *s == seq),
    )
}

fn dropped_at_check_7(events: &[AppEvent], seq: u64) -> bool {
    has(
        events,
        |e| matches!(e, AppEvent::MessageDropped { seq: s, check: 7, .. } if *s == seq),
    )
}

/// An app that read a note from bob, so it holds a fresh copy of bob's `identity.json`.
async fn app_holding_bobs_document(w: &World) -> App {
    let mut app = w.join("wallet").await;
    let (seq, _) = w.note(app.app_id(), "first");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq));
    app
}

/// Bob's next `identity.json` on his Homeserver, listing `cert` in place of the one his app
/// was listed with: a renewal.
fn publish_renewal(w: &World, cert: &AppCert) {
    let held = w.homeserver.identity_doc(&w.bob.public()).unwrap();
    let mut body = held.body().clone();
    body.version += 1;
    body.apps = vec![ListedApp {
        app_id: cert.app_id(),
        cert: cert.hash(),
    }];
    w.homeserver
        .publish(&IdentityDoc::sign(&w.bob, body).unwrap())
        .unwrap();
}

/// A note from bob's app under `cert`.
fn note_under(w: &World, cert: &AppCert, to: [u8; 16], text: &str) -> u64 {
    w.switch
        .send(
            &w.bob,
            &w.bob_keys,
            cert,
            "sample.note",
            json!({ "text": text }),
            &[to],
        )
        .unwrap()
        .0
}

/// Bob's app renews its certificate and sends under the new one before the app's copy of
/// his document is old enough to read again: the copy doesn't list it, so the app reads the
/// document again, finds the renewal, and keeps the message.
#[tokio::test]
async fn test_sender_document_renewed_certificate_before_the_copy_ages_is_kept() {
    let w = World::new();
    let mut app = app_holding_bobs_document(&w).await;
    w.clock.advance_ms(60_000);
    let renewed = cert_for(&w.bob, &w.bob_keys, w.clock.now_ms(), &["sample-a"]);
    publish_renewal(&w, &renewed);
    let seq = note_under(&w, &renewed, app.app_id(), "after the renewal");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert!(app.cursor().seq >= seq);
}

/// A certificate bob's newest document doesn't list either: read again once, then dropped
/// as before.
#[tokio::test]
async fn test_sender_document_unlisted_certificate_is_read_again_once_then_dropped() {
    let w = World::new();
    let mut app = app_holding_bobs_document(&w).await;
    w.clock.advance_ms(60_000);
    let unlisted = cert_for(&w.bob, &w.bob_keys, w.clock.now_ms(), &["sample-a"]);
    let seq = note_under(&w, &unlisted, app.app_id(), "unlisted");
    let reads = w.homeserver.identity_reads(&w.bob.public());
    let report = app.receive(None).await.unwrap();
    assert!(
        dropped_at_check_7(&report.events, seq),
        "{:?}",
        report.events
    );
    assert_eq!(w.homeserver.identity_reads(&w.bob.public()), reads + 1);
    assert!(app.cursor().seq >= seq);
    // A copy too old to use is read once, and that read decides: no second one.
    w.clock.advance_ms(crate::app::DOC_CACHE_MS);
    let seq = note_under(&w, &unlisted, app.app_id(), "unlisted again");
    let report = app.receive(None).await.unwrap();
    assert!(
        dropped_at_check_7(&report.events, seq),
        "{:?}",
        report.events
    );
    assert_eq!(w.homeserver.identity_reads(&w.bob.public()), reads + 2);
}

fn held(events: &[AppEvent], seq: u64) -> bool {
    has(
        events,
        |e| matches!(e, AppEvent::Held { seq: s } if *s == seq),
    )
}

/// A sender sending under one unlisted certificate after another: one read of its document
/// for all of them within [`SENDER_REREAD_MS`], however many entries. Those of the read that
/// read it are judged against that copy; those of a later read within the window are held,
/// with the cursor before them, and judged by the first read after it.
#[tokio::test]
async fn test_sender_document_unlisted_certificates_are_read_again_once_per_window() {
    let w = World::new();
    let mut app = app_holding_bobs_document(&w).await;
    w.clock.advance_ms(60_000);
    let me = app.app_id();
    let bob = w.bob.public();
    let unlisted = |n: u64| cert_for(&w.bob, &w.bob_keys, w.clock.now_ms() + n, &["sample-a"]);
    let first: Vec<u64> = (0..5)
        .map(|n| note_under(&w, &unlisted(n), me, &format!("unlisted {n}")))
        .collect();
    let reads = w.homeserver.identity_reads(&bob);
    let report = app.receive(None).await.unwrap();
    assert_eq!(w.homeserver.identity_reads(&bob), reads + 1);
    for seq in &first {
        assert!(
            dropped_at_check_7(&report.events, *seq),
            "{seq}: {:?}",
            report.events
        );
    }
    // Within the window, a later read reads it no more, and drops nothing on its answer.
    w.clock.advance_ms(SENDER_REREAD_MS / 2);
    let later: Vec<u64> = (5..8)
        .map(|n| note_under(&w, &unlisted(n), me, &format!("unlisted {n}")))
        .collect();
    let report = app.receive(None).await.unwrap();
    assert_eq!(w.homeserver.identity_reads(&bob), reads + 1);
    for seq in &later {
        assert!(held(&report.events, *seq), "{seq}: {:?}", report.events);
        assert!(!dropped_at_check_7(&report.events, *seq));
    }
    assert!(app.cursor().seq < later[0]);
    // Past it, one more read judges them all.
    w.clock.advance_ms(SENDER_REREAD_MS / 2);
    let report = app.receive(None).await.unwrap();
    assert_eq!(w.homeserver.identity_reads(&bob), reads + 2);
    for seq in &later {
        assert!(
            dropped_at_check_7(&report.events, *seq),
            "{seq}: {:?}",
            report.events
        );
    }
    assert!(app.cursor().seq >= later[2]);
}

/// An entry under an unlisted certificate has bob's document read again and is dropped;
/// seconds later bob's newer document lists another certificate, and an entry under it
/// comes within the window: it is held, not dropped on the older answer, and kept once
/// the first read after the window reads the document.
#[tokio::test]
async fn test_sender_document_newly_listed_certificate_within_the_window_is_kept() {
    let w = World::new();
    let mut app = app_holding_bobs_document(&w).await;
    w.clock.advance_ms(60_000);
    let me = app.app_id();
    let bob = w.bob.public();
    let unlisted = cert_for(&w.bob, &w.bob_keys, w.clock.now_ms(), &["sample-a"]);
    let dropped = note_under(&w, &unlisted, me, "unlisted");
    let reads = w.homeserver.identity_reads(&bob);
    let report = app.receive(None).await.unwrap();
    assert!(
        dropped_at_check_7(&report.events, dropped),
        "{:?}",
        report.events
    );
    assert_eq!(w.homeserver.identity_reads(&bob), reads + 1);
    w.clock.advance_ms(10_000);
    let listed = cert_for(&w.bob, &w.bob_keys, w.clock.now_ms(), &["sample-a"]);
    publish_renewal(&w, &listed);
    let seq = note_under(&w, &listed, me, "newly listed");
    let report = app.receive(None).await.unwrap();
    assert!(held(&report.events, seq), "{:?}", report.events);
    assert!(!dropped_at_check_7(&report.events, seq));
    assert!(app.cursor().seq < seq);
    assert_eq!(w.homeserver.identity_reads(&bob), reads + 1);
    w.clock.advance_ms(SENDER_REREAD_MS);
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(w.homeserver.identity_reads(&bob), reads + 2);
}

/// The document can't be read again when the copy doesn't list the certificate: the entry is
/// held, reported, and the cursor stays before it, as for a sender that can't be checked;
/// once the document reads again it is kept.
#[tokio::test]
async fn test_sender_document_unreachable_when_read_again_holds_the_entry() {
    let w = World::new();
    let mut app = app_holding_bobs_document(&w).await;
    w.clock.advance_ms(60_000);
    let renewed = cert_for(&w.bob, &w.bob_keys, w.clock.now_ms(), &["sample-a"]);
    publish_renewal(&w, &renewed);
    w.homeserver.set_down(true);
    // Two entries in one read: the second meets the failed read of the first, held too.
    let seqs = [
        note_under(&w, &renewed, app.app_id(), "held"),
        note_under(&w, &renewed, app.app_id(), "held too"),
    ];
    let bob = w.bob.public();
    let reads = w.homeserver.identity_reads(&bob);
    let report = app.receive(None).await.unwrap();
    assert_eq!(w.homeserver.identity_reads(&bob), reads + 1);
    for seq in seqs {
        assert!(held(&report.events, seq), "{seq}: {:?}", report.events);
        assert!(!dropped_at_check_7(&report.events, seq));
    }
    assert!(app.cursor().seq < seqs[0]);
    // Within the window: held again, without another read.
    let report = app.receive(None).await.unwrap();
    for seq in seqs {
        assert!(held(&report.events, seq));
        assert!(!dropped_at_check_7(&report.events, seq));
    }
    assert_eq!(w.homeserver.identity_reads(&bob), reads + 1);
    // Back up, and past the window: read again once, and both kept.
    w.homeserver.set_down(false);
    w.clock.advance_ms(SENDER_REREAD_MS);
    let report = app.receive(None).await.unwrap();
    for seq in seqs {
        assert!(received(&report.events, seq), "{seq}: {:?}", report.events);
    }
    assert_eq!(w.homeserver.identity_reads(&bob), reads + 2);
}

/// A Homeserver that serves bob's older document again after the app took his renewal: an
/// entry under his first certificate, which only the older document lists, has the
/// document read again once and is dropped, since the older copy doesn't replace the newer
/// one held.
#[tokio::test]
async fn test_sender_document_older_copy_served_again_lists_nothing_back() {
    let w = World::new();
    let mut app = app_holding_bobs_document(&w).await;
    let older = w.homeserver.identity_doc(&w.bob.public()).unwrap();
    w.clock.advance_ms(60_000);
    let renewed = cert_for(&w.bob, &w.bob_keys, w.clock.now_ms(), &["sample-a"]);
    publish_renewal(&w, &renewed);
    let seq = note_under(&w, &renewed, app.app_id(), "under the renewal");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    // The Homeserver goes back to the older document.
    w.homeserver.publish(&older).unwrap();
    w.clock.advance_ms(SENDER_REREAD_MS);
    let bob = w.bob.public();
    let reads = w.homeserver.identity_reads(&bob);
    let seq = note_under(&w, &w.bob_cert.clone(), app.app_id(), "under the first");
    let report = app.receive(None).await.unwrap();
    assert!(!received(&report.events, seq));
    assert!(
        dropped_at_check_7(&report.events, seq),
        "{:?}",
        report.events
    );
    assert_eq!(w.homeserver.identity_reads(&bob), reads + 1);
}
