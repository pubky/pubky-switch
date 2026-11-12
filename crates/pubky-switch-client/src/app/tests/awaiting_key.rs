//! Entries that wait for a scope key the app doesn't hold yet (Switch spec 3.5, 8.2; Switch
//! wire 5.1): stored locally and passed at once, tried again once a key bundle brings the
//! key, and bounded together with the entries whose sender couldn't be checked.

use std::sync::{Arc, Mutex};

use pubky_switch_core::keys::IdentityKey;
use pubky_switch_core::ops::{KeyBundlePut, OpKind};
use pubky_switch_core::records::{AppCert, seal_bundle_parts};

use super::moves::has;
use super::shared_flows::{ItemsProtocol, items, value};
use super::*;
use crate::app::{
    AppEvent, Collection, DOC_CACHE_MS, DropReason, MAX_CURSOR_DEFER_MS, MAX_UNVERIFIED_AGE_MS,
    MAX_UNVERIFIED_PER_SENDER, MAX_UNVERIFIED_TOTAL, ParkReason, ReceiveContext, RecordTarget,
    StoreFailure,
};
use crate::error::StoreError;
use crate::transport::MockTransport;

/// What [`Keyed`]'s receive step does with a note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Write the note's record whatever the keys held, and apply.
    Write,
    /// Without the current data epoch's key, answer [`Outcome::AwaitKey`] for it; with it,
    /// write the note's record.
    Check,
    /// Without the key of this epoch, answer [`Outcome::AwaitKey`] for it; with it, write
    /// the note's record.
    Await(u64),
}

/// [`ItemsProtocol`], whose receive step writes one record per note, named by its
/// `msg_id`, through the context.
struct Keyed {
    items: ItemsProtocol,
    mode: Mutex<Mode>,
    /// How many of the next steps fail for want of the store, for now.
    unavailable: Mutex<u32>,
    /// The `msg_id` of every step run, in order.
    runs: Mutex<Vec<String>>,
}

impl Keyed {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            items: ItemsProtocol::default(),
            mode: Mutex::new(mode),
            unavailable: Mutex::new(0),
            runs: Mutex::new(Vec::new()),
        })
    }

    fn runs(&self) -> usize {
        self.runs.lock().unwrap().len()
    }

    fn runs_of(&self, msg_id: &str) -> usize {
        self.runs
            .lock()
            .unwrap()
            .iter()
            .filter(|id| *id == msg_id)
            .count()
    }
}

fn note_target(msg_id: &str) -> RecordTarget {
    RecordTarget::new(items(), msg_id.as_bytes())
}

impl Protocol for Keyed {
    fn has_keys(&self, scope: &str) -> bool {
        self.items.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.items.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.items.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.items.accepts(cert)
    }

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.items.check_body(message)
    }

    fn receive_with(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        let msg_id = message.message.msg_id.clone();
        self.runs.lock().unwrap().push(msg_id.clone());
        {
            let mut unavailable = self.unavailable.lock().unwrap();
            if *unavailable > 0 {
                *unavailable -= 1;
                return Outcome::Retry(StoreFailure::unavailable(StoreError::Unavailable));
            }
        }
        let waits_for = match *self.mode.lock().unwrap() {
            Mode::Write => None,
            Mode::Check => Some(cx.data_epoch()),
            Mode::Await(epoch) => Some(epoch),
        };
        if let Some(data_epoch) = waits_for
            && !cx.holds_scope_key("scope-a", data_epoch)
        {
            return Outcome::AwaitKey { data_epoch };
        }
        // Written anyway in `Mode::Write`: without the key the context refuses it, and the
        // effect applies without it.
        let _ = cx.put_record(&note_target(&msg_id), &value(&[&msg_id]), Vec::new());
        Outcome::Apply(Effect::default())
    }

    fn resend_needed(
        &self,
        needed: &ResendNeeded,
    ) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.items.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.items.missed(missed)
    }

    fn collections(&self) -> Vec<Collection> {
        vec![items()]
    }
}

/// alice's wallet with `protocol`, talking through `transport`, read once so the join's
/// listing is done.
async fn wallet(w: &World, protocol: &Arc<Keyed>, transport: &Arc<MockTransport>) -> App {
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let env = w.signer.env_with(
        Arc::new(MemoryStore::new()),
        Arc::clone(transport) as Arc<dyn crate::transport::Transport>,
    );
    let mut app = App::join(env, protocol.clone(), World::config(), request)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    app
}

/// The record writes the switch applied: effects done.
fn record_puts(w: &World) -> usize {
    w.switch
        .applied()
        .iter()
        .filter(|op| matches!(op.body().kind, OpKind::RecordPut(_)))
        .count()
}

/// The requests sent since `from`, as method and path without the query.
fn requests_since(transport: &MockTransport, from: usize) -> Vec<String> {
    transport
        .requests()
        .iter()
        .skip(from)
        .map(|request| {
            let path = request.path_and_query.split('?').next().unwrap_or_default();
            format!("{} {path}", request.method)
        })
        .collect()
}

/// How many of `requests` go to the key bundle routes, `GET` and `POST`.
fn key_requests(requests: &[String], method: &str) -> usize {
    requests
        .iter()
        .filter(|line| line.starts_with(method) && line.ends_with("/keys"))
        .count()
}

/// The signer stores `me`'s parts over `first..=last`.
fn store_parts(w: &World, me: [u8; 16], cert: &AppCert, first: u64, last: u64) {
    let has_keys = |scope: &str| SampleProtocol::default().has_keys(scope);
    for part in seal_bundle_parts(&w.alice, cert, first, last, &has_keys).unwrap() {
        w.switch
            .signer_op(OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: me,
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }))
            .unwrap();
    }
}

fn awaiting(epoch: u64) -> Option<ParkReason> {
    Some(ParkReason::AwaitingKey { data_epoch: epoch })
}

fn store_failing(events: &[AppEvent]) -> bool {
    has(events, |e| matches!(e, AppEvent::StoreFailing { .. }))
}

/// A sender identity other than alice's, its `identity.json` published and listing its one
/// app, so its entries pass check 7.
struct Peer {
    identity: IdentityKey,
    keys: AppKeys,
    cert: AppCert,
}

fn published_peer(w: &World, name: &str) -> Peer {
    let peer = super::identity(name);
    let keys = peer.app_keys("app");
    let cert = cert_for(peer.key(), &keys, w.clock.now_ms() - 1000, &["scope-a"]);
    let mut body = IdentityBody::first(
        peer.public(),
        peer.signer_id(),
        Inbox::new(PEER_ORIGIN, [3; 32]),
        IdentityPolicy::default(),
    );
    body.apps.push(ListedApp {
        app_id: cert.app_id(),
        cert: cert.hash(),
    });
    w.homeserver
        .publish(&IdentityDoc::sign(peer.key(), body).unwrap())
        .unwrap();
    Peer {
        identity: IdentityKey::from_secret(peer.key().secret_bytes()),
        keys,
        cert,
    }
}

/// `n` notes from `peer` to `to`, a millisecond apart; their `seq`s.
fn notes_from(w: &World, peer: &Peer, to: [u8; 16], n: usize) -> Vec<u64> {
    (0..n)
        .map(|_| {
            w.clock.advance_ms(1);
            w.switch
                .send(
                    &peer.identity,
                    &peer.keys,
                    &peer.cert,
                    "sample.note",
                    json!({ "text": "waits" }),
                    &[to],
                )
                .unwrap()
                .0
        })
        .collect()
}

/// A read with nothing new on the feed, after one that sends the cursor move a read may
/// have deferred: the requests it sends.
async fn idle_read(w: &World, app: &mut App, transport: &MockTransport) -> Vec<String> {
    w.clock.advance_ms(MAX_CURSOR_DEFER_MS + 1);
    app.receive(None).await.unwrap();
    let from = transport.requests().len();
    app.receive(None).await.unwrap();
    requests_since(transport, from)
}

/// A key that never comes: the entry is stored at once with the cursor past it, and the
/// key costs one bundle fetch and one full-bundle request, however many reads follow. No
/// later read runs the step again or asks for keys. At the bound the entry goes, with one
/// duty event, and nothing waits after.
#[tokio::test]
async fn test_awaiting_key_that_never_comes_costs_one_request_then_goes_at_the_bound() {
    let w = World::new();
    let protocol = Keyed::new(Mode::Write);
    let transport = w.switch.transport();
    let mut app = wallet(&w, &protocol, &transport).await;
    // A new data epoch whose keys never reach the app.
    w.next_doc(|body| body.data_epoch = 2);
    let (seq, note) = w.note(app.app_id(), "hello");
    let from = transport.requests().len();
    let report = app.receive(None).await.unwrap();
    let sent = requests_since(&transport, from);
    assert_eq!(app.stored_at(seq).map(|s| s.reason), awaiting(2));
    assert!(app.cursor().seq >= seq, "the cursor passes the entry");
    assert_eq!(record_puts(&w), 0);
    assert_eq!(key_requests(&sent, "POST"), 1, "{sent:?}");
    assert_eq!(protocol.runs_of(&note.msg_id), 1);
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::Parked {
            id: None,
            reason: ParkReason::AwaitingKey { data_epoch: 2 },
            ..
        }
    )));
    assert!(has(&report.events, |e| *e
        == AppEvent::AwaitingKeys {
            epochs: vec![2],
            entries: 1,
        }
        && !e.is_duty()));
    // Reads days apart: none runs the step or asks for a key.
    let from = transport.requests().len();
    let mut events = Vec::new();
    for _ in 0..5 {
        w.clock.advance_ms(3 * pubky_switch_core::records::DAY_MS);
        events.extend(app.receive(None).await.unwrap().events);
    }
    let sent = requests_since(&transport, from);
    assert_eq!(
        key_requests(&sent, "GET") + key_requests(&sent, "POST"),
        0,
        "{sent:?}"
    );
    assert_eq!(protocol.runs_of(&note.msg_id), 1);
    assert!(!store_failing(&events));
    assert_eq!(app.stored_at(seq).map(|s| s.reason), awaiting(2));
    // Past the bound from its acceptance, by the service time verified: it goes, told once.
    w.clock.advance_ms(MAX_UNVERIFIED_AGE_MS);
    for _ in 0..3 {
        events.extend(app.receive(None).await.unwrap().events);
    }
    let dropped: Vec<&AppEvent> = events
        .iter()
        .filter(|e| matches!(e, AppEvent::StoredEntryDropped { .. }))
        .collect();
    assert_eq!(dropped.len(), 1, "{dropped:?}");
    assert!(matches!(
        dropped[0],
        AppEvent::StoredEntryDropped {
            seq: s,
            reason: DropReason::Age,
            awaited_epoch: Some(2),
            ..
        } if *s == seq && dropped[0].is_duty()
    ));
    assert!(app.stored_at(seq).is_none());
    let report = app.receive(None).await.unwrap();
    assert!(!has(&report.events, |e| matches!(
        e,
        AppEvent::AwaitingKeys { .. }
    )));
    assert_eq!(protocol.runs_of(&note.msg_id), 1);
    assert!(!store_failing(&events));
}

/// A key that comes late: the read whose feed brings the key bundle part takes the entry,
/// once, and no later read hands it over again.
#[tokio::test]
async fn test_awaiting_key_that_comes_late_takes_the_entry_once() {
    let w = World::new();
    let protocol = Keyed::new(Mode::Check);
    let transport = w.switch.transport();
    let mut app = wallet(&w, &protocol, &transport).await;
    let cert = app.cert().clone();
    w.next_doc(|body| body.data_epoch = 2);
    let (seq, note) = w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    assert_eq!(app.stored_at(seq).map(|s| s.reason), awaiting(2));
    let id = app.stored_id_at(seq).unwrap();
    assert_eq!(protocol.runs_of(&note.msg_id), 1);
    // Reads before the key run nothing.
    app.receive(None).await.unwrap();
    assert_eq!(protocol.runs_of(&note.msg_id), 1);
    // The signer answers the full-bundle request: the read that brings the part takes the
    // entry.
    store_parts(&w, app.app_id(), &cert, 1, 2);
    let report = app.receive(None).await.unwrap();
    assert_eq!(record_puts(&w), 1);
    assert_eq!(protocol.runs_of(&note.msg_id), 2);
    assert!(app.stored_at(seq).is_none());
    assert!(has(&report.events, |e| *e
        == AppEvent::Unparked { seq, stored_id: id }));
    assert!(!has(&report.events, |e| matches!(
        e,
        AppEvent::AwaitingKeys { .. }
    )));
    for _ in 0..3 {
        w.clock.advance_ms(MAX_CURSOR_DEFER_MS + 1);
        app.receive(None).await.unwrap();
    }
    assert_eq!(record_puts(&w), 1);
    assert_eq!(protocol.runs_of(&note.msg_id), 2);
}

/// A step's [`Outcome::AwaitKey`] and a step that writes without the key both end in an
/// entry stored as waiting, the cursor past it. The first fetches the bundle and asks for
/// a full one; the second, with the request out, asks for nothing. A step that waits for a
/// later epoch's key asks for nothing either: that key comes once the epoch rises.
#[tokio::test]
async fn test_awaiting_key_from_await_key_and_from_a_write_without_the_key() {
    let w = World::new();
    let protocol = Keyed::new(Mode::Check);
    let transport = w.switch.transport();
    let mut app = wallet(&w, &protocol, &transport).await;
    w.next_doc(|body| body.data_epoch = 2);
    let (checked, _) = w.note(app.app_id(), "checks first");
    let from = transport.requests().len();
    app.receive(None).await.unwrap();
    let sent = requests_since(&transport, from);
    assert_eq!(app.stored_at(checked).map(|s| s.reason), awaiting(2));
    assert!(app.cursor().seq >= checked);
    assert_eq!(key_requests(&sent, "POST"), 1, "{sent:?}");

    *protocol.mode.lock().unwrap() = Mode::Write;
    let (written, _) = w.note(app.app_id(), "writes anyway");
    let from = transport.requests().len();
    app.receive(None).await.unwrap();
    let sent = requests_since(&transport, from);
    assert_eq!(app.stored_at(written).map(|s| s.reason), awaiting(2));
    assert!(app.cursor().seq >= written, "the cursor passes the entry");
    assert_eq!(
        key_requests(&sent, "GET") + key_requests(&sent, "POST"),
        0,
        "{sent:?}"
    );
    assert_eq!(record_puts(&w), 0);

    *protocol.mode.lock().unwrap() = Mode::Await(3);
    let (later, _) = w.note(app.app_id(), "a later epoch");
    let from = transport.requests().len();
    let report = app.receive(None).await.unwrap();
    let sent = requests_since(&transport, from);
    assert_eq!(app.stored_at(later).map(|s| s.reason), awaiting(3));
    assert_eq!(
        key_requests(&sent, "GET") + key_requests(&sent, "POST"),
        0,
        "{sent:?}"
    );
    assert!(has(&report.events, |e| *e
        == AppEvent::AwaitingKeys {
            epochs: vec![2, 3],
            entries: 3,
        }));
}

/// An entry that waits for a key raises no [`AppEvent::StoreFailing`] however long it
/// waits, and keeps no count of the store's retries: one its step retried for want of the
/// store before it waited for the key ends that count.
#[tokio::test]
async fn test_awaiting_key_raises_no_store_failing_and_keeps_no_retry_count() {
    let w = World::new();
    let protocol = Keyed::new(Mode::Check);
    let transport = w.switch.transport();
    let mut app = wallet(&w, &protocol, &transport).await;
    w.next_doc(|body| body.data_epoch = 2);
    *protocol.unavailable.lock().unwrap() = 2;
    let (seq, _) = w.note(app.app_id(), "hello");
    let mut events = Vec::new();
    for _ in 0..2 {
        events.extend(app.receive(None).await.unwrap().events);
    }
    assert_eq!(app.retry_reads_at(seq), Some(2));
    assert!(
        app.cursor().seq < seq,
        "held while the store is unavailable"
    );
    events.extend(app.receive(None).await.unwrap().events);
    assert_eq!(app.stored_at(seq).map(|s| s.reason), awaiting(2));
    assert!(
        app.no_retries(),
        "the count ends when the step waits for a key"
    );
    for _ in 0..(RETRY_READS + 2) {
        w.clock.advance_ms(World::config().park_after_ms + 1);
        events.extend(app.receive(None).await.unwrap().events);
    }
    assert!(!store_failing(&events), "{events:?}");
    assert_eq!(app.stored_at(seq).map(|s| s.reason), awaiting(2));
    assert!(app.no_retries());
}

const RETRY_READS: u32 = crate::app::RETRY_EVENT_READS;

/// Many senders' entries waiting for a key: the bounds hold, per sender and in all, and a
/// read with 128 entries waiting sends the requests a read with one waiting sends, and runs
/// no step.
#[tokio::test]
async fn test_awaiting_key_many_senders_bounded_and_reads_stay_flat() {
    let w = World::new();
    let protocol = Keyed::new(Mode::Write);
    let transport = w.switch.transport();
    let mut app = wallet(&w, &protocol, &transport).await;
    w.next_doc(|body| body.data_epoch = 2);
    let (first, _) = w.note(app.app_id(), "the first to wait");
    app.receive(None).await.unwrap();
    assert_eq!(app.stored_at(first).map(|s| s.reason), awaiting(2));
    let one_waiting = idle_read(&w, &mut app, &transport).await;

    let peers: Vec<Peer> = ["carol", "dave", "erin"]
        .iter()
        .map(|name| published_peer(&w, name))
        .collect();
    let over = MAX_UNVERIFIED_PER_SENDER + 6;
    let mut seqs = Vec::new();
    for peer in &peers {
        seqs.push(notes_from(&w, peer, app.app_id(), over));
    }
    let mut events = app.receive(None).await.unwrap().events;
    for seq in seqs.iter().flatten() {
        assert_eq!(app.stored_at(*seq).map(|s| s.reason), awaiting(2), "{seq}");
    }
    // The bounds apply at the start of the next read.
    events.extend(app.receive(None).await.unwrap().events);
    let waiting: Vec<_> = app
        .state
        .parked
        .values()
        .filter(|stored| stored.reason == ParkReason::AwaitingKey { data_epoch: 2 })
        .collect();
    assert_eq!(waiting.len(), MAX_UNVERIFIED_TOTAL);
    for peer in &peers {
        let held = waiting
            .iter()
            .filter(|stored| stored.sender == peer.identity.public())
            .count();
        assert!(held <= MAX_UNVERIFIED_PER_SENDER, "{held}");
    }
    let dropped = events
        .iter()
        .filter(|e| matches!(e, AppEvent::StoredEntryDropped { .. }))
        .count();
    assert_eq!(dropped, 1 + 3 * over - MAX_UNVERIFIED_TOTAL);
    assert!(has(&events, |e| matches!(
        e,
        AppEvent::StoredEntryDropped {
            reason: DropReason::PerSender,
            ..
        }
    )));
    assert!(has(&events, |e| matches!(
        e,
        AppEvent::StoredEntryDropped {
            reason: DropReason::Total,
            ..
        }
    )));
    // A read with them all waiting: the same requests as with one, and no step run.
    let runs = protocol.runs();
    let many_waiting = idle_read(&w, &mut app, &transport).await;
    assert_eq!(many_waiting, one_waiting);
    assert_eq!(protocol.runs(), runs);
}

/// Entries that wait for a key and entries whose sender couldn't be checked count together
/// against the per-sender bound: 40 of each from one sender are 16 over, and those accepted
/// earliest, the waiting ones, go.
#[tokio::test]
async fn test_awaiting_key_counts_with_unverified_entries_against_the_bounds() {
    let w = World::new();
    let protocol = Keyed::new(Mode::Write);
    let transport = w.switch.transport();
    let mut app = wallet(&w, &protocol, &transport).await;
    w.next_doc(|body| body.data_epoch = 2);
    let peer = published_peer(&w, "carol");
    let waiting = notes_from(&w, &peer, app.app_id(), 40);
    app.receive(None).await.unwrap();
    // The sender's Homeserver goes down, and its copy grows stale: its next entries are
    // held, then stored as unverifiable.
    w.homeserver.set_down(true);
    w.clock.advance_ms(DOC_CACHE_MS + 1);
    let unverified = notes_from(&w, &peer, app.app_id(), 40);
    app.receive(None).await.unwrap();
    w.clock.advance_ms(World::config().park_after_ms + 1);
    app.receive(None).await.unwrap();
    for seq in &unverified {
        assert_eq!(
            app.stored_at(*seq).map(|s| s.reason),
            Some(ParkReason::Unverifiable),
            "{seq}"
        );
    }
    let report = app.receive(None).await.unwrap();
    let dropped: Vec<u64> = report
        .events
        .iter()
        .filter_map(|e| match e {
            AppEvent::StoredEntryDropped {
                seq,
                reason: DropReason::PerSender,
                awaited_epoch: Some(2),
                ..
            } => Some(*seq),
            _ => None,
        })
        .collect();
    assert_eq!(dropped, waiting[..16].to_vec());
    assert!(unverified.iter().all(|seq| app.stored_at(*seq).is_some()));
}

/// A key that arrives in a read that ends owing a listing: the entry waiting for it isn't
/// handed over in that read. The next read lists first, then takes it (Switch spec 8.2).
#[tokio::test]
async fn test_awaiting_key_waits_for_an_owed_listing() {
    let w = World::new();
    let protocol = Keyed::new(Mode::Check);
    let transport = w.switch.transport();
    let mut app = wallet(&w, &protocol, &transport).await;
    let cert = app.cert().clone();
    w.next_doc(|body| body.data_epoch = 2);
    let (seq, note) = w.note(app.app_id(), "hello");
    app.receive(None).await.unwrap();
    assert_eq!(app.stored_at(seq).map(|s| s.reason), awaiting(2));
    // A `missed` item, which the read lists for, the key's part, and a second `missed`
    // item, which owes another listing and ends the read: it lists at most once.
    w.switch.push_missed(3, START, START + 1);
    store_parts(&w, app.app_id(), &cert, 1, 2);
    w.switch.push_missed(3, START, START + 1);
    app.receive(None).await.unwrap();
    assert!(app.holds_epoch_keys(2), "the key came in that read");
    assert!(app.listing_owed().await.unwrap());
    assert_eq!(protocol.runs_of(&note.msg_id), 1, "not handed over");
    assert_eq!(record_puts(&w), 0);
    let from = transport.requests().len();
    app.receive(None).await.unwrap();
    let sent = requests_since(&transport, from);
    assert_eq!(protocol.runs_of(&note.msg_id), 2);
    assert_eq!(record_puts(&w), 1);
    let listed = sent
        .iter()
        .position(|line| line.ends_with("/records"))
        .unwrap();
    let effect = sent
        .iter()
        .position(|line| line.starts_with("POST") && line.ends_with("/ops"));
    assert!(effect.is_some_and(|effect| listed < effect), "{sent:?}");
}

/// A step that waits for a later epoch's key, with no full bundle asked for: no fetch can
/// bring a key past the current epoch, so neither entry asks for one. The key comes once the
/// epoch rises.
#[tokio::test]
async fn test_awaiting_key_of_a_later_epoch_fetches_nothing() {
    let w = World::new();
    let protocol = Keyed::new(Mode::Await(2));
    let transport = w.switch.transport();
    let mut app = wallet(&w, &protocol, &transport).await;
    let (first, _) = w.note(app.app_id(), "one");
    let (second, _) = w.note(app.app_id(), "two");
    let from = transport.requests().len();
    app.receive(None).await.unwrap();
    let sent = requests_since(&transport, from);
    assert_eq!(app.stored_at(first).map(|s| s.reason), awaiting(2));
    assert_eq!(app.stored_at(second).map(|s| s.reason), awaiting(2));
    assert!(app.cursor().seq >= second);
    assert_eq!(
        key_requests(&sent, "GET") + key_requests(&sent, "POST"),
        0,
        "{sent:?}"
    );
}
