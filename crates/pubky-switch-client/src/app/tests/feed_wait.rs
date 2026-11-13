//! Waiting for the feed with a handle that doesn't hold the app (Switch wire 7.4.4): what it
//! wakes with, the position and the wait it sends, a switch that refuses every wait, the
//! held read across a recovery in place, dropping it at each await, and a host that writes
//! and sends while it waits. Then the read's per-call budgets, which keep a read short: the
//! kept batches it sends again and the pages of an owed listing.

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use pubky_switch_core::keys::ReceiveKey;
use pubky_switch_core::ops::{AllowKind, OpKind, Position};
use pubky_switch_core::records::{
    Freeze, FreezeBody, Inbox, ReceiveKeyBody, ReceiveKeyRecord, RemovedApp,
};
use pubky_switch_core::scopes::Permission;
use serde_json::{Map, json};

use super::held_reads::Recording;
use super::shared_flows::{ItemsProtocol, items, value};
use super::*;
use crate::app::{
    AppError, AppEvent, FeedWait, KEPT_RESENDS_PER_READ, LISTING_PAGES_PER_READ, LeaveMode,
    LeaveReport, MAX_PAUSE_MS, MAX_WAIT_SECONDS, MIN_PAUSE_MS, OpBatch, OutgoingMessage,
    RecordTarget, UPKEEP_READ_MS, WaitPace, Woken,
};
use crate::error::TransportError;
use crate::testing::SWITCH_ORIGIN as ORIGIN;
use crate::testing::{PeerSwitch, Router};
use crate::transport::{BoxFuture, Request, Response, Transport};

/// What the gate does with the feed reads it passes.
#[derive(Clone, Copy, Default)]
struct Mode {
    /// Every feed read with `wait` is answered `503 unavailable` under a key the app
    /// doesn't know.
    refuse_waits: bool,
    /// Every feed read fails to connect.
    feeds_down: bool,
    /// Every request waits here, before it reaches the switch.
    paused: bool,
}

/// The switch's transport, recording the query of each feed read with `wait`.
struct Gate {
    inner: Arc<dyn Transport>,
    mode: Mutex<Mode>,
    waits: Mutex<Vec<String>>,
}

impl Gate {
    fn over(inner: Arc<dyn Transport>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            mode: Mutex::new(Mode::default()),
            waits: Mutex::new(Vec::new()),
        })
    }

    fn mode(&self) -> Mode {
        *self.mode.lock().unwrap()
    }

    fn set(&self, change: impl FnOnce(&mut Mode)) {
        change(&mut self.mode.lock().unwrap());
    }

    /// The queries of the feed reads with `wait`, in order.
    fn waits(&self) -> Vec<String> {
        self.waits.lock().unwrap().clone()
    }

    /// The `name` parameter of the last feed read with `wait`.
    fn last(&self, name: &str) -> String {
        let waits = self.waits();
        let query = waits.last().expect("a wait was sent");
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .expect("the parameter is in the query")
            .to_owned()
    }
}

impl Transport for Gate {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(async move {
            let query = request
                .path_and_query
                .split_once("/feed?")
                .map(|(_, query)| query.to_owned());
            let waits = query.as_ref().is_some_and(|q| q.contains("wait="));
            if waits && let Some(query) = query.clone() {
                self.waits.lock().unwrap().push(query);
            }
            while self.mode().paused {
                tokio::task::yield_now().await;
            }
            let mode = self.mode();
            if waits && mode.refuse_waits {
                return Ok(Recording::forged(&request));
            }
            if query.is_some() && mode.feeds_down {
                return Err(TransportError::Connect("the switch is down".into()));
            }
            self.inner.send(request).await
        })
    }
}

/// Alice's account behind a gate, bob's switch for sending, and the items protocol.
struct Setup {
    w: World,
    peer: Arc<PeerSwitch>,
    shop: [u8; 16],
    gate: Arc<Gate>,
    router: Arc<Router>,
    protocol: Arc<ItemsProtocol>,
}

impl Setup {
    /// With `holding`, the switch holds a waiting read as the service does; otherwise it
    /// answers one at once.
    fn new(holding: bool) -> Self {
        let w = World::new();
        let peer = PeerSwitch::new(
            identity("bob"),
            PEER_ORIGIN,
            Arc::clone(&w.clock),
            Arc::clone(&w.homeserver),
        );
        let shop = peer
            .add_app("shop", &AppSpec::new(&["scope-a"]), &["sample.note"], false)
            .unwrap();
        let inner = if holding {
            w.switch.holding_transport()
        } else {
            w.switch.transport()
        };
        let gate = Gate::over(inner);
        let router = Arc::new(Router::new());
        router.add(ORIGIN, Arc::clone(&gate) as Arc<dyn Transport>);
        router.add(PEER_ORIGIN, peer.transport());
        Self {
            w,
            peer,
            shop,
            gate,
            router,
            protocol: Arc::new(ItemsProtocol::default()),
        }
    }

    async fn join_on(&self, name: &str, store: Arc<dyn StateStore>) -> App {
        let app = AppSpec::new(&["scope-a"]).with_permissions(&Permission::ALL);
        let request = self.w.signer.approve(&app_keys(name), &app).unwrap();
        let env = self
            .w
            .signer
            .env_with(store, Arc::clone(&self.router) as Arc<dyn Transport>);
        let mut app = App::join(env, self.protocol.clone(), World::config(), request)
            .await
            .unwrap();
        self.settle(&mut app).await;
        app
    }

    /// Read the feed to its end and send the deferred cursor move.
    async fn settle(&self, app: &mut App) {
        app.receive(None).await.unwrap();
        self.w.clock.advance_ms(3_000);
        app.receive(None).await.unwrap();
        assert!(app.state.cursor.deferred_since_ms.is_none());
    }

    async fn join(&self, name: &str) -> App {
        self.join_on(name, Arc::new(MemoryStore::new())).await
    }

    /// A note from bob's shop to `to`.
    fn note(&self, to: [u8; 16]) -> u64 {
        self.peer
            .send_to(
                &self.w.switch,
                self.shop,
                "sample.note",
                json!({ "text": "hello" }),
                &[to],
            )
            .unwrap()
            .0
    }

    /// A notice from alice's other app `phone` to `to`: an entry that applies nothing, so
    /// its cursor move is deferred.
    fn notice(&self, phone: &App, to: [u8; 16]) -> u64 {
        self.w
            .switch
            .send(
                &self.w.alice,
                &app_keys("phone"),
                phone.cert(),
                "sample.notice",
                json!({ "text": "hi" }),
                &[to],
            )
            .unwrap()
            .0
    }
}

fn received(events: &[AppEvent]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|e| match e {
            AppEvent::MessageReceived { seq, .. } => Some(*seq),
            _ => None,
        })
        .collect()
}

/// Poll `wait` once, as a host's select does before another branch wins.
fn poll_once(wait: &mut std::pin::Pin<Box<impl Future<Output = Woken>>>) -> Poll<Woken> {
    wait.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}

/// Wait until the switch holds `reads` reads.
async fn held(w: &World, reads: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while w.switch.held_reads() < reads {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the reads are held");
}

/// The app's keys in the store, with their values, and its state in memory.
fn snapshot(app: &App, store: &MemoryStore) -> (Vec<crate::store::KeyValue>, String) {
    let stored = store.scan(&app.ns, b"", None, u32::MAX).unwrap();
    (stored, format!("{:?}", app.state))
}

#[tokio::test]
async fn test_feed_wait_is_ready_quiet_or_read_now() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    // Nothing on the feed: quiet.
    assert_eq!(app.feed_wait(25).wait().await, Woken::Quiet);
    // An entry: ready, and the read takes it.
    let note = s.note(app.app_id());
    assert_eq!(app.feed_wait(25).wait().await, Woken::Ready);
    let report = app.receive(None).await.unwrap();
    assert_eq!(received(&report.events), vec![note]);
    s.settle(&mut app).await;
    assert_eq!(app.feed_wait(25).wait().await, Woken::Quiet);
    // A refusal, an answer that doesn't verify, a switch that can't be reached: read now.
    s.gate.set(|mode| mode.refuse_waits = true);
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadNow);
    s.gate.set(|mode| {
        mode.refuse_waits = false;
        mode.feeds_down = true;
    });
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadNow);
    s.gate.set(|mode| mode.feeds_down = false);
    // A certificate that expired since: the switch's `403 cert_expired`.
    s.w.clock
        .set_ms(app.cert().expires_at().saturating_add(1_000));
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadNow);
}

#[tokio::test]
async fn test_feed_wait_never_retries_a_refused_wait() {
    // A switch that refuses every wait costs one receive per wait: the handle sends one
    // read and wakes, whatever the answer, and the host's read then succeeds.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    for (refuse, down) in [(true, false), (false, true)] {
        s.gate.set(|mode| {
            mode.refuse_waits = refuse;
            mode.feeds_down = down;
        });
        let before = s.gate.waits().len();
        for round in 1..=5 {
            assert_eq!(app.feed_wait(25).wait().await, Woken::ReadNow);
            assert_eq!(s.gate.waits().len(), before + round, "one read a wait");
            s.gate.set(|mode| mode.feeds_down = false);
            app.receive(None).await.unwrap();
            s.gate.set(|mode| mode.feeds_down = down);
        }
        s.gate.set(|mode| mode.feeds_down = false);
    }
}

#[tokio::test]
async fn test_feed_wait_caps_and_cuts_its_wait_as_the_read_does() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let phone = s.join("phone").await;
    s.settle(&mut app).await;
    // At most 25 seconds, and at least one.
    assert_eq!(app.feed_wait(60).wait().await, Woken::Quiet);
    assert_eq!(s.gate.last("wait"), "25");
    assert_eq!(app.feed_wait(0).wait().await, Woken::Quiet);
    assert_eq!(s.gate.last("wait"), "1");
    assert_eq!(app.feed_wait(7).wait().await, Woken::Quiet);
    assert_eq!(s.gate.last("wait"), "7");
    // A notice applies nothing: its cursor move is deferred, for 2 seconds.
    s.notice(&phone, app.app_id());
    app.receive(None).await.unwrap();
    assert!(app.state.cursor.deferred_since_ms.is_some());
    // The wait ends when the move falls due, as the read's long poll does, and an empty
    // answer then is a read: the read sends the move.
    s.w.clock.advance_ms(500);
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadNow);
    assert_eq!(s.gate.last("wait"), "2");
    app.receive(Some(25)).await.unwrap();
    assert_eq!(s.gate.last("wait"), "2");
    s.w.clock.advance_ms(2_000);
    app.receive(None).await.unwrap();
    assert!(app.state.cursor.deferred_since_ms.is_none());
    assert_eq!(app.feed_wait(25).wait().await, Woken::Quiet);
    assert_eq!(s.gate.last("wait"), "25");
}

#[tokio::test]
async fn test_feed_wait_taken_before_a_read_wakes_to_nothing_new() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let early = app.feed_wait(25);
    let note = s.note(app.app_id());
    let report = app.receive(None).await.unwrap();
    assert_eq!(received(&report.events), vec![note]);
    // The early handle waits from before the entry: it wakes, and the read finds nothing.
    assert_eq!(early.wait().await, Woken::Ready);
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events).is_empty(), "{:?}", report.events);
    // A handle taken now waits past it.
    s.settle(&mut app).await;
    assert_eq!(app.feed_wait(25).wait().await, Woken::Quiet);
    assert_eq!(s.gate.last("after"), app.cursor().to_string());
}

#[tokio::test]
async fn test_feed_wait_goes_past_an_entry_the_cursor_stays_before() {
    // An entry whose sender can't be checked is held, the cursor before it: a wait from the
    // cursor would wake at once, and a host would read again and again. The handle waits
    // past it, and once the wait has passed a read tries the entry again.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    s.w.homeserver.set_down(true);
    let held = s.note(app.app_id());
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::Held { seq } if *seq == held))
    );
    assert!(app.cursor().seq < held);
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadNow);
    assert_eq!(s.gate.last("after"), format!("1:{held}"));
    // Once the sender can be checked, the read takes it, and the wait is quiet again.
    s.w.homeserver.set_down(false);
    let report = app.receive(None).await.unwrap();
    assert_eq!(received(&report.events), vec![held]);
    s.settle(&mut app).await;
    assert_eq!(app.feed_wait(25).wait().await, Woken::Quiet);
}

#[tokio::test]
async fn test_feed_wait_after_a_failed_read_is_read_now_without_a_request() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    s.gate.set(|mode| mode.feeds_down = true);
    assert!(app.receive(None).await.is_err());
    s.gate.set(|mode| mode.feeds_down = false);
    // The state the next read loads again may be behind memory: only a read goes on.
    let sent = s.gate.waits().len();
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadNow);
    assert_eq!(s.gate.waits().len(), sent);
    app.receive(None).await.unwrap();
    assert_eq!(app.feed_wait(25).wait().await, Woken::Quiet);
    assert_eq!(s.gate.waits().len(), sent + 1);
}

#[tokio::test]
async fn test_feed_wait_held_across_a_recovery_in_place_is_read_now() {
    // The held read gets the operator's `503` with no head (Switch wire 7.4.4): the
    // handle wakes once, sends nothing more, and the host's read follows the recovery.
    let s = Setup::new(true);
    let mut app = s.join("wallet").await;
    let waiting = tokio::spawn(app.feed_wait(25).wait());
    held(&s.w, 1).await;
    let pending = SigningKey::from_bytes(&seed("service/alice/in-place"));
    let prev = s.w.switch.identity_doc().unwrap().hash();
    let doc =
        s.w.signer
            .sign_next(|body| {
                body.generation = 2;
                body.inbox = Inbox::new(ORIGIN, pending.verifying_key().to_bytes());
                body.recovery_from = Some(1);
            })
            .unwrap();
    let sent = s.gate.waits().len();
    s.w.switch
        .recover_in_place(pending.clone(), &doc, prev)
        .unwrap();
    let woken = tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("the held read is answered")
        .unwrap();
    assert_eq!(woken, Woken::ReadNow);
    assert_eq!(s.gate.waits().len(), sent, "no read sent again");
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
}

#[tokio::test]
async fn test_feed_wait_two_at_once_each_hold_a_read() {
    let s = Setup::new(true);
    let app = s.join("wallet").await;
    let first = tokio::spawn(app.feed_wait(25).wait());
    let second = tokio::spawn(app.feed_wait(25).wait());
    held(&s.w, 2).await;
    s.note(app.app_id());
    for waiting in [first, second] {
        let woken = tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .expect("woken")
            .unwrap();
        assert_eq!(woken, Woken::Ready);
    }
}

#[tokio::test]
async fn test_feed_wait_dropped_at_any_point_leaves_nothing_behind() {
    let s = Setup::new(true);
    let store = Arc::new(MemoryStore::new());
    let mut app = s
        .join_on("wallet", Arc::clone(&store) as Arc<dyn StateStore>)
        .await;
    let before = snapshot(&app, &store);
    // Never polled.
    drop(app.feed_wait(25).wait());
    // Paused on the way, before the switch saw it.
    s.gate.set(|mode| mode.paused = true);
    let mut wait = Box::pin(app.feed_wait(25).wait());
    assert!(poll_once(&mut wait).is_pending());
    assert_eq!(s.w.switch.held_reads(), 0);
    drop(wait);
    s.gate.set(|mode| mode.paused = false);
    // Held at the switch.
    let mut wait = Box::pin(app.feed_wait(25).wait());
    assert!(poll_once(&mut wait).is_pending());
    assert_eq!(s.w.switch.held_reads(), 1);
    drop(wait);
    assert_eq!(s.w.switch.held_reads(), 0, "the read is held no more");
    assert_eq!(snapshot(&app, &store), before);
    // The app reads on as before.
    let note = s.note(app.app_id());
    let report = app.receive(None).await.unwrap();
    assert_eq!(received(&report.events), vec![note]);
}

#[tokio::test]
async fn test_feed_wait_doesnt_hold_the_app_while_it_writes_and_sends() {
    // A host task waits through a handle while it writes a record and sends a message on
    // the same app: both finish while the read is held, and the record's write, on the
    // feed, wakes the wait.
    let s = Setup::new(true);
    let mut app = s.join("wallet").await;
    let waiting = tokio::spawn(app.feed_wait(25).wait());
    held(&s.w, 1).await;
    let mut body = Map::new();
    body.insert("text".into(), json!("paid"));
    let host = async {
        let (_, delivery) = app
            .send(OutgoingMessage::new(s.w.bob.public(), "sample.note", body))
            .await
            .unwrap();
        assert!(matches!(delivery, crate::app::Delivery::Accepted { .. }));
        app.put_record(&RecordTarget::new(items(), b"n1"), &value(&["a"]), vec![])
            .await
            .unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), host)
        .await
        .expect("the calls finish while the read is held");
    let woken = tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("woken")
        .unwrap();
    assert_eq!(woken, Woken::Ready);
    app.receive(None).await.unwrap();
}

#[test]
fn test_feed_wait_is_send_and_static_and_shows_no_key() {
    fn assert_owned<T: Send + 'static>(_: &T) {}
    let w = World::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let app = runtime.block_on(w.join("wallet"));
    let wait: FeedWait = app.feed_wait(25);
    let shown = format!("{wait:?}");
    assert!(shown.starts_with("FeedWait"), "{shown}");
    assert!(!shown.contains(&pubky_switch_core::enc::b64(
        &app_keys("wallet").signing_public()
    )));
    assert!(!shown.to_lowercase().contains("cert"), "{shown}");
    assert_owned(&wait);
    assert_owned(&wait.wait());
}

// -------------------------------------------------------------------------------------
// Per-call budgets

/// A conversation entry for `pubky`.
fn conversation(pubky: [u8; 32]) -> OpBatch {
    OpBatch::new().op(OpKind::AllowPut {
        pubky,
        kind: AllowKind::Conversation,
    })
}

/// The conversation entries the switch applied, by the identity each names.
fn conversations(w: &World) -> Vec<[u8; 32]> {
    w.switch
        .applied()
        .iter()
        .filter_map(|op| match op.body().kind {
            OpKind::AllowPut { pubky, .. } => Some(pubky),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn test_receive_sends_kept_batches_again_oldest_first_within_its_budget() {
    // Six writes queued while the account was frozen are kept, each sent once and answered
    // `410 moved`. Once the move is called off, a read sends the four oldest and says more
    // are left; the next read sends the rest.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let next = SigningKey::from_bytes(&seed("service/alice/next"));
    let freeze = Freeze::sign(
        &s.w.alice,
        FreezeBody {
            identity: s.w.alice.public(),
            inbox: Inbox::new("https://next.example", next.verifying_key().to_bytes()),
            next_generation: 2,
            issued_at: s.w.clock.now_ms(),
            nonce: [2; 16],
        },
    )
    .unwrap();
    s.w.switch.freeze(&freeze).unwrap();
    let before = conversations(&s.w).len();
    for n in 0..6u8 {
        s.w.clock.advance_ms(1_000);
        let error = app
            .submit_batch(conversation([n + 10; 32]))
            .await
            .unwrap_err();
        assert!(error.kept_batch().is_some(), "{error:?}");
    }
    assert_eq!(app.kept_batches().await.unwrap().len(), 6);
    s.w.switch.unfreeze(&freeze).unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(report.more, "{:?}", report.events);
    let oldest: Vec<[u8; 32]> = (10..14).map(|n| [n; 32]).collect();
    assert_eq!(
        conversations(&s.w)[before..],
        oldest[..KEPT_RESENDS_PER_READ]
    );
    assert_eq!(app.kept_batches().await.unwrap().len(), 2);
    let report = app.receive(None).await.unwrap();
    assert!(!report.more, "{:?}", report.events);
    let all: Vec<[u8; 32]> = (10..16).map(|n| [n; 32]).collect();
    assert_eq!(conversations(&s.w)[before..], all[..]);
    assert!(app.kept_batches().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_receive_lists_within_its_page_budget_and_goes_on_at_the_next_read() {
    // A `missed` item owes a listing; with one record a page, ten records take ten pages.
    // The first read lists four after the item and stops there; the next lists four more
    // before the feed, and hands nothing over either; the third lists the last two and
    // only then takes the entry after the item.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    for n in 0..10 {
        let target = RecordTarget::new(items(), format!("n{n}").as_bytes());
        app.put_record(&target, &value(&["a"]), vec![])
            .await
            .unwrap();
    }
    s.settle(&mut app).await;
    s.w.switch.lock().max_page_bytes = 1;
    s.w.switch.push_missed(1, START, START);
    let note = s.note(app.app_id());
    let pages = || {
        s.router
            .log()
            .iter()
            .filter(|line| line.contains("/records?"))
            .count()
    };
    let before = pages();
    let budget = LISTING_PAGES_PER_READ as usize;
    for read in 1..=2 {
        let report = app.receive(None).await.unwrap();
        assert!(report.more, "read {read}");
        assert_eq!(pages() - before, read * budget, "read {read}");
        assert!(received(&report.events).is_empty(), "{:?}", report.events);
        assert!(app.listing_owed().await.unwrap());
    }
    let report = app.receive(None).await.unwrap();
    assert!(!report.more);
    assert_eq!(pages() - before, 10, "the listing goes on, not again");
    assert!(!app.listing_owed().await.unwrap());
    assert_eq!(received(&report.events), vec![note]);
}

// -------------------------------------------------------------------------------------
// The host's loop

/// What the host's loop of the [`FeedWait`] docs did.
#[derive(Debug, Default)]
struct LoopRun {
    /// The reads and the waits it made, the steps it was given.
    steps: usize,
    /// The reads among them.
    reads: usize,
    /// The requests the app and its handles sent.
    requests: usize,
    /// The pauses [`WaitPace`] gave, in order.
    pauses: Vec<Duration>,
    /// The loop came to a wait the switch holds, and waits there.
    held: bool,
}

/// The host's loop of the [`FeedWait`] docs, for `steps` reads and waits. Its pauses are
/// recorded, not slept, and no time passes: every wait that ends took no time, and one the
/// switch holds ends the run, the loop waiting there.
async fn host_loop(s: &Setup, app: &mut App, steps: usize) -> LoopRun {
    let before = s.router.log().len();
    let mut pace = WaitPace::new();
    let mut run = LoopRun::default();
    'reads: while run.steps < steps {
        run.steps += 1;
        run.reads += 1;
        match app.receive(None).await {
            Ok(report) if report.more => continue,
            Ok(_) => {}
            Err(_) => {
                run.pauses.push(pace.after_failed_read());
                continue;
            }
        }
        while run.steps < steps {
            run.steps += 1;
            let wait = app.feed_wait(MAX_WAIT_SECONDS);
            let asked = wait.seconds();
            let Ok(woken) = tokio::time::timeout(Duration::from_millis(200), wait.wait()).await
            else {
                run.held = true;
                break 'reads;
            };
            if let Some(pause) = pace.after_wait(woken, asked, Duration::ZERO) {
                run.pauses.push(pause);
            }
            if woken != Woken::Quiet {
                break;
            }
        }
    }
    run.requests = s.router.log().len() - before;
    run
}

/// Every round of `run` paused, the pauses doubling to [`MAX_PAUSE_MS`]: the loop doesn't
/// spin, however many rounds it is given.
fn paced(run: &LoopRun, rounds: usize) {
    assert!(!run.held, "{run:?}");
    assert_eq!(run.pauses.len(), rounds, "{run:?}");
    assert_eq!(run.pauses[0], Duration::from_millis(MIN_PAUSE_MS));
    assert_eq!(
        run.pauses.last(),
        Some(&Duration::from_millis(MAX_PAUSE_MS)),
        "{run:?}"
    );
}

fn waits_for_key(report: &crate::app::ReceiveReport) -> bool {
    report
        .events
        .iter()
        .any(|e| matches!(e, AppEvent::ListingWaitsForKey))
}

/// The wallet with no scope key, and a `missed` item it has read past: its listing waits
/// for the key, and every read says so.
async fn listing_waiting_for_a_key(s: &Setup, store: &Arc<MemoryStore>) -> App {
    let mut app = s
        .join_on("wallet", Arc::clone(store) as Arc<dyn StateStore>)
        .await;
    app.state.scope_keys.keys.clear();
    let mut tx = app.tx().unwrap();
    tx.delete_prefix("scope/").unwrap();
    app.commit(tx).await.unwrap();
    s.w.switch.push_missed(3, START, START + 1);
    s.note(app.app_id());
    app.receive(None).await.unwrap();
    assert!(app.listing_owed().await.unwrap());
    let report = app.receive(None).await.unwrap();
    assert!(waits_for_key(&report), "{:?}", report.events);
    app
}

#[tokio::test]
async fn test_feed_wait_loop_waits_on_a_quiet_feed_with_no_pause() {
    let s = Setup::new(true);
    let mut app = s.join("wallet").await;
    let run = host_loop(&s, &mut app, 100).await;
    assert!(run.held, "{run:?}");
    assert!(run.pauses.is_empty(), "{run:?}");
    assert_eq!(run.reads, 1);
}

#[tokio::test]
async fn test_feed_wait_loop_on_a_removed_app_pauses_every_round_and_sends_nothing() {
    let s = Setup::new(true);
    let mut app = s.join("wallet").await;
    let me = app.app_id();
    s.w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from: START,
        });
    });
    assert!(app.receive(None).await.unwrap().stopped);
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadLater);
    let run = host_loop(&s, &mut app, 40).await;
    paced(&run, 20);
    assert_eq!(run.requests, 0, "{:?}", s.router.log());
}

#[tokio::test]
async fn test_feed_wait_loop_on_an_app_that_left_pauses_every_round_and_sends_nothing() {
    let s = Setup::new(true);
    let mut app = s.join("wallet").await;
    assert_eq!(
        app.leave(LeaveMode::TwoStep).await.unwrap(),
        LeaveReport::AwaitingRemoval
    );
    let before = s.router.log().len();
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadLater);
    assert_eq!(s.router.log().len(), before, "no wait is sent");
    // Every read is refused for good, with no request: each pauses.
    let run = host_loop(&s, &mut app, 20).await;
    paced(&run, 20);
    assert_eq!(run.requests, 0, "{:?}", s.router.log());
}

#[tokio::test]
async fn test_feed_wait_loop_awaiting_device_sync_pauses_every_round() {
    let s = Setup::new(true);
    let mut app = s.join("wallet").await;
    app.set_multi_device(true).await.unwrap();
    let foreign = ReceiveKey::from_secret(1, [44; 32]);
    let record = ReceiveKeyRecord::sign(
        &app_keys("wallet"),
        app.cert(),
        ReceiveKeyBody::new(app.cert(), &foreign),
    )
    .unwrap();
    s.w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::ReceiveKeyPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    assert!(app.receive(None).await.unwrap().stopped);
    let cursor = app.cursor();
    let waits = s.gate.waits().len();
    let run = host_loop(&s, &mut app, 40).await;
    paced(&run, 20);
    // No wait is sent, and each read stops where the last did.
    assert_eq!(s.gate.waits().len(), waits);
    assert_eq!(app.cursor(), cursor);
    assert!(run.requests <= 2 * run.reads, "{run:?}");
}

#[tokio::test]
async fn test_feed_wait_loop_with_a_listing_waiting_for_a_key_pauses_after_an_entry() {
    let s = Setup::new(true);
    let store = Arc::new(MemoryStore::new());
    let mut app = listing_waiting_for_a_key(&s, &store).await;
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadLater);
    // A new entry doesn't make the loop read again and again: no wait can show the key.
    s.note(app.app_id());
    let waits = s.gate.waits().len();
    let run = host_loop(&s, &mut app, 40).await;
    paced(&run, 20);
    assert_eq!(s.gate.waits().len(), waits);
    assert!(run.requests <= 2 * run.reads, "{run:?}");
}

#[tokio::test]
async fn test_feed_wait_loop_with_a_listing_waiting_for_a_key_pauses_after_a_restart() {
    let s = Setup::new(true);
    let store = Arc::new(MemoryStore::new());
    let app = listing_waiting_for_a_key(&s, &store).await;
    let id = app.app_id();
    drop(app);
    let env =
        s.w.signer
            .env_with(store, Arc::clone(&s.router) as Arc<dyn Transport>);
    let mut app = App::load(env, s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    let waits = s.gate.waits().len();
    let run = host_loop(&s, &mut app, 40).await;
    paced(&run, 20);
    assert_eq!(s.gate.waits().len(), waits);
    assert!(run.requests <= 2 * run.reads, "{run:?}");
}

#[tokio::test]
async fn test_feed_wait_loop_pauses_when_the_switch_ends_every_wait_at_once() {
    // A switch, or a proxy before it, that answers a wait at once with an empty page, and
    // one that refuses every wait: each wait ends sooner than it asked, and pauses.
    for refuse in [false, true] {
        let s = Setup::new(false);
        let mut app = s.join("wallet").await;
        s.gate.set(|mode| mode.refuse_waits = refuse);
        let waits = s.gate.waits().len();
        let run = host_loop(&s, &mut app, 40).await;
        let sent = s.gate.waits().len() - waits;
        assert_eq!(run.pauses.len(), sent, "{run:?}");
        assert!(run.pauses.len() >= 20, "{run:?}");
        assert_eq!(
            run.pauses.last(),
            Some(&Duration::from_millis(MAX_PAUSE_MS)),
            "{run:?}"
        );
    }
}

#[tokio::test]
async fn test_feed_wait_reads_a_quiet_feed_once_the_upkeep_interval_has_passed() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    s.settle(&mut app).await;
    // A wait that ends before the interval is quiet; one that ends at it is a read.
    s.w.clock.advance_ms(UPKEEP_READ_MS - 25_000 - 1);
    assert_eq!(app.feed_wait(25).wait().await, Woken::Quiet);
    s.w.clock.advance_ms(1);
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadNow);
    app.receive(None).await.unwrap();
    assert_eq!(app.feed_wait(25).wait().await, Woken::Quiet);
    // An app loaded and not read since: a quiet wait is a read.
    let store = Arc::new(MemoryStore::new());
    let app = s
        .join_on("phone", Arc::clone(&store) as Arc<dyn StateStore>)
        .await;
    let id = app.app_id();
    drop(app);
    let env =
        s.w.signer
            .env_with(store, Arc::clone(&s.router) as Arc<dyn Transport>);
    let app = App::load(env, s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadNow);
}

#[tokio::test]
async fn test_feed_wait_asks_a_second_once_a_deferred_move_is_due() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let phone = s.join("phone").await;
    s.settle(&mut app).await;
    s.notice(&phone, app.app_id());
    app.receive(None).await.unwrap();
    assert!(app.state.cursor.deferred_since_ms.is_some());
    // Due, and not sent yet: the wait is one second, and a read.
    s.w.clock.advance_ms(5_000);
    let wait = app.feed_wait(25);
    assert_eq!(wait.seconds(), 1);
    assert_eq!(wait.wait().await, Woken::ReadNow);
    assert_eq!(s.gate.last("wait"), "1");
}

#[tokio::test]
async fn test_feed_wait_cut_to_exactly_its_seconds_is_a_read() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let phone = s.join("phone").await;
    s.settle(&mut app).await;
    s.notice(&phone, app.app_id());
    app.receive(None).await.unwrap();
    assert!(app.state.cursor.deferred_since_ms.is_some());
    // The move falls due in 2 s, the wait asked for: the wait ends with it.
    let wait = app.feed_wait(2);
    assert_eq!(wait.seconds(), 2);
    assert_eq!(wait.wait().await, Woken::ReadNow);
    let wait = app.feed_wait(3);
    assert_eq!(wait.seconds(), 2);
    assert_eq!(wait.wait().await, Woken::ReadNow);
}

#[tokio::test]
async fn test_feed_wait_never_goes_from_before_the_cursor() {
    // A read records a position at or past the cursor. Should the cursor be past it all
    // the same, the wait goes from the cursor, never from behind it.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let cursor = app.cursor();
    assert!(cursor.seq > 0);
    let behind = Position {
        seq: cursor.seq - 1,
        ..cursor
    };
    app.next_wait = crate::app::wait::NextWait::From(crate::app::wait::WaitFrom {
        position: behind,
        again: false,
    });
    assert_eq!(app.feed_wait(25).wait().await, Woken::Quiet);
    assert_eq!(s.gate.last("after"), cursor.to_string());
}

#[tokio::test]
async fn test_feed_wait_on_a_frozen_account_is_read_now() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    s.settle(&mut app).await;
    let next = SigningKey::from_bytes(&seed("service/alice/next"));
    let freeze = Freeze::sign(
        &s.w.alice,
        FreezeBody {
            identity: s.w.alice.public(),
            inbox: Inbox::new("https://next.example", next.verifying_key().to_bytes()),
            next_generation: 2,
            issued_at: s.w.clock.now_ms(),
            nonce: [2; 16],
        },
    )
    .unwrap();
    s.w.switch.freeze(&freeze).unwrap();
    let sent = s.gate.waits().len();
    assert_eq!(app.feed_wait(25).wait().await, Woken::ReadNow);
    assert_eq!(s.gate.waits().len(), sent + 1, "the wait was sent");
}

#[tokio::test]
async fn test_feed_wait_on_a_page_of_items_not_shown_with_more_is_ready() {
    // The switch scans one item a page, here an entry for another app of the account: the
    // page shows nothing and says there is more, which only a read can follow.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let phone = s.join("phone").await;
    s.settle(&mut app).await;
    s.note(phone.app_id());
    s.note(app.app_id());
    s.w.switch.lock().max_page_scan = Some(1);
    assert_eq!(app.feed_wait(25).wait().await, Woken::Ready);
    s.w.switch.lock().max_page_scan = None;
    let report = app.receive(None).await.unwrap();
    assert_eq!(received(&report.events).len(), 1, "{:?}", report.events);
}

// -------------------------------------------------------------------------------------
// The read's budgets, at their edges and across a restart

/// The switch applies a write, and its answer is lost to a timeout.
struct LostAnswers {
    inner: Arc<dyn Transport>,
    on: std::sync::atomic::AtomicBool,
}

impl Transport for LostAnswers {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(async move {
            let lose = self.on.load(std::sync::atomic::Ordering::SeqCst)
                && request.method == "POST"
                && request.path_and_query.ends_with("/ops");
            let answer = self.inner.send(request).await;
            if lose {
                return Err(TransportError::Timeout);
            }
            answer
        })
    }
}

impl Setup {
    /// Lose the answer of every batch the switch applies, until `found` is called.
    fn lose_answers(&self) -> Arc<LostAnswers> {
        let lost = Arc::new(LostAnswers {
            inner: Arc::clone(&self.gate) as Arc<dyn Transport>,
            on: std::sync::atomic::AtomicBool::new(true),
        });
        self.router
            .add(ORIGIN, Arc::clone(&lost) as Arc<dyn Transport>);
        lost
    }
}

impl LostAnswers {
    fn found(&self) {
        self.on.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn test_receive_settles_a_write_whose_answer_timed_out_as_applied_once() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let lost = s.lose_answers();
    let target = RecordTarget::new(items(), b"n1");
    let puts = || {
        s.w.switch
            .applied()
            .iter()
            .filter(|op| matches!(op.body().kind, OpKind::RecordPut(_)))
            .count()
    };
    let error = app
        .put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap_err();
    assert!(
        matches!(error.unkept(), AppError::Transport(TransportError::Timeout)),
        "{error:?}"
    );
    let id = error.kept_batch().expect("kept");
    assert_eq!(puts(), 1, "applied at the switch");
    lost.found();
    app.receive(None).await.unwrap();
    assert!(matches!(
        app.kept_batch(id).await.unwrap(),
        Some(crate::app::KeptBatchStatus::Applied { .. })
    ));
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(puts(), 1, "applied once");
    let key = app.record_key(&target).unwrap();
    let held = app.shared_record(&key).await.unwrap().expect("cached");
    assert_eq!(super::shared_flows::ids(held.content.value()), vec!["a"]);
}

#[tokio::test]
async fn test_receive_goes_on_with_a_listing_across_a_restart() {
    let s = Setup::new(false);
    let store = Arc::new(MemoryStore::new());
    let mut app = s
        .join_on("wallet", Arc::clone(&store) as Arc<dyn StateStore>)
        .await;
    let id = app.app_id();
    for n in 0..10 {
        let target = RecordTarget::new(items(), format!("n{n}").as_bytes());
        app.put_record(&target, &value(&["a"]), vec![])
            .await
            .unwrap();
    }
    s.settle(&mut app).await;
    s.w.switch.lock().max_page_bytes = 1;
    s.w.switch.push_missed(1, START, START);
    let note = s.note(app.app_id());
    let pages = || {
        s.router
            .log()
            .iter()
            .filter(|line| line.contains("/records?"))
            .count()
    };
    let before = pages();
    assert!(app.receive(None).await.unwrap().more);
    assert_eq!(pages() - before, 4);
    drop(app);
    let env =
        s.w.signer
            .env_with(store, Arc::clone(&s.router) as Arc<dyn Transport>);
    let mut app = App::load(env, s.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    assert!(app.receive(None).await.unwrap().more);
    let report = app.receive(None).await.unwrap();
    assert!(!report.more);
    assert_eq!(pages() - before, 10, "the listing goes on, not again");
    assert_eq!(received(&report.events), vec![note]);
}

#[tokio::test]
async fn test_receive_says_more_only_past_the_kept_batch_budget() {
    for (writes, more) in [
        (KEPT_RESENDS_PER_READ, false),
        (KEPT_RESENDS_PER_READ + 1, true),
    ] {
        let s = Setup::new(false);
        let mut app = s.join("wallet").await;
        let next = SigningKey::from_bytes(&seed("service/alice/next"));
        let freeze = Freeze::sign(
            &s.w.alice,
            FreezeBody {
                identity: s.w.alice.public(),
                inbox: Inbox::new("https://next.example", next.verifying_key().to_bytes()),
                next_generation: 2,
                issued_at: s.w.clock.now_ms(),
                nonce: [2; 16],
            },
        )
        .unwrap();
        s.w.switch.freeze(&freeze).unwrap();
        for n in 0..writes {
            s.w.clock.advance_ms(1_000);
            let pubky = [u8::try_from(n).unwrap() + 10; 32];
            let error = app.submit_batch(conversation(pubky)).await.unwrap_err();
            assert!(error.kept_batch().is_some(), "{error:?}");
        }
        s.w.switch.unfreeze(&freeze).unwrap();
        let report = app.receive(None).await.unwrap();
        assert_eq!(report.more, more, "{writes} kept");
    }
}

#[tokio::test]
async fn test_receive_with_kept_batches_whose_answers_are_lost_says_no_more() {
    // The read reports the batches waiting and no `more`, so the host doesn't read again at
    // once.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let _lost = s.lose_answers();
    for n in 0..6u8 {
        s.w.clock.advance_ms(1_000);
        let error = app
            .submit_batch(conversation([n + 10; 32]))
            .await
            .unwrap_err();
        // The first is kept; each later write first sends the kept ones, times out, and
        // keeps nothing of its own.
        assert!(
            matches!(error.unkept(), AppError::Transport(TransportError::Timeout)),
            "{error:?}"
        );
    }
    let report = app.receive(None).await.unwrap();
    assert!(!report.more);
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::KeptBatchesWaiting { .. })),
        "{:?}",
        report.events
    );
}

// -------------------------------------------------------------------------------------
// Bounded calls: a write's kept batches, and a read's time budget

/// The switch's transport, each request of which takes `ms` of the app's clock, as a switch
/// that answers each request just inside its timeout.
struct Slow {
    inner: Arc<dyn Transport>,
    clock: Arc<crate::clock::TestClock>,
    ms: std::sync::atomic::AtomicU64,
}

impl Transport for Slow {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(async move {
            let answer = self.inner.send(request).await;
            self.clock
                .advance_ms(self.ms.load(std::sync::atomic::Ordering::SeqCst));
            answer
        })
    }
}

impl Setup {
    /// From now on each request to alice's switch takes `ms` of the app's clock.
    fn slow(&self, ms: u64) -> Arc<Slow> {
        let slow = Arc::new(Slow {
            inner: Arc::clone(&self.gate) as Arc<dyn Transport>,
            clock: Arc::clone(&self.w.clock),
            ms: std::sync::atomic::AtomicU64::new(ms),
        });
        self.router
            .add(ORIGIN, Arc::clone(&slow) as Arc<dyn Transport>);
        slow
    }

    /// The requests sent to alice's switch since `from`, the router's log length then.
    fn sent_since(&self, from: usize) -> Vec<String> {
        self.router.log()[from..]
            .iter()
            .filter(|line| line.contains(ORIGIN))
            .cloned()
            .collect()
    }

    /// Freeze alice's account, so every write is kept and answered `410 moved`.
    fn freeze(&self) -> Freeze {
        let next = SigningKey::from_bytes(&seed("service/alice/next"));
        let freeze = Freeze::sign(
            &self.w.alice,
            FreezeBody {
                identity: self.w.alice.public(),
                inbox: Inbox::new("https://next.example", next.verifying_key().to_bytes()),
                next_generation: 2,
                issued_at: self.w.clock.now_ms(),
                nonce: [2; 16],
            },
        )
        .unwrap();
        self.w.switch.freeze(&freeze).unwrap();
        freeze
    }
}

#[tokio::test]
async fn test_write_sends_one_kept_batch_again_and_keeps_its_own_behind_the_rest() {
    // Three writes kept while the account was frozen: the first sent and refused, the two
    // after it kept unsent behind it. The next write sends the oldest again, and, two still
    // kept, keeps its own behind them and says which one is ahead; reads then send them all,
    // in the order they were kept.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let freeze = s.freeze();
    for n in 0..3u8 {
        s.w.clock.advance_ms(1_000);
        let error = app
            .submit_batch(conversation([n + 10; 32]))
            .await
            .unwrap_err();
        assert!(error.kept_batch().is_some(), "{error:?}");
    }
    s.w.switch.unfreeze(&freeze).unwrap();
    let before = conversations(&s.w).len();
    let error = app.submit_batch(conversation([13; 32])).await.unwrap_err();
    let own = error.kept_batch().expect("its own batch kept");
    let AppError::Refused(crate::app::Refusal::KeptBatchesAhead(ahead)) = error.unkept() else {
        panic!("{error:?}");
    };
    assert_eq!(ahead.kept, 2, "the two still kept from before");
    assert!(
        ahead.kept_since_ms.is_none() && ahead.answer_until_ms.is_none(),
        "never sent, so no window: {ahead:?}"
    );
    assert_eq!(
        conversations(&s.w)[before..],
        [[10; 32]],
        "one sent again first"
    );
    assert!(app.kept_batch(own).await.unwrap().is_some());
    app.receive(None).await.unwrap();
    let all: Vec<[u8; 32]> = (10..14).map(|n| [n; 32]).collect();
    assert_eq!(conversations(&s.w)[before..], all[..], "in the order kept");
    assert!(app.kept_batches().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_write_behind_a_failing_kept_batch_names_it() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let lost = s.lose_answers();
    s.w.clock.advance_ms(1_000);
    let first = app
        .submit_batch(conversation([10; 32]))
        .await
        .unwrap_err()
        .kept_batch()
        .expect("kept");
    s.w.clock.advance_ms(1_000);
    let error = app.submit_batch(conversation([11; 32])).await.unwrap_err();
    let AppError::Ahead { ahead, .. } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(ahead.batch_id, first);
    assert_eq!(ahead.kept, 1);
    let since = ahead.kept_since_ms.expect("sent before");
    assert_eq!(
        ahead.answer_until_ms,
        Some(since + crate::app::KEPT_BATCH_ANSWER_MS)
    );
    assert!(
        matches!(error.unkept(), AppError::Transport(TransportError::Timeout)),
        "{error:?}"
    );
    assert_eq!(error.kept_batch(), None, "nothing of this write is kept");
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
    lost.found();
}

#[tokio::test]
async fn test_write_on_a_slow_switch_sends_at_most_three_requests() {
    // Each request takes just under the short timeout: a write with one batch kept ahead
    // sends it again, takes its time sample and sends its own, and so ends within about
    // 30 s at the default timeouts.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let freeze = s.freeze();
    s.w.clock.advance_ms(1_000);
    app.submit_batch(conversation([10; 32])).await.unwrap_err();
    s.w.switch.unfreeze(&freeze).unwrap();
    s.slow(9_900);
    let from = s.router.log().len();
    let started = s.w.clock.now_ms();
    app.submit_batch(conversation([11; 32])).await.unwrap();
    let sent = s.sent_since(from);
    assert!(sent.len() <= 3, "{sent:?}");
    assert!(s.w.clock.now_ms() - started <= 30_000);
}

#[tokio::test]
async fn test_receive_on_a_slow_switch_stops_on_its_time_budget_and_goes_on() {
    // A feed of many pages, each request taking 9 s of the app's clock: a read stops once its
    // 20 s are spent, says more, and the next read goes on from where it got, not from the
    // cursor; across a restart too. Every entry is handed over once.
    let s = Setup::new(false);
    let store = Arc::new(MemoryStore::new());
    let mut app = s
        .join_on("wallet", Arc::clone(&store) as Arc<dyn StateStore>)
        .await;
    let id = app.app_id();
    let notes: Vec<u64> = (0..12).map(|_| s.note(app.app_id())).collect();
    app.config.page_size = 1;
    s.slow(9_000);
    let mut handed = Vec::new();
    let started = s.w.clock.now_ms();
    let report = app.receive(None).await.unwrap();
    assert!(report.more, "{:?}", report.events);
    handed.extend(received(&report.events));
    assert!(
        s.w.clock.now_ms() - started <= crate::app::DEFAULT_CALL_BUDGET_MS + 3 * 9_000,
        "within the budget and the read's last requests"
    );
    assert!(
        !handed.is_empty() && handed.len() < notes.len(),
        "{handed:?}"
    );
    drop(app);
    let env =
        s.w.signer
            .env_with(store, Arc::clone(&s.router) as Arc<dyn Transport>);
    let mut config = World::config();
    config.page_size = 1;
    let mut app = App::load(env, s.protocol.clone(), config, id)
        .await
        .unwrap();
    for _ in 0..20 {
        let from = s.router.log().len();
        let report = app.receive(None).await.unwrap();
        handed.extend(received(&report.events));
        // Each read goes on past what the one before handed over.
        let after = s.sent_since(from);
        assert!(after.len() <= 8, "{after:?}");
        if !report.more {
            break;
        }
    }
    assert_eq!(handed, notes, "each once, in order");
}

#[tokio::test]
async fn test_receive_reads_at_most_its_page_budget() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let notes: Vec<u64> = (0..6).map(|_| s.note(app.app_id())).collect();
    app.config.page_size = 1;
    let from = s.router.log().len();
    let report = app.receive(None).await.unwrap();
    assert!(report.more);
    let pages = s
        .sent_since(from)
        .iter()
        .filter(|line| line.contains("/feed?"))
        .count();
    assert_eq!(pages, crate::app::FEED_PAGES_PER_READ as usize);
    let mut handed = received(&report.events);
    for _ in 0..4 {
        let report = app.receive(None).await.unwrap();
        handed.extend(received(&report.events));
        if !report.more {
            break;
        }
    }
    assert_eq!(handed, notes);
}

#[tokio::test]
async fn test_update_record_takes_one_time_sample_for_all_its_tries() {
    // The phone writes the record after the wallet's last read: the wallet's first try is
    // refused `409 conflict`, the next builds on the phone's write, and the call takes its
    // service time once.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = RecordTarget::new(items(), b"n1");
    app.put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    s.settle(&mut app).await;
    phone.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["p"]), vec![])
        .await
        .unwrap();
    let samples = |from: usize| {
        s.sent_since(from)
            .iter()
            .filter(|line| {
                line.contains("/feed?") && line.contains("limit=1") && !line.contains("wait=")
            })
            .count()
    };
    let puts = |from: usize| {
        s.sent_since(from)
            .iter()
            .filter(|line| line.contains("/ops"))
            .count()
    };
    let from = s.router.log().len();
    let updated = app
        .update_record(&target, vec![], |_| Some(value(&["w"])))
        .await
        .unwrap();
    assert!(updated.is_some());
    assert!(
        puts(from) >= 2,
        "a conflict, then the write: {:?}",
        s.sent_since(from)
    );
    assert_eq!(samples(from), 1, "{:?}", s.sent_since(from));
}

// -------------------------------------------------------------------------------------
// Bounded calls: the order of batches kept behind others, a read that goes on past a held
// entry, and calls whose time is spent

impl Setup {
    /// Freeze alice's account again, under a freeze of its own `nonce`.
    fn freeze_again(&self, nonce: u8) -> Freeze {
        let next = SigningKey::from_bytes(&seed("service/alice/next"));
        let freeze = Freeze::sign(
            &self.w.alice,
            FreezeBody {
                identity: self.w.alice.public(),
                inbox: Inbox::new("https://next.example", next.verifying_key().to_bytes()),
                next_generation: 2,
                issued_at: self.w.clock.now_ms(),
                nonce: [nonce; 16],
            },
        )
        .unwrap();
        self.w.switch.freeze(&freeze).unwrap();
        freeze
    }
}

fn kept_behind(error: &AppError) -> bool {
    matches!(
        error.unkept(),
        AppError::Refused(crate::app::Refusal::KeptBatchesAhead(_))
    )
}

#[tokio::test]
async fn test_kept_batches_behind_others_go_out_in_creation_order() {
    // Three writes kept while the account was frozen. Each later write sends the oldest
    // again and keeps its own behind the rest, never sent: the batches never sent go in
    // the order they were kept, whatever their random IDs.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let before = conversations(&s.w).len();
    let freeze = s.freeze();
    for n in 10..13u8 {
        s.w.clock.advance_ms(1_000);
        app.submit_batch(conversation([n; 32])).await.unwrap_err();
    }
    s.w.switch.unfreeze(&freeze).unwrap();
    for n in 20..26u8 {
        s.w.clock.advance_ms(1_000);
        let error = app.submit_batch(conversation([n; 32])).await.unwrap_err();
        assert!(kept_behind(&error), "{error:?}");
    }
    let unsent = app
        .kept_batches()
        .await
        .unwrap()
        .iter()
        .filter(|(_, pending)| pending.kept_ms.is_none())
        .count();
    assert_eq!(unsent, 3, "the last three writes are kept, never sent");
    for _ in 0..8 {
        if !app.receive(None).await.unwrap().more {
            break;
        }
    }
    let order: Vec<[u8; 32]> = [10u8, 11, 12, 20, 21, 22, 23, 24, 25]
        .iter()
        .map(|n| [*n; 32])
        .collect();
    assert_eq!(conversations(&s.w)[before..], order[..]);
    assert!(app.kept_batches().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_write_during_a_freeze_goes_after_a_batch_kept_behind() {
    // A write kept behind an earlier one, never sent; then the account is frozen again,
    // and a later write's resend of the earlier one is answered `410 moved`, the write kept
    // too. Once the freeze is called off, every batch goes in the order the calls kept
    // them.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let before = conversations(&s.w).len();
    let freeze = s.freeze();
    for n in 10..12u8 {
        s.w.clock.advance_ms(1_000);
        app.submit_batch(conversation([n; 32])).await.unwrap_err();
    }
    s.w.switch.unfreeze(&freeze).unwrap();
    s.w.clock.advance_ms(1_000);
    let error = app.submit_batch(conversation([12; 32])).await.unwrap_err();
    assert!(kept_behind(&error), "{error:?}");
    let again = s.freeze_again(3);
    s.w.clock.advance_ms(1_000);
    let error = app.submit_batch(conversation([13; 32])).await.unwrap_err();
    assert!(error.kept_batch().is_some(), "{error:?}");
    s.w.switch.unfreeze(&again).unwrap();
    for _ in 0..4 {
        if !app.receive(None).await.unwrap().more {
            break;
        }
    }
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(
        conversations(&s.w)[before..],
        [[10; 32], [11; 32], [12; 32], [13; 32]],
        "in the order the calls kept them"
    );
}

#[tokio::test]
async fn test_receive_stopped_on_its_budget_goes_on_past_a_held_entry() {
    // An entry whose sender can't be checked is held, the cursor before it, and the read
    // stops on its page budget past it. The next read goes on from where it got, so the
    // held entry takes none of its budget; the read after the end starts at the cursor
    // again, and takes the held entry once its sender can be checked. Each once, in order.
    let s = Setup::new(false);
    let store = Arc::new(MemoryStore::new());
    let mut app = s
        .join_on("wallet", Arc::clone(&store) as Arc<dyn StateStore>)
        .await;
    let id = app.app_id();
    let phone = s.join("phone").await;
    s.settle(&mut app).await;
    s.w.homeserver.set_down(true);
    let held = s.note(app.app_id());
    let notices: Vec<u64> = (0..6).map(|_| s.notice(&phone, app.app_id())).collect();
    app.config.page_size = 1;
    let first = app.receive(None).await.unwrap();
    assert!(first.more, "{:?}", first.events);
    assert!(
        first
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::Held { seq } if *seq == held)),
        "{:?}",
        first.events
    );
    assert!(app.cursor().seq < held);
    let mut handed = received(&first.events);
    assert_eq!(handed, notices[..3], "{:?}", first.events);
    // Across a restart too.
    drop(app);
    let env =
        s.w.signer
            .env_with(store, Arc::clone(&s.router) as Arc<dyn Transport>);
    let mut config = World::config();
    config.page_size = 1;
    let mut app = App::load(env, s.protocol.clone(), config, id)
        .await
        .unwrap();
    let from = s.router.log().len();
    let second = app.receive(None).await.unwrap();
    assert!(
        !second
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::Held { .. })),
        "{:?}",
        second.events
    );
    assert!(
        s.sent_since(from)
            .iter()
            .any(|line| line.contains(&format!("after=1%3A{}", notices[2]))
                || line.contains(&format!("after=1:{}", notices[2]))),
        "{:?}",
        s.sent_since(from)
    );
    handed.extend(received(&second.events));
    assert_eq!(handed, notices, "{:?}", second.events);
    assert!(!second.more, "{:?}", second.events);
    assert!(app.cursor().seq < held);
    s.w.homeserver.set_down(false);
    let mut later = Vec::new();
    for _ in 0..4 {
        let report = app.receive(None).await.unwrap();
        later.extend(received(&report.events));
        if !report.more {
            break;
        }
    }
    assert_eq!(later, vec![held]);
    assert!(app.cursor().seq >= notices[5]);
}

#[tokio::test]
async fn test_receive_with_its_time_spent_stops_only_between_batches() {
    // With no time left, a read processes one item and stops at the next batch boundary:
    // never inside a batch's items. The next reads go on from there.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    s.settle(&mut app).await;
    let contact = |n: u8| OpKind::AllowPut {
        pubky: [n; 32],
        kind: AllowKind::Contact,
    };
    phone
        .submit_batch(
            OpBatch::new()
                .op(contact(41))
                .op(contact(42))
                .op(contact(43)),
        )
        .await
        .unwrap();
    let end_of_batch = s.w.switch.seq();
    phone
        .submit_batch(OpBatch::new().op(contact(44)))
        .await
        .unwrap();
    let last = s.w.switch.seq();
    assert!(last > end_of_batch);
    app.config.call_budget_ms = 0;
    let report = app.receive(None).await.unwrap();
    assert!(report.more, "{:?}", report.events);
    assert_eq!(app.cursor().seq, end_of_batch, "at the batch's end");
    for _ in 0..4 {
        if !app.receive(None).await.unwrap().more {
            break;
        }
    }
    assert!(app.alarm().is_none(), "{:?}", app.alarm());
    assert_eq!(app.cursor().seq, last);
}

#[tokio::test]
async fn test_receive_with_its_time_spent_sends_one_kept_batch_again() {
    // With no time left, a read sends the oldest kept batch again and leaves the rest for
    // the next read, saying so.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let before = conversations(&s.w).len();
    let freeze = s.freeze();
    for n in 10..13u8 {
        s.w.clock.advance_ms(1_000);
        app.submit_batch(conversation([n; 32])).await.unwrap_err();
    }
    s.w.switch.unfreeze(&freeze).unwrap();
    app.config.call_budget_ms = 0;
    let report = app.receive(None).await.unwrap();
    assert!(report.more, "{:?}", report.events);
    assert_eq!(conversations(&s.w)[before..], [[10; 32]]);
    assert_eq!(app.kept_batches().await.unwrap().len(), 2);
}

#[tokio::test]
async fn test_update_record_with_its_time_spent_tries_once() {
    // The phone writes the record after the wallet's last read: with no time left, the
    // wallet's update makes its one try and returns the `409 conflict` it met.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let mut phone = s.join("phone").await;
    let target = RecordTarget::new(items(), b"n1");
    app.put_record(&target, &value(&["a"]), vec![])
        .await
        .unwrap();
    s.settle(&mut app).await;
    phone.receive(None).await.unwrap();
    phone
        .put_record(&target, &value(&["p"]), vec![])
        .await
        .unwrap();
    app.config.call_budget_ms = 0;
    let from = s.router.log().len();
    let error = app
        .update_record(&target, vec![], |_| Some(value(&["w"])))
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        Some(pubky_switch_core::http::ErrorCode::Conflict),
        "{error:?}"
    );
    let puts = s
        .sent_since(from)
        .iter()
        .filter(|line| line.contains("/ops"))
        .count();
    assert_eq!(puts, 1, "{:?}", s.sent_since(from));
}

#[tokio::test]
async fn test_receive_with_its_time_spent_still_retries_every_stored_entry() {
    // Thirty-two entries stored because their senders couldn't be checked: bob's stay so,
    // carol's fifth can be checked now. With no time left each read retries one stored
    // entry; every one of them still comes up within a bound of reads, carol's included.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let carol = PeerSwitch::new(
        identity("carol"),
        "https://carol.example",
        Arc::clone(&s.w.clock),
        Arc::clone(&s.w.homeserver),
    );
    let carol_shop = carol
        .add_app("shop", &AppSpec::new(&["scope-a"]), &["sample.note"], false)
        .unwrap();
    s.w.homeserver.set_down(true);
    let mut carols = 0;
    for n in 0..32 {
        if n == 4 {
            carol
                .send_to(
                    &s.w.switch,
                    carol_shop,
                    "sample.note",
                    json!({ "text": "from carol" }),
                    &[app.app_id()],
                )
                .unwrap();
            carols += 1;
        } else {
            s.note(app.app_id());
        }
    }
    assert_eq!(carols, 1);
    app.receive(None).await.unwrap();
    s.w.clock.advance_ms(app.config.park_after_ms + 1);
    let report = app.receive(None).await.unwrap();
    let parked = report
        .events
        .iter()
        .filter(|e| matches!(e, AppEvent::Parked { .. }))
        .count();
    assert_eq!(parked, 32, "{:?}", report.events);
    // Bob's identity.json is gone; carol's reads.
    s.w.homeserver.remove(
        identity("bob").public(),
        pubky_switch_core::records::IDENTITY_PATH,
    );
    s.w.homeserver.set_down(false);
    app.config.call_budget_ms = 0;
    let mut unparked = 0;
    for _ in 0..64 {
        let report = app.receive(None).await.unwrap();
        unparked += report
            .events
            .iter()
            .filter(|e| matches!(e, AppEvent::Unparked { .. }))
            .count();
        if unparked > 0 {
            break;
        }
    }
    assert_eq!(unparked, 1, "carol's entry is retried at last");
}

/// The switch's transport, which calls a freeze off once the first batch sent through it is
/// answered, as a signer that calls a move off while a write is under way.
struct CallsOff {
    inner: Arc<dyn Transport>,
    switch: Arc<crate::testing::ScriptedSwitch>,
    freeze: Mutex<Option<Freeze>>,
}

impl Transport for CallsOff {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(async move {
            let batch = request.method == "POST" && request.path_and_query.ends_with("/ops");
            let answer = self.inner.send(request).await;
            if batch && let Some(freeze) = self.freeze.lock().unwrap().take() {
                self.switch.unfreeze(&freeze).unwrap();
            }
            answer
        })
    }
}

#[tokio::test]
async fn test_write_during_a_freeze_called_off_goes_after_the_kept_batch() {
    // A write kept during a freeze; the next write's resend of it is answered `410 moved`,
    // and the freeze is called off right after. The write keeps its own batch unsent behind
    // the kept one and reports the `410 moved`: sent at once it would be applied first.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let before = conversations(&s.w).len();
    let freeze = s.freeze();
    s.w.clock.advance_ms(1_000);
    app.submit_batch(conversation([10; 32])).await.unwrap_err();
    s.router.add(
        ORIGIN,
        Arc::new(CallsOff {
            inner: Arc::clone(&s.gate) as Arc<dyn Transport>,
            switch: Arc::clone(&s.w.switch),
            freeze: Mutex::new(Some(freeze)),
        }) as Arc<dyn Transport>,
    );
    let from = s.router.log().len();
    s.w.clock.advance_ms(1_000);
    let error = app.submit_batch(conversation([11; 32])).await.unwrap_err();
    let own = error.kept_batch().expect("its own batch kept");
    assert_eq!(
        error.code(),
        Some(pubky_switch_core::http::ErrorCode::Moved),
        "{error:?}"
    );
    let batches = s
        .sent_since(from)
        .iter()
        .filter(|line| line.contains("/ops"))
        .count();
    assert_eq!(batches, 1, "only the kept batch: {:?}", s.sent_since(from));
    let kept = app.kept_batches().await.unwrap();
    assert!(
        kept.iter()
            .any(|(id, pending)| *id == own && pending.kept_ms.is_none()),
        "kept unsent"
    );
    assert!(conversations(&s.w)[before..].is_empty());
    for _ in 0..4 {
        if !app.receive(None).await.unwrap().more {
            break;
        }
    }
    assert!(app.kept_batches().await.unwrap().is_empty());
    assert_eq!(conversations(&s.w)[before..], [[10; 32], [11; 32]]);
}

#[tokio::test]
async fn test_outbox_keeps_one_conversation_entry_behind_kept_batches() {
    // Two batches kept while the account is frozen. A message to a new peer keeps its
    // conversation entry behind them; flushing the outbox again keeps no second copy, and
    // once the freeze is called off every batch goes, the entry once.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let freeze = s.freeze();
    for n in 10..12u8 {
        s.w.clock.advance_ms(1_000);
        app.submit_batch(conversation([n; 32])).await.unwrap_err();
    }
    let peer = identity("carol").public();
    let mut body = Map::new();
    body.insert("text".into(), json!("hello"));
    app.queue(OutgoingMessage::new(peer, "sample.note", body))
        .await
        .unwrap();
    let entry = OpKind::AllowPut {
        pubky: peer,
        kind: AllowKind::Conversation,
    };
    let kept_entries = |kept: &[([u8; 16], crate::app::batch::PendingBatch)]| {
        kept.iter()
            .filter(|(_, pending)| {
                crate::client::Batch::from_body(pending.body.clone())
                    .unwrap()
                    .ops()
                    .iter()
                    .any(|op| op.body().kind == entry)
            })
            .count()
    };
    for _ in 0..3 {
        s.w.clock.advance_ms(1_000);
        app.flush_outbox().await.unwrap();
    }
    let kept = app.kept_batches().await.unwrap();
    assert_eq!(kept_entries(&kept), 1, "one copy kept");
    assert_eq!(kept.len(), 3);
    s.w.switch.unfreeze(&freeze).unwrap();
    for _ in 0..4 {
        if !app.receive(None).await.unwrap().more {
            break;
        }
    }
    assert!(app.kept_batches().await.unwrap().is_empty());
    let applied = conversations(&s.w);
    assert_eq!(applied.iter().filter(|pubky| **pubky == peer).count(), 1);
}

// -------------------------------------------------------------------------------------
// Bounded calls: the outbox and a peek

/// A note from alice's app to bob.
fn note_to_bob(s: &Setup, text: &str) -> OutgoingMessage {
    let mut body = Map::new();
    body.insert("text".into(), json!(text));
    OutgoingMessage::new(s.w.bob.public(), "sample.note", body)
}

/// How many times each of `ids`, all queued, was tried, in order.
async fn tries(app: &App, ids: &[String]) -> Vec<u64> {
    let mut out = Vec::new();
    for id in ids {
        match app.delivery(id).await.unwrap() {
            Some(crate::app::Delivery::Queued { tries, .. }) => out.push(tries),
            other => panic!("{other:?}"),
        }
    }
    out
}

impl Setup {
    /// From now on each request to bob's switch takes `ms` of the app's clock.
    fn slow_peer(&self, ms: u64) -> Arc<Slow> {
        let slow = Arc::new(Slow {
            inner: self.peer.transport(),
            clock: Arc::clone(&self.w.clock),
            ms: std::sync::atomic::AtomicU64::new(ms),
        });
        self.router
            .add(PEER_ORIGIN, Arc::clone(&slow) as Arc<dyn Transport>);
        slow
    }

    /// Flush while a flush says more, at most `rounds` times; returns the messages done.
    async fn flush_all(&self, app: &mut App, rounds: usize) -> Vec<String> {
        let mut done = Vec::new();
        for _ in 0..rounds {
            let report = app.flush_outbox().await.unwrap();
            done.extend(report.done.iter().cloned());
            if !report.more {
                return done;
            }
        }
        panic!("still more after {rounds} flushes");
    }
}

#[tokio::test]
async fn test_flush_outbox_tries_at_most_its_budget_and_goes_round() {
    // Six messages to bob, whose switch answers `503 staged`: a flush tries four and says
    // more, and the next tries the two left and ends the pass. A new pass starts after the
    // last one tried. Once bob's switch serves, flushes until none says more deliver each
    // once.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    s.peer.set_staged(true);
    let mut ids = Vec::new();
    for n in 0..6 {
        s.w.clock.advance_ms(1);
        ids.push(app.queue(note_to_bob(&s, &format!("n{n}"))).await.unwrap());
    }
    let report = app.flush_outbox().await.unwrap();
    assert!(report.more, "{report:?}");
    assert_eq!(report.queued.len(), 6, "{report:?}");
    assert_eq!(tries(&app, &ids).await, [1, 1, 1, 1, 0, 0]);
    // The pass goes on with the two left, and ends.
    let report = app.flush_outbox().await.unwrap();
    assert!(!report.more, "{report:?}");
    assert_eq!(tries(&app, &ids).await, [1, 1, 1, 1, 1, 1]);
    // The next flush starts a new pass, after the last one tried.
    let report = app.flush_outbox().await.unwrap();
    assert!(report.more, "{report:?}");
    assert_eq!(tries(&app, &ids).await, [2, 2, 2, 2, 1, 1]);
    s.peer.set_staged(false);
    // The pass under way ends with the two it hadn't tried; the next trigger's pass takes
    // the rest.
    let mut done = s.flush_all(&mut app, 3).await;
    done.extend(s.flush_all(&mut app, 3).await);
    done.sort();
    let mut all = ids.clone();
    all.sort();
    assert_eq!(done, all);
    let received = s.peer.received();
    for id in &ids {
        assert_eq!(received.iter().filter(|m| *m == id).count(), 1, "{id}");
    }
}

#[tokio::test]
async fn test_flush_outbox_on_a_slow_switch_stops_on_its_time_budget() {
    // Each request to bob's switch takes 9 s of the app's clock: a flush tries no message
    // past its 20 s once one went, and says more. Later flushes deliver the rest, each once.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let mut ids = Vec::new();
    for n in 0..3 {
        s.w.clock.advance_ms(1);
        ids.push(app.queue(note_to_bob(&s, &format!("n{n}"))).await.unwrap());
    }
    s.slow_peer(9_000);
    let started = s.w.clock.now_ms();
    let report = app.flush_outbox().await.unwrap();
    assert!(report.more, "{report:?}");
    assert!(
        !report.done.is_empty() && report.done.len() < ids.len(),
        "{report:?}"
    );
    assert!(
        s.w.clock.now_ms() - started <= crate::app::DEFAULT_CALL_BUDGET_MS + 2 * 9_000,
        "within the budget and one message's try"
    );
    let mut done = report.done.clone();
    done.extend(s.flush_all(&mut app, 3).await);
    done.sort();
    let mut all = ids.clone();
    all.sort();
    assert_eq!(done, all);
    let received = s.peer.received();
    for id in &ids {
        assert_eq!(received.iter().filter(|m| *m == id).count(), 1, "{id}");
    }
}

#[tokio::test]
async fn test_flush_message_past_its_time_budget_writes_its_record_job_in_the_same_try() {
    // Bob's switch takes 25 s to answer: the message is accepted past the call's budget, and
    // its record job still goes in the same try, which is one unit and goes whole.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let target = RecordTarget::new(items(), b"n1");
    let signed = app
        .sign_message(note_to_bob(&s, "hello"))
        .unwrap()
        .with_record(crate::app::RecordJob {
            target: target.clone(),
            tag: b"sent".to_vec(),
        });
    let msg_id = app.queue_signed(signed).await.unwrap();
    s.slow_peer(25_000);
    let delivery = app.flush_message(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Some(crate::app::Delivery::Accepted { .. })),
        "{delivery:?}"
    );
    let key = app.record_key(&target).unwrap();
    let record = app.shared_record(&key).await.unwrap().unwrap();
    assert_eq!(
        record.content,
        crate::app::RecordContent::Value(value(&[msg_id.as_str()]))
    );
    assert!(app.outbox_record(&msg_id).await.is_none(), "every job done");
}

#[tokio::test]
async fn test_peek_reads_at_most_its_page_budget() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    for _ in 0..3 {
        s.note(app.app_id());
    }
    app.config.page_size = 1;
    let from = s.router.log().len();
    let report = app.peek().await.unwrap();
    assert!(report.more, "{report:?}");
    assert_eq!(report.items.len(), crate::app::PEEK_PAGES);
    let pages = s
        .sent_since(from)
        .iter()
        .filter(|line| line.contains("/feed?"))
        .count();
    assert_eq!(pages, crate::app::PEEK_PAGES);
    // One page holds them all: no more.
    app.config.page_size = 100;
    let report = app.peek().await.unwrap();
    assert!(!report.more, "{report:?}");
    assert_eq!(report.items.len(), 3);
}

#[tokio::test]
async fn test_flush_outbox_while_more_stops_after_one_pass() {
    // Six messages to bob, whose switch answers `503 staged`, as in an outage: a host that
    // flushes while a flush says more stops after one pass, each message tried once. Only a
    // later flush, on the host's own triggers, tries them again.
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    s.peer.set_staged(true);
    let mut ids = Vec::new();
    for n in 0..6 {
        s.w.clock.advance_ms(1);
        ids.push(app.queue(note_to_bob(&s, &format!("n{n}"))).await.unwrap());
    }
    let mut flushes = 0;
    loop {
        flushes += 1;
        let report = app.flush_outbox().await.unwrap();
        if !report.more {
            assert_eq!(report.queued.len(), ids.len(), "{report:?}");
            break;
        }
        assert!(flushes < 10, "the loop settles");
    }
    assert_eq!(flushes, 2);
    assert_eq!(tries(&app, &ids).await, [1; 6]);
}

// -------------------------------------------------------------------------------------
// Checks: owed identity deliveries before the outbox, and passes under way

/// A switch that takes `ms` of the app's clock for each request, then fails to connect.
struct SlowFailing {
    clock: Arc<crate::clock::TestClock>,
    ms: u64,
}

impl Transport for SlowFailing {
    fn send(&self, _: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        Box::pin(async move {
            self.clock.advance_ms(self.ms);
            Err(TransportError::Connect("down".into()))
        })
    }
}

impl Setup {
    /// The app in `store` wrote to `pubky`'s switch just now, which holds an older own
    /// `identity.json`.
    async fn mark_recent(&self, app: &App, store: &Arc<MemoryStore>, pubky: &[u8; 32]) {
        let ns = crate::store::client_namespace(&app.app_id());
        let mut tx = crate::app::state::Tx::new(&ns);
        crate::app::directory::put_peer(
            &mut tx,
            pubky,
            &crate::app::directory::PeerSwitch {
                known_version: Some(1),
                last_sent_ms: Some(self.w.clock.now_ms()),
            },
        )
        .unwrap();
        tx.commit(&crate::store::StoreHandle::inline(
            Arc::clone(store) as Arc<dyn StateStore>
        ))
        .await
        .unwrap();
    }

    /// A counterparty `name` whose switch takes `ms` for each request and fails, recent for
    /// the app in `store`. Returns its Pubky ID.
    async fn slow_failing_counterparty(
        &self,
        app: &App,
        store: &Arc<MemoryStore>,
        name: &str,
        ms: u64,
    ) -> [u8; 32] {
        let key = identity(name);
        let pubky = key.public();
        let origin = format!("https://{name}.example");
        let published = PeerSwitch::new(
            key,
            &origin,
            Arc::clone(&self.w.clock),
            Arc::clone(&self.w.homeserver),
        );
        published
            .add_app("shop", &AppSpec::new(&["scope-a"]), &["sample.note"], false)
            .unwrap();
        self.router.add(
            &origin,
            Arc::new(SlowFailing {
                clock: Arc::clone(&self.w.clock),
                ms,
            }) as Arc<dyn Transport>,
        );
        self.mark_recent(app, store, &pubky).await;
        pubky
    }

    /// An own `identity.json` that removes an app, taken by `app`.
    async fn remove_an_app(&self, app: &mut App) {
        let now = self.w.clock.now_ms();
        self.w.next_doc(|body| {
            body.removed.push(RemovedApp {
                app_id: [9; 16],
                distrust_from: now,
            })
        });
        app.refresh_identity().await.unwrap();
    }

    /// One trigger of the host: flush while a flush says more.
    async fn flush_while_more(&self, app: &mut App) -> usize {
        for flushes in 1..=10 {
            if !app.flush_outbox().await.unwrap().more {
                return flushes;
            }
        }
        panic!("still more after 10 flushes");
    }
}

/// A record job owed while a slow switch that keeps failing is owed the own `identity.json`:
/// the owed delivery spends each flush's budget before the outbox. The message's try, record
/// job included, goes whole in the joint pass, so the host's triggers have the record written.
#[tokio::test]
async fn test_flush_outbox_record_job_behind_a_slow_failing_peer_is_written() {
    let s = Setup::new(false);
    let store = Arc::new(MemoryStore::new());
    let mut app = s
        .join_on("wallet", Arc::clone(&store) as Arc<dyn StateStore>)
        .await;
    s.slow_failing_counterparty(&app, &store, "carol", 25_000)
        .await;
    s.remove_an_app(&mut app).await;
    let target = RecordTarget::new(items(), b"n1");
    let signed = app
        .sign_message(note_to_bob(&s, "hello"))
        .unwrap()
        .with_record(crate::app::RecordJob {
            target: target.clone(),
            tag: b"sent".to_vec(),
        });
    let msg_id = app.queue_signed(signed).await.unwrap();
    let key = app.record_key(&target).unwrap();
    for _ in 0..5 {
        s.flush_while_more(&mut app).await;
        s.w.clock.advance_ms(60_000);
    }
    assert!(
        matches!(
            app.delivery(&msg_id).await.unwrap(),
            Some(crate::app::Delivery::Accepted { .. })
        ),
        "delivered"
    );
    assert!(
        app.shared_record(&key).await.unwrap().is_some(),
        "the record job owed is written within five triggers"
    );
}

/// The same record job, its counterparty's switch still written to (recent) all along:
/// it isn't given up at the retention without a single try of its write.
#[tokio::test]
async fn test_flush_outbox_record_job_behind_a_slow_failing_peer_isnt_given_up() {
    let s = Setup::new(false);
    let store = Arc::new(MemoryStore::new());
    let mut app = s
        .join_on("wallet", Arc::clone(&store) as Arc<dyn StateStore>)
        .await;
    let carol = s
        .slow_failing_counterparty(&app, &store, "carol", 25_000)
        .await;
    s.remove_an_app(&mut app).await;
    let target = RecordTarget::new(items(), b"n1");
    let signed = app
        .sign_message(note_to_bob(&s, "hello"))
        .unwrap()
        .with_record(crate::app::RecordJob {
            target: target.clone(),
            tag: b"sent".to_vec(),
        });
    let msg_id = app.queue_signed(signed).await.unwrap();
    s.flush_while_more(&mut app).await;
    let Some(crate::app::Delivery::Accepted { accepted_at_ms }) =
        app.delivery(&msg_id).await.unwrap()
    else {
        panic!("accepted");
    };
    // The host flushes once a day for the 30 days of the retention.
    for day in 1..=30u64 {
        s.w.clock
            .set_ms(accepted_at_ms + day * pubky_switch_core::records::DAY_MS);
        s.mark_recent(&app, &store, &carol).await;
        s.flush_while_more(&mut app).await;
    }
    let dropped = app
        .unacknowledged_events()
        .await
        .unwrap()
        .iter()
        .any(|e| matches!(e, AppEvent::RecordJobDropped { msg_id: m, .. } if *m == msg_id));
    let key = app.record_key(&target).unwrap();
    assert!(
        !dropped || app.shared_record(&key).await.unwrap().is_some(),
        "the record job was given up without its write ever being tried"
    );
}

/// The worst case of a flush: the budget and one unit started within it. Two owed
/// deliveries of the own `identity.json` and one message, each request 25 s: the first
/// delivery is the flush's one unit, and the rest wait for the next flushes of the loop.
#[tokio::test]
async fn test_flush_outbox_worst_case_is_the_budget_and_one_unit() {
    let s = Setup::new(false);
    let store = Arc::new(MemoryStore::new());
    let mut app = s
        .join_on("wallet", Arc::clone(&store) as Arc<dyn StateStore>)
        .await;
    s.slow_failing_counterparty(&app, &store, "carol", 25_000)
        .await;
    s.slow_failing_counterparty(&app, &store, "dave", 25_000)
        .await;
    s.remove_an_app(&mut app).await;
    app.queue(note_to_bob(&s, "n0")).await.unwrap();
    s.slow_peer(25_000);
    let started = s.w.clock.now_ms();
    let report = app.flush_outbox().await.unwrap();
    let took = s.w.clock.now_ms() - started;
    assert!(
        took <= crate::app::DEFAULT_CALL_BUDGET_MS + 25_000,
        "the budget and one unit past it, took {took} ms"
    );
    // The message waits for the rest of the pass, in the same loop.
    let mut done = report.done.clone();
    let mut more = report.more;
    while more {
        let report = app.flush_outbox().await.unwrap();
        done.extend(report.done.iter().cloned());
        more = report.more;
    }
    assert_eq!(done.len(), 1, "delivered in the same loop");
}

/// A pass under way survives a restart, its first message leaving the outbox, and a message
/// queued meanwhile: the next flush tries only what the pass hasn't reached, the new message
/// included, and ends it; the flush after starts a new pass after the last one tried.
#[tokio::test]
async fn test_flush_outbox_pass_survives_a_restart_and_changes_under_way() {
    let s = Setup::new(false);
    let store = Arc::new(MemoryStore::new());
    let mut app = s
        .join_on("wallet", Arc::clone(&store) as Arc<dyn StateStore>)
        .await;
    s.peer.set_staged(true);
    let mut ids = Vec::new();
    for n in 0..6 {
        s.w.clock.advance_ms(1);
        ids.push(app.queue(note_to_bob(&s, &format!("n{n}"))).await.unwrap());
    }
    assert!(app.flush_outbox().await.unwrap().more);
    assert_eq!(tries(&app, &ids).await, [1, 1, 1, 1, 0, 0]);
    // The pass's first message is delivered on its own.
    s.peer.set_staged(false);
    assert!(matches!(
        app.flush_message(&ids[0]).await.unwrap(),
        Some(crate::app::Delivery::Accepted { .. })
    ));
    s.peer.set_staged(true);
    s.w.clock.advance_ms(1);
    ids.push(app.queue(note_to_bob(&s, "n6")).await.unwrap());
    drop(app);
    let env = s.w.signer.env_with(
        Arc::clone(&store) as Arc<dyn StateStore>,
        Arc::clone(&s.router) as Arc<dyn Transport>,
    );
    let mut app = App::load(
        env,
        s.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    let report = app.flush_outbox().await.unwrap();
    assert!(!report.more, "{report:?}");
    assert_eq!(tries(&app, &ids[1..]).await, [1, 1, 1, 1, 1, 1]);
    let report = app.flush_outbox().await.unwrap();
    assert!(report.more, "{report:?}");
    assert_eq!(tries(&app, &ids[1..]).await, [2, 2, 2, 2, 1, 1]);
}

/// Two messages whose tries fail, each past the time budget, then a healthy one: one
/// trigger's loop "flush while more" delivers the healthy one, each tried once.
#[tokio::test]
async fn test_flush_outbox_two_slow_failures_then_a_healthy_message_in_one_loop() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let mut ids = Vec::new();
    for n in 0..3 {
        s.w.clock.advance_ms(1);
        ids.push(app.queue(note_to_bob(&s, &format!("n{n}"))).await.unwrap());
    }
    s.slow_peer(25_000);
    for _ in 0..2 {
        s.peer.fail_next(
            "inbox",
            pubky_switch_core::http::ErrorCode::Unavailable,
            json!(null),
        );
    }
    let mut done = Vec::new();
    let mut flushes = 0;
    loop {
        flushes += 1;
        let report = app.flush_outbox().await.unwrap();
        done.extend(report.done.iter().cloned());
        if !report.more {
            break;
        }
        assert!(flushes < 10, "the loop settles");
    }
    assert_eq!(done, vec![ids[2].clone()]);
    assert_eq!(tries(&app, &ids[..2]).await, [1, 1]);
    assert_eq!(flushes, 3);
}

/// Held messages make no request and don't count: a flush of six held messages ends the
/// pass at once.
#[tokio::test]
async fn test_flush_outbox_held_messages_end_the_pass_without_a_request() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    s.peer.set_staged(true);
    let mut ids = Vec::new();
    for n in 0..6 {
        s.w.clock.advance_ms(1);
        ids.push(app.queue(note_to_bob(&s, &format!("n{n}"))).await.unwrap());
    }
    app.hold_queued(&s.w.bob.public()).await.unwrap();
    let from = s.router.log().len();
    let report = app.flush_outbox().await.unwrap();
    assert!(!report.more, "{report:?}");
    assert!(
        !s.router.log()[from..]
            .iter()
            .any(|line| line.contains(PEER_ORIGIN)),
        "no request to bob's switch"
    );
    assert_eq!(tries(&app, &ids).await, [0; 6]);
}

/// Three slow switches that keep failing are owed the own `identity.json`, each spending a
/// flush's budget, and four messages wait on a switch that answers `503 staged`: a host
/// that flushes while a flush says more stops after one pass, each message tried once.
#[tokio::test]
async fn test_flush_outbox_while_more_tries_each_message_once_with_owed_peers() {
    let s = Setup::new(false);
    let store = Arc::new(MemoryStore::new());
    let mut app = s
        .join_on("wallet", Arc::clone(&store) as Arc<dyn StateStore>)
        .await;
    for name in ["carol", "dave", "erin"] {
        s.slow_failing_counterparty(&app, &store, name, 25_000)
            .await;
    }
    s.remove_an_app(&mut app).await;
    s.peer.set_staged(true);
    let mut ids = Vec::new();
    for n in 0..4 {
        s.w.clock.advance_ms(1);
        ids.push(app.queue(note_to_bob(&s, &format!("n{n}"))).await.unwrap());
    }
    let mut flushes = 0;
    while app.flush_outbox().await.unwrap().more {
        flushes += 1;
        assert!(flushes < 50, "the loop settles");
    }
    flushes += 1;
    assert_eq!(
        tries(&app, &ids).await,
        [1, 1, 1, 1],
        "each message tried once in one loop, of {flushes} flushes"
    );
}

/// A message to a new counterparty whose conversation entry's batch was kept, its answer
/// lost: the host's flushes alone, with no read, still have it delivered.
#[tokio::test]
async fn test_flush_outbox_message_behind_its_kept_conversation_entry_goes_without_a_read() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    s.w.switch.fail_next(crate::testing::Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    let (msg_id, delivery) = app.send(note_to_bob(&s, "hello")).await.unwrap();
    assert!(
        matches!(delivery, crate::app::Delivery::Queued { .. }),
        "{delivery:?}"
    );
    assert_eq!(
        app.kept_batches().await.unwrap().len(),
        1,
        "the entry is kept"
    );
    for _ in 0..3 {
        s.w.clock.advance_ms(60_000);
        s.flush_while_more(&mut app).await;
    }
    let delivery = app.delivery(&msg_id).await.unwrap();
    assert!(
        matches!(delivery, Some(crate::app::Delivery::Accepted { .. })),
        "{delivery:?}, kept {}",
        app.kept_batches().await.unwrap().len()
    );
}

/// Three slow failing switches owed the own `identity.json` and four messages answered
/// `503`. A joint pass under way across a restart, with a switch newly owed and a message
/// queued after the pass began: the host's loop tries each switch and each message of the
/// pass once, the new message with them, and leaves the new switch to the next pass, which
/// tries every one once more.
#[tokio::test]
async fn test_flush_outbox_joint_pass_across_a_restart_with_newcomers() {
    let s = Setup::new(false);
    let store = Arc::new(MemoryStore::new());
    let mut app = s
        .join_on("wallet", Arc::clone(&store) as Arc<dyn StateStore>)
        .await;
    let slow = ["carol", "dave", "erin"];
    for name in slow {
        s.slow_failing_counterparty(&app, &store, name, 25_000)
            .await;
    }
    s.remove_an_app(&mut app).await;
    s.peer.set_staged(true);
    let mut ids = Vec::new();
    for n in 0..4 {
        s.w.clock.advance_ms(1);
        ids.push(app.queue(note_to_bob(&s, &format!("n{n}"))).await.unwrap());
    }
    let requests = |name: &str| {
        let origin = format!("https://{name}.example");
        s.router
            .log()
            .iter()
            .filter(|line| line.contains(&origin))
            .count()
    };
    assert!(app.flush_outbox().await.unwrap().more);
    // After the pass began: a switch newly owed, by a second removal, and a new message.
    s.slow_failing_counterparty(&app, &store, "frank", 25_000)
        .await;
    let now = s.w.clock.now_ms();
    s.w.next_doc(|body| {
        body.removed.push(RemovedApp {
            app_id: [8; 16],
            distrust_from: now,
        })
    });
    app.refresh_identity().await.unwrap();
    s.w.clock.advance_ms(1);
    ids.push(app.queue(note_to_bob(&s, "n4")).await.unwrap());
    drop(app);
    let env = s.w.signer.env_with(
        Arc::clone(&store) as Arc<dyn StateStore>,
        Arc::clone(&s.router) as Arc<dyn Transport>,
    );
    let mut app = App::load(
        env,
        s.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    let mut flushes = 1;
    while app.flush_outbox().await.unwrap().more {
        flushes += 1;
        assert!(flushes < 20, "the loop settles");
    }
    assert_eq!(tries(&app, &ids).await, [1; 5], "{flushes} flushes");
    for name in slow {
        assert_eq!(requests(name), 1, "{name}");
    }
    assert_eq!(
        requests("frank"),
        0,
        "the new switch waits for the next pass"
    );
    s.flush_while_more(&mut app).await;
    assert_eq!(tries(&app, &ids).await, [2; 5]);
    for name in slow {
        assert_eq!(requests(name), 2, "{name}");
    }
    assert_eq!(requests("frank"), 1);
}

/// A delivery answered `409 stale_key` once its round's budget has passed: the reseal waits
/// for the next try, which reseals and delivers. The message stays queued, not failed, and
/// is sent once.
#[tokio::test]
async fn test_flush_outbox_stale_key_past_the_round_budget_is_resolved_by_the_next_try() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let (_, delivery) = app.send(note_to_bob(&s, "one")).await.unwrap();
    assert!(
        matches!(delivery, crate::app::Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    // Bob rotates; the cached directory still names the old key.
    s.peer.rotate(0).unwrap();
    let slow = s.slow_peer(21_000);
    let (second, delivery) = app.send(note_to_bob(&s, "two")).await.unwrap();
    assert!(
        matches!(delivery, crate::app::Delivery::Queued { .. }),
        "{delivery:?}"
    );
    slow.ms.store(1_000, std::sync::atomic::Ordering::SeqCst);
    s.w.clock.advance_ms(60_000);
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![second.clone()], "{report:?}");
    assert_eq!(
        s.peer.received().iter().filter(|m| **m == second).count(),
        1
    );
}

/// A message whose conversation entry is in the second of two kept batches (kept while the
/// account was frozen): each pass sends one kept batch again, oldest first, so it goes in
/// the second pass, the one that sends its batch.
#[tokio::test]
async fn test_flush_outbox_message_behind_its_entry_in_the_second_kept_batch() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let freeze = s.freeze();
    s.w.clock.advance_ms(1_000);
    app.submit_batch(conversation([10; 32])).await.unwrap_err();
    s.w.clock.advance_ms(1_000);
    let msg_id = app.queue(note_to_bob(&s, "hello")).await.unwrap();
    app.flush_outbox().await.unwrap();
    assert_eq!(app.kept_batches().await.unwrap().len(), 2, "two kept");
    s.w.switch.unfreeze(&freeze).unwrap();
    let delivered = |delivery: Option<crate::app::Delivery>| {
        matches!(delivery, Some(crate::app::Delivery::Accepted { .. }))
    };
    s.w.clock.advance_ms(60_000);
    s.flush_while_more(&mut app).await;
    let first = delivered(app.delivery(&msg_id).await.unwrap());
    s.w.clock.advance_ms(60_000);
    s.flush_while_more(&mut app).await;
    let second = delivered(app.delivery(&msg_id).await.unwrap());
    assert!(!first, "the first pass sends the batch ahead of its own");
    assert!(second, "in the second pass, which sends its batch");
}

/// A kept batch whose resend takes 25 s and fails, sent again first in every pass: the
/// messages of each pass still go, each once, in the same loop.
#[tokio::test]
async fn test_flush_outbox_slow_failing_kept_batch_starves_no_message() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let (_, delivery) = app.send(note_to_bob(&s, "first")).await.unwrap();
    assert!(
        matches!(delivery, crate::app::Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    for _ in 0..12 {
        s.w.switch.fail_next(crate::testing::Fault::Unreachable {
            path: "/ops".into(),
            after: 0,
        });
    }
    app.submit_batch(conversation([10; 32])).await.unwrap_err();
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
    s.peer.set_staged(true);
    let mut ids = Vec::new();
    for n in 0..3 {
        s.w.clock.advance_ms(1);
        ids.push(app.queue(note_to_bob(&s, &format!("n{n}"))).await.unwrap());
    }
    s.slow(25_000);
    for round in 1..=2u64 {
        s.w.clock.advance_ms(60_000);
        let flushes = s.flush_while_more(&mut app).await;
        assert_eq!(tries(&app, &ids).await, [round; 3], "{flushes} flushes");
    }
    assert_eq!(app.kept_batches().await.unwrap().len(), 1, "still kept");
}

/// The same with bob's switch slow at every try, so no round ever has time to reseal: the
/// key the `409 stale_key` named is taken when the reseal is skipped, and the next try's
/// first attempt seals to it and delivers.
#[tokio::test]
async fn test_flush_outbox_stale_key_skipped_every_time_is_sealed_at_the_next_try() {
    let s = Setup::new(false);
    let mut app = s.join("wallet").await;
    let (_, delivery) = app.send(note_to_bob(&s, "one")).await.unwrap();
    assert!(
        matches!(delivery, crate::app::Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    s.peer.rotate(0).unwrap();
    s.slow_peer(21_000);
    let (second, delivery) = app.send(note_to_bob(&s, "two")).await.unwrap();
    assert!(
        matches!(delivery, crate::app::Delivery::Queued { .. }),
        "{delivery:?}"
    );
    s.w.clock.advance_ms(60_000);
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![second.clone()], "{report:?}");
    assert_eq!(
        s.peer.received().iter().filter(|m| **m == second).count(),
        1
    );
}
