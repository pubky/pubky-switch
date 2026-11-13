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
