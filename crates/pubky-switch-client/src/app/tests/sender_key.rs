//! A sender whose copy of the recipient's `identity.json` names a service key the
//! recipient's switch no longer answers with, as after a provider loss in place (Switch
//! spec 12.6): an answer that doesn't verify with that key has the document read again,
//! once per [`SENDER_REREAD_MS`] for one recipient, and the delivery tried under the key the
//! newer one names (Switch spec 4.3, "re-fetched after any failure").

use serde_json::Map;

use super::*;
use crate::app::{Delivery, OutgoingMessage, SENDER_REREAD_MS};
use crate::testing::{PeerSwitch, Router};
use crate::transport::Transport;

/// Alice's world, bob's switch, and a router between them.
struct Setup {
    w: World,
    peer: Arc<PeerSwitch>,
    router: Arc<Router>,
}

impl Setup {
    fn new() -> Self {
        let w = World::new();
        let peer = PeerSwitch::new(
            identity("bob"),
            PEER_ORIGIN,
            Arc::clone(&w.clock),
            Arc::clone(&w.homeserver),
        );
        peer.add_app(
            "shop",
            &AppSpec::new(&["sample-a"]),
            &["sample.note"],
            false,
        )
        .unwrap();
        let router = Arc::new(Router::new());
        router.add_switch(crate::testing::SWITCH_ORIGIN, &w.switch);
        router.add(PEER_ORIGIN, peer.transport());
        Self { w, peer, router }
    }

    async fn join(&self) -> App {
        let request = self.w.approve(&app_keys("wallet"), &["sample-a"]);
        let env = self.w.signer.env_with(
            Arc::clone(&self.w.store) as Arc<dyn StateStore>,
            Arc::clone(&self.router) as Arc<dyn Transport>,
        );
        App::join(env, self.w.protocol.clone(), World::config(), request)
            .await
            .unwrap()
    }

    fn note(&self, text: &str) -> OutgoingMessage {
        let mut body = Map::new();
        body.insert("text".into(), json!(text));
        OutgoingMessage::new(self.w.bob.public(), "sample.note", body)
    }

    /// How many times bob's `identity.json` was read from his Homeserver.
    fn reads(&self) -> u64 {
        self.w.homeserver.identity_reads(&self.w.bob.public())
    }

    /// How many appends bob's switch was sent.
    fn appends(&self) -> usize {
        self.peer
            .routes()
            .iter()
            .filter(|route| *route == "POST inbox")
            .count()
    }

    /// The wallet, having delivered a first note to bob: it holds a fresh copy of his
    /// document.
    async fn wallet(&self) -> App {
        let mut app = self.join().await;
        let (_, delivery) = app.send(self.note("first")).await.unwrap();
        assert!(
            matches!(delivery, Delivery::Accepted { .. }),
            "{delivery:?}"
        );
        self.w.clock.advance_ms(60_000);
        app
    }
}

fn accepted(delivery: &Delivery) -> bool {
    matches!(delivery, Delivery::Accepted { .. })
}

#[tokio::test]
async fn test_sender_key_recovery_in_place_delivers_at_the_first_retry() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    s.peer.recover_in_place(seed("bob/next-service")).unwrap();
    let reads = s.reads();
    // Staged: its answer is signed with the new key. The document is read again once, and
    // the try under the new key is answered `503 staged`, which the app can now check.
    let (msg_id, delivery) = app.send(s.note("during")).await.unwrap();
    assert!(!accepted(&delivery), "{delivery:?}");
    assert_eq!(s.reads(), reads + 1);
    assert!(
        matches!(&delivery, Delivery::Queued { last_error: Some(e), .. } if e.contains("staged")),
        "{delivery:?}"
    );
    // Serving again, a second later, well within the 10-minute cache of the document read
    // before the loss: the first retry delivers.
    s.peer.set_staged(false);
    s.w.clock.advance_ms(1_000);
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()], "{report:?}");
    assert!(s.peer.received().contains(&msg_id));
    assert_eq!(s.reads(), reads + 1);
}

#[tokio::test]
async fn test_sender_key_unchanged_document_stays_queued() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    // Answers under a key no document names, the document unchanged.
    s.peer.sign_with(Some(seed("bob/foreign")));
    let reads = s.reads();
    let appends = s.appends();
    let (_, delivery) = app.send(s.note("signed by another key")).await.unwrap();
    assert!(!accepted(&delivery), "{delivery:?}");
    assert_eq!(s.reads(), reads + 1);
    // Nothing new to try under: the append isn't sent again.
    assert_eq!(s.appends(), appends + 1);
    // The same try again, a second later: queued, nothing read.
    s.w.clock.advance_ms(1_000);
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.queued.len(), 1, "{report:?}");
    assert_eq!(s.reads(), reads + 1);
}

#[tokio::test]
async fn test_sender_key_reread_is_bounded_per_recipient() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    s.peer.sign_with(Some(seed("bob/foreign")));
    let reads = s.reads();
    // A hostile switch answering every try under an unknown key: within the window, one read
    // whatever the number of tries.
    for text in ["one", "two", "three", "four"] {
        let (_, delivery) = app.send(s.note(text)).await.unwrap();
        assert!(!accepted(&delivery), "{delivery:?}");
        app.flush_outbox().await.unwrap();
        s.w.clock.advance_ms(10_000);
    }
    assert_eq!(s.reads(), reads + 1);
    // Once the window has passed, one more.
    s.w.clock.advance_ms(SENDER_REREAD_MS);
    app.flush_outbox().await.unwrap();
    assert_eq!(s.reads(), reads + 2);
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(s.reads(), reads + 2);
    assert_eq!(report.queued.len(), 4, "{report:?}");
}

#[tokio::test]
async fn test_sender_key_still_unverified_under_the_newer_key_is_queued_once() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    s.peer.recover_in_place(seed("bob/next-service")).unwrap();
    s.peer.set_staged(false);
    // The newer document names a key the switch doesn't answer with either.
    s.peer.sign_with(Some(seed("bob/foreign")));
    let reads = s.reads();
    let (msg_id, delivery) = app.send(s.note("after")).await.unwrap();
    assert!(!accepted(&delivery), "{delivery:?}");
    assert_eq!(s.reads(), reads + 1);
    // Answering under the key the newer document names again, it goes.
    s.peer.sign_with(None);
    let report = app.flush_outbox().await.unwrap();
    assert_eq!(report.done, vec![msg_id], "{report:?}");
}

#[tokio::test]
async fn test_sender_key_verified_refusal_reads_nothing() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    s.peer.set_staged(true);
    let reads = s.reads();
    let (_, delivery) = app.send(s.note("staged")).await.unwrap();
    assert!(!accepted(&delivery), "{delivery:?}");
    assert_eq!(s.reads(), reads);
}

/// The newer document read after an answer that didn't verify fails to commit: the read
/// counts for nothing, so the next try, within [`SENDER_REREAD_MS`], reads it again and
/// delivers under the new key, rather than waiting out the window under the old one.
#[tokio::test]
async fn test_sender_key_failed_save_of_the_newer_document_doesnt_delay_the_reread() {
    use crate::store::{Fault as StoreFault, FaultStore};
    let s = Setup::new();
    let id = s.wallet().await.app_id();
    let faulty = Arc::new(FaultStore::new(
        Arc::clone(&s.w.store) as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    let env = s.w.signer.env_with(
        Arc::clone(&faulty) as Arc<dyn StateStore>,
        Arc::clone(&s.router) as Arc<dyn Transport>,
    );
    let mut app = App::load(env, s.w.protocol.clone(), World::config(), id)
        .await
        .unwrap();
    s.peer.recover_in_place(seed("bob/next-service")).unwrap();
    let received = s.peer.received().len();
    let reads = s.reads();
    // Every key of bob's copy: the newer document's commit is refused once.
    let doc = crate::app::state::key::ident_doc(&s.w.bob.public());
    let bob = doc.trim_end_matches("doc");
    faulty.fail_put_once(bob.as_bytes());
    let msg_id = app.queue(s.note("after the loss")).await.unwrap();
    let error = app.flush_outbox().await.unwrap_err();
    assert!(matches!(error, crate::app::AppError::Store(_)), "{error:?}");
    assert_eq!(s.reads(), reads + 1);
    assert_eq!(s.peer.received().len(), received);
    // Serving again, a second later: the try reads the document again and delivers.
    s.peer.set_staged(false);
    s.w.clock.advance_ms(1_000);
    let report = app.flush_outbox().await.unwrap();
    let delivery = app.delivery(&msg_id).await.unwrap();
    assert_eq!(report.done, vec![msg_id.clone()], "{report:?} {delivery:?}");
    assert!(s.peer.received().contains(&msg_id));
    assert_eq!(s.reads(), reads + 2);
}

/// Bob's switch through a transport that takes a minute and a second of the app's clock per
/// request, after which bob publishes a newer `identity.json` naming another service key;
/// at most 30 requests, then it fails to connect.
struct Rotating {
    inner: Arc<dyn Transport>,
    peer: Arc<PeerSwitch>,
    clock: Arc<crate::clock::TestClock>,
    sent: std::sync::atomic::AtomicU8,
}

impl Transport for Rotating {
    fn send(
        &self,
        request: crate::transport::Request,
    ) -> crate::transport::BoxFuture<
        '_,
        Result<crate::transport::Response, crate::error::TransportError>,
    > {
        Box::pin(async move {
            let n = self.sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n >= 30 {
                return Err(crate::error::TransportError::Connect("down".into()));
            }
            self.clock.advance_ms(SENDER_REREAD_MS + 1_000);
            let answer = self.inner.send(request).await;
            self.peer
                .recover_in_place([n.wrapping_add(100); 32])
                .unwrap();
            answer
        })
    }
}

/// A hostile switch answering every request under a key no document names, each answer
/// taking longer than the reread window, while its identity publishes a newer document
/// naming another key each time: one try reads the document again a bounded number of
/// times, as the delivery's docs say.
#[tokio::test]
async fn test_sender_key_reread_is_bounded_per_try_however_slow_the_switch() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    s.peer.sign_with(Some(seed("bob/foreign")));
    let rotating = Arc::new(Rotating {
        inner: s.peer.transport(),
        peer: Arc::clone(&s.peer),
        clock: Arc::clone(&s.w.clock),
        sent: std::sync::atomic::AtomicU8::new(0),
    });
    s.router
        .add(PEER_ORIGIN, Arc::clone(&rotating) as Arc<dyn Transport>);
    let reads = s.reads();
    let started = s.w.clock.now_ms();
    let (_, delivery) = app.send(s.note("slow")).await.unwrap();
    assert!(!accepted(&delivery), "{delivery:?}");
    let sent = rotating.sent.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        s.reads() <= reads + 2,
        "one try read the document {} times, sent {sent} requests, took {} s",
        s.reads() - reads,
        (s.w.clock.now_ms() - started) / 1_000
    );
}
