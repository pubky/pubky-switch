//! A feed read the switch holds while the account recovers in place (Switch wire 7.4.4,
//! spec 12.6 step 1).

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use pubky_switch_core::records::Inbox;
use pubky_switch_core::scopes::Permission;

use super::moves::{Router, join_on};
use super::*;
use crate::app::AppEvent;
use crate::testing::SWITCH_ORIGIN as ORIGIN;
use crate::transport::{Request, Response, Transport};

/// The switch's holding transport, keeping each feed answer's status and body.
struct Recording {
    inner: Arc<dyn Transport>,
    feeds: Mutex<Vec<(u16, serde_json::Value)>>,
}

impl Transport for Recording {
    fn send(
        &self,
        request: Request,
    ) -> crate::transport::BoxFuture<'_, Result<Response, crate::error::TransportError>> {
        Box::pin(async move {
            let feed = request.path_and_query.contains("/feed");
            let answer = self.inner.send(request).await;
            if feed && let Ok(response) = &answer {
                let body = serde_json::from_slice(&response.body).unwrap_or_default();
                self.feeds.lock().unwrap().push((response.status, body));
            }
            answer
        })
    }
}

#[tokio::test]
async fn test_feed_read_held_across_a_recovery_in_place_is_read_again_at_the_new_sequence() {
    // The app's read is held when its account recovers in place. The switch answers it
    // `503 unavailable` with the operator key, which isn't the account's answer: the read
    // fails for now, never for good, and the app's next read follows the recovery and reads
    // from the start of the new sequence.
    let w = World::new();
    let router = Router::of(&w);
    let recording = Arc::new(Recording {
        inner: w.switch.holding_transport(),
        feeds: Mutex::new(Vec::new()),
    });
    router.add_transport(ORIGIN, Arc::clone(&recording) as Arc<dyn Transport>);
    let store = Arc::new(MemoryStore::new());
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 1);
    let pending = SigningKey::from_bytes(&seed("service/alice/in-place"));
    let prev = w.switch.identity_doc().unwrap().hash();
    let held = async {
        while w.switch.held_reads() == 0 {
            tokio::task::yield_now().await;
        }
        let doc = w
            .signer
            .sign_next(|body| {
                body.generation = 2;
                body.inbox = Inbox::new(ORIGIN, pending.verifying_key().to_bytes());
                body.recovery_from = Some(1);
            })
            .unwrap();
        w.switch
            .recover_in_place(pending.clone(), &doc, prev)
            .unwrap();
    };
    let feeds_before = recording.feeds.lock().unwrap().len();
    // Woken by the recovery: a read left held would never end, the switch's clock standing.
    let (read, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(app.receive(Some(10)), held)
    })
    .await
    .expect("the held read is answered");
    // The held read's own answer: `503 unavailable` with no head.
    let feeds = recording.feeds.lock().unwrap().clone();
    let (status, body) = &feeds[feeds_before];
    assert_eq!(
        (*status, body["code"].as_str()),
        (503, Some("unavailable")),
        "{body}"
    );
    assert!(body.get("head").is_none(), "{body}");
    // Not final: the read followed the recovery and went on at the new sequence.
    let report = read.unwrap();
    assert!(
        report.events.iter().any(|event| matches!(
            event,
            AppEvent::ProviderLost {
                lost_generation: 1,
                generation: 2
            }
        )),
        "{:?}",
        report.events
    );
    assert_eq!(app.cursor().generation, 2);
    assert!(app.alarm().is_none(), "{:?}", app.alarm());
    // The next read reads at the new generation.
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
}
