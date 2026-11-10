//! The scripted switch's `GET /apps` against the service's rules (Switch wire 7.4.12): an
//! app's last-seen time, its open attempts, and a departure's rotation, which stays done after
//! the signer purges the app from `removed`.

// The helpers set up fixed test state, where a failure is a test failure.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use pubky_switch_client::app::{App, AppConfig, ClaimOp, ObligationDeadline};
use pubky_switch_client::client::answers::AppStatus;
use pubky_switch_client::clock::TestClock;
use pubky_switch_client::store::{MemoryStore, StateStore};
use pubky_switch_client::testing::{
    AppSpec, ProtocolSpec, START_MS, Seeds, TestHomeserver, TestIdentity, TestProtocol, TestSigner,
};
use pubky_switch_client::{Credentials, SwitchClient};
use pubky_switch_core::claims::Basis;
use pubky_switch_core::records::{DAY_MS, RemovedApp};
use pubky_switch_core::scopes::Permission;

fn spec() -> ProtocolSpec {
    ProtocolSpec {
        keyed_scopes: vec!["notes".into()],
        collections: Vec::new(),
        accepts: Vec::new(),
    }
}

struct Setup {
    alice: TestSigner,
    clock: Arc<TestClock>,
}

impl Setup {
    fn new() -> Self {
        let clock = Arc::new(TestClock::new(START_MS));
        let alice = TestSigner::new(
            TestIdentity::new(&Seeds::default(), "alice"),
            Arc::clone(&clock),
            Arc::new(TestHomeserver::new()),
            spec(),
        );
        Self { alice, clock }
    }

    async fn join(&self, name: &str) -> App {
        let keys = self.alice.identity().app_keys(name);
        let app = AppSpec::new(&["notes"]).with_permissions(&Permission::ALL);
        let request = self.alice.approve(&keys, &app).unwrap();
        let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
        App::join(
            self.alice.env(store),
            Arc::new(TestProtocol::new(spec())),
            AppConfig::default(),
            request,
        )
        .await
        .unwrap()
    }

    /// `app`'s status in the signer's `GET /apps`.
    async fn status(&self, app: &[u8; 16]) -> AppStatus {
        let identity = self.alice.identity().public();
        let client = SwitchClient::new(
            self.alice.origin(),
            identity,
            Credentials::Signer {
                identity,
                key: Arc::new(self.alice.identity().key().clone()),
            },
            Some(self.alice.switch().service_key()),
            self.alice.switch().transport(),
            self.clock.clone(),
        )
        .unwrap();
        let answer = client.apps().await.unwrap();
        answer.apps.into_iter().find(|s| &s.app_id == app).unwrap()
    }
}

#[tokio::test]
async fn test_scripted_apps_last_seen_is_the_apps_latest_request() {
    let s = Setup::new();
    let keys = s.alice.identity().app_keys("quiet");
    s.alice
        .register_app(&keys, &AppSpec::new(&["notes"]))
        .unwrap();
    let quiet = s.status(&keys.app_id_bytes()).await;
    assert!(quiet.current);
    assert_eq!(quiet.last_seen, None);
    s.clock.advance_ms(60_000);
    let app = s.join("wallet").await;
    let seen = s.status(&app.app_id()).await;
    assert_eq!(seen.last_seen, Some(START_MS + 60_000));
}

#[tokio::test]
async fn test_scripted_apps_lists_an_apps_open_attempts_until_done() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let (claim_key, attempt_id) = ([5; 32], [6; 16]);
    let deadline = START_MS + DAY_MS;
    app.write_claim(
        ClaimOp::attempt(claim_key, 0, attempt_id, 3600, Some(deadline)),
        vec![],
        ObligationDeadline::At(deadline),
    )
    .await
    .unwrap();
    let open = s.status(&app.app_id()).await.open_attempts;
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].claim_key, claim_key);
    assert_eq!(open[0].attempt_id, attempt_id);
    assert_eq!(open[0].outcome, "open");
    let condition = app.claim_condition(&claim_key).await.unwrap();
    app.write_claim(
        ClaimOp::done(claim_key, 1, attempt_id, Basis::Owner, None).unwrap(),
        vec![condition],
        ObligationDeadline::At(deadline),
    )
    .await
    .unwrap();
    assert!(s.status(&app.app_id()).await.open_attempts.is_empty());
}

#[tokio::test]
async fn test_scripted_apps_rotation_stays_done_after_a_purge() {
    let s = Setup::new();
    let keys = s.alice.identity().app_keys("leaving");
    s.alice
        .register_app(&keys, &AppSpec::new(&["notes"]))
        .unwrap();
    let id = keys.app_id_bytes();
    s.alice.switch().leave(id).unwrap();
    assert!(s.status(&id).await.awaiting_rotation);
    s.alice
        .next_doc(|body| {
            body.apps.retain(|a| a.app_id != id);
            body.removed.push(RemovedApp {
                app_id: id,
                distrust_from: START_MS,
            });
            body.data_epoch += 1;
        })
        .unwrap();
    assert!(!s.status(&id).await.awaiting_rotation);
    s.alice
        .next_doc(|body| body.removed.retain(|r| r.app_id != id))
        .unwrap();
    let purged = s.status(&id).await;
    assert!(!purged.awaiting_rotation);
    assert!(!purged.current);
    assert!(purged.departed_at.is_some());
}
