//! The scripted switch's `GET /apps` against the service's rules (Switch wire 7.4.12): an
//! app's last-seen time, its open attempts, a departure's rotation, which stays done after
//! the signer purges the app from `removed`, and the purge itself (9.1).

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

#[tokio::test]
async fn test_scripted_apps_lists_the_app_ids_an_enrollment_kept() {
    use pubky_switch_client::testing::{SWITCH_ORIGIN, ScriptedSwitch};
    use pubky_switch_core::keys::IdentityKey;
    use pubky_switch_core::records::{
        Enrollment, EnrollmentBody, IdentityBody, IdentityDoc, IdentityPolicy, Inbox,
    };
    let key = IdentityKey::from_secret([31; 32]);
    let identity = key.public();
    let clock = Arc::new(TestClock::new(START_MS));
    let switch = ScriptedSwitch::unenrolled(&key, [32; 32], Arc::clone(&clock));
    let kept = [44; 16];
    let client = |pinned| {
        SwitchClient::new(
            SWITCH_ORIGIN,
            identity,
            Credentials::Signer {
                identity,
                key: Arc::new(key.clone()),
            },
            pinned,
            switch.transport(),
            clock.clone(),
        )
        .unwrap()
    };
    let body = EnrollmentBody {
        identity,
        origin: SWITCH_ORIGIN.to_owned(),
        nonce: [1; 16],
        policy: IdentityPolicy::default(),
        identity_doc: None,
        revoked_apps: Some(vec![kept]),
    };
    let enrollment = Enrollment::sign(&key, body).unwrap();
    let answer = client(None).enroll(&enrollment).await.unwrap();
    let first = IdentityBody::first(
        identity,
        [2; 16],
        Inbox::new(SWITCH_ORIGIN, answer.service_key),
        IdentityPolicy::default(),
    );
    switch
        .deliver_identity(&IdentityDoc::sign(&key, first).unwrap())
        .unwrap();
    clock.advance_ms(60_000);
    let apps = client(Some(answer.service_key)).apps().await.unwrap();
    let status = apps.apps.iter().find(|s| s.app_id == kept).unwrap();
    assert!(!status.current);
    assert_eq!(status.revoked_at, Some(START_MS));
    assert_eq!(status.departed_at, None);
    assert_eq!(status.keys_through, None);
}

#[tokio::test]
async fn test_scripted_apps_current_isnt_expiry() {
    // Spec 3.4's sense: a listed app whose certificate lapsed is still current, and
    // `cert_expires_at` shows the lapse. Once revoked, it isn't current.
    let s = Setup::new();
    let keys = s.alice.identity().app_keys("lapsed");
    s.alice
        .register_app(&keys, &AppSpec::new(&["notes"]))
        .unwrap();
    let id = keys.app_id_bytes();
    assert!(s.status(&id).await.current);
    s.clock.advance_ms(800 * DAY_MS);
    let lapsed = s.status(&id).await;
    assert!(lapsed.current);
    assert!(
        lapsed
            .cert_expires_at
            .is_some_and(|at| at < START_MS + 800 * DAY_MS)
    );
    s.alice.switch().revoke(id).unwrap();
    assert!(!s.status(&id).await.current);
}

#[tokio::test]
async fn test_scripted_apps_last_seen_stops_once_the_app_is_revoked() {
    let s = Setup::new();
    let app = s.join("wallet").await;
    let seen = s.status(&app.app_id()).await.last_seen;
    assert!(seen.is_some());
    s.alice.switch().revoke(app.app_id()).unwrap();
    s.clock.advance_ms(60_000);
    // The revoked app's requests are refused, and don't count as seen.
    let _ = s
        .alice
        .switch()
        .handle(&pubky_switch_client::transport::Request {
            method: "GET".into(),
            origin: s.alice.origin().to_owned(),
            path_and_query: format!(
                "/v1/{}/feed",
                pubky_switch_core::enc::zbase32_encode(&s.alice.identity().public())
            ),
            headers: vec![pubky_switch_client::transport::Header {
                name: pubky_switch_core::http::header::APP.to_owned(),
                value: pubky_switch_core::enc::zbase32_encode(&app.app_id()),
            }],
            body: Vec::new(),
        });
    assert_eq!(s.status(&app.app_id()).await.last_seen, seen);
}

#[tokio::test]
async fn test_scripted_switches_at_two_origins_each_take_their_own_enrollment() {
    use pubky_switch_client::testing::ScriptedSwitch;
    use pubky_switch_core::keys::IdentityKey;
    use pubky_switch_core::records::{Enrollment, EnrollmentBody, IdentityPolicy};
    let clock = Arc::new(TestClock::new(START_MS));
    let enroll = |key: &IdentityKey, switch: &Arc<ScriptedSwitch>, origin: &str, named: &str| {
        let identity = key.public();
        let client = SwitchClient::new(
            origin,
            identity,
            Credentials::Signer {
                identity,
                key: Arc::new(key.clone()),
            },
            None,
            switch.transport(),
            clock.clone(),
        )
        .unwrap();
        let enrollment = Enrollment::sign(
            key,
            EnrollmentBody {
                identity,
                origin: named.to_owned(),
                nonce: [1; 16],
                policy: IdentityPolicy::default(),
                identity_doc: None,
                revoked_apps: None,
            },
        )
        .unwrap();
        async move { client.enroll(&enrollment).await }
    };
    let (a, b) = (
        IdentityKey::from_secret([51; 32]),
        IdentityKey::from_secret([52; 32]),
    );
    let (origin_a, origin_b) = ("https://a.switch.example", "https://b.switch.example");
    let at_a = ScriptedSwitch::unenrolled_at(&a, [53; 32], Arc::clone(&clock), origin_a);
    let at_b = ScriptedSwitch::unenrolled_at(&b, [54; 32], Arc::clone(&clock), origin_b);
    // Each takes an enrollment that names its own origin, and refuses one naming the other.
    assert!(enroll(&a, &at_a, origin_a, origin_b).await.is_err());
    assert!(enroll(&a, &at_a, origin_a, origin_a).await.is_ok());
    assert!(enroll(&b, &at_b, origin_b, origin_b).await.is_ok());
}

impl Setup {
    /// The signer revokes `app`, moves it to `removed` at a higher data epoch, then purges
    /// it from there; the switch's status of it in `removed`, and after.
    async fn revoke_and_purge(&self, app: [u8; 16]) -> (AppStatus, AppStatus) {
        self.alice.switch().revoke(app).unwrap();
        self.alice
            .next_doc(|body| {
                body.apps.retain(|a| a.app_id != app);
                body.removed.push(RemovedApp {
                    app_id: app,
                    distrust_from: START_MS,
                });
                body.data_epoch += 1;
            })
            .unwrap();
        let removed = self.status(&app).await;
        self.alice
            .next_doc(|body| body.removed.retain(|r| r.app_id != app))
            .unwrap();
        (removed, self.status(&app).await)
    }
}

#[tokio::test]
async fn test_scripted_apps_purged_at_the_delivery_that_drops_it() {
    let s = Setup::new();
    let app = s.join("wallet").await;
    let id = app.app_id();
    let (removed, purged) = s.revoke_and_purge(id).await;
    // Kept while in `removed`.
    assert!(removed.record_cert.is_some());
    assert!(removed.last_seen.is_some());
    // Then down to its App ID and revocation time, as at the service.
    assert!(!purged.current);
    assert_eq!(purged.revoked_at, removed.revoked_at);
    assert_eq!(
        (
            purged.last_seen,
            purged.record_cert,
            purged.record_at,
            purged.keys_through,
            purged.cert_expires_at,
            purged.unread_entries,
        ),
        (None, None, None, None, None, 0)
    );
    assert!(purged.bundle_ranges.is_empty());
    let held = s.alice.switch().app(&id);
    assert!(held.purged && held.record.is_none() && held.receive_key.is_none());
}

#[tokio::test]
async fn test_scripted_apps_purge_waits_for_the_apps_open_attempt() {
    let s = Setup::new();
    let mut app = s.join("wallet").await;
    let id = app.app_id();
    let (claim_key, attempt_id) = ([5; 32], [6; 16]);
    let deadline = START_MS + DAY_MS;
    app.write_claim(
        ClaimOp::attempt(claim_key, 0, attempt_id, 3600, Some(deadline)),
        vec![],
        ObligationDeadline::At(deadline),
    )
    .await
    .unwrap();
    let (_, dropped) = s.revoke_and_purge(id).await;
    // In neither list, but it owns an open attempt: it keeps everything.
    assert!(dropped.record_cert.is_some());
    assert_eq!(dropped.open_attempts.len(), 1);
    assert!(!s.alice.switch().app(&id).purged);
    // Its last open attempt resolved, it goes.
    s.alice
        .switch()
        .fail_attempt(claim_key, attempt_id, [9; 16]);
    let purged = s.status(&id).await;
    assert!(purged.record_cert.is_none() && purged.open_attempts.is_empty());
    assert!(s.alice.switch().app(&id).purged);
}
