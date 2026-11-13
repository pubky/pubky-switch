//! The app's own record as its protocols change it: a member, `accepts` and `expires_at`,
//! re-signed, delivered with `app.put` and then published on the Homeserver (Switch spec
//! 4.2, 12.1 step 2; Switch wire 2.1, 3.2, 6.2), and signing under a protocol's own label
//! (Switch spec 13.2).

use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::labels;
use pubky_switch_core::records::{AppRecord, AppRecordBody, app_record_path};
use pubky_switch_core::sig::SignedDoc;
use serde_json::Map;

use super::*;
use crate::app::{
    AppError, AppEvent, LeaveMode, PUBLISHED_CHECK_MS, Publication, Refusal, UserConfirmed,
};
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::Fault;

/// The protocol name the tests' member goes under.
const PROTO: &str = "sample";

/// An app that publishes its record.
fn publishing() -> AppConfig {
    AppConfig {
        publishes_record: true,
        ..AppConfig::default()
    }
}

fn member(value: Value) -> Option<Map<String, Value>> {
    match value {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn record_of(app: &App) -> AppRecord {
    AppRecord::verify(app.record(), &app.identity()).unwrap()
}

impl World {
    async fn join_publishing(&self, name: &str) -> App {
        let request = self.approve(&app_keys(name), &["scope-a"]);
        App::join(self.env(), self.protocol.clone(), publishing(), request)
            .await
            .unwrap()
    }

    async fn load_publishing_on(&self, store: Arc<dyn StateStore>, app: [u8; 16]) -> App {
        App::load(self.env_on(store), self.protocol.clone(), publishing(), app)
            .await
            .unwrap()
    }

    /// The record the Homeserver holds for `app`, as its bytes.
    fn published(&self, app: [u8; 16]) -> Option<Vec<u8>> {
        self.homeserver
            .file(self.alice.public(), &app_record_path(&app))
    }

    /// How many times the app's record path was written to.
    fn record_writes(&self, app: [u8; 16]) -> u64 {
        self.homeserver
            .writes(&self.alice.public(), &app_record_path(&app))
    }

    /// The record the switch holds for `app`.
    fn held(&self, app: [u8; 16]) -> Option<SignedDoc> {
        self.switch.app(&app).record
    }

    /// How many `app.put` operations the switch applied.
    fn app_puts(&self) -> usize {
        self.switch
            .applied()
            .iter()
            .filter(|op| matches!(op.body().kind, OpKind::AppPut { .. }))
            .count()
    }
}

fn bytes_of(record: &SignedDoc) -> Vec<u8> {
    serde_json::to_vec(record).unwrap()
}

#[tokio::test]
async fn test_own_record_join_publishes_the_delivered_record() {
    let w = World::new();
    let app = w.join_publishing("wallet").await;
    let id = app.app_id();
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

#[tokio::test]
async fn test_own_record_join_without_publishing_writes_nothing() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let id = app.app_id();
    let publication = app
        .set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    assert_eq!(publication, Publication::NotPublishing);
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    assert_eq!(w.record_writes(id), 0);
    assert!(w.published(id).is_none());
    // Nothing is owed in the store either.
    let ns = crate::store::client_namespace(&id);
    assert!(w.store.get(&ns, b"pending/publish").unwrap().is_none());
}

#[tokio::test]
async fn test_own_record_join_publish_failure_stays_owed_across_a_load() {
    let w = World::new();
    w.homeserver.fail_writes(1, false);
    let id = w.join_publishing("wallet").await.app_id();
    assert!(w.published(id).is_none());
    let mut app = w.load_publishing_on(w.store.clone(), id).await;
    app.receive(None).await.unwrap();
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

#[tokio::test]
async fn test_own_record_load_publishing_needs_a_writer() {
    let w = World::new();
    let id = w.join_publishing("wallet").await.app_id();
    let env = AppEnv {
        homeserver_writer: None,
        ..w.env()
    };
    let error = App::load(env, w.protocol.clone(), publishing(), id)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error}"
    );
    // Without publishing, it needs none.
    let env = AppEnv {
        homeserver_writer: None,
        ..w.env()
    };
    App::load(env, w.protocol.clone(), AppConfig::default(), id)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_own_record_publishing_needs_a_writer() {
    let w = World::new();
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let env = AppEnv {
        homeserver_writer: None,
        ..w.env()
    };
    let error = App::join(env, w.protocol.clone(), publishing(), request)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error}"
    );
    assert_eq!(w.app_puts(), 0);
}

#[tokio::test]
async fn test_own_record_member_set_delivers_then_publishes() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let before = record_of(&app);
    w.clock.advance_ms(1_000);
    let expires = w.clock.now_ms() + 30 * pubky_switch_core::records::DAY_MS;
    let publication = app
        .set_protocol_member(
            PROTO,
            member(json!({ "endpoints": { "x": "y" } })),
            Some(expires),
        )
        .await
        .unwrap();
    assert_eq!(publication, Publication::Published);
    let after = record_of(&app);
    assert!(after.updated_at() > before.updated_at());
    assert_eq!(after.expires_at(), Some(expires));
    assert_eq!(
        after.body().protocol(PROTO),
        member(json!({ "endpoints": { "x": "y" } })).as_ref()
    );
    assert_eq!(after.body().accepts, before.body().accepts);
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
    // Removing the member is a change too.
    w.clock.advance_ms(1_000);
    app.set_protocol_member(PROTO, None, Some(expires))
        .await
        .unwrap();
    assert!(record_of(&app).body().protocol(PROTO).is_none());
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

#[tokio::test]
async fn test_own_record_member_unchanged_signs_nothing() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let value = member(json!({ "a": 1 }));
    app.set_protocol_member(PROTO, value.clone(), None)
        .await
        .unwrap();
    let record = app.record().clone();
    let (puts, writes) = (w.app_puts(), w.record_writes(id));
    w.clock.advance_ms(1_000);
    let publication = app.set_protocol_member(PROTO, value, None).await.unwrap();
    assert_eq!(publication, Publication::Published);
    assert_eq!(app.record(), &record);
    assert_eq!((w.app_puts(), w.record_writes(id)), (puts, writes));
}

#[tokio::test]
async fn test_own_record_member_name_refused() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let record = app.record().clone();
    let puts = w.app_puts();
    for name in ["", "Upper", "_lead", "a:b", &"n".repeat(33)] {
        let error = app
            .set_protocol_member(name, member(json!({})), None)
            .await
            .unwrap_err();
        assert!(
            matches!(error, AppError::Refused(Refusal::Usage(_))),
            "{name}: {error}"
        );
    }
    assert_eq!(app.record(), &record);
    assert_eq!(w.app_puts(), puts);
}

#[tokio::test]
async fn test_own_record_member_the_switch_would_refuse_is_refused_before_it_is_kept() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let record = app.record().clone();
    let puts = w.app_puts();
    // Numbers outside the integer rule (Switch wire 1.1), and a record over the operation
    // cap (Switch wire 6.1).
    let huge = "x".repeat(pubky_switch_core::ops::MAX_OP_BYTES);
    for value in [
        json!({ "n": 1.5 }),
        json!({ "n": -1 }),
        json!({ "s": huge }),
    ] {
        let error = app
            .set_protocol_member(PROTO, member(value), None)
            .await
            .unwrap_err();
        assert!(
            matches!(error, AppError::Refused(Refusal::Usage(_))),
            "{error}"
        );
        assert_eq!(app.record(), &record);
    }
    assert_eq!(w.app_puts(), puts);
    // Nothing is owed: the next read delivers nothing.
    app.receive(None).await.unwrap();
    assert_eq!(w.app_puts(), puts);
    assert_eq!(w.held(id), Some(record));
    let reloaded = w.load_publishing_on(w.store.clone(), id).await;
    assert_eq!(reloaded.record(), app.record());
}

#[tokio::test]
async fn test_own_record_renewal_signs_again_with_the_same_members() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let expires = w.clock.now_ms() + pubky_switch_core::records::DAY_MS;
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), Some(expires))
        .await
        .unwrap();
    let before = record_of(&app);
    w.clock.advance_ms(1_000);
    // The same expiry still renews: a new updated_at.
    app.renew_record(Some(expires)).await.unwrap();
    let renewed = record_of(&app);
    assert!(renewed.updated_at() > before.updated_at());
    assert_eq!(renewed.body().protocols, before.body().protocols);
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
    // A record that doesn't expire.
    app.renew_record(None).await.unwrap();
    assert_eq!(record_of(&app).expires_at(), None);
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
}

#[tokio::test]
async fn test_own_record_updated_at_later_than_the_held_one_on_a_clock_behind() {
    let w = World::new();
    let id = w.join_publishing("wallet").await.app_id();
    // The device's clock is a minute behind the one the record was made by: the record still
    // moves forward (Switch spec 4.2).
    let clock = Arc::new(crate::clock::TestClock::new(w.clock.now_ms() - 60_000));
    let env = AppEnv {
        clock: clock as Arc<dyn Clock>,
        ..w.env()
    };
    let mut app = App::load(env, w.protocol.clone(), publishing(), id)
        .await
        .unwrap();
    let before = record_of(&app);
    // Signed and kept before anything is sent: the switch isn't reached.
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    app.renew_record(None).await.unwrap_err();
    assert_eq!(record_of(&app).updated_at(), before.updated_at() + 1);
    app.publish_record().await.unwrap();
    assert_eq!(record_of(&app).updated_at(), before.updated_at() + 1);
    assert_eq!(w.held(app.app_id()).as_ref(), Some(app.record()));
}

#[tokio::test]
async fn test_own_record_conflict_with_another_device_is_written_again_later() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    // Another device of the app delivered a record at the time this one is about to use.
    let mut other = AppRecordBody::new(app.cert(), Vec::new(), w.clock.now_ms());
    other.label = Some("other device".into());
    let other = AppRecord::sign(&app_keys("wallet"), other).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: other.signed().clone(),
            },
        )
        .unwrap();
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    let mine = record_of(&app);
    assert_eq!(mine.updated_at(), other.updated_at() + 1);
    assert!(mine.body().protocol(PROTO).is_some());
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

/// Switch spec 4.2: the record is delivered with `app.put` before it is published, so a
/// refused delivery publishes nothing.
#[tokio::test]
async fn test_own_record_refused_delivery_publishes_nothing() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let published = w.published(id);
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Error {
        path: "/ops".into(),
        code: ErrorCode::NotCurrent,
        current: json!({}),
    });
    let error = app
        .set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotCurrent), "{error}");
    assert_ne!(w.held(id).as_ref(), Some(app.record()));
    assert_eq!(w.published(id), published);
    // The record stays kept, and the next read delivers and publishes it.
    app.receive(None).await.unwrap();
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

#[tokio::test]
async fn test_own_record_lost_answer_is_settled_by_the_same_bytes() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let published = w.published(id);
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    // The switch took it; the app doesn't know yet, so nothing is published.
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    assert_eq!(w.published(id), published);
    let puts = w.app_puts();
    let mut loaded = w.load_publishing_on(w.store.clone(), id).await;
    loaded.receive(None).await.unwrap();
    // Sent again as it was: no second write at the switch.
    assert_eq!(w.app_puts(), puts);
    assert_eq!(loaded.record(), app.record());
    assert_eq!(w.published(id), Some(bytes_of(loaded.record())));
}

#[tokio::test]
async fn test_own_record_unreachable_switch_keeps_the_record() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let held = w.held(id);
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    assert_eq!(w.held(id), held);
    let publication = app.publish_record().await.unwrap();
    assert_eq!(publication, Publication::Published);
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

/// Switch spec 4.2: a publication that failed is published again.
#[tokio::test]
async fn test_own_record_homeserver_failure_stays_owed() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let published = w.published(id);
    w.clock.advance_ms(1_000);
    w.homeserver.fail_writes(1, false);
    let publication = app
        .set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    assert!(
        matches!(publication, Publication::Owed { .. }),
        "{publication:?}"
    );
    // The switch holds the record either way.
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    // Meanwhile readers of the Homeserver see the earlier record, as published at join; a
    // reader of both copies takes the switch's, its `updated_at` being later (Switch spec
    // 4.2).
    assert_eq!(w.published(id), published);
    let earlier: SignedDoc = serde_json::from_slice(&published.unwrap()).unwrap();
    let earlier = AppRecord::verify(&earlier, &w.alice.public()).unwrap();
    assert!(earlier.body().protocol(PROTO).is_none());
    assert!(earlier.updated_at() < record_of(&app).updated_at());
    // Owed across a load; the read publishes it and reports nothing failed.
    let mut loaded = w.load_publishing_on(w.store.clone(), id).await;
    let report = loaded.receive(None).await.unwrap();
    assert_eq!(w.published(id), Some(bytes_of(loaded.record())));
    assert!(
        !report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::RecordPublishFailed { .. })),
        "{:?}",
        report.events
    );
    let writes = w.record_writes(id);
    loaded.receive(None).await.unwrap();
    assert_eq!(w.record_writes(id), writes);
}

#[tokio::test]
async fn test_own_record_homeserver_failure_at_a_read_doesnt_fail_it() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.homeserver.fail_writes(2, false);
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::RecordPublishFailed { .. })),
        "{:?}",
        report.events
    );
    assert_ne!(w.published(id), Some(bytes_of(app.record())));
    app.receive(None).await.unwrap();
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

#[tokio::test]
async fn test_own_record_homeserver_lost_answer_is_settled_by_the_copy() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.homeserver.fail_writes(1, true);
    let publication = app
        .set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    assert!(matches!(publication, Publication::Owed { .. }));
    let writes = w.record_writes(id);
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
    // The copy read first is the record already: nothing more is written, and nothing is
    // owed from then on.
    assert_eq!(app.publish_record().await.unwrap(), Publication::Published);
    assert_eq!(w.record_writes(id), writes);
    assert!(app.state.pending_publish.is_none());
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

/// The wallet joined on `w.store`, loaded again on a store that fails as `fault` says.
async fn on_faulty_store(w: &World, fault: StoreFault) -> (App, Arc<FaultStore>) {
    let id = w.join_publishing("wallet").await.app_id();
    let faulty = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        fault,
    ));
    let app = w
        .load_publishing_on(Arc::clone(&faulty) as Arc<dyn StateStore>, id)
        .await;
    assert_eq!(faulty.commits(), 0);
    w.clock.advance_ms(1_000);
    (app, faulty)
}

#[tokio::test]
async fn test_own_record_crash_before_the_record_is_kept_sends_nothing() {
    let w = World::new();
    let (mut app, _) = on_faulty_store(&w, StoreFault::FailBefore(1)).await;
    let id = app.app_id();
    let (held, published, puts) = (w.held(id), w.published(id), w.app_puts());
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    assert_eq!(w.app_puts(), puts);
    let mut loaded = w.load_publishing_on(w.store.clone(), id).await;
    loaded.receive(None).await.unwrap();
    assert_eq!(w.app_puts(), puts);
    assert_eq!(w.held(id), held);
    assert_eq!(loaded.record(), held.as_ref().unwrap());
    assert_eq!(w.published(id), published);
}

#[tokio::test]
async fn test_own_record_crash_after_the_record_is_kept_sends_it_on_load() {
    let w = World::new();
    let (mut app, _) = on_faulty_store(&w, StoreFault::StopAfter(1)).await;
    let id = app.app_id();
    let (held, published) = (w.held(id), w.published(id));
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    // Kept, not sent.
    assert_eq!(w.held(id), held);
    assert_eq!(w.published(id), published);
    let mut loaded = w.load_publishing_on(w.store.clone(), id).await;
    assert!(record_of(&loaded).body().protocol(PROTO).is_some());
    loaded.receive(None).await.unwrap();
    assert_eq!(w.held(id).as_ref(), Some(loaded.record()));
    assert_eq!(w.published(id), Some(bytes_of(loaded.record())));
}

#[tokio::test]
async fn test_own_record_crash_before_the_answer_is_kept_publishes_after_the_resend() {
    let w = World::new();
    let (mut app, _) = on_faulty_store(&w, StoreFault::FailBefore(2)).await;
    let id = app.app_id();
    let published = w.published(id);
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    // The switch holds it; the answer isn't kept, so nothing is published yet.
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    assert_eq!(w.published(id), published);
    let puts = w.app_puts();
    let mut loaded = w.load_publishing_on(w.store.clone(), id).await;
    loaded.receive(None).await.unwrap();
    assert_eq!(w.app_puts(), puts);
    assert_eq!(w.published(id), Some(bytes_of(loaded.record())));
}

#[tokio::test]
async fn test_own_record_crash_after_the_answer_is_kept_publishes_on_load() {
    let w = World::new();
    let (mut app, _) = on_faulty_store(&w, StoreFault::StopAfter(2)).await;
    let id = app.app_id();
    let published = w.published(id);
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    assert_eq!(w.published(id), published);
    let puts = w.app_puts();
    let mut loaded = w.load_publishing_on(w.store.clone(), id).await;
    loaded.receive(None).await.unwrap();
    // Nothing is delivered again: the store knows the switch holds it.
    assert_eq!(w.app_puts(), puts);
    assert_eq!(w.published(id), Some(bytes_of(loaded.record())));
}

#[tokio::test]
async fn test_own_record_crash_after_publishing_is_settled_by_the_copy() {
    let w = World::new();
    let (mut app, _) = on_faulty_store(&w, StoreFault::FailBefore(3)).await;
    let id = app.app_id();
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
    let writes = w.record_writes(id);
    let mut loaded = w.load_publishing_on(w.store.clone(), id).await;
    loaded.receive(None).await.unwrap();
    // Owed across the crash; the copy read first is the record, so nothing is written.
    assert_eq!(w.record_writes(id), writes);
    assert!(loaded.state.pending_publish.is_none());
    assert_eq!(w.published(id), Some(bytes_of(loaded.record())));
}

/// [`SampleProtocol`] whose `accepts` a test narrows.
#[derive(Default)]
struct Narrowing {
    sample: SampleProtocol,
    only: Mutex<Option<Vec<String>>>,
}

impl Protocol for Narrowing {
    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }
    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }
    fn check_scopes(&self, m: &Message, s: &AppCert, o: &AppCert) -> Result<(), String> {
        self.sample.check_scopes(m, s, o)
    }
    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.only
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| self.sample.accepts(cert))
    }
    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(message)
    }
    fn resend_needed(&self, n: &ResendNeeded) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.resend_needed(n)
    }
    fn missed(&self, m: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.missed(m)
    }
}

#[tokio::test]
async fn test_own_record_accepts_follow_the_protocol() {
    let w = World::new();
    let protocol = Arc::new(Narrowing::default());
    let request = w.approve(&app_keys("wallet"), &["scope-a"]);
    let mut app = App::join(w.env(), protocol.clone(), publishing(), request)
        .await
        .unwrap();
    let id = app.app_id();
    let record = app.record().clone();
    // Unchanged: nothing is signed.
    app.update_accepts().await.unwrap();
    assert_eq!(app.record(), &record);
    *protocol.only.lock().unwrap() = Some(vec!["sample.note".into()]);
    w.clock.advance_ms(1_000);
    app.update_accepts().await.unwrap();
    assert_eq!(
        record_of(&app).body().accepts,
        vec!["sample.note".to_owned()]
    );
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

#[tokio::test]
async fn test_own_record_changes_refused_once_left() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    app.leave(LeaveMode::Immediate(UserConfirmed::new()))
        .await
        .unwrap();
    let writes = w.record_writes(id);
    for error in [
        app.set_protocol_member(PROTO, member(json!({})), None)
            .await
            .unwrap_err(),
        app.renew_record(None).await.unwrap_err(),
        app.publish_record().await.unwrap_err(),
        app.sign_protocol("sample/v1/grant", &[b"x"]).unwrap_err(),
    ] {
        assert!(matches!(error, AppError::Refused(Refusal::Left)), "{error}");
    }
    assert_eq!(w.record_writes(id), writes);
}

#[tokio::test]
async fn test_own_record_sign_protocol_verifies_under_its_label() {
    let w = World::new();
    let app = w.join("wallet").await;
    let fields: [&[u8]; 2] = [b"grantee", &[7; 32]];
    let sig = app.sign_protocol("sample/v1/grant", &fields).unwrap();
    let key = app.cert().signing_key();
    pubky_switch_core::sig::verify(&key, "sample/v1/grant", &fields, &sig).unwrap();
    // Under any other label, or other fields, it doesn't verify.
    assert!(pubky_switch_core::sig::verify(&key, "sample/v1/other", &fields, &sig).is_err());
    assert!(pubky_switch_core::sig::verify(&key, "sample/v1/grant", &fields[..1], &sig).is_err());
}

#[tokio::test]
async fn test_own_record_sign_protocol_refuses_a_switch_label() {
    let w = World::new();
    let app = w.join("wallet").await;
    for label in [
        labels::sig::APP_RECORD,
        labels::sig::MSG,
        labels::sig::OP,
        labels::sig::HTTP,
        labels::sig::RECEIVE_KEY,
        labels::sig::APP_REQUEST,
        "pubky-switch/v1/any-later-format",
        "pubky-switch/v2/app-record",
        "pubky-switch/v9/any",
        "pubky-switch/",
    ] {
        let error = app.sign_protocol(label, &[b"body"]).unwrap_err();
        assert!(
            matches!(error, AppError::Refused(Refusal::Usage(_))),
            "{label}: {error}"
        );
    }
}

#[tokio::test]
async fn test_own_record_renewed_certificate_is_republished() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let me = app.app_id();
    let old = app.cert().clone();
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms() + 1000,
        &["scope-a"],
    );
    w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: me,
            cert: renewed.signed().clone(),
        })
        .unwrap();
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.apps.push(ListedApp {
            app_id: me,
            cert: renewed.hash(),
        });
        body.renewed.push(pubky_switch_core::records::RenewedCert {
            app_id: me,
            cert: old.hash(),
            until: None,
        });
    });
    // The Homeserver fails at the read's tries, at the delivery and after the feed: the
    // record carrying the new certificate is delivered, and published at the next read
    // (Switch spec 3.2 step 3).
    w.homeserver.fail_writes(2, false);
    app.receive(None).await.unwrap();
    assert_eq!(app.cert().hash(), renewed.hash());
    assert_eq!(w.held(me).as_ref(), Some(app.record()));
    assert_ne!(w.published(me), Some(bytes_of(app.record())));
    app.receive(None).await.unwrap();
    let published: SignedDoc = serde_json::from_slice(&w.published(me).unwrap()).unwrap();
    assert_eq!(&published, app.record());
    let record = AppRecord::verify(&published, &w.alice.public()).unwrap();
    assert_eq!(record.cert().hash(), renewed.hash());
}

/// Switch spec 4.2: the newest record the switch accepted is the one published. A first
/// record whose publication failed is never written over a later one.
#[tokio::test]
async fn test_own_record_failed_publication_never_puts_an_older_record_over_a_newer() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    w.homeserver.fail_writes(1, false);
    let first = app
        .set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    assert!(matches!(first, Publication::Owed { .. }));
    let r1 = app.record().clone();
    w.clock.advance_ms(1_000);
    let second = app
        .set_protocol_member(PROTO, member(json!({ "a": 2 })), None)
        .await
        .unwrap();
    assert_eq!(second, Publication::Published);
    let r2 = app.record().clone();
    assert_ne!(r1, r2);
    assert_eq!(w.published(id), Some(bytes_of(&r2)));
    // Later reads and publications keep the newer one.
    w.clock.advance_ms(PUBLISHED_CHECK_MS);
    app.receive(None).await.unwrap();
    app.publish_record().await.unwrap();
    let mut loaded = w.load_publishing_on(w.store.clone(), id).await;
    loaded.receive(None).await.unwrap();
    assert_eq!(w.published(id), Some(bytes_of(&r2)));
}

/// Switch spec 4.2: a Homeserver copy that differs from the newest record the switch
/// accepted is replaced by it, at the read after the copy's check is due, or at once on
/// `publish_record`.
#[tokio::test]
async fn test_own_record_copy_that_differs_is_replaced_by_the_newest_accepted() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let path = app_record_path(&id);
    app.receive(None).await.unwrap();
    w.homeserver
        .put(w.alice.public(), &path, b"not a record".to_vec());
    // Checked at most once per PUBLISHED_CHECK_MS while nothing is owed.
    app.receive(None).await.unwrap();
    assert_eq!(w.published(id), Some(b"not a record".to_vec()));
    w.clock.advance_ms(PUBLISHED_CHECK_MS);
    app.receive(None).await.unwrap();
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
    // Gone from the Homeserver: written again on publish_record.
    w.homeserver.remove(w.alice.public(), &path);
    assert_eq!(app.publish_record().await.unwrap(), Publication::Published);
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

/// Switch spec 4.2, 12.3: a publishing app leaves in two steps, deleting its Homeserver
/// record and then calling `leave`; nothing is published from the commit that starts the
/// leave on, across a restart between the two.
#[tokio::test]
async fn test_own_record_leave_deletes_the_record_and_publishes_nothing_after() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    assert!(w.published(id).is_some());
    w.switch.fail_next(Fault::Unreachable {
        path: "leave".into(),
        after: 0,
    });
    app.leave(LeaveMode::TwoStep).await.unwrap_err();
    assert!(w.published(id).is_none());
    let writes = w.record_writes(id);
    drop(app);
    let mut app = w.load_publishing_on(w.store.clone(), id).await;
    app.receive(None).await.unwrap_err();
    app.publish_record().await.unwrap_err();
    w.clock.advance_ms(PUBLISHED_CHECK_MS);
    app.receive(None).await.unwrap_err();
    assert!(w.published(id).is_none());
    assert_eq!(w.record_writes(id), writes);
    // The leave goes on, and still publishes nothing.
    app.leave(LeaveMode::TwoStep).await.unwrap();
    assert!(w.published(id).is_none());
    assert_eq!(w.record_writes(id), writes);
}

/// Switch spec 4.2: a Homeserver copy with a later `updated_at` is never written over, as
/// after a restore from a backup older than the record published since.
#[tokio::test]
async fn test_own_record_restore_from_an_older_backup_never_rolls_the_copy_back() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    app.receive(None).await.unwrap();
    let backup = app.backup().await.unwrap();
    w.clock.advance_ms(1_000);
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    let newer = app.record().clone();
    assert_eq!(w.published(id), Some(bytes_of(&newer)));
    drop(app);
    let mut restored = App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        w.protocol.clone(),
        publishing(),
        &backup,
    )
    .await
    .unwrap();
    assert_ne!(restored.record(), &newer);
    assert_eq!(
        restored.publish_record().await.unwrap(),
        Publication::Superseded
    );
    assert_eq!(w.published(id), Some(bytes_of(&newer)));
}

/// A key of the app's own that no device of it made is registered: a compromise.
fn register_foreign_key(w: &World, app: &App) {
    use pubky_switch_core::keys::ReceiveKey;
    use pubky_switch_core::records::{ReceiveKeyBody, ReceiveKeyRecord};
    let foreign = ReceiveKey::from_secret(1, [42; 32]);
    let record = ReceiveKeyRecord::sign(
        &app_keys("wallet"),
        app.cert(),
        ReceiveKeyBody::new(app.cert(), &foreign),
    )
    .unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::ReceiveKeyPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
}

/// Switch spec 3.6, 12.3: on a compromise a publishing app leaves at once. Its Homeserver
/// down, the delete fails, and the app leaves at the switch all the same, in the read that
/// raised the alarm, and publishes nothing after.
#[tokio::test]
async fn test_own_record_compromise_leave_goes_with_the_homeserver_down() {
    use crate::app::Alarm;
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    register_foreign_key(&w, &app);
    w.homeserver.set_down(true);
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(error, AppError::Alarm(Alarm::Compromise { n: 1, .. })),
        "{error:?}"
    );
    assert!(w.switch.app(&id).departed, "the leave waited on the delete");
    let writes = w.record_writes(id);
    w.homeserver.set_down(false);
    app.receive(None).await.unwrap_err();
    assert_eq!(w.record_writes(id), writes);
}

/// An immediate leave goes on when the delete fails, reporting it; a two-step leave waits
/// for the delete, and calls `leave` once it is made (Switch spec 12.3).
#[tokio::test]
async fn test_own_record_only_a_two_step_leave_waits_for_the_delete() {
    let w = World::new();
    let mut two_step = w.join_publishing("wallet").await;
    let id = two_step.app_id();
    w.homeserver.set_down(true);
    let error = two_step.leave(LeaveMode::TwoStep).await.unwrap_err();
    assert!(matches!(error, AppError::Transport(_)), "{error:?}");
    assert!(!w.switch.app(&id).departed);
    w.homeserver.set_down(false);
    two_step.leave(LeaveMode::TwoStep).await.unwrap();
    assert!(w.switch.app(&id).departed);
    assert!(w.published(id).is_none());

    let mut immediate = w.join_publishing("phone").await;
    let id = immediate.app_id();
    w.homeserver.set_down(true);
    immediate
        .leave(LeaveMode::Immediate(UserConfirmed::new()))
        .await
        .unwrap();
    assert!(w.switch.app(&id).departed);
    assert!(
        immediate
            .take_events()
            .iter()
            .any(|e| matches!(e, AppEvent::RecordPublishFailed { .. }))
    );
}

/// The wallet restored on a store of its own from `backup`.
async fn restored_publishing(w: &World, backup: &crate::app::AppBackup) -> App {
    App::restore(
        w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        w.protocol.clone(),
        publishing(),
        backup,
    )
    .await
    .unwrap()
}

/// Switch spec 4.2: a backup taken while a record's `app.put` was refused carries the
/// accepted record apart. The restored app publishes only that one, never the refused
/// record it holds; the protocol's next change delivers the record held again, signed
/// anew, and publishes it once the switch accepts it.
#[tokio::test]
async fn test_own_record_restore_never_publishes_a_record_the_switch_refused() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let accepted = w.held(id);
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Error {
        path: "/ops".into(),
        code: ErrorCode::NotCurrent,
        current: json!({}),
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    let refused = app.record().clone();
    let backup = app.backup().await.unwrap();
    drop(app);
    let mut restored = restored_publishing(&w, &backup).await;
    assert_eq!(restored.record(), &refused);
    restored.receive(None).await.unwrap();
    assert_eq!(
        restored.publish_record().await.unwrap(),
        Publication::Published
    );
    assert_eq!(w.held(id), accepted);
    assert_eq!(w.published(id), accepted.as_ref().map(bytes_of));
    // The protocol sets its member again: signed anew, delivered, then published.
    w.clock.advance_ms(1_000);
    restored
        .set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap();
    assert_ne!(restored.record(), &refused);
    assert_eq!(
        record_of(&restored).body().protocol(PROTO),
        member(json!({ "a": 1 })).as_ref()
    );
    assert_eq!(w.held(id).as_ref(), Some(restored.record()));
    assert_eq!(w.published(id), Some(bytes_of(restored.record())));
}

/// As above, the `app.put` never answered when the backup was taken: a restored read
/// publishes the accepted record, never the one held.
#[tokio::test]
async fn test_own_record_restore_never_publishes_a_record_never_delivered() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let accepted = w.held(id);
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    let undelivered = app.record().clone();
    let backup = app.backup().await.unwrap();
    drop(app);
    let mut restored = restored_publishing(&w, &backup).await;
    restored.receive(None).await.unwrap();
    w.clock.advance_ms(PUBLISHED_CHECK_MS);
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    restored.receive(None).await.unwrap();
    assert_eq!(w.held(id), accepted);
    assert_ne!(w.published(id), Some(bytes_of(&undelivered)));
    assert_eq!(w.published(id), accepted.as_ref().map(bytes_of));
}

/// A backup carrying no accepted record publishes nothing once restored, until the switch
/// accepts one of the app's.
#[tokio::test]
async fn test_own_record_restore_without_an_accepted_record_publishes_nothing() {
    let w = World::new();
    let app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let mut backup = serde_json::to_value(app.backup().await.unwrap()).unwrap();
    backup.as_object_mut().unwrap().remove("accepted").unwrap();
    let backup: crate::app::AppBackup = serde_json::from_value(backup).unwrap();
    drop(app);
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    let mut restored = restored_publishing(&w, &backup).await;
    assert_eq!(
        restored.publish_record().await.unwrap(),
        Publication::NothingAccepted
    );
    assert!(w.published(id).is_none());
}

/// Switch spec 4.2: a restore of an app that publishes needs a Homeserver writer, as a join
/// and a load do; nothing is written without one.
#[tokio::test]
async fn test_own_record_restore_publishing_needs_a_writer() {
    let w = World::new();
    let app = w.join_publishing("wallet").await;
    let backup = app.backup().await.unwrap();
    drop(app);
    let env = AppEnv {
        homeserver_writer: None,
        ..w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>)
    };
    let error = App::restore(env, w.protocol.clone(), publishing(), &backup)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::Usage(_))),
        "{error}"
    );
}

/// A `409 conflict` naming no record is a refusal: nothing is noted or published, and the
/// record goes again at the next read.
#[tokio::test]
async fn test_own_record_conflict_naming_no_record_publishes_nothing() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let accepted = w.held(id);
    let published = w.published(id);
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Error {
        path: "/ops".into(),
        code: ErrorCode::Conflict,
        current: json!({}),
    });
    let error = app
        .set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict), "{error}");
    assert_eq!(w.held(id), accepted);
    assert_eq!(w.published(id), published);
    assert!(app.state.pending_publish.is_none());
    assert_ne!(app.state.accepted.as_ref(), Some(app.record()));
    app.receive(None).await.unwrap();
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

/// A re-send whose first send the switch applied, answered `409 conflict` naming no record,
/// as a batch held without its proofs is (Switch wire 6.4 step 5): the switch's directory
/// shows it holds the record, so it is delivered and published.
#[tokio::test]
async fn test_own_record_conflict_on_a_resend_the_switch_holds_is_delivered() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    assert_eq!(w.held(id).as_ref(), Some(app.record()));
    w.switch.fail_next(Fault::Error {
        path: "/ops".into(),
        code: ErrorCode::Conflict,
        current: json!({}),
    });
    assert_eq!(app.publish_record().await.unwrap(), Publication::Published);
    assert_eq!(app.state.accepted.as_ref(), Some(app.record()));
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

/// Nothing owed and the check's read failing: nothing failed is reported, and the next read
/// checks the copy again.
#[tokio::test]
async fn test_own_record_check_that_cant_read_owes_nothing() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.homeserver.set_down(true);
    let publication = app.publish_record().await.unwrap();
    assert!(
        matches!(publication, Publication::Unchecked { .. }),
        "{publication:?}"
    );
    assert!(app.state.pending_publish.is_none());
    assert!(
        !app.take_events()
            .iter()
            .any(|e| matches!(e, AppEvent::RecordPublishFailed { .. }))
    );
    w.homeserver.set_down(false);
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    app.receive(None).await.unwrap();
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

/// A check that finds the copy missing and fails to write it back owes the publication:
/// the next read writes it, without waiting out the check's interval.
#[tokio::test]
async fn test_own_record_failed_repair_goes_again_at_the_next_read() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.clock.advance_ms(PUBLISHED_CHECK_MS);
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    w.homeserver.fail_writes(1, false);
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::RecordPublishFailed { .. })),
        "{:?}",
        report.events
    );
    assert!(w.published(id).is_none());
    w.clock.advance_ms(1_000);
    app.receive(None).await.unwrap();
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

/// Switch spec 4.2, 12.3: an app whose devices share its keys writes a missing copy back
/// only in a read, after its feed. So when one device leaves, deleting the record, another
/// device's read sees the departure in its feed first, and writes nothing.
#[tokio::test]
async fn test_own_record_other_device_never_writes_back_a_record_deleted_to_leave() {
    let w = World::new();
    let mut a = w.join_publishing("wallet").await;
    let id = a.app_id();
    let path = app_record_path(&id);
    a.set_multi_device(true).await.unwrap();
    let backup = a.backup().await.unwrap();
    let mut b = restored_publishing(&w, &backup).await;
    b.receive(None).await.unwrap();
    b.end_reconcile(UserConfirmed::new()).await.ok();
    // A missing copy waits for a read, and the read writes it back after its feed.
    w.homeserver.remove(w.alice.public(), &path);
    assert_eq!(a.publish_record().await.unwrap(), Publication::AwaitingRead);
    assert!(w.published(id).is_none());
    a.receive(None).await.unwrap();
    assert_eq!(w.published(id), Some(bytes_of(a.record())));
    // B leaves: A's next read, its check due, writes nothing back.
    b.leave(LeaveMode::Immediate(UserConfirmed::new()))
        .await
        .unwrap();
    assert!(w.published(id).is_none());
    let writes = w.record_writes(id);
    w.clock.advance_ms(PUBLISHED_CHECK_MS);
    let _ = a.receive(None).await;
    assert!(w.published(id).is_none());
    assert_eq!(w.record_writes(id), writes);
}

/// Switch spec 12.3: the leave's state is committed before the Homeserver record is
/// deleted. A store that stops at that commit leaves the record published and the app
/// current; the load after goes on with the whole leave.
#[tokio::test]
async fn test_own_record_crash_before_the_leave_is_kept_deletes_nothing() {
    let w = World::new();
    let (mut app, _) = on_faulty_store(&w, StoreFault::StopBefore(1)).await;
    let id = app.app_id();
    let published = w.published(id);
    assert!(published.is_some());
    app.leave(LeaveMode::TwoStep).await.unwrap_err();
    assert_eq!(w.published(id), published);
    assert!(!w.switch.app(&id).departed);
    let mut loaded = w.load_publishing_on(w.store.clone(), id).await;
    loaded.leave(LeaveMode::TwoStep).await.unwrap();
    assert!(w.published(id).is_none());
    assert!(w.switch.app(&id).departed);
}

/// Switch spec 4.2: the kept record goes to the switch at the start of a read, before the
/// feed, so a read whose feed fails still delivers it.
#[tokio::test]
async fn test_own_record_kept_record_goes_before_the_feed() {
    let w = World::new();
    let mut app = w.join("wallet").await;
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    let kept = app.record().clone();
    assert_ne!(w.held(id).as_ref(), Some(&kept));
    w.switch.fail_next(Fault::Unreachable {
        path: "/feed".into(),
        after: 0,
    });
    app.receive(None).await.unwrap_err();
    assert_eq!(w.held(id).as_ref(), Some(&kept));
    assert!(app.state.pending_record.is_none());
}

/// Switch spec 4.2: a read publishes a record it delivers before its feed right away, the
/// switch's acceptance showing the app current, also when the read then fails.
#[tokio::test]
async fn test_own_record_read_publishes_the_record_it_delivers_before_the_feed() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    let kept = app.record().clone();
    w.switch.fail_next(Fault::Unreachable {
        path: "/feed".into(),
        after: 0,
    });
    app.receive(None).await.unwrap_err();
    assert_eq!(w.held(id).as_ref(), Some(&kept));
    assert_eq!(w.published(id), Some(bytes_of(&kept)));
}

/// Switch spec 4.2, wire 6.4 step 5: the switch applied the kept record, its answer lost,
/// and another device of the app put a later one. Once the switch forgets the batch's
/// proofs, the re-send gets `409 conflict` naming no record, and the directory shows the
/// later record: the kept one is superseded. It is dropped, and the later record, which
/// carries the certificate the app presents, taken as the accepted record and the one the
/// app presents; nothing is published or signed again over it, and the reads go on.
#[tokio::test]
async fn test_own_record_conflict_on_a_resend_a_later_record_superseded_is_dropped() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    let kept = app.record().clone();
    assert_eq!(w.held(id).as_ref(), Some(&kept));
    // Another device of the app puts a later record, and publishes it.
    w.clock.advance_ms(1_000);
    let mut later = AppRecordBody::new(app.cert(), Vec::new(), w.clock.now_ms());
    later.label = Some("other device".into());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    w.homeserver.put(
        w.alice.public(),
        &app_record_path(&id),
        bytes_of(later.signed()),
    );
    // This device stays offline until the switch forgets the batch's proofs.
    w.clock.advance_ms(pubky_switch_core::ops::BATCH_PROOFS_MS);
    let puts = w.app_puts();
    app.receive(None).await.unwrap();
    assert!(app.state.pending_record.is_none());
    assert_eq!(app.state.accepted.as_ref(), Some(later.signed()));
    assert_eq!(app.record(), later.signed());
    assert_eq!(w.app_puts(), puts, "signed again over the later record");
    assert_eq!(w.held(id).as_ref(), Some(later.signed()));
    assert_eq!(w.published(id), Some(bytes_of(later.signed())));
    app.receive(None).await.unwrap();
    // The next change builds on the later record: the other device's label stays.
    w.clock.advance_ms(1_000);
    app.set_protocol_member(PROTO, member(json!({ "b": 2 })), None)
        .await
        .unwrap();
    let held = AppRecord::verify(&w.held(id).unwrap(), &app.identity()).unwrap();
    assert_eq!(held.body().label.as_deref(), Some("other device"));
    assert_eq!(
        held.body().protocol(PROTO),
        member(json!({ "b": 2 })).as_ref()
    );
    assert!(held.updated_at() > later.updated_at());
}

/// Switch spec 4.2: a read publishes only once its feed shows the app current, so an app
/// revoked while offline, whose record the signer's clean-up deleted, writes nothing back.
#[tokio::test]
async fn test_own_record_revoked_app_writes_no_copy_back() {
    use pubky_switch_core::records::RemovedApp;
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    app.receive(None).await.unwrap();
    w.switch.revoke(id).unwrap();
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != id);
        body.removed.push(RemovedApp {
            app_id: id,
            distrust_from: START,
        });
    });
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    w.clock.advance_ms(PUBLISHED_CHECK_MS);
    let outcome = app.receive(None).await;
    assert!(
        w.published(id).is_none(),
        "a revoked app wrote its record back: {outcome:?}"
    );
}

/// Switch spec 12.3: a delete that fails holds back no immediate leave, also one asked for
/// after a two-step leave whose delete failed.
#[tokio::test]
async fn test_own_record_immediate_leave_after_a_failed_two_step_one_goes_ahead() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.homeserver.set_down(true);
    app.leave(LeaveMode::TwoStep).await.unwrap_err();
    assert!(!w.switch.app(&id).departed);
    app.leave(LeaveMode::Immediate(UserConfirmed::new()))
        .await
        .unwrap();
    assert!(w.switch.app(&id).departed);
    assert!(
        app.take_events()
            .iter()
            .any(|e| matches!(e, AppEvent::RecordPublishFailed { .. }))
    );
}

/// Switch spec 3.6, 12.3: a leave after a compromise goes without the delete, also a
/// two-step one asked for once the compromise's own leave failed.
#[tokio::test]
async fn test_own_record_two_step_leave_after_a_compromise_goes_without_the_delete() {
    use crate::app::Alarm;
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    register_foreign_key(&w, &app);
    w.homeserver.set_down(true);
    w.switch.fail_next(Fault::Unreachable {
        path: "/leave".into(),
        after: 0,
    });
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(error, AppError::Alarm(Alarm::Compromise { n: 1, .. })),
        "{error:?}"
    );
    assert!(!w.switch.app(&id).departed);
    let outcome = app.leave(LeaveMode::TwoStep).await;
    assert!(
        w.switch.app(&id).departed,
        "the leave waited on the delete: {outcome:?}"
    );
}

/// An app whose devices share its keys owes a missing copy's write-back to its next read.
/// When owing it fails to commit, the check that found the copy missing counts for
/// nothing: the next healthy read writes the copy back at once, without waiting out
/// [`PUBLISHED_CHECK_MS`] (Switch spec 4.2).
#[tokio::test]
async fn test_own_record_failed_save_of_an_owed_write_back_doesnt_delay_it() {
    let w = World::new();
    let id = w.join_publishing("wallet").await.app_id();
    let faulty = Arc::new(FaultStore::new(
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    let mut app = w
        .load_publishing_on(Arc::clone(&faulty) as Arc<dyn StateStore>, id)
        .await;
    app.set_multi_device(true).await.unwrap();
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    faulty.fail_put_once(b"pending/publish");
    let error = app.publish_record().await.unwrap_err();
    assert!(matches!(error, AppError::Store(_)), "{error:?}");
    assert!(w.published(id).is_none());
    w.clock.advance_ms(1_000);
    app.receive(None).await.unwrap();
    assert_eq!(w.published(id), Some(bytes_of(app.record())));
}

/// An app whose devices share its keys holds a kept record; another device
/// leaves, deleting the Homeserver copy. The kept record's `app.put` at the read's start is
/// refused, so the read's own publication never writes the copy back.
#[tokio::test]
async fn test_own_record_kept_record_after_another_device_left_writes_nothing_back() {
    let w = World::new();
    let mut a = w.join_publishing("wallet").await;
    let id = a.app_id();
    a.set_multi_device(true).await.unwrap();
    let backup = a.backup().await.unwrap();
    let mut b = restored_publishing(&w, &backup).await;
    b.receive(None).await.unwrap();
    b.end_reconcile(UserConfirmed::new()).await.ok();
    a.receive(None).await.unwrap();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    a.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    assert!(a.state.pending_record.is_some());
    b.leave(LeaveMode::Immediate(UserConfirmed::new()))
        .await
        .unwrap();
    assert!(w.published(id).is_none());
    let writes = w.record_writes(id);
    w.clock.advance_ms(PUBLISHED_CHECK_MS);
    let outcome = a.receive(None).await;
    assert!(w.published(id).is_none(), "{outcome:?}");
    assert_eq!(w.record_writes(id), writes);
}

/// After a kept record is dropped as superseded, a record call that changes
/// nothing must not sign the superseded body again over the later record.
#[tokio::test]
async fn test_own_record_superseded_drop_then_unchanged_call_signs_nothing() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    w.clock.advance_ms(1_000);
    let accepts = record_of(&app).body().accepts.clone();
    let mut later = AppRecordBody::new(app.cert(), accepts, w.clock.now_ms());
    later.label = Some("other device".into());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    w.clock.advance_ms(pubky_switch_core::ops::BATCH_PROOFS_MS);
    app.receive(None).await.unwrap();
    assert!(app.state.pending_record.is_none());
    let puts = w.app_puts();
    app.update_accepts().await.unwrap();
    let held = AppRecord::verify(&w.held(id).unwrap(), &app.identity()).unwrap();
    assert_eq!(
        w.app_puts(),
        puts,
        "an unchanged call signed again: the switch now holds label {:?}, protocols {:?}",
        held.body().label,
        held.body().protocols.keys().collect::<Vec<_>>()
    );
}

/// The drop of a superseded kept record is in the store, so a load after it
/// sends nothing again.
#[tokio::test]
async fn test_own_record_superseded_drop_holds_across_a_load() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    w.clock.advance_ms(1_000);
    let later = AppRecordBody::new(app.cert(), Vec::new(), w.clock.now_ms());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    w.clock.advance_ms(pubky_switch_core::ops::BATCH_PROOFS_MS);
    app.receive(None).await.unwrap();
    drop(app);
    let mut loaded = w.load_publishing_on(w.store.clone(), id).await;
    assert!(loaded.state.pending_record.is_none());
    loaded.receive(None).await.unwrap();
    assert_eq!(w.held(id).as_ref(), Some(later.signed()));
}

/// A `409` naming no record, with a directory that lists no record of the app,
/// is a refusal: the kept record stays, nothing is noted or published.
#[tokio::test]
async fn test_own_record_conflict_naming_no_record_with_no_directory_entry_keeps_it() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let accepted = app.state.accepted.clone();
    let published = w.published(id);
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Error {
        path: "/ops".into(),
        code: ErrorCode::Conflict,
        current: json!({}),
    });
    w.switch.fail_next(Fault::Replace {
        path: "/directory".into(),
        member: "apps".into(),
        value: json!([]),
    });
    let error = app
        .set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Conflict), "{error}");
    assert!(app.state.pending_record.is_some());
    assert_eq!(app.state.accepted, accepted);
    assert_eq!(w.published(id), published);
}

/// A read that delivers a kept record with the Homeserver down reports the
/// failed publication once.
#[tokio::test]
async fn test_own_record_read_reports_a_failed_publication_once() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    app.take_events();
    w.homeserver.set_down(true);
    let report = app.receive(None).await.unwrap();
    let failed = report
        .events
        .iter()
        .filter(|e| matches!(e, AppEvent::RecordPublishFailed { .. }))
        .count();
    assert_eq!(failed, 1, "{:?}", report.events);
}

/// The call's mode decides: a two-step leave after an immediate one that failed
/// at the switch waits for the delete.
#[tokio::test]
async fn test_own_record_two_step_leave_after_a_failed_immediate_one_waits() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.homeserver.set_down(true);
    w.switch.fail_next(Fault::Unreachable {
        path: "/leave".into(),
        after: 0,
    });
    app.leave(LeaveMode::Immediate(UserConfirmed::new()))
        .await
        .unwrap_err();
    assert!(!w.switch.app(&id).departed);
    let error = app.leave(LeaveMode::TwoStep).await.unwrap_err();
    assert!(matches!(error, AppError::Transport(_)), "{error:?}");
    assert!(!w.switch.app(&id).departed);
    w.homeserver.set_down(false);
    app.leave(LeaveMode::TwoStep).await.unwrap();
    assert!(w.switch.app(&id).departed);
    assert!(w.published(id).is_none());
}

/// An app whose devices share its keys writes a missing copy back right after
/// the switch accepts its `app.put` at a read's start, also when the read's feed then fails.
#[tokio::test]
async fn test_own_record_delivery_at_a_read_start_writes_a_missing_copy_back() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    app.set_multi_device(true).await.unwrap();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    let kept = app.record().clone();
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    w.switch.fail_next(Fault::Unreachable {
        path: "/feed".into(),
        after: 0,
    });
    app.receive(None).await.unwrap_err();
    assert_eq!(w.held(id).as_ref(), Some(&kept));
    assert_eq!(w.published(id), Some(bytes_of(&kept)));
}

/// A later record that superseded a kept one carries another certificate: a renewal
/// another device took, whose `cert.put` the feed shows only as a stub. The newest own
/// `identity.json` lists it, so the app takes it with that record as after a restore
/// (Switch spec 3.2 step 3): nothing is signed over it, and an unchanged record call signs
/// nothing.
#[tokio::test]
async fn test_own_record_superseded_by_a_record_under_a_renewal_takes_the_renewal() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    // Another device takes a renewal and puts a later record carrying it.
    w.clock.advance_ms(1_000);
    let renewed = super::flows::renew_listed(&w, &app);
    let accepts = w.protocol.accepts(&renewed);
    let mut later = AppRecordBody::new(&renewed, accepts, w.clock.now_ms());
    later.label = Some("other device".into());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    w.clock.advance_ms(pubky_switch_core::ops::BATCH_PROOFS_MS);
    let puts = w.app_puts();
    app.receive(None).await.unwrap();
    assert!(app.state.pending_record.is_none());
    assert_eq!(app.state.accepted.as_ref(), Some(later.signed()));
    assert_eq!(app.cert().hash(), renewed.hash());
    assert_eq!(app.record(), later.signed());
    app.update_accepts().await.unwrap();
    app.receive(None).await.unwrap();
    assert_eq!(w.app_puts(), puts, "signed over the later record");
    assert_eq!(w.held(id).as_ref(), Some(later.signed()));
}

/// A leave kept by a store written before the mode stopped being kept still loads: its
/// `two_step` member is ignored.
#[test]
fn test_own_record_leave_state_with_a_two_step_member_loads() {
    let leave: crate::app::state::LeaveState = serde_json::from_value(json!({
        "left_at_ms": null,
        "two_step": true,
        "removed_seen_ms": null,
        "keys_deleted_ms": null,
        "compromise": false,
    }))
    .unwrap();
    assert_eq!(leave, crate::app::state::LeaveState::default());
}

/// The signer's renewal reaches the app's feed as a `cert.put` before the `identity.json`
/// that lists it: the app holds the renewal and keeps presenting the old certificate.
fn store_renewal_unlisted(w: &World, app: &App) -> pubky_switch_core::records::AppCert {
    use pubky_switch_core::ops::KeyBundlePut;
    use pubky_switch_core::records::seal_bundle_parts;
    let me = app.app_id();
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["scope-a"],
    );
    let has_keys = |s: &str| SampleProtocol::default().has_keys(s);
    let epoch = w.switch.identity_doc().unwrap().data_epoch();
    let mut batch = vec![OpKind::CertPut {
        target_app_id: me,
        cert: renewed.signed().clone(),
    }];
    for part in seal_bundle_parts(&w.alice, &renewed, 1, epoch, &has_keys).unwrap() {
        batch.push(OpKind::KeyBundlePut(KeyBundlePut {
            target_app_id: me,
            bundle: part.bundle,
            first_epoch: part.first_epoch,
            last_epoch: part.last_epoch,
        }));
    }
    w.switch.signer_batch(batch).unwrap();
    renewed
}

/// The signer lists `renewed`, the renewal of `old`.
fn list_renewal(
    w: &World,
    me: [u8; 16],
    old: &pubky_switch_core::records::AppCert,
    renewed: &pubky_switch_core::records::AppCert,
) {
    use pubky_switch_core::records::{ListedApp, RenewedCert};
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.apps.push(ListedApp {
            app_id: me,
            cert: renewed.hash(),
        });
        body.renewed.push(RenewedCert {
            app_id: me,
            cert: old.hash(),
            until: None,
        });
    });
}

/// The app saw the renewal's `cert.put` but not yet the `identity.json` listing it,
/// and its kept record was applied and then superseded by another device's later record
/// under the renewal. The app takes the later record with the renewal, and signs
/// nothing over it.
#[tokio::test]
async fn test_own_record_superseded_under_a_renewal_the_app_holds_keeps_the_later_body() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let old = app.cert().clone();
    w.clock.advance_ms(1_000);
    let renewed = store_renewal_unlisted(&w, &app);
    app.receive(None).await.unwrap();
    assert!(app.state.renewal.is_some(), "the cert.put was not seen");
    assert_eq!(app.cert().hash(), old.hash());
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    list_renewal(&w, id, &old, &renewed);
    w.clock.advance_ms(1_000);
    let accepts = w.protocol.accepts(&renewed);
    let mut later = AppRecordBody::new(&renewed, accepts, w.clock.now_ms());
    later.label = Some("other device".into());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    w.clock.advance_ms(pubky_switch_core::ops::BATCH_PROOFS_MS);
    let puts = w.app_puts();
    let outcome = app.receive(None).await;
    let held = AppRecord::verify(&w.held(id).unwrap(), &app.identity()).unwrap();
    assert_eq!(app.cert().hash(), renewed.hash(), "{outcome:?}");
    assert_eq!(
        w.app_puts(),
        puts,
        "signed over the later record: the switch holds label {:?}, protocols {:?} ({outcome:?})",
        held.body().label,
        held.body().protocols.keys().collect::<Vec<_>>()
    );
}

/// A switch whose directory shows a later record of the app under a certificate the
/// newest `identity.json` doesn't list (a faulty one). The app takes nothing of that record:
/// it is not accepted, and never published over the good Homeserver copy.
#[tokio::test]
async fn test_own_record_superseded_by_an_unlisted_record_publishes_nothing_of_it() {
    use pubky_switch_core::enc::zbase32_encode;
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let published = w.published(id);
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    w.clock.advance_ms(1_000);
    let unlisted = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["scope-a"],
    );
    let accepts = w.protocol.accepts(&unlisted);
    let shown = AppRecordBody::new(&unlisted, accepts, w.clock.now_ms());
    let shown = AppRecord::sign(&app_keys("wallet"), shown).unwrap();
    w.clock.advance_ms(pubky_switch_core::ops::BATCH_PROOFS_MS);
    w.switch.fail_next(Fault::Replace {
        path: "/directory".into(),
        member: "apps".into(),
        value: json!([{ "app_id": zbase32_encode(&id), "record": shown.signed(), "receive_key": null }]),
    });
    let outcome = app.receive(None).await;
    assert_ne!(
        w.published(id),
        Some(bytes_of(shown.signed())),
        "the app published a record under an unlisted certificate: {outcome:?}"
    );
    assert_ne!(
        app.state.accepted.as_ref(),
        Some(shown.signed()),
        "taken as accepted ({outcome:?}); Homeserver held {:?} before",
        published.is_some()
    );
}

/// A `409` naming no record, with a directory (a faulty one) showing a different
/// record of the app at the kept record's own `updated_at`: no later record superseded it,
/// so it is a refusal, and nothing of the shown record is taken.
#[tokio::test]
async fn test_own_record_conflict_naming_no_record_with_a_same_time_record_keeps_it() {
    use pubky_switch_core::enc::zbase32_encode;
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let accepted = app.state.accepted.clone();
    w.clock.advance_ms(1_000);
    let accepts = record_of(&app).body().accepts.clone();
    let mut shown = AppRecordBody::new(app.cert(), accepts, w.clock.now_ms());
    shown.label = Some("shown".into());
    let shown = AppRecord::sign(&app_keys("wallet"), shown).unwrap();
    w.switch.fail_next(Fault::Error {
        path: "/ops".into(),
        code: ErrorCode::Conflict,
        current: json!({}),
    });
    w.switch.fail_next(Fault::Replace {
        path: "/directory".into(),
        member: "apps".into(),
        value: json!([{ "app_id": zbase32_encode(&id), "record": shown.signed(), "receive_key": null }]),
    });
    let outcome = app
        .set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await;
    assert_eq!(record_of(&app).updated_at(), shown.updated_at());
    assert!(outcome.is_err(), "{outcome:?}");
    assert!(app.state.pending_record.is_some());
    assert_eq!(app.state.accepted, accepted);
}

/// The drop of a superseded kept record and the take of the later one are in the store: a
/// load after them presents the later record as accepted, and an unchanged record call
/// signs nothing.
#[tokio::test]
async fn test_own_record_superseding_record_taken_holds_across_a_load() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    w.clock.advance_ms(1_000);
    let accepts = record_of(&app).body().accepts.clone();
    let mut later = AppRecordBody::new(app.cert(), accepts, w.clock.now_ms());
    later.label = Some("other device".into());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    w.clock.advance_ms(pubky_switch_core::ops::BATCH_PROOFS_MS);
    app.receive(None).await.unwrap();
    drop(app);
    let mut loaded = w.load_publishing_on(w.store.clone(), id).await;
    assert_eq!(loaded.state.accepted.as_ref(), Some(later.signed()));
    assert_eq!(loaded.record(), later.signed());
    let puts = w.app_puts();
    loaded.update_accepts().await.unwrap();
    assert_eq!(w.app_puts(), puts, "an unchanged call signed again");
}

/// Taking a superseding record resets the Homeserver check: the read that takes it
/// compares the copy with it at once, though the copy was checked minutes before, and
/// writes the newer record over the older copy (Switch spec 4.2).
#[tokio::test]
async fn test_own_record_superseding_record_taken_is_checked_on_the_homeserver_at_once() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    let before = w.published(id);
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    // Another device puts a later record, and its Homeserver write is lost.
    w.clock.advance_ms(1_000);
    let accepts = record_of(&app).body().accepts.clone();
    let later = AppRecordBody::new(app.cert(), accepts, w.clock.now_ms());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    // The re-send is answered as one whose batch the switch holds without its proofs.
    w.switch.fail_next(Fault::Error {
        path: "/ops".into(),
        code: ErrorCode::Conflict,
        current: json!({}),
    });
    assert_eq!(w.published(id), before);
    app.receive(None).await.unwrap();
    assert_eq!(app.state.accepted.as_ref(), Some(later.signed()));
    assert_eq!(w.published(id), Some(bytes_of(later.signed())));
}

/// The later record another device put carries a renewal, and the directory read that
/// would take it fails. The app still comes to present the renewal, and its next record
/// call doesn't leave every read failing.
#[tokio::test]
async fn test_own_record_superseded_under_a_renewal_whose_take_fails_recovers() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    w.clock.advance_ms(1_000);
    let renewed = super::flows::renew_listed(&w, &app);
    let accepts = w.protocol.accepts(&renewed);
    let mut later = AppRecordBody::new(&renewed, accepts, w.clock.now_ms());
    later.label = Some("other device".into());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    w.clock.advance_ms(pubky_switch_core::ops::BATCH_PROOFS_MS);
    // The first directory read goes through, the second fails.
    w.switch.fail_next(Fault::Unreachable {
        path: "/directory".into(),
        after: 1,
    });
    let first = app.receive(None).await;
    for _ in 0..3 {
        w.clock.advance_ms(1_000);
        let _ = app.receive(None).await;
    }
    let taken = app.cert().hash() == renewed.hash();
    w.clock.advance_ms(1_000);
    let call = app.update_accepts().await;
    let mut reads = Vec::new();
    for _ in 0..3 {
        w.clock.advance_ms(1_000);
        reads.push(app.receive(None).await.map(|_| ()));
    }
    assert!(
        taken && reads.iter().all(Result::is_ok),
        "renewal taken: {taken}; first read {first:?}; update_accepts {call:?}; reads {reads:?}"
    );
    let held = AppRecord::verify(&w.held(id).unwrap(), &app.identity()).unwrap();
    assert_eq!(held.body().label.as_deref(), Some("other device"));
}

/// Another device takes a renewal and puts a record carrying it while this device is
/// offline, with no record kept here. This device comes to present the renewal, and its
/// next record call doesn't leave every read failing.
#[tokio::test]
async fn test_own_record_renewal_another_device_took_while_offline_is_taken() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    app.receive(None).await.unwrap();
    w.clock.advance_ms(1_000);
    let renewed = super::flows::renew_listed(&w, &app);
    let accepts = w.protocol.accepts(&renewed);
    let mut later = AppRecordBody::new(&renewed, accepts, w.clock.now_ms());
    later.label = Some("other device".into());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    w.clock.advance_ms(1_000);
    let mut reads = Vec::new();
    for _ in 0..2 {
        w.clock.advance_ms(1_000);
        reads.push(app.receive(None).await.map(|_| ()));
    }
    let taken = app.cert().hash() == renewed.hash();
    w.clock.advance_ms(1_000);
    let call = app
        .set_protocol_member(PROTO, member(json!({ "b": 2 })), None)
        .await;
    w.clock.advance_ms(1_000);
    let after = app.receive(None).await.map(|_| ());
    assert!(
        taken && after.is_ok(),
        "renewal taken: {taken}; reads {reads:?}; a change {call:?}; read after {after:?}"
    );
}

/// A listed renewal no record in the directory carries yet: a read looks once and takes
/// nothing, looks again only once the doc cache's interval has passed, and takes it then
/// from the record another device has put meanwhile.
#[tokio::test]
async fn test_own_record_listed_renewal_not_in_the_directory_is_looked_for_again_later() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    app.receive(None).await.unwrap();
    let old = app.cert().clone();
    w.clock.advance_ms(1_000);
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["scope-a"],
    );
    list_renewal(&w, id, &old, &renewed);
    app.refresh_identity().await.unwrap();
    let _ = app.receive(None).await;
    let looked = app.renewal_looked_ms.expect("looked, and found nothing");
    assert_eq!(app.cert().hash(), old.hash());
    w.clock.advance_ms(1_000);
    let _ = app.receive(None).await;
    assert_eq!(app.renewal_looked_ms, Some(looked), "not looked again yet");
    // Another device puts its record under the renewal; the next look takes it.
    let accepts = w.protocol.accepts(&renewed);
    let later = AppRecordBody::new(&renewed, accepts, w.clock.now_ms());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    w.clock.advance_ms(crate::app::DOC_CACHE_MS);
    let _ = app.receive(None).await;
    assert_eq!(app.cert().hash(), renewed.hash());
    assert_eq!(app.renewal_looked_ms, None);
    app.receive(None).await.unwrap();
}

/// Another device takes a renewal and puts its record while this device, offline, keeps a
/// record change under the old certificate. The read that takes the renewal keeps the
/// change, signed anew under it: the app stays current and the switch comes to hold it.
#[tokio::test]
async fn test_take_listed_renewal_kept_record_under_the_old_cert() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    app.receive(None).await.unwrap();
    w.clock.advance_ms(1_000);
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    app.set_protocol_member(PROTO, member(json!({ "a": 1 })), None)
        .await
        .unwrap_err();
    assert!(app.state.pending_record.is_some());
    w.clock.advance_ms(1_000);
    let renewed = super::flows::renew_listed(&w, &app);
    let accepts = w.protocol.accepts(&renewed);
    let mut later = AppRecordBody::new(&renewed, accepts, w.clock.now_ms());
    later.label = Some("other device".into());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    let mut reads = Vec::new();
    for _ in 0..3 {
        w.clock.advance_ms(1_000);
        reads.push(app.receive(None).await.map(|r| r.stopped));
    }
    assert!(app.state.gone.is_none(), "marked gone; reads {reads:?}");
    assert_eq!(app.cert().hash(), renewed.hash());
    let held = AppRecord::verify(&w.held(id).unwrap(), &app.identity()).unwrap();
    assert_eq!(held.cert().hash(), renewed.hash());
    assert_eq!(
        held.body().protocols.get(PROTO),
        member(json!({ "a": 1 })).as_ref()
    );
}

/// After a renewal is taken from the directory, the publish check compares the Homeserver
/// copy with the record taken, as after a superseding record's take: the older copy is
/// replaced, and a missing copy is written back as the record taken, never the older one.
#[tokio::test]
async fn test_take_listed_renewal_publish_check_compares_the_taken_record() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    app.receive(None).await.unwrap();
    w.clock.advance_ms(1_000);
    let renewed = super::flows::renew_listed(&w, &app);
    let accepts = w.protocol.accepts(&renewed);
    let mut later = AppRecordBody::new(&renewed, accepts, w.clock.now_ms());
    later.label = Some("other device".into());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    app.refresh_identity().await.unwrap();
    w.clock.advance_ms(1_000);
    app.receive(None).await.unwrap();
    assert_eq!(app.cert().hash(), renewed.hash());
    assert_eq!(app.state.accepted.as_ref(), Some(later.signed()));
    w.clock.advance_ms(PUBLISHED_CHECK_MS + 1);
    app.receive(None).await.unwrap();
    assert_eq!(w.published(id), Some(bytes_of(later.signed())));
    app.set_multi_device(true).await.unwrap();
    w.homeserver.remove(w.alice.public(), &app_record_path(&id));
    w.clock.advance_ms(PUBLISHED_CHECK_MS + 1);
    app.receive(None).await.unwrap();
    assert_eq!(w.published(id), Some(bytes_of(later.signed())));
}

/// The app holds a later renewal's `cert.put` while its own `identity.json` still lists the
/// renewal another device took. Taking that one keeps the later one, which the next
/// `identity.json` lists, and the app takes it then.
#[tokio::test]
async fn test_take_listed_renewal_keeps_a_later_held_renewal() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let me = app.app_id();
    app.receive(None).await.unwrap();
    w.clock.advance_ms(1_000);
    let renewed = super::flows::renew_listed(&w, &app);
    let accepts = w.protocol.accepts(&renewed);
    let later = AppRecordBody::new(&renewed, accepts, w.clock.now_ms());
    let later = AppRecord::sign(&app_keys("wallet"), later).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: later.signed().clone(),
            },
        )
        .unwrap();
    w.clock.advance_ms(1_000);
    let third = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["scope-a"],
    );
    w.switch
        .signer_batch(vec![OpKind::CertPut {
            target_app_id: me,
            cert: third.signed().clone(),
        }])
        .unwrap();
    w.clock.advance_ms(1_000);
    app.receive(None).await.unwrap();
    assert_eq!(
        app.state.renewal.as_ref().map(|r| r.hash()),
        Some(third.hash())
    );
    w.clock.advance_ms(1_000);
    app.receive(None).await.unwrap();
    list_renewal(&w, me, &renewed, &third);
    for _ in 0..3 {
        w.clock.advance_ms(crate::app::DOC_CACHE_MS);
        app.receive(None).await.unwrap();
    }
    assert_eq!(
        app.cert().hash(),
        third.hash(),
        "the later renewal was dropped"
    );
}

/// A listed certificate that isn't a renewal of the one held, here one issued before it,
/// is never taken from the directory: the look finds nothing it may take, is paced, and the
/// reads go on.
#[tokio::test]
async fn test_own_record_listed_certificate_that_doesnt_renew_is_not_taken() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    app.receive(None).await.unwrap();
    let old = app.cert().clone();
    let earlier = cert_for(
        &w.alice,
        &app_keys("wallet"),
        old.issued_at() - 1_000,
        &["scope-a"],
    );
    list_renewal(&w, id, &old, &earlier);
    w.clock.advance_ms(1_000);
    let accepts = w.protocol.accepts(&earlier);
    let record = AppRecordBody::new(&earlier, accepts, w.clock.now_ms());
    let record = AppRecord::sign(&app_keys("wallet"), record).unwrap();
    w.switch
        .app_op(
            &app_keys("wallet"),
            OpKind::AppPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    app.refresh_identity().await.unwrap();
    let _ = app.receive(None).await;
    assert_eq!(
        app.cert().hash(),
        old.hash(),
        "not a renewal of the one held"
    );
    assert!(app.renewal_looked_ms.is_some(), "looked, and paced");
}

/// A look whose directory carries a newer own `identity.json` that removes the app takes
/// it, and the read stops there, telling the host.
#[tokio::test]
async fn test_own_record_look_that_brings_the_apps_removal_stops_the_read() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    app.receive(None).await.unwrap();
    let old = app.cert().clone();
    w.clock.advance_ms(1_000);
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["scope-a"],
    );
    list_renewal(&w, id, &old, &renewed);
    app.refresh_identity().await.unwrap();
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != id);
        body.removed.push(pubky_switch_core::records::RemovedApp {
            app_id: id,
            distrust_from: w.clock.now_ms(),
        });
    });
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped, "{:?}", report.events);
    assert!(
        report.events.iter().any(|e| matches!(e, AppEvent::Removed)),
        "{:?}",
        report.events
    );
}

/// A look whose directory read fails doesn't fail the read: only a record write is
/// refused under the earlier certificate, so the read goes on, and the look is paced.
#[tokio::test]
async fn test_own_record_look_that_fails_lets_the_read_go_on() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    app.receive(None).await.unwrap();
    let old = app.cert().clone();
    w.clock.advance_ms(1_000);
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["scope-a"],
    );
    list_renewal(&w, id, &old, &renewed);
    app.refresh_identity().await.unwrap();
    let (note, _) = w.note(id, "hello");
    w.switch.fail_next(Fault::Unreachable {
        path: "/directory".into(),
        after: 0,
    });
    let report = app.receive(None).await.unwrap();
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::MessageReceived { seq, .. } if *seq == note)),
        "{:?}",
        report.events
    );
    assert!(app.renewal_looked_ms.is_some());
}

/// A look whose directory carries a newer own `identity.json` that removes the app and
/// raises the data epoch, and the key fetch the epoch rise makes fails after the document
/// is taken. The read still stops at the removal, before its feed, and hands nothing over.
#[tokio::test]
async fn test_take_listed_renewal_removal_with_an_epoch_rise_stops_the_read() {
    let w = World::new();
    let mut app = w.join_publishing("wallet").await;
    let id = app.app_id();
    app.receive(None).await.unwrap();
    let old = app.cert().clone();
    w.clock.advance_ms(1_000);
    let renewed = cert_for(
        &w.alice,
        &app_keys("wallet"),
        w.clock.now_ms(),
        &["scope-a"],
    );
    list_renewal(&w, id, &old, &renewed);
    app.refresh_identity().await.unwrap();
    // A batch kept from an earlier call, which a read sends again before its feed.
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    app.submit_batch(
        crate::app::OpBatch::new().op(pubky_switch_core::ops::OpKind::AllowPut {
            pubky: [10; 32],
            kind: pubky_switch_core::ops::AllowKind::Conversation,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(app.kept_batches().await.unwrap().len(), 1);
    let (note, _) = w.note(id, "hello");
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != id);
        body.removed.push(pubky_switch_core::records::RemovedApp {
            app_id: id,
            distrust_from: w.clock.now_ms(),
        });
        body.data_epoch += 1;
    });
    // The key fetch the epoch rise makes fails, after the look took the document.
    w.switch.fail_next(Fault::Unreachable {
        path: "/keys".into(),
        after: 0,
    });
    // The kept batch, sent again after the removal, would meet this fault.
    w.switch.fail_next(Fault::Unreachable {
        path: "/ops".into(),
        after: 0,
    });
    let reads = w.switch.lock().feed_reads;
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped, "{:?}", report.events);
    let left: Vec<String> = w
        .switch
        .lock()
        .faults
        .iter()
        .map(|fault| match fault {
            Fault::Unreachable { path, .. } => path.clone(),
            _ => String::new(),
        })
        .collect();
    assert_eq!(
        left,
        ["/ops"],
        "the key fetch failed, and nothing was sent after it"
    );
    // Told once: the read stops at the removal rather than going on to find it again.
    assert_eq!(
        report
            .events
            .iter()
            .filter(|e| matches!(e, AppEvent::Removed))
            .count(),
        1,
        "{:?}",
        report.events
    );
    assert!(
        !report
            .events
            .iter()
            .any(|e| matches!(e, AppEvent::MessageReceived { seq, .. } if *seq == note)),
        "{:?}",
        report.events
    );
    // It stops at the document the look took, before its feed.
    assert_eq!(
        w.switch.lock().feed_reads,
        reads,
        "no feed read after the removal"
    );
}
