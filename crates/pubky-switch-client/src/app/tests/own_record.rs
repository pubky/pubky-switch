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
