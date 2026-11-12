//! Forgetting a processed pair (`forget.rs`, Switch spec 11): a protocol that gives up what a
//! message brought forgets its pair with that eviction, in one commit, so a re-sent copy is
//! delivered again instead of dropped as a duplicate.

use std::sync::Mutex;

use pubky_switch_core::message::MessagePlaintext;

use super::moves::has;
use super::*;
use crate::app::{AppError, AppEvent, ReceiveContext, Refusal};
use crate::store::{Fault as StoreFault, FaultStore};
use crate::testing::Fault;

/// [`SampleProtocol`], whose note with `evict` gives up the note of that `msg_id` from the
/// same sender: it forgets its pair and deletes its local copy in the step. With `drop` set
/// too, the step forgets and then drops the message. With `pad`, the step first writes that
/// many bytes of local state, and goes on to apply when the forget is refused.
#[derive(Default)]
struct Evicting {
    sample: SampleProtocol,
    /// What each `forget_processed` of a step returned.
    forgot: Mutex<Vec<bool>>,
    /// The forgets refused in a step with `pad`.
    refused: Mutex<Vec<AppError>>,
}

impl Protocol for Evicting {
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
        self.sample.accepts(cert)
    }
    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(message)
    }
    fn backup_name(&self) -> Option<String> {
        Some("sample".into())
    }
    fn receive_with(&self, message: &ReceivedMessage, cx: &mut ReceiveContext<'_>) -> Outcome {
        if let Some(evict) = message.message.body.get("evict").and_then(Value::as_str) {
            let pad = message.message.body.get("pad").and_then(Value::as_u64);
            if let Some(pad) = pad {
                let write = LocalWrite::Put {
                    key: b"pad".to_vec(),
                    value: vec![0; usize::try_from(pad).unwrap()],
                };
                if cx.local(write).is_err() {
                    return Outcome::Drop {
                        reason: "pad".into(),
                    };
                }
            }
            let forgot = match cx.forget_processed(message.sender, evict) {
                Ok(forgot) => forgot,
                Err(error) if pad.is_some() => {
                    self.refused.lock().unwrap().push(error);
                    return self.sample.receive(message);
                }
                Err(error) => {
                    return Outcome::Drop {
                        reason: error.to_string(),
                    };
                }
            };
            self.forgot.lock().unwrap().push(forgot);
            if cx
                .local(LocalWrite::Delete {
                    key: format!("notes/{evict}").into_bytes(),
                })
                .is_err()
            {
                return Outcome::Drop {
                    reason: "local".into(),
                };
            }
            if message.message.body.get("drop").is_some() {
                return Outcome::Drop {
                    reason: "dropped after forgetting".into(),
                };
            }
        }
        self.sample.receive(message)
    }
    fn resend_needed(&self, n: &ResendNeeded) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.resend_needed(n)
    }
    fn missed(&self, m: &MissedEntries) -> Result<Vec<LocalWrite>, crate::app::StoreFailure> {
        self.sample.missed(m)
    }
}

fn received(events: &[AppEvent], seq: u64) -> bool {
    has(
        events,
        |e| matches!(e, AppEvent::MessageReceived { seq: s, .. } if *s == seq),
    )
}

fn duplicate(events: &[AppEvent], seq: u64) -> bool {
    has(
        events,
        |e| matches!(e, AppEvent::Duplicate { seq: s, .. } if *s == seq),
    )
}

struct Setup {
    w: World,
    protocol: Arc<Evicting>,
}

impl Setup {
    fn new() -> Self {
        Self {
            w: World::new(),
            protocol: Arc::new(Evicting::default()),
        }
    }

    async fn wallet_on(&self, store: Arc<dyn StateStore>) -> App {
        let request = self.w.approve(&app_keys("wallet"), &["scope-a"]);
        App::join(
            self.w.env_on(store),
            self.protocol.clone(),
            World::config(),
            request,
        )
        .await
        .unwrap()
    }

    async fn wallet(&self) -> App {
        self.wallet_on(Arc::clone(&self.w.store) as Arc<dyn StateStore>)
            .await
    }

    /// A note from bob with `body`.
    fn note(&self, to: [u8; 16], body: Value) -> (u64, Message) {
        self.w
            .switch
            .send(
                &self.w.bob,
                &self.w.bob_keys,
                &self.w.bob_cert,
                "sample.note",
                body,
                &[to],
            )
            .unwrap()
    }

    /// `message` sent again, the same signed plaintext.
    fn again(&self, to: [u8; 16], message: &Message) -> u64 {
        let plaintext: MessagePlaintext = message.sign(&self.w.bob_keys).unwrap();
        self.w
            .switch
            .send_plaintext(self.w.bob.public(), &self.w.bob_cert, &plaintext, &[to])
            .unwrap()
    }
}

async fn note_kept(app: &App, msg_id: &str) -> bool {
    app.protocol_get(format!("notes/{msg_id}").as_bytes())
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn test_forget_processed_in_a_step_redelivers_the_evicted_message() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    let me = app.app_id();
    let (_, kept) = s.note(me, json!({ "text": "kept" }));
    let (_, other) = s.note(me, json!({ "text": "other" }));
    app.receive(None).await.unwrap();
    assert!(note_kept(&app, &kept.msg_id).await);
    // A note whose step gives up the first: its pair goes with the local delete, in the
    // step's commit.
    let (evicting, _) = s.note(me, json!({ "text": "evict", "evict": kept.msg_id }));
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, evicting), "{:?}", report.events);
    assert_eq!(*s.protocol.forgot.lock().unwrap(), vec![true]);
    assert!(!note_kept(&app, &kept.msg_id).await);
    // A re-send of the evicted note is a new entry, applied; one of the other, a duplicate.
    let effects = s.w.effects();
    let again = s.again(me, &kept);
    let other_again = s.again(me, &other);
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, again), "{:?}", report.events);
    assert!(!duplicate(&report.events, again));
    assert!(
        duplicate(&report.events, other_again),
        "{:?}",
        report.events
    );
    assert_eq!(s.w.effects(), effects + 1);
    assert!(note_kept(&app, &kept.msg_id).await);
}

#[tokio::test]
async fn test_forget_processed_with_a_dropped_step_forgets_nothing() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    let me = app.app_id();
    let (_, kept) = s.note(me, json!({ "text": "kept" }));
    app.receive(None).await.unwrap();
    // The step forgets, deletes and then drops the message: neither is committed.
    s.note(
        me,
        json!({ "text": "evict", "evict": kept.msg_id, "drop": true }),
    );
    app.receive(None).await.unwrap();
    assert!(note_kept(&app, &kept.msg_id).await);
    let again = s.again(me, &kept);
    let report = app.receive(None).await.unwrap();
    assert!(duplicate(&report.events, again), "{:?}", report.events);
}

#[tokio::test]
async fn test_forget_processed_waits_with_a_kept_effect() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    let me = app.app_id();
    let (_, kept) = s.note(me, json!({ "text": "kept" }));
    app.receive(None).await.unwrap();
    // The evicting step's batch is taken and its answer lost: the effect is kept, and the
    // forget with it, so the pair is still held.
    s.note(me, json!({ "text": "evict", "evict": kept.msg_id }));
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    app.receive(None).await.unwrap_err();
    let ns = crate::store::client_namespace(&me);
    let pair = crate::app::state::key::processed(&s.w.bob.public(), &kept.msg_id);
    assert!(s.w.store.get(&ns, pair.as_bytes()).unwrap().is_some());
    // The next load settles the kept effect, and the forget commits with its outcome.
    let mut app = App::load(s.w.env(), s.protocol.clone(), World::config(), me)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    assert!(s.w.store.get(&ns, pair.as_bytes()).unwrap().is_none());
    assert!(!note_kept(&app, &kept.msg_id).await);
    let again = s.again(me, &kept);
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, again), "{:?}", report.events);
}

#[tokio::test]
async fn test_forget_processed_refused_while_its_effect_is_kept() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    let me = app.app_id();
    let (_, note) = s.note(me, json!({ "text": "kept" }));
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    app.receive(None).await.unwrap_err();
    let error = app
        .forget_processed(s.w.bob.public(), &note.msg_id, &[])
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::NotNow(_))),
        "{error}"
    );
}

#[tokio::test]
async fn test_forget_processed_outside_a_step_commits_with_the_eviction() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    let me = app.app_id();
    let (_, kept) = s.note(me, json!({ "text": "kept" }));
    let (_, other) = s.note(me, json!({ "text": "other" }));
    app.receive(None).await.unwrap();
    let evict = [LocalWrite::Delete {
        key: format!("notes/{}", kept.msg_id).into_bytes(),
    }];
    // Another sender's pair, or an unknown msg_id: nothing is held, only the writes go.
    assert!(
        !app.forget_processed(s.w.alice.public(), &kept.msg_id, &[])
            .await
            .unwrap()
    );
    assert!(
        !app.forget_processed(
            s.w.bob.public(),
            "00000000-0000-4000-8000-000000000000",
            &[]
        )
        .await
        .unwrap()
    );
    let again = s.again(me, &kept);
    let report = app.receive(None).await.unwrap();
    assert!(duplicate(&report.events, again), "{:?}", report.events);
    // The forget and the eviction in one commit.
    assert!(
        app.forget_processed(s.w.bob.public(), &kept.msg_id, &evict)
            .await
            .unwrap()
    );
    assert!(!note_kept(&app, &kept.msg_id).await);
    // The pair and its time index are gone: nothing is left to prune.
    let ns = crate::store::client_namespace(&me);
    let left: Vec<_> =
        s.w.store
            .scan(&ns, b"proct/", None, 1000)
            .unwrap()
            .into_iter()
            .filter(|(key, _)| String::from_utf8_lossy(key).ends_with(&kept.msg_id))
            .collect();
    assert!(left.is_empty());
    // Forgetting it again finds nothing.
    assert!(
        !app.forget_processed(s.w.bob.public(), &kept.msg_id, &[])
            .await
            .unwrap()
    );
    let again = s.again(me, &kept);
    let other_again = s.again(me, &other);
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, again), "{:?}", report.events);
    assert!(
        duplicate(&report.events, other_again),
        "{:?}",
        report.events
    );
}

#[tokio::test]
async fn test_forget_processed_and_its_writes_fail_together() {
    let s = Setup::new();
    let me = s.wallet().await.app_id();
    let (_, kept) = s.note(me, json!({ "text": "kept" }));
    let mut app = App::load(s.w.env(), s.protocol.clone(), World::config(), me)
        .await
        .unwrap();
    app.receive(None).await.unwrap();
    drop(app);
    let faulty = Arc::new(FaultStore::new(
        Arc::clone(&s.w.store) as Arc<dyn StateStore>,
        StoreFault::FailBefore(1),
    ));
    let mut app = App::load(
        s.w.env_on(Arc::clone(&faulty) as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        me,
    )
    .await
    .unwrap();
    assert_eq!(faulty.commits(), 0);
    let evict = [LocalWrite::Delete {
        key: format!("notes/{}", kept.msg_id).into_bytes(),
    }];
    app.forget_processed(s.w.bob.public(), &kept.msg_id, &evict)
        .await
        .unwrap_err();
    // Neither went: the note is kept and its re-send is a duplicate.
    assert!(note_kept(&app, &kept.msg_id).await);
    let again = s.again(me, &kept);
    let report = app.receive(None).await.unwrap();
    assert!(duplicate(&report.events, again), "{:?}", report.events);
}

#[tokio::test]
async fn test_forget_processed_stays_forgotten_across_a_reload_and_a_restore() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    let me = app.app_id();
    let (_, kept) = s.note(me, json!({ "text": "kept" }));
    let (_, other) = s.note(me, json!({ "text": "other" }));
    app.receive(None).await.unwrap();
    assert!(
        app.forget_processed(s.w.bob.public(), &kept.msg_id, &[])
            .await
            .unwrap()
    );
    drop(app);
    let mut app = App::load(s.w.env(), s.protocol.clone(), World::config(), me)
        .await
        .unwrap();
    // A backup with the protocol's layer carries the processed pairs: not the forgotten one.
    let backup = app.backup_layered().await.unwrap();
    drop(app);
    let mut restored = App::restore(
        s.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        s.protocol.clone(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    restored
        .end_reconcile(crate::app::UserConfirmed::new())
        .await
        .ok();
    let again = s.again(me, &kept);
    let other_again = s.again(me, &other);
    let report = restored.receive(None).await.unwrap();
    assert!(received(&report.events, again), "{:?}", report.events);
    assert!(
        duplicate(&report.events, other_again),
        "{:?}",
        report.events
    );
}

#[tokio::test]
async fn test_forget_processed_refused_while_an_entry_stored_locally_holds_it() {
    let s = Setup::new();
    let mut app = s.wallet().await;
    let me = app.app_id();
    let (_, note) = s.note(me, json!({ "text": "kept" }));
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    app.receive(None).await.unwrap_err();
    // The kept effect's entry stored locally, its fate uncertain, as after a move.
    let mut app = App::load(s.w.env(), s.protocol.clone(), World::config(), me)
        .await
        .unwrap();
    let pending = app.state.pending_effect.clone().unwrap();
    let (id, stored) = crate::app::uncertain_copy(&app.state, &pending, Some(99)).unwrap();
    let mut tx = app.tx().unwrap();
    tx.put(&crate::app::state::key::parked(id), &stored)
        .unwrap();
    tx.delete(crate::app::state::key::PENDING_EFFECT).unwrap();
    app.commit(tx).await.unwrap();
    let mut app = App::load(s.w.env(), s.protocol.clone(), World::config(), me)
        .await
        .unwrap();
    assert!(app.state.pending_effect.is_none() && app.state.parked.contains_key(&id));
    let error = app
        .forget_processed(s.w.bob.public(), &note.msg_id, &[])
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(Refusal::NotNow(_))),
        "{error}"
    );
}

#[tokio::test]
async fn test_forget_processed_in_a_step_without_operations() {
    // Own apps' notices have no operations: the forget goes in the read's commit.
    let s = Setup::new();
    let mut app = s.wallet().await;
    let me = app.app_id();
    let phone = s.w.other_app("phone", &[]);
    let phone_cert = s.w.switch.app(&phone.app_id_bytes()).cert.unwrap();
    let notice = |body: Value| {
        s.w.switch
            .send(
                &s.w.alice,
                &phone,
                &phone_cert,
                "sample.notice",
                body,
                &[me],
            )
            .unwrap()
    };
    let (_, kept) = notice(json!({ "text": "kept" }));
    app.receive(None).await.unwrap();
    let effects = s.w.effects();
    notice(json!({ "text": "evict", "evict": kept.msg_id }));
    app.receive(None).await.unwrap();
    assert_eq!(s.w.effects(), effects);
    assert_eq!(*s.protocol.forgot.lock().unwrap(), vec![true]);
    assert!(!note_kept(&app, &kept.msg_id).await);
    let plaintext = kept.sign(&phone).unwrap();
    let again =
        s.w.switch
            .send_plaintext(s.w.alice.public(), &phone_cert, &plaintext, &[me])
            .unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, again), "{:?}", report.events);
}

/// The keys a step forgets count against `MAX_STEP_LOCAL_BYTES` with its local writes: a
/// forget past the bound is refused, so the pair stays and a re-send is still a duplicate,
/// and the step's effect, applied all the same, is stored as too large.
#[tokio::test]
async fn test_forget_processed_past_the_step_bound_is_refused() {
    use crate::app::{MAX_STEP_LOCAL_BYTES, ParkReason};
    let s = Setup::new();
    let mut app = s.wallet().await;
    let me = app.app_id();
    let (_, first) = s.note(me, json!({ "text": "first" }));
    app.receive(None).await.unwrap();
    // Room left for a little more, not for the forget's two keys.
    let pad = MAX_STEP_LOCAL_BYTES - crate::app::LOCAL_WRITE_OVERHEAD_BYTES - b"pad".len() - 16;
    s.note(
        me,
        json!({ "text": "evict", "evict": first.msg_id, "pad": pad }),
    );
    app.receive(None).await.unwrap();
    let refused = s.protocol.refused.lock().unwrap().clone();
    assert!(
        matches!(refused.as_slice(), [AppError::Refused(Refusal::Usage(_))]),
        "{refused:?}"
    );
    assert!(s.protocol.forgot.lock().unwrap().is_empty());
    assert!(
        app.parked_entries()
            .await
            .unwrap()
            .iter()
            .any(|entry| entry.reason == ParkReason::EffectTooLarge),
    );
    let again = s.again(me, &first);
    let report = app.receive(None).await.unwrap();
    assert!(duplicate(&report.events, again), "{:?}", report.events);
}

/// A kept effect that forgets a pair, applied by the old service and settled from the old
/// chain when the app follows a move (Switch spec 12.5 "Kept batches"): the forget commits
/// with that outcome, as with any other.
#[tokio::test]
async fn test_forget_processed_settled_at_a_move_forgets_the_pair() {
    use super::moves::{NEXT, Router, freeze_for, join_on, next_key, publish_at};
    let s = Setup::new();
    let router = Router::of(&s.w);
    let mut app = join_on(
        &s.w,
        &router,
        Arc::clone(&s.w.store) as Arc<dyn StateStore>,
        s.protocol.clone(),
        &[Permission::ConversationAdd],
    )
    .await;
    let me = app.app_id();
    let (_, kept) = s.note(me, json!({ "text": "kept" }));
    app.receive(None).await.unwrap();
    s.note(me, json!({ "text": "evict", "evict": kept.msg_id }));
    s.w.switch
        .fail_next(Fault::LoseAnswer { path: "ops".into() });
    app.receive(None).await.unwrap_err();
    let ns = crate::store::client_namespace(&me);
    let pair = crate::app::state::key::processed(&s.w.bob.public(), &kept.msg_id);
    assert!(s.w.store.get(&ns, pair.as_bytes()).unwrap().is_some());
    // The move: the old service freezes, the next imports it, and the app follows.
    let n_key = next_key();
    s.w.switch.freeze(&freeze_for(&s.w, &n_key, 2)).unwrap();
    let next = s.w.switch.import_into(n_key.to_bytes());
    router.add(NEXT, &next);
    let _ = app.receive(None).await;
    publish_at(
        &s.w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    app.receive(None).await.unwrap();
    assert!(app.state.pending_effect.is_none());
    assert!(s.w.store.get(&ns, pair.as_bytes()).unwrap().is_none());
    assert!(!note_kept(&app, &kept.msg_id).await);
}
