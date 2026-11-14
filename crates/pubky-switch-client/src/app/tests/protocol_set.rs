//! Several protocols on one app: the spec's sample protocol `tasks` beside a second one,
//! `chat`, each with its own kinds, scope root, local state, backup layer, owed calls and
//! duty events.

use std::sync::{Arc, Mutex};

use pubky_switch_core::message::Message;
use pubky_switch_core::ops::{AllowKind, OpKind};
use pubky_switch_core::records::AppCert;
use pubky_switch_core::scopes::Permission;
use serde_json::json;

use super::*;
use crate::app::{
    AppBackup, AppError, AppEvent, CertificateRefusal, Delivery, MAX_STEP_LOCAL_BYTES, OpBatch,
    OutgoingMessage, ProtocolLayer, ProtocolSet, Refusal, RestoreContext, StoreFailure,
    UserConfirmed,
};
use crate::error::StoreError;
use crate::testing::Fault;

/// A neutral protocol named `name`: its scope `name` has keys, it accepts `<name>.item` and
/// `<name>.clear` (and `foreign`, which isn't its own), keeps each message it takes under
/// its `msg_id`, and clears its whole state on `<name>.clear`.
#[derive(Default)]
struct Named {
    name: String,
    /// A kind it lists in `accepts` though another protocol owns it.
    foreign: Option<String>,
    /// The (`seq`, kind) of each message taken, in order.
    received: Mutex<Vec<(u64, String)>>,
    /// The kinds check 8 asked it about.
    checked: Mutex<Vec<String>>,
    /// The `seq` of each missed item it took.
    missed: Mutex<Vec<u64>>,
    /// The pubkys of the deny list changes it took.
    denies: Mutex<Vec<[u8; 32]>>,
    /// How many of the next missed calls fail.
    failing_missed: Mutex<u32>,
    /// Its missed answers are over the bound.
    huge_missed: bool,
    /// How many of the next deny list change calls fail.
    failing_deny: Mutex<u32>,
    /// The position of each deny list gap it took, and whether its list was read.
    gaps: Mutex<Vec<(u64, bool)>>,
    /// How many of the next deny list gap calls fail.
    failing_gap: Mutex<u32>,
    /// How many of the next receive steps end in a retry.
    retrying: Mutex<u32>,
    /// Its effects carry a conversation entry for the sender.
    with_ops: bool,
    /// It refuses every own certificate.
    refuse_cert: Mutex<bool>,
    /// Whether each restore step was handed a layer.
    restored: Mutex<Vec<bool>>,
    /// It holds its outbox messages back.
    holding: Mutex<bool>,
    /// The kinds of the outbox messages it was asked about.
    asked_send: Mutex<Vec<String>>,
    /// The `seq` of each feed item it took, a message or a missed item, in the order taken.
    taken: Mutex<Vec<u64>>,
    /// Its collections.
    collections: Vec<crate::app::Collection>,
}

fn named(name: &str) -> Named {
    Named {
        name: name.into(),
        ..Named::default()
    }
}

fn count_down(counter: &Mutex<u32>) -> bool {
    let mut left = counter.lock().unwrap();
    let fails = *left > 0;
    *left = left.saturating_sub(1);
    fails
}

impl Protocol for Named {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn collections(&self) -> Vec<crate::app::Collection> {
        self.collections.clone()
    }

    fn has_keys(&self, scope: &str) -> bool {
        scope == self.name
    }

    fn sent_between_own_apps(&self, _kind: &str) -> bool {
        false
    }

    fn check_scopes(&self, message: &Message, _: &AppCert, _: &AppCert) -> Result<(), String> {
        self.checked.lock().unwrap().push(message.kind.clone());
        if message.kind.starts_with(&format!("{}.", self.name)) {
            Ok(())
        } else {
            Err("named: another protocol's kind".into())
        }
    }

    fn accepts(&self, _cert: &AppCert) -> Vec<String> {
        let mut kinds = vec![
            format!("{}.item", self.name),
            format!("{}.clear", self.name),
        ];
        kinds.extend(self.foreign.clone());
        kinds
    }

    fn check_body(&self, _message: &ReceivedMessage) -> Result<(), String> {
        Ok(())
    }

    fn receive(
        &self,
        message: &ReceivedMessage,
        _: &mut crate::app::ReceiveContext<'_>,
    ) -> Outcome {
        if count_down(&self.retrying) {
            return Outcome::Retry(StoreFailure::unavailable(StoreError::Unavailable));
        }
        self.received
            .lock()
            .unwrap()
            .push((message.seq, message.message.kind.clone()));
        self.taken.lock().unwrap().push(message.seq);
        let local = if message.message.kind.ends_with(".clear") {
            vec![LocalWrite::DeletePrefix { prefix: Vec::new() }]
        } else {
            vec![LocalWrite::Put {
                key: message.message.msg_id.clone().into_bytes(),
                value: self.name.clone().into_bytes(),
            }]
        };
        let ops = if self.with_ops {
            vec![(
                Vec::new(),
                OpKind::AllowPut {
                    pubky: message.sender,
                    kind: AllowKind::Conversation,
                },
            )]
        } else {
            Vec::new()
        };
        Outcome::Apply(Effect { ops, local })
    }

    fn resend_needed(&self, _: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
        Ok(Vec::new())
    }

    fn missed(&self, missed: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
        if count_down(&self.failing_missed) {
            return Err(StoreError::Unavailable.into());
        }
        self.missed.lock().unwrap().push(missed.seq);
        self.taken.lock().unwrap().push(missed.seq);
        let value = if self.huge_missed {
            vec![0; MAX_STEP_LOCAL_BYTES]
        } else {
            b"1".to_vec()
        };
        Ok(vec![LocalWrite::Put {
            key: format!("missed/{}", missed.seq).into_bytes(),
            value,
        }])
    }

    fn deny_list_changed(
        &self,
        change: &crate::app::DenyListChange,
    ) -> Result<Vec<LocalWrite>, StoreFailure> {
        if count_down(&self.failing_deny) {
            return Err(StoreError::Unavailable.into());
        }
        self.denies.lock().unwrap().push(change.pubky);
        Ok(Vec::new())
    }

    fn deny_list_gap(
        &self,
        gap: &crate::app::DenyListGap,
    ) -> Result<Vec<LocalWrite>, StoreFailure> {
        if count_down(&self.failing_gap) {
            return Err(StoreError::Unavailable.into());
        }
        self.gaps.lock().unwrap().push((gap.seq, gap.list_read));
        Ok(Vec::new())
    }

    fn may_send(&self, message: &Message) -> bool {
        self.asked_send.lock().unwrap().push(message.kind.clone());
        !*self.holding.lock().unwrap()
    }

    fn check_own_certificate(&self, _cert: &AppCert) -> Result<(), String> {
        if *self.refuse_cert.lock().unwrap() {
            Err("named: a certificate it doesn't run with".into())
        } else {
            Ok(())
        }
    }

    fn restore_layer(
        &self,
        layer: Option<&ProtocolLayer>,
        _: &RestoreContext<'_>,
    ) -> Result<Vec<LocalWrite>, String> {
        self.restored.lock().unwrap().push(layer.is_some());
        let Some(layer) = layer else {
            return Ok(Vec::new());
        };
        let state = crate::app::decode_local_state(&layer.data).ok_or("named: unreadable")?;
        Ok(state
            .into_iter()
            .map(|(key, value)| LocalWrite::Put { key, value })
            .collect())
    }
}

/// `tasks` and `chat` on one app, with the store it keeps.
struct Pair {
    w: World,
    tasks: Arc<Named>,
    chat: Arc<Named>,
    store: Arc<MemoryStore>,
}

impl Pair {
    fn new() -> Self {
        Self::with(named("tasks"), named("chat"))
    }

    fn with(tasks: Named, chat: Named) -> Self {
        Self {
            w: World::new(),
            tasks: Arc::new(tasks),
            chat: Arc::new(chat),
            store: Arc::new(MemoryStore::new()),
        }
    }

    fn set(&self) -> ProtocolSet {
        ProtocolSet::new(vec![
            Arc::clone(&self.tasks) as Arc<dyn Protocol>,
            Arc::clone(&self.chat) as Arc<dyn Protocol>,
        ])
        .unwrap()
    }

    fn env(&self) -> AppEnv {
        self.w
            .env_on(Arc::clone(&self.store) as Arc<dyn StateStore>)
    }

    fn approve(&self, name: &str, permissions: &[Permission]) -> JoinRequest {
        // In the fixed order (Switch wire 3.1).
        let all: Vec<Permission> = Permission::ALL
            .iter()
            .copied()
            .filter(|p| *p == Permission::ConversationAdd || permissions.contains(p))
            .collect();
        self.w
            .signer
            .approve(
                &app_keys(name),
                &AppSpec::new(&["tasks", "chat"]).with_permissions(&all),
            )
            .unwrap()
    }

    async fn join_with(&self, permissions: &[Permission]) -> App {
        let request = self.approve("wallet", permissions);
        App::join(self.env(), self.set(), World::config(), request)
            .await
            .unwrap()
    }

    async fn join(&self) -> App {
        self.join_with(&[]).await
    }

    async fn load(&self, app: [u8; 16]) -> Result<App, AppError> {
        App::load(self.env(), self.set(), World::config(), app).await
    }

    /// A message of `kind` from bob's app to `to`.
    fn send(&self, to: [u8; 16], kind: &str) -> u64 {
        self.w
            .switch
            .send(
                &self.w.bob,
                &self.w.bob_keys,
                &self.w.bob_cert,
                kind,
                json!({ "text": kind }),
                &[to],
            )
            .unwrap()
            .0
    }

    fn snapshot(&self, app: &[u8; 16]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let ns = crate::store::client_namespace(app);
        self.store.scan(&ns, b"", None, u32::MAX).unwrap()
    }
}

fn kinds(protocol: &Named) -> Vec<String> {
    protocol
        .received
        .lock()
        .unwrap()
        .iter()
        .map(|(_, kind)| kind.clone())
        .collect()
}

async fn read(app: &mut App, times: usize) {
    for _ in 0..times {
        app.receive(None).await.unwrap();
    }
}

fn usage(result: Result<impl std::fmt::Debug, AppError>, part: &str) {
    match result {
        Err(AppError::Refused(Refusal::Usage(why))) if why.contains(part) => {}
        other => panic!("not a usage refusal naming `{part}`: {other:?}"),
    }
}

#[test]
fn test_protocol_set_refuses_names_and_collections_given_twice() {
    let one = |name: &str| Arc::new(named(name)) as Arc<dyn Protocol>;
    let set = ProtocolSet::new(vec![one("tasks"), one("chat")]).unwrap();
    assert_eq!(set.names(), ["tasks", "chat"]);
    usage(
        ProtocolSet::new(vec![one("tasks"), one("tasks")]),
        "given twice",
    );
    usage(
        ProtocolSet::new(vec![one("chat_x")]),
        "isn't a protocol name",
    );
    usage(ProtocolSet::new(Vec::new()), "needs a protocol");
    struct Listing(&'static str);
    impl Protocol for Listing {
        fn name(&self) -> String {
            self.0.into()
        }
        fn has_keys(&self, _: &str) -> bool {
            false
        }
        fn sent_between_own_apps(&self, _: &str) -> bool {
            false
        }
        fn check_scopes(&self, _: &Message, _: &AppCert, _: &AppCert) -> Result<(), String> {
            Ok(())
        }
        fn accepts(&self, _: &AppCert) -> Vec<String> {
            Vec::new()
        }
        fn check_body(&self, _: &ReceivedMessage) -> Result<(), String> {
            Ok(())
        }
        fn resend_needed(&self, _: &ResendNeeded) -> Result<Vec<LocalWrite>, StoreFailure> {
            Ok(Vec::new())
        }
        fn missed(&self, _: &MissedEntries) -> Result<Vec<LocalWrite>, StoreFailure> {
            Ok(Vec::new())
        }
        fn collections(&self) -> Vec<crate::app::Collection> {
            vec![crate::app::Collection::new(
                "shared.items",
                pubky_switch_core::ident::Policy::new(self.0, &[self.0]),
            )]
        }
    }
    usage(
        ProtocolSet::new(vec![Arc::new(Listing("tasks")), Arc::new(Listing("chat"))]),
        "given by two protocols",
    );
}

#[test]
fn test_protocol_set_routes_roots_and_leaves_out_kinds_of_others() {
    let p = Pair::with(
        named("tasks"),
        Named {
            foreign: Some("tasks.extra".into()),
            ..named("chat")
        },
    );
    let set = p.set();
    assert!(set.has_keys("tasks") && set.has_keys("chat"));
    // A root no registered protocol owns has no keys, and no protocol is asked about it.
    assert!(!set.has_keys("news"));
    assert_eq!(
        set.of_kind("chat.item").map(|r| r.name.as_str()),
        Some("chat")
    );
    assert_eq!(
        set.of_kind("tasks_ext.item").map(|r| r.name.as_str()),
        Some("tasks")
    );
    assert!(set.of_kind("chats.item").is_none());
    // `chat` lists a kind of `tasks`: the record leaves it out.
    let cert = cert_for(&p.w.alice, &app_keys("wallet"), START, &["tasks", "chat"]);
    assert_eq!(
        set.accepts(&cert),
        ["tasks.item", "tasks.clear", "chat.item", "chat.clear"]
    );
}

#[tokio::test]
async fn test_protocol_set_hands_each_kind_to_its_owner_only() {
    let p = Pair::new();
    let mut app = p.join().await;
    let me = app.app_id();
    p.send(me, "tasks.item");
    p.send(me, "chat.item");
    let other = p.send(me, "news.item");
    let report = app.receive(None).await.unwrap();
    assert_eq!(kinds(&p.tasks), ["tasks.item"]);
    assert_eq!(kinds(&p.chat), ["chat.item"]);
    // Only the owner judges a kind at check 8: `chat` is never asked about `tasks`'s.
    assert_eq!(*p.chat.checked.lock().unwrap(), ["chat.item"]);
    assert_eq!(*p.tasks.checked.lock().unwrap(), ["tasks.item"]);
    // A kind no registered protocol owns is dropped at check 8.
    assert!(report.events.iter().any(|event| matches!(
        event,
        AppEvent::MessageDropped { seq, check: 8, .. } if *seq == other
    )));
}

#[tokio::test]
async fn test_protocol_set_keeps_each_protocols_local_state_apart() {
    let p = Pair::new();
    let mut app = p.join().await;
    let me = app.app_id();
    p.send(me, "tasks.item");
    p.send(me, "chat.item");
    // `chat` clears its whole key space: `tasks`'s state stays.
    p.send(me, "chat.clear");
    read(&mut app, 1).await;
    let tasks = app.protocol_scan("tasks", b"").await.unwrap();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].1, b"tasks");
    assert!(app.protocol_scan("chat", b"").await.unwrap().is_empty());
    usage(app.protocol_get("news", b"").await, "no protocol `news`");
    usage(app.protocol_commit("news", &[]).await, "no protocol `news`");
}

#[tokio::test]
async fn test_protocol_set_retry_of_one_protocol_lets_the_other_go_on() {
    let p = Pair::new();
    *p.tasks.retrying.lock().unwrap() = 1;
    let mut app = p.join().await;
    let me = app.app_id();
    let first = p.send(me, "tasks.item");
    let second = p.send(me, "chat.item");
    read(&mut app, 1).await;
    // `chat`'s later entry is taken past the held one; `tasks`'s waits.
    assert!(kinds(&p.tasks).is_empty());
    assert_eq!(
        *p.chat.received.lock().unwrap(),
        [(second, "chat.item".into())]
    );
    read(&mut app, 1).await;
    assert_eq!(
        *p.tasks.received.lock().unwrap(),
        [(first, "tasks.item".into())]
    );
    // Each taken once.
    assert_eq!(kinds(&p.chat), ["chat.item"]);
}

#[tokio::test]
async fn test_protocol_set_owed_call_holds_only_its_own_protocol() {
    let p = Pair::new();
    // It fails the call when handed, and again at the next read's retry.
    *p.tasks.failing_missed.lock().unwrap() = 2;
    let mut app = p.join().await;
    let me = app.app_id();
    let now = p.w.clock.now_ms();
    let gap = p.w.switch.push_missed(3, now, now);
    p.send(me, "tasks.item");
    p.send(me, "chat.item");
    read(&mut app, 2).await;
    // `chat` took the missed item and its later entry; `tasks` owes the call, and its
    // later entry waits behind it.
    assert_eq!(*p.chat.missed.lock().unwrap(), [gap]);
    assert_eq!(kinds(&p.chat), ["chat.item"]);
    assert!(p.tasks.missed.lock().unwrap().is_empty());
    assert!(kinds(&p.tasks).is_empty());
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 1);
    read(&mut app, 2).await;
    // The call made again goes to `tasks` alone, then its entry, in feed order.
    assert_eq!(*p.tasks.missed.lock().unwrap(), [gap]);
    assert_eq!(kinds(&p.tasks), ["tasks.item"]);
    assert_eq!(*p.chat.missed.lock().unwrap(), [gap]);
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 0);
}

#[tokio::test]
async fn test_protocol_set_call_one_protocol_keeps_failing_never_stops_the_other() {
    let p = Pair::new();
    *p.tasks.failing_missed.lock().unwrap() = u32::MAX;
    let mut app = p.join().await;
    let me = app.app_id();
    let now = p.w.clock.now_ms();
    p.w.switch.push_missed(3, now, now);
    read(&mut app, 2).await;
    for n in 0..3 {
        p.send(me, "chat.item");
        let report = app.receive(None).await.unwrap();
        assert!(!report.stopped, "read {n}: {report:?}");
    }
    assert_eq!(kinds(&p.chat).len(), 3);
    assert!(p.tasks.missed.lock().unwrap().is_empty());
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 1);
}

/// An own app of alice's that manages the lists, on the sample protocol.
async fn manager(p: &Pair) -> App {
    let request =
        p.w.signer
            .approve(
                &app_keys("manager"),
                &AppSpec::new(&["sample-a"])
                    .with_permissions(&[Permission::ListsRead, Permission::ListsManage]),
            )
            .unwrap();
    App::join(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.w.protocol.clone(),
        World::config(),
        request,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn test_protocol_set_deny_change_one_protocol_fails_stops_the_read_for_all() {
    let p = Pair::new();
    *p.chat.failing_deny.lock().unwrap() = 1;
    let mut app = p.join_with(&[Permission::ListsRead]).await;
    let me = app.app_id();
    let mut manager = manager(&p).await;
    manager.deny(&[7; 32]).await.unwrap();
    p.send(me, "tasks.item");
    let report = app.receive(None).await.unwrap();
    // `tasks` took the change; `chat` failed it, so nothing later goes to anyone.
    assert!(report.stopped, "{report:?}");
    assert_eq!(*p.tasks.denies.lock().unwrap(), [[7; 32]]);
    assert!(p.chat.denies.lock().unwrap().is_empty());
    assert!(kinds(&p.tasks).is_empty());
    read(&mut app, 2).await;
    // Made again for `chat` alone: `tasks` isn't handed it twice.
    assert_eq!(*p.chat.denies.lock().unwrap(), [[7; 32]]);
    assert_eq!(*p.tasks.denies.lock().unwrap(), [[7; 32]]);
    assert_eq!(kinds(&p.tasks), ["tasks.item"]);
}

#[tokio::test]
async fn test_protocol_set_restore_gap_one_protocol_fails_is_told_again_to_each() {
    // A restore owes every protocol the deny list gap at the restored cursor; while one
    // fails it, it stays owed to both, so the tell that takes the copy of the lists hands
    // each the list the copy is taken from, and the read holds for every protocol
    // meanwhile.
    let p = Pair::new();
    let mut app = p.join_with(&[Permission::ListsRead]).await;
    let me = app.app_id();
    read(&mut app, 1).await;
    // The join's gap, the baseline, went to both.
    assert_eq!(p.tasks.gaps.lock().unwrap().len(), 1);
    assert_eq!(p.chat.gaps.lock().unwrap().len(), 1);
    let backup = app.backup_layered().await.unwrap();
    let at = app.cursor().seq;
    drop(app);
    p.tasks.gaps.lock().unwrap().clear();
    p.chat.gaps.lock().unwrap().clear();
    *p.chat.failing_gap.lock().unwrap() = 1;
    let mut restored = App::restore(p.env(), p.set(), World::config(), &backup)
        .await
        .unwrap();
    restored.end_reconcile(UserConfirmed::new()).await.ok();
    p.send(me, "tasks.item");
    let report = restored.receive(None).await.unwrap();
    assert!(report.stopped, "{report:?}");
    assert_eq!(*p.tasks.gaps.lock().unwrap(), [(at, true)]);
    assert!(p.chat.gaps.lock().unwrap().is_empty());
    assert!(kinds(&p.tasks).is_empty());
    read(&mut restored, 2).await;
    assert_eq!(*p.chat.gaps.lock().unwrap(), [(at, true)]);
    assert_eq!(*p.tasks.gaps.lock().unwrap(), [(at, true), (at, true)]);
    assert_eq!(kinds(&p.tasks), ["tasks.item"]);
    assert!(
        !restored
            .reader()
            .exists(crate::app::feed::DENY_GAP)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_protocol_set_gap_noted_again_is_told_to_every_protocol() {
    // Every gap noted is told to every protocol: one that took a gap still owed to another
    // is told the later one too.
    let p = Pair::new();
    *p.chat.failing_gap.lock().unwrap() = 1;
    let mut app = p.join_with(&[Permission::ListsRead]).await;
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped, "{report:?}");
    assert_eq!(p.tasks.gaps.lock().unwrap().len(), 1);
    assert!(p.chat.gaps.lock().unwrap().is_empty());
    app.allow_list().await.unwrap();
    read(&mut app, 1).await;
    assert_eq!(p.tasks.gaps.lock().unwrap().len(), 2);
    assert_eq!(p.chat.gaps.lock().unwrap().len(), 1);
    read(&mut app, 1).await;
    assert_eq!(p.tasks.gaps.lock().unwrap().len(), 2);
    assert_eq!(p.chat.gaps.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_protocol_set_gap_told_without_the_list_is_owed_again_to_each() {
    // An answer that verifies but can't be read tells the gap without the list: while
    // another protocol still owes it, the one told is owed it again too, so both get the
    // list once it reads.
    let p = Pair::new();
    *p.chat.failing_gap.lock().unwrap() = 1;
    let mut app = p.join_with(&[Permission::ListsRead]).await;
    p.w.switch.fail_next(Fault::LeaveOut {
        path: "/allow".into(),
        member: "deny".into(),
    });
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped, "{report:?}");
    let told = |protocol: &Named| -> Vec<bool> {
        protocol
            .gaps
            .lock()
            .unwrap()
            .iter()
            .map(|(_, read)| *read)
            .collect()
    };
    assert_eq!(told(&p.tasks), [false]);
    assert!(told(&p.chat).is_empty());
    read(&mut app, 2).await;
    assert_eq!(told(&p.tasks), [false, true]);
    assert_eq!(told(&p.chat), [true]);
    assert!(
        !app.reader()
            .exists(crate::app::feed::DENY_GAP)
            .await
            .unwrap()
    );
}

async fn with_state(p: &Pair) -> (App, AppBackup) {
    let mut app = p.join().await;
    for name in ["tasks", "chat"] {
        app.protocol_commit(
            name,
            &[LocalWrite::Put {
                key: b"k".to_vec(),
                value: name.as_bytes().to_vec(),
            }],
        )
        .await
        .unwrap();
    }
    let backup = app.backup_layered().await.unwrap();
    (app, backup)
}

#[tokio::test]
async fn test_protocol_set_backup_round_trip_keeps_each_layer_apart() {
    let p = Pair::new();
    let (_app, backup) = with_state(&p).await;
    let layers = backup.layers().unwrap();
    assert_eq!(
        layers
            .iter()
            .map(|l| l.protocol.as_str())
            .collect::<Vec<_>>(),
        ["tasks", "chat"]
    );
    let restored = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &AppBackup::from_bytes(&backup.to_bytes().unwrap()).unwrap(),
    )
    .await
    .unwrap();
    for name in ["tasks", "chat"] {
        assert_eq!(
            restored.protocol_scan(name, b"").await.unwrap(),
            [(b"k".to_vec(), name.as_bytes().to_vec())]
        );
    }
}

/// `backup`'s bytes with its layers changed by `change`.
fn edited(backup: &AppBackup, change: impl FnOnce(&mut Vec<serde_json::Value>)) -> AppBackup {
    let mut bytes: serde_json::Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
    let serde_json::Value::Array(layers) = &mut bytes["layers"] else {
        panic!("no layers");
    };
    change(layers);
    AppBackup::from_bytes(&serde_json::to_vec(&bytes).unwrap()).unwrap()
}

#[tokio::test]
async fn test_protocol_set_restore_refuses_a_layer_of_no_registered_protocol() {
    let p = Pair::new();
    let (app, backup) = with_state(&p).await;
    let foreign = edited(&backup, |layers| {
        layers[1]["name"] = json!("news");
    });
    let store = Arc::new(MemoryStore::new());
    let error = App::restore(
        p.w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &foreign,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, AppError::InvalidData(why) if why.contains("`news`")),
        "{error:?}"
    );
    let ns = crate::store::client_namespace(&app.app_id());
    assert!(store.is_empty(&ns));
}

#[tokio::test]
async fn test_protocol_set_restore_hands_none_to_a_protocol_without_a_layer() {
    let p = Pair::new();
    let (_app, backup) = with_state(&p).await;
    let only_tasks = edited(&backup, |layers| {
        layers.retain(|layer| layer["name"] == json!("tasks"));
    });
    p.chat.restored.lock().unwrap().clear();
    p.tasks.restored.lock().unwrap().clear();
    let restored = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &only_tasks,
    )
    .await
    .unwrap();
    assert_eq!(*p.chat.restored.lock().unwrap(), [false]);
    assert_eq!(*p.tasks.restored.lock().unwrap(), [true]);
    assert!(
        restored
            .protocol_scan("chat", b"")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(restored.protocol_scan("tasks", b"").await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_protocol_set_load_refuses_another_set_and_writes_nothing() {
    let p = Pair::new();
    let app = p.join().await;
    let id = app.app_id();
    drop(app);
    let before = p.snapshot(&id);
    let lacking = App::load(p.env(), Arc::clone(&p.tasks), World::config(), id).await;
    usage(lacking, "`chat`");
    let wider = ProtocolSet::new(vec![
        Arc::clone(&p.tasks) as Arc<dyn Protocol>,
        Arc::clone(&p.chat) as Arc<dyn Protocol>,
        Arc::new(named("news")),
    ])
    .unwrap();
    usage(
        App::load(p.env(), wider, World::config(), id).await,
        "`news`",
    );
    assert_eq!(p.snapshot(&id), before);
    // The set it was set up with, in another order, loads.
    let reordered = ProtocolSet::new(vec![
        Arc::clone(&p.chat) as Arc<dyn Protocol>,
        Arc::clone(&p.tasks) as Arc<dyn Protocol>,
    ])
    .unwrap();
    App::load(p.env(), reordered, World::config(), id)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_protocol_set_join_refuses_a_scope_no_protocol_owns() {
    let p = Pair::new();
    let request = p.approve("wallet", &[]);
    let error = App::join(p.env(), Arc::clone(&p.tasks), World::config(), request)
        .await
        .map(|app| app.app_id());
    usage(error, "`chat`");
    let ns = crate::store::client_namespace(&app_keys("wallet").app_id_bytes());
    assert!(p.store.is_empty(&ns));
}

#[tokio::test]
async fn test_protocol_set_join_refuses_a_certificate_a_protocol_refuses() {
    let p = Pair::with(
        named("tasks"),
        Named {
            refuse_cert: Mutex::new(true),
            ..named("chat")
        },
    );
    let request = p.approve("wallet", &[]);
    let error = App::join(p.env(), p.set(), World::config(), request)
        .await
        .map(|app| app.app_id())
        .unwrap_err();
    assert!(
        matches!(&error, AppError::Refused(Refusal::Certificate { protocol, .. }) if protocol == "chat"),
        "{error:?}"
    );
    let ns = crate::store::client_namespace(&app_keys("wallet").app_id_bytes());
    assert!(p.store.is_empty(&ns));
}

#[tokio::test]
async fn test_protocol_set_duty_event_stays_for_its_owner_until_it_acknowledges() {
    let p = Pair::with(
        Named {
            huge_missed: true,
            ..named("tasks")
        },
        named("chat"),
    );
    let mut app = p.join().await;
    let me = app.app_id();
    let now = p.w.clock.now_ms();
    p.w.switch.push_missed(1, now, now);
    read(&mut app, 2).await;
    // `tasks`'s answer was over the bound: the duty event is for `tasks` alone.
    let tasks = app.unacknowledged_events_for("tasks").await.unwrap();
    let [refused] = tasks.as_slice() else {
        panic!("{tasks:?}");
    };
    assert!(matches!(refused, AppEvent::LocalWritesRefused { .. }));
    let id = refused.id().unwrap();
    assert_eq!(app.event_owners(id).unwrap(), ["tasks"]);
    assert!(
        app.unacknowledged_events_for("chat")
            .await
            .unwrap()
            .is_empty()
    );
    // `chat`'s acknowledgement leaves it, across a load.
    app.ack_events_for("chat", id).await.unwrap();
    usage(app.ack_events_for("news", id).await, "no protocol `news`");
    drop(app);
    let mut app = p.load(me).await.unwrap();
    assert_eq!(
        app.unacknowledged_events_for("tasks").await.unwrap().len(),
        1
    );
    app.ack_events_for("tasks", id).await.unwrap();
    assert!(app.unacknowledged_events().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_protocol_set_batch_local_writes_need_their_protocol() {
    let p = Pair::new();
    let mut app = p.join().await;
    let write = LocalWrite::Put {
        key: b"b".to_vec(),
        value: b"1".to_vec(),
    };
    let op = || OpKind::AllowPut {
        pubky: [9; 32],
        kind: AllowKind::Conversation,
    };
    usage(
        app.submit_batch(OpBatch::new().op(op()).local(write.clone()))
            .await,
        "names its protocol",
    );
    usage(
        app.submit_batch(OpBatch::for_protocol("news").op(op()).local(write.clone()))
            .await,
        "no protocol `news`",
    );
    app.submit_batch(OpBatch::for_protocol("chat").op(op()).local(write))
        .await
        .unwrap();
    assert!(app.protocol_get("chat", b"b").await.unwrap().is_some());
    assert!(app.protocol_get("tasks", b"b").await.unwrap().is_none());
}

#[tokio::test]
async fn test_protocol_set_reconcile_mode_ends_once_every_protocol_ends_it() {
    let p = Pair::new();
    let (_app, backup) = with_state(&p).await;
    let mut app = App::restore(
        p.w.env_on(Arc::clone(&p.store) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    app.refresh_identity().await.unwrap();
    read(&mut app, 1).await;
    assert!(app.reconcile_mode());
    assert!(
        !app.end_reconcile_for("tasks", UserConfirmed::new())
            .await
            .unwrap()
    );
    assert!(app.reconcile_mode());
    usage(
        app.end_reconcile_for("news", UserConfirmed::new()).await,
        "no protocol `news`",
    );
    // Kept across a load.
    let id = app.app_id();
    drop(app);
    let mut app = p.load(id).await.unwrap();
    assert!(app.reconcile_mode());
    assert!(
        app.end_reconcile_for("chat", UserConfirmed::new())
            .await
            .unwrap()
    );
    assert!(!app.reconcile_mode());
}

/// The stubs after `app`'s cursor dropped behind a checkpoint, more than 30 days old, by
/// `writer`'s chain items (Switch wire 7.4.4): `app`'s next read continues from the
/// checkpoint with its continuity unverified.
async fn stubs_dropped_behind(p: &Pair, writer: &mut App, app: &mut App) {
    let deny = |n: u8| OpBatch::new().op(OpKind::DenyPut { pubky: [n; 32] });
    for reader in [&mut *writer, &mut *app] {
        p.send(reader.app_id(), "tasks.item");
        reader.receive(None).await.unwrap();
        reader.submit_batch(deny(0xee)).await.unwrap();
    }
    let at = p.w.switch.lock().apps[&app.app_id()].cursor;
    for n in 1..=5 {
        writer.submit_batch(deny(n)).await.unwrap();
    }
    p.send(writer.app_id(), "tasks.item");
    writer.receive(None).await.unwrap();
    writer.submit_batch(deny(0xee)).await.unwrap();
    p.w.clock
        .advance_ms(31 * pubky_switch_core::records::DAY_MS);
    writer.submit_batch(deny(6)).await.unwrap();
    assert!(p.w.switch.retained().1 > at, "the stubs went");
}

#[tokio::test]
async fn test_protocol_set_reconcile_mode_started_again_asks_every_protocol_again() {
    // `tasks` ended the reconcile mode a first continuity gap started; a second gap starts
    // it again, so `chat` ending it doesn't end it: `tasks` reconciles again too.
    let p = Pair::new();
    p.w.switch.set_retention(Some(crate::testing::Retention {
        checkpoint_behind: 3,
        ..crate::testing::Retention::default()
    }));
    let mut writer = p.join_with(&[Permission::ListsManage]).await;
    let request = p.approve("phone", &[Permission::ListsManage]);
    let mut app = App::join(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        request,
    )
    .await
    .unwrap();
    stubs_dropped_behind(&p, &mut writer, &mut app).await;
    app.receive(None).await.unwrap();
    assert!(app.reconcile_mode());
    assert!(
        !app.end_reconcile_for("tasks", UserConfirmed::new())
            .await
            .unwrap()
    );
    stubs_dropped_behind(&p, &mut writer, &mut app).await;
    app.receive(None).await.unwrap();
    assert!(
        !app.end_reconcile_for("chat", UserConfirmed::new())
            .await
            .unwrap()
    );
    assert!(app.reconcile_mode());
    assert!(
        app.end_reconcile_for("tasks", UserConfirmed::new())
            .await
            .unwrap()
    );
    assert!(!app.reconcile_mode());
}

#[tokio::test]
async fn test_protocol_set_kept_effect_lost_answer_lands_both_protocols_writes_once() {
    let p = Pair::with(
        Named {
            with_ops: true,
            ..named("tasks")
        },
        named("chat"),
    );
    let mut app = p.join().await;
    let me = app.app_id();
    let (_, chat) =
        p.w.switch
            .send(
                &p.w.bob,
                &p.w.bob_keys,
                &p.w.bob_cert,
                "chat.item",
                json!({}),
                &[me],
            )
            .unwrap();
    let (_, tasks) =
        p.w.switch
            .send(
                &p.w.bob,
                &p.w.bob_keys,
                &p.w.bob_cert,
                "tasks.item",
                json!({}),
                &[me],
            )
            .unwrap();
    // The effect's batch is applied and its answer lost: the app crashes with the effect
    // kept (`pending/effect`), `chat`'s write committed with it.
    p.w.switch.fail_next(Fault::LoseAnswer {
        path: "/ops".into(),
    });
    let _ = app.receive(None).await;
    drop(app);
    let mut app = p.load(me).await.unwrap();
    read(&mut app, 2).await;
    // The same bytes went again: one conversation entry, one receive step, each write once.
    assert_eq!(p.w.effects(), 1);
    assert_eq!(kinds(&p.tasks), ["tasks.item"]);
    assert_eq!(kinds(&p.chat), ["chat.item"]);
    assert_eq!(
        app.protocol_scan("tasks", b"").await.unwrap(),
        [(tasks.msg_id.into_bytes(), b"tasks".to_vec())]
    );
    assert_eq!(
        app.protocol_scan("chat", b"").await.unwrap(),
        [(chat.msg_id.into_bytes(), b"chat".to_vec())]
    );
}

/// alice's wallet and bob's shop, each running its own `tasks` and `chat`, on two switches;
/// the wallet's protocols come back with it.
async fn senders() -> (super::protocol_api::Pair, Arc<Named>, Arc<Named>, App, App) {
    let p = super::protocol_api::Pair::new();
    let tasks = Arc::new(named("tasks"));
    let chat = Arc::new(named("chat"));
    let set = |tasks: Arc<Named>, chat: Arc<Named>| {
        ProtocolSet::new(vec![tasks as Arc<dyn Protocol>, chat as Arc<dyn Protocol>]).unwrap()
    };
    let wallet = p
        .join_set(
            &p.alice,
            "wallet",
            set(Arc::clone(&tasks), Arc::clone(&chat)),
            &["tasks", "chat"],
        )
        .await;
    let shop = p
        .join_set(
            &p.bob,
            "shop",
            set(Arc::new(named("tasks")), Arc::new(named("chat"))),
            &["tasks", "chat"],
        )
        .await;
    (p, tasks, chat, wallet, shop)
}

fn untried(delivery: &Option<Delivery>) -> bool {
    matches!(
        delivery,
        Some(Delivery::Queued {
            tries: 0,
            undeliverable_since_ms: None,
            ..
        })
    )
}

#[tokio::test]
async fn test_protocol_set_may_send_holds_its_own_messages_on_every_path() {
    let (p, tasks, chat, mut wallet, mut shop) = senders().await;
    let alice = p.alice.identity().public();
    let to = p.bob.identity().public();
    let message = |kind: &str| OutgoingMessage::new(to, kind, serde_json::Map::new());
    shop.invite(&alice).await.unwrap();
    *tasks.holding.lock().unwrap() = true;
    // `send`: `tasks`'s message stays queued untried, `chat`'s goes.
    let (sent, delivery) = wallet.send(message("tasks.item")).await.unwrap();
    assert!(untried(&Some(delivery.clone())), "{delivery:?}");
    let (other, delivery) = wallet.send(message("chat.item")).await.unwrap();
    assert!(
        matches!(delivery, Delivery::Accepted { .. }),
        "{delivery:?}"
    );
    // `flush_message` and `flush_outbox`: still held.
    let queued = wallet.queue(message("tasks.item")).await.unwrap();
    assert!(untried(&wallet.flush_message(&queued).await.unwrap()));
    let report = wallet.flush_outbox().await.unwrap();
    assert!(report.queued.contains(&sent) && report.queued.contains(&queued));
    assert!(untried(&wallet.delivery(&sent).await.unwrap()));
    assert_eq!(p.bob.switch().entries_from(&alice), 1);
    // Each protocol is asked only about its own messages.
    assert!(
        tasks
            .asked_send
            .lock()
            .unwrap()
            .iter()
            .all(|k| k == "tasks.item")
    );
    assert!(
        chat.asked_send
            .lock()
            .unwrap()
            .iter()
            .all(|k| k == "chat.item")
    );
    assert!(!chat.asked_send.lock().unwrap().is_empty());
    // Once `tasks` lets them go, both go; a re-send it holds waits, `chat`'s goes.
    *tasks.holding.lock().unwrap() = false;
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 3);
    *tasks.holding.lock().unwrap() = true;
    wallet.resend(&sent).await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 3);
    wallet.resend(&other).await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 4);
    *tasks.holding.lock().unwrap() = false;
    wallet.flush_outbox().await.unwrap();
    assert_eq!(p.bob.switch().entries_from(&alice), 5);
}

#[tokio::test]
async fn test_protocol_set_may_send_hold_is_no_try_when_the_recipient_refuses() {
    // bob doesn't admit alice: `chat`'s message is tried and answered `403 not_admitted`,
    // its wait begun; `tasks`'s, held, is never tried, so its wait doesn't start.
    let (p, tasks, _chat, mut wallet, _shop) = senders().await;
    let to = p.bob.identity().public();
    let message = |kind: &str| OutgoingMessage::new(to, kind, serde_json::Map::new());
    *tasks.holding.lock().unwrap() = true;
    let (held, _) = wallet.send(message("tasks.item")).await.unwrap();
    let (refused, delivery) = wallet.send(message("chat.item")).await.unwrap();
    assert!(
        matches!(
            delivery,
            Delivery::Queued {
                undeliverable_since_ms: Some(_),
                ..
            }
        ),
        "{delivery:?}"
    );
    for _ in 0..3 {
        wallet.flush_outbox().await.unwrap();
    }
    assert!(untried(&wallet.delivery(&held).await.unwrap()));
    assert!(!untried(&wallet.delivery(&refused).await.unwrap()));
    assert_eq!(p.bob.switch().entries_from(&p.alice.identity().public()), 0);
}

/// The conversation entries `switch` applied, by counterparty.
fn conversations_added(switch: &crate::testing::ScriptedSwitch) -> Vec<[u8; 32]> {
    let mut added: Vec<[u8; 32]> = switch
        .applied()
        .iter()
        .filter_map(|op| match op.body().kind {
            OpKind::AllowPut {
                pubky,
                kind: AllowKind::Conversation,
            } => Some(pubky),
            _ => None,
        })
        .collect();
    added.sort();
    added
}

/// carol's identity.
fn carol() -> [u8; 32] {
    pubky_switch_core::keys::IdentityKey::from_secret(seed("carol/identity")).public()
}

/// A provider loss of an app running the sample protocol and `chat`, which names carol and
/// fails its next `failing` loss calls; the app's store.
async fn lost_beside(
    failing: u32,
) -> (
    super::moves::Lost,
    Arc<super::moves::LossProtocol>,
    Arc<dyn StateStore>,
) {
    let chat = Arc::new(super::moves::LossProtocol {
        name: Some("chat"),
        counterparties: vec![carol()],
        failing: Mutex::new(failing),
        ..super::moves::LossProtocol::default()
    });
    let store = Arc::new(MemoryStore::new()) as Arc<dyn StateStore>;
    let lost = super::moves::lost_world_beside(
        Arc::clone(&store),
        &[
            Permission::ListsRead,
            Permission::ListsManage,
            Permission::ConversationAdd,
        ],
        false,
        true,
        vec![Arc::clone(&chat)],
    )
    .await;
    (lost, chat, store)
}

/// Both protocols' writes landed once each, under their own prefixes, and both their
/// counterparties were added back.
async fn both_answered(lost: &super::moves::Lost, app: &App) {
    for name in ["sample", "chat"] {
        assert_eq!(
            app.protocol_get(name, b"lost/1").await.unwrap(),
            Some(b"1".to_vec()),
            "{name}"
        );
    }
    let mut both = vec![lost.w.bob.public(), carol()];
    both.sort();
    assert_eq!(conversations_added(&lost.next), both);
}

#[tokio::test]
async fn test_protocol_set_provider_loss_asks_each_protocol_once_and_merges_conversations() {
    let (lost, chat, store) = lost_beside(0).await;
    let (app, events) = super::moves::follow_loss(&lost, store).await.unwrap();
    assert!(super::moves::has(&events, |e| matches!(
        e,
        AppEvent::ProviderRecovered { generation: 2 }
    )));
    // Each protocol was asked once, with the same loss.
    let sample = lost.protocol.losses.lock().unwrap().clone();
    assert_eq!(sample.len(), 1);
    assert_eq!(*chat.losses.lock().unwrap(), sample);
    both_answered(&lost, &app).await;
}

#[tokio::test]
async fn test_protocol_set_provider_loss_call_one_protocol_fails_is_made_again_for_it_alone() {
    let (lost, chat, store) = lost_beside(1).await;
    // `chat` fails its call: the recovery stops at the step, with the protocol's error, and
    // `sample`'s answer, asked first, is committed.
    let first = super::moves::follow_loss(&lost, Arc::clone(&store)).await;
    assert!(
        matches!(&first, Err(AppError::Protocol(failure))
            if *failure.error() == StoreError::Unavailable),
        "{:?}",
        first.map(|_| ())
    );
    assert_eq!(lost.protocol.losses.lock().unwrap().len(), 1);
    assert!(chat.losses.lock().unwrap().is_empty());
    assert!(conversations_added(&lost.next).is_empty());
    // The next call asks `chat` alone; the recovery goes on, with both answers.
    let (app, events) = super::moves::follow_loss(&lost, store).await.unwrap();
    assert!(super::moves::has(&events, |e| matches!(
        e,
        AppEvent::ProviderRecovered { generation: 2 }
    )));
    let sample = lost.protocol.losses.lock().unwrap().clone();
    assert_eq!(sample.len(), 1, "`sample` isn't asked twice");
    assert_eq!(*chat.losses.lock().unwrap(), sample);
    both_answered(&lost, &app).await;
}

/// The `expires_at` of `app`'s record.
fn record_expiry(app: &App) -> Option<u64> {
    pubky_switch_core::records::AppRecord::verify(app.record(), &app.identity())
        .unwrap()
        .expires_at()
}

fn a_member() -> Option<serde_json::Map<String, serde_json::Value>> {
    let mut member = serde_json::Map::new();
    member.insert("a".into(), json!(1));
    Some(member)
}

#[tokio::test]
async fn test_protocol_set_record_expiry_is_the_earliest_any_protocol_asked_for() {
    let p = Pair::new();
    let mut app = p.join().await;
    let now = p.w.clock.now_ms();
    let day = pubky_switch_core::records::DAY_MS;
    app.set_protocol_member("tasks", a_member(), Some(now + 30 * day))
        .await
        .unwrap();
    assert_eq!(record_expiry(&app), Some(now + 30 * day));
    // `chat` asks for an earlier one: the record takes it.
    app.set_protocol_member("chat", a_member(), Some(now + 10 * day))
        .await
        .unwrap();
    assert_eq!(record_expiry(&app), Some(now + 10 * day));
    // `tasks` renewing for later doesn't move it past `chat`'s, across a load too.
    app.renew_record("tasks", Some(now + 60 * day))
        .await
        .unwrap();
    assert_eq!(record_expiry(&app), Some(now + 10 * day));
    let id = app.app_id();
    drop(app);
    let mut app = p.load(id).await.unwrap();
    // `chat` asks for none: `tasks`'s is the record's.
    app.renew_record("chat", None).await.unwrap();
    assert_eq!(record_expiry(&app), Some(now + 60 * day));
    // Neither asks for one: the record doesn't expire.
    app.set_protocol_member("tasks", None, None).await.unwrap();
    assert_eq!(record_expiry(&app), None);
    let record = app.record().clone();
    // The member and the expiry of a protocol not registered are refused, nothing signed.
    usage(
        app.set_protocol_member("news", a_member(), Some(now)).await,
        "no protocol `news`",
    );
    usage(
        app.renew_record("news", Some(now)).await,
        "no protocol `news`",
    );
    assert_eq!(app.record(), &record);
}

#[tokio::test]
async fn test_protocol_set_record_expiry_lapsed_refuses_the_renewal_naming_its_protocol() {
    let p = Pair::new();
    let mut app = p.join().await;
    let now = p.w.clock.now_ms();
    let day = pubky_switch_core::records::DAY_MS;
    app.set_protocol_member("tasks", a_member(), Some(now + day))
        .await
        .unwrap();
    app.renew_record("chat", Some(now + 30 * day))
        .await
        .unwrap();
    p.w.clock.advance_ms(2 * day);
    let record = app.record().clone();
    let delivered = p.w.switch.app(&app.app_id()).record;
    // `tasks`'s expiry lapsed: `chat`'s renewal is refused, naming `tasks`, and nothing is
    // signed or sent.
    usage(
        app.renew_record("chat", Some(now + 60 * day)).await,
        "`tasks`",
    );
    usage(
        app.set_protocol_member("chat", a_member(), None).await,
        "`tasks`",
    );
    assert_eq!(app.record(), &record);
    assert_eq!(p.w.switch.app(&app.app_id()).record, delivered);
    // One asked at now has lapsed too.
    usage(
        app.renew_record("tasks", Some(p.w.clock.now_ms())).await,
        "`tasks`",
    );
    // `tasks` asking for a later one renews it.
    let later = p.w.clock.now_ms() + day;
    app.renew_record("tasks", Some(later)).await.unwrap();
    assert_eq!(record_expiry(&app), Some(later));
}

#[tokio::test]
async fn test_protocol_set_record_expiries_both_lapsed_renew_in_turn() {
    // Both protocols' expiries lapse: each renewal is refused while the other's has
    // lapsed, but its own ask is kept, so the second renewal signs the record, across a
    // reload too; an ask cleared to none is kept the same way.
    let p = Pair::new();
    let mut app = p.join().await;
    let now = p.w.clock.now_ms();
    let day = pubky_switch_core::records::DAY_MS;
    app.renew_record("tasks", Some(now + day)).await.unwrap();
    app.renew_record("chat", Some(now + 2 * day)).await.unwrap();
    p.w.clock.advance_ms(3 * day);
    let record = app.record().clone();
    let later = p.w.clock.now_ms() + 10 * day;
    usage(app.renew_record("tasks", Some(later)).await, "`chat`");
    assert_eq!(app.record(), &record, "nothing signed yet");
    let me = app.app_id();
    drop(app);
    let mut app = p.load(me).await.unwrap();
    app.renew_record("chat", None).await.unwrap();
    assert_eq!(record_expiry(&app), Some(later));
    // `tasks`'s lapses again: `chat`'s later ask is kept, and `tasks` clearing its own
    // signs the record with `chat`'s.
    p.w.clock.advance_ms(11 * day);
    let far = p.w.clock.now_ms() + 30 * day;
    usage(app.renew_record("chat", Some(far)).await, "`tasks`");
    app.renew_record("tasks", None).await.unwrap();
    assert_eq!(record_expiry(&app), Some(far));
}

#[tokio::test]
async fn test_protocol_set_record_expiries_go_with_a_backup_and_one_of_no_protocol_refuses() {
    let p = Pair::new();
    let mut app = p.join().await;
    let now = p.w.clock.now_ms();
    let day = pubky_switch_core::records::DAY_MS;
    app.set_protocol_member("chat", a_member(), Some(now + 10 * day))
        .await
        .unwrap();
    app.renew_record("tasks", Some(now + 60 * day))
        .await
        .unwrap();
    let backup = app.backup().await.unwrap();
    let mut restored = App::restore(
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &backup,
    )
    .await
    .unwrap();
    // The restore kept both: `chat` asking for none leaves `tasks`'s.
    restored.renew_record("chat", None).await.unwrap();
    assert_eq!(record_expiry(&restored), Some(now + 60 * day));
    // An expiry of a protocol not registered refuses the restore, which writes nothing.
    let mut bytes: serde_json::Value = serde_json::from_slice(&backup.to_bytes().unwrap()).unwrap();
    bytes["record_expiries"][0][0] = json!("news");
    let foreign = AppBackup::from_bytes(&serde_json::to_vec(&bytes).unwrap()).unwrap();
    let store = Arc::new(MemoryStore::new());
    let error = App::restore(
        p.w.env_on(Arc::clone(&store) as Arc<dyn StateStore>),
        p.set(),
        World::config(),
        &foreign,
    )
    .await
    .map(|app| app.app_id())
    .unwrap_err();
    assert!(
        matches!(&error, AppError::InvalidData(why) if why.contains("`news`")),
        "{error:?}"
    );
    assert!(store.is_empty(&crate::store::client_namespace(&app.app_id())));
}

#[tokio::test]
async fn test_protocol_set_owed_call_never_lets_the_cursor_pass_what_its_protocol_must_see() {
    let p = Pair::new();
    // `tasks` fails every missed call until it is let through.
    *p.tasks.failing_missed.lock().unwrap() = u32::MAX;
    let mut app = p.join().await;
    let me = app.app_id();
    let now = p.w.clock.now_ms();
    let first_gap = p.w.switch.push_missed(3, now, now);
    let held = p.send(me, "tasks.item");
    let chat_first = p.send(me, "chat.item");
    let second_gap = p.w.switch.push_missed(2, now, now);
    let chat_second = p.send(me, "chat.item");
    read(&mut app, 4).await;
    // `chat` took what comes before the second call, in feed order; `tasks` owes the first
    // call, its entry is held, and the second call is owed to it behind the first. The
    // second call is past the cursor, which stays before the held entry, so the feed
    // stops at it: `chat`'s later entry waits until the cursor gets there.
    assert_eq!(
        *p.chat.taken.lock().unwrap(),
        [first_gap, chat_first, second_gap]
    );
    assert!(p.tasks.taken.lock().unwrap().is_empty());
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 2);
    // The cursor stays before the held entry, past the call owed before it.
    assert!(
        app.cursor().seq >= first_gap && app.cursor().seq < held,
        "{:?}",
        app.cursor()
    );
    // Once `tasks` takes the calls, it gets the rest in feed order, each once; `chat`
    // gets its later entry, and nothing again, and the cursor goes on.
    *p.tasks.failing_missed.lock().unwrap() = 0;
    read(&mut app, 4).await;
    assert_eq!(
        *p.tasks.taken.lock().unwrap(),
        [first_gap, held, second_gap]
    );
    assert_eq!(
        *p.chat.taken.lock().unwrap(),
        [first_gap, chat_first, second_gap, chat_second]
    );
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 0);
    assert!(app.cursor().seq >= chat_second, "{:?}", app.cursor());
}

#[tokio::test]
async fn test_protocol_set_load_refuses_a_certificate_with_a_root_no_protocol_owns() {
    let p = Pair::new();
    let id = p.join().await.app_id();
    // The certificate the app holds names a scope of a root none of its protocols owns.
    let cert = cert_for(
        &p.w.alice,
        &app_keys("wallet"),
        START,
        &["tasks", "chat", "news"],
    );
    let ns = crate::store::client_namespace(&id);
    let mut batch = crate::store::WriteBatch::new();
    batch
        .put(
            &ns,
            b"cert".to_vec(),
            crate::app::state::encode(cert.signed()).unwrap(),
        )
        .unwrap();
    p.store.commit(batch).unwrap();
    let before = p.snapshot(&id);
    usage(p.load(id).await, "`news`");
    assert_eq!(p.snapshot(&id), before);
}

#[tokio::test]
async fn test_protocol_set_check_8_refuses_a_kind_no_protocol_owns_and_asks_only_the_owner() {
    use pubky_switch_core::receive::KindRules;
    let p = Pair::new();
    let app = p.join().await;
    let me = app.app_id();
    let set = p.set();
    let own = cert_for(&p.w.alice, &app_keys("wallet"), START, &["tasks", "chat"]);
    let rules = crate::app::protocols::Rules::new(&set, &own, &[]);
    let message = |kind: &str| {
        p.w.switch
            .send(
                &p.w.bob,
                &p.w.bob_keys,
                &p.w.bob_cert,
                kind,
                json!({}),
                &[me],
            )
            .unwrap()
            .1
    };
    // A kind no registered protocol owns fails check 8 itself, no protocol asked.
    let refused = rules.check_scopes(&message("news.item"), &p.w.bob_cert);
    assert!(
        matches!(&refused, Err(pubky_switch_core::Error::Invalid(why))
            if why == crate::app::protocols::NO_OWNER),
        "{refused:?}"
    );
    assert!(p.tasks.checked.lock().unwrap().is_empty());
    assert!(p.chat.checked.lock().unwrap().is_empty());
    // An owned kind goes to its owner alone.
    rules
        .check_scopes(&message("chat.item"), &p.w.bob_cert)
        .unwrap();
    assert_eq!(*p.chat.checked.lock().unwrap(), ["chat.item"]);
    assert!(p.tasks.checked.lock().unwrap().is_empty());
}

/// `p`'s app running `tasks` alone, its certificate holding only `tasks`'s scopes.
async fn tasks_alone(p: &Pair) -> App {
    let request =
        p.w.signer
            .approve(&app_keys("wallet"), &AppSpec::new(&["tasks"]))
            .unwrap();
    App::join(
        p.env(),
        Arc::clone(&p.tasks) as Arc<dyn Protocol>,
        World::config(),
        request,
    )
    .await
    .unwrap()
}

/// The signer renews `app`'s certificate with `scopes` (Switch spec 3.2 steps 1 and 2):
/// `app` reads its `cert.put`, then the own `identity.json` listing it.
async fn renewed_and_listed(p: &Pair, app: &mut App, scopes: &[&str]) -> AppCert {
    let me = app.app_id();
    let old = app.cert().clone();
    let renewed = issue_cert(
        &p.w.alice,
        &app_keys("wallet"),
        &AppSpec::new(scopes),
        p.w.clock.now_ms() + 1000,
    )
    .unwrap();
    p.w.switch
        .signer_op(OpKind::CertPut {
            target_app_id: me,
            cert: renewed.signed().clone(),
        })
        .unwrap();
    app.receive(None).await.unwrap();
    p.w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.apps.push(pubky_switch_core::records::ListedApp {
            app_id: me,
            cert: renewed.hash(),
        });
        body.renewed.retain(|r| r.app_id != me);
        body.renewed.push(pubky_switch_core::records::RenewedCert {
            app_id: me,
            cert: old.hash(),
            until: None,
        });
    });
    app.receive(None).await.unwrap();
    renewed
}

/// The certificate refusals `app` keeps, with the refused certificates' `issued_at`.
async fn cert_refusals(app: &mut App) -> Vec<(u64, CertificateRefusal)> {
    app.unacknowledged_events()
        .await
        .unwrap()
        .into_iter()
        .filter_map(|event| match event {
            AppEvent::CertificateRefused {
                issued_at, refusal, ..
            } => Some((issued_at, refusal)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn test_protocol_set_renewal_with_a_root_no_protocol_owns_is_not_taken() {
    // The signer renews an app running `tasks` alone with `chat`'s scopes too: taken, the
    // app would never load again, with `tasks` (an unowned root) or with both (another
    // set). It keeps its certificate, and the host is told once, naming the root.
    let p = Pair::new();
    let mut app = tasks_alone(&p).await;
    let me = app.app_id();
    let old = app.cert().clone();
    let renewed = renewed_and_listed(&p, &mut app, &["tasks", "chat"]).await;
    assert_eq!(app.cert().hash(), old.hash());
    assert_eq!(
        cert_refusals(&mut app).await,
        [(
            renewed.issued_at(),
            CertificateRefusal::UnownedRoot("chat".into())
        )]
    );
    // Later reads, a look in the directory among them, neither take it nor tell it again.
    p.w.clock.advance_ms(crate::app::identity::DOC_CACHE_MS + 1);
    read(&mut app, 2).await;
    assert_eq!(app.cert().hash(), old.hash());
    assert_eq!(cert_refusals(&mut app).await.len(), 1);
    drop(app);
    let app = App::load(
        p.env(),
        Arc::clone(&p.tasks) as Arc<dyn Protocol>,
        World::config(),
        me,
    )
    .await
    .unwrap();
    assert_eq!(app.cert().hash(), old.hash());
}

#[tokio::test]
async fn test_protocol_set_renewal_a_protocol_refuses_is_not_taken_and_a_later_one_is() {
    let p = Pair::new();
    let mut app = p.join().await;
    let me = app.app_id();
    let old = app.cert().clone();
    *p.chat.refuse_cert.lock().unwrap() = true;
    let refused = renewed_and_listed(&p, &mut app, &["tasks", "chat"]).await;
    assert_eq!(app.cert().hash(), old.hash());
    let refusals = cert_refusals(&mut app).await;
    let [(issued_at, CertificateRefusal::Protocol { protocol, .. })] = refusals.as_slice() else {
        panic!("not a protocol's refusal");
    };
    assert_eq!(
        (*issued_at, protocol.as_str()),
        (refused.issued_at(), "chat")
    );
    // A later renewal both protocols run with is taken, and the app loads with it.
    *p.chat.refuse_cert.lock().unwrap() = false;
    p.w.clock.advance_ms(2000);
    let taken = renewed_and_listed(&p, &mut app, &["tasks", "chat"]).await;
    assert_eq!(app.cert().hash(), taken.hash());
    drop(app);
    assert_eq!(p.load(me).await.unwrap().cert().hash(), taken.hash());
}

#[tokio::test]
async fn test_protocol_set_restore_in_place_keeps_the_owners_backup_and_store_give_a_call() {
    // A missed call both protocols fail is in a layered backup; `tasks` then takes it and
    // `chat` fails it again. Restored in place, `tasks`'s layer is back without the call's
    // writes: the call is owed to both again, the backup's owners with the store's.
    let p = Pair::with(
        Named {
            failing_missed: Mutex::new(1),
            ..named("tasks")
        },
        Named {
            failing_missed: Mutex::new(2),
            ..named("chat")
        },
    );
    let mut app = p.join().await;
    let now = p.w.clock.now_ms();
    let seq = p.w.switch.push_missed(1, now, now);
    read(&mut app, 1).await;
    let backup = app.backup_layered().await.unwrap();
    read(&mut app, 1).await;
    assert_eq!(*p.tasks.missed.lock().unwrap(), [seq]);
    assert!(p.chat.missed.lock().unwrap().is_empty());
    drop(app);
    p.tasks.missed.lock().unwrap().clear();
    let mut restored = App::restore(p.env(), p.set(), World::config(), &backup)
        .await
        .unwrap();
    let kept = restored
        .reader()
        .scan::<crate::app::feed::Owed>(crate::app::state::key::OWED_PREFIX)
        .await
        .unwrap();
    let [(_, owed)] = <[_; 1]>::try_from(kept).unwrap();
    assert_eq!(owed.to, ["tasks", "chat"]);
    restored.end_reconcile(UserConfirmed::new()).await.ok();
    read(&mut restored, 1).await;
    assert_eq!(*p.tasks.missed.lock().unwrap(), [seq]);
    assert_eq!(*p.chat.missed.lock().unwrap(), [seq]);
    assert_eq!(
        restored
            .protocol_get("tasks", format!("missed/{seq}").as_bytes())
            .await
            .unwrap(),
        Some(b"1".to_vec())
    );
    assert_eq!(restored.owed_protocol_calls().await.unwrap(), 0);
}

/// A duty event planted in `p`'s store for `app`, for the protocols `to`.
fn plant_duty(p: &Pair, app: &[u8; 16], n: u64, to: &[&str]) {
    let kept = crate::app::events::KeptDuty {
        to: to.iter().map(|name| (*name).to_owned()).collect(),
        duty: crate::app::events::Duty::KeptBatchDropped { batch_id: [1; 16] },
    };
    let mut batch = crate::store::WriteBatch::new();
    batch
        .put(
            &crate::store::client_namespace(app),
            crate::app::state::key::duty(n).into_bytes(),
            crate::app::state::encode(&kept).unwrap(),
        )
        .unwrap();
    p.store.commit(batch).unwrap();
}

#[tokio::test]
async fn test_protocol_set_duty_event_of_no_registered_protocol_fails_the_load() {
    // An event for a protocol not registered, or for none, could never be acknowledged:
    // the load fails closed. A restore in place keeps it for the registered protocols it
    // names, and leaves one for none of them behind, counted.
    let p = Pair::new();
    let mut app = p.join().await;
    let me = app.app_id();
    let backup = app.backup_layered().await.unwrap();
    drop(app);
    plant_duty(&p, &me, 900, &["chat"]);
    p.load(me).await.unwrap();
    for to in [&["news"][..], &[], &["tasks", "news"]] {
        plant_duty(&p, &me, 900, to);
        assert!(
            matches!(
                p.load(me).await.map(|app| app.app_id()),
                Err(AppError::Store(StoreError::Corrupt))
            ),
            "{to:?}"
        );
    }
    plant_duty(&p, &me, 901, &["news"]);
    let mut restored = App::restore(p.env(), p.set(), World::config(), &backup)
        .await
        .unwrap();
    let events = restored.take_events();
    assert!(
        events.iter().any(|e| matches!(
            e,
            AppEvent::RestoreLeftBehind {
                duty_events: 1,
                owed_calls: 0,
                ..
            }
        )),
        "{events:?}"
    );
    let dropped = restored
        .unacknowledged_events()
        .await
        .unwrap()
        .into_iter()
        .find_map(|e| matches!(e, AppEvent::KeptBatchDropped { .. }).then(|| e.id()))
        .flatten()
        .unwrap();
    assert_eq!(restored.event_owners(dropped).unwrap(), ["tasks"]);
    drop(restored);
    p.load(me).await.unwrap();
}

#[tokio::test]
async fn test_protocol_set_restore_in_place_owes_a_call_only_the_store_holds_to_every_protocol() {
    // `tasks` takes a missed call after the backup and `chat` fails it; the restore in place
    // puts `tasks`'s layer back without the call's writes, so the call the store carries is
    // owed to both, and each takes it.
    let p = Pair::with(
        named("tasks"),
        Named {
            failing_missed: Mutex::new(u32::MAX),
            ..named("chat")
        },
    );
    let mut app = p.join().await;
    read(&mut app, 1).await;
    let backup = app.backup_layered().await.unwrap();
    let now = p.w.clock.now_ms();
    let seq = p.w.switch.push_missed(1, now, now);
    read(&mut app, 1).await;
    assert_eq!(*p.tasks.missed.lock().unwrap(), [seq]);
    assert!(p.chat.missed.lock().unwrap().is_empty());
    drop(app);
    p.tasks.missed.lock().unwrap().clear();
    *p.chat.failing_missed.lock().unwrap() = 0;
    let mut restored = App::restore(p.env(), p.set(), World::config(), &backup)
        .await
        .unwrap();
    restored.end_reconcile(UserConfirmed::new()).await.ok();
    read(&mut restored, 4).await;
    assert_eq!(*p.tasks.missed.lock().unwrap(), [seq]);
    assert_eq!(*p.chat.missed.lock().unwrap(), [seq]);
    assert_eq!(restored.owed_protocol_calls().await.unwrap(), 0);
}

#[tokio::test]
async fn test_protocol_set_fresh_restore_hands_a_call_after_the_backup_to_every_protocol() {
    // The same call, restored on another store: the feed reads its item again and hands it
    // to both.
    let p = Pair::with(
        named("tasks"),
        Named {
            failing_missed: Mutex::new(u32::MAX),
            ..named("chat")
        },
    );
    let mut app = p.join().await;
    read(&mut app, 1).await;
    let backup = app.backup_layered().await.unwrap();
    let now = p.w.clock.now_ms();
    let seq = p.w.switch.push_missed(1, now, now);
    read(&mut app, 1).await;
    drop(app);
    p.tasks.missed.lock().unwrap().clear();
    *p.chat.failing_missed.lock().unwrap() = 0;
    let env =
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, p.set(), World::config(), &backup)
        .await
        .unwrap();
    restored.end_reconcile(UserConfirmed::new()).await.ok();
    read(&mut restored, 4).await;
    assert_eq!(*p.tasks.missed.lock().unwrap(), [seq]);
    assert_eq!(*p.chat.missed.lock().unwrap(), [seq]);
    assert_eq!(restored.owed_protocol_calls().await.unwrap(), 0);
}

#[tokio::test]
async fn test_protocol_set_gap_waits_behind_a_call_one_protocol_owes() {
    // `tasks` owes a missed call it keeps failing: a gap noted after it isn't told to any
    // protocol, and the read holds; once `tasks` takes the call, the gap follows it.
    let p = Pair::with(
        Named {
            failing_missed: Mutex::new(u32::MAX),
            ..named("tasks")
        },
        named("chat"),
    );
    let mut app = p.join_with(&[Permission::ListsRead]).await;
    read(&mut app, 1).await;
    let now = p.w.clock.now_ms();
    let seq = p.w.switch.push_missed(1, now, now);
    read(&mut app, 1).await;
    p.tasks.gaps.lock().unwrap().clear();
    p.chat.gaps.lock().unwrap().clear();
    app.allow_list().await.unwrap();
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped, "{report:?}");
    assert!(p.tasks.gaps.lock().unwrap().is_empty());
    assert!(p.chat.gaps.lock().unwrap().is_empty());
    *p.tasks.failing_missed.lock().unwrap() = 0;
    read(&mut app, 1).await;
    assert_eq!(*p.tasks.missed.lock().unwrap(), [seq]);
    assert_eq!(p.tasks.gaps.lock().unwrap().len(), 1);
    assert_eq!(p.chat.gaps.lock().unwrap().len(), 1);
}

/// `tasks` alone, with `lists.read`.
async fn solo(p: &Pair) -> App {
    let all: Vec<Permission> = Permission::ALL
        .iter()
        .copied()
        .filter(|q| *q == Permission::ConversationAdd || *q == Permission::ListsRead)
        .collect();
    let request =
        p.w.signer
            .approve(
                &app_keys("wallet"),
                &AppSpec::new(&["tasks"]).with_permissions(&all),
            )
            .unwrap();
    App::join(
        p.env(),
        Arc::clone(&p.tasks) as Arc<dyn Protocol>,
        World::config(),
        request,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn test_protocol_set_single_protocol_failing_a_call_stops_the_read() {
    // With one protocol a call it fails stops the read, and a gap noted after it waits.
    let p = Pair::with(
        Named {
            failing_missed: Mutex::new(u32::MAX),
            ..named("tasks")
        },
        named("chat"),
    );
    let mut app = solo(&p).await;
    let me = app.app_id();
    read(&mut app, 1).await;
    let now = p.w.clock.now_ms();
    let seq = p.w.switch.push_missed(1, now, now);
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped, "{report:?}");
    p.tasks.gaps.lock().unwrap().clear();
    app.allow_list().await.unwrap();
    p.send(me, "tasks.item");
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped, "{report:?}");
    assert!(p.tasks.gaps.lock().unwrap().is_empty());
    assert!(kinds(&p.tasks).is_empty());
    *p.tasks.failing_missed.lock().unwrap() = 0;
    read(&mut app, 2).await;
    assert_eq!(*p.tasks.missed.lock().unwrap(), [seq]);
    assert_eq!(p.tasks.gaps.lock().unwrap().len(), 1);
    assert_eq!(kinds(&p.tasks), ["tasks.item"]);
}

#[tokio::test]
async fn test_protocol_set_record_write_waits_behind_a_call_its_protocol_owes() {
    // `tasks` owes a missed call it keeps failing: a write of its record isn't judged for
    // it yet, so the cursor stays before the write while `chat` takes its later entry; once
    // `tasks` takes the call, the cursor passes both.
    let list = crate::app::Collection::new(
        "tasks.list",
        pubky_switch_core::ident::Policy::new("tasks", &["tasks"]),
    );
    let p = Pair::with(
        Named {
            failing_missed: Mutex::new(u32::MAX),
            collections: vec![list.clone()],
            ..named("tasks")
        },
        named("chat"),
    );
    let mut app = p.join().await;
    let me = app.app_id();
    read(&mut app, 1).await;
    let now = p.w.clock.now_ms();
    let missed = p.w.switch.push_missed(1, now, now);
    read(&mut app, 1).await;
    assert!(p.tasks.missed.lock().unwrap().is_empty());
    let target = crate::app::RecordTarget::new(list, b"key");
    app.put_record(&target, b"{}", vec![]).await.unwrap();
    let later = p.send(me, "chat.item");
    read(&mut app, 2).await;
    assert_eq!(kinds(&p.chat), ["chat.item"]);
    assert!(app.cursor().seq < later, "{:?}", app.cursor());
    *p.tasks.failing_missed.lock().unwrap() = 0;
    read(&mut app, 2).await;
    assert_eq!(*p.tasks.missed.lock().unwrap(), [missed]);
    assert!(app.cursor().seq >= later, "{:?}", app.cursor());
    assert_eq!(kinds(&p.chat), ["chat.item"], "handed once");
}

#[tokio::test]
async fn test_protocol_set_undelivered_message_is_told_to_its_kinds_protocol_only() {
    // A message given up is a duty event of the protocol of its kind alone.
    let (p, _tasks, _chat, mut wallet, _shop) = senders().await;
    let to = p.bob.identity().public();
    let queued = wallet
        .queue(OutgoingMessage::new(
            to,
            "chat.item",
            serde_json::Map::new(),
        ))
        .await
        .unwrap();
    wallet.take_events();
    assert_eq!(
        wallet.withdraw_queued(&to).await.unwrap(),
        vec![queued.clone()]
    );
    let events = wallet.take_events();
    let told: Vec<&AppEvent> = events
        .iter()
        .filter(|e| matches!(e, AppEvent::MessageUndelivered { msg_id, .. } if *msg_id == queued))
        .collect();
    assert_eq!(told.len(), 1);
    let id = told[0].id().unwrap();
    assert_eq!(wallet.event_owners(id), Some(&["chat".to_string()][..]));
    assert!(!wallet.event_is_for(told[0], "tasks"));
}

#[tokio::test]
async fn test_protocol_set_call_every_protocol_owes_stops_the_read() {
    // Both protocols fail the missed call: nothing can be handed to either, so the page
    // stops after it and every later read holds until one takes it.
    let p = Pair::with(
        Named {
            failing_missed: Mutex::new(u32::MAX),
            ..named("tasks")
        },
        Named {
            failing_missed: Mutex::new(u32::MAX),
            ..named("chat")
        },
    );
    let mut app = p.join().await;
    let me = app.app_id();
    read(&mut app, 1).await;
    let now = p.w.clock.now_ms();
    let seq = p.w.switch.push_missed(1, now, now);
    assert!(app.receive(None).await.unwrap().stopped);
    p.send(me, "chat.item");
    assert!(app.receive(None).await.unwrap().stopped);
    assert!(kinds(&p.chat).is_empty());
    *p.chat.failing_missed.lock().unwrap() = 0;
    read(&mut app, 2).await;
    assert_eq!(*p.chat.missed.lock().unwrap(), [seq]);
    assert_eq!(kinds(&p.chat), ["chat.item"]);
    assert!(p.tasks.missed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_protocol_set_restored_gap_waits_behind_a_call_a_protocol_owes() {
    // `tasks` owes a missed call it keeps failing when the backup is taken: the restore
    // carries the call and owes a gap at its cursor, and the gap waits behind the call, for
    // every protocol, until `tasks` takes it.
    let p = Pair::with(
        Named {
            failing_missed: Mutex::new(u32::MAX),
            ..named("tasks")
        },
        named("chat"),
    );
    let mut app = p.join_with(&[Permission::ListsRead]).await;
    read(&mut app, 1).await;
    let now = p.w.clock.now_ms();
    let seq = p.w.switch.push_missed(1, now, now);
    read(&mut app, 1).await;
    assert_eq!(app.owed_protocol_calls().await.unwrap(), 1);
    let backup = app.backup_layered().await.unwrap();
    drop(app);
    p.tasks.gaps.lock().unwrap().clear();
    p.chat.gaps.lock().unwrap().clear();
    let env =
        p.w.env_on(Arc::new(MemoryStore::new()) as Arc<dyn StateStore>);
    let mut restored = App::restore(env, p.set(), World::config(), &backup)
        .await
        .unwrap();
    restored.end_reconcile(UserConfirmed::new()).await.ok();
    read(&mut restored, 3).await;
    assert!(p.tasks.missed.lock().unwrap().is_empty());
    assert!(p.tasks.gaps.lock().unwrap().is_empty(), "the gap waits");
    assert!(p.chat.gaps.lock().unwrap().is_empty());
    *p.tasks.failing_missed.lock().unwrap() = 0;
    read(&mut restored, 1).await;
    assert_eq!(*p.tasks.missed.lock().unwrap(), [seq]);
    assert_eq!(p.tasks.gaps.lock().unwrap().len(), 1);
    assert_eq!(p.chat.gaps.lock().unwrap().len(), 1);
}
