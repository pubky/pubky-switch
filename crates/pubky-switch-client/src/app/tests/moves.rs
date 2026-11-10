//! Moves, provider loss, revocation and erasure against scripted switches: the old service,
//! and the next one, reached by origin through one transport.

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use pubky_switch_core::chain::ItemType;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::{AllowKind, OpKind};
use pubky_switch_core::records::{
    AppCertBody, CLOCK_TOLERANCE_MS, Freeze, FreezeBody, IDENTITY_PATH, RemovedApp,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;

use super::fake::{Fault, Item};
use super::*;
use crate::app::{
    AppError, AppEvent, ClaimOp, Evidence, LossActions, ObligationDeadline, ProviderLoss,
    ProviderStatus, PushRelay, UserConfirmed,
};
use crate::error::ClientError;
use crate::error::TransportError;
use crate::store::{Fault as StoreFault, FaultStore};
use crate::transport::{MockTransport, Request, Response};

/// The next service's origin.
pub(crate) const NEXT: &str = "https://next.example";

pub(crate) fn has(events: &[AppEvent], pred: impl Fn(&AppEvent) -> bool) -> bool {
    events.iter().any(pred)
}

fn received(events: &[AppEvent], seq: u64) -> bool {
    has(
        events,
        |e| matches!(e, AppEvent::MessageReceived { seq: s, .. } if *s == seq),
    )
}

/// Switches by origin.
type Routes = Vec<(String, Arc<FakeSwitch>)>;

/// Scripted switches by origin, behind one transport.
#[derive(Clone, Default)]
pub(crate) struct Router {
    switches: Arc<Mutex<Routes>>,
    /// Feed reads left before every further one fails to connect, when set.
    feeds_left: Arc<Mutex<Option<u64>>>,
}

impl Router {
    pub(crate) fn of(w: &World) -> Self {
        let router = Self::default();
        router.add(ORIGIN, &w.switch);
        router
    }

    /// Route `origin` to `switch`, in place of any switch routed there.
    pub(crate) fn add(&self, origin: &str, switch: &Arc<FakeSwitch>) {
        let mut switches = self.switches.lock().unwrap();
        switches.retain(|(o, _)| o != origin);
        switches.push((origin.to_owned(), Arc::clone(switch)));
    }

    /// Route nothing to `origin` any more: its service is unreachable.
    pub(crate) fn remove(&self, origin: &str) {
        self.switches.lock().unwrap().retain(|(o, _)| o != origin);
    }

    /// Fail every feed read after the next `reads`, so a read that never ends fails.
    pub(crate) fn limit_feeds(&self, reads: u64) {
        *self.feeds_left.lock().unwrap() = Some(reads);
    }

    fn handle(&self, request: &Request) -> Result<Response, TransportError> {
        if request.path_and_query.contains("/feed")
            && let Some(left) = self.feeds_left.lock().unwrap().as_mut()
        {
            if *left == 0 {
                return Err(TransportError::Connect("too many feed reads".into()));
            }
            *left -= 1;
        }
        let switch = self
            .switches
            .lock()
            .unwrap()
            .iter()
            .find(|(origin, _)| *origin == request.origin)
            .map(|(_, switch)| Arc::clone(switch));
        match switch {
            Some(switch) => switch.handle(request),
            None => Err(TransportError::Connect("no such origin".into())),
        }
    }

    pub(crate) fn env(&self, w: &World, store: Arc<dyn StateStore>) -> AppEnv {
        let router = self.clone();
        AppEnv {
            store: StoreHandle::inline(store),
            transport: Arc::new(MockTransport::with_handler(move |request| {
                router.handle(request)
            })),
            clock: Arc::clone(&w.clock) as Arc<dyn Clock>,
            homeserver: Arc::clone(&w.homeserver) as Arc<dyn HomeserverReader>,
        }
    }
}

/// The sample protocol, also recording provider losses and naming bob for a conversation
/// entry after one.
#[derive(Default)]
pub(crate) struct LossProtocol {
    pub(crate) sample: SampleProtocol,
    pub(crate) losses: Mutex<Vec<ProviderLoss>>,
    pub(crate) counterparties: Vec<[u8; 32]>,
}

impl Protocol for LossProtocol {
    fn has_keys(&self, scope: &str) -> bool {
        self.sample.has_keys(scope)
    }

    fn sent_between_own_apps(&self, kind: &str) -> bool {
        self.sample.sent_between_own_apps(kind)
    }

    fn check_scopes(
        &self,
        message: &Message,
        sender: &AppCert,
        own: &AppCert,
    ) -> Result<(), String> {
        self.sample.check_scopes(message, sender, own)
    }

    fn accepts(&self, cert: &AppCert) -> Vec<String> {
        self.sample.accepts(cert)
    }

    fn check_body(&self, message: &ReceivedMessage) -> Result<(), String> {
        self.sample.check_body(message)
    }

    fn receive(&self, message: &ReceivedMessage) -> Outcome {
        self.sample.receive(message)
    }

    fn resend_needed(&self, needed: &ResendNeeded) -> Vec<LocalWrite> {
        self.sample.resend_needed(needed)
    }

    fn missed(&self, missed: &MissedEntries) -> Vec<LocalWrite> {
        self.sample.missed(missed)
    }

    fn provider_lost(&self, loss: &ProviderLoss) -> LossActions {
        self.losses.lock().unwrap().push(*loss);
        LossActions {
            conversations: self.counterparties.clone(),
            local: vec![LocalWrite::Put {
                key: format!("lost/{}", loss.lost_generation).into_bytes(),
                value: b"1".to_vec(),
            }],
        }
    }
}

/// The signer approves the wallet's keys for `scope-a` with `permissions`.
pub(crate) fn approve_with(w: &World, permissions: &[Permission]) -> JoinRequest {
    let keys = app_keys("wallet");
    let now = w.clock.now_ms();
    let cert = AppCert::issue(
        &w.alice,
        AppCertBody::new(
            w.alice.public(),
            keys.signing_public(),
            keys.bundle_public(),
            vec!["scope-a".into()],
            permissions,
            now,
            now + DEFAULT_CERT_LIFETIME_MS,
        ),
    )
    .unwrap();
    let auth = AuthRequest {
        client_id: "sample.example".into(),
        client_key: [7; 32],
        caps: format!("{}:rw", app_record_path(&keys.app_id_bytes())),
        secret: [8; 32],
    };
    let request = AppRequest::sign(
        &keys,
        AppRequestBody::new(&keys, vec!["scope-a".into()], &auth),
    )
    .unwrap();
    let doc = w.next_doc(|body| {
        body.apps.push(ListedApp {
            app_id: cert.app_id(),
            cert: cert.hash(),
        })
    });
    let approval =
        Approval::issue(&w.alice, &request, cert, doc, &|s| s.starts_with("scope-a")).unwrap();
    JoinRequest {
        identity: w.alice.public(),
        keys,
        request,
        approval: approval.to_json().unwrap(),
    }
}

pub(crate) async fn join_on(
    w: &World,
    router: &Router,
    store: Arc<dyn StateStore>,
    protocol: Arc<dyn Protocol>,
    permissions: &[Permission],
) -> App {
    App::join(
        router.env(w, store),
        protocol,
        World::config(),
        approve_with(w, permissions),
    )
    .await
    .unwrap()
}

pub(crate) async fn join(w: &World, router: &Router) -> App {
    join_on(
        w,
        router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[],
    )
    .await
}

pub(crate) fn next_key() -> SigningKey {
    SigningKey::from_bytes(&seed("service/alice/next"))
}

/// The signer's freeze naming the next service at `NEXT`.
pub(crate) fn freeze_for(w: &World, next: &SigningKey, next_generation: u64) -> Freeze {
    Freeze::sign(
        &w.alice,
        FreezeBody {
            identity: w.alice.public(),
            inbox: Inbox::new(NEXT, next.verifying_key().to_bytes()),
            next_generation,
            issued_at: w.clock.now_ms(),
            nonce: [next_generation as u8; 16],
        },
    )
    .unwrap()
}

/// The signer delivers alice's next version naming `inbox` at `generation` to `to`, and
/// publishes it.
pub(crate) fn publish_at(
    w: &World,
    to: &FakeSwitch,
    inbox: Inbox,
    generation: u64,
    recovery_from: Option<u64>,
) -> IdentityDoc {
    let mut body = w.body.lock().unwrap();
    body.version += 1;
    body.generation = generation;
    body.inbox = inbox;
    body.recovery_from = recovery_from;
    let doc = IdentityDoc::sign(&w.alice, body.clone()).unwrap();
    to.deliver_identity(&doc);
    w.homeserver.publish(&doc);
    doc
}

/// The transition proof of the first chain item the app wrote at `switch`.
fn first_proof(switch: &FakeSwitch) -> SignedDoc {
    switch
        .lock()
        .items
        .iter()
        .find_map(|item| match item {
            Item::Chain {
                item_type: ItemType::Op,
                proof: Some(proof),
                ..
            } => Some(proof.clone()),
            _ => None,
        })
        .unwrap()
}

fn note_at(w: &World, switch: &FakeSwitch, to: [u8; 16], text: &str) -> u64 {
    switch
        .send(
            &w.bob,
            &w.bob_keys,
            &w.bob_cert,
            "sample.note",
            json!({ "text": text }),
            &[to],
        )
        .0
}

fn conversations_at(switch: &FakeSwitch) -> usize {
    switch
        .applied()
        .iter()
        .filter(|op| {
            matches!(
                op.body().kind,
                OpKind::AllowPut {
                    kind: AllowKind::Conversation,
                    ..
                }
            )
        })
        .count()
}

// -------------------------------------------------------------------------------------
// Cooperative move (Switch spec 12.5)

#[tokio::test]
async fn test_move_followed_from_a_frozen_feed() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let seq = w.note(me, "before").0;
    assert!(received(&app.receive(None).await.unwrap().events, seq));
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.switch))])
        .await
        .unwrap();
    // The signer freezes the old service; the next one imports the account, staged.
    let n_key = next_key();
    let freeze = freeze_for(&w, &n_key, 2);
    w.switch.freeze(&freeze);
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Moved)));
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::EvidenceUploaded {
            heads: 1,
            proofs: 1
        }
    )));
    // The staged upload carried the newest head and the old service's proof, with the
    // app's certificate.
    let uploads = next.uploads();
    assert_eq!(uploads.len(), 1);
    assert!(uploads[0].1);
    let head = &uploads[0].0["heads"][0];
    assert_eq!(head["seq"].as_u64(), Some(w.switch.tip_seq()));
    assert_eq!(app.cursor().generation, 1);
    // Waiting changes nothing until the move is published.
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert_eq!(next.uploads().len(), 1);
    // The signer publishes generation 2 naming the next service.
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(!report.stopped, "{:?}", report.events);
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderFollowed { generation: 2 }
    )));
    assert_eq!(app.cursor().generation, 2);
    assert_eq!(app.own_identity().generation(), 2);
    // The record and the current key went to the next service at generation 2.
    let reregistered = next.applied();
    assert!(
        reregistered.iter().any(|op| op.body().generation == 2
            && matches!(op.body().kind, OpKind::ReceiveKeyPut { .. }))
    );
    // The old service's proofs went again once the move was published, without the cert.
    let uploads = next.uploads();
    assert_eq!(uploads.len(), 2);
    assert!(!uploads[1].1);
    // A note at the next service is received; the chain view carried across.
    let seq = note_at(&w, &next, me, "after");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(conversations_at(&next), 1);
    assert!(app.alarm().is_none());
    // Without list permissions the app doesn't compare the lists.
    assert!(!has(&report.events, |e| matches!(
        e,
        AppEvent::ListsDiffer { .. }
    )));
}

#[tokio::test]
async fn test_move_followed_from_a_410_answer() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    // A note waits in the feed; the frozen service's pages don't carry the freeze here, so
    // the app learns of it from its effect's `410 moved`.
    w.note(me, "before");
    let n_key = next_key();
    let freeze = freeze_for(&w, &n_key, 2);
    w.switch.freeze(&freeze);
    w.switch.lock().freeze_in_feed = false;
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Moved)));
    assert_eq!(next.uploads().len(), 1);
    // Nothing was applied at the frozen service.
    assert_eq!(w.effects(), 0);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderFollowed { generation: 2 }
    )));
    // The note is processed at the next service, which imported it.
    assert_eq!(conversations_at(&next), 1);
}

#[tokio::test]
async fn test_move_found_through_the_public_read() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let n_key = next_key();
    let freeze = freeze_for(&w, &n_key, 2);
    w.switch.freeze(&freeze);
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    assert_eq!(
        app.check_for_move().await.unwrap(),
        ProviderStatus::AwaitingMove { next_generation: 2 }
    );
    assert_eq!(next.uploads().len(), 1);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Followed { generation: 2 }
    );
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Current
    );
}

#[tokio::test]
async fn test_move_refuses_a_forged_freeze() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let next = w.switch.import_into(next_key());
    router.add(NEXT, &next);
    // A freeze bob's key signed, for bob's identity: not alice's.
    let forged = Freeze::sign(
        &w.bob,
        FreezeBody {
            identity: w.bob.public(),
            inbox: Inbox::new(NEXT, next_key().verifying_key().to_bytes()),
            next_generation: 2,
            issued_at: START,
            nonce: [9; 16],
        },
    )
    .unwrap();
    w.note(me, "hello");
    w.switch.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Moved,
        current: json!({ "freeze": forged.signed() }),
    });
    let error = app.receive(None).await.unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // Nothing was followed: no upload, and the app reads on at its service.
    assert!(next.uploads().is_empty());
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Current
    );
    app.receive(None).await.unwrap();
    assert_eq!(w.effects(), 1);
    // A freeze that skips a generation is refused too, though alice signed it.
    let skipping = freeze_for(&w, &next_key(), 3);
    w.switch.freeze(&skipping);
    let error = app.check_for_move().await.unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    assert!(next.uploads().is_empty());
}

#[tokio::test]
async fn test_move_cancelled_by_an_unfreeze_stays() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let n_key = next_key();
    let freeze = freeze_for(&w, &n_key, 2);
    w.switch.freeze(&freeze);
    let next = w.switch.import_into(n_key);
    router.add(NEXT, &next);
    assert!(app.receive(None).await.unwrap().stopped);
    // The signer aborts: the old service resumes.
    w.switch.unfreeze(&freeze);
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::MoveCancelled
    )));
    let seq = w.note(me, "still here").0;
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(app.cursor().generation, 1);
}

#[tokio::test]
async fn test_move_import_conflict_is_reported_and_the_move_goes_on() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2));
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    next.fail_next(Fault::Error {
        path: "recovery/upload".into(),
        code: ErrorCode::Conflict,
        current: json!({ "conflicts": ["a head the import doesn't extend"] }),
    });
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::EvidenceRefused { code } if code == "conflict"
    )));
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Followed { generation: 2 }
    );
}

#[tokio::test]
async fn test_move_compares_the_admission_lists() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[
            Permission::ListsRead,
            Permission::ListsManage,
            Permission::ConversationAdd,
        ],
    )
    .await;
    let me = app.app_id();
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    let erin = IdentityKey::from_secret(seed("erin/identity")).public();
    w.switch.signer_op(OpKind::AllowPut {
        pubky: carol,
        kind: AllowKind::Contact,
    });
    app.receive(None).await.unwrap();
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2));
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    // A faulty export: carol is gone, erin was never added, and an invite code in this
    // app's name that it never registered.
    let planted = [1u8; 32];
    next.lock().shared.plant_invite(planted, 1, me);
    next.lock().allow = Some(json!({
        "contacts": [pubky_switch_core::enc::pubky_id(&erin)],
        "conversations": [], "deny": [], "flagged": [],
        "invite_codes": [{ "code_hash": pubky_switch_core::enc::b64(&planted),
                           "expires_at": "2026-02-01T00:00:00.000Z", "max_uses": 1, "uses": 0,
                           "written_by": pubky_switch_core::enc::zbase32_encode(&me) }],
    }));
    app.receive(None).await.unwrap();
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::ListsDiffer {
                added: 1,
                unverified_contacts: 1,
                withdrawn_codes: 1
            }
        )),
        "{:?}",
        report.events
    );
    let applied = next.applied();
    assert!(applied.iter().any(|op| matches!(
        op.body().kind,
        OpKind::AllowPut { pubky, kind: AllowKind::Contact } if pubky == carol
    )));
    assert!(applied.iter().any(|op| matches!(
        op.body().kind,
        OpKind::InviteCodeDelete { code_hash } if code_hash == planted
    )));
    // Erin is shown, not removed.
    assert!(
        !applied
            .iter()
            .any(|op| matches!(op.body().kind, OpKind::AllowDelete { .. }))
    );
}

#[tokio::test]
async fn test_move_registers_again_a_key_the_next_service_rolled_back() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let first = w.switch.app(&me).receive_key.clone();
    w.note(me, "one");
    w.clock.advance_ms(25 * 3_600_000);
    app.receive(None).await.unwrap();
    assert_eq!(w.switch.app(&me).receive_n, Some(1));
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2));
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    // The export shows the app's older key as current.
    {
        let mut inner = next.lock();
        let held = inner.apps.get_mut(&me).unwrap();
        held.receive_key = first;
        held.receive_n = Some(0);
    }
    app.receive(None).await.unwrap();
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::ReceiveKeyRolledBack {
                shown: 0,
                current: 1
            }
        )),
        "{:?}",
        report.events
    );
    assert_eq!(next.app(&me).receive_n, Some(1));
}

#[tokio::test]
async fn test_move_next_service_showing_a_foreign_key_is_a_compromise() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2));
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    // A key signed with the app's signing key that no device of the app made.
    let thief = pubky_switch_core::keys::ReceiveKey::generate(1).unwrap();
    let record = pubky_switch_core::records::ReceiveKeyRecord::sign(
        &app_keys("wallet"),
        app.cert(),
        pubky_switch_core::records::ReceiveKeyBody::new(app.cert(), &thief),
    )
    .unwrap();
    {
        let mut inner = next.lock();
        let held = inner.apps.get_mut(&me).unwrap();
        held.receive_key = Some(record.signed().clone());
        held.receive_n = Some(1);
    }
    app.receive(None).await.unwrap();
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Alarm(crate::app::Alarm::Compromise { n: 1, .. })
        ),
        "{error:?}"
    );
    // It left at once, at the service it follows.
    assert!(next.app(&me).departed);
}

#[tokio::test]
async fn test_key_change_in_place_is_followed_without_a_freeze() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    // The same origin under a new key at generation 2: nothing exported, the chain goes on.
    let pending = SigningKey::from_bytes(&seed("service/alice/pending"));
    let changed = w.switch.import_into(pending.clone());
    router.add(ORIGIN, &changed);
    publish_at(
        &w,
        &changed,
        Inbox::new(ORIGIN, pending.verifying_key().to_bytes()),
        2,
        None,
    );
    let seq = note_at(&w, &changed, me, "after the change");
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderFollowed { generation: 2 }
    )));
    assert!(received(&report.events, seq), "{:?}", report.events);
    assert_eq!(app.cursor().generation, 2);
}

/// Join and read at the old service, freeze it and import the account at the next one,
/// publish the move, and queue a note there: everything the follow then reads.
async fn moved_world(store: Arc<dyn StateStore>) -> (World, Router, Arc<FakeSwitch>, u64) {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(&w, &router, store, w.protocol.clone(), &[]).await;
    let me = app.app_id();
    w.note(me, "before");
    app.receive(None).await.unwrap();
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.switch))])
        .await
        .unwrap();
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2));
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let seq = note_at(&w, &next, me, "after");
    (w, router, next, seq)
}

/// The follow: reads until the note at the next service is processed.
async fn follow_move(
    w: &World,
    router: &Router,
    store: Arc<dyn StateStore>,
) -> Result<(), AppError> {
    let mut app = App::load(
        router.env(w, store),
        w.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await?;
    app.receive(None).await?;
    app.receive(None).await?;
    Ok(())
}

#[tokio::test]
async fn test_move_crash_at_each_commit_point_resumes() {
    let counting_inner = Arc::new(MemoryStore::new());
    let (w, router, _, _) = moved_world(Arc::clone(&counting_inner) as Arc<dyn StateStore>).await;
    let counting = Arc::new(FaultStore::new(
        counting_inner as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    follow_move(&w, &router, Arc::clone(&counting) as Arc<dyn StateStore>)
        .await
        .unwrap();
    let commits = counting.commits();
    assert!(commits > 5, "the follow commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let inner = Arc::new(MemoryStore::new());
            let (w, router, next, seq) =
                moved_world(Arc::clone(&inner) as Arc<dyn StateStore>).await;
            let fault = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let first = follow_move(&w, &router, Arc::clone(&fault) as Arc<dyn StateStore>).await;
            assert!(fault.stopped(), "commit {n} of {commits} is reached");
            assert!(first.is_err());
            follow_move(&w, &router, Arc::clone(&inner) as Arc<dyn StateStore>)
                .await
                .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            let app = App::load(
                router.env(&w, Arc::clone(&inner) as Arc<dyn StateStore>),
                w.protocol.clone(),
                World::config(),
                app_keys("wallet").app_id_bytes(),
            )
            .await
            .unwrap();
            assert_eq!(app.cursor().generation, 2, "commit {n} ({stop_after})");
            assert!(app.cursor().seq >= seq, "commit {n} ({stop_after})");
            // The note at the next service was applied once.
            assert_eq!(conversations_at(&next), 1, "commit {n} ({stop_after})");
            // Nothing was applied at the frozen service after the freeze.
            assert_eq!(w.effects(), 1, "commit {n} ({stop_after})");
            assert!(app.alarm().is_none());
        }
    }
}

// -------------------------------------------------------------------------------------
// Provider loss (Switch spec 12.6)

struct Lost {
    w: World,
    router: Router,
    protocol: Arc<LossProtocol>,
    next: Arc<FakeSwitch>,
    carol: [u8; 32],
    dave: [u8; 32],
    note_at_ms: u64,
}

/// An app with the list permissions, a contact and a deny entry in its copy, a note
/// processed, and kept evidence; then the signer declares generation 1 lost at a new
/// service, and the old one is gone.
async fn lost_world(store: Arc<dyn StateStore>) -> Lost {
    let w = World::new();
    let router = Router::of(&w);
    let protocol = Arc::new(LossProtocol {
        counterparties: vec![w.bob.public()],
        ..LossProtocol::default()
    });
    let mut app = join_on(
        &w,
        &router,
        store,
        Arc::clone(&protocol) as Arc<dyn Protocol>,
        &[
            Permission::ListsRead,
            Permission::ListsManage,
            Permission::ConversationAdd,
        ],
    )
    .await;
    let me = app.app_id();
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    let dave = IdentityKey::from_secret(seed("dave/identity")).public();
    w.switch.signer_op(OpKind::AllowPut {
        pubky: carol,
        kind: AllowKind::Contact,
    });
    w.switch.signer_op(OpKind::DenyPut { pubky: dave });
    w.clock.advance_ms(1000);
    let note_at_ms = w.clock.now_ms();
    w.note(me, "before the loss");
    app.receive(None).await.unwrap();
    app.keep_evidence(vec![Evidence::Proof(first_proof(&w.switch))])
        .await
        .unwrap();
    w.clock.advance_ms(60_000);
    let n_key = next_key();
    let next = FakeSwitch::recovering(
        IdentityKey::from_secret(seed("alice/identity")),
        n_key.clone(),
        Arc::clone(&w.clock),
        2,
        1,
    );
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        Some(1),
    );
    // The old service is unreachable.
    w.switch.lock().erased = true;
    Lost {
        w,
        router,
        protocol,
        next,
        carol,
        dave,
        note_at_ms,
    }
}

/// The follow: the own identity.json from the Homeserver, then a read. Returns the app and
/// the read's events.
async fn follow_loss(
    lost: &Lost,
    store: Arc<dyn StateStore>,
) -> Result<(App, Vec<AppEvent>), AppError> {
    let mut app = App::load(
        lost.router.env(&lost.w, store),
        Arc::clone(&lost.protocol) as Arc<dyn Protocol>,
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await?;
    app.refresh_identity().await?;
    let report = app.receive(None).await?;
    Ok((app, report.events))
}

#[tokio::test]
async fn test_loss_recovers_at_the_new_generation() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    let (mut app, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    let me = app.app_id();
    assert!(has(&events, |e| matches!(
        e,
        AppEvent::ProviderLost {
            lost_generation: 1,
            generation: 2
        }
    )));
    assert!(has(&events, |e| matches!(
        e,
        AppEvent::ProviderRecovered { generation: 2 }
    )));
    // Registered at the new service with an `n` above every one registered before.
    assert_eq!(lost.next.app(&me).receive_n, Some(1));
    assert!(lost.next.app(&me).record.is_some());
    // Evidence first, with the lost generation's identity.json, the old head and proofs;
    // then the lists from the app's copy.
    let uploads = lost.next.uploads();
    assert_eq!(uploads.len(), 2, "{uploads:?}");
    let evidence = &uploads[0].0;
    assert_eq!(evidence["heads"].as_array().unwrap().len(), 1);
    assert_eq!(evidence["proofs"].as_array().unwrap().len(), 1);
    let lost_doc = SignedDoc::from_strict_value(&evidence["lost_identity"]).unwrap();
    assert_eq!(
        IdentityDoc::verify(&lost_doc, &lost.w.alice.public())
            .unwrap()
            .generation(),
        1
    );
    let lists = &uploads[1].0["lists"];
    assert_eq!(
        lists["contacts"],
        json!([pubky_switch_core::enc::pubky_id(&lost.carol)])
    );
    assert_eq!(
        lists["deny"],
        json!([pubky_switch_core::enc::pubky_id(&lost.dave)])
    );
    // The protocol was asked for re-sends once, from the cursor's time at the old service.
    let losses = lost.protocol.losses.lock().unwrap().clone();
    assert_eq!(losses.len(), 1);
    assert_eq!(losses[0].lost_generation, 1);
    assert_eq!(losses[0].accepted_from_ms, lost.note_at_ms);
    assert!(losses[0].uncertain_until_ms > losses[0].declared_at_ms);
    assert_eq!(
        app.protocol_get(b"lost/1").await.unwrap(),
        Some(b"1".to_vec())
    );
    // Bob's conversation entry was added back.
    assert_eq!(conversations_at(&lost.next), 1);
    // Reconcile mode until the protocol's reconciliation ends it.
    assert!(app.reconcile_mode());
    assert!(app.may_attempt(false).is_err());
    let info = app.recovery_info().await.unwrap().unwrap();
    assert!(info.steps_done);
    assert_eq!(info.loss.generation, 2);
    assert_eq!(app.cursor().generation, 2);
    // The new service's feed is followed from its start; a note there is received.
    let seq = note_at(&lost.w, &lost.next, me, "after the loss");
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
    app.end_reconcile(UserConfirmed::new()).await.unwrap();
    assert!(!app.reconcile_mode());
    // Nothing is asked again.
    app.receive(None).await.unwrap();
    assert_eq!(lost.protocol.losses.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_loss_refused_upload_is_reported_and_recovery_goes_on() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    lost.next.fail_next(Fault::Error {
        path: "recovery/upload".into(),
        code: ErrorCode::Conflict,
        current: json!({}),
    });
    let (app, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(has(&events, |e| matches!(
        e,
        AppEvent::EvidenceRefused { code } if code == "conflict"
    )));
    let info = app.recovery_info().await.unwrap().unwrap();
    assert!(info.steps_done);
    // The refused evidence isn't sent again; the lists went.
    assert_eq!(lost.next.uploads().len(), 1);
    assert_eq!(lost.protocol.losses.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_loss_registration_naming_another_key_stops_the_recovery() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    lost.next.fail_next(Fault::Error {
        path: "ops".into(),
        code: ErrorCode::Conflict,
        current: json!({ "receive_key": null }),
    });
    let error = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidData(_)), "{error:?}");
    // Nothing past the registration ran; the next read resumes it.
    assert!(lost.next.uploads().is_empty());
    assert!(lost.protocol.losses.lock().unwrap().is_empty());
    let (app, _) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(app.recovery_info().await.unwrap().unwrap().steps_done);
}

#[tokio::test]
async fn test_loss_crash_at_each_commit_point_resumes() {
    let counting_inner = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&counting_inner) as Arc<dyn StateStore>).await;
    let counting = Arc::new(FaultStore::new(
        counting_inner as Arc<dyn StateStore>,
        StoreFault::None,
    ));
    follow_loss(&lost, Arc::clone(&counting) as Arc<dyn StateStore>)
        .await
        .unwrap();
    let commits = counting.commits();
    assert!(commits > 5, "the recovery commits {commits} times");
    for stop_after in [false, true] {
        for n in 1..=commits {
            let inner = Arc::new(MemoryStore::new());
            let lost = lost_world(Arc::clone(&inner) as Arc<dyn StateStore>).await;
            let fault = Arc::new(FaultStore::new(
                Arc::clone(&inner) as Arc<dyn StateStore>,
                if stop_after {
                    StoreFault::StopAfter(n)
                } else {
                    StoreFault::StopBefore(n)
                },
            ));
            let first = follow_loss(&lost, Arc::clone(&fault) as Arc<dyn StateStore>).await;
            assert!(fault.stopped(), "commit {n} of {commits} is reached");
            assert!(first.is_err());
            let (app, _) = follow_loss(&lost, Arc::clone(&inner) as Arc<dyn StateStore>)
                .await
                .unwrap_or_else(|e| panic!("restart after commit {n} ({stop_after}): {e}"));
            let me = app.app_id();
            let info = app.recovery_info().await.unwrap().unwrap();
            assert!(info.steps_done, "commit {n} ({stop_after})");
            assert!(app.reconcile_mode());
            // One registration at the new service; the re-sends' writes committed, the
            // protocol asked again only when the commit that carries them didn't happen.
            assert_eq!(lost.next.app(&me).receive_n, Some(1), "commit {n}");
            assert_eq!(
                app.protocol_get(b"lost/1").await.unwrap(),
                Some(b"1".to_vec()),
                "commit {n} ({stop_after})"
            );
            assert!(lost.protocol.losses.lock().unwrap().len() <= 2);
            assert!(conversations_at(&lost.next) >= 1);
            assert!(app.alarm().is_none(), "commit {n} ({stop_after})");
        }
    }
}

// -------------------------------------------------------------------------------------
// Revocation and erasure (Switch spec 12.2, 12.7)

#[derive(Default)]
pub(crate) struct NoRelay;

impl PushRelay for NoRelay {
    fn register(
        &self,
        _relay_url: String,
        device_token: String,
        _push_key: [u8; 32],
    ) -> crate::transport::BoxFuture<'_, Result<String, TransportError>> {
        Box::pin(async move { Ok(format!("handle-{}", device_token.len())) })
    }
}

#[tokio::test]
async fn test_revoked_app_stops_and_drops_its_push_setting() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    app.register_push(&NoRelay, "https://push.example/v1/hook", "token")
        .await
        .unwrap();
    // The signer revokes the app at the service: every call is `403 not_current`. Until it
    // publishes the revocation, the newest identity.json still lists the app, which reports
    // the answer and isn't gone (Switch spec 12.2).
    w.switch.revoke(me);
    let error = app.receive(None).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotCurrent));
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Current
    );
    // The signer publishes the app as removed (Switch spec 12.2 step 3).
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from: START,
        });
    });
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Removed)));
    assert!(has(&report.events, |e| matches!(e, AppEvent::PushRemoved)));
    assert!(app.push_registration().await.unwrap().is_none());
    // It stays stopped, also once loaded again, and asks the service nothing.
    let mut app = w_load(&w, &router).await;
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert_eq!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
}

async fn w_load(w: &World, router: &Router) -> App {
    App::load(
        router.env(w, Arc::clone(&w.store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn test_removed_in_identity_json_stops_for_good() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from: START,
        });
    });
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::Removed)));
    assert_eq!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
}

#[tokio::test]
async fn test_erased_account_is_gone_once_the_identity_is_unpublished() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    w.switch.lock().erased = true;
    // While the identity still publishes its identity.json, the unsigned 404 explains
    // nothing: the error stands and the app isn't stopped.
    let error = app.receive(None).await.unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Switch(ClientError::BadServiceSignature { status: 404 })
        ),
        "{error:?}"
    );
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Current
    );
    // The signer erased the account and deleted identity.json from the Homeserver.
    w.homeserver
        .files
        .lock()
        .unwrap()
        .remove(&(w.alice.public(), IDENTITY_PATH.to_owned()));
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert!(has(&report.events, |e| matches!(e, AppEvent::AccountGone)));
    assert_eq!(app.follow_provider().await.unwrap(), ProviderStatus::Gone);
}

#[test]
fn test_residual_window_is_a_minute_and_the_tolerance() {
    assert_eq!(crate::app::RESIDUAL_WINDOW_MS, 60_000 + CLOCK_TOLERANCE_MS);
}

#[tokio::test]
async fn test_evidence_takes_only_record_and_claim_operations() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let usage = |error: AppError| matches!(error, AppError::Refused(crate::app::Refusal::Usage(_)));
    // The join's app.put is no evidence.
    let op = w.switch.applied()[0].signed().clone();
    let cert = app.cert().signed().clone();
    let error = app
        .keep_evidence(vec![Evidence::Op {
            op,
            cert,
            proof: None,
        }])
        .await
        .unwrap_err();
    assert!(usage(error));
    // Nor is a proof that doesn't read.
    let error = app
        .keep_evidence(vec![Evidence::Proof(SignedDoc::from_parts(
            b"{}", &[0; 64],
        ))])
        .await
        .unwrap_err();
    assert!(usage(error));
    // A proof is kept, and forgotten; its Debug shows nothing of it.
    let proof = Evidence::Proof(first_proof(&w.switch));
    assert_eq!(format!("{proof:?}"), "Evidence::Proof");
    app.keep_evidence(vec![proof.clone()]).await.unwrap();
    app.forget_evidence(&[proof]).await.unwrap();
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2));
    let next = w.switch.import_into(n_key);
    router.add(NEXT, &next);
    app.receive(None).await.unwrap();
    assert_eq!(next.uploads()[0].0["proofs"], json!([]));
}

#[tokio::test]
async fn test_not_current_while_listed_with_another_certificate_is_no_removal() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    // The newest identity.json lists the app with a renewed certificate it hasn't taken.
    let mut body = w.body.lock().unwrap().clone();
    body.version += 1;
    for listed in body.apps.iter_mut().filter(|a| a.app_id == me) {
        listed.cert = [9; 32];
    }
    w.homeserver
        .publish(&IdentityDoc::sign(&w.alice, body).unwrap());
    w.switch.fail_next(Fault::Error {
        path: "feed".into(),
        code: ErrorCode::NotCurrent,
        current: json!({}),
    });
    let error = app.receive(None).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotCurrent));
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Current
    );
}

// -------------------------------------------------------------------------------------
// Earlier generations' evidence, and writes before the upload

const CLAIM: [u8; 32] = [5; 32];
const ATTEMPT: [u8; 16] = [6; 16];

/// The same origin under a new key at generation 2, published (a key change in place).
fn change_key(w: &World, router: &Router) -> Arc<FakeSwitch> {
    let pending = SigningKey::from_bytes(&seed("service/alice/pending"));
    let changed = w.switch.import_into(pending.clone());
    router.add(ORIGIN, &changed);
    publish_at(
        w,
        &changed,
        Inbox::new(ORIGIN, pending.verifying_key().to_bytes()),
        2,
        None,
    );
    changed
}

#[tokio::test]
async fn test_claim_read_after_a_key_change_checks_earlier_proofs_with_their_key() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    app.write_claim(
        ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
        vec![],
        ObligationDeadline::NoDeadline,
    )
    .await
    .unwrap();
    change_key(&w, &router);
    app.receive(None).await.unwrap();
    assert_eq!(app.cursor().generation, 2);
    // The entry carries generation 1's proof: checked with that generation's key, no alarm.
    let read = app.read_claim(&CLAIM).await.unwrap().unwrap();
    assert_eq!(read.entries.len(), 1);
    assert!(app.alarm().is_none(), "{:?}", app.alarm());
}

#[tokio::test]
async fn test_claim_entry_of_an_earlier_generation_in_the_feed_is_kept() {
    let w = World::new();
    let router = Router::of(&w);
    let phone_store = Arc::new(MemoryStore::new());
    let mut phone = App::join(
        router.env(&w, Arc::clone(&phone_store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        World::config(),
        w.approve(&app_keys("phone"), &["scope-a"]),
    )
    .await
    .unwrap();
    phone.receive(None).await.unwrap();
    let mut wallet = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &Permission::ALL,
    )
    .await;
    wallet
        .write_claim(
            ClaimOp::attempt(CLAIM, 0, ATTEMPT, 3600, None),
            vec![],
            ObligationDeadline::NoDeadline,
        )
        .await
        .unwrap();
    change_key(&w, &router);
    // The phone learns of the change first, then reads generation 1's items at the new key.
    phone.refresh_identity().await.unwrap();
    phone.receive(None).await.unwrap();
    assert_eq!(phone.cursor().generation, 2);
    assert!(phone.alarm().is_none(), "{:?}", phone.alarm());
    let evidence = phone.claim_evidence(&CLAIM).await.unwrap();
    assert!(evidence.is_some(), "the entry's evidence is kept");
}

#[tokio::test]
async fn test_loss_writes_wait_for_the_upload() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    lost.next.fail_next(Fault::LoseAnswer {
        path: "recovery/upload".into(),
    });
    assert!(
        follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
            .await
            .is_err()
    );
    let mut app = App::load(
        lost.router
            .env(&lost.w, Arc::clone(&store) as Arc<dyn StateStore>),
        Arc::clone(&lost.protocol) as Arc<dyn Protocol>,
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap();
    let applied = lost.next.applied().len();
    let error = app
        .submit_batch(crate::app::OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppError::Refused(crate::app::Refusal::NotNow(_))),
        "{error:?}"
    );
    let error = app.end_reconcile(UserConfirmed::new()).await.unwrap_err();
    assert!(
        matches!(error, AppError::Refused(crate::app::Refusal::NotNow(_))),
        "{error:?}"
    );
    assert_eq!(lost.next.applied().len(), applied);
    // Once the upload went, the app writes.
    app.receive(None).await.unwrap();
    assert!(app.recovery_info().await.unwrap().unwrap().steps_done);
    app.submit_batch(crate::app::OpBatch::new().op(OpKind::DenyPut { pubky: [9; 32] }))
        .await
        .unwrap();
}

// -------------------------------------------------------------------------------------
// Provider changes that go wrong on the way (Switch spec 12.5 "Abort", 12.6, 13.5)

/// A third service's origin.
pub(crate) const THIRD: &str = "https://third.example";

/// A service recovering alice's account at `generation` after the loss of `from`, at
/// `THIRD`, with the signer's document naming it delivered and published.
fn third_recovering(w: &World, router: &Router, generation: u64, from: u64) -> Arc<FakeSwitch> {
    let key = SigningKey::from_bytes(&seed("service/alice/third"));
    let third = FakeSwitch::recovering(
        IdentityKey::from_secret(seed("alice/identity")),
        key.clone(),
        Arc::clone(&w.clock),
        generation,
        from,
    );
    router.add(THIRD, &third);
    publish_at(
        w,
        &third,
        Inbox::new(THIRD, key.verifying_key().to_bytes()),
        generation,
        Some(from),
    );
    third
}

fn transport(error: &AppError) -> bool {
    matches!(error, AppError::Transport(_))
}

fn allow_ops_for(ops: &[pubky_switch_core::ops::SignedOp], who: [u8; 32]) -> usize {
    ops.iter()
        .filter(|op| matches!(op.body().kind, OpKind::AllowPut { pubky, .. } if pubky == who))
        .count()
}

#[tokio::test]
async fn test_move_reads_the_old_feed_past_pages_of_entries_alone() {
    let w = World::new();
    let router = Router::of(&w);
    let config = AppConfig {
        page_size: 2,
        ..World::config()
    };
    let mut app = App::join(
        router.env(&w, Arc::clone(&w.store) as Arc<dyn StateStore>),
        w.protocol.clone(),
        config,
        approve_with(&w, &[]),
    )
    .await
    .unwrap();
    let me = app.app_id();
    // More than a page of inbox entries after the last chain item, then the freeze.
    for i in 0..5 {
        w.note(me, &format!("note {i}"));
    }
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2));
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    // A read of the old feed that never ends fails here instead of running on.
    router.limit_feeds(50);
    let report = app.receive(None).await.unwrap();
    assert!(report.stopped);
    assert_eq!(next.uploads().len(), 1, "{:?}", report.events);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderFollowed { generation: 2 }
    )));
    // Every entry is processed once, at the next service.
    assert_eq!(conversations_at(&next), 5);
    assert_eq!(w.effects(), 0);
}

#[tokio::test]
async fn test_move_stuck_at_a_gone_next_service_follows_a_newer_loss() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2));
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    assert!(app.receive(None).await.unwrap().stopped);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    // The next service is gone before the app re-registers there: the move is stuck.
    router.remove(NEXT);
    let error = app.receive(None).await.unwrap_err();
    assert!(transport(&error), "{error:?}");
    assert!(transport(&app.receive(None).await.unwrap_err()));
    // The signer declares generation 2 lost, at a third service.
    let third = third_recovering(&w, &router, 3, 2);
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::ProviderChangeSuperseded {
                generation: 2,
                newer: 3
            }
        )),
        "{:?}",
        report.events
    );
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderLost {
            lost_generation: 2,
            generation: 3
        }
    )));
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderRecovered { generation: 3 }
    )));
    assert_eq!(app.cursor().generation, 3);
    assert!(third.app(&me).receive_n.is_some());
    assert!(app.alarm().is_none());
}

#[tokio::test]
async fn test_loss_stuck_at_a_gone_service_follows_a_newer_loss() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    // The new service is gone too before the app registers there.
    lost.router.remove(NEXT);
    let error = follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
        .await
        .unwrap_err();
    assert!(transport(&error), "{error:?}");
    // The signer declares generation 2 lost, at a third service.
    let third = third_recovering(&lost.w, &lost.router, 3, 2);
    let (app, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(
        has(&events, |e| matches!(
            e,
            AppEvent::ProviderChangeSuperseded {
                generation: 2,
                newer: 3
            }
        )),
        "{events:?}"
    );
    let info = app.recovery_info().await.unwrap().unwrap();
    assert!(info.steps_done);
    assert_eq!(info.loss.lost_generation, 2);
    assert_eq!(info.loss.generation, 3);
    assert!(third.app(&app.app_id()).receive_n.is_some());
    // The re-sends are asked once, from the cursor's time at the first service.
    let losses = lost.protocol.losses.lock().unwrap().clone();
    assert_eq!(losses.len(), 1);
    assert_eq!(losses[0].accepted_from_ms, lost.note_at_ms);
}

#[tokio::test]
async fn test_move_carries_kept_batches_to_the_next_service() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    let erin = IdentityKey::from_secret(seed("erin/identity")).public();
    let dave = IdentityKey::from_secret(seed("dave/identity")).public();
    let contact = |pubky| {
        crate::app::OpBatch::new().op(OpKind::AllowPut {
            pubky,
            kind: AllowKind::Contact,
        })
    };
    // A batch the old service applied, its answer lost.
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.submit_batch(contact(carol)).await.is_err());
    // A batch queued while the account is frozen (Switch spec 12.5 step 2).
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2));
    let error = app.submit_batch(contact(erin)).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Moved));
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    assert!(app.receive(None).await.unwrap().stopped);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::KeptBatchApplied { .. }
        )),
        "{:?}",
        report.events
    );
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::KeptBatchSignedAgain { .. }
    )));
    assert!(app.admits(&carol).await.unwrap());
    // The batch the old service never applied goes to the next one at generation 2, with
    // the next write.
    app.submit_batch(contact(dave)).await.unwrap();
    let applied = next.applied();
    assert!(applied.iter().any(|op| op.body().generation == 2
        && matches!(op.body().kind, OpKind::AllowPut { pubky, .. } if pubky == erin)));
    // The one it applied isn't applied again.
    assert_eq!(allow_ops_for(&applied, carol), 0);
    assert_eq!(allow_ops_for(&w.switch.applied(), carol), 1);
    assert_eq!(allow_ops_for(&applied, erin), 1);
}

#[tokio::test]
async fn test_move_settles_an_effect_the_old_service_applied() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let (seq, message) = w.note(me, "before");
    // The effect is applied at the old service, and its answer lost.
    w.switch.fail_next(Fault::LoseAnswer { path: "ops".into() });
    assert!(app.receive(None).await.is_err());
    assert_eq!(w.effects(), 1);
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2));
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    let report = app.receive(None).await.unwrap();
    assert!(
        has(&report.events, |e| matches!(
            e,
            AppEvent::ProviderFollowed { generation: 2 }
        )),
        "{:?}",
        report.events
    );
    assert!(received(&report.events, seq));
    // Applied once, at the old service: the entry isn't processed again at the next one.
    assert_eq!(conversations_at(&next), 0);
    assert_eq!(w.effects(), 1);
    assert!(app.cursor().seq >= seq);
    assert_eq!(
        app.protocol_get(format!("notes/{}", message.msg_id).as_bytes())
            .await
            .unwrap(),
        Some(b"before".to_vec())
    );
}

/// The app at `store`, loaded through the loss's router.
async fn load_lost(lost: &Lost, store: Arc<dyn StateStore>) -> App {
    App::load(
        lost.router.env(&lost.w, store),
        Arc::clone(&lost.protocol) as Arc<dyn Protocol>,
        World::config(),
        app_keys("wallet").app_id_bytes(),
    )
    .await
    .unwrap()
}

/// A receive key record of the wallet's signing key for `key`.
fn wallet_key_record(
    app: &App,
    key: &pubky_switch_core::keys::ReceiveKey,
) -> pubky_switch_core::records::ReceiveKeyRecord {
    pubky_switch_core::records::ReceiveKeyRecord::sign(
        &app_keys("wallet"),
        app.cert(),
        pubky_switch_core::records::ReceiveKeyBody::new(app.cert(), key),
    )
    .unwrap()
}

#[tokio::test]
async fn test_loss_registration_taken_by_another_device_is_adopted() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    // The first follow can't reach the new service: the loss starts, its batch kept.
    lost.router.remove(NEXT);
    assert!(
        follow_loss(&lost, Arc::clone(&store) as Arc<dyn StateStore>)
            .await
            .is_err()
    );
    // Another device of the app registers its key first, and shares its kid.
    let mut app = load_lost(&lost, Arc::clone(&store) as Arc<dyn StateStore>).await;
    let other = pubky_switch_core::keys::ReceiveKey::generate(1).unwrap();
    let record = wallet_key_record(&app, &other);
    lost.next
        .app_op(
            &app_keys("wallet"),
            OpKind::ReceiveKeyPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    app.take_device_keys(crate::app::DeviceKeys {
        receive_keys: Vec::new(),
        known: vec![(pubky_switch_core::enc::b64(&other.kid), 1)],
        rotation_ms: 0,
    })
    .await
    .unwrap();
    drop(app);
    lost.router.add(NEXT, &lost.next);
    let (app, events) = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap();
    assert!(
        has(&events, |e| matches!(e, AppEvent::RotationLost { n: 1 })),
        "{events:?}"
    );
    // This device's own key went; its record went alone.
    assert_eq!(app.receive_key_numbers(), vec![0]);
    assert!(lost.next.app(&app.app_id()).record.is_some());
    assert!(app.recovery_info().await.unwrap().unwrap().steps_done);
    assert!(app.alarm().is_none());
}

#[tokio::test]
async fn test_loss_registration_taken_by_a_foreign_key_is_a_compromise() {
    let store = Arc::new(MemoryStore::new());
    let lost = lost_world(Arc::clone(&store) as Arc<dyn StateStore>).await;
    // A copy of the signing key registers a key of its own first at the new service.
    let app = load_lost(&lost, Arc::clone(&store) as Arc<dyn StateStore>).await;
    let me = app.app_id();
    let thief = pubky_switch_core::keys::ReceiveKey::generate(1).unwrap();
    let record = wallet_key_record(&app, &thief);
    drop(app);
    lost.next
        .app_op(
            &app_keys("wallet"),
            OpKind::ReceiveKeyPut {
                record: record.signed().clone(),
            },
        )
        .unwrap();
    let error = follow_loss(&lost, store as Arc<dyn StateStore>)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            AppError::Alarm(crate::app::Alarm::Compromise { n: 1, .. })
        ),
        "{error:?}"
    );
    // It left at once, at the new service.
    assert!(lost.next.app(&me).departed);
}

#[tokio::test]
async fn test_not_current_while_listed_with_its_own_certificate_isnt_gone() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    // The newest identity.json lists the app with the certificate it presents.
    w.switch.fail_next(Fault::Error {
        path: "feed".into(),
        code: ErrorCode::NotCurrent,
        current: json!({}),
    });
    let error = app.receive(None).await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::NotCurrent));
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Current
    );
    // The next read goes on.
    let seq = w.note(me, "after").0;
    let report = app.receive(None).await.unwrap();
    assert!(received(&report.events, seq), "{:?}", report.events);
}

#[tokio::test]
async fn test_gone_app_refuses_every_read() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    w.next_doc(|body| {
        body.apps.retain(|a| a.app_id != me);
        body.removed.push(RemovedApp {
            app_id: me,
            distrust_from: START,
        });
    });
    assert!(app.receive(None).await.unwrap().stopped);
    let gone = |error: AppError| matches!(error, AppError::Refused(crate::app::Refusal::Gone));
    let target = crate::app::RecordTarget::new(super::shared_flows::items(), b"key");
    for _ in 0..2 {
        assert!(gone(
            app.register_push(&NoRelay, "https://push.example/v1/hook", "token")
                .await
                .unwrap_err()
        ));
        assert!(gone(app.read_claim(&[1; 32]).await.unwrap_err()));
        assert!(gone(app.read_record(&target).await.unwrap_err()));
        assert!(gone(app.peek().await.unwrap_err()));
        // The read itself reports the app stopped, asking the service nothing.
        assert!(app.receive(None).await.unwrap().stopped);
        app = w_load(&w, &router).await;
    }
}

#[tokio::test]
async fn test_registration_sent_again_never_takes_the_service_cursor_back() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    w.note(me, "one");
    app.receive(None).await.unwrap();
    // A chain item the cursor passes with its move deferred, then the rotation, whose
    // registration doesn't reach the service.
    w.switch.signer_op(OpKind::DenyPut { pubky: [9; 32] });
    w.clock.advance_ms(25 * 3_600_000);
    w.switch.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 0,
    });
    assert!(app.receive(None).await.is_err());
    // A later effect moves the service's cursor further, then the registration goes again.
    let seq = w.note(me, "two").0;
    app.receive(None).await.unwrap();
    assert_eq!(w.switch.app(&me).receive_n, Some(1));
    assert!(
        w.switch.app(&me).cursor >= seq,
        "{}",
        w.switch.app(&me).cursor
    );
}

#[tokio::test]
async fn test_device_sync_doesnt_bring_back_a_deleted_key() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let shared = app.device_keys();
    w.note(me, "one");
    app.receive(None).await.unwrap();
    w.clock.advance_ms(25 * 3_600_000);
    app.receive(None).await.unwrap();
    app.receive(None).await.unwrap();
    // Key 0 went once the cursor passed key 1's registration.
    assert_eq!(app.receive_key_numbers(), vec![1]);
    // Another device still shares key 0: it doesn't come back.
    app.take_device_keys(shared).await.unwrap();
    assert_eq!(app.receive_key_numbers(), vec![1]);
}

#[tokio::test]
async fn test_move_lists_batch_is_kept_and_sent_again_unchanged() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join_on(
        &w,
        &router,
        Arc::clone(&w.store) as Arc<dyn StateStore>,
        w.protocol.clone(),
        &[Permission::ListsRead, Permission::ListsManage],
    )
    .await;
    let carol = IdentityKey::from_secret(seed("carol/identity")).public();
    w.switch.signer_op(OpKind::AllowPut {
        pubky: carol,
        kind: AllowKind::Contact,
    });
    app.receive(None).await.unwrap();
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2));
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    // The export lacks carol.
    next.lock().allow = Some(json!({
        "contacts": [], "conversations": [], "deny": [], "flagged": [], "invite_codes": [],
    }));
    app.receive(None).await.unwrap();
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    // The re-registration goes through; the batch adding carol back doesn't.
    next.fail_next(Fault::Unreachable {
        path: "ops".into(),
        after: 1,
    });
    assert!(app.receive(None).await.is_err());
    let report = app.receive(None).await.unwrap();
    assert!(has(&report.events, |e| matches!(
        e,
        AppEvent::ProviderFollowed { generation: 2 }
    )));
    // The batch went again, the bytes signed before it was first sent, and once.
    let unreached = next.lock().unreached.clone();
    let request = pubky_switch_core::ops::OpsRequest::parse(&unreached[0]).unwrap();
    let sent_id = request
        .signed()
        .map(|signed| pubky_switch_core::ops::SignedOp::peek(signed).unwrap())
        .next()
        .unwrap()
        .body()
        .batch
        .id;
    let applied = next.applied();
    assert_eq!(allow_ops_for(&applied, carol), 1);
    assert!(applied.iter().any(|op| op.body().batch.id == sent_id
        && matches!(op.body().kind, OpKind::AllowPut { pubky, .. } if pubky == carol)));
}

#[tokio::test]
async fn test_unsigned_404_with_a_newer_own_document_is_followed_not_erased() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let n_key = next_key();
    w.switch.freeze(&freeze_for(&w, &n_key, 2));
    let next = w.switch.import_into(n_key.clone());
    router.add(NEXT, &next);
    publish_at(
        &w,
        &next,
        Inbox::new(NEXT, n_key.verifying_key().to_bytes()),
        2,
        None,
    );
    // The app holds the verified document naming the next service; then the old service
    // drops the account and the Homeserver serves no identity.json.
    assert!(app.refresh_identity().await.unwrap());
    w.switch.lock().erased = true;
    w.homeserver
        .files
        .lock()
        .unwrap()
        .remove(&(w.alice.public(), IDENTITY_PATH.to_owned()));
    let over = app
        .take_over(Err(AppError::Switch(ClientError::BadServiceSignature {
            status: 404,
        })))
        .await;
    assert!(matches!(over, crate::app::provider::TakeOver::ReadAgain));
    assert_eq!(
        app.follow_provider().await.unwrap(),
        ProviderStatus::Followed { generation: 2 }
    );
}

#[tokio::test]
async fn test_chain_hashes_behind_the_cursor_stay_bounded() {
    let w = World::new();
    let router = Router::of(&w);
    let mut app = join(&w, &router).await;
    let me = app.app_id();
    let ns = crate::store::client_namespace(&me);
    let rows = |w: &World| {
        w.store
            .scan(&ns, b"chain/at/", None, u32::MAX)
            .unwrap()
            .len()
    };
    for round in 0..3u8 {
        for i in 0..100u8 {
            w.switch.signer_op(OpKind::DenyPut {
                pubky: [round.wrapping_mul(100).wrapping_add(i); 32],
            });
        }
        app.receive(None).await.unwrap();
        assert!(
            rows(&w) <= crate::app::chain::HASHES_BEHIND + 2,
            "{} rows",
            rows(&w)
        );
    }
    // The view still checks what it reads, and reloads.
    let seq = w.note(me, "after").0;
    let mut app = w_load(&w, &router).await;
    assert!(received(&app.receive(None).await.unwrap().events, seq));
    assert!(app.alarm().is_none());
}
