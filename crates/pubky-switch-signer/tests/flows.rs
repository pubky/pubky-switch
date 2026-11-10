//! The signer's enrollment and `identity.json` deliveries against the scripted switch
//! (Switch spec 4.3, 12.8; Switch wire 3.3, 3.7, 3.13, 7.4.1, 7.4.2), with crash tests over
//! every commit.
//!
//! The scripted switch judges each delivery by the core's `check_delivery`, the rule the
//! service applies; the same flows run against the service once it serves enrollment and
//! `PUT /identity`.

// The helpers outside `#[test]` functions build fixed fixtures, where a failure is a test
// failure: the workspace's no-panic lints don't apply to them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use pubky_switch_client::TransportError;
use pubky_switch_client::clock::TestClock;
use pubky_switch_client::store::{Fault, FaultStore, MemoryStore, StateStore, StoreHandle};
use pubky_switch_client::testing::{SWITCH_ORIGIN, ScriptedSwitch};
use pubky_switch_client::transport::{BoxFuture, MockTransport};
use pubky_switch_core::keys::IdentityKey;
use pubky_switch_core::records::{
    IDENTITY_PATH, IdentityDoc, Limits, SIGNER_BACKUP_PATH, SignerBackup, SignerRecords,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_signer::{
    AddOutcome, Alert, Homeserver, IdentityKeyring, IdentitySecret, Protocol, Protocols, Refusal,
    ScopeDef, SecretVault, Signer, SignerEnv, SignerError, SignerStatus, Source, VaultError,
};

const SECRET: [u8; 32] = [11; 32];
const SERVICE_SECRET: [u8; 32] = [22; 32];
const START_MS: u64 = 1_767_225_600_000;

/// A vault holding one secret.
struct Vault(Mutex<Option<[u8; 32]>>);

impl SecretVault for Vault {
    fn load(&self) -> Result<Option<IdentitySecret>, VaultError> {
        Ok(self.0.lock().unwrap().map(IdentitySecret::from_bytes))
    }
    fn add(&self, secret: &IdentitySecret) -> Result<AddOutcome, VaultError> {
        let mut held = self.0.lock().unwrap();
        if held.is_some() {
            return Ok(AddOutcome::Occupied);
        }
        *held = Some(*secret.as_bytes());
        Ok(AddOutcome::Stored)
    }
    fn delete(&self) -> Result<(), VaultError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

/// The identity's Homeserver: its files, every write in order, and a switch to take it down.
#[derive(Default)]
struct TestHomeserver {
    files: Mutex<HashMap<String, Vec<u8>>>,
    writes: Mutex<Vec<(String, Vec<u8>)>>,
    down: Mutex<bool>,
}

impl TestHomeserver {
    fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().unwrap().get(path).cloned()
    }

    fn set(&self, path: &str, bytes: Vec<u8>) {
        self.files.lock().unwrap().insert(path.to_owned(), bytes);
    }

    /// The distinct bodies written at `path`.
    fn distinct_writes(&self, path: &str) -> usize {
        let writes = self.writes.lock().unwrap();
        let bodies: BTreeSet<&Vec<u8>> = writes
            .iter()
            .filter(|(p, _)| p == path)
            .map(|(_, b)| b)
            .collect();
        bodies.len()
    }
}

impl Homeserver for TestHomeserver {
    fn get(&self, path: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        let answer = if *self.down.lock().unwrap() {
            Err(TransportError::Connect("down".into()))
        } else {
            Ok(self.file(path))
        };
        Box::pin(async move { answer })
    }
    fn put(&self, path: &str, bytes: Vec<u8>) -> BoxFuture<'_, Result<(), TransportError>> {
        let answer = if *self.down.lock().unwrap() {
            Err(TransportError::Connect("down".into()))
        } else {
            self.writes
                .lock()
                .unwrap()
                .push((path.to_owned(), bytes.clone()));
            self.set(path, bytes);
            Ok(())
        };
        Box::pin(async move { answer })
    }
}

/// A protocol with one neutral scope.
struct Notes;

impl Protocol for Notes {
    fn name(&self) -> &str {
        "notes"
    }
    fn scopes(&self) -> Vec<ScopeDef> {
        vec![ScopeDef::keyed("notes")]
    }
    fn check_scopes(&self, _: &[&str]) -> Result<(), String> {
        Ok(())
    }
    fn permissions(&self, _: &[&str]) -> Vec<Permission> {
        Vec::new()
    }
}

/// One identity, its switch, its Homeserver and an install's store.
struct World {
    key: IdentityKey,
    switch: Arc<ScriptedSwitch>,
    transport: Arc<MockTransport>,
    homeserver: Arc<TestHomeserver>,
    clock: Arc<TestClock>,
    vault: Arc<Vault>,
}

impl World {
    fn new() -> Self {
        let key = IdentityKey::from_secret(SECRET);
        let clock = Arc::new(TestClock::new(START_MS));
        let switch = ScriptedSwitch::unenrolled(&key, SERVICE_SECRET, Arc::clone(&clock));
        Self {
            transport: switch.transport(),
            switch,
            homeserver: Arc::new(TestHomeserver::default()),
            clock,
            vault: Arc::new(Vault(Mutex::new(Some(SECRET)))),
            key,
        }
    }

    fn env(&self, store: Arc<dyn StateStore>) -> SignerEnv {
        SignerEnv {
            store: StoreHandle::inline(store),
            clock: self.clock.clone(),
            transport: self.transport.clone(),
            homeserver: self.homeserver.clone(),
            protocols: Protocols::new(vec![Arc::new(Notes)]).unwrap(),
        }
    }

    fn keyring(&self) -> IdentityKeyring {
        IdentityKeyring::open(self.vault.clone()).unwrap()
    }

    /// A signer of this identity, enrolled and serving, with its store.
    async fn enrolled(&self) -> (Signer, Arc<MemoryStore>) {
        let store = Arc::new(MemoryStore::new());
        let mut signer = Signer::create(self.env(store.clone()), self.keyring(), SWITCH_ORIGIN)
            .await
            .unwrap();
        signer.resume().await.unwrap();
        (signer, store)
    }

    /// The backup on the Homeserver, opened.
    fn backup(&self) -> SignerRecords {
        let bytes = self.homeserver.file(SIGNER_BACKUP_PATH).expect("a backup");
        let backup: SignerBackup = serde_json::from_slice(&bytes).unwrap();
        backup.open(&self.key).unwrap()
    }

    /// The `identity.json` the Homeserver publishes.
    fn published(&self) -> Option<IdentityDoc> {
        let bytes = self.homeserver.file(IDENTITY_PATH)?;
        let signed: SignedDoc = serde_json::from_slice(&bytes).unwrap();
        Some(IdentityDoc::verify(&signed, &self.key.public()).unwrap())
    }

    /// The distinct bodies of the requests whose path ends with `suffix`.
    fn distinct_requests(&self, method: &str, suffix: &str) -> usize {
        let bodies: BTreeSet<Vec<u8>> = self
            .transport
            .requests()
            .into_iter()
            .filter(|r| r.method == method && r.path_and_query.ends_with(suffix))
            .map(|r| r.body)
            .collect();
        bodies.len()
    }

    /// A version after `doc` signed by another install, delivered to the switch behind the
    /// signer's back.
    fn other_install_version(&self, doc: &IdentityDoc, install: [u8; 16]) -> IdentityDoc {
        let mut body = doc.body().clone();
        body.version += 1;
        body.signer = install;
        IdentityDoc::sign(&self.key, body).unwrap()
    }
}

#[tokio::test]
async fn test_signer_enrollment_delivers_then_publishes_the_first_version() {
    let world = World::new();
    let (signer, _) = world.enrolled().await;
    assert_eq!(signer.status(), SignerStatus::Signing);
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(
        (doc.version(), doc.generation(), doc.data_epoch()),
        (1, 1, 1)
    );
    // The first version names this switch, its key and this install (Switch spec 4.3).
    assert_eq!(doc.inbox().url, SWITCH_ORIGIN);
    assert_eq!(doc.inbox().service_key, world.switch.service_key());
    assert_eq!(doc.body().signer, signer.install_id());
    // Delivered, then published: both copies are the signer's high-water mark.
    let high = signer.high_water().unwrap();
    assert_eq!((high.version, high.doc_hash), (1, doc.hash()));
    assert_eq!(world.switch.identity_doc().unwrap().signed(), doc.signed());
    assert_eq!(world.published().unwrap().signed(), doc.signed());
    // The backup holds that version, for this identity (Switch wire 3.13).
    let records = world.backup();
    assert_eq!(records.identity_doc().signed(), doc.signed());
    assert_eq!(records.prev(), None);
    assert!(signer.alerts().is_empty());
}

#[tokio::test]
async fn test_signer_create_refuses_an_identity_already_set_up() {
    let world = World::new();
    let (_, store) = world.enrolled().await;
    let error = Signer::create(world.env(store), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap_err();
    assert_eq!(error, SignerError::Refused(Refusal::AlreadySetUp));
}

#[tokio::test]
async fn test_signer_open_refuses_an_empty_store() {
    let world = World::new();
    let error = Signer::open(world.env(Arc::new(MemoryStore::new())), world.keyring())
        .await
        .unwrap_err();
    assert_eq!(error, SignerError::Refused(Refusal::NotSetUp));
}

#[tokio::test]
async fn test_signer_create_refuses_an_origin_that_isnt_a_switch_origin() {
    let world = World::new();
    for origin in ["http://switch.example", "https://switch.example/v1"] {
        let error = Signer::create(
            world.env(Arc::new(MemoryStore::new())),
            world.keyring(),
            origin,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, SignerError::InvalidData(_)),
            "{origin}: {error:?}"
        );
    }
}

#[tokio::test]
async fn test_signer_open_keeps_the_install_and_the_high_water_mark() {
    let world = World::new();
    let (signer, store) = world.enrolled().await;
    let opened = Signer::open(world.env(store), world.keyring())
        .await
        .unwrap();
    assert_eq!(opened.install_id(), signer.install_id());
    assert_eq!(opened.high_water(), signer.high_water());
    assert_eq!(opened.status(), SignerStatus::Signing);
}

#[tokio::test]
async fn test_signer_new_version_builds_on_the_newest() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let second = signer.set_record_max_age(Some(2_592_000)).await.unwrap();
    assert_eq!(second.version(), 2);
    assert_eq!(second.body().record_max_age, Some(2_592_000));
    assert_eq!(second.body().signer, signer.install_id());
    assert_eq!(signer.high_water().unwrap().doc_hash, second.hash());
    assert_eq!(
        world.switch.identity_doc().unwrap().signed(),
        second.signed()
    );
    assert_eq!(world.published().unwrap().signed(), second.signed());
    // The backup was written before the delivery, holding the version and its `prev`.
    let records = world.backup();
    assert_eq!(records.identity_doc().signed(), second.signed());
    assert_eq!(records.prev(), Some(first.hash()));
}

#[tokio::test]
async fn test_signer_a_backup_write_that_fails_stops_the_delivery() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    *world.homeserver.down.lock().unwrap() = true;
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert!(matches!(error, SignerError::Homeserver(_)), "{error:?}");
    // Nothing reached the switch: the backup comes first (Switch wire 3.13).
    assert_eq!(world.switch.identity_doc().unwrap().version(), 1);
    assert_eq!(signer.high_water().unwrap().version, 1);
    // Once the Homeserver is back, the same version goes out.
    *world.homeserver.down.lock().unwrap() = false;
    signer.resume().await.unwrap();
    assert_eq!(world.switch.identity_doc().unwrap().version(), 2);
    assert_eq!(world.distinct_requests("PUT", "/identity"), 2);
}

#[tokio::test]
async fn test_signer_refuses_a_new_version_while_a_flow_is_in_progress() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    *world.homeserver.down.lock().unwrap() = true;
    signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    let error = signer.set_record_max_age(Some(3_600)).await.unwrap_err();
    assert_eq!(error, SignerError::Refused(Refusal::FlowInProgress));
}

#[tokio::test]
async fn test_signer_a_newer_version_by_another_install_stops_signing() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let other = [9; 16];
    world
        .switch
        .deliver_identity(&world.other_install_version(&first, other))
        .unwrap();
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: other });
    assert_eq!(signer.status(), SignerStatus::ManagedBy { install: other });
    assert!(
        signer
            .alerts()
            .contains(&Alert::ManagedByOtherInstall { install: other })
    );
    // The newer copy is adopted as the high-water mark, and this install signs nothing more.
    assert_eq!(signer.high_water().unwrap().version, 2);
    let error = signer
        .set_connect_requests(Default::default())
        .await
        .unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: other });
    // It never publishes another install's version (Switch spec 4.3).
    assert_eq!(world.published().unwrap().version(), 1);
}

#[tokio::test]
async fn test_signer_another_installs_backup_stops_signing_before_the_delivery() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let other = [7; 16];
    let theirs = world.other_install_version(&first, other);
    let records = SignerRecords::new(
        IdentityKey::from_secret(SECRET),
        theirs,
        &[],
        &[],
        Limits::default(),
        &[],
        Some(first.hash()),
    )
    .unwrap();
    let backup = SignerBackup::seal(&world.key, &records).unwrap();
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, serde_json::to_vec(&backup).unwrap());
    let error = signer.set_record_max_age(Some(86_400)).await.unwrap_err();
    assert_eq!(error, SignerError::NotNamed { install: other });
    // Nothing was written or delivered (Switch wire 3.13 "Another install's backup").
    assert_eq!(world.switch.identity_doc().unwrap().version(), 1);
    assert_eq!(world.backup().identity_doc().body().signer, other);
}

#[tokio::test]
async fn test_signer_own_earlier_backup_doesnt_stop_signing() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    // The backup of version 1 names this install: the next version goes out.
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    signer.set_record_max_age(None).await.unwrap();
    assert_eq!(signer.high_water().unwrap().version, 3);
}

#[tokio::test]
async fn test_signer_an_unreadable_backup_is_replaced_with_an_alert() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    world.homeserver.set(
        SIGNER_BACKUP_PATH,
        b"{\"envelopes\":[],\"sig\":\"x\"}".to_vec(),
    );
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    assert!(signer.alerts().contains(&Alert::BackupUnreadable));
    assert_eq!(world.backup().identity_doc().version(), 2);
}

#[tokio::test]
async fn test_signer_an_older_copy_at_the_switch_is_a_rollback_alarm() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    signer.set_record_max_age(Some(86_400)).await.unwrap();
    // The switch goes back to version 1.
    world.switch.deliver_identity(&first).unwrap();
    let error = signer.set_record_max_age(None).await.unwrap_err();
    let alert = Alert::Rollback {
        source: Source::Switch,
        version: 1,
        generation: 1,
        high_water_version: 2,
    };
    assert_eq!(error, SignerError::Alarm(alert.clone()));
    assert!(signer.alerts().contains(&alert));
    // The high-water mark doesn't go back.
    assert_eq!(signer.high_water().unwrap().version, 2);
}

#[tokio::test]
async fn test_signer_another_body_at_the_high_water_version_is_equivocation() {
    let world = World::new();
    let (mut signer, _) = world.enrolled().await;
    let first = signer.identity_doc().unwrap().unwrap();
    let second = signer.set_record_max_age(Some(86_400)).await.unwrap();
    // Another version 2, built on the same first version.
    let mut body = first.body().clone();
    body.version = 2;
    body.record_max_age = Some(3_600);
    let forked = IdentityDoc::sign(&world.key, body).unwrap();
    assert_ne!(forked.body_hash(), second.body_hash());
    world.switch.deliver_identity(&forked).unwrap();
    let error = signer.set_record_max_age(None).await.unwrap_err();
    let alert = Alert::Equivocation {
        source: Source::Switch,
        version: 2,
    };
    assert_eq!(error, SignerError::Alarm(alert.clone()));
    assert_eq!(signer.high_water().unwrap().doc_hash, second.hash());
}

#[tokio::test]
async fn test_signer_a_lost_answer_is_resent_with_the_same_bytes() {
    use pubky_switch_client::testing::Fault as SwitchFault;
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/v1/enroll".into(),
    });
    world.switch.fail_next(SwitchFault::LoseAnswer {
        path: "/identity".into(),
    });
    assert!(signer.resume().await.is_err());
    assert!(signer.resume().await.is_err());
    signer.resume().await.unwrap();
    // The enrollment and the delivery each went out twice, the same bytes both times, and
    // the switch took the retry (Switch wire 2.1, 7.4.2).
    assert_eq!(world.distinct_requests("POST", "/v1/enroll"), 1);
    assert_eq!(world.distinct_requests("PUT", "/identity"), 1);
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(world.switch.identity_doc().unwrap().signed(), doc.signed());
}

/// Run the enrollment with the store stopping before or after commit `n`, then reopen the
/// store as a restarted process would and finish.
async fn crash_at(fault: Fault) -> (World, Signer) {
    let world = World::new();
    let memory: Arc<dyn StateStore> = Arc::new(MemoryStore::new());
    let faulty = Arc::new(FaultStore::new(Arc::clone(&memory), fault));
    let created = Signer::create(world.env(faulty.clone()), world.keyring(), SWITCH_ORIGIN).await;
    if let Ok(mut signer) = created {
        let _ = signer.resume().await;
    }
    let env = world.env(memory);
    let mut signer = match Signer::open(env.clone(), world.keyring()).await {
        Ok(signer) => signer,
        Err(SignerError::Refused(Refusal::NotSetUp)) => {
            Signer::create(env, world.keyring(), SWITCH_ORIGIN)
                .await
                .unwrap()
        }
        Err(error) => panic!("{fault:?}: {error:?}"),
    };
    signer
        .resume()
        .await
        .unwrap_or_else(|e| panic!("{fault:?}: {e:?}"));
    (world, signer)
}

#[tokio::test]
async fn test_signer_enrollment_survives_a_crash_at_every_commit() {
    // Set up, enrolled, backup sealed, backup written, delivered, published: six commits.
    let world = World::new();
    let counting = Arc::new(FaultStore::new(Arc::new(MemoryStore::new()), Fault::None));
    let mut signer = Signer::create(world.env(counting.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    assert_eq!(counting.commits(), 6);
    for n in 1..=7 {
        for fault in [Fault::StopBefore(n), Fault::StopAfter(n)] {
            let (world, signer) = crash_at(fault).await;
            let doc = signer.identity_doc().unwrap().unwrap();
            assert_eq!(doc.version(), 1, "{fault:?}");
            assert_eq!(world.switch.identity_doc().unwrap().signed(), doc.signed());
            assert_eq!(world.published().unwrap().signed(), doc.signed());
            assert_eq!(world.backup().identity_doc().signed(), doc.signed());
            // Nothing signed twice: one enrollment, one document and one backup went out,
            // however often each was sent.
            assert_eq!(
                world.distinct_requests("POST", "/v1/enroll"),
                1,
                "{fault:?}"
            );
            assert_eq!(world.distinct_requests("PUT", "/identity"), 1, "{fault:?}");
            assert_eq!(
                world.homeserver.distinct_writes(SIGNER_BACKUP_PATH),
                1,
                "{fault:?}"
            );
        }
    }
}
