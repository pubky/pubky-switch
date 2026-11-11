//! A world to run a flow in: a clock, the Homeservers, and switches by origin, either the
//! service or the scripted switch.
//!
//! The two kinds of world have one surface, so a flow is written once. A flow reaches a
//! switch only as its parties do, through the [`Transport`] the world gives the real
//! [`Signer`](pubky_switch_signer::Signer) and the real
//! [`App`](pubky_switch_client::app::App); it never calls a switch's test calls.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pubky_switch::limits::Limits;
use pubky_switch_client::TransportError;
use pubky_switch_client::app::{AppEnv, HomeserverReader};
use pubky_switch_client::clock::{Clock, TestClock};
use pubky_switch_client::store::{StateStore, StoreHandle};
use pubky_switch_client::testing::{
    Router, START_MS, ScriptedSwitch, Seeds, TestHomeserver, TestIdentity,
};
use pubky_switch_client::transport::{BoxFuture, Request, Response, Transport};
use pubky_switch_core::enc::zbase32_encode;
use pubky_switch_core::http::header;
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_signer::{
    AddOutcome, Homeserver, IdentityKeyring, IdentitySecret, Protocols, SecretVault, SignerEnv,
    VaultError,
};
use serde_json::Value;

use crate::HarnessError;
use crate::check::Checker;
use crate::service::{RealSwitch, database_configured};
use crate::trace::{Fault, Names, Recorder, Trace};

/// The seed of the operator key every switch of a world signs with where it can't tie an
/// answer to an account (Switch wire 7.1): the scripted switch's fixed one.
const OPERATOR_SECRET: [u8; 32] = [42; 32];

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What answers a world's requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// The service of this workspace, in process, on PostgreSQL.
    Service,
    /// The client's scripted switch.
    Scripted,
}

/// One run's world.
pub struct World {
    backend: Backend,
    seeds: Seeds,
    clock: Arc<TestClock>,
    files: Arc<TestHomeserver>,
    router: Arc<Router>,
    recorder: Arc<Recorder>,
    checker: Arc<Checker>,
    names: Arc<Names>,
    services: Mutex<Vec<RealSwitch>>,
    scripted: Mutex<Vec<Arc<ScriptedSwitch>>>,
}

impl std::fmt::Debug for World {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "World({:?}, {:?})", self.backend, self.router)
    }
}

impl World {
    /// A world answered by `backend`, with no switch yet and its clock at
    /// [`START_MS`]; `None` for the service when no test database is configured and the
    /// run is to be skipped.
    ///
    /// # Errors
    ///
    /// When a test database is required and not configured.
    pub fn start(backend: Backend) -> Result<Option<Self>, HarnessError> {
        if backend == Backend::Service && !database_configured()? {
            return Ok(None);
        }
        let names = Arc::new(Names::default());
        let router = Arc::new(Router::new());
        let checker = Arc::new(Checker::default());
        checker.operator(IdentityKey::from_secret(OPERATOR_SECRET).public());
        let recorder = Arc::new(Recorder::new(
            router.clone() as Arc<dyn Transport>,
            names.clone(),
            checker.clone(),
        ));
        Ok(Some(Self {
            backend,
            seeds: Seeds::default(),
            clock: Arc::new(TestClock::new(START_MS)),
            files: Arc::new(TestHomeserver::new()),
            router,
            recorder,
            checker,
            names,
            services: Mutex::new(Vec::new()),
            scripted: Mutex::new(Vec::new()),
        }))
    }

    /// What answers this world's requests.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// The identity `name`, with the keys its name gives it in every world, and its Pubky
    /// ID shown as `{name}` in the trace.
    ///
    /// # Errors
    ///
    /// When the name already stands for another ID.
    pub fn identity(&self, name: &str) -> Result<TestIdentity, HarnessError> {
        let identity = TestIdentity::new(&self.seeds, name);
        self.names.add(&identity.key().id(), name)?;
        Ok(identity)
    }

    /// The keys of `identity`'s app `app`, the same in every world, with its App ID shown
    /// as `{identity/app}` in the trace, so two identities' apps of one name read apart.
    ///
    /// # Errors
    ///
    /// When the name already stands for another ID.
    pub fn app_keys(&self, identity: &TestIdentity, app: &str) -> Result<AppKeys, HarnessError> {
        let keys = identity.app_keys(app);
        self.names.add(
            &zbase32_encode(&keys.app_id_bytes()),
            &format!("{}/{app}", identity.name()),
        )?;
        Ok(keys)
    }

    /// Put a switch at `origin` where none of `identities` has an account yet; their signers
    /// enroll there. One switch hosts them all, each with its own account, which takes the
    /// service key of its identity's seed when the identities enroll in the order given.
    ///
    /// # Errors
    ///
    /// When the service can't be started.
    pub async fn add_switch(
        &self,
        origin: &str,
        identities: &[&TestIdentity],
    ) -> Result<(), HarnessError> {
        self.add_switch_with(origin, identities, Limits::default())
            .await
    }

    /// As [`World::add_switch`], the service running with `limits` (Switch wire 9.2) in
    /// place of its defaults, as an operator may configure it. The scripted switch has no
    /// such setting: it keeps its own.
    ///
    /// # Errors
    ///
    /// When the service can't be started.
    pub async fn add_switch_with(
        &self,
        origin: &str,
        identities: &[&TestIdentity],
        limits: Limits,
    ) -> Result<(), HarnessError> {
        // Each account's answers are verified with the service key of its identity's seed
        // (an Ed25519 key, as an identity key is).
        for identity in identities {
            self.checker.account(
                &identity.key().id(),
                identity.public(),
                IdentityKey::from_secret(identity.service_secret()).public(),
            );
        }
        match self.backend {
            Backend::Service => {
                let switch = RealSwitch::start(
                    origin,
                    self.clock.clone(),
                    identities
                        .iter()
                        .map(|identity| identity.service_secret())
                        .collect(),
                    OPERATOR_SECRET,
                    limits,
                )
                .await?
                .ok_or_else(|| HarnessError::Setup("no test database".into()))?;
                self.router.add(origin, switch.transport());
                lock(&self.services).push(switch);
            }
            Backend::Scripted => {
                // A scripted switch holds one account: one per identity, behind one origin.
                let mut accounts = Vec::with_capacity(identities.len());
                for identity in identities {
                    let switch = ScriptedSwitch::unenrolled(
                        identity.key(),
                        identity.service_secret(),
                        self.clock.clone(),
                    );
                    accounts.push((
                        identity.key().id(),
                        switch.transport() as Arc<dyn Transport>,
                    ));
                    lock(&self.scripted).push(switch);
                }
                self.router.add(origin, Arc::new(Accounts { accounts }));
            }
        }
        Ok(())
    }

    /// The transport every party of this world sends through: to the switch of the
    /// request's origin, recorded.
    pub fn transport(&self) -> Arc<dyn Transport> {
        self.recorder.clone()
    }

    /// The clock every party and every switch of this world reads.
    pub fn clock(&self) -> &Arc<TestClock> {
        &self.clock
    }

    /// The time now, in Unix milliseconds.
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Let `ms` milliseconds pass for everyone.
    pub fn advance_ms(&self, ms: u64) {
        self.clock.advance_ms(ms);
        for switch in lock(&self.services).iter() {
            switch.sample_time();
        }
    }

    /// The environment of `identity`'s signer on `store`: this world's transport and clock,
    /// the identity's own Homeserver, and the [`crate::parties::Notes`] protocol.
    ///
    /// # Errors
    ///
    /// When the protocols don't register.
    pub fn signer_env(
        &self,
        identity: &TestIdentity,
        store: Arc<dyn StateStore>,
    ) -> Result<SignerEnv, HarnessError> {
        let protocols = Protocols::new(vec![Arc::new(crate::parties::Notes)])
            .map_err(|error| HarnessError::Setup(error.to_string()))?;
        Ok(SignerEnv {
            store: StoreHandle::inline(store),
            clock: self.clock.clone() as Arc<dyn Clock>,
            transport: self.transport(),
            homeserver: Arc::new(OwnFiles {
                identity: identity.public(),
                files: self.files.clone(),
            }),
            protocols,
        })
    }

    /// A keyring holding `identity`'s key, as after the host stored it in its vault.
    ///
    /// # Errors
    ///
    /// When the keyring doesn't open.
    pub fn keyring(&self, identity: &TestIdentity) -> Result<IdentityKeyring, HarnessError> {
        let vault = Arc::new(MemoryVault(Mutex::new(Some(identity.key().secret_bytes()))));
        IdentityKeyring::open(vault).map_err(|error| HarnessError::Setup(error.to_string()))
    }

    /// An empty vault, as on an install that doesn't hold the identity's key yet: a signer
    /// taking the identity over puts the secret there once its take-over has won.
    pub fn empty_vault(&self) -> Arc<dyn SecretVault> {
        Arc::new(MemoryVault(Mutex::new(None)))
    }

    /// The environment of an app on `store`: this world's transport, clock and Homeservers.
    pub fn app_env(&self, store: Arc<dyn StateStore>) -> AppEnv {
        AppEnv {
            store: StoreHandle::inline(store),
            transport: self.transport(),
            clock: self.clock.clone() as Arc<dyn Clock>,
            homeserver: self.files.clone() as Arc<dyn HomeserverReader>,
        }
    }

    /// The Homeservers of this world: every identity's public files.
    pub fn files(&self) -> &Arc<TestHomeserver> {
        &self.files
    }

    /// Note an outcome in the trace: what a party returned or raised at this point.
    pub fn outcome(&self, name: &str, value: &Value) {
        self.recorder.outcome(name, value);
    }

    /// Keep each answer in the trace as `distort` changes it, as if the switch had answered
    /// so; the caller gets the answer unchanged. For the harness's own tests, which check
    /// that a switch answering differently is noticed where the client itself accepts it.
    pub fn distort(&self, distort: impl Fn(&Request, &mut Response) + Send + Sync + 'static) {
        self.recorder.distort(distort);
    }

    /// Lose the answer to the next `method` request whose path contains `path`: the switch
    /// takes the request and answers, and the caller sees a timeout.
    pub fn lose_answer(&self, method: &str, path: &str) {
        self.recorder.fail_next(Fault::LoseAnswer {
            method: method.to_owned(),
            path: path.to_owned(),
        });
    }

    /// Make the switch unreachable for the next `method` request whose path contains
    /// `path`: nothing is applied, and the caller fails to connect.
    pub fn unreachable(&self, method: &str, path: &str) {
        self.unreachable_after(method, path, 0);
    }

    /// As [`World::unreachable`], once `after` matching requests went through.
    pub fn unreachable_after(&self, method: &str, path: &str, after: usize) {
        self.recorder.fail_next(Fault::Unreachable {
            method: method.to_owned(),
            path: path.to_owned(),
            after,
        });
    }

    /// The faults asked for that no request has met yet.
    pub fn faults_left(&self) -> usize {
        self.recorder.faults_left()
    }

    /// How many accounts have a feed read held at a switch now, waiting for a change
    /// (Switch wire 7.4.4 `wait`). The scripted switch holds none: it answers a waiting
    /// read at once.
    pub fn held_reads(&self) -> usize {
        lock(&self.services)
            .iter()
            .map(RealSwitch::held_reads)
            .sum()
    }

    /// A request no key signs, as any reader of the network sends it: `method path` at
    /// `origin`, with no body.
    ///
    /// # Errors
    ///
    /// When the request doesn't reach a switch.
    pub async fn request(
        &self,
        method: &str,
        origin: &str,
        path: &str,
    ) -> Result<Response, TransportError> {
        self.transport()
            .send(Request {
                method: method.to_owned(),
                origin: origin.to_owned(),
                path_and_query: path.to_owned(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await
    }

    /// What this run showed so far.
    pub fn trace(&self) -> Trace {
        self.recorder.trace()
    }

    /// End the world: drop the services' test databases.
    ///
    /// # Errors
    ///
    /// When a database can't be dropped.
    pub async fn close(self) -> Result<(), HarnessError> {
        let services = std::mem::take(&mut *lock(&self.services));
        // The routes hold the services' transports.
        drop(self.recorder);
        drop(self.router);
        for switch in services {
            switch.close().await?;
        }
        Ok(())
    }
}

/// The scripted switches of one origin, one per account: a request goes to the switch of the
/// account its path names, and an enrollment to the switch of the identity it is signed for.
struct Accounts {
    accounts: Vec<(String, Arc<dyn Transport>)>,
}

impl Transport for Accounts {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        let named = match request.path_and_query.strip_prefix("/v1/") {
            Some("enroll") => request.header(header::IDENTITY),
            Some(rest) => rest.split(['/', '?']).next(),
            None => None,
        };
        let account = self
            .accounts
            .iter()
            .find(|(id, _)| Some(id.as_str()) == named)
            .map(|(_, transport)| transport.clone());
        Box::pin(async move {
            match account {
                Some(transport) => transport.send(request).await,
                None => Err(TransportError::Connect("no scripted account".into())),
            }
        })
    }
}

/// One identity's own Homeserver, as its signer reads and writes it: its files among the
/// world's.
struct OwnFiles {
    identity: [u8; 32],
    files: Arc<TestHomeserver>,
}

impl Homeserver for OwnFiles {
    fn get(&self, path: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        self.files.get(self.identity, path.to_owned())
    }

    fn put(&self, path: &str, bytes: Vec<u8>) -> BoxFuture<'_, Result<(), TransportError>> {
        self.files.put(self.identity, path, bytes);
        Box::pin(async { Ok(()) })
    }

    fn delete(&self, path: &str) -> BoxFuture<'_, Result<(), TransportError>> {
        self.files.remove(self.identity, path);
        Box::pin(async { Ok(()) })
    }
}

/// A vault in memory.
struct MemoryVault(Mutex<Option<[u8; 32]>>);

impl SecretVault for MemoryVault {
    fn load(&self) -> Result<Option<IdentitySecret>, VaultError> {
        Ok(lock(&self.0).map(IdentitySecret::from_bytes))
    }

    fn add(&self, secret: &IdentitySecret) -> Result<AddOutcome, VaultError> {
        let mut held = lock(&self.0);
        if held.is_some() {
            return Ok(AddOutcome::Occupied);
        }
        *held = Some(*secret.as_bytes());
        Ok(AddOutcome::Stored)
    }

    fn delete(&self) -> Result<(), VaultError> {
        *lock(&self.0) = None;
        Ok(())
    }
}
