//! Service keys, their marks, and the erasure ledger (Switch spec 6.5).
//!
//! Each account has its own service key, one per generation. The key store holds it and,
//! **with it and apart from the state a database backup restores**, the newest head the key
//! signed: its mark. The key signs no head behind its mark or beside it (a fork), so a
//! service whose database was restored from a backup can't sign for the lost state; the
//! account fails stop until the signer starts a new generation. The mark moves with the
//! key: whoever holds the key holds the mark.
//!
//! The key store also keeps the erasure ledger: each erased identity and the time of its
//! erasure, so that a database restored from a backup taken before an erasure erases the
//! account again before it serves anything.
//!
//! [`KeyStore`] is the interface, ready for an HSM or a KMS. [`FileKeyStore`] keeps keys,
//! marks and the ledger in files on a disk of their own, written and synced before an
//! answer goes out. Secret keys never leave the key store: callers get public keys and
//! signatures.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{Read, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use ed25519_dalek::SigningKey;
use parking_lot::Mutex;
use pubky_switch_core::{
    chain::{ChainTip, SignedHead},
    signing::Signs,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The longest identity accepted in the erasure ledger, in characters.
const MAX_IDENTITY_LEN: usize = 64;

/// The key store settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeysConfig {
    /// The directory of the file key store. Required to run the service. Put it on a disk
    /// that database backups don't cover, and back it up on its own.
    pub path: Option<PathBuf>,
    /// How many days the operator keeps database backups: the erasure ledger keeps each
    /// erasure that long, so a database restored from any kept backup erases the account
    /// again (Switch spec 6.5). Unset, the ledger keeps every erasure for good.
    pub backup_retention_days: Option<u64>,
}

/// The readiness check of the file key store: its directories are there and readable.
#[derive(Clone, Debug)]
pub struct KeyStoreReadiness(pub FileKeyStore);

impl crate::admin::ReadinessCheck for KeyStoreReadiness {
    fn name(&self) -> &str {
        "keys"
    }

    fn check(&self) -> crate::admin::CheckFuture<'_> {
        let root = self.0.root().to_path_buf();
        Box::pin(async move {
            for dir in DIRS {
                fs::read_dir(root.join(dir))
                    .map_err(|_| format!("the key store's {dir} directory isn't readable"))?;
            }
            Ok(())
        })
    }
}

/// The ID of one service key: 32 lowercase hex digits, chosen at random by the key store.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyId(String);

impl KeyId {
    /// Parse a key ID.
    pub fn parse(text: &str) -> Result<Self, KeyStoreError> {
        if text.len() == 32
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(text.to_string()))
        } else {
            Err(KeyStoreError::InvalidId)
        }
    }

    /// The ID as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A new random ID, for a key whose deletion is owed before it exists
    /// ([`KeyStore::generate_as`]).
    pub fn random() -> Result<Self, KeyStoreError> {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).map_err(|_| KeyStoreError::Random)?;
        Ok(Self(hex::encode(raw)))
    }
}

impl TryFrom<String> for KeyId {
    type Error = KeyStoreError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<KeyId> for String {
    fn from(id: KeyId) -> Self {
        id.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A newly generated service key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceKey {
    /// Its ID in the key store.
    pub id: KeyId,
    /// Its Ed25519 public key.
    pub public: [u8; 32],
}

/// A head of an account's chain: its generation, `seq` and chain hash (Switch wire 6.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mark {
    /// The generation.
    pub generation: u64,
    /// The head's `seq`.
    pub seq: u64,
    /// The chain hash at `seq`.
    #[serde(with = "hex_bytes")]
    pub chain_hash: [u8; 32],
}

/// How a head compares with a key's mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkCheck {
    /// The key has signed no head yet.
    Unmarked,
    /// The head is the mark, or extends it.
    Current,
    /// The head is behind the mark: the state the key signed was lost.
    Behind,
    /// The head is at the mark's `seq` with another chain hash: a fork.
    Fork,
    /// The head belongs to another generation than the key's.
    OtherGeneration,
}

impl MarkCheck {
    /// Whether the key may sign this head.
    pub fn allows_signing(self) -> bool {
        matches!(self, Self::Unmarked | Self::Current)
    }
}

/// Compare `head` with `mark`.
pub fn check_mark(mark: Option<&Mark>, head: &Mark) -> MarkCheck {
    let Some(mark) = mark else {
        return MarkCheck::Unmarked;
    };
    if mark.generation != head.generation {
        MarkCheck::OtherGeneration
    } else if head.seq < mark.seq {
        MarkCheck::Behind
    } else if head.seq == mark.seq && head.chain_hash != mark.chain_hash {
        MarkCheck::Fork
    } else {
        MarkCheck::Current
    }
}

/// What a key store can fail at.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// No key with this ID.
    #[error("no such service key")]
    NotFound,
    /// A key ID or identity that isn't well formed.
    #[error("invalid key ID or identity")]
    InvalidId,
    /// The key would sign a head behind its mark or beside it.
    #[error("the head is {0:?} the key's mark")]
    Refused(MarkCheck),
    /// Stored key material or a mark that doesn't decode.
    #[error("corrupt key store entry: {0}")]
    Corrupt(String),
    /// The storage failed.
    #[error("key store storage: {0}")]
    Io(#[from] std::io::Error),
    /// No randomness for a new key.
    #[error("no randomness for a new key")]
    Random,
}

/// A future returned by a [`KeyStore`] method.
pub type KeyFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, KeyStoreError>> + Send + 'a>>;

/// Holds the service keys, their marks and the erasure ledger.
///
/// Every write is durable when its future resolves. A write runs to its end, in order with
/// the store's other writes, even if its caller stops waiting.
pub trait KeyStore: Send + Sync {
    /// Generate a new service key.
    fn generate(&self) -> KeyFuture<'_, ServiceKey>;

    /// Generate a new key under `id`, an ID the caller chose ([`KeyId::random`]), so the
    /// caller can owe its deletion durably before it exists: a push key (Switch wire 8.1),
    /// which never gets a mark and whose deletion records no erasure. An `id` already in use
    /// is refused.
    fn generate_as<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceKey>;

    /// The public key of `id`.
    fn public_key<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, [u8; 32]>;

    /// A signer for `id`, for the core's signing functions: responses, transition proofs,
    /// manifests and, through [`sign_head`] only, heads.
    fn signer<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceSigner>;

    /// The operator key's signer: it signs answers the service can't tie to an account,
    /// such as one to an unknown account (Switch wire 7.1). No client knows it.
    fn operator(&self) -> KeyFuture<'_, ServiceSigner>;

    /// The newest head `id` signed, if any.
    fn mark<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, Option<Mark>>;

    /// Move the mark of `id` to `head` if `head` extends it. An older head, from an
    /// answer another one overtook, leaves it. A head beside the mark, or of another
    /// generation, is refused.
    fn advance_mark<'a>(&'a self, id: &'a KeyId, head: Mark) -> KeyFuture<'a, MarkCheck>;

    /// Delete `id` and its mark, for good.
    fn delete<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ()>;

    /// Record that `identity`'s account was erased at `erased_at_ms`.
    fn record_erasure<'a>(&'a self, identity: &'a str, erased_at_ms: u64) -> KeyFuture<'a, ()>;

    /// When `identity`'s account was last erased, if ever; never for an identity the ledger
    /// can't hold, which [`KeyStore::record_erasure`] refuses. Every call to an account
    /// asks, so it must be cheap: a store that caches the ledger holds at least what the
    /// ledger holds.
    fn erasure<'a>(&'a self, identity: &'a str) -> KeyFuture<'a, Option<u64>>;

    /// Every erasure the ledger holds: each identity, with the time of its latest erasure.
    fn erasures(&self) -> KeyFuture<'_, Vec<(String, u64)>>;

    /// Forget the erasures recorded before `before_ms`, whose accounts no database backup
    /// the operator keeps can hold any more (Switch spec 6.5); the number forgotten.
    fn forget_erasures_before(&self, before_ms: u64) -> KeyFuture<'_, usize>;
}

/// A service key's signer: it signs `lp(label, fields...)` under a Switch label, for the
/// core's signing functions (Switch wire 2.1). The secret key stays inside it.
///
/// A head is signed only through [`sign_head`], which checks the key's mark first.
#[derive(Clone)]
pub struct ServiceSigner(Arc<dyn Signs + Send + Sync>);

impl ServiceSigner {
    /// A signer over `key`, for a key store that holds keys in memory or behind its own
    /// signing interface, such as an HSM's.
    pub fn new(key: Arc<dyn Signs + Send + Sync>) -> Self {
        Self(key)
    }
}

impl std::fmt::Debug for ServiceSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSigner")
            .field("public", &hex::encode(self.0.public_key()))
            .finish_non_exhaustive()
    }
}

impl Signs for ServiceSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.public_key()
    }

    fn sign_fields(&self, label: &str, fields: &[&[u8]]) -> [u8; 64] {
        self.0.sign_fields(label, fields)
    }
}

impl From<ChainTip> for Mark {
    fn from(tip: ChainTip) -> Self {
        Self {
            generation: tip.generation,
            seq: tip.seq,
            chain_hash: tip.chain_hash,
        }
    }
}

/// Sign the head at `tip` for `identity`, unless it is behind `mark`, the key's newest
/// signed head, or beside it (Switch spec 6.5): the only way the service signs a head.
/// Signing doesn't move the mark: [`KeyStore::advance_mark`] does, once the head's state is
/// durable.
pub fn sign_head(
    signer: &ServiceSigner,
    mark: Option<&Mark>,
    identity: &[u8; 32],
    tip: &ChainTip,
) -> Result<SignedHead, KeyStoreError> {
    let check = check_mark(mark, &Mark::from(*tip));
    if !check.allows_signing() {
        return Err(KeyStoreError::Refused(check));
    }
    Ok(SignedHead::sign(signer, identity, tip))
}

/// Sign a checkpoint at `at`, a chain item at or before `head` in its generation, for
/// `identity` (Switch spec 6.5, 8.3; wire 7.4.4): a head at an earlier `seq` of the chain the
/// key serves, not a state behind its mark, so it is signed only while `head`, the account's
/// state, is at or past `mark`. Like [`sign_head`], it doesn't move the mark. The caller
/// gives `at`'s chain hash as it read it from the chain.
pub fn sign_checkpoint(
    signer: &ServiceSigner,
    mark: Option<&Mark>,
    identity: &[u8; 32],
    head: &ChainTip,
    at: &ChainTip,
) -> Result<SignedHead, KeyStoreError> {
    let check = check_mark(mark, &Mark::from(*head));
    if !check.allows_signing() {
        return Err(KeyStoreError::Refused(check));
    }
    if at.generation != head.generation || at.seq > head.seq {
        return Err(KeyStoreError::Refused(MarkCheck::OtherGeneration));
    }
    Ok(SignedHead::sign(signer, identity, at))
}

/// A key store in files under one directory:
///
/// - `keys/<id>`: the key's 32-byte secret seed, readable by the owner only;
/// - `marks/<id>`: its mark, as JSON;
/// - `erasures/<identity>`: the time of the identity's erasure, in Unix milliseconds.
///
/// Every file is written to a temporary file, synced, renamed into place and its directory
/// synced, so a crash leaves the old content or the new, never a mix. A write that fails may
/// have landed its rename without the directory sync, so nothing the store reads from a file
/// counts as written before a directory sync covers it: a retry that finds its file in place
/// repeats the sync before it reports success, writes the file again or is refused, and the
/// store syncs its directories when it opens, before it reads them. Put the directory on
/// a disk that database backups don't cover, and back it up on its own: losing it loses
/// every account's service key.
///
/// One process at a time may use a directory.
#[derive(Clone)]
pub struct FileKeyStore {
    inner: Arc<Inner>,
}

struct Inner {
    root: PathBuf,
    keys: Mutex<HashMap<KeyId, Arc<SigningKey>>>,
    marks: Mutex<HashMap<KeyId, Option<Mark>>>,
    /// The erasure ledger, read whole from its files at open, so a request's check needs no
    /// file read. It holds at least what the files hold: an erasure goes in before its file
    /// is written, and leaves only once its file's removal is durable.
    ledger: Mutex<HashMap<String, u64>>,
    /// Held around every read-check-write of a mark, a deletion and an erasure record,
    /// inside the blocking task that does it. A caller that stops waiting can't release it
    /// early: the task runs to its end, so writes land in the order they were checked.
    writes: Mutex<()>,
    /// The operator key, once a directory sync covers the `operator` file that names it.
    operator: Mutex<Option<Arc<SigningKey>>>,
    /// Pauses a mark write before it lands, for tests.
    #[cfg(test)]
    pause: Mutex<Option<PauseGate>>,
    /// Fails directory syncs and tracks what a crash would undo, for tests.
    #[cfg(test)]
    faults: Arc<Mutex<Faults>>,
}

/// The directories under the store's root.
const DIRS: [&str; 3] = ["keys", "marks", "erasures"];

/// Directory syncs that fail on request, and a model of a crash: every rename and removal
/// no directory sync covers yet, which a crash may undo.
#[cfg(test)]
#[derive(Default)]
struct Faults {
    /// How many of a directory's next syncs fail.
    failing: HashMap<PathBuf, usize>,
    /// Each rename or removal not yet covered by a sync of its directory, with the content
    /// the file had before it, if it existed.
    unsynced: Vec<(PathBuf, Option<Vec<u8>>)>,
}

#[cfg(test)]
impl Faults {
    /// Fail the next `times` syncs of `dir`.
    fn fail_sync(&mut self, dir: &Path, times: usize) {
        self.failing.insert(dir.to_path_buf(), times);
    }

    /// Whether this sync of `dir` fails.
    fn fails(&mut self, dir: &Path) -> bool {
        match self.failing.get_mut(dir) {
            Some(left) if *left > 0 => {
                *left -= 1;
                true
            }
            _ => false,
        }
    }

    /// A rename onto `path` or its removal landed: `before` is what the file held.
    fn changed(&mut self, path: &Path, before: Option<Vec<u8>>) {
        self.unsynced.push((path.to_path_buf(), before));
    }

    /// A sync of `dir` succeeded: a crash no longer undoes the changes in it.
    fn synced(&mut self, dir: &Path) {
        self.unsynced.retain(|(path, _)| path.parent() != Some(dir));
    }

    /// Crash: undo every change no directory sync covers, newest first.
    fn crash(&mut self) {
        while let Some((path, before)) = self.unsynced.pop() {
            match before {
                Some(bytes) => fs::write(&path, bytes).expect("restore"),
                None => fs::remove_file(&path).expect("remove"),
            }
        }
    }
}

/// Pauses the mark write for `seq` once: it says so on `paused`, then waits on `release`.
#[cfg(test)]
struct PauseGate {
    seq: u64,
    paused: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

impl std::fmt::Debug for FileKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKeyStore")
            .field("root", &self.inner.root)
            .finish_non_exhaustive()
    }
}

impl FileKeyStore {
    /// Open the key store at `root`, creating its directories if they don't exist.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, KeyStoreError> {
        Self::start(Inner::new(root.into()))
    }

    /// Open the key store at `root` with `faults`, which outlive it: a test's next store on
    /// the same directory takes them over, as the next process takes over the disk.
    #[cfg(test)]
    fn open_with_faults(
        root: impl Into<PathBuf>,
        faults: Arc<Mutex<Faults>>,
    ) -> Result<Self, KeyStoreError> {
        let mut inner = Inner::new(root.into());
        inner.faults = faults;
        Self::start(inner)
    }

    fn start(inner: Inner) -> Result<Self, KeyStoreError> {
        for dir in DIRS {
            create_private_dir(&inner.root.join(dir))?;
        }
        // An earlier process may have landed a rename or a removal and stopped before its
        // directory sync, or failed it: the file is there to read, and a crash could still
        // undo it. Sync every directory before reading any, so a mark this store compares a
        // head with, an erasure it holds and the operator file are all durable.
        for dir in DIRS {
            inner.sync_dir(&inner.root.join(dir))?;
        }
        inner.sync_dir(&inner.root)?;
        let ledger = read_ledger(&inner.root.join("erasures"))?;
        *inner.ledger.lock() = ledger;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The directory.
    pub fn root(&self) -> &Path {
        &self.inner.root
    }
}

impl Inner {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            keys: Mutex::new(HashMap::new()),
            marks: Mutex::new(HashMap::new()),
            ledger: Mutex::new(HashMap::new()),
            writes: Mutex::new(()),
            operator: Mutex::new(None),
            #[cfg(test)]
            pause: Mutex::new(None),
            #[cfg(test)]
            faults: Arc::default(),
        }
    }

    /// Sync `dir`, so a rename or a removal in it is durable.
    fn sync_dir(&self, dir: &Path) -> Result<(), KeyStoreError> {
        #[cfg(test)]
        if self.faults.lock().fails(dir) {
            return Err(std::io::Error::other("injected directory sync failure").into());
        }
        sync_dir(dir)?;
        #[cfg(test)]
        self.faults.lock().synced(dir);
        Ok(())
    }

    /// Write `bytes` to `path` atomically and durably: a temporary file in the same
    /// directory, synced, renamed into place, then the directory synced. `exclusive` refuses
    /// to replace an existing file. On a failure the rename may have landed without the
    /// directory sync: whoever then finds the file in place syncs the directory before
    /// counting it as written.
    fn write_atomic(
        &self,
        path: &Path,
        bytes: &[u8],
        exclusive: bool,
    ) -> Result<(), KeyStoreError> {
        let dir = path
            .parent()
            .ok_or_else(|| KeyStoreError::Io(std::io::Error::other("path without a directory")))?;
        #[cfg(test)]
        let before = fs::read(path).ok();
        rename_into_place(dir, path, bytes, exclusive)?;
        #[cfg(test)]
        self.faults.lock().changed(path, before);
        self.sync_dir(dir)
    }

    /// Remove the file at `path`, if it is there. The removal is durable once its directory
    /// is synced, which the caller does also when the file was already gone: an earlier
    /// removal may have landed without its sync.
    fn remove_file(&self, path: &Path) -> Result<(), KeyStoreError> {
        #[cfg(test)]
        let before = fs::read(path).ok();
        match fs::remove_file(path) {
            Ok(()) => {
                #[cfg(test)]
                self.faults.lock().changed(path, before);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn key_path(&self, id: &KeyId) -> PathBuf {
        self.root.join("keys").join(id.as_str())
    }

    fn mark_path(&self, id: &KeyId) -> PathBuf {
        self.root.join("marks").join(id.as_str())
    }

    fn erasure_path(&self, identity: &str) -> Result<PathBuf, KeyStoreError> {
        if !is_ledger_name(identity) {
            return Err(KeyStoreError::InvalidId);
        }
        Ok(self.root.join("erasures").join(identity))
    }

    fn load_key(&self, id: &KeyId) -> Result<Arc<SigningKey>, KeyStoreError> {
        if let Some(key) = self.keys.lock().get(id) {
            return Ok(key.clone());
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        let mut file = match File::open(self.key_path(id)) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(KeyStoreError::NotFound);
            }
            Err(error) => return Err(error.into()),
        };
        let mut rest = [0u8; 1];
        file.read_exact(seed.as_mut())
            .map_err(|_| KeyStoreError::Corrupt(format!("key {id}: too short")))?;
        if file.read(&mut rest)? != 0 {
            return Err(KeyStoreError::Corrupt(format!("key {id}: too long")));
        }
        let key = Arc::new(SigningKey::from_bytes(&seed));
        self.keys.lock().insert(id.clone(), key.clone());
        Ok(key)
    }

    fn load_mark(&self, id: &KeyId) -> Result<Option<Mark>, KeyStoreError> {
        if let Some(mark) = self.marks.lock().get(id) {
            return Ok(*mark);
        }
        let mark = match fs::read(self.mark_path(id)) {
            Ok(bytes) => Some(
                serde_json::from_slice::<Mark>(&bytes)
                    .map_err(|error| KeyStoreError::Corrupt(format!("mark {id}: {error}")))?,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        self.marks.lock().insert(id.clone(), mark);
        Ok(mark)
    }

    fn generate_sync(&self) -> Result<ServiceKey, KeyStoreError> {
        self.generate_as_sync(KeyId::random()?)
    }

    fn generate_as_sync(&self, id: KeyId) -> Result<ServiceKey, KeyStoreError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| KeyStoreError::Random)?;
        self.write_atomic(&self.key_path(&id), seed.as_ref(), true)?;
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        self.keys.lock().insert(id.clone(), Arc::new(key));
        Ok(ServiceKey { id, public })
    }

    /// The operator key, made on first use: `operator` holds its ID.
    fn operator_sync(&self) -> Result<Arc<SigningKey>, KeyStoreError> {
        if let Some(key) = self.operator.lock().clone() {
            return Ok(key);
        }
        let path = self.root.join("operator");
        let _writes = self.writes.lock();
        if let Some(key) = self.operator.lock().clone() {
            return Ok(key);
        }
        let id = match fs::read_to_string(&path) {
            Ok(text) => {
                let id = KeyId::parse(text.trim())?;
                // The file may be one whose rename landed and whose directory sync then
                // failed. Sync again before the key signs anything, so a crash can't drop
                // the file and have another key take its place.
                self.sync_dir(&self.root)?;
                id
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let key = self.generate_sync()?;
                self.write_atomic(&path, key.id.as_str().as_bytes(), true)?;
                key.id
            }
            Err(error) => return Err(error.into()),
        };
        let key = self.load_key(&id)?;
        *self.operator.lock() = Some(key.clone());
        Ok(key)
    }

    /// Keep `seed` as a new key, for tests that need the vectors' fixed keys.
    #[cfg(any(test, feature = "test-util"))]
    fn import_sync(&self, seed: &[u8; 32]) -> Result<ServiceKey, KeyStoreError> {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).map_err(|_| KeyStoreError::Random)?;
        let id = KeyId(hex::encode(raw));
        self.write_atomic(&self.key_path(&id), seed, true)?;
        let key = SigningKey::from_bytes(seed);
        let public = key.verifying_key().to_bytes();
        self.keys.lock().insert(id.clone(), Arc::new(key));
        Ok(ServiceKey { id, public })
    }

    fn advance_mark_sync(&self, id: &KeyId, head: Mark) -> Result<MarkCheck, KeyStoreError> {
        let _writes = self.writes.lock();
        // A mark is only meaningful with its key.
        self.load_key(id)?;
        let current = self.load_mark(id)?;
        let check = check_mark(current.as_ref(), &head);
        match check {
            MarkCheck::Behind => Ok(check),
            MarkCheck::Current if current == Some(head) => Ok(check),
            MarkCheck::Unmarked | MarkCheck::Current => {
                #[cfg(test)]
                self.pause_before_write(head.seq);
                let bytes = serde_json::to_vec(&head)
                    .map_err(|error| KeyStoreError::Corrupt(error.to_string()))?;
                self.write_atomic(&self.mark_path(id), &bytes, false)?;
                self.marks.lock().insert(id.clone(), Some(head));
                Ok(check)
            }
            MarkCheck::Fork | MarkCheck::OtherGeneration => Err(KeyStoreError::Refused(check)),
        }
    }

    #[cfg(test)]
    fn pause_before_write(&self, seq: u64) {
        let gate = {
            let mut pause = self.pause.lock();
            if pause.as_ref().is_some_and(|gate| gate.seq == seq) {
                pause.take()
            } else {
                None
            }
        };
        if let Some(gate) = gate {
            let _ = gate.paused.send(());
            let _ = gate.release.recv();
        }
    }

    fn read_erasure(path: &Path) -> Result<Option<u64>, KeyStoreError> {
        match fs::read_to_string(path) {
            Ok(text) => text
                .trim()
                .parse::<u64>()
                .map(Some)
                .map_err(|error| KeyStoreError::Corrupt(format!("erasure: {error}"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Keep the latest erasure time: an account created before it is erased again after a
    /// restore (Switch spec 6.5), so an older time must never replace a newer one.
    fn record_erasure_sync(&self, identity: &str, erased_at_ms: u64) -> Result<(), KeyStoreError> {
        let path = self.erasure_path(identity)?;
        let _writes = self.writes.lock();
        let recorded = Self::read_erasure(&path)?;
        // The ledger in memory takes the erasure first, so it holds at least what the files
        // hold, also when a write lands its file and then fails: on that side it only erases.
        let latest = recorded.map_or(erased_at_ms, |recorded| recorded.max(erased_at_ms));
        {
            let mut ledger = self.ledger.lock();
            let held = ledger.entry(identity.to_string()).or_insert(latest);
            *held = (*held).max(latest);
        }
        if recorded.is_some_and(|recorded| recorded >= erased_at_ms) {
            // The file may be one whose rename landed and whose directory sync then failed:
            // the erasure isn't recorded until a sync covers it. The caller drops its duty
            // to record on this answer, and a crash would then lose the entry the restore
            // protection reads (Switch spec 6.5).
            return self.sync_dir(&self.root.join("erasures"));
        }
        self.write_atomic(&path, erased_at_ms.to_string().as_bytes(), false)
    }

    /// Remove the ledger's files of erasures before `before_ms`, each removal durable before
    /// its entry leaves the ledger in memory.
    fn forget_erasures_sync(&self, before_ms: u64) -> Result<usize, KeyStoreError> {
        let _writes = self.writes.lock();
        let old: Vec<String> = self
            .ledger
            .lock()
            .iter()
            .filter(|(_, at)| **at < before_ms)
            .map(|(identity, _)| identity.clone())
            .collect();
        let dir = self.root.join("erasures");
        for identity in &old {
            self.remove_file(&dir.join(identity))?;
        }
        if !old.is_empty() {
            self.sync_dir(&dir)?;
            let mut ledger = self.ledger.lock();
            for identity in &old {
                ledger.remove(identity);
            }
        }
        Ok(old.len())
    }

    fn delete_sync(&self, id: &KeyId) -> Result<(), KeyStoreError> {
        let _writes = self.writes.lock();
        // The key goes first: a key whose mark is gone could sign behind it, while a mark
        // without its key signs nothing.
        for path in [self.key_path(id), self.mark_path(id)] {
            self.remove_file(&path)?;
            if let Some(dir) = path.parent() {
                self.sync_dir(dir)?;
            }
        }
        self.keys.lock().remove(id);
        self.marks.lock().remove(id);
        Ok(())
    }
}

/// Run blocking file work off the async runtime.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, KeyStoreError> + Send + 'static,
) -> Result<T, KeyStoreError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| KeyStoreError::Io(std::io::Error::other(error.to_string())))?
}

impl KeyStore for FileKeyStore {
    fn generate(&self) -> KeyFuture<'_, ServiceKey> {
        let store = self.inner.clone();
        Box::pin(blocking(move || store.generate_sync()))
    }

    fn generate_as<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceKey> {
        let store = self.inner.clone();
        let id = id.clone();
        Box::pin(blocking(move || store.generate_as_sync(id)))
    }

    fn public_key<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, [u8; 32]> {
        let store = self.inner.clone();
        let id = id.clone();
        Box::pin(blocking(move || {
            Ok(store.load_key(&id)?.verifying_key().to_bytes())
        }))
    }

    fn signer<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceSigner> {
        let store = self.inner.clone();
        let id = id.clone();
        Box::pin(async move {
            let key = blocking(move || store.load_key(&id)).await?;
            Ok(ServiceSigner(key as Arc<dyn Signs + Send + Sync>))
        })
    }

    fn operator(&self) -> KeyFuture<'_, ServiceSigner> {
        let store = self.inner.clone();
        Box::pin(async move {
            let key = blocking(move || store.operator_sync()).await?;
            Ok(ServiceSigner(key as Arc<dyn Signs + Send + Sync>))
        })
    }

    fn mark<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, Option<Mark>> {
        let store = self.inner.clone();
        let id = id.clone();
        Box::pin(blocking(move || {
            // A mark is only meaningful with its key.
            store.load_key(&id)?;
            store.load_mark(&id)
        }))
    }

    fn advance_mark<'a>(&'a self, id: &'a KeyId, head: Mark) -> KeyFuture<'a, MarkCheck> {
        let store = self.inner.clone();
        let id = id.clone();
        Box::pin(blocking(move || store.advance_mark_sync(&id, head)))
    }

    fn delete<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ()> {
        let store = self.inner.clone();
        let id = id.clone();
        Box::pin(blocking(move || store.delete_sync(&id)))
    }

    fn record_erasure<'a>(&'a self, identity: &'a str, erased_at_ms: u64) -> KeyFuture<'a, ()> {
        let store = self.inner.clone();
        let identity = identity.to_string();
        Box::pin(blocking(move || {
            store.record_erasure_sync(&identity, erased_at_ms)
        }))
    }

    fn erasure<'a>(&'a self, identity: &'a str) -> KeyFuture<'a, Option<u64>> {
        // A name the ledger can't hold was never recorded: no erasure.
        let found = self.inner.ledger.lock().get(identity).copied();
        Box::pin(std::future::ready(Ok(found)))
    }

    fn erasures(&self) -> KeyFuture<'_, Vec<(String, u64)>> {
        let mut all: Vec<(String, u64)> = self
            .inner
            .ledger
            .lock()
            .iter()
            .map(|(identity, at)| (identity.clone(), *at))
            .collect();
        all.sort_unstable();
        Box::pin(std::future::ready(Ok(all)))
    }

    fn forget_erasures_before(&self, before_ms: u64) -> KeyFuture<'_, usize> {
        let store = self.inner.clone();
        Box::pin(blocking(move || store.forget_erasures_sync(before_ms)))
    }
}

/// Whether `name` may name an identity in the erasure ledger: a Pubky ID's characters, at
/// most [`MAX_IDENTITY_LEN`]. A write's temporary file, which starts with a dot, never does.
fn is_ledger_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_IDENTITY_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// The erasure ledger in `dir`: every file an identity names, with its time. A write's
/// temporary file, left by a crash, isn't an entry; any other file that doesn't read is
/// refused, so a ledger that can't be read whole stops the store from opening.
fn read_ledger(dir: &Path) -> Result<HashMap<String, u64>, KeyStoreError> {
    let mut ledger = HashMap::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(KeyStoreError::Corrupt(
                "erasure: a file name isn't UTF-8".into(),
            ));
        };
        if name.starts_with('.') && name.ends_with(".tmp") {
            continue;
        }
        if !is_ledger_name(name) {
            return Err(KeyStoreError::Corrupt(format!(
                "erasure: {name} names no identity"
            )));
        }
        if let Some(at) = Inner::read_erasure(&entry.path())? {
            ledger.insert(name.to_string(), at);
        }
    }
    Ok(ledger)
}

/// Create `dir` and its parents, readable by the owner only.
fn create_private_dir(dir: &Path) -> Result<(), KeyStoreError> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `bytes` to a temporary file in `dir`, sync it and rename it to `path`, a file in
/// `dir`. `exclusive` refuses to replace an existing file. The rename isn't durable until
/// `dir` is synced.
fn rename_into_place(
    dir: &Path,
    path: &Path,
    bytes: &[u8],
    exclusive: bool,
) -> Result<(), KeyStoreError> {
    if exclusive && path.exists() {
        return Err(KeyStoreError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "key file exists",
        )));
    }
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| KeyStoreError::Random)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(KeyStoreError::InvalidId)?;
    let temp = dir.join(format!(".{name}.{}.tmp", hex::encode(suffix)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Sync a directory, so a rename or removal in it is durable.
fn sync_dir(dir: &Path) -> Result<(), KeyStoreError> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Hex encoding for 32-byte values in JSON.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(text, &mut bytes).map_err(D::Error::custom)?;
        Ok(bytes)
    }
}

/// A key store whose new keys are given seeds, in order, for tests that replay the
/// vectors' fixed service keys; everything else is the file store's.
#[cfg(any(test, feature = "test-util"))]
pub struct FixedKeys {
    store: FileKeyStore,
    seeds: Mutex<std::collections::VecDeque<[u8; 32]>>,
    operator: Option<[u8; 32]>,
    operator_key: Mutex<Option<Arc<SigningKey>>>,
}

#[cfg(any(test, feature = "test-util"))]
impl FixedKeys {
    /// Hand out `seeds` as new keys, in order, then random ones; sign operator answers with
    /// `operator` when given.
    pub fn new(store: FileKeyStore, seeds: Vec<[u8; 32]>, operator: Option<[u8; 32]>) -> Self {
        Self {
            store,
            seeds: Mutex::new(seeds.into()),
            operator,
            operator_key: Mutex::new(None),
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
impl KeyStore for FixedKeys {
    fn generate(&self) -> KeyFuture<'_, ServiceKey> {
        let next = self.seeds.lock().pop_front();
        match next {
            Some(seed) => {
                let store = self.store.inner.clone();
                Box::pin(blocking(move || store.import_sync(&seed)))
            }
            None => self.store.generate(),
        }
    }

    fn generate_as<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceKey> {
        self.store.generate_as(id)
    }

    fn public_key<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, [u8; 32]> {
        self.store.public_key(id)
    }

    fn signer<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceSigner> {
        self.store.signer(id)
    }

    fn operator(&self) -> KeyFuture<'_, ServiceSigner> {
        let Some(seed) = self.operator else {
            return self.store.operator();
        };
        let key = self
            .operator_key
            .lock()
            .get_or_insert_with(|| Arc::new(SigningKey::from_bytes(&seed)))
            .clone();
        Box::pin(async move { Ok(ServiceSigner(key as Arc<dyn Signs + Send + Sync>)) })
    }

    fn mark<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, Option<Mark>> {
        self.store.mark(id)
    }

    fn advance_mark<'a>(&'a self, id: &'a KeyId, head: Mark) -> KeyFuture<'a, MarkCheck> {
        self.store.advance_mark(id, head)
    }

    fn delete<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ()> {
        self.store.delete(id)
    }

    fn record_erasure<'a>(&'a self, identity: &'a str, erased_at_ms: u64) -> KeyFuture<'a, ()> {
        self.store.record_erasure(identity, erased_at_ms)
    }

    fn erasure<'a>(&'a self, identity: &'a str) -> KeyFuture<'a, Option<u64>> {
        self.store.erasure(identity)
    }

    fn erasures(&self) -> KeyFuture<'_, Vec<(String, u64)>> {
        self.store.erasures()
    }

    fn forget_erasures_before(&self, before_ms: u64) -> KeyFuture<'_, usize> {
        self.store.forget_erasures_before(before_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_switch_core::{chain::ZERO_HASH, labels, sig};

    fn mark(seq: u64, hash: u8) -> Mark {
        Mark {
            generation: 1,
            seq,
            chain_hash: [hash; 32],
        }
    }

    fn open() -> (tempfile::TempDir, FileKeyStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileKeyStore::open(dir.path()).expect("open");
        (dir, store)
    }

    #[test]
    fn test_check_mark_cases() {
        let current = mark(10, 1);
        assert_eq!(check_mark(None, &current), MarkCheck::Unmarked);
        assert_eq!(check_mark(Some(&current), &mark(10, 1)), MarkCheck::Current);
        assert_eq!(check_mark(Some(&current), &mark(11, 2)), MarkCheck::Current);
        assert_eq!(check_mark(Some(&current), &mark(9, 1)), MarkCheck::Behind);
        assert_eq!(check_mark(Some(&current), &mark(10, 2)), MarkCheck::Fork);
        let other = Mark {
            generation: 2,
            ..current
        };
        assert_eq!(
            check_mark(Some(&current), &other),
            MarkCheck::OtherGeneration
        );
    }

    #[tokio::test]
    async fn test_key_store_signs_with_generated_key() {
        let (_dir, store) = open();
        let key = store.generate().await.expect("generate");
        assert_eq!(store.public_key(&key.id).await.expect("public"), key.public);
        let signer = store.signer(&key.id).await.expect("signer");
        assert_eq!(signer.public_key(), key.public);
        let fields: [&[u8]; 2] = [b"status", b"body"];
        let signature = signer.sign_fields(labels::sig::HTTP_RESPONSE, &fields);
        sig::verify(&key.public, labels::sig::HTTP_RESPONSE, &fields, &signature)
            .expect("verifies under its label");
        assert!(sig::verify(&key.public, labels::sig::HEAD, &fields, &signature).is_err());
    }

    #[tokio::test]
    async fn test_key_store_keeps_keys_and_marks_across_reopen() {
        let (dir, store) = open();
        let key = store.generate().await.expect("generate");
        store
            .advance_mark(&key.id, mark(5, 1))
            .await
            .expect("advance");
        drop(store);
        let store = FileKeyStore::open(dir.path()).expect("reopen");
        assert_eq!(store.public_key(&key.id).await.expect("public"), key.public);
        assert_eq!(store.mark(&key.id).await.expect("mark"), Some(mark(5, 1)));
    }

    #[tokio::test]
    async fn test_key_store_mark_only_moves_forward() {
        let (_dir, store) = open();
        let key = store.generate().await.expect("generate");
        assert_eq!(store.mark(&key.id).await.expect("mark"), None);
        let check = store
            .advance_mark(&key.id, mark(5, 1))
            .await
            .expect("first");
        assert_eq!(check, MarkCheck::Unmarked);
        let check = store
            .advance_mark(&key.id, mark(7, 2))
            .await
            .expect("ahead");
        assert_eq!(check, MarkCheck::Current);
        // An overtaken answer's older head leaves the mark where it is.
        let check = store
            .advance_mark(&key.id, mark(6, 3))
            .await
            .expect("older");
        assert_eq!(check, MarkCheck::Behind);
        assert_eq!(store.mark(&key.id).await.expect("mark"), Some(mark(7, 2)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_key_store_cancelled_advance_keeps_marks_in_order() {
        let (dir, store) = open();
        let key = store.generate().await.expect("generate");
        let (paused_tx, paused) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        *store.inner.pause.lock() = Some(PauseGate {
            seq: 1001,
            paused: paused_tx,
            release: release_rx,
        });

        // The write for 1001 pauses before it lands, and its caller is cancelled.
        let first = tokio::spawn({
            let (store, id) = (store.clone(), key.id.clone());
            async move { store.advance_mark(&id, mark(1001, 1)).await }
        });
        tokio::task::spawn_blocking(move || paused.recv())
            .await
            .expect("join")
            .expect("the write paused");
        first.abort();
        assert!(first.await.expect_err("cancelled").is_cancelled());

        // 1002 waits behind the write still running for 1001.
        let second = tokio::spawn({
            let (store, id) = (store.clone(), key.id.clone());
            async move { store.advance_mark(&id, mark(1002, 2)).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!second.is_finished(), "serialized behind the paused write");
        release.send(()).expect("release");
        assert_eq!(
            second.await.expect("join").expect("advance"),
            MarkCheck::Current
        );

        drop(store);
        let store = FileKeyStore::open(dir.path()).expect("reopen");
        assert_eq!(
            store.mark(&key.id).await.expect("mark"),
            Some(mark(1002, 2))
        );
    }

    #[tokio::test]
    async fn test_key_store_operator_key_is_kept() {
        let (dir, store) = open();
        let first = store.operator().await.expect("operator").public_key();
        let store = FileKeyStore::open(dir.path()).expect("reopen");
        assert_eq!(
            store.operator().await.expect("operator").public_key(),
            first
        );
    }

    #[tokio::test]
    async fn test_key_store_erasure_ledger_keeps_the_latest_time() {
        let (dir, store) = open();
        let identity = "6frao8w9ss5cn544qd64hynikrbr97ae1s5941c7ma5e1epifhgy";
        store.record_erasure(identity, 2_000).await.expect("record");
        // An older erasure landing after a newer one doesn't take the ledger back.
        store.record_erasure(identity, 1_000).await.expect("record");
        let store = FileKeyStore::open(dir.path()).expect("reopen");
        assert_eq!(store.erasure(identity).await.expect("read"), Some(2_000));
        store.record_erasure(identity, 3_000).await.expect("record");
        assert_eq!(store.erasure(identity).await.expect("read"), Some(3_000));
    }

    #[tokio::test]
    async fn test_key_store_refuses_fork_and_other_generation() {
        let (_dir, store) = open();
        let key = store.generate().await.expect("generate");
        store.advance_mark(&key.id, mark(5, 1)).await.expect("mark");
        assert!(matches!(
            store.advance_mark(&key.id, mark(5, 2)).await,
            Err(KeyStoreError::Refused(MarkCheck::Fork))
        ));
        let other = Mark {
            generation: 2,
            ..mark(6, 1)
        };
        assert!(matches!(
            store.advance_mark(&key.id, other).await,
            Err(KeyStoreError::Refused(MarkCheck::OtherGeneration))
        ));
        assert_eq!(store.mark(&key.id).await.expect("mark"), Some(mark(5, 1)));
    }

    #[tokio::test]
    async fn test_key_store_sign_checkpoint_only_while_the_head_is_at_the_mark() {
        // A checkpoint at an earlier `seq` of the chain the key serves is signed while the
        // account's head is at or past the mark, and refused once the head is behind it, on
        // a fork, or for a point past the head or of another generation (Switch spec 6.5).
        let (_dir, store) = open();
        let key = store.generate().await.expect("generate");
        let signer = store.signer(&key.id).await.expect("signer");
        let identity = [3u8; 32];
        let tip = |seq: u64, hash: u8| ChainTip {
            generation: 1,
            seq,
            chain_hash: [hash; 32],
        };
        let marked = mark(5, 1);
        let checkpoint = sign_checkpoint(&signer, Some(&marked), &identity, &tip(5, 1), &tip(2, 7))
            .expect("at the mark");
        assert_eq!(
            (checkpoint.generation, checkpoint.seq, checkpoint.chain_hash),
            (1, 2, [7; 32])
        );
        checkpoint
            .verify(&signer.public_key(), &identity)
            .expect("signed");
        sign_checkpoint(&signer, Some(&marked), &identity, &tip(6, 9), &tip(6, 9))
            .expect("ahead, at the head");
        sign_checkpoint(&signer, None, &identity, &tip(3, 1), &tip(2, 7)).expect("unmarked");
        for (head, at, refused) in [
            (tip(4, 1), tip(2, 7), MarkCheck::Behind),
            (tip(5, 2), tip(2, 7), MarkCheck::Fork),
        ] {
            assert!(matches!(
                sign_checkpoint(&signer, Some(&marked), &identity, &head, &at),
                Err(KeyStoreError::Refused(check)) if check == refused
            ));
        }
        let other = ChainTip {
            generation: 2,
            ..tip(2, 7)
        };
        for at in [tip(6, 7), other] {
            assert!(matches!(
                sign_checkpoint(&signer, Some(&marked), &identity, &tip(5, 1), &at),
                Err(KeyStoreError::Refused(MarkCheck::OtherGeneration))
            ));
        }
    }

    #[tokio::test]
    async fn test_key_store_sign_head_refuses_behind_and_fork() {
        let (_dir, store) = open();
        let key = store.generate().await.expect("generate");
        let signer = store.signer(&key.id).await.expect("signer");
        let identity = [3u8; 32];
        let tip = |seq: u64, hash: u8| ChainTip {
            generation: 1,
            seq,
            chain_hash: if seq == 0 { ZERO_HASH } else { [hash; 32] },
        };
        // Unmarked: any head, the empty chain's included.
        sign_head(&signer, None, &identity, &tip(0, 0)).expect("empty chain");
        let marked = mark(5, 1);
        let head = sign_head(&signer, Some(&marked), &identity, &tip(5, 1)).expect("the mark");
        assert_eq!(
            (head.generation, head.seq, head.chain_hash),
            (1, 5, [1; 32])
        );
        sign_head(&signer, Some(&marked), &identity, &tip(6, 9)).expect("ahead");
        assert!(matches!(
            sign_head(&signer, Some(&marked), &identity, &tip(4, 1)),
            Err(KeyStoreError::Refused(MarkCheck::Behind))
        ));
        assert!(matches!(
            sign_head(&signer, Some(&marked), &identity, &tip(5, 2)),
            Err(KeyStoreError::Refused(MarkCheck::Fork))
        ));
        let other = ChainTip {
            generation: 2,
            ..tip(9, 9)
        };
        assert!(matches!(
            sign_head(&signer, Some(&marked), &identity, &other),
            Err(KeyStoreError::Refused(MarkCheck::OtherGeneration))
        ));
    }

    #[tokio::test]
    async fn test_key_store_generate_as_takes_the_id_once() {
        // A key generated under an ID the caller chose, owed before it exists: signs, has no
        // mark, and a second key under the same ID is refused.
        let (_dir, store) = open();
        let id = KeyId::random().expect("id");
        let key = store.generate_as(&id).await.expect("generate");
        assert_eq!(key.id, id);
        assert_eq!(store.public_key(&id).await.expect("public"), key.public);
        assert_eq!(store.mark(&id).await.expect("mark"), None);
        assert!(store.generate_as(&id).await.is_err());
        assert_eq!(store.public_key(&id).await.expect("public"), key.public);
        store.delete(&id).await.expect("delete");
        assert!(matches!(
            store.public_key(&id).await,
            Err(KeyStoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn test_key_store_delete_removes_key_and_mark() {
        let (dir, store) = open();
        let key = store.generate().await.expect("generate");
        store.advance_mark(&key.id, mark(5, 1)).await.expect("mark");
        store.delete(&key.id).await.expect("delete");
        assert!(matches!(
            store.signer(&key.id).await,
            Err(KeyStoreError::NotFound)
        ));
        let store = FileKeyStore::open(dir.path()).expect("reopen");
        assert!(matches!(
            store.mark(&key.id).await,
            Err(KeyStoreError::NotFound)
        ));
        // Deleting again is fine.
        store.delete(&key.id).await.expect("delete again");
    }

    #[tokio::test]
    async fn test_key_store_unknown_key_is_not_found() {
        let (_dir, store) = open();
        let id = KeyId::parse("00112233445566778899aabbccddeeff").expect("id");
        assert!(matches!(
            store.public_key(&id).await,
            Err(KeyStoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn test_key_store_detects_corrupt_key() {
        let (dir, store) = open();
        let id = KeyId::parse("00112233445566778899aabbccddeeff").expect("id");
        fs::write(dir.path().join("keys").join(id.as_str()), [1u8; 31]).expect("write");
        assert!(matches!(
            store.public_key(&id).await,
            Err(KeyStoreError::Corrupt(_))
        ));
    }

    #[tokio::test]
    async fn test_key_store_erasure_ledger() {
        let (dir, store) = open();
        let identity = "6frao8w9ss5cn544qd64hynikrbr97ae1s5941c7ma5e1epifhgy";
        assert_eq!(store.erasure(identity).await.expect("read"), None);
        store
            .record_erasure(identity, 1_767_225_600_000)
            .await
            .expect("record");
        let store = FileKeyStore::open(dir.path()).expect("reopen");
        assert_eq!(
            store.erasure(identity).await.expect("read"),
            Some(1_767_225_600_000)
        );
        assert!(matches!(
            store.record_erasure("../keys/x", 1).await,
            Err(KeyStoreError::InvalidId)
        ));
        assert_eq!(store.erasure("../keys/x").await.expect("read"), None);
    }

    #[tokio::test]
    async fn test_key_store_erasure_ledger_lists_and_forgets_before_a_time() {
        let (dir, store) = open();
        for (identity, at) in [("aaa", 1_000), ("bbb", 2_000), ("ccc", 3_000)] {
            store.record_erasure(identity, at).await.expect("record");
        }
        assert_eq!(
            store.erasures().await.expect("list"),
            vec![
                ("aaa".to_string(), 1_000),
                ("bbb".to_string(), 2_000),
                ("ccc".to_string(), 3_000)
            ]
        );
        // Before 2,000: only the first goes; one at the time stays.
        assert_eq!(
            store.forget_erasures_before(2_000).await.expect("forget"),
            1
        );
        assert_eq!(store.erasure("aaa").await.expect("read"), None);
        assert_eq!(store.erasure("bbb").await.expect("read"), Some(2_000));
        // The removal is durable: a reopened store reads the same ledger.
        let store = FileKeyStore::open(dir.path()).expect("reopen");
        assert_eq!(
            store.erasures().await.expect("list"),
            vec![("bbb".to_string(), 2_000), ("ccc".to_string(), 3_000)]
        );
        assert_eq!(store.forget_erasures_before(0).await.expect("forget"), 0);
    }

    #[tokio::test]
    async fn test_key_store_erasure_ledger_holds_an_erasure_its_file_already_records() {
        // A write whose rename landed but whose directory sync failed leaves the file in
        // place and the record refused; the retry finds the file and must still put the
        // erasure in the ledger the checks read (Switch spec 6.5).
        let (dir, store) = open();
        fs::write(dir.path().join("erasures").join("aaa"), "1000").expect("landed");
        store.record_erasure("aaa", 1_000).await.expect("record");
        assert_eq!(store.erasure("aaa").await.expect("read"), Some(1_000));
    }

    /// A store with faults to inject, which a later store on the same directory takes over.
    fn open_faulty() -> (tempfile::TempDir, FileKeyStore, Arc<Mutex<Faults>>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let faults = Arc::new(Mutex::new(Faults::default()));
        let store = FileKeyStore::open_with_faults(dir.path(), faults.clone()).expect("open");
        (dir, store, faults)
    }

    /// The machine crashes, losing what no directory sync covers, and a new process opens
    /// the store.
    fn crash_and_reopen(dir: &tempfile::TempDir, faults: &Arc<Mutex<Faults>>) -> FileKeyStore {
        faults.lock().crash();
        FileKeyStore::open_with_faults(dir.path(), faults.clone()).expect("reopen")
    }

    #[tokio::test]
    async fn test_key_store_erasure_retry_syncs_the_directory_before_it_is_recorded() {
        // The rename lands and the directory sync fails: the record is refused. Its retry
        // finds the file in place and must sync the directory before it reports the erasure
        // recorded, or a crash loses an entry the caller no longer owes (Switch spec 6.5).
        let (dir, store, faults) = open_faulty();
        let erasures = dir.path().join("erasures");
        faults.lock().fail_sync(&erasures, 1);
        assert!(matches!(
            store.record_erasure("aaa", 1_000).await,
            Err(KeyStoreError::Io(_))
        ));
        assert!(erasures.join("aaa").exists(), "the rename landed");
        // The ledger in memory holds it meanwhile: on that side it only erases.
        assert_eq!(store.erasure("aaa").await.expect("read"), Some(1_000));
        store.record_erasure("aaa", 1_000).await.expect("retry");
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.erasure("aaa").await.expect("read"), Some(1_000));
    }

    #[tokio::test]
    async fn test_key_store_erasure_retry_is_refused_while_the_directory_sync_fails() {
        let (dir, store, faults) = open_faulty();
        let erasures = dir.path().join("erasures");
        faults.lock().fail_sync(&erasures, 2);
        for _ in 0..2 {
            assert!(matches!(
                store.record_erasure("aaa", 1_000).await,
                Err(KeyStoreError::Io(_))
            ));
        }
        // Nothing reported it recorded, and the crash loses it.
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.erasure("aaa").await.expect("read"), None);
        store.record_erasure("aaa", 1_000).await.expect("record");
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.erasure("aaa").await.expect("read"), Some(1_000));
    }

    #[tokio::test]
    async fn test_key_store_older_erasure_after_an_unsynced_newer_one_syncs_the_directory() {
        // The same retry, asked with an older time: the file already holds a newer erasure,
        // nothing is written, and the directory is still synced.
        let (dir, store, faults) = open_faulty();
        faults.lock().fail_sync(&dir.path().join("erasures"), 1);
        assert!(store.record_erasure("aaa", 2_000).await.is_err());
        store.record_erasure("aaa", 1_000).await.expect("older");
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.erasure("aaa").await.expect("read"), Some(2_000));
    }

    #[tokio::test]
    async fn test_key_store_forget_erasures_retry_syncs_the_directory() {
        let (dir, store, faults) = open_faulty();
        store.record_erasure("aaa", 1_000).await.expect("record");
        faults.lock().fail_sync(&dir.path().join("erasures"), 1);
        assert!(store.forget_erasures_before(2_000).await.is_err());
        // The removal isn't durable: the ledger still holds the erasure.
        assert_eq!(store.erasure("aaa").await.expect("read"), Some(1_000));
        assert_eq!(store.forget_erasures_before(2_000).await.expect("retry"), 1);
        assert_eq!(store.erasure("aaa").await.expect("read"), None);
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.erasure("aaa").await.expect("read"), None);
    }

    #[tokio::test]
    async fn test_key_store_mark_left_unsynced_is_synced_before_the_next_process_reads_it() {
        // A mark's rename lands, its directory sync fails and the process stops. The next
        // process reads the new mark from the file; an advance to the same head then writes
        // nothing, so the open itself must have made the mark durable, or a crash takes the
        // key's mark back behind a head it signed (Switch spec 6.5).
        let (dir, store, faults) = open_faulty();
        let key = store.generate().await.expect("generate");
        store
            .advance_mark(&key.id, mark(1, 1))
            .await
            .expect("first");
        faults.lock().fail_sync(&dir.path().join("marks"), 1);
        assert!(matches!(
            store.advance_mark(&key.id, mark(2, 2)).await,
            Err(KeyStoreError::Io(_))
        ));
        // The same process still holds the mark it last wrote durably.
        assert_eq!(store.mark(&key.id).await.expect("mark"), Some(mark(1, 1)));
        drop(store);
        let store = FileKeyStore::open_with_faults(dir.path(), faults.clone()).expect("restart");
        assert_eq!(store.mark(&key.id).await.expect("mark"), Some(mark(2, 2)));
        assert_eq!(
            store.advance_mark(&key.id, mark(2, 2)).await.expect("same"),
            MarkCheck::Current
        );
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.mark(&key.id).await.expect("mark"), Some(mark(2, 2)));
    }

    #[tokio::test]
    async fn test_key_store_mark_retry_in_the_same_process_writes_again() {
        let (dir, store, faults) = open_faulty();
        let key = store.generate().await.expect("generate");
        faults.lock().fail_sync(&dir.path().join("marks"), 1);
        assert!(store.advance_mark(&key.id, mark(1, 1)).await.is_err());
        store
            .advance_mark(&key.id, mark(1, 1))
            .await
            .expect("retry");
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(store.mark(&key.id).await.expect("mark"), Some(mark(1, 1)));
    }

    #[tokio::test]
    async fn test_key_store_operator_retry_syncs_the_directory_before_the_key_signs() {
        // The `operator` file's rename lands and the root's sync fails. The retry finds the
        // file and must sync the root before it hands out the key, or a crash drops the file
        // and another key takes its place.
        let (dir, store, faults) = open_faulty();
        faults.lock().fail_sync(dir.path(), 1);
        assert!(matches!(store.operator().await, Err(KeyStoreError::Io(_))));
        assert!(dir.path().join("operator").exists(), "the rename landed");
        let first = store.operator().await.expect("retry").public_key();
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(
            store.operator().await.expect("operator").public_key(),
            first
        );
    }

    #[tokio::test]
    async fn test_key_store_operator_retry_is_refused_while_the_directory_sync_fails() {
        let (dir, store, faults) = open_faulty();
        faults.lock().fail_sync(dir.path(), 2);
        assert!(store.operator().await.is_err());
        assert!(store.operator().await.is_err());
        let first = store.operator().await.expect("operator").public_key();
        let store = crash_and_reopen(&dir, &faults);
        assert_eq!(
            store.operator().await.expect("operator").public_key(),
            first
        );
    }

    #[tokio::test]
    async fn test_key_store_generate_as_refuses_the_id_of_an_unsynced_key() {
        // A key whose rename landed without the directory sync is never handed out: the
        // write is refused, and so is a retry under the same ID.
        let (dir, store, faults) = open_faulty();
        let id = KeyId::random().expect("id");
        faults.lock().fail_sync(&dir.path().join("keys"), 1);
        assert!(store.generate_as(&id).await.is_err());
        assert!(store.generate_as(&id).await.is_err());
    }

    #[tokio::test]
    async fn test_key_store_delete_retry_syncs_the_directory() {
        let (dir, store, faults) = open_faulty();
        let key = store.generate().await.expect("generate");
        faults.lock().fail_sync(&dir.path().join("keys"), 1);
        assert!(store.delete(&key.id).await.is_err());
        store.delete(&key.id).await.expect("retry");
        let store = crash_and_reopen(&dir, &faults);
        assert!(matches!(
            store.public_key(&key.id).await,
            Err(KeyStoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn test_key_store_open_fails_when_a_directory_sync_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        for failing in [dir.path().to_path_buf(), dir.path().join("marks")] {
            let faults = Arc::new(Mutex::new(Faults::default()));
            faults.lock().fail_sync(&failing, 1);
            assert!(matches!(
                FileKeyStore::open_with_faults(dir.path(), faults),
                Err(KeyStoreError::Io(_))
            ));
        }
        FileKeyStore::open(dir.path()).expect("open");
    }

    #[tokio::test]
    async fn test_key_store_erasure_ledger_skips_a_write_left_by_a_crash() {
        let (dir, store) = open();
        store.record_erasure("aaa", 1_000).await.expect("record");
        drop(store);
        // A write's temporary file, as a crash before its rename leaves it.
        fs::write(
            dir.path()
                .join("erasures")
                .join(".bbb.0011223344556677.tmp"),
            "2000",
        )
        .expect("temp");
        let store = FileKeyStore::open(dir.path()).expect("reopen");
        assert_eq!(
            store.erasures().await.expect("list"),
            vec![("aaa".to_string(), 1_000)]
        );
    }

    #[tokio::test]
    async fn test_key_store_erasure_ledger_that_doesnt_read_refuses_to_open() {
        let (dir, store) = open();
        store.record_erasure("aaa", 1_000).await.expect("record");
        drop(store);
        let ledger = dir.path().join("erasures");
        fs::write(ledger.join("aaa"), "not a time").expect("corrupt");
        assert!(matches!(
            FileKeyStore::open(dir.path()),
            Err(KeyStoreError::Corrupt(_))
        ));
        fs::write(ledger.join("aaa"), "1000").expect("fixed");
        fs::write(ledger.join("Not-An-Identity"), "1000").expect("stray");
        assert!(matches!(
            FileKeyStore::open(dir.path()),
            Err(KeyStoreError::Corrupt(_))
        ));
    }

    #[test]
    fn test_key_id_parsing() {
        assert!(KeyId::parse("00112233445566778899aabbccddeeff").is_ok());
        for bad in [
            "",
            "00112233445566778899AABBCCDDEEFF",
            "00112233445566778899aabbccddeef",
            "../112233445566778899aabbccddeeff",
        ] {
            assert!(KeyId::parse(bad).is_err(), "{bad}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_key_store_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, store) = open();
        let key = store.generate().await.expect("generate");
        let mode = fs::metadata(dir.path().join("keys").join(key.id.as_str()))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let mode = fs::metadata(dir.path().join("keys"))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
