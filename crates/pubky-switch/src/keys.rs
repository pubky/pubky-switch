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
            for dir in ["keys", "marks", "erasures"] {
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
/// Every write is durable when its future resolves.
pub trait KeyStore: Send + Sync {
    /// Generate a new service key.
    fn generate(&self) -> KeyFuture<'_, ServiceKey>;

    /// The public key of `id`.
    fn public_key<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, [u8; 32]>;

    /// A signer for `id`, for the core's signing functions: responses, transition proofs,
    /// manifests and, through [`sign_head`] only, heads.
    fn signer<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ServiceSigner>;

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

    /// When `identity`'s account was last erased, if ever.
    fn erasure<'a>(&'a self, identity: &'a str) -> KeyFuture<'a, Option<u64>>;
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

/// A key store in files under one directory:
///
/// - `keys/<id>`: the key's 32-byte secret seed, readable by the owner only;
/// - `marks/<id>`: its mark, as JSON;
/// - `erasures/<identity>`: the time of the identity's erasure, in Unix milliseconds.
///
/// Every file is written to a temporary file, synced, renamed into place and its directory
/// synced, so a crash leaves the old content or the new, never a mix. Put the directory on
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
    /// Serializes mark updates, so that two advances can't both read the old mark.
    mark_writes: tokio::sync::Mutex<()>,
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
        let root = root.into();
        for dir in ["keys", "marks", "erasures"] {
            create_private_dir(&root.join(dir))?;
        }
        Ok(Self {
            inner: Arc::new(Inner {
                root,
                keys: Mutex::new(HashMap::new()),
                marks: Mutex::new(HashMap::new()),
                mark_writes: tokio::sync::Mutex::new(()),
            }),
        })
    }

    /// The directory.
    pub fn root(&self) -> &Path {
        &self.inner.root
    }
}

impl Inner {
    fn key_path(&self, id: &KeyId) -> PathBuf {
        self.root.join("keys").join(id.as_str())
    }

    fn mark_path(&self, id: &KeyId) -> PathBuf {
        self.root.join("marks").join(id.as_str())
    }

    fn erasure_path(&self, identity: &str) -> Result<PathBuf, KeyStoreError> {
        if identity.is_empty()
            || identity.len() > MAX_IDENTITY_LEN
            || !identity
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
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
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| KeyStoreError::Random)?;
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).map_err(|_| KeyStoreError::Random)?;
        let id = KeyId(hex::encode(raw));
        write_atomic(&self.key_path(&id), seed.as_ref(), true)?;
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        self.keys.lock().insert(id.clone(), Arc::new(key));
        Ok(ServiceKey { id, public })
    }

    fn delete_sync(&self, id: &KeyId) -> Result<(), KeyStoreError> {
        // The key goes first: a key whose mark is gone could sign behind it, while a mark
        // without its key signs nothing.
        for path in [self.key_path(id), self.mark_path(id)] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            if let Some(dir) = path.parent() {
                sync_dir(dir)?;
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
        Box::pin(async move {
            let _write = self.inner.mark_writes.lock().await;
            let current = self.mark(id).await?;
            let check = check_mark(current.as_ref(), &head);
            match check {
                MarkCheck::Behind => Ok(check),
                MarkCheck::Current if current == Some(head) => Ok(check),
                MarkCheck::Unmarked | MarkCheck::Current => {
                    let store = self.inner.clone();
                    let id = id.clone();
                    blocking(move || {
                        let bytes = serde_json::to_vec(&head)
                            .map_err(|error| KeyStoreError::Corrupt(error.to_string()))?;
                        write_atomic(&store.mark_path(&id), &bytes, false)?;
                        store.marks.lock().insert(id, Some(head));
                        Ok(())
                    })
                    .await?;
                    Ok(check)
                }
                MarkCheck::Fork | MarkCheck::OtherGeneration => Err(KeyStoreError::Refused(check)),
            }
        })
    }

    fn delete<'a>(&'a self, id: &'a KeyId) -> KeyFuture<'a, ()> {
        Box::pin(async move {
            let _write = self.inner.mark_writes.lock().await;
            let store = self.inner.clone();
            let id = id.clone();
            blocking(move || store.delete_sync(&id)).await
        })
    }

    fn record_erasure<'a>(&'a self, identity: &'a str, erased_at_ms: u64) -> KeyFuture<'a, ()> {
        let path = self.inner.erasure_path(identity);
        Box::pin(blocking(move || {
            write_atomic(&path?, erased_at_ms.to_string().as_bytes(), false)
        }))
    }

    fn erasure<'a>(&'a self, identity: &'a str) -> KeyFuture<'a, Option<u64>> {
        let path = self.inner.erasure_path(identity);
        Box::pin(blocking(move || match fs::read_to_string(path?) {
            Ok(text) => text
                .trim()
                .parse::<u64>()
                .map(Some)
                .map_err(|error| KeyStoreError::Corrupt(format!("erasure: {error}"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }))
    }
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

/// Write `bytes` to `path` atomically and durably: a temporary file in the same directory,
/// synced, renamed into place, then the directory synced. `exclusive` refuses to replace an
/// existing file.
fn write_atomic(path: &Path, bytes: &[u8], exclusive: bool) -> Result<(), KeyStoreError> {
    let dir = path
        .parent()
        .ok_or_else(|| KeyStoreError::Io(std::io::Error::other("path without a directory")))?;
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
        sync_dir(dir)
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
