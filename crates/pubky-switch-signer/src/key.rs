//! The identity key interface (Switch spec 3.1, 12.8; Switch wire 2.1).
//!
//! The host keeps the identity's 32-byte Ed25519 secret in the device's secure storage and
//! hands it to this crate through a [`SecretVault`]: three calls that move opaque bytes, so
//! that host code never signs, derives or parses anything. Neither the iOS Secure Enclave nor
//! the Android Keystore supports Ed25519, so the key must be in software while it signs; it is
//! loaded for one operation at a time and zeroized after.
//!
//! Every use of the key goes through an [`IdentityKeyring`], whose signing and derivation
//! entry points belong to this crate alone. The crate signs only inputs it builds itself, for
//! the identity-key formats of Switch wire 2.3, the approval's companion claim (Switch wire
//! 3.10) and Pubky's own formats for the same key, and its public API offers no signing of
//! bytes a caller supplies (Switch wire 2.1). The secret leaves the vault for two reasons only,
//! each named by an [`ExportReason`]: sealed in a hand-over to another signer (Switch wire
//! 3.12), or sealed in the signer's own backup (Switch wire 3.13).
//!
//! # For hosts
//!
//! - **iOS:** one keychain item of a class ending in `ThisDeviceOnly` (Switch spec 3.1).
//! - **Android:** a file encrypted under a Keystore key and excluded from backups.
//! - **A key derived from a wallet seed:** `load` may derive it each time. `delete` then can't
//!   make the key unrecoverable, and the host tells the user so before a hand-over (Switch spec
//!   12.8, "The limit").

use std::sync::Arc;

use pubky_switch_core::enc::{kid, pubky_id};
use pubky_switch_core::keys::IdentityKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The identity's 32-byte Ed25519 secret, its seed (Switch spec 13.3). Zeroized on drop, and
/// never shown by `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecret([u8; 32]);

impl IdentitySecret {
    /// The secret of these 32 bytes, as the host's vault keeps them.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The secret of a slice the host's vault returned.
    ///
    /// # Errors
    ///
    /// [`KeyError::Malformed`] when `bytes` isn't 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, KeyError> {
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| KeyError::Malformed)
    }

    /// The bytes, for the vault to store. Sensitive.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The core's key for one operation. The returned key zeroizes itself on drop.
    fn key(&self) -> IdentityKey {
        IdentityKey::from_secret(self.0)
    }
}

impl std::fmt::Debug for IdentitySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentitySecret(..)")
    }
}

/// Where the host keeps the identity secret. Implemented by the host app, for example on the
/// iOS keychain or the Android Keystore.
///
/// The calls are synchronous, so Swift and Kotlin implement them without async callbacks.
/// Each is atomic: after `store` returns `Ok`, `load` returns that secret, also after a crash.
pub trait SecretVault: Send + Sync {
    /// The secret the vault holds, or `None` when it holds none.
    ///
    /// # Errors
    ///
    /// [`VaultError`] when the vault can't be read, for example while the device is locked.
    fn load(&self) -> Result<Option<IdentitySecret>, VaultError>;

    /// Store `secret`, replacing any the vault holds.
    ///
    /// # Errors
    ///
    /// [`VaultError`] when the vault can't be written.
    fn store(&self, secret: &IdentitySecret) -> Result<(), VaultError>;

    /// Delete the secret from every copy the host keeps (Switch spec 3.1, "Deleting a key").
    /// Deleting a secret the vault doesn't hold succeeds.
    ///
    /// # Errors
    ///
    /// [`VaultError`] when the vault can't be written.
    fn delete(&self) -> Result<(), VaultError>;
}

/// A failure the host's vault reports. Its text is the host's, and never holds the secret.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[error("vault: {0}")]
pub struct VaultError(pub String);

/// A failure of the identity key.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyError {
    /// The host's vault failed.
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// The vault holds no identity secret.
    #[error("identity key: the vault holds none")]
    Missing,
    /// The vault already holds an identity secret, so a new one isn't stored over it.
    #[error("identity key: the vault already holds one")]
    Occupied,
    /// The secret isn't the identity's: its public key isn't the one expected.
    #[error("identity key: the secret isn't this identity's")]
    Mismatch,
    /// A secret that isn't 32 bytes.
    #[error("identity key: a secret that isn't 32 bytes")]
    Malformed,
    /// The secure random generator failed.
    #[error("identity key: {0}")]
    Crypto(String),
}

/// Why the identity secret leaves the vault (Switch spec 12.8). There is no other reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportReason {
    /// Sealed in a hand-over to the app with this App ID, the new signer (Switch wire 3.12).
    HandOver {
        /// The new signer's App ID.
        to_app: [u8; 16],
    },
    /// Sealed in the signer's own backup on the Homeserver (Switch wire 3.13).
    Backup,
}

/// The identity key, through the host's vault.
///
/// It holds the identity's public key and the vault, never the secret: each use loads the
/// secret, checks that it is still this identity's, uses it and drops it.
#[derive(Clone)]
pub struct IdentityKeyring {
    vault: Arc<dyn SecretVault>,
    public: [u8; 32],
}

impl std::fmt::Debug for IdentityKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityKeyring({})", self.pubky_id())
    }
}

impl IdentityKeyring {
    /// The identity whose secret `vault` holds.
    ///
    /// # Errors
    ///
    /// [`KeyError::Missing`] when the vault holds none, or the vault's error.
    pub fn open(vault: Arc<dyn SecretVault>) -> Result<Self, KeyError> {
        let secret = vault.load()?.ok_or(KeyError::Missing)?;
        let public = secret.key().public();
        Ok(Self { vault, public })
    }

    /// A new identity: a fresh secret from the secure random generator, stored in `vault`,
    /// which must hold none. The secret is read back and checked before this returns, so a
    /// vault that loses writes is found now, not at the first signature.
    ///
    /// # Errors
    ///
    /// [`KeyError::Occupied`] when the vault already holds a secret, [`KeyError::Crypto`] when
    /// the generator fails, [`KeyError::Mismatch`] when the vault returns another secret than
    /// the one stored, or the vault's error.
    pub fn create(vault: Arc<dyn SecretVault>) -> Result<Self, KeyError> {
        if vault.load()?.is_some() {
            return Err(KeyError::Occupied);
        }
        let key = IdentityKey::generate().map_err(|e| KeyError::Crypto(e.to_string()))?;
        let secret = IdentitySecret::from_bytes(key.secret_bytes());
        vault.store(&secret)?;
        let keyring = Self {
            vault,
            public: key.public(),
        };
        keyring.load()?;
        Ok(keyring)
    }

    /// Take the identity secret received in a hand-over, or opened from the signer's backup,
    /// into `vault` (Switch spec 12.8). The secret must be the key of `identity`, and the vault
    /// must hold none, or that same secret already, as after a retry.
    ///
    /// # Errors
    ///
    /// [`KeyError::Mismatch`] when `secret` isn't the key of `identity`, [`KeyError::Occupied`]
    /// when the vault holds another secret, or the vault's error.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the hand-over and restore flows take received keys"
        )
    )]
    pub(crate) fn install(
        vault: Arc<dyn SecretVault>,
        identity: &[u8; 32],
        secret: &IdentitySecret,
    ) -> Result<Self, KeyError> {
        if secret.key().public() != *identity {
            return Err(KeyError::Mismatch);
        }
        match vault.load()? {
            Some(held) if held.as_bytes() == secret.as_bytes() => {}
            Some(_) => return Err(KeyError::Occupied),
            None => vault.store(secret)?,
        }
        let keyring = Self {
            vault,
            public: *identity,
        };
        keyring.load()?;
        Ok(keyring)
    }

    /// The identity's Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// The identity's Pubky ID.
    pub fn pubky_id(&self) -> String {
        pubky_id(&self.public)
    }

    /// The public half of the backup key, which the signer's backup is sealed to, and its kid
    /// (Switch spec 13.3, Switch wire 3.13).
    ///
    /// # Errors
    ///
    /// The errors of a load from the vault.
    pub fn backup_public(&self) -> Result<([u8; 32], [u8; 8]), KeyError> {
        self.with_key(|key| {
            let public = key.backup_public();
            (public, kid(&public))
        })
    }

    /// The secret, checked against this identity.
    fn load(&self) -> Result<IdentitySecret, KeyError> {
        let secret = self.vault.load()?.ok_or(KeyError::Missing)?;
        if secret.key().public() != self.public {
            return Err(KeyError::Mismatch);
        }
        Ok(secret)
    }

    /// Run `use_key` with the identity key, for one signature or derivation over an input this
    /// crate built: an identity-key format of Switch wire 2.3, the approval's companion claim
    /// (Switch wire 3.10), the Switch root and the keys it yields, or the backup key (Switch
    /// wire 1.5). The key is dropped, and zeroized, when `use_key` returns. `use_key` never
    /// reads the secret bytes: that is [`IdentityKeyring::for_export`]'s alone.
    ///
    /// # Errors
    ///
    /// [`KeyError::Missing`] or [`KeyError::Mismatch`] when the vault no longer holds this
    /// identity's secret, or the vault's error.
    pub(crate) fn with_key<T>(
        &self,
        use_key: impl FnOnce(&IdentityKey) -> T,
    ) -> Result<T, KeyError> {
        let secret = self.load()?;
        let key = secret.key();
        Ok(use_key(&key))
    }

    /// Run `seal` with the identity key, to seal its secret for `reason` (Switch spec 12.8):
    /// into a hand-over to the new signer (Switch wire 3.12) or into the signer's backup
    /// (Switch wire 3.13). This is the one place the secret bytes may be read, and only to
    /// seal them at once.
    ///
    /// # Errors
    ///
    /// The errors of [`IdentityKeyring::with_key`].
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the hand-over and backup flows seal the key")
    )]
    pub(crate) fn for_export<T>(
        &self,
        reason: ExportReason,
        seal: impl FnOnce(ExportReason, &IdentityKey) -> T,
    ) -> Result<T, KeyError> {
        self.with_key(|key| seal(reason, key))
    }

    /// Delete the identity secret from the vault (Switch spec 3.1, 12.8): once a hand-over
    /// has taken effect, or after a received one was refused.
    ///
    /// # Errors
    ///
    /// The vault's error.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the hand-over flows delete the key")
    )]
    pub(crate) fn destroy(&self) -> Result<(), KeyError> {
        self.vault.delete()?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A vault in process memory, for tests.
    #[derive(Default)]
    pub(crate) struct MemoryVault {
        secret: Mutex<Option<[u8; 32]>>,
        failing: Mutex<bool>,
    }

    impl MemoryVault {
        pub(crate) fn holding(secret: [u8; 32]) -> Arc<Self> {
            let vault = Self::default();
            *vault.secret.lock().unwrap() = Some(secret);
            Arc::new(vault)
        }

        fn replace(&self, secret: Option<[u8; 32]>) {
            *self.secret.lock().unwrap() = secret;
        }

        fn fail(&self) {
            *self.failing.lock().unwrap() = true;
        }

        fn check(&self) -> Result<(), VaultError> {
            if *self.failing.lock().unwrap() {
                return Err(VaultError("locked".into()));
            }
            Ok(())
        }
    }

    impl SecretVault for MemoryVault {
        fn load(&self) -> Result<Option<IdentitySecret>, VaultError> {
            self.check()?;
            Ok(self.secret.lock().unwrap().map(IdentitySecret::from_bytes))
        }
        fn store(&self, secret: &IdentitySecret) -> Result<(), VaultError> {
            self.check()?;
            self.replace(Some(*secret.as_bytes()));
            Ok(())
        }
        fn delete(&self) -> Result<(), VaultError> {
            self.check()?;
            self.replace(None);
            Ok(())
        }
    }

    /// A vault that drops every write.
    struct ForgetfulVault;

    impl SecretVault for ForgetfulVault {
        fn load(&self) -> Result<Option<IdentitySecret>, VaultError> {
            Ok(None)
        }
        fn store(&self, _: &IdentitySecret) -> Result<(), VaultError> {
            Ok(())
        }
        fn delete(&self) -> Result<(), VaultError> {
            Ok(())
        }
    }

    fn public_of(secret: [u8; 32]) -> [u8; 32] {
        IdentityKey::from_secret(secret).public()
    }

    #[test]
    fn test_key_create_then_open_is_the_same_identity() {
        let vault = Arc::new(MemoryVault::default());
        let created = IdentityKeyring::create(vault.clone()).unwrap();
        let opened = IdentityKeyring::open(vault).unwrap();
        assert_eq!(created.public_key(), opened.public_key());
        assert_eq!(created.pubky_id(), pubky_id(&created.public_key()));
        assert_eq!(
            created.backup_public().unwrap(),
            opened.backup_public().unwrap()
        );
    }

    #[test]
    fn test_key_open_refuses_an_empty_vault() {
        let vault = Arc::new(MemoryVault::default());
        assert_eq!(IdentityKeyring::open(vault).unwrap_err(), KeyError::Missing);
    }

    #[test]
    fn test_key_create_refuses_an_occupied_vault() {
        let vault = MemoryVault::holding([1; 32]);
        assert_eq!(
            IdentityKeyring::create(vault.clone()).unwrap_err(),
            KeyError::Occupied
        );
        // The held secret is untouched.
        assert_eq!(
            IdentityKeyring::open(vault).unwrap().public_key(),
            public_of([1; 32])
        );
    }

    #[test]
    fn test_key_create_finds_a_vault_that_loses_writes() {
        assert_eq!(
            IdentityKeyring::create(Arc::new(ForgetfulVault)).unwrap_err(),
            KeyError::Missing
        );
    }

    #[test]
    fn test_key_every_use_checks_the_vault_still_holds_this_identity() {
        let vault = MemoryVault::holding([1; 32]);
        let keyring = IdentityKeyring::open(vault.clone()).unwrap();
        let public = keyring.with_key(|key| key.public()).unwrap();
        assert_eq!(public, public_of([1; 32]));

        vault.replace(Some([2; 32]));
        assert_eq!(keyring.with_key(|_| ()).unwrap_err(), KeyError::Mismatch);
        vault.replace(None);
        assert_eq!(keyring.with_key(|_| ()).unwrap_err(), KeyError::Missing);
        assert_eq!(keyring.backup_public().unwrap_err(), KeyError::Missing);
    }

    #[test]
    fn test_key_vault_errors_pass_through() {
        let vault = MemoryVault::holding([1; 32]);
        let keyring = IdentityKeyring::open(vault.clone()).unwrap();
        vault.fail();
        let locked = KeyError::Vault(VaultError("locked".into()));
        assert_eq!(keyring.with_key(|_| ()).unwrap_err(), locked);
        assert_eq!(keyring.destroy().unwrap_err(), locked);
        assert_eq!(IdentityKeyring::open(vault).unwrap_err(), locked);
    }

    #[test]
    fn test_key_install_takes_a_received_secret() {
        let vault = Arc::new(MemoryVault::default());
        let secret = IdentitySecret::from_bytes([3; 32]);
        let identity = public_of([3; 32]);
        let keyring = IdentityKeyring::install(vault.clone(), &identity, &secret).unwrap();
        assert_eq!(keyring.public_key(), identity);
        // A retry with the same secret succeeds.
        IdentityKeyring::install(vault, &identity, &secret).unwrap();
    }

    #[test]
    fn test_key_install_refuses_another_identitys_secret() {
        let vault = Arc::new(MemoryVault::default());
        let identity = public_of([3; 32]);
        let other = IdentitySecret::from_bytes([4; 32]);
        assert_eq!(
            IdentityKeyring::install(vault.clone(), &identity, &other).unwrap_err(),
            KeyError::Mismatch
        );
        assert!(vault.load().unwrap().is_none(), "nothing stored");
    }

    #[test]
    fn test_key_install_refuses_an_occupied_vault() {
        let vault = MemoryVault::holding([5; 32]);
        let secret = IdentitySecret::from_bytes([3; 32]);
        assert_eq!(
            IdentityKeyring::install(vault.clone(), &public_of([3; 32]), &secret).unwrap_err(),
            KeyError::Occupied
        );
        assert_eq!(vault.load().unwrap().unwrap().as_bytes(), &[5; 32]);
    }

    #[test]
    fn test_key_destroy_deletes_the_secret() {
        let vault = MemoryVault::holding([1; 32]);
        let keyring = IdentityKeyring::open(vault.clone()).unwrap();
        keyring.destroy().unwrap();
        assert!(vault.load().unwrap().is_none());
        assert_eq!(keyring.with_key(|_| ()).unwrap_err(), KeyError::Missing);
        // Deleting again succeeds.
        keyring.destroy().unwrap();
    }

    #[test]
    fn test_key_export_names_its_reason() {
        let keyring = IdentityKeyring::open(MemoryVault::holding([6; 32])).unwrap();
        for reason in [
            ExportReason::Backup,
            ExportReason::HandOver { to_app: [8; 16] },
        ] {
            let (seen, secret) = keyring
                .for_export(reason, |why, key| (why, key.secret_bytes()))
                .unwrap();
            assert_eq!(seen, reason);
            assert_eq!(secret, [6; 32]);
        }
    }

    #[test]
    fn test_key_secret_never_shows_in_debug() {
        let secret = IdentitySecret::from_bytes([0xab; 32]);
        let text = format!("{secret:?}");
        assert_eq!(text, "IdentitySecret(..)");
        let keyring = IdentityKeyring::open(MemoryVault::holding([0xab; 32])).unwrap();
        let text = format!("{keyring:?}");
        assert!(!text.contains("ab, ") && !text.contains("abab"), "{text}");
        assert!(text.contains(&keyring.pubky_id()), "{text}");
    }

    #[test]
    fn test_key_secret_from_slice_needs_32_bytes() {
        assert_eq!(
            IdentitySecret::from_slice(&[1; 32]).unwrap().as_bytes(),
            &[1; 32]
        );
        for len in [0, 31, 33, 64] {
            assert_eq!(
                IdentitySecret::from_slice(&vec![1; len]).unwrap_err(),
                KeyError::Malformed
            );
        }
    }
}
