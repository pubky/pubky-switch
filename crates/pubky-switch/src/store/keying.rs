//! The keying lock: what makes "the account still has this key" and "signed with it" one
//! step, so no answer is signed with an account's key once its erasure, or a change of its
//! key, has committed (Switch wire 7.4.16: the erasure's answer "is the last answer that key
//! signs").
//!
//! Each account has a Postgres advisory lock, held in the database, so it also keeps two
//! processes safe during an overlap in a restart or failover:
//! - a [keyed section](Store::while_keyed) takes it shared, reads the account's key in a
//!   statement of its own, and signs while it holds the lock;
//! - an erasure or a change of the account's key takes it exclusive
//!   ([`AccountTxn::exclude_signers`]) in its own transaction, before it signs its own answer,
//!   and holds it until it commits.
//!
//! So every keyed signature is made either before the exclusive holder takes the lock, while
//! the account still names the key, or after it commits, when it doesn't and nothing is
//! signed. An answer signed before may still be delivered after, as on any slow network;
//! none is signed after.
//!
//! **Lock order.** The account's row lock (`FOR UPDATE`, [`Store::begin`]) first, then the
//! exclusive keying lock: an erasure and a key change take them in that order. A keyed
//! section takes only the shared keying lock and plain reads, never a row lock, and waits on
//! nothing else; between its key read and the end of its signing it makes no await. So no
//! wait cycle exists. A keyed section that fails, by the pool, the connection or the
//! commit, signs nothing that goes out: its caller answers with the operator's `503`.
//!
//! **The two statements.** The lock and the key read must be separate statements, in a
//! transaction that is READ COMMITTED whatever the pool's default: a statement reads the
//! snapshot taken when it starts, so a read in the statement that waited for the lock would
//! still see the row from before the erasure committed.

use sqlx::Executor;

use super::{AccountTxn, Store, StoreError};
use crate::keys::KeyId;

/// The advisory lock key of `account`'s keying lock: 64 bits of `hash` over a
/// domain-separated text, so it meets no other advisory lock of the service, nor the one
/// sqlx takes for migrations. Two accounts whose keys collide only make one's erasure wait
/// for the other's short keyed sections.
pub fn keying_lock_key(account: &str) -> i64 {
    let digest = pubky_switch_core::enc::hash(format!("pubky-switch/keying/{account}").as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(bytes)
}

/// What a keyed section found.
#[derive(Debug)]
pub enum Keyed<T> {
    /// The account names the key: what the section signed.
    Signed(T),
    /// The account is gone: erased, or never hosted.
    Gone,
    /// The account names another key: enrolled again, or its key changed.
    Rekeyed,
}

impl Store {
    /// Run `sign` only while `account` names `key` as its service key, or, with
    /// `pending`, as its pending key of the next generation (an enrollment's answer), under
    /// the account's shared keying lock (the module's doc). `sign` runs synchronously,
    /// between the key read and the commit, and its result is returned only once the
    /// section committed.
    ///
    /// # Errors
    ///
    /// A store failure, the lock's wait past `lock_timeout_ms` included: the caller signs
    /// nothing with the account's key then.
    pub async fn while_keyed<T>(
        &self,
        account: &str,
        key: &KeyId,
        pending: bool,
        sign: impl FnOnce() -> T,
    ) -> Result<Keyed<T>, StoreError> {
        let mut tx = self.pool().begin().await.map_err(StoreError::from_db)?;
        // Statement 1: the shared lock, in a READ COMMITTED transaction whatever the pool's
        // default; the numbers are formatted, as `SET` takes no bind parameters.
        tx.execute(
            format!(
                "SET TRANSACTION ISOLATION LEVEL READ COMMITTED; \
                 SET LOCAL lock_timeout = {}; \
                 SELECT pg_advisory_xact_lock_shared({})",
                self.lock_timeout_ms,
                keying_lock_key(account)
            )
            .as_str(),
        )
        .await
        .map_err(StoreError::from_db)?;
        // Statement 2, a new one: its snapshot is taken now that the lock is held, so it sees
        // an erasure or a key change that committed while the lock was waited for.
        let row: Option<(String, Option<String>)> =
            sqlx::query_as("SELECT service_key, pending_key FROM accounts WHERE id = $1")
                .bind(account)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::from_db)?;
        let keyed = match row {
            None => Keyed::Gone,
            Some((service_key, pending_key))
                if service_key == key.as_str()
                    || (pending && pending_key.as_deref() == Some(key.as_str())) =>
            {
                Keyed::Signed(sign())
            }
            Some(_) => Keyed::Rekeyed,
        };
        tx.commit().await.map_err(StoreError::from_db)?;
        Ok(keyed)
    }
}

impl AccountTxn {
    /// Take the account's keying lock exclusive, until this transaction ends: no keyed
    /// section signs with the account's key meanwhile, and once it commits, none signs with
    /// a key it no longer names (the module's doc). An erasure takes it before it signs its
    /// answer, the last its key signs; a change of the account's key takes it before it
    /// switches the key and before it signs anything with the outgoing one. It comes after
    /// the account's row lock, which this transaction holds.
    ///
    /// # Errors
    ///
    /// A store failure, the lock's wait past `lock_timeout_ms` included.
    pub async fn exclude_signers(&mut self) -> Result<(), StoreError> {
        let key = keying_lock_key(&self.head().id);
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(key)
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        Ok(())
    }
}
