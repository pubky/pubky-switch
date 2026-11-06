//! The account and its transaction.
//!
//! An [`AccountTxn`] is one request's view of one account: it holds the account's lock from
//! [`Store::begin`](super::Store::begin) until it commits or is dropped. It hands out
//! `seq`s, moves the chain head and stamps the service time, and writes them back when it
//! commits. Dropping it without committing, or a process that dies before the commit,
//! rolls everything back.

use sqlx::{PgConnection, PgPool, Postgres, Row, Transaction};

use super::{StoreError, from_db, to_db};
use crate::keys::{KeyId, KeyStore, KeyStoreError, Mark, MarkCheck, check_mark};

/// A new account, at enrollment (Switch wire 7.4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewAccount {
    /// The identity's Pubky ID.
    pub id: String,
    /// The identity's Ed25519 public key.
    pub identity_key: [u8; 32],
    /// The generation the account starts at.
    pub generation: u64,
    /// The generation's service key.
    pub service_key: KeyId,
    /// The service time of the enrollment.
    pub created_at_ms: u64,
}

/// An account's position: its generation and key, the last `seq` given out, the chain head
/// and the stamped service time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountHead {
    /// The identity's Pubky ID.
    pub id: String,
    /// The identity's Ed25519 public key.
    pub identity_key: [u8; 32],
    /// The generation the account serves.
    pub generation: u64,
    /// The generation's service key.
    pub service_key: KeyId,
    /// The last `seq` given out, shared by inbox entries and chain items; 0 before any.
    pub last_seq: u64,
    /// The newest chain item's `seq` and the chain hash there; `None` before the first.
    pub chain: Option<(u64, [u8; 32])>,
    /// The last service time the account stamped.
    pub stamped_time_ms: u64,
    /// When the account was created.
    pub created_at_ms: u64,
}

impl AccountHead {
    /// The chain head as a mark, `None` before the first chain item.
    pub fn head_mark(&self) -> Option<Mark> {
        self.chain.map(|(seq, chain_hash)| Mark {
            generation: self.generation,
            seq,
            chain_hash,
        })
    }
}

/// A committed request: what it committed is durable, so an answer carrying a `seq`, a
/// proof or a head may go out. Only [`AccountTxn::commit`] and
/// [`AccountTxn::commit_marked`] make one.
#[derive(Debug)]
pub struct Committed {
    head: AccountHead,
}

impl Committed {
    /// The account's position as committed.
    pub fn head(&self) -> &AccountHead {
        &self.head
    }
}

/// Why a commit gave no [`Committed`].
#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    /// Nothing was committed.
    #[error("not committed: {0}")]
    NotCommitted(StoreError),
    /// The state is committed, but the key's mark couldn't move to its head, so the head
    /// mustn't go out. The answer is `503 unavailable`; a retry finds the committed state.
    #[error("committed, but the key's mark didn't move: {0}")]
    MarkNotMoved(KeyStoreError),
}

/// One request's transaction on one account, holding the account's lock.
pub struct AccountTxn {
    tx: Transaction<'static, Postgres>,
    head: AccountHead,
    loaded: AccountHead,
}

impl std::fmt::Debug for AccountTxn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountTxn")
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

/// Insert an account unless one exists.
pub(super) async fn create(pool: &PgPool, account: &NewAccount) -> Result<bool, StoreError> {
    let created = sqlx::query(
        "INSERT INTO accounts (id, identity_key, generation, service_key, created_at_ms, \
         stamped_time_ms) VALUES ($1, $2, $3, $4, $5, $5) ON CONFLICT (id) DO NOTHING",
    )
    .bind(&account.id)
    .bind(account.identity_key.as_slice())
    .bind(to_db(account.generation, "generation")?)
    .bind(account.service_key.as_str())
    .bind(to_db(account.created_at_ms, "created_at_ms")?)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(created == 1)
}

impl AccountTxn {
    /// Lock account `id` in `tx` and read its position.
    pub(super) async fn lock(
        mut tx: Transaction<'static, Postgres>,
        id: &str,
    ) -> Result<Option<Self>, StoreError> {
        let row = sqlx::query(
            "SELECT id, identity_key, generation, service_key, last_seq, chain_seq, chain_hash, \
             stamped_time_ms, created_at_ms FROM accounts WHERE id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::from_db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let identity_key: Vec<u8> = row.try_get("identity_key")?;
        let service_key: String = row.try_get("service_key")?;
        let chain_seq: Option<i64> = row.try_get("chain_seq")?;
        let chain_hash: Option<Vec<u8>> = row.try_get("chain_hash")?;
        let chain = match (chain_seq, chain_hash) {
            (Some(seq), Some(hash)) => Some((
                from_db(seq, "chain_seq")?,
                <[u8; 32]>::try_from(hash.as_slice())
                    .map_err(|_| StoreError::Corrupt("chain_hash"))?,
            )),
            (None, None) => None,
            _ => return Err(StoreError::Corrupt("chain head")),
        };
        let head = AccountHead {
            id: row.try_get("id")?,
            identity_key: <[u8; 32]>::try_from(identity_key.as_slice())
                .map_err(|_| StoreError::Corrupt("identity_key"))?,
            generation: from_db(row.try_get("generation")?, "generation")?,
            service_key: KeyId::parse(&service_key)
                .map_err(|_| StoreError::Corrupt("service_key"))?,
            last_seq: from_db(row.try_get("last_seq")?, "last_seq")?,
            chain,
            stamped_time_ms: from_db(row.try_get("stamped_time_ms")?, "stamped_time_ms")?,
            created_at_ms: from_db(row.try_get("created_at_ms")?, "created_at_ms")?,
        };
        Ok(Some(Self {
            tx,
            loaded: head.clone(),
            head,
        }))
    }

    /// The account's position, with this request's changes.
    pub fn head(&self) -> &AccountHead {
        &self.head
    }

    /// Stamp the service time for this request: the time base, or the last time the account
    /// stamped if the time base is earlier, so service time never goes back for an
    /// identity (Switch spec 10.1, Switch wire 7.3 step 3). Kept only if the request commits.
    pub fn stamp(&mut self, base_ms: u64) -> u64 {
        self.head.stamped_time_ms = self.head.stamped_time_ms.max(base_ms);
        self.head.stamped_time_ms
    }

    /// Give out the next `seq` (Switch spec 6.3).
    pub fn next_seq(&mut self) -> Result<u64, StoreError> {
        let seq = self
            .head
            .last_seq
            .checked_add(1)
            .filter(|seq| i64::try_from(*seq).is_ok())
            .ok_or(StoreError::OutOfRange("seq"))?;
        self.head.last_seq = seq;
        Ok(seq)
    }

    /// Move the chain head to the chain item at `seq`, whose chain hash is `chain_hash`.
    /// `seq` must have been given out by this request, after the current chain head.
    pub fn set_chain_head(&mut self, seq: u64, chain_hash: [u8; 32]) -> Result<(), StoreError> {
        let after_head = self.head.chain.is_none_or(|(head, _)| seq > head);
        if !after_head || seq <= self.loaded.last_seq || seq > self.head.last_seq {
            return Err(StoreError::OutOfRange("chain head seq"));
        }
        self.head.chain = Some((seq, chain_hash));
        Ok(())
    }

    /// Compare the account's chain head with its service key's mark. A state behind the
    /// mark, or beside it, is lost committed state: the account fails stop with
    /// `503 unavailable` until the signer starts a new generation (Switch spec 6.5,
    /// Switch wire 7.3 step 10). Only a serving account is held to its mark.
    pub async fn mark_check(&self, keys: &dyn KeyStore) -> Result<MarkCheck, KeyStoreError> {
        let mark = keys.mark(&self.head.service_key).await?;
        Ok(match (self.loaded.head_mark(), mark) {
            (Some(head), mark) => check_mark(mark.as_ref(), &head),
            (None, None) => MarkCheck::Unmarked,
            // The key signed a head, and the state holds no chain at all.
            (None, Some(mark)) if mark.generation == self.loaded.generation => MarkCheck::Behind,
            (None, Some(_)) => MarkCheck::OtherGeneration,
        })
    }

    /// The transaction's connection, for the queries of the account's other state. Every
    /// query on it is part of this request, and commits or rolls back with it.
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    /// Commit the request. Once this returns, what it committed is durable, and the
    /// answer may go out. For a staged account, or a request whose answer carries no head;
    /// a serving account's answer with a head goes through [`AccountTxn::commit_marked`].
    pub async fn commit(mut self) -> Result<Committed, StoreError> {
        if self.head != self.loaded {
            let chain_seq = self
                .head
                .chain
                .map(|(seq, _)| to_db(seq, "chain_seq"))
                .transpose()?;
            let chain_hash = self.head.chain.map(|(_, hash)| hash.to_vec());
            let updated = sqlx::query(
                "UPDATE accounts SET last_seq = $2, chain_seq = $3, chain_hash = $4, \
                 stamped_time_ms = $5 WHERE id = $1",
            )
            .bind(&self.head.id)
            .bind(to_db(self.head.last_seq, "last_seq")?)
            .bind(chain_seq)
            .bind(chain_hash)
            .bind(to_db(self.head.stamped_time_ms, "stamped_time_ms")?)
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?
            .rows_affected();
            if updated != 1 {
                return Err(StoreError::Corrupt("account row vanished under its lock"));
            }
        }
        self.tx.commit().await.map_err(StoreError::from_db)?;
        Ok(Committed { head: self.head })
    }

    /// Commit the request, then move the service key's mark to the committed chain head,
    /// so the key never signs a state behind it. Only then may the answer, with its signed
    /// head, go out (Switch wire 7.3 step 10).
    ///
    /// The order matters. A mark moved before the commit, by a commit that then failed,
    /// would stop the account for good; a state committed before its mark moved is only
    /// ahead of the mark, which is safe, and the next answer moves it.
    pub async fn commit_marked(self, keys: &dyn KeyStore) -> Result<Committed, CommitError> {
        let committed = self.commit().await.map_err(CommitError::NotCommitted)?;
        if let Some(head) = committed.head.head_mark() {
            keys.advance_mark(&committed.head.service_key, head)
                .await
                .map_err(CommitError::MarkNotMoved)?;
        }
        Ok(committed)
    }
}
