//! The account and its transaction.
//!
//! An [`AccountTxn`] is one request's view of one account: it holds the account's lock from
//! [`Store::begin`](super::Store::begin) until it commits or is dropped. It hands out
//! `seq`s, moves the chain head and stamps the service time, and writes them back when it
//! commits. Dropping it without committing, or a process that dies before the commit,
//! rolls everything back.

use sqlx::{PgConnection, PgPool, Postgres, Row, Transaction};

use super::{StoreError, from_db, to_db};
use pubky_switch_core::sig::SignedDoc;

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
    /// The limits the enrollment announces, kept for every later enrollment.
    pub limits: pubky_switch_core::records::Limits,
    /// The `identity.json` the enrollment carried, for a new provider (Switch wire 3.7).
    pub identity_doc: Option<SignedDoc>,
    /// The App IDs the enrollment's `revoked_apps` names, kept for good from the start
    /// (Switch wire 3.7).
    pub revoked_apps: Vec<[u8; 16]>,
    /// The document hash of the enrollment that creates the account, whose answer the
    /// account keeps (Switch wire 3.7).
    pub enrollment_hash: [u8; 32],
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
    /// The chain tip the next chain item links to: the newest item's `seq` and chain hash,
    /// or `seq` 0 and the zero hash before any (Switch wire 6.6).
    pub fn chain_tip(&self) -> pubky_switch_core::chain::ChainTip {
        let (seq, chain_hash) = self
            .chain
            .unwrap_or((0, pubky_switch_core::chain::ZERO_HASH));
        pubky_switch_core::chain::ChainTip {
            generation: self.generation,
            seq,
            chain_hash,
        }
    }

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

/// Where a request's endpoint started, so a refusal can undo what it wrote
/// ([`AccountTxn::rollback_to`]).
#[derive(Debug)]
pub struct Savepoint {
    head: AccountHead,
    changed: bool,
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
    changed: bool,
    last_seen: Option<([u8; 16], u64)>,
    /// Sender identities that hit an append limit in this request (Switch wire 9.4 Flags).
    flag_hits: Vec<[u8; 32]>,
    /// The flagged senders kept (`max_flags`), for the hits above.
    max_flags: u64,
    /// A transaction on the reader pool, begun before the lock, to export this one's
    /// snapshot to ([`AccountTxn::snapshot_read`]).
    pub(super) reader: Option<Transaction<'static, Postgres>>,
    /// The reader, once this transaction's snapshot is exported to it.
    pub(super) snapshot: Option<super::SnapshotRead>,
    /// For tests: where that read waits before it reads.
    #[cfg(any(test, feature = "test-util"))]
    pub(super) snapshot_pause: Option<super::testing::SnapshotPause>,
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
    let identity_doc = account
        .identity_doc
        .as_ref()
        .map(super::identity::encode_doc)
        .transpose()?;
    let mut tx = pool.begin().await.map_err(StoreError::from_db)?;
    let created = sqlx::query(
        "INSERT INTO accounts (id, identity_key, generation, service_key, created_at_ms, \
         stamped_time_ms, announced_limits, identity_doc) VALUES ($1, $2, $3, $4, $5, $5, $6, $7) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&account.id)
    .bind(account.identity_key.as_slice())
    .bind(to_db(account.generation, "generation")?)
    .bind(account.service_key.as_str())
    .bind(to_db(account.created_at_ms, "created_at_ms")?)
    .bind(
        serde_json::to_vec(&account.limits)
            .map_err(|_| StoreError::Corrupt("the announced limits don't encode"))?,
    )
    .bind(identity_doc)
    .execute(&mut *tx)
    .await
    .map_err(StoreError::from_db)?
    .rows_affected();
    if created != 1 {
        return Ok(false);
    }
    for app_id in &account.revoked_apps {
        sqlx::query(
            "INSERT INTO kept_app_ids (account_id, app_id, reason, at_ms) \
             VALUES ($1, $2, 'enrolled', $3) ON CONFLICT DO NOTHING",
        )
        .bind(&account.id)
        .bind(app_id.as_slice())
        .bind(to_db(account.created_at_ms, "created_at_ms")?)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::from_db)?;
    }
    // The apps the enrollment's identity.json lists are listed for the first time here
    // (Switch wire 7.4.12 keys_through).
    if let Some(doc) = &account.identity_doc {
        let doc = pubky_switch_core::records::IdentityDoc::verify(doc, &account.identity_key)
            .map_err(|_| StoreError::Corrupt("the enrollment's identity.json"))?;
        let listed = super::apps::newly_listed(None, &doc);
        super::apps::note_listings(&mut tx, &account.id, &listed, doc.data_epoch()).await?;
    }
    // The first enrollment's answer: an account keeps far fewer than any limit allows.
    super::enrollments::keep(
        &mut tx,
        &account.id,
        &account.enrollment_hash,
        &account.service_key,
        account.created_at_ms,
        u64::MAX >> 1,
        true,
        false,
    )
    .await?;
    tx.commit().await.map_err(StoreError::from_db)?;
    Ok(true)
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
            changed: false,
            last_seen: None,
            flag_hits: Vec::new(),
            max_flags: 0,
            reader: None,
            snapshot: None,
            #[cfg(any(test, feature = "test-util"))]
            snapshot_pause: None,
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

    /// Note that this request changes the account, so its commit wakes the requests
    /// waiting on it ([`crate::changes`]). A request that gives out a `seq` or moves the
    /// chain head counts as a change without this; one that only stamps the time doesn't.
    pub fn note_change(&mut self) {
        self.changed = true;
    }

    /// Note an own app's authenticated request at `at_ms` (Switch wire 7.3 step 6). It is
    /// written with the commit, also when the endpoint is refused and rolled back.
    pub fn note_last_seen(&mut self, app_id: [u8; 16], at_ms: u64) {
        self.last_seen = Some((app_id, at_ms));
    }

    /// Note a hit of `sender` against an append limit (Switch wire 9.4 Flags). It is written
    /// with the commit, also when the append is refused and rolled back, as the refusal is
    /// what it counts.
    pub fn note_flag_hit(&mut self, sender: [u8; 32], max_flags: u64) {
        self.flag_hits.push(sender);
        self.max_flags = max_flags;
    }

    /// Mark the start of the request's endpoint. Everything it writes after this, its
    /// `seq`s and chain head included, can be undone with [`AccountTxn::rollback_to`],
    /// while the stamped time stays.
    pub async fn savepoint(&mut self) -> Result<Savepoint, StoreError> {
        sqlx::query("SAVEPOINT endpoint")
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        Ok(Savepoint {
            head: self.head.clone(),
            changed: self.changed,
        })
    }

    /// Undo everything written since `savepoint`, keeping the time this request stamped:
    /// a refused request commits its stamp and nothing else (Switch wire 7.3 steps 3 and
    /// 10). If this fails the transaction must not be committed.
    pub async fn rollback_to(&mut self, savepoint: Savepoint) -> Result<(), StoreError> {
        sqlx::query("ROLLBACK TO SAVEPOINT endpoint")
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        let stamped_time_ms = self.head.stamped_time_ms;
        self.head = AccountHead {
            stamped_time_ms,
            ..savepoint.head
        };
        self.changed = savepoint.changed;
        Ok(())
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
            // A new seq or chain head is a change waiting readers care about; a stamped
            // time alone, which every request may move, isn't.
            if self.head.last_seq != self.loaded.last_seq || self.head.chain != self.loaded.chain {
                self.changed = true;
            }
        }
        if let Some((app_id, at_ms)) = self.last_seen {
            sqlx::query("UPDATE apps SET last_seen_ms = $3 WHERE account_id = $1 AND app_id = $2")
                .bind(&self.head.id)
                .bind(app_id.as_slice())
                .bind(to_db(at_ms, "last_seen_ms")?)
                .execute(&mut *self.tx)
                .await
                .map_err(StoreError::from_db)?;
        }
        let flag_hits = std::mem::take(&mut self.flag_hits);
        for sender in &flag_hits {
            sqlx::query(
                "INSERT INTO sender_flags (account_id, pubky, hits, last_hit_ms) \
                 VALUES ($1, $2, 1, $3) ON CONFLICT (account_id, pubky) DO UPDATE \
                 SET hits = sender_flags.hits + 1, last_hit_ms = $3",
            )
            .bind(&self.head.id)
            .bind(sender.as_slice())
            .bind(to_db(self.head.stamped_time_ms, "last_hit_ms")?)
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        }
        // At most `max_flags` flagged senders, the least frequent dropping, and of those
        // equally frequent the one hit longest ago (Switch wire 9.1).
        if !flag_hits.is_empty() {
            sqlx::query(
                "DELETE FROM sender_flags WHERE account_id = $1 AND pubky IN ( \
                     SELECT pubky FROM sender_flags WHERE account_id = $1 \
                     ORDER BY hits DESC, last_hit_ms DESC, pubky OFFSET $2)",
            )
            .bind(&self.head.id)
            .bind(to_db(self.max_flags, "max_flags")?)
            .execute(&mut *self.tx)
            .await
            .map_err(StoreError::from_db)?;
        }
        if self.changed {
            // Sent with the commit, and only if it commits.
            sqlx::query("SELECT pg_notify($1, $2)")
                .bind(crate::changes::CHANNEL)
                .bind(&self.head.id)
                .execute(&mut *self.tx)
                .await
                .map_err(StoreError::from_db)?;
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
