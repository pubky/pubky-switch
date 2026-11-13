//! The push delivery queue (Switch spec 9 step 4, Switch wire 8.2): one row per webhook owed,
//! queued with its `notify` entry and sent by a background worker (`service::webhooks`).
//!
//! - **Timed by the database's clock:** every time a row holds (its entry, when it is due,
//!   its lease) is the database's `statement_timestamp()` in milliseconds, read once by each
//!   statement, never an instance's own clock, so instances whose clocks disagree still agree
//!   on when a row is due, leased or past its minute. The service's trusted time is only the
//!   webhook's `ts`.
//! - **Queued** in the append's transaction, one row per handle of each target app's
//!   registration, at most [`PUSH_PER_HOST`] toward one relay host
//!   ([`AccountTxn::queue_pushes`]), so a row exists only if its entry commits, and nothing is
//!   sent during the append.
//! - **Claimed** by one instance at a time ([`Store::claim_pushes`]): under one advisory lock
//!   that every instance's claims take, so they run one at a time, and `FOR UPDATE SKIP
//!   LOCKED`; then a lease of [`PUSH_LEASE_MS`], committed before anything is sent. An account
//!   has at most [`PUSH_PER_ACCOUNT`] rows in flight at once, across instances. An attempt
//!   ends within 10 s of its claim (`service::webhooks`), well inside the lease, so no two
//!   instances send one row at once; an instance that dies mid-attempt leaves the row to be
//!   retried when the lease ends.
//! - **In flight or waiting:** a row's next attempt is more than [`PUSH_RETRY_MS`] away only
//!   in the first 10 s of a lease, since a failure schedules its retry [`PUSH_RETRY_MS`] later
//!   and a lease runs [`PUSH_LEASE_MS`]. So those are the rows that may be in flight, and a row
//!   waiting for its retry counts against no cap.
//! - **Signed under its registration's lock** ([`Store::hold_push_registration`]): the
//!   registration must still name the row's push key and handle, and the key must not be
//!   owed deleting. The row is held `FOR SHARE` while the webhook is signed, so a removal or a
//!   replacement, which owes the key's deletion, waits for the signature; the key store
//!   deletes the key only after that commits. So no key a sweep may be deleting ever signs.
//! - **Gone** once delivered, after its last attempt (3, within 1 minute of its entry), when
//!   its registration goes (the foreign key's cascade: a removal, a recovery in place, an
//!   erasure), at a replacement, and when its handle leaves the list (`store::push`); and,
//!   with or without trusted time, once past its minute ([`Store::drop_stale_pushes`]).
//!
//! A row holds the handle, which it must, and nothing of the message. Its `Debug` shows no
//! handle.

use std::collections::{HashMap, HashSet};

use sqlx::{Executor, Postgres, Row, Transaction};

use pubky_switch_core::{
    net::{UrlUse, check_url},
    sig::SignedDoc,
};

use super::{AccountTxn, Store, StoreError, identity::decode_doc};
use crate::keys::KeyId;

/// The database's clock, in milliseconds: one reading for the whole statement.
macro_rules! db_now_ms {
    () => {
        "(extract(epoch FROM statement_timestamp()) * 1000)::bigint"
    };
}

/// How long after its entry a delivery may be attempted (Switch wire 8.2: 1 minute).
pub const PUSH_WINDOW_MS: i64 = 60_000;

/// How long after a failure the next attempt is due (Switch wire 8.2: 20 s).
pub const PUSH_RETRY_MS: i64 = 20_000;

/// How long a claim leases its row: 30 s, so that for the first 10 s of the lease, all an
/// attempt may take, the row's next attempt is more than [`PUSH_RETRY_MS`] away, which no
/// row waiting for its retry is (the module's doc).
pub const PUSH_LEASE_MS: i64 = 30_000;

/// The most rows of one account in flight at once, across instances: one registration's
/// handles. With `push.concurrency` at its default of 16, one account takes at most half of
/// an instance's attempts, so one whose relay never answers leaves the rest to the others.
pub const PUSH_PER_ACCOUNT: i64 = 8;

/// The most webhooks one entry queues toward one relay host: one registration's handles. An
/// entry then makes at most 8 webhooks, 24 attempts, toward any host, as one app does,
/// however many of the account's apps name that host.
pub const PUSH_PER_HOST: usize = 8;

/// How long a claim waits for the claims' lock, and an attempt for its registration's row
/// lock, before it gives up and fails: short, since each holds a connection while it waits.
pub const HOLD_LOCK_TIMEOUT_MS: u64 = 1_000;

/// The advisory lock every instance's claims take (the module's doc), apart from every other
/// advisory lock of the service, as `store::keying` derives its keys.
fn claims_lock_key() -> i64 {
    let digest = pubky_switch_core::enc::hash(b"pubky-switch/push-claims");
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(bytes)
}

/// A delivery claimed for one attempt.
#[derive(Clone, PartialEq, Eq)]
pub struct QueuedPush {
    /// The row.
    pub id: i64,
    /// The account's Pubky ID.
    pub account: String,
    /// The App ID of the registration.
    pub app_id: [u8; 16],
    /// The push key the registration held when the row was queued.
    pub push_key: KeyId,
    /// The handle.
    pub handle: String,
    /// The attempts made, this one included.
    pub attempts: u32,
}

impl std::fmt::Debug for QueuedPush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedPush")
            .field("id", &self.id)
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

/// A registration held `FOR SHARE` while its webhook is signed: dropping this releases it.
/// It carries what tells whether its account still serves at this service.
pub struct HeldRegistration {
    _tx: Transaction<'static, Postgres>,
    /// The relay URL.
    pub relay_url: String,
    /// The account's newest `identity.json`, as signed.
    pub identity: Option<SignedDoc>,
    /// The account's identity key.
    pub identity_key: [u8; 32],
    /// The account's service key.
    pub service_key: KeyId,
}

impl std::fmt::Debug for HeldRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldRegistration").finish_non_exhaustive()
    }
}

fn queued_push(row: &sqlx::postgres::PgRow) -> Result<QueuedPush, StoreError> {
    let app_id: Vec<u8> = row.try_get("app_id")?;
    let push_key: String = row.try_get("push_key_id")?;
    let attempts: i32 = row.try_get("attempts")?;
    Ok(QueuedPush {
        id: row.try_get("id")?,
        account: row.try_get("account_id")?,
        app_id: <[u8; 16]>::try_from(app_id.as_slice())
            .map_err(|_| StoreError::Corrupt("push_deliveries.app_id"))?,
        push_key: KeyId::parse(&push_key)
            .map_err(|_| StoreError::Corrupt("push_deliveries.push_key_id"))?,
        handle: row.try_get("handle")?,
        attempts: u32::try_from(attempts)
            .map_err(|_| StoreError::Corrupt("push_deliveries.attempts"))?,
    })
}

/// A registration an entry queues webhooks for: its app, push key, relay URL and handles.
type Target = (Vec<u8>, String, String, Vec<String>);

/// The deliveries one entry queues for `registrations`, in their order: one per handle of
/// each, at most [`PUSH_PER_HOST`] toward one relay host, the host as `check_url` spells it.
/// A relay URL that no longer passes its checks gets none: it would be refused when sent.
fn toward_each_host(registrations: Vec<Target>) -> (Vec<Vec<u8>>, Vec<String>, Vec<String>) {
    let mut queued: HashMap<String, usize> = HashMap::new();
    let (mut apps, mut keys, mut handles) = (Vec::new(), Vec::new(), Vec::new());
    for (app, key, relay_url, listed) in registrations {
        let Ok(checked) = check_url(&relay_url, &UrlUse::Relay) else {
            continue;
        };
        let toward = queued.entry(checked.host).or_default();
        let mut seen = HashSet::new();
        for handle in listed {
            if *toward >= PUSH_PER_HOST {
                break;
            }
            if seen.insert(handle.clone()) {
                *toward += 1;
                apps.push(app.clone());
                keys.push(key.clone());
                handles.push(handle);
            }
        }
    }
    (apps, keys, handles)
}

impl Store {
    /// Delete the deliveries that can't be attempted any more, by the database's clock: past
    /// their minute or their last attempt, and not leased. It needs no trusted time, so the
    /// queue stays bounded while the service has none. Returns how many went.
    pub async fn drop_stale_pushes(&self) -> Result<u64, StoreError> {
        Ok(sqlx::query(concat!(
            "DELETE FROM push_deliveries WHERE next_attempt_ms <= ",
            db_now_ms!(),
            " AND (attempts >= 3 OR entry_at_ms + $1 <= ",
            db_now_ms!(),
            ")"
        ))
        .bind(PUSH_WINDOW_MS)
        .execute(self.pool())
        .await
        .map_err(StoreError::from_db)?
        .rows_affected())
    }

    /// Claim at most `limit` due deliveries, oldest first, each leased for
    /// [`PUSH_LEASE_MS`] with its attempt counted: within its minute, under 3 attempts, not
    /// claimed by another instance, and with at most [`PUSH_PER_ACCOUNT`] of its account's
    /// rows in flight, those already leased by any instance included. Claims of every
    /// instance take turns (the module's doc). The claim commits before anything is sent.
    pub async fn claim_pushes(&self, limit: usize) -> Result<Vec<QueuedPush>, StoreError> {
        let mut tx = self.pool().begin().await.map_err(StoreError::from_db)?;
        // Statement 1: the claims' lock, in a READ COMMITTED transaction whatever the pool's
        // default, so the claim below, a statement of its own, sees every claim committed
        // while it waited. The numbers are formatted, as `SET` takes no bind parameters.
        tx.execute(
            format!(
                "SET TRANSACTION ISOLATION LEVEL READ COMMITTED; \
                 SET LOCAL lock_timeout = {HOLD_LOCK_TIMEOUT_MS}; \
                 SELECT pg_advisory_xact_lock({})",
                claims_lock_key()
            )
            .as_str(),
        )
        .await
        .map_err(StoreError::from_db)?;
        let rows = sqlx::query(concat!(
            "UPDATE push_deliveries SET attempts = attempts + 1, next_attempt_ms = ",
            db_now_ms!(),
            " + $2 WHERE id IN (SELECT id FROM push_deliveries WHERE id IN (\
             SELECT due.id FROM (SELECT d.id, d.account_id, row_number() OVER \
             (PARTITION BY d.account_id ORDER BY d.next_attempt_ms, d.id) AS n \
             FROM push_deliveries d WHERE d.next_attempt_ms <= ",
            db_now_ms!(),
            " AND d.attempts < 3 AND d.entry_at_ms + $3 > ",
            db_now_ms!(),
            ") due WHERE due.n + (SELECT count(*) FROM push_deliveries l \
             WHERE l.account_id = due.account_id AND l.next_attempt_ms > ",
            db_now_ms!(),
            " + $4) <= $5) ORDER BY next_attempt_ms, id LIMIT $1 FOR UPDATE SKIP LOCKED) \
             RETURNING id, account_id, app_id, push_key_id, handle, attempts"
        ))
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .bind(PUSH_LEASE_MS)
        .bind(PUSH_WINDOW_MS)
        .bind(PUSH_RETRY_MS)
        .bind(PUSH_PER_ACCOUNT)
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::from_db)?;
        tx.commit().await.map_err(StoreError::from_db)?;
        // A row that doesn't read is skipped, its lease left to run out, and goes once its
        // attempts or its minute are spent ([`Store::drop_stale_pushes`]): it holds up no
        // other.
        Ok(rows
            .iter()
            .filter_map(|row| {
                queued_push(row)
                    .inspect_err(|error| tracing::warn!(%error, "push deliveries: a row"))
                    .ok()
            })
            .collect())
    }

    /// `push`'s registration, held `FOR SHARE` until the result is dropped, if it still names
    /// the row's push key and handle and the key isn't owed deleting, with its account's
    /// newest `identity.json` and keys; `None` otherwise, when the delivery isn't sent. Waits
    /// at most [`HOLD_LOCK_TIMEOUT_MS`] for a request that holds it, so an attempt doesn't
    /// sit on a connection behind a request. The account's row isn't locked: its requests
    /// don't wait for a webhook.
    pub async fn hold_push_registration(
        &self,
        push: &QueuedPush,
    ) -> Result<Option<HeldRegistration>, StoreError> {
        let mut tx = self.pool().begin().await.map_err(StoreError::from_db)?;
        sqlx::query(&format!("SET LOCAL lock_timeout = {HOLD_LOCK_TIMEOUT_MS}"))
            .execute(&mut *tx)
            .await
            .map_err(StoreError::from_db)?;
        let row = sqlx::query(
            "SELECT r.relay_url, a.identity_doc, a.identity_key, a.service_key \
             FROM push_registrations r JOIN accounts a ON a.id = r.account_id \
             WHERE r.account_id = $1 \
             AND r.app_id = $2 AND r.push_key_id = $3 AND $4 = ANY(r.handles) \
             AND NOT EXISTS (SELECT 1 FROM erased_keys e WHERE e.key_id = r.push_key_id) \
             FOR SHARE OF r",
        )
        .bind(&push.account)
        .bind(push.app_id.as_slice())
        .bind(push.push_key.as_str())
        .bind(&push.handle)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::from_db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let identity: Option<Vec<u8>> = row.try_get("identity_doc")?;
        let identity_key: Vec<u8> = row.try_get("identity_key")?;
        let service_key: String = row.try_get("service_key")?;
        Ok(Some(HeldRegistration {
            relay_url: row.try_get("relay_url")?,
            identity: identity
                .map(|doc| decode_doc(&doc, "identity_doc"))
                .transpose()?,
            identity_key: identity_key
                .try_into()
                .map_err(|_| StoreError::Corrupt("accounts.identity_key"))?,
            service_key: KeyId::parse(&service_key)
                .map_err(|_| StoreError::Corrupt("accounts.service_key"))?,
            _tx: tx,
        }))
    }

    /// The delivery `id` is done: delivered, failed for the last time, or not to be sent.
    pub async fn finish_push(&self, id: i64) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM push_deliveries WHERE id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// The delivery `id` failed: retried [`PUSH_RETRY_MS`] later by the database's clock,
    /// unless that was its third attempt or the retry would fall past its minute, when it
    /// goes. Returns whether it is retried.
    pub async fn fail_push(&self, id: i64) -> Result<bool, StoreError> {
        let retried = sqlx::query(concat!(
            "UPDATE push_deliveries SET next_attempt_ms = ",
            db_now_ms!(),
            " + $2 WHERE id = $1 AND attempts < 3 AND entry_at_ms + $3 > ",
            db_now_ms!(),
            " + $2"
        ))
        .bind(id)
        .bind(PUSH_RETRY_MS)
        .bind(PUSH_WINDOW_MS)
        .execute(self.pool())
        .await
        .map_err(StoreError::from_db)?
        .rows_affected()
            > 0;
        if !retried {
            self.finish_push(id).await?;
        }
        Ok(retried)
    }
}

impl AccountTxn {
    /// Queue a webhook to each handle of the registration of each of `targets`, an entry's
    /// target apps, for a `notify` entry (Switch wire 8.2), at most [`PUSH_PER_HOST`] toward
    /// one relay host, due at once by the database's clock. Returns how many were queued.
    pub async fn queue_pushes(&mut self, targets: &[[u8; 16]]) -> Result<u64, StoreError> {
        let id = self.head().id.clone();
        let targets: Vec<Vec<u8>> = targets.iter().map(|app| app.to_vec()).collect();
        let registrations: Vec<Target> = sqlx::query_as(
            "SELECT app_id, push_key_id, relay_url, handles FROM push_registrations \
             WHERE account_id = $1 AND app_id = ANY($2) ORDER BY app_id",
        )
        .bind(&id)
        .bind(&targets)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let (apps, keys, handles) = toward_each_host(registrations);
        if apps.is_empty() {
            return Ok(0);
        }
        Ok(sqlx::query(concat!(
            "INSERT INTO push_deliveries (account_id, app_id, push_key_id, handle, entry_at_ms, \
             next_attempt_ms) SELECT $1, t.app_id, t.push_key_id, t.handle, ",
            db_now_ms!(),
            ", ",
            db_now_ms!(),
            " FROM unnest($2::bytea[], $3::text[], $4::text[]) AS t(app_id, push_key_id, handle)"
        ))
        .bind(&id)
        .bind(&apps)
        .bind(&keys)
        .bind(&handles)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?
        .rows_affected())
    }

    /// Drop the queued deliveries of `app` whose handle `keep` doesn't hold, all of them when
    /// `keep` is empty: at a replacement and at a new list of handles.
    pub(super) async fn drop_pushes_except(
        &mut self,
        app: &[u8; 16],
        keep: &[String],
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "DELETE FROM push_deliveries WHERE account_id = $1 AND app_id = $2 \
             AND NOT (handle = ANY($3))",
        )
        .bind(id)
        .bind(app.as_slice())
        .bind(keep)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }
}
