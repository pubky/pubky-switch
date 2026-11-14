//! Every account's chain head, read without the account's lock, for an operator's check of
//! the heads against their keys' marks after a restore (Switch spec 6.5).
//!
//! These reads run on one plain connection whose session is read only, so they need no
//! durability check, no migration and no instance lock, and run beside a running service or
//! against a hot standby. They change nothing.

use std::str::FromStr;

use sqlx::{Connection, Executor, PgConnection, Row, postgres::PgConnectOptions};

use super::{StoreError, from_db, to_db};
use crate::keys::KeyId;

/// An account's head as the database holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHead {
    /// The identity's Pubky ID.
    pub id: String,
    /// The identity's Ed25519 public key.
    pub identity_key: [u8; 32],
    /// The generation the account serves.
    pub generation: u64,
    /// The generation's service key.
    pub service_key: KeyId,
    /// The next generation's pending key, once an enrollment answered one (Switch wire
    /// 3.3).
    pub pending_key: Option<KeyId>,
    /// The newest chain item's `seq` and the chain hash there; `None` before the first.
    pub chain: Option<(u64, [u8; 32])>,
    /// When the account was created, in service time.
    pub created_at_ms: u64,
    /// The newest `identity.json` the account holds, in the carrying form the store keeps,
    /// not decoded: one that doesn't decode is the caller's to judge.
    pub identity_doc: Option<Vec<u8>>,
}

/// Open one connection to `url` with a read-only session: every transaction on it is read
/// only, so it works against a hot standby and writes nothing.
pub async fn open_read_only(url: &str) -> Result<PgConnection, StoreError> {
    let options = PgConnectOptions::from_str(url)?;
    open_read_only_with(&options).await
}

/// Open one connection to `options` with a read-only session ([`open_read_only`]).
pub async fn open_read_only_with(options: &PgConnectOptions) -> Result<PgConnection, StoreError> {
    let mut conn = PgConnection::connect_with(options).await?;
    if let Err(error) = conn
        .execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
        .await
    {
        let _ = conn.close().await;
        return Err(StoreError::from_db(error));
    }
    Ok(conn)
}

/// Up to `limit` accounts after `after` in the order of their IDs, each with its service
/// key's ID: one page of every account.
pub async fn service_keys_after(
    conn: &mut PgConnection,
    after: Option<&str>,
    limit: u32,
) -> Result<Vec<(String, KeyId)>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, service_key FROM accounts WHERE $1::TEXT IS NULL OR id > $1 \
         ORDER BY id LIMIT $2",
    )
    .bind(after)
    .bind(to_db(u64::from(limit), "limit")?)
    .fetch_all(conn)
    .await
    .map_err(StoreError::from_db)?;
    rows.iter()
        .map(|row| {
            let key: String = row.try_get("service_key")?;
            Ok((
                row.try_get("id")?,
                KeyId::parse(&key).map_err(|_| StoreError::Corrupt("service_key"))?,
            ))
        })
        .collect()
}

/// Whether anything in the database names key `id` now: an account's service key or its
/// pending key, or a deletion owed in `erased_keys`, by an erasure, a retirement or a push
/// key's release still under way (Switch wire 7.4.16).
pub async fn key_named(conn: &mut PgConnection, id: &KeyId) -> Result<bool, StoreError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM accounts WHERE service_key = $1 OR pending_key = $1) \
         OR EXISTS (SELECT 1 FROM erased_keys WHERE key_id = $1)",
    )
    .bind(id.as_str())
    .fetch_one(conn)
    .await
    .map_err(StoreError::from_db)
}

/// The heads of the accounts `ids` names that are there now, in the order of their IDs.
pub async fn heads(conn: &mut PgConnection, ids: &[String]) -> Result<Vec<StoredHead>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, identity_key, generation, service_key, pending_key, chain_seq, \
         chain_hash, created_at_ms, identity_doc FROM accounts WHERE id = ANY($1) ORDER BY id",
    )
    .bind(ids)
    .fetch_all(conn)
    .await
    .map_err(StoreError::from_db)?;
    rows.iter()
        .map(|row| {
            let identity_key: Vec<u8> = row.try_get("identity_key")?;
            let service_key: String = row.try_get("service_key")?;
            let pending_key: Option<String> = row.try_get("pending_key")?;
            let chain_seq: Option<i64> = row.try_get("chain_seq")?;
            let chain_hash: Option<Vec<u8>> = row.try_get("chain_hash")?;
            let chain = match (chain_seq, chain_hash) {
                (Some(seq), Some(hash)) => Some((
                    from_db(seq, "chain_seq")?,
                    <[u8; 32]>::try_from(hash.as_slice())
                        .map_err(|_| StoreError::Corrupt("chain_hash"))?,
                )),
                (None, None) => None,
                _ => return Err(StoreError::Corrupt("chain_seq and chain_hash")),
            };
            Ok(StoredHead {
                id: row.try_get("id")?,
                identity_key: <[u8; 32]>::try_from(identity_key.as_slice())
                    .map_err(|_| StoreError::Corrupt("identity_key"))?,
                generation: from_db(row.try_get("generation")?, "generation")?,
                service_key: KeyId::parse(&service_key)
                    .map_err(|_| StoreError::Corrupt("service_key"))?,
                pending_key: pending_key
                    .map(|key| KeyId::parse(&key).map_err(|_| StoreError::Corrupt("pending_key")))
                    .transpose()?,
                chain,
                created_at_ms: from_db(row.try_get("created_at_ms")?, "created_at_ms")?,
                identity_doc: row.try_get("identity_doc")?,
            })
        })
        .collect()
}
