//! The lists `GET /allow` shows (Switch wire 7.4.6): contacts, conversation entries, the deny
//! list, flagged senders and live invite codes, each whole, read in the request's own
//! request's snapshot, after the lock ([`SnapshotRead`]), so they are the state at its
//! stamped service time.

use sqlx::Row;

use super::{ListName, SnapshotRead, StoreError, from_db, to_db};

/// A list entry as `GET /allow` shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowEntry {
    /// The Pubky ID.
    pub pubky: [u8; 32],
    /// The writing app; `None` for a conversation entry the service wrote for a sender an
    /// invite code admitted.
    pub written_by: Option<[u8; 16]>,
    /// The service time of the write.
    pub at_ms: u64,
    /// The invite code's hash, on an entry the service wrote.
    pub code_hash: Option<[u8; 32]>,
    /// The invite code's context as its writer wrote it, on an entry the service wrote.
    pub context: Option<Vec<u8>>,
    /// The service time of the last append the entry admitted.
    pub last_used_ms: Option<u64>,
}

/// A live invite code as `GET /allow` shows it, without its context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowInvite {
    /// `hash(code bytes)`.
    pub code_hash: [u8; 32],
    /// When it expires.
    pub expires_at_ms: u64,
    /// How many appends it admits.
    pub max_uses: u64,
    /// How many it admitted.
    pub uses: u64,
    /// The writing app.
    pub writer: [u8; 16],
}

fn array<const N: usize>(bytes: &[u8], what: &'static str) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(bytes).map_err(|_| StoreError::Corrupt(what))
}

impl SnapshotRead {
    /// Every entry of `list`, by Pubky ID.
    pub async fn allow_entries(&mut self, list: ListName) -> Result<Vec<AllowEntry>, StoreError> {
        let id = self.id.clone();
        let rows = sqlx::query(
            "SELECT pubky, written_by, at_ms, code_hash, context, last_used_ms FROM list_entries \
             WHERE account_id = $1 AND list = $2 ORDER BY pubky",
        )
        .bind(id)
        .bind(list.as_str())
        .fetch_all(&mut *self.tx)
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                let pubky: Vec<u8> = row.try_get("pubky")?;
                let by: Option<Vec<u8>> = row.try_get("written_by")?;
                let code: Option<Vec<u8>> = row.try_get("code_hash")?;
                let last: Option<i64> = row.try_get("last_used_ms")?;
                Ok(AllowEntry {
                    pubky: array(&pubky, "pubky")?,
                    written_by: by.map(|by| array(&by, "written_by")).transpose()?,
                    at_ms: from_db(row.try_get("at_ms")?, "at_ms")?,
                    code_hash: code.map(|code| array(&code, "code_hash")).transpose()?,
                    context: row.try_get("context")?,
                    last_used_ms: last.map(|ms| from_db(ms, "last_used_ms")).transpose()?,
                })
            })
            .collect()
    }

    /// The senders flagged at least `min_hits` times (Switch wire 9.4 Flags), the most
    /// frequent first, then by Pubky ID.
    pub async fn flagged_senders(
        &mut self,
        min_hits: u64,
    ) -> Result<Vec<([u8; 32], u64)>, StoreError> {
        let id = self.id.clone();
        let rows = sqlx::query(
            "SELECT pubky, hits FROM sender_flags WHERE account_id = $1 AND hits >= $2 \
             ORDER BY hits DESC, pubky",
        )
        .bind(id)
        .bind(to_db(min_hits, "flag_after")?)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                let pubky: Vec<u8> = row.try_get("pubky")?;
                Ok((
                    array(&pubky, "pubky")?,
                    from_db(row.try_get("hits")?, "hits")?,
                ))
            })
            .collect()
    }

    /// The invite codes live at `now_ms`, with uses left and unexpired, by code hash.
    pub async fn live_invite_codes(&mut self, now_ms: u64) -> Result<Vec<AllowInvite>, StoreError> {
        let id = self.id.clone();
        let rows = sqlx::query(
            "SELECT code_hash, expires_at_ms, max_uses, uses, writer FROM invite_codes \
             WHERE account_id = $1 AND uses < max_uses AND expires_at_ms > $2 ORDER BY code_hash",
        )
        .bind(id)
        .bind(to_db(now_ms, "now_ms")?)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                let hash: Vec<u8> = row.try_get("code_hash")?;
                let writer: Vec<u8> = row.try_get("writer")?;
                Ok(AllowInvite {
                    code_hash: array(&hash, "code_hash")?,
                    expires_at_ms: from_db(row.try_get("expires_at_ms")?, "expires_at_ms")?,
                    max_uses: from_db(row.try_get("max_uses")?, "max_uses")?,
                    uses: from_db(row.try_get("uses")?, "uses")?,
                    writer: array(&writer, "writer")?,
                })
            })
            .collect()
    }
}
