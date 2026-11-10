//! Inbox entries (Switch wire 7.4.3, 9.1): kept, sealed, until every current target's cursor
//! has passed them. The service never holds the keys that open an envelope; it reads only
//! the header, which names the targets' receive keys.

use pubky_switch_core::sig::SignedDoc;
use sqlx::Row;

use super::{
    AccountTxn, StoreError, from_db,
    identity::{decode_doc, encode_doc},
    to_db,
};

/// An entry to keep.
#[derive(Clone, Debug)]
pub struct NewEntry<'a> {
    /// The `seq` it takes.
    pub seq: u64,
    /// Its entry ID.
    pub entry_id: [u8; 16],
    /// The sender identity.
    pub sender: [u8; 32],
    /// The sender app.
    pub sender_app: [u8; 16],
    /// The sender app's certificate.
    pub cert: &'a SignedDoc,
    /// When the inbox accepted it.
    pub accepted_at_ms: u64,
    /// The envelope.
    pub envelope: &'a [u8],
    /// BLAKE3 of the envelope.
    pub envelope_hash: [u8; 32],
    /// The apps it is wrapped to.
    pub targets: &'a [[u8; 16]],
    /// The context of the invite code that admitted the sender, as written.
    pub context: Option<&'a [u8]>,
    /// The append's answer, for a retry by content.
    pub answer: &'a [u8],
    /// What it counts against the inbox quota.
    pub quota_bytes: u64,
}

/// A stored entry as the feed shows it (Switch wire 7.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEntry {
    /// Its `seq`.
    pub seq: u64,
    /// Its entry ID.
    pub entry_id: [u8; 16],
    /// The sender identity.
    pub sender: [u8; 32],
    /// The sender app's certificate.
    pub cert: SignedDoc,
    /// When the inbox accepted it.
    pub accepted_at_ms: u64,
    /// The envelope.
    pub envelope: Vec<u8>,
    /// The apps it is wrapped to.
    pub targets: Vec<[u8; 16]>,
    /// The invite code's context, as written.
    pub context: Option<Vec<u8>>,
}

pub(super) fn entry_of(row: &sqlx::postgres::PgRow) -> Result<StoredEntry, StoreError> {
    let entry_id: Vec<u8> = row.try_get("entry_id")?;
    let sender: Vec<u8> = row.try_get("sender")?;
    let cert: Vec<u8> = row.try_get("cert")?;
    let targets: Vec<Vec<u8>> = row.try_get("targets")?;
    Ok(StoredEntry {
        seq: from_db(row.try_get("seq")?, "seq")?,
        entry_id: <[u8; 16]>::try_from(entry_id.as_slice())
            .map_err(|_| StoreError::Corrupt("entry_id"))?,
        sender: <[u8; 32]>::try_from(sender.as_slice())
            .map_err(|_| StoreError::Corrupt("an entry's sender"))?,
        cert: decode_doc(&cert, "an entry's certificate")?,
        accepted_at_ms: from_db(row.try_get("accepted_at_ms")?, "accepted_at_ms")?,
        envelope: row.try_get("envelope")?,
        targets: targets
            .iter()
            .map(|target| {
                <[u8; 16]>::try_from(target.as_slice())
                    .map_err(|_| StoreError::Corrupt("an entry's target"))
            })
            .collect::<Result<_, _>>()?,
        context: row.try_get("context")?,
    })
}

/// How much of the inbox quota is held: by every entry, and by one sender's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InboxUsage {
    /// Every entry's counted bytes.
    pub total: u64,
    /// The sender's.
    pub sender: u64,
}

impl AccountTxn {
    /// The answer an append of the envelope of hash `envelope_hash` from `sender` got, while
    /// the service holds it (Switch wire 7.4.3 check 1).
    pub async fn appended_answer(
        &mut self,
        sender: &[u8; 32],
        envelope_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let id = self.head().id.clone();
        sqlx::query_scalar(
            "SELECT answer FROM inbox_entries WHERE account_id = $1 AND sender = $2 \
             AND envelope_hash = $3",
        )
        .bind(id)
        .bind(sender.as_slice())
        .bind(envelope_hash.as_slice())
        .fetch_optional(self.conn())
        .await
        .map_err(StoreError::from_db)
    }

    /// The inbox quota's use: every entry's, and `sender`'s (Switch wire 9.3).
    pub async fn inbox_usage(&mut self, sender: &[u8; 32]) -> Result<InboxUsage, StoreError> {
        let id = self.head().id.clone();
        let row = sqlx::query(
            "SELECT coalesce(sum(quota_bytes), 0)::BIGINT AS total, \
             coalesce(sum(quota_bytes) FILTER (WHERE sender = $2), 0)::BIGINT AS sender \
             FROM inbox_entries WHERE account_id = $1",
        )
        .bind(id)
        .bind(sender.as_slice())
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(InboxUsage {
            total: from_db(row.try_get("total")?, "inbox bytes")?,
            sender: from_db(row.try_get("sender")?, "sender bytes")?,
        })
    }

    /// Keep an entry at its `seq`, which this request gave out.
    pub async fn add_entry(&mut self, entry: &NewEntry<'_>) -> Result<(), StoreError> {
        let head = self.head().clone();
        let targets: Vec<Vec<u8>> = entry.targets.iter().map(|app| app.to_vec()).collect();
        sqlx::query(
            "INSERT INTO inbox_entries (account_id, generation, seq, entry_id, sender, \
             sender_app, cert, accepted_at_ms, envelope, envelope_hash, targets, context, \
             answer, quota_bytes) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(&head.id)
        .bind(to_db(head.generation, "generation")?)
        .bind(to_db(entry.seq, "seq")?)
        .bind(entry.entry_id.as_slice())
        .bind(entry.sender.as_slice())
        .bind(entry.sender_app.as_slice())
        .bind(encode_doc(entry.cert)?)
        .bind(to_db(entry.accepted_at_ms, "accepted_at_ms")?)
        .bind(entry.envelope)
        .bind(entry.envelope_hash.as_slice())
        .bind(targets)
        .bind(entry.context)
        .bind(entry.answer)
        .bind(to_db(entry.quota_bytes, "quota_bytes")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        self.note_change();
        Ok(())
    }

    /// Delete the entries every current target has passed (Switch wire 9.1): each target
    /// in `current`, the App IDs current now, has its cursor, in the generation the account
    /// serves, at or past the entry. An entry with no current target stays, for the
    /// unreadable item that replaces it.
    pub async fn delete_passed_entries(&mut self, current: &[[u8; 16]]) -> Result<u64, StoreError> {
        let head = self.head().clone();
        let current: Vec<Vec<u8>> = current.iter().map(|app| app.to_vec()).collect();
        let deleted = sqlx::query(
            "DELETE FROM inbox_entries e WHERE e.account_id = $1 AND e.generation = $2 \
             AND EXISTS (SELECT 1 FROM unnest(e.targets) AS t(app_id) WHERE t.app_id = ANY($3)) \
             AND NOT EXISTS ( \
                 SELECT 1 FROM unnest(e.targets) AS t(app_id) \
                 WHERE t.app_id = ANY($3) \
                 AND NOT EXISTS (SELECT 1 FROM apps a \
                                 WHERE a.account_id = e.account_id AND a.app_id = t.app_id \
                                 AND a.cursor_generation = e.generation \
                                 AND a.cursor_seq >= e.seq))",
        )
        .bind(&head.id)
        .bind(to_db(head.generation, "generation")?)
        .bind(current)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?
        .rows_affected();
        Ok(deleted)
    }

    /// Each current app's unread entries, and of those, the ones it is the only current
    /// target of (Switch wire 7.4.12 `unread_entries`, `sole_target_unread`), for the apps
    /// with any; `current` holds the App IDs current now.
    pub async fn unread_counts(
        &mut self,
        current: &[[u8; 16]],
    ) -> Result<Vec<([u8; 16], u64, u64)>, StoreError> {
        let head = self.head().clone();
        let current: Vec<Vec<u8>> = current.iter().map(|app| app.to_vec()).collect();
        let rows = sqlx::query(
            "WITH unread AS ( \
                 SELECT e.seq, t.app_id FROM inbox_entries e, unnest(e.targets) AS t(app_id) \
                 WHERE e.account_id = $1 AND e.generation = $2 AND t.app_id = ANY($3) \
                 AND NOT EXISTS (SELECT 1 FROM apps a \
                                 WHERE a.account_id = e.account_id AND a.app_id = t.app_id \
                                 AND a.cursor_generation = e.generation \
                                 AND a.cursor_seq >= e.seq)), \
             current_targets AS ( \
                 SELECT e.seq, count(*) AS n FROM inbox_entries e, unnest(e.targets) AS t(app_id) \
                 WHERE e.account_id = $1 AND e.generation = $2 AND t.app_id = ANY($3) \
                 GROUP BY e.seq) \
             SELECT u.app_id, count(*)::BIGINT AS unread, \
                    (count(*) FILTER (WHERE c.n = 1))::BIGINT AS sole \
             FROM unread u JOIN current_targets c ON c.seq = u.seq GROUP BY u.app_id",
        )
        .bind(&head.id)
        .bind(to_db(head.generation, "generation")?)
        .bind(current)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                let app: Vec<u8> = row.try_get("app_id")?;
                Ok((
                    <[u8; 16]>::try_from(app.as_slice())
                        .map_err(|_| StoreError::Corrupt("app_id"))?,
                    from_db(row.try_get("unread")?, "unread")?,
                    from_db(row.try_get("sole")?, "sole")?,
                ))
            })
            .collect()
    }

    /// Use one of the invite code `code_hash`'s uses, and write the service's conversation
    /// entry for `sender` naming it, with its context (Switch spec 7, wire 7.4.3 check 7),
    /// atomically with the append.
    pub async fn use_invite(
        &mut self,
        code_hash: &[u8; 32],
        sender: &[u8; 32],
        context: &[u8],
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "UPDATE invite_codes SET uses = uses + 1 WHERE account_id = $1 AND code_hash = $2",
        )
        .bind(&id)
        .bind(code_hash.as_slice())
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        sqlx::query(
            "INSERT INTO list_entries (account_id, list, pubky, written_by, at_ms, code_hash, \
             context) VALUES ($1, 'conversation', $2, NULL, $3, $4, $5) \
             ON CONFLICT (account_id, list, pubky) DO NOTHING",
        )
        .bind(&id)
        .bind(sender.as_slice())
        .bind(to_db(at_ms, "at_ms")?)
        .bind(code_hash.as_slice())
        .bind(context)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// The app each of `kids` was registered by, for the kids the account ever registered
    /// (Switch spec 3.6: a kid is never registered twice in an account).
    pub async fn kid_holders(
        &mut self,
        kids: &[[u8; 8]],
    ) -> Result<Vec<([u8; 8], [u8; 16])>, StoreError> {
        let id = self.head().id.clone();
        let kids: Vec<Vec<u8>> = kids.iter().map(|kid| kid.to_vec()).collect();
        let rows = sqlx::query(
            "SELECT kid, app_id FROM receive_keys WHERE account_id = $1 AND kid = ANY($2)",
        )
        .bind(id)
        .bind(kids)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                let kid: Vec<u8> = row.try_get("kid")?;
                let app: Vec<u8> = row.try_get("app_id")?;
                Ok((
                    <[u8; 8]>::try_from(kid.as_slice()).map_err(|_| StoreError::Corrupt("kid"))?,
                    <[u8; 16]>::try_from(app.as_slice())
                        .map_err(|_| StoreError::Corrupt("app_id"))?,
                ))
            })
            .collect()
    }

    /// Note an admitted append's time on the sender's conversation entry (Switch spec 7
    /// "Pruning": `last_used`).
    pub async fn note_conversation_used(
        &mut self,
        sender: &[u8; 32],
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "UPDATE list_entries SET last_used_ms = $3 WHERE account_id = $1 \
             AND list = 'conversation' AND pubky = $2",
        )
        .bind(id)
        .bind(sender.as_slice())
        .bind(to_db(at_ms, "last_used_ms")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }
}
