//! Inbox entries (Switch wire 7.4.3, 9.1): kept, sealed, until every current target's cursor
//! has passed them, not waiting for targets marked lagging. The service never holds the keys
//! that open an envelope; it reads only the header, which names the targets' receive keys.
//!
//! The inbox also holds the items the service writes itself, each at a `seq` of its own
//! (7.4.4, 7.5): an `unreadable` item for an entry no current app can open once its targets
//! departed, and a `missed` item telling a lagging app how many entries it missed.

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

/// An item of the inbox as the feed shows it (Switch wire 7.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboxItem {
    /// An entry, shown to its target apps.
    Entry(StoredEntry),
    /// An entry no current app can open after its targets departed, without its envelope:
    /// shown to every current app.
    Unreadable {
        /// Its `seq`, given out at the departure.
        seq: u64,
        /// The entry's entry ID.
        entry_id: [u8; 16],
        /// The entry's sender identity.
        sender: [u8; 32],
        /// When the inbox accepted the entry.
        accepted_at_ms: u64,
    },
    /// What a lagging app missed: shown to that app only.
    Missed {
        /// Its `seq`.
        seq: u64,
        /// How many entries targeting the app the service deleted before it read them.
        entries: u64,
        /// The first of their acceptance times.
        from_ms: u64,
        /// The last of their acceptance times.
        until_ms: u64,
    },
}

impl InboxItem {
    /// Its `seq`.
    pub fn seq(&self) -> u64 {
        match self {
            Self::Entry(entry) => entry.seq,
            Self::Unreadable { seq, .. } | Self::Missed { seq, .. } => *seq,
        }
    }
}

/// An inbox row read with its `item_kind`, as [`InboxItem`].
pub(super) fn item_of(row: &sqlx::postgres::PgRow) -> Result<InboxItem, StoreError> {
    let kind: String = row.try_get("item_kind")?;
    match kind.as_str() {
        "entry" => Ok(InboxItem::Entry(entry_of(row)?)),
        "unreadable" => {
            let entry_id: Vec<u8> = row.try_get("entry_id")?;
            let sender: Vec<u8> = row.try_get("sender")?;
            Ok(InboxItem::Unreadable {
                seq: from_db(row.try_get("seq")?, "seq")?,
                entry_id: <[u8; 16]>::try_from(entry_id.as_slice())
                    .map_err(|_| StoreError::Corrupt("entry_id"))?,
                sender: <[u8; 32]>::try_from(sender.as_slice())
                    .map_err(|_| StoreError::Corrupt("an entry's sender"))?,
                accepted_at_ms: from_db(row.try_get("accepted_at_ms")?, "accepted_at_ms")?,
            })
        }
        "missed" => Ok(InboxItem::Missed {
            seq: from_db(row.try_get("seq")?, "seq")?,
            entries: from_db(row.try_get("missed_entries")?, "missed_entries")?,
            from_ms: from_db(row.try_get("missed_from_ms")?, "missed_from_ms")?,
            until_ms: from_db(row.try_get("missed_until_ms")?, "missed_until_ms")?,
        }),
        _ => Err(StoreError::Corrupt("an inbox item's kind")),
    }
}

fn app_ids(apps: &[[u8; 16]]) -> Vec<Vec<u8>> {
    apps.iter().map(|app| app.to_vec()).collect()
}

fn app_of(bytes: &[u8]) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(bytes).map_err(|_| StoreError::Corrupt("app_id"))
}

/// The entries one release deleted that a lagging target hadn't read, for its `missed` item.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Misses {
    entries: u64,
    from_ms: u64,
    until_ms: u64,
}

impl Misses {
    fn add(&mut self, at_ms: u64) {
        if self.entries == 0 {
            self.from_ms = at_ms;
            self.until_ms = at_ms;
        } else {
            self.from_ms = self.from_ms.min(at_ms);
            self.until_ms = self.until_ms.max(at_ms);
        }
        self.entries = self.entries.saturating_add(1);
    }
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
             coalesce(sum(quota_bytes) FILTER (WHERE sender = $2 AND kind = 'entry'), 0)::BIGINT \
             AS sender \
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

    /// Release what every reader it waits for has passed (Switch wire 9.1), for the App IDs
    /// `current` current now and the ones of them in `lagging`, marked lagging (empty
    /// without trusted time, so entries then wait for every current target, 7.4.4):
    /// - an entry goes once every current target that isn't lagging has its cursor, in the
    ///   generation the account serves, at or past it. An entry with no current target
    ///   stays, for the unreadable item that replaces it ([`Self::convert_unreadable`]). A
    ///   lagging target that hadn't read an entry that goes gets a `missed` item for it;
    /// - an unreadable item goes once every current app, lagging ones included, has passed
    ///   it;
    /// - a `missed` item goes once its app has passed it, or isn't current.
    ///
    /// The number of entries and items deleted.
    pub async fn delete_passed_entries(
        &mut self,
        current: &[[u8; 16]],
        lagging: &[[u8; 16]],
    ) -> Result<u64, StoreError> {
        let head = self.head().clone();
        let generation = to_db(head.generation, "generation")?;
        let rows = sqlx::query(
            "DELETE FROM inbox_entries e WHERE e.account_id = $1 AND e.generation = $2 \
             AND e.kind = 'entry' \
             AND EXISTS (SELECT 1 FROM unnest(e.targets) AS t(app_id) WHERE t.app_id = ANY($3)) \
             AND NOT EXISTS ( \
                 SELECT 1 FROM unnest(e.targets) AS t(app_id) \
                 WHERE t.app_id = ANY($3) AND NOT (t.app_id = ANY($4)) \
                 AND NOT EXISTS (SELECT 1 FROM apps a \
                                 WHERE a.account_id = e.account_id AND a.app_id = t.app_id \
                                 AND a.cursor_generation = e.generation \
                                 AND a.cursor_seq >= e.seq)) \
             RETURNING e.seq, e.targets, e.accepted_at_ms",
        )
        .bind(&head.id)
        .bind(generation)
        .bind(app_ids(current))
        .bind(app_ids(lagging))
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let mut deleted = u64::try_from(rows.len()).unwrap_or(u64::MAX);
        // What each lagging target missed: the deleted entries targeting it past its cursor.
        let cursors = self.cursors(lagging).await?;
        let mut misses: std::collections::BTreeMap<[u8; 16], Misses> =
            std::collections::BTreeMap::new();
        for row in &rows {
            let seq = from_db(row.try_get("seq")?, "seq")?;
            let at_ms = from_db(row.try_get("accepted_at_ms")?, "accepted_at_ms")?;
            let targets: Vec<Vec<u8>> = row.try_get("targets")?;
            for target in &targets {
                let target = app_of(target)?;
                if let Some(cursor) = cursors.get(&target)
                    && *cursor < seq
                {
                    misses.entry(target).or_default().add(at_ms);
                }
            }
        }
        for (app, missed) in misses {
            self.record_missed(&app, missed).await?;
        }
        deleted = deleted.saturating_add(
            sqlx::query(
                "DELETE FROM inbox_entries e WHERE e.account_id = $1 AND e.generation = $2 \
                 AND ( \
                     (e.kind = 'unreadable' AND cardinality($3::BYTEA[]) > 0 \
                      AND NOT EXISTS ( \
                          SELECT 1 FROM unnest($3::BYTEA[]) AS c(app_id) \
                          WHERE NOT EXISTS (SELECT 1 FROM apps a \
                                            WHERE a.account_id = e.account_id \
                                            AND a.app_id = c.app_id \
                                            AND a.cursor_generation = e.generation \
                                            AND a.cursor_seq >= e.seq))) \
                     OR (e.kind = 'missed' \
                         AND (NOT (e.targets[1] = ANY($3)) \
                              OR EXISTS (SELECT 1 FROM apps a \
                                         WHERE a.account_id = e.account_id \
                                         AND a.app_id = e.targets[1] \
                                         AND a.cursor_generation = e.generation \
                                         AND a.cursor_seq >= e.seq))))",
            )
            .bind(&head.id)
            .bind(generation)
            .bind(app_ids(current))
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?
            .rows_affected(),
        );
        if deleted > 0 {
            self.note_change();
        }
        Ok(deleted)
    }

    /// The cursor position of each of `apps` in the generation the account serves, 0 before
    /// any.
    async fn cursors(
        &mut self,
        apps: &[[u8; 16]],
    ) -> Result<std::collections::BTreeMap<[u8; 16], u64>, StoreError> {
        let head = self.head().clone();
        let mut cursors: std::collections::BTreeMap<[u8; 16], u64> =
            apps.iter().map(|app| (*app, 0)).collect();
        if apps.is_empty() {
            return Ok(cursors);
        }
        let rows = sqlx::query(
            "SELECT app_id, cursor_seq FROM apps WHERE account_id = $1 AND app_id = ANY($2) \
             AND cursor_generation = $3",
        )
        .bind(&head.id)
        .bind(app_ids(apps))
        .bind(to_db(head.generation, "generation")?)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        for row in &rows {
            let app: Vec<u8> = row.try_get("app_id")?;
            let seq: Option<i64> = row.try_get("cursor_seq")?;
            cursors.insert(
                app_of(&app)?,
                seq.map(|s| from_db(s, "cursor_seq"))
                    .transpose()?
                    .unwrap_or(0),
            );
        }
        Ok(cursors)
    }

    /// Record `missed` for `app` (Switch wire 7.4.4): a `missed` item at a new `seq`,
    /// replacing one the app hasn't passed with one covering both.
    async fn record_missed(&mut self, app: &[u8; 16], missed: Misses) -> Result<(), StoreError> {
        let head = self.head().clone();
        let generation = to_db(head.generation, "generation")?;
        let cursor = self.cursors(&[*app]).await?.get(app).copied().unwrap_or(0);
        let unpassed = sqlx::query(
            "DELETE FROM inbox_entries WHERE account_id = $1 AND generation = $2 \
             AND kind = 'missed' AND targets[1] = $3 AND seq > $4 \
             RETURNING missed_entries, missed_from_ms, missed_until_ms",
        )
        .bind(&head.id)
        .bind(generation)
        .bind(app.as_slice())
        .bind(to_db(cursor, "cursor")?)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let mut merged = missed;
        for row in &unpassed {
            let entries = from_db(row.try_get("missed_entries")?, "missed_entries")?;
            merged.entries = merged.entries.saturating_add(entries);
            merged.from_ms = merged
                .from_ms
                .min(from_db(row.try_get("missed_from_ms")?, "missed_from_ms")?);
            merged.until_ms = merged
                .until_ms
                .max(from_db(row.try_get("missed_until_ms")?, "missed_until_ms")?);
        }
        let seq = self.next_seq()?;
        sqlx::query(
            "INSERT INTO inbox_entries (account_id, generation, seq, kind, accepted_at_ms, \
             envelope, targets, quota_bytes, missed_entries, missed_from_ms, missed_until_ms) \
             VALUES ($1, $2, $3, 'missed', $4, '\\x', ARRAY[$5::BYTEA], 0, $6, $7, $8)",
        )
        .bind(&head.id)
        .bind(generation)
        .bind(to_db(seq, "seq")?)
        .bind(to_db(merged.until_ms, "accepted_at_ms")?)
        .bind(app.as_slice())
        .bind(to_db(merged.entries, "missed_entries")?)
        .bind(to_db(merged.from_ms, "missed_from_ms")?)
        .bind(to_db(merged.until_ms, "missed_until_ms")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        self.note_change();
        Ok(())
    }

    /// Turn each entry left with no current target, `current` holding the App IDs current
    /// now, into an unreadable item at a new `seq`, in their order (Switch wire 7.4.4, spec
    /// 8.2): its envelope goes, it keeps its entry ID, sender and acceptance time, and it
    /// counts `overhead` against the inbox quota. Called at a departure, after its chain
    /// item, so every item comes after the departure an app verifies before it acts on one.
    /// The number converted.
    pub async fn convert_unreadable(
        &mut self,
        current: &[[u8; 16]],
        overhead: u64,
    ) -> Result<u64, StoreError> {
        let head = self.head().clone();
        let generation = to_db(head.generation, "generation")?;
        let seqs: Vec<i64> = sqlx::query_scalar(
            "SELECT seq FROM inbox_entries WHERE account_id = $1 AND generation = $2 \
             AND kind = 'entry' AND NOT (targets && $3::BYTEA[]) ORDER BY seq",
        )
        .bind(&head.id)
        .bind(generation)
        .bind(app_ids(current))
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        for old in &seqs {
            let seq = self.next_seq()?;
            sqlx::query(
                "UPDATE inbox_entries SET seq = $4, kind = 'unreadable', envelope = '\\x', \
                 quota_bytes = $5 WHERE account_id = $1 AND generation = $2 AND seq = $3",
            )
            .bind(&head.id)
            .bind(generation)
            .bind(old)
            .bind(to_db(seq, "seq")?)
            .bind(to_db(overhead.max(1), "quota_bytes")?)
            .execute(self.conn())
            .await
            .map_err(StoreError::from_db)?;
        }
        if !seqs.is_empty() {
            self.note_change();
        }
        Ok(u64::try_from(seqs.len()).unwrap_or(u64::MAX))
    }

    /// The bytes of the inbox each of `current` hasn't read, as its lagging is measured
    /// (Switch wire 7.4.4): the quota bytes of each entry targeting it and of each
    /// unreadable item, past its cursor; `missed` items count for nothing.
    pub async fn unread_bytes(
        &mut self,
        current: &[[u8; 16]],
    ) -> Result<Vec<([u8; 16], u64)>, StoreError> {
        let head = self.head().clone();
        let rows = sqlx::query(
            "SELECT c.app_id, coalesce(sum(e.quota_bytes), 0)::BIGINT AS bytes \
             FROM unnest($3::BYTEA[]) AS c(app_id) \
             LEFT JOIN apps a ON a.account_id = $1 AND a.app_id = c.app_id \
             LEFT JOIN inbox_entries e ON e.account_id = $1 AND e.generation = $2 \
                 AND ((e.kind = 'entry' AND c.app_id = ANY(e.targets)) OR e.kind = 'unreadable') \
                 AND NOT coalesce(a.cursor_generation = e.generation AND a.cursor_seq >= e.seq, \
                                  false) \
             GROUP BY c.app_id",
        )
        .bind(&head.id)
        .bind(to_db(head.generation, "generation")?)
        .bind(app_ids(current))
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        rows.iter()
            .map(|row| {
                let app: Vec<u8> = row.try_get("app_id")?;
                Ok((
                    app_of(&app)?,
                    from_db(row.try_get("bytes")?, "unread bytes")?,
                ))
            })
            .collect()
    }

    /// The apps marked lagging.
    pub async fn lagging_apps(&mut self) -> Result<Vec<[u8; 16]>, StoreError> {
        let id = self.head().id.clone();
        let rows: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT app_id FROM apps WHERE account_id = $1 AND lagging")
                .bind(id)
                .fetch_all(self.conn())
                .await
                .map_err(StoreError::from_db)?;
        rows.iter().map(|app| app_of(app)).collect()
    }

    /// Mark `apps` lagging, or clear their marks (Switch wire 7.4.4).
    pub async fn set_lagging(
        &mut self,
        apps: &[[u8; 16]],
        lagging: bool,
    ) -> Result<(), StoreError> {
        if apps.is_empty() {
            return Ok(());
        }
        let id = self.head().id.clone();
        sqlx::query(
            "UPDATE apps SET lagging = $3 WHERE account_id = $1 AND app_id = ANY($2) \
             AND lagging <> $3",
        )
        .bind(id)
        .bind(app_ids(apps))
        .bind(lagging)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// Each app's unread entries, the entries held that target it and that its cursor
    /// hasn't passed, whether or not it is current; and of those, the ones it is the only
    /// current target of (Switch wire 7.4.12 `unread_entries`, `sole_target_unread`), for the
    /// apps with any. `current` holds the App IDs current.
    pub async fn unread_counts(
        &mut self,
        current: &[[u8; 16]],
    ) -> Result<Vec<([u8; 16], u64, u64)>, StoreError> {
        let head = self.head().clone();
        let current: Vec<Vec<u8>> = current.iter().map(|app| app.to_vec()).collect();
        let rows = sqlx::query(
            "WITH unread AS ( \
                 SELECT e.seq, t.app_id FROM inbox_entries e, unnest(e.targets) AS t(app_id) \
                 WHERE e.account_id = $1 AND e.generation = $2 AND e.kind = 'entry' \
                 AND NOT EXISTS (SELECT 1 FROM apps a \
                                 WHERE a.account_id = e.account_id AND a.app_id = t.app_id \
                                 AND a.cursor_generation = e.generation \
                                 AND a.cursor_seq >= e.seq)), \
             current_targets AS ( \
                 SELECT e.seq, count(*) AS n FROM inbox_entries e, unnest(e.targets) AS t(app_id) \
                 WHERE e.account_id = $1 AND e.generation = $2 AND e.kind = 'entry' \
                 AND t.app_id = ANY($3) \
                 GROUP BY e.seq) \
             SELECT u.app_id, count(*)::BIGINT AS unread, \
                    (count(*) FILTER (WHERE c.n = 1 AND u.app_id = ANY($3)))::BIGINT AS sole \
             FROM unread u LEFT JOIN current_targets c ON c.seq = u.seq GROUP BY u.app_id",
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
        // The conversation entry answers the sender's connect request (Switch wire 7.4.7).
        self.delete_connect(sender).await?;
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
