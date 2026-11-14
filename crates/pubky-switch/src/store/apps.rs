//! What `GET /apps` reads of an account (Switch wire 7.4.12): its apps' rows, the App IDs it
//! keeps for good, when each app was first listed, the key bundle parts, the open attempts
//! and the generations its kept proofs name; and the purge of removed apps (9.1).

use std::collections::BTreeMap;

use pubky_switch_core::{claims::Outcome, records::IdentityDoc};
use sqlx::Row;

use super::{AccountTxn, StoreError, StoredApp, from_db, to_db};

/// Why an App ID is kept for good (Switch wire 9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeptReason {
    /// The signer revoked it.
    Revoked,
    /// It left.
    Departed,
    /// An enrollment's `revoked_apps` named it.
    Enrolled,
}

/// An App ID the account keeps for good.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeptAppId {
    /// The App ID.
    pub app_id: [u8; 16],
    /// Why.
    pub reason: KeptReason,
    /// When it was revoked or departed, or the enrollment that named it.
    pub at_ms: u64,
    /// The newest document's data epoch then, which its rotation goes above; `None` for an
    /// enrollment's.
    pub data_epoch: Option<u64>,
    /// Whether a delivered document has listed it in `removed` above that epoch: a
    /// departure's rotation is done, for good.
    pub rotated: bool,
}

/// An attempt that is `open` or `unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenAttempt {
    /// Its claim.
    pub claim_key: [u8; 32],
    /// The attempt ID.
    pub attempt_id: [u8; 16],
    /// The app that wrote it.
    pub owner: [u8; 16],
    /// Whether its outcome is `unknown` rather than `open`.
    pub unknown: bool,
}

/// A stored key bundle part's epochs and `seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartSpan {
    /// Its first data epoch.
    pub first_epoch: u64,
    /// Its last data epoch.
    pub last_epoch: u64,
    /// The `seq` of its `key_bundle.put`.
    pub seq: u64,
}

/// What `GET /apps` reads, under the account's lock.
#[derive(Clone, Debug, Default)]
pub struct AppsView {
    /// Every app row.
    pub apps: Vec<StoredApp>,
    /// The service time of each app's last authenticated request (Switch wire 7.3 step 6).
    pub last_seen: BTreeMap<[u8; 16], u64>,
    /// Every App ID kept for good.
    pub kept: Vec<KeptAppId>,
    /// The data epoch of the first document that listed each app.
    pub listings: BTreeMap<[u8; 16], u64>,
    /// The key bundle parts stored for each app, by `first_epoch`.
    pub parts: BTreeMap<[u8; 16], Vec<PartSpan>>,
    /// Every attempt open or unknown.
    pub open_attempts: Vec<OpenAttempt>,
    /// Each current app's unread entries, and of those the ones it is the only current
    /// target of: filled by the service, which judges which apps are current
    /// ([`AccountTxn::unread_counts`]).
    pub unread: BTreeMap<[u8; 16], (u64, u64)>,
    /// The apps marked lagging (Switch wire 7.4.4).
    pub lagging: std::collections::BTreeSet<[u8; 16]>,
    /// The generations that some current record's kept proof names (Switch wire 7.4.9).
    pub record_generations: Vec<u64>,
    /// The generations that some live claim's entry proof names (Switch wire 6.8).
    pub claim_entry_generations: Vec<u64>,
}

fn app_id(bytes: &[u8]) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(bytes).map_err(|_| StoreError::Corrupt("app_id"))
}

fn reason(text: &str) -> Result<KeptReason, StoreError> {
    match text {
        "revoked" => Ok(KeptReason::Revoked),
        "departed" => Ok(KeptReason::Departed),
        "enrolled" => Ok(KeptReason::Enrolled),
        _ => Err(StoreError::Corrupt("a kept App ID's reason")),
    }
}

/// Record that `doc` lists each of `apps` for the first time: their `keys_through` starts at
/// its data epoch (Switch wire 7.4.12). The first listing's epoch is kept.
pub(super) async fn note_listings(
    conn: &mut sqlx::PgConnection,
    account: &str,
    apps: &[[u8; 16]],
    epoch: u64,
) -> Result<(), StoreError> {
    for app in apps {
        sqlx::query(
            "INSERT INTO app_listings (account_id, app_id, listed_epoch) VALUES ($1, $2, $3) \
             ON CONFLICT DO NOTHING",
        )
        .bind(account)
        .bind(app.as_slice())
        .bind(to_db(epoch, "listed_epoch")?)
        .execute(&mut *conn)
        .await
        .map_err(StoreError::from_db)?;
    }
    Ok(())
}

/// The apps `later` lists that `earlier` doesn't: those it lists for the first time.
pub fn newly_listed(earlier: Option<&IdentityDoc>, later: &IdentityDoc) -> Vec<[u8; 16]> {
    later
        .body()
        .apps
        .iter()
        .map(|app| app.app_id)
        .filter(|app| earlier.is_none_or(|doc| doc.listed_cert(app).is_none()))
        .collect()
}

impl AccountTxn {
    /// Where `app`'s `keys_through` starts (Switch wire 7.4.12): the data epoch of the first
    /// `identity.json` that listed it, raised as the key bundle parts it passed went
    /// ([`Self::raise_keys_start`]). `app_listings.listed_epoch` holds it. `None` for an App
    /// ID no document listed here, or one purged: a batch may name either as a target, which
    /// its rules then refuse.
    pub async fn listed_epoch(&mut self, app: &[u8; 16]) -> Result<Option<u64>, StoreError> {
        let id = self.head().id.clone();
        let epoch: Option<i64> = sqlx::query_scalar(
            "SELECT listed_epoch FROM app_listings WHERE account_id = $1 AND app_id = $2",
        )
        .bind(id)
        .bind(app.as_slice())
        .fetch_optional(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        epoch
            .map(|epoch| from_db(epoch, "listed_epoch"))
            .transpose()
    }

    /// Raise where `app`'s `keys_through` starts to `epoch`: the key bundle parts it passed
    /// that held its keys through `epoch` are gone, so `keys_through` keeps that height from
    /// here (Switch wire 7.4.12). It never goes down.
    pub async fn raise_keys_start(&mut self, app: &[u8; 16], epoch: u64) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        sqlx::query(
            "INSERT INTO app_listings (account_id, app_id, listed_epoch) VALUES ($1, $2, $3) \
             ON CONFLICT (account_id, app_id) \
             DO UPDATE SET listed_epoch = GREATEST(app_listings.listed_epoch, $3)",
        )
        .bind(id)
        .bind(app.as_slice())
        .bind(to_db(epoch, "listed_epoch")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// Record that the document this request takes lists `apps` for the first time, at
    /// data epoch `epoch` (Switch wire 7.4.12 `keys_through`).
    pub async fn note_listings(&mut self, apps: &[[u8; 16]], epoch: u64) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        note_listings(self.conn(), &id, apps, epoch).await
    }

    /// Note the rotations `doc` makes: each departed app it lists in `removed` at a data epoch
    /// above the one at its departure (Switch wire 7.4.12 `awaiting_rotation`).
    pub async fn note_rotations(
        &mut self,
        removed: &[[u8; 16]],
        epoch: u64,
    ) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        let removed: Vec<Vec<u8>> = removed.iter().map(|app| app.to_vec()).collect();
        sqlx::query(
            "UPDATE kept_app_ids SET rotated = true WHERE account_id = $1 \
             AND reason = 'departed' AND app_id = ANY($2) \
             AND data_epoch < $3",
        )
        .bind(id)
        .bind(removed)
        .bind(to_db(epoch, "data_epoch")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// Every App ID the account keeps for good, with why, when and its rotation (Switch
    /// wire 9.1, 7.4.12), by App ID.
    pub async fn kept_entries(&mut self) -> Result<Vec<KeptAppId>, StoreError> {
        let id = self.head().id.clone();
        let mut kept = Vec::new();
        for row in sqlx::query(
            "SELECT app_id, reason, at_ms, data_epoch, rotated FROM kept_app_ids \
             WHERE account_id = $1 ORDER BY app_id",
        )
        .bind(&id)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?
        {
            let app: Vec<u8> = row.try_get("app_id")?;
            let reason_text: String = row.try_get("reason")?;
            let data_epoch: Option<i64> = row.try_get("data_epoch")?;
            kept.push(KeptAppId {
                app_id: app_id(&app)?,
                reason: reason(&reason_text)?,
                at_ms: from_db(row.try_get("at_ms")?, "at_ms")?,
                data_epoch: data_epoch.map(|e| from_db(e, "data_epoch")).transpose()?,
                rotated: row.try_get("rotated")?,
            });
        }
        Ok(kept)
    }

    /// Purge each of `apps`, App IDs kept for good that the newest `identity.json` lists in
    /// neither `apps` nor `removed` and whose rotation is done, once it owns no attempt open
    /// or `unknown` (Switch wire 9.1 "Departure, revoked app"): its app record, renewed
    /// certificate, cursor, last-seen time and lagging mark (its `apps` row), its receive
    /// key records, its key bundle parts and its listing go. Its `kept_app_ids` row stays
    /// for good, so it is never current again, and so do its kids, each with its App ID and
    /// no record, so none is registered again (Switch spec 3.6) and an envelope wrapped to
    /// one is told the app isn't current (wire 7.6 `not_current`). Everything other rules
    /// depend on stays: the claims and attempts it wrote, the shared records it wrote with
    /// their `writer` and certificate, the list entries it wrote, the inbox entries naming
    /// it as a target, whose release judges current apps only, and the chain items, its key
    /// bundle parts' included; the documents of its `app.put` and `cert.put` items and of
    /// its deleted parts' `key_bundle.put` items go before the commit, as no app may read
    /// them in full any more (wire 7.5). Returns the App IDs purged; one that holds nothing
    /// any more is passed by.
    pub async fn purge_apps(&mut self, apps: &[[u8; 16]]) -> Result<Vec<[u8; 16]>, StoreError> {
        let id = self.head().id.clone();
        let apps: Vec<Vec<u8>> = apps.iter().map(|app| app.to_vec()).collect();
        // Only an App ID kept for good, and only one that still holds something: one purged
        // before is passed by without reading the claims.
        let holding: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT k.app_id FROM kept_app_ids k WHERE k.account_id = $1 \
             AND k.app_id = ANY($2) AND ( \
                 EXISTS (SELECT 1 FROM apps a \
                         WHERE a.account_id = $1 AND a.app_id = k.app_id) \
                 OR EXISTS (SELECT 1 FROM receive_keys r \
                            WHERE r.account_id = $1 AND r.app_id = k.app_id \
                            AND r.record IS NOT NULL) \
                 OR EXISTS (SELECT 1 FROM key_bundle_parts p \
                            WHERE p.account_id = $1 AND p.target_app_id = k.app_id) \
                 OR EXISTS (SELECT 1 FROM app_listings l \
                            WHERE l.account_id = $1 AND l.app_id = k.app_id)) \
             ORDER BY k.app_id",
        )
        .bind(&id)
        .bind(&apps)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        if holding.is_empty() {
            return Ok(Vec::new());
        }
        // An app owning an attempt open or unknown keeps everything until it is resolved:
        // open_owners names the owner of each such attempt.
        let owning: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT DISTINCT o.app_id FROM claims c, unnest(c.open_owners) AS o(app_id) \
             WHERE c.account_id = $1 AND cardinality(c.open_owners) > 0 \
             AND o.app_id = ANY($2)",
        )
        .bind(&id)
        .bind(&holding)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let gone: Vec<Vec<u8>> = holding
            .into_iter()
            .filter(|app| !owning.contains(app))
            .collect();
        if gone.is_empty() {
            return Ok(Vec::new());
        }
        // Its kids stay, each row with its record cleared: the rows are the account's kid
        // index, which keeps a kid from being registered twice and names the app an
        // envelope wrapped to it (Switch spec 3.6).
        for statement in [
            "DELETE FROM apps WHERE account_id = $1 AND app_id = ANY($2)",
            "UPDATE receive_keys SET record = NULL WHERE account_id = $1 AND app_id = ANY($2)",
            "DELETE FROM app_listings WHERE account_id = $1 AND app_id = ANY($2)",
        ] {
            sqlx::query(statement)
                .bind(&id)
                .bind(&gone)
                .execute(self.conn())
                .await
                .map_err(StoreError::from_db)?;
        }
        // A part no longer stored shows as its stub, as at `set_bundle_parts`.
        let parts: Vec<i64> = sqlx::query_scalar(
            "DELETE FROM key_bundle_parts WHERE account_id = $1 AND target_app_id = ANY($2) \
             RETURNING seq",
        )
        .bind(&id)
        .bind(&gone)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let parts: Vec<u64> = parts
            .into_iter()
            .map(|seq| from_db(seq, "seq"))
            .collect::<Result<_, _>>()?;
        self.note_superseded(parts);
        let gone: Vec<[u8; 16]> = gone
            .iter()
            .map(|app| app_id(app))
            .collect::<Result<_, _>>()?;
        for app in &gone {
            self.note_app_documents(*app);
        }
        Ok(gone)
    }

    /// What `GET /apps` reports (Switch wire 7.4.12), read under the account's lock.
    pub async fn apps_view(&mut self) -> Result<AppsView, StoreError> {
        let id = self.head().id.clone();
        let mut view = AppsView {
            apps: self.apps().await?,
            ..AppsView::default()
        };
        view.kept = self.kept_entries().await?;
        view.lagging = self.lagging_apps().await?.into_iter().collect();
        for row in sqlx::query(
            "SELECT app_id, last_seen_ms FROM apps WHERE account_id = $1 \
             AND last_seen_ms IS NOT NULL",
        )
        .bind(&id)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?
        {
            let app: Vec<u8> = row.try_get("app_id")?;
            view.last_seen.insert(
                app_id(&app)?,
                from_db(row.try_get("last_seen_ms")?, "last_seen_ms")?,
            );
        }
        for row in
            sqlx::query("SELECT app_id, listed_epoch FROM app_listings WHERE account_id = $1")
                .bind(&id)
                .fetch_all(self.conn())
                .await
                .map_err(StoreError::from_db)?
        {
            let app: Vec<u8> = row.try_get("app_id")?;
            view.listings.insert(
                app_id(&app)?,
                from_db(row.try_get("listed_epoch")?, "listed_epoch")?,
            );
        }
        for row in sqlx::query(
            "SELECT target_app_id, first_epoch, last_epoch, seq FROM key_bundle_parts \
             WHERE account_id = $1 ORDER BY target_app_id, first_epoch",
        )
        .bind(&id)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?
        {
            let app: Vec<u8> = row.try_get("target_app_id")?;
            view.parts.entry(app_id(&app)?).or_default().push(PartSpan {
                first_epoch: from_db(row.try_get("first_epoch")?, "first_epoch")?,
                last_epoch: from_db(row.try_get("last_epoch")?, "last_epoch")?,
                seq: from_db(row.try_get("seq")?, "seq")?,
            });
        }
        // Only claims with an attempt open or unknown name an owner in open_owners.
        for row in sqlx::query(
            "SELECT claim_key, state FROM claims WHERE account_id = $1 \
             AND cardinality(open_owners) > 0 ORDER BY claim_key",
        )
        .bind(&id)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?
        {
            let key: Vec<u8> = row.try_get("claim_key")?;
            let claim_key = <[u8; 32]>::try_from(key.as_slice())
                .map_err(|_| StoreError::Corrupt("claim_key"))?;
            let state: Vec<u8> = row.try_get("state")?;
            let claim = super::claim_codec::decode(&state)?;
            for attempt in &claim.attempts {
                if matches!(attempt.outcome, Outcome::Open | Outcome::Unknown) {
                    view.open_attempts.push(OpenAttempt {
                        claim_key,
                        attempt_id: attempt.attempt_id,
                        owner: attempt.owner,
                        unknown: attempt.outcome == Outcome::Unknown,
                    });
                }
            }
        }
        let (records, entries) = self.kept_proof_generations().await?;
        view.record_generations = records;
        view.claim_entry_generations = entries;
        Ok(view)
    }

    /// The generations the account's kept proofs name (Switch wire 3.3 "Service keys"):
    /// those of each current record's write proof (7.4.9), and those of each live claim's
    /// entry proofs (6.8), each ascending. A record taken from a recovery upload keeps no
    /// proof (7.4.14), so it names none.
    pub async fn kept_proof_generations(&mut self) -> Result<(Vec<u64>, Vec<u64>), StoreError> {
        let id = self.head().id.clone();
        let generation = self.head().generation;
        let records: Vec<i64> = sqlx::query_scalar(
            "SELECT DISTINCT generation FROM shared_records WHERE account_id = $1 \
             AND NOT from_upload ORDER BY generation",
        )
        .bind(&id)
        .fetch_all(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let records = records
            .into_iter()
            .map(|g| from_db(g, "generation"))
            .collect::<Result<Vec<_>, _>>()?;
        // Claim entries are kept for the generation the account serves: every live claim's
        // entry proof names it.
        let live_entries: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM claim_entries e JOIN claims c \
             ON c.account_id = e.account_id AND c.claim_key = e.claim_key \
             WHERE e.account_id = $1 AND NOT c.tombstone)",
        )
        .bind(&id)
        .fetch_one(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        let entries = if live_entries {
            vec![generation]
        } else {
            Vec::new()
        };
        Ok((records, entries))
    }
}
