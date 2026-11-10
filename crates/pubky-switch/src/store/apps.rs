//! What `GET /apps` reads of an account (Switch wire 7.4.12): its apps' rows, the App IDs it
//! keeps for good, when each app was first listed, the key bundle parts, the open attempts
//! and the generations its kept proofs name.

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
    /// enrollment's, and for one kept before the service recorded it.
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
/// its data epoch (Switch wire 7.4.12). An app already recorded keeps its first epoch.
pub(super) async fn note_listings(
    conn: &mut sqlx::PgConnection,
    account: &str,
    apps: &[[u8; 16]],
    epoch: u64,
) -> Result<(), StoreError> {
    for app in apps {
        // An app the account holds anything of was listed before: by a document from before
        // app_listings existed, if it has no row. Its first epoch is unknown, never this one.
        sqlx::query(
            "INSERT INTO app_listings (account_id, app_id, listed_epoch) \
             SELECT $1, $2, $3 WHERE NOT EXISTS \
                 (SELECT 1 FROM apps WHERE account_id = $1 AND app_id = $2) \
             AND NOT EXISTS \
                 (SELECT 1 FROM key_bundle_parts WHERE account_id = $1 AND target_app_id = $2) \
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
    /// Record that the document this request takes lists `apps` for the first time, at
    /// data epoch `epoch` (Switch wire 7.4.12 `keys_through`).
    pub async fn note_listings(&mut self, apps: &[[u8; 16]], epoch: u64) -> Result<(), StoreError> {
        let id = self.head().id.clone();
        note_listings(self.conn(), &id, apps, epoch).await
    }

    /// Note the rotations `doc` makes: each departed app it lists in `removed` at a data epoch
    /// above the one at its departure (Switch wire 7.4.12 `awaiting_rotation`). An App ID
    /// kept without that epoch counts any.
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
             AND (data_epoch IS NULL OR data_epoch < $3)",
        )
        .bind(id)
        .bind(removed)
        .bind(to_db(epoch, "data_epoch")?)
        .execute(self.conn())
        .await
        .map_err(StoreError::from_db)?;
        Ok(())
    }

    /// What `GET /apps` reports (Switch wire 7.4.12), read under the account's lock.
    pub async fn apps_view(&mut self) -> Result<AppsView, StoreError> {
        let id = self.head().id.clone();
        let mut view = AppsView {
            apps: self.apps().await?,
            ..AppsView::default()
        };
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
            view.kept.push(KeptAppId {
                app_id: app_id(&app)?,
                reason: reason(&reason_text)?,
                at_ms: from_db(row.try_get("at_ms")?, "at_ms")?,
                data_epoch: data_epoch.map(|e| from_db(e, "data_epoch")).transpose()?,
                rotated: row.try_get("rotated")?,
            });
        }
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
    /// entry proofs (6.8), each ascending.
    pub async fn kept_proof_generations(&mut self) -> Result<(Vec<u64>, Vec<u64>), StoreError> {
        let id = self.head().id.clone();
        let generation = self.head().generation;
        let records: Vec<i64> = sqlx::query_scalar(
            "SELECT DISTINCT generation FROM shared_records WHERE account_id = $1 \
             ORDER BY generation",
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
