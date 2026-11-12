//! What a recovery upload changed, the app's side (Switch wire 7.4.14, Switch spec 12.6
//! step 3).
//!
//! An upload merges evidence into the switch's state without a chain item for what it
//! changed: a record taken from it has no `record.put` at the service, and a claim it
//! rebuilt or made divergent no entry. Its `upload` transition lists the keys, as the
//! uploader's answer does: every app, the uploader included, reads the transition in its
//! feed and marks each key to read again, in the commit that passes the transition, so a
//! crash loses no mark:
//!
//! - **claims** (`clread/<claim_key>`, as after a stub): read again by
//!   [`App::reread_claims`], which raises [`AppEvent::ClaimChanged`] for a held view the
//!   read changed. A divergent claim is doubtful, so no automatic attempt relies on it
//!   ([`App::claim_doubt`]).
//! - **records** (`rcread/<key>`): read again by [`App::reread_records`] with
//!   `GET /records/{key}`, and taken as any read write is, after the checks of Switch spec
//!   10.3: its version is the service's word, since no proof dates it.
//!
//! A record whose view shows `divergent` is held so (`rcdiv/<key>`, [`SharedRecord::divergent`]):
//! uploads conflict with its current write, which the app still takes as it would any
//! other. It stays so until a view shows it isn't, until the app takes a newer write at the
//! service, its own or one from the feed, which clears the switch's divergent uploads
//! (Switch wire 7.4.14), or until a provider loss, whose new service holds none of them. What to do about it,
//! such as writing the record again, is the protocol's.
//!
//! [`SharedRecord::divergent`]: super::records::SharedRecord::divergent

use pubky_switch_core::enc::{b64, unb64_array};
use pubky_switch_core::http::Retry;
use pubky_switch_core::scopes::Permission;

use super::claims::reread_key;
use super::events::AppEvent;
use super::state::Tx;
use super::{App, AppError};
use crate::error::{ClientError, StoreError};

/// A record the app reads again after an upload listed it (`rcread/<key>`), with when it
/// was marked, device time: the oldest marks go first.
const RECORD_REREAD_PREFIX: &str = "rcread/";
/// A record whose latest view the app read shows divergent uploads (`rcdiv/<key>`).
pub(super) const DIVERGENT_PREFIX: &str = "rcdiv/";

/// The most records one read reads again after an upload listed them. Each is a request of
/// its own (`GET /records/{key}`), so the bound keeps a read's cost and time bounded after
/// an upload that changed many records, as [`super::claims::CLAIM_REREADS_PER_READ`] does
/// for claims. The records past it stay marked, oldest mark first, for the next read.
pub const RECORD_REREADS_PER_READ: usize = 16;

/// The most keys of each kind, records and claims, the app marks for one upload: an
/// `upload` transition names at most 14,742 keys (Switch wire 10.3, the `chain` part's
/// size). A list longer than that comes from no service that keeps the wire's caps, and
/// the keys past it are left unmarked.
const MAX_MARKED_KEYS: usize = 14_742;

/// What one mark takes in a commit, at most: its namespace, key and value.
const MARK_BYTES: u64 = 128;

// The marks of one upload fit the room a feed item has in its read's commit.
const _: () = assert!(2 * (MAX_MARKED_KEYS as u64) * MARK_BYTES <= super::feed::ITEM_ROOM_BYTES);

fn record_reread_key(key: &[u8; 32]) -> String {
    format!("{RECORD_REREAD_PREFIX}{}", b64(key))
}

pub(super) fn divergent_key(key: &[u8; 32]) -> String {
    format!("{DIVERGENT_PREFIX}{}", b64(key))
}

impl App {
    /// Mark for reading again the records and claims an upload changed or made divergent,
    /// from its `upload` transition in the feed (Switch wire 7.4.14), in `tx`.
    /// A key already marked keeps its mark's time. An app without `claims.read` can't read
    /// claims, and marks none; a record it may not read is unmarked when the switch refuses
    /// its read.
    pub(crate) async fn mark_uploaded<'a>(
        &mut self,
        records: impl IntoIterator<Item = &'a [u8; 32]>,
        claims: impl IntoIterator<Item = &'a [u8; 32]>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let at = self.now();
        for key in records.into_iter().take(MAX_MARKED_KEYS) {
            let mark = record_reread_key(key);
            if !self.reader().exists(&mark).await? {
                tx.put(&mark, &at)?;
            }
        }
        if self.state.cert.has_permission(Permission::ClaimsRead) {
            for claim_key in claims.into_iter().take(MAX_MARKED_KEYS) {
                let mark = reread_key(claim_key);
                if !self.reader().exists(&mark).await? {
                    tx.put(&mark, &at)?;
                }
            }
        }
        Ok(())
    }

    /// At the end of a read: read again the records an upload listed (Switch wire 7.4.14),
    /// at most [`RECORD_REREADS_PER_READ`] of them, the oldest marks first, one request
    /// each, and take each view as any read write is. A record read is unmarked in the
    /// commit of what it read, and so is one the switch doesn't know (`404`) or refuses to
    /// read for good, such as one whose read scope the app lacks (`403`). A read that fails
    /// on the network, or that the switch may answer later, stops the reads here, its
    /// record and the rest still marked, and the feed's read still succeeds; an alarm or a
    /// store failure fails it.
    pub(crate) async fn reread_records(&mut self) -> Result<(), AppError> {
        let mut marks = self.reader().scan::<u64>(RECORD_REREAD_PREFIX).await?;
        marks.sort_by(|(a_key, a_at), (b_key, b_at)| a_at.cmp(b_at).then(a_key.cmp(b_key)));
        for (rest, _) in marks.into_iter().take(RECORD_REREADS_PER_READ) {
            let key = unb64_array::<32>(&rest).map_err(|_| AppError::Store(StoreError::Corrupt))?;
            let view = match self.record_view(&key).await {
                Ok(view) => view,
                Err(AppError::Switch(ClientError::Switch { code, .. }))
                    if code.retry() == Retry::No =>
                {
                    None
                }
                Err(AppError::Transport(_) | AppError::Switch(_)) => break,
                Err(error) => return Err(error),
            };
            // A record the app holds is read as its collection, the protocol's or not, as
            // any read of it is; another as the protocol's collections take it.
            let collection = self.held_collection(&key).await?;
            let mut tx = self.tx()?;
            if let Some(view) = view {
                self.take_view(&view, collection.as_ref().map(|c| (&key, c)), &mut tx)
                    .await?;
            }
            tx.delete(&record_reread_key(&key))?;
            self.commit(tx).await?;
        }
        Ok(())
    }

    /// Hold what a record view says of divergent uploads (Switch wire 7.4.9, 7.4.14):
    /// [`AppEvent::RecordDivergent`] once the record becomes divergent, not again while it
    /// stays so.
    pub(crate) async fn note_divergent(
        &mut self,
        key: &[u8; 32],
        divergent: bool,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let mark = divergent_key(key);
        let held = self.reader().exists(&mark).await?;
        if divergent && !held {
            tx.put(&mark, &())?;
            self.events.push(AppEvent::RecordDivergent { key: *key });
        } else if !divergent && held {
            tx.delete(&mark)?;
        }
        Ok(())
    }

    /// Whether the latest view the app read of record `key` shows divergent uploads, not
    /// cleared since.
    pub(crate) async fn is_divergent(&self, key: &[u8; 32]) -> Result<bool, AppError> {
        self.reader().exists(&divergent_key(key)).await
    }
}
