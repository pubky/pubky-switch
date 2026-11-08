//! `identity.json` copies (Switch spec 4.3; Switch wire 3.3): the app's own and its
//! senders'.
//!
//! For every identity the app keeps the newest copy it took, from any source (the
//! approval, its switch's feed and directory, the Homeserver), the version and generation
//! floor, and the hash of every body it saw by version:
//!
//! - a copy below the floor is ignored: readers use the higher version;
//! - another body at a version seen is equivocation. For the own identity it is an alarm
//!   that stops the app; for a sender it is an alert, and the app takes nothing more from
//!   that identity;
//! - an own copy that lists again an App ID an earlier version removed is an alarm too.
//!
//! The Homeserver is read through [`HomeserverReader`], one method, so tests can fake it.
//! The Pubky implementation (a `PublicStorage` read of
//! `/pub/pubky-switch/v1/identity.json`) belongs to the host's Pubky integration and isn't
//! part of this crate yet.

use pubky_switch_core::records::{IDENTITY_PATH, IdentityDoc, VersionOrder};
use pubky_switch_core::sig::SignedDoc;

use super::error::{Alarm, AppError};
use super::state::{CachedDoc, Floor, Reader, Tx, key};
use crate::error::TransportError;
use crate::transport::BoxFuture;

/// How long a sender's `identity.json` copy is used without reading it again: 10 minutes
/// (Switch spec 4.3, "Caching for verification and use").
pub const DOC_CACHE_MS: u64 = 10 * 60_000;

/// Reads a public file of an identity's Homeserver.
///
/// Object-safe; the app holds an `Arc<dyn HomeserverReader>`. The host implements it on its
/// Pubky client; tests fake it.
pub trait HomeserverReader: Send + Sync {
    /// The bytes at `path` on `identity`'s Homeserver, `None` when there is no such file.
    ///
    /// # Errors
    ///
    /// A [`TransportError`] when the Homeserver can't be read now.
    fn get(
        &self,
        identity: [u8; 32],
        path: String,
    ) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>>;
}

/// What taking a copy did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Taken {
    /// A newer copy, now the one held.
    Newer,
    /// The copy held already, or the same body.
    Same,
    /// Below the floor: ignored.
    Older,
}

/// Another body at a version seen (Switch wire 3.3 "Equivocation").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Equivocation {
    pub(crate) version: u64,
}

/// Take a verified copy of `doc`'s identity against what the store holds for it, and add
/// the records it changes to `tx`. `held` is the newest copy held, if any.
///
/// # Errors
///
/// [`Equivocation`] for another body at a version seen; nothing is written then but the
/// mark.
pub(crate) async fn take_copy(
    reader: &Reader,
    tx: &mut Tx,
    doc: &IdentityDoc,
    held: Option<&IdentityDoc>,
    now_ms: u64,
) -> Result<Result<Taken, Equivocation>, AppError> {
    let identity = doc.identity();
    let version = doc.version();
    if let Some(seen) = reader
        .get::<String>(&key::ident_body(&identity, version))
        .await?
        && seen != pubky_switch_core::enc::b64(&doc.body_hash())
    {
        tx.put(&key::ident_equivocated(&identity), &version)?;
        return Ok(Err(Equivocation { version }));
    }
    if let Some(held) = held {
        match held.compare(doc) {
            VersionOrder::Equivocation => {
                tx.put(&key::ident_equivocated(&identity), &version)?;
                return Ok(Err(Equivocation { version }));
            }
            VersionOrder::Same | VersionOrder::SameBody => return Ok(Ok(Taken::Same)),
            VersionOrder::Older => return Ok(Ok(Taken::Older)),
            VersionOrder::Newer => {}
        }
    }
    let floor = reader
        .get::<Floor>(&key::ident_floor(&identity))
        .await?
        .unwrap_or_default();
    if version < floor.version || doc.generation() < floor.generation {
        return Ok(Ok(Taken::Older));
    }
    tx.put(
        &key::ident_body(&identity, version),
        &pubky_switch_core::enc::b64(&doc.body_hash()),
    )?;
    tx.put(
        &key::ident_floor(&identity),
        &Floor {
            version: version.max(floor.version),
            generation: doc.generation().max(floor.generation),
        },
    )?;
    tx.put(
        &key::ident_doc(&identity),
        &CachedDoc {
            doc: doc.signed().clone(),
            fetched_ms: now_ms,
        },
    )?;
    Ok(Ok(Taken::Newer))
}

/// The newest copy held for `identity`, verified, with when it was read.
pub(crate) async fn held_copy(
    reader: &Reader,
    identity: &[u8; 32],
) -> Result<Option<(IdentityDoc, u64)>, AppError> {
    let Some(cached) = reader.get::<CachedDoc>(&key::ident_doc(identity)).await? else {
        return Ok(None);
    };
    let doc = IdentityDoc::verify(&cached.doc, identity)
        .map_err(|_| AppError::Store(crate::error::StoreError::Corrupt))?;
    Ok(Some((doc, cached.fetched_ms)))
}

/// Read `identity`'s `identity.json` from its Homeserver: `Ok(None)` when it publishes
/// none, an error when it can't be read or doesn't verify.
pub(crate) async fn read_homeserver(
    homeserver: &dyn HomeserverReader,
    identity: &[u8; 32],
) -> Result<Option<IdentityDoc>, AppError> {
    let Some(bytes) = homeserver.get(*identity, IDENTITY_PATH.to_owned()).await? else {
        return Ok(None);
    };
    let signed: SignedDoc = pubky_switch_core::json::parse_json(&bytes)?;
    Ok(Some(IdentityDoc::verify(&signed, identity)?))
}

/// The checks of a newer own copy beyond the floor (Switch spec 4.3): it may follow the
/// copy held, and lists no App ID the held copy removed.
pub(crate) fn check_own_successor(held: &IdentityDoc, newer: &IdentityDoc) -> Result<(), Alarm> {
    held.check_successor(newer)
        .map_err(|error| Alarm::IdentityRollback {
            reason: error.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MemoryStore, StoreHandle};
    use pubky_switch_core::keys::IdentityKey;
    use pubky_switch_core::records::{IdentityBody, IdentityPolicy, Inbox, ListedApp, RemovedApp};
    use std::sync::Arc;

    fn doc(version: u64, change: impl Fn(&mut IdentityBody)) -> IdentityDoc {
        let key = IdentityKey::from_secret([1; 32]);
        let mut body = IdentityBody::first(
            key.public(),
            [0; 16],
            Inbox::new("https://switch.example", [9; 32]),
            IdentityPolicy::default(),
        );
        body.version = version;
        change(&mut body);
        IdentityDoc::sign(&key, body).unwrap()
    }

    fn reader() -> (Reader, StoreHandle) {
        let store = StoreHandle::inline(Arc::new(MemoryStore::new()));
        (
            Reader {
                ns: "client/a".into(),
                store: store.clone(),
            },
            store,
        )
    }

    async fn take(
        reader: &Reader,
        store: &StoreHandle,
        d: &IdentityDoc,
    ) -> Result<Taken, Equivocation> {
        let held = held_copy(reader, &d.identity())
            .await
            .unwrap()
            .map(|(d, _)| d);
        let mut tx = Tx::new("client/a");
        let taken = take_copy(reader, &mut tx, d, held.as_ref(), 1)
            .await
            .unwrap();
        tx.commit(store).await.unwrap();
        taken
    }

    #[tokio::test]
    async fn test_take_copy_keeps_the_newest_and_ignores_older() {
        let (reader, store) = reader();
        let v1 = doc(1, |_| {});
        let v2 = doc(2, |_| {});
        assert!(matches!(take(&reader, &store, &v1).await, Ok(Taken::Newer)));
        assert!(matches!(take(&reader, &store, &v2).await, Ok(Taken::Newer)));
        assert_eq!(take(&reader, &store, &v1).await, Ok(Taken::Older));
        assert_eq!(take(&reader, &store, &v2).await, Ok(Taken::Same));
        let held = held_copy(&reader, &v2.identity()).await.unwrap().unwrap();
        assert_eq!(held.0.version(), 2);
    }

    #[tokio::test]
    async fn test_take_copy_finds_equivocation_even_below_the_newest() {
        let (reader, store) = reader();
        let v1 = doc(1, |_| {});
        let v2 = doc(2, |_| {});
        take(&reader, &store, &v1).await.unwrap();
        take(&reader, &store, &v2).await.unwrap();
        // Another body at version 1, seen after version 2: still equivocation.
        let other = doc(1, |b| {
            b.removed.push(RemovedApp {
                app_id: [3; 16],
                distrust_from: 5,
            })
        });
        assert_eq!(
            take(&reader, &store, &other).await,
            Err(Equivocation { version: 1 })
        );
        assert!(
            reader
                .exists(&key::ident_equivocated(&v1.identity()))
                .await
                .unwrap()
        );
    }

    #[test]
    fn test_own_successor_refuses_a_removed_app_listed_again() {
        let removed = doc(2, |b| {
            b.removed.push(RemovedApp {
                app_id: [3; 16],
                distrust_from: 5,
            })
        });
        let listed_again = doc(3, |b| {
            b.apps.push(ListedApp {
                app_id: [3; 16],
                cert: [4; 32],
            })
        });
        assert!(check_own_successor(&removed, &listed_again).is_err());
        assert!(check_own_successor(&removed, &doc(3, |_| {})).is_ok());
    }
}
