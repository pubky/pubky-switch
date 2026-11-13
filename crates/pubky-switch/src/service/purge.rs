//! The purge of removed apps (Switch wire 9.1 "Departure, revoked app", Switch spec 6.3): a
//! revoked or departed app keeps its record, receive key records, key bundle parts, cursor
//! and last-seen time while the newest `identity.json` lists it in `apps` or `removed`,
//! while its departure awaits its rotation, and while it owns an attempt open or `unknown`.
//! Once none of these holds, they go, at the request that made the last of them false: the
//! `identity.json` delivery that leaves it in neither list, the revocation of an app the
//! newest document lists in neither, or the batch or recovery upload that resolves the last
//! attempt it owned. Its App ID, with its revocation or departure time and its rotation,
//! stays for good, and so do its kids (Switch spec 3.6) ([`AccountTxn::purge_apps`]).

use std::collections::BTreeSet;

use pubky_switch_core::{claims::Claim, records::IdentityDoc};

use super::apps::awaiting_rotation;
use crate::store::{AccountTxn, KeptAppId, StoreError};

/// Whether `kept`, an App ID kept for good, may be purged under `doc`, the newest
/// `identity.json`, the attempts it owns apart (Switch wire 9.1): `doc` lists it in neither
/// `apps` nor `removed`, and its rotation is done. Only a departure awaits one (7.4.12
/// `awaiting_rotation`): the signer revokes, and rotates for its own revocations, and an
/// App ID an enrollment named was never served. Without a document nothing is purged, since
/// no delivery has left the app out.
pub(crate) fn may_purge(kept: &KeptAppId, doc: Option<&IdentityDoc>) -> bool {
    let app = &kept.app_id;
    let in_neither =
        doc.is_some_and(|doc| doc.listed_cert(app).is_none() && !doc.lists_removed(app));
    in_neither && !awaiting_rotation(kept)
}

/// Purge the removed apps that may go under `doc`, the newest `identity.json` after this
/// request (Switch wire 9.1): every App ID kept for good, or only those of `among`, that
/// [`may_purge`] allows and that owns no attempt open or `unknown`. Returns the App IDs
/// purged. At most the App IDs the account keeps are read, a few hundred at most, and one
/// purged before holds nothing and is passed by.
///
/// # Errors
///
/// A [`StoreError`] when the store fails.
pub(super) async fn purge_removed_apps(
    txn: &mut AccountTxn,
    doc: Option<&IdentityDoc>,
    among: Option<&[[u8; 16]]>,
) -> Result<Vec<[u8; 16]>, StoreError> {
    let candidates: Vec<[u8; 16]> = txn
        .kept_entries()
        .await?
        .iter()
        .filter(|kept| among.is_none_or(|among| among.contains(&kept.app_id)))
        .filter(|kept| may_purge(kept, doc))
        .map(|kept| kept.app_id)
        .collect();
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    txn.purge_apps(&candidates).await
}

/// The owners of an attempt open or `unknown` (Switch wire 6.8) on `claim`.
fn open_owners(claim: &Claim) -> impl Iterator<Item = [u8; 16]> + '_ {
    claim
        .attempts
        .iter()
        .filter(|attempt| !claim.tombstone && attempt.outcome.unresolved())
        .map(|attempt| attempt.owner)
}

/// The apps that own an attempt open or `unknown` on one of `before`, the claims a request
/// changes as they were, and none on `after`, the same claims as it leaves them: those whose
/// last such attempt the request may have resolved, so they may be purged now
/// ([`purge_removed_apps`]). The claims the request didn't change are judged by the store.
pub(super) fn released_owners<'a>(
    before: impl IntoIterator<Item = &'a Claim>,
    after: impl IntoIterator<Item = &'a Claim>,
) -> Vec<[u8; 16]> {
    let still: BTreeSet<[u8; 16]> = after.into_iter().flat_map(open_owners).collect();
    before
        .into_iter()
        .flat_map(open_owners)
        .filter(|owner| !still.contains(owner))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use pubky_switch_core::claims::{Attempt, Outcome};

    use super::*;

    fn claim(attempts: &[([u8; 16], Outcome)]) -> Claim {
        Claim {
            attempts: attempts
                .iter()
                .enumerate()
                .map(|(index, (owner, outcome))| Attempt {
                    attempt_id: [u8::try_from(index).unwrap_or_default(); 16],
                    owner: *owner,
                    outcome: *outcome,
                    opened_at: 0,
                    orphan_after: 60,
                    possibly_duplicate: false,
                    duplicate: false,
                    resolved_by: None,
                    from_upload: false,
                })
                .collect(),
            ..Claim::default()
        }
    }

    #[test]
    fn test_purge_released_owner_of_a_resolved_attempt() {
        let before = claim(&[([1; 16], Outcome::Open), ([2; 16], Outcome::Unknown)]);
        let after = claim(&[([1; 16], Outcome::Failed), ([2; 16], Outcome::Unknown)]);
        assert_eq!(released_owners([&before], [&after]), vec![[1; 16]]);
    }

    #[test]
    fn test_purge_no_owner_released_while_an_attempt_stays_open() {
        // Still open on another claim the request changed, or not resolved at all.
        let before = claim(&[([1; 16], Outcome::Open)]);
        let other = claim(&[([1; 16], Outcome::Open)]);
        let resolved = claim(&[([1; 16], Outcome::Done)]);
        assert!(released_owners([&before, &other], [&resolved, &other]).is_empty());
        assert!(released_owners([&before], [&before]).is_empty());
        // A new attempt releases nobody.
        assert!(released_owners([], [&before]).is_empty());
    }
}
