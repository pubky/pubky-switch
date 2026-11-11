//! The key bundle parts the switch keeps for an app, and the epoch through which the app
//! holds its keys (Switch wire 6.2 `key_bundle.put`, 7.4.12), beside the part checks of
//! [`super::check_key_bundle_put`].

/// A key bundle part the switch stores for an app: its epochs and the `seq` of its
/// `key_bundle.put`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredPart {
    /// Its first data epoch.
    pub first_epoch: u64,
    /// Its last data epoch.
    pub last_epoch: u64,
    /// The `seq` it was stored at.
    pub seq: u64,
}

/// `keys_through` (Switch wire 7.4.12): the newest data epoch through which the app holds
/// every scope key. It starts at `start`, the epoch of the first `identity.json` listing the
/// app, or unknown, and rises to a part's `last_epoch` for each part the app's cursor has
/// passed that starts at most one epoch after what the app holds (or at 1 when that is
/// unknown), the parts taken in `first_epoch` order.
pub fn keys_through(start: Option<u64>, parts: &[StoredPart], cursor: u64) -> Option<u64> {
    let mut passed: Vec<&StoredPart> = parts.iter().filter(|part| part.seq <= cursor).collect();
    passed.sort_by_key(|part| part.first_epoch);
    let mut held = start;
    for part in passed {
        let continues = match held {
            Some(through) => part.first_epoch <= through.saturating_add(1),
            None => part.first_epoch == 1,
        };
        if continues {
            held = Some(held.map_or(part.last_epoch, |through| through.max(part.last_epoch)));
        }
    }
    held
}

/// The indexes of the stored parts that go (Switch wire 6.2): unless a full-bundle request
/// is in force, those the target's cursor has passed and that `keys_through` covers. A
/// request is in force from the `POST /keys` until the target's cursor has passed the part
/// that completed it, or the part that replaced that one; the caller judges it.
pub fn parts_to_drop(
    parts: &[StoredPart],
    cursor: u64,
    keys_through: Option<u64>,
    request_in_force: bool,
) -> Vec<usize> {
    let Some(through) = keys_through.filter(|_| !request_in_force) else {
        return Vec::new();
    };
    parts
        .iter()
        .enumerate()
        .filter(|(_, part)| part.seq <= cursor && part.last_epoch <= through)
        .map(|(index, _)| index)
        .collect()
}

/// Whether the parts cover every data epoch from 1 to `epoch`, which ends a pending
/// full-bundle request (Switch wire 6.2).
pub fn covers(parts: &[StoredPart], epoch: u64) -> bool {
    let mut sorted: Vec<&StoredPart> = parts.iter().collect();
    sorted.sort_by_key(|part| part.first_epoch);
    let mut next = 1u64;
    for part in sorted {
        if part.first_epoch > next {
            break;
        }
        next = next.max(part.last_epoch.saturating_add(1));
    }
    next > epoch
}
