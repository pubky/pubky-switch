//! Delivering `identity.json` to the own switch, and the service keys it must keep (Switch
//! wire 3.3, 7.4.2; Switch spec 4.3).
//!
//! These are the pure rules: the service gives what it holds for the account and gets the
//! answer the wire format fixes, and the signer gets the `service_keys` list it must write.

use super::{IdentityDoc, MAX_SERVICE_KEYS, ServiceKeyEntry};
use crate::error::{Result, invalid};

/// What a service holds for an account, as `PUT /v1/{id}/identity` judges a delivery
/// (Switch wire 3.3).
#[derive(Clone, Copy, Debug)]
pub struct AccountView<'a> {
    /// The newest version held, if any.
    pub held: Option<&'a IdentityDoc>,
    /// The app limit announced at enrollment.
    pub app_limit: u64,
    /// Whether the account is staged: the newest document doesn't name it yet.
    pub staged: bool,
    /// The service's origin.
    pub origin: &'a str,
    /// The pending key of the next generation an enrollment here answered, if any.
    pub pending_key: Option<[u8; 32]>,
    /// The App IDs the service revoked or saw depart, and those enrollments named, kept for
    /// good.
    pub kept_app_ids: &'a [[u8; 16]],
    /// The kept proofs: each generation that some current record's or live claim's entry's
    /// kept proof names, with the key that verifies those proofs.
    pub kept_proofs: KeptProofs<'a>,
}

/// The transition proofs a switch keeps that are checked with their generation's service key
/// (Switch wire 3.3, "Service keys"): the proof of each current record's write (Switch wire
/// 7.4.9) and the proof of each entry of a live claim (Switch wire 6.8). Each kind is given
/// as the generations its proofs name, with the key that verifies them; a generation may
/// appear in both, and more than once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeptProofs<'a> {
    /// Each generation some current record's kept proof names, with its key.
    pub records: &'a [(u64, [u8; 32])],
    /// Each generation some live claim's entry proof names, with its key.
    pub claim_entries: &'a [(u64, [u8; 32])],
}

impl KeptProofs<'_> {
    /// Every kept proof's generation and key, records' first.
    fn all(&self) -> impl Iterator<Item = &(u64, [u8; 32])> {
        self.records.iter().chain(self.claim_entries)
    }

    /// The generations whose service keys a document must keep (Switch wire 3.3, 7.4.12):
    /// those some kept proof names, less the ones `recovery_from` declares lost, ascending,
    /// each once. This is the `proof_generations` that `GET /apps` reports.
    pub fn generations(&self, recovery_from: Option<u64>) -> Vec<u64> {
        without_lost(self.all().map(|(g, _)| *g), recovery_from)
    }
}

/// How a generation change is taken at the service (Switch wire 3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationChange {
    /// At a staged account: the move to this service.
    Staged,
    /// In place, without `recovery_from` naming the ending generation: a service key
    /// rotation. The sequence and chain continue under the new key.
    KeyRotation,
    /// In place, with `recovery_from` naming the ending generation: a provider loss at the
    /// same service. The account starts afresh.
    ProviderLoss,
}

/// A delivery the service takes (Switch wire 3.3, 7.4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// A new version, which the service chains; with the generation change it makes, if any.
    New(Option<GenerationChange>),
    /// The newest version's bytes again: success without a new chain item, answered with the
    /// original delivery's transition proof.
    Retry,
}

/// A delivery the service refuses (Switch wire 3.3, 7.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeliveryRefusal {
    /// `400 bad_request`, with the rule.
    BadRequest(&'static str),
    /// `409 stale_identity`, with the rule; the answer carries the copy the service holds.
    StaleIdentity(&'static str),
    /// `409 conflict`: the document leaves out the service keys of these generations, which
    /// the answer's `current.proof_generations` names, ascending.
    Conflict {
        /// The generations left out.
        proof_generations: Vec<u64>,
    },
}

impl std::fmt::Display for DeliveryRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeliveryRefusal::BadRequest(why) => write!(f, "400 bad_request: {why}"),
            DeliveryRefusal::StaleIdentity(why) => write!(f, "409 stale_identity: {why}"),
            DeliveryRefusal::Conflict { .. } => {
                f.write_str("409 conflict: Switch wire 3.3: a needed service key is left out")
            }
        }
    }
}

/// Judge a verified delivery of `doc`, naming `prev` as the version it builds on, by the
/// rules the service enforces at `PUT /identity`, in their order (Switch wire 3.3). The
/// caller has verified `doc` for the account's identity.
///
/// # Errors
///
/// The [`DeliveryRefusal`] of the first rule that fails.
pub fn check_delivery(
    account: &AccountView<'_>,
    doc: &IdentityDoc,
    prev: Option<&[u8; 32]>,
) -> std::result::Result<Delivery, DeliveryRefusal> {
    let body = doc.body();
    if u64::try_from(body.apps.len()).unwrap_or(u64::MAX) > account.app_limit {
        return Err(DeliveryRefusal::BadRequest(
            "Switch wire 3.3: more apps than the app limit",
        ));
    }
    if let Err(left_out) = check_kept_service_keys(doc, &account.kept_proofs) {
        return Err(DeliveryRefusal::Conflict {
            proof_generations: left_out,
        });
    }
    let Some(held) = account.held else {
        if doc.check_first().is_err() {
            return Err(DeliveryRefusal::BadRequest(
                "Switch wire 3.3: a first document has version, generation and data_epoch 1, \
                 or recovery_from",
            ));
        }
        if prev.is_some() {
            return Err(DeliveryRefusal::StaleIdentity(
                "Switch wire 3.3: the account holds no version, so prev is null",
            ));
        }
        return Ok(Delivery::New(None));
    };
    if held.signed() == doc.signed() {
        return Ok(Delivery::Retry);
    }
    if prev != Some(&held.hash()) {
        return Err(DeliveryRefusal::StaleIdentity(
            "Switch wire 3.3: prev isn't the newest version held",
        ));
    }
    let (held_body, held_generation) = (held.body(), held.generation());
    if body.version <= held_body.version || body.generation < held_generation {
        return Err(DeliveryRefusal::StaleIdentity(
            "Switch wire 3.3: not a higher version at no lower generation",
        ));
    }
    let change = if body.generation == held_generation {
        None
    } else if account.staged {
        Some(GenerationChange::Staged)
    } else if Some(body.generation) == held_generation.checked_add(1)
        && body.inbox.url == account.origin
        && Some(body.inbox.service_key) == account.pending_key
    {
        if body.recovery_from == Some(held_generation) {
            Some(GenerationChange::ProviderLoss)
        } else {
            Some(GenerationChange::KeyRotation)
        }
    } else {
        return Err(DeliveryRefusal::BadRequest(
            "Switch wire 3.3: a new generation that this account can't take",
        ));
    };
    for app in &body.apps {
        if held.lists_removed(&app.app_id) {
            return Err(DeliveryRefusal::BadRequest(
                "Switch wire 3.3: apps lists an App ID the version held lists in removed",
            ));
        }
        if account.kept_app_ids.contains(&app.app_id) && held.listed_cert(&app.app_id).is_none() {
            return Err(DeliveryRefusal::BadRequest(
                "Switch wire 3.3: apps lists an App ID the service revoked or saw depart",
            ));
        }
    }
    Ok(Delivery::New(change))
}

/// The generations a document must keep the service key of (Switch wire 3.3, 7.4.12), the
/// `proof_generations` that `GET /apps` reports: those some current record's kept proof names
/// (`records`) and those some live claim's entry proof names (`claim_entries`), less the ones
/// `recovery_from` declares lost (it and earlier), ascending, each once.
pub fn needed_generations(
    records: &[u64],
    claim_entries: &[u64],
    recovery_from: Option<u64>,
) -> Vec<u64> {
    without_lost(records.iter().chain(claim_entries).copied(), recovery_from)
}

/// `generations` less the ones `recovery_from` declares lost, ascending, each once.
fn without_lost(generations: impl Iterator<Item = u64>, recovery_from: Option<u64>) -> Vec<u64> {
    let mut out: Vec<u64> = generations
        .filter(|g| recovery_from.is_none_or(|lost| *g > lost))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The service's check of the kept service keys (Switch wire 3.3): the document gives, in
/// `inbox.service_key` or `service_keys`, the key that verifies the kept proofs of every
/// generation they name, current records' and live claims' entries' alike, except those it
/// declares lost. A generation counts as left out unless every kept proof of it verifies
/// with the key the document gives for it.
///
/// # Errors
///
/// The generations left out, ascending, for the `409 conflict` answer's
/// `current.proof_generations`.
pub fn check_kept_service_keys(
    doc: &IdentityDoc,
    kept: &KeptProofs<'_>,
) -> std::result::Result<(), Vec<u64>> {
    let left_out: Vec<u64> = kept
        .generations(doc.body().recovery_from)
        .into_iter()
        .filter(|g| {
            let given = doc.service_key_of(*g);
            kept.all()
                .any(|(x, key)| x == g && given.as_ref() != Some(key))
        })
        .collect();
    if left_out.is_empty() {
        Ok(())
    } else {
        Err(left_out)
    }
}

/// The `service_keys` a signer writes in the document that starts generation `new`, at a
/// move or a key change in place (Switch wire 3.3, "Service keys").
///
/// With the switch's latest `proof_generations` report, it lists the key of every reported
/// generation other than `new`, and drops the others. Without a report it drops nothing: it
/// keeps every key of `held_list` and adds `outgoing`, the outgoing generation and its key.
/// Generations `recovery_from` declares lost are left out either way. `keys` are the other
/// service keys the signer holds, by generation.
///
/// # Errors
///
/// [`crate::Error::Invalid`] if the list would need more than 256 entries, or a reported
/// generation's key the signer doesn't hold: the move or key change is refused, and the user
/// shown why.
pub fn signer_service_keys(
    report: Option<&[u64]>,
    held_list: &[ServiceKeyEntry],
    outgoing: ServiceKeyEntry,
    keys: &[ServiceKeyEntry],
    new: u64,
    recovery_from: Option<u64>,
) -> Result<Vec<ServiceKeyEntry>> {
    let key_of = |generation: u64| {
        keys.iter()
            .chain(held_list)
            .chain(std::iter::once(&outgoing))
            .find(|k| k.generation == generation)
            .map(|k| k.key)
    };
    let generations: Vec<u64> = match report {
        Some(reported) => reported.iter().copied().filter(|g| *g != new).collect(),
        None => held_list
            .iter()
            .map(|k| k.generation)
            .chain(std::iter::once(outgoing.generation))
            .collect(),
    };
    let generations = without_lost(generations.into_iter(), recovery_from);
    if generations.len() > MAX_SERVICE_KEYS {
        return invalid("Switch wire 3.3: the move or key change needs more than 256 service keys");
    }
    generations
        .into_iter()
        .map(|generation| match key_of(generation) {
            Some(key) => Ok(ServiceKeyEntry { generation, key }),
            None => invalid(
                "Switch wire 3.3: the move or key change needs a service key the signer doesn't \
                 hold",
            ),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::fixtures::{app, identity, other_app};
    use crate::records::{IdentityBody, IdentityPolicy, Inbox, ListedApp, RemovedApp};

    const ORIGIN: &str = "https://inbox.example";

    fn body(version: u64) -> IdentityBody {
        let mut b = IdentityBody::first(
            identity().public(),
            [7; 16],
            Inbox::new(ORIGIN, [8; 32]),
            IdentityPolicy::default(),
        );
        b.version = version;
        b.apps.push(ListedApp {
            app_id: app().app_id_bytes(),
            cert: [1; 32],
        });
        b
    }

    fn sign(b: IdentityBody) -> IdentityDoc {
        IdentityDoc::sign(&identity(), b).unwrap()
    }

    fn account<'a>(held: Option<&'a IdentityDoc>) -> AccountView<'a> {
        AccountView {
            held,
            app_limit: 32,
            staged: false,
            origin: ORIGIN,
            pending_key: Some([9; 32]),
            kept_app_ids: &[],
            kept_proofs: KeptProofs::default(),
        }
    }

    #[test]
    fn test_delivery_first_document() {
        let v1 = sign(body(1));
        assert_eq!(
            check_delivery(&account(None), &v1, None),
            Ok(Delivery::New(None))
        );
        assert!(matches!(
            check_delivery(&account(None), &v1, Some(&[0; 32])),
            Err(DeliveryRefusal::StaleIdentity(_))
        ));
        assert!(matches!(
            check_delivery(&account(None), &sign(body(3)), None),
            Err(DeliveryRefusal::BadRequest(_))
        ));
    }

    #[test]
    fn test_delivery_compare_and_swap() {
        let (v1, v2) = (sign(body(1)), sign(body(2)));
        let at_v1 = account(Some(&v1));
        assert_eq!(
            check_delivery(&at_v1, &v2, Some(&v1.hash())),
            Ok(Delivery::New(None))
        );
        // The same bytes again are a retry, whatever prev they name.
        assert_eq!(check_delivery(&at_v1, &v1, None), Ok(Delivery::Retry));
        for prev in [None, Some(v2.hash())] {
            assert!(matches!(
                check_delivery(&at_v1, &v2, prev.as_ref()),
                Err(DeliveryRefusal::StaleIdentity(_))
            ));
        }
        let at_v2 = account(Some(&v2));
        assert!(matches!(
            check_delivery(&at_v2, &v1, Some(&v2.hash())),
            Err(DeliveryRefusal::StaleIdentity(_))
        ));
    }

    #[test]
    fn test_delivery_app_limit() {
        let v1 = sign(body(1));
        let mut tight = account(None);
        tight.app_limit = 0;
        assert!(matches!(
            check_delivery(&tight, &v1, None),
            Err(DeliveryRefusal::BadRequest(_))
        ));
    }

    #[test]
    fn test_delivery_generation_changes() {
        let v1 = sign(body(1));
        let mut next = body(2);
        next.generation = 2;
        next.inbox.service_key = [9; 32];
        let rotation = sign(next.clone());
        assert_eq!(
            check_delivery(&account(Some(&v1)), &rotation, Some(&v1.hash())),
            Ok(Delivery::New(Some(GenerationChange::KeyRotation)))
        );
        next.recovery_from = Some(1);
        assert_eq!(
            check_delivery(&account(Some(&v1)), &sign(next.clone()), Some(&v1.hash())),
            Ok(Delivery::New(Some(GenerationChange::ProviderLoss)))
        );
        let mut other_key = next.clone();
        other_key.inbox.service_key = [5; 32];
        assert!(matches!(
            check_delivery(
                &account(Some(&v1)),
                &sign(other_key.clone()),
                Some(&v1.hash())
            ),
            Err(DeliveryRefusal::BadRequest(_))
        ));
        let mut staged = account(Some(&v1));
        staged.staged = true;
        assert_eq!(
            check_delivery(&staged, &sign(other_key), Some(&v1.hash())),
            Ok(Delivery::New(Some(GenerationChange::Staged)))
        );
        let mut skip = body(2);
        skip.generation = 3;
        skip.inbox.service_key = [9; 32];
        assert!(matches!(
            check_delivery(&account(Some(&v1)), &sign(skip), Some(&v1.hash())),
            Err(DeliveryRefusal::BadRequest(_))
        ));
    }

    #[test]
    fn test_delivery_refuses_removed_and_kept_app_ids() {
        let gone = other_app().app_id_bytes();
        let mut held = body(1);
        held.removed.push(RemovedApp {
            app_id: gone,
            distrust_from: 0,
        });
        let v1 = sign(held);
        let mut back = body(2);
        back.apps.push(ListedApp {
            app_id: gone,
            cert: [2; 32],
        });
        let back = sign(back);
        assert!(matches!(
            check_delivery(&account(Some(&v1)), &back, Some(&v1.hash())),
            Err(DeliveryRefusal::BadRequest(_))
        ));
        // After a purge, the kept App ID alone refuses it.
        let purged = sign(body(1));
        let kept = [gone];
        let mut view = account(Some(&purged));
        view.kept_app_ids = &kept;
        assert!(matches!(
            check_delivery(&view, &back, Some(&purged.hash())),
            Err(DeliveryRefusal::BadRequest(_))
        ));
        // Unless the version held still lists it, a departure awaiting its rotation.
        let wallet = [app().app_id_bytes()];
        view.kept_app_ids = &wallet;
        check_delivery(&view, &sign(body(2)), Some(&purged.hash())).unwrap();
    }

    /// Kept proofs of current records only.
    fn records(keys: &[(u64, [u8; 32])]) -> KeptProofs<'_> {
        KeptProofs {
            records: keys,
            claim_entries: &[],
        }
    }

    #[test]
    fn test_kept_service_keys() {
        let mut next = body(7);
        next.generation = 2;
        next.service_keys = vec![ServiceKeyEntry {
            generation: 1,
            key: [8; 32],
        }];
        let doc = sign(next.clone());
        check_kept_service_keys(&doc, &records(&[(1, [8; 32]), (2, [8; 32])])).unwrap();
        assert_eq!(
            check_kept_service_keys(&doc, &records(&[(1, [6; 32])])),
            Err(vec![1])
        );
        next.service_keys.clear();
        let without = sign(next.clone());
        assert_eq!(
            check_kept_service_keys(&without, &records(&[(1, [8; 32])])),
            Err(vec![1])
        );
        next.recovery_from = Some(1);
        check_kept_service_keys(&sign(next), &records(&[(1, [8; 32])]))
            .expect("a lost generation is exempt");
        let kept = [(1, [8; 32])];
        let view = AccountView {
            kept_proofs: records(&kept),
            ..account(None)
        };
        assert_eq!(
            check_delivery(&view, &without, None),
            Err(DeliveryRefusal::Conflict {
                proof_generations: vec![1]
            })
        );
    }

    #[test]
    fn test_kept_service_keys_claim_entries() {
        let mut next = body(7);
        next.generation = 2;
        next.service_keys = vec![ServiceKeyEntry {
            generation: 1,
            key: [8; 32],
        }];
        let doc = sign(next.clone());
        // A live claim's entry proof of generation 1, with no record's: its key is kept.
        let entries = [(1, [8; 32])];
        let kept = KeptProofs {
            records: &[],
            claim_entries: &entries,
        };
        assert_eq!(kept.generations(None), vec![1]);
        check_kept_service_keys(&doc, &kept).unwrap();
        next.service_keys.clear();
        let without = sign(next.clone());
        assert_eq!(check_kept_service_keys(&without, &kept), Err(vec![1]));
        let view = AccountView {
            kept_proofs: kept,
            ..account(None)
        };
        assert_eq!(
            check_delivery(&view, &without, None),
            Err(DeliveryRefusal::Conflict {
                proof_generations: vec![1]
            })
        );
        // A record's proof and an entry's of one generation must both verify with its key.
        let records = [(1, [8; 32])];
        let other = [(1, [6; 32])];
        let split = KeptProofs {
            records: &records,
            claim_entries: &other,
        };
        assert_eq!(check_kept_service_keys(&doc, &split), Err(vec![1]));
    }

    #[test]
    fn test_needed_generations_cover_claim_entries() {
        // Records' and live claims' entries' generations together, ascending, each once.
        assert_eq!(needed_generations(&[3, 2], &[1, 3], None), vec![1, 2, 3]);
        assert_eq!(needed_generations(&[], &[2], None), vec![2]);
        // Generations recovery_from declares lost are left out, an entry's too.
        assert_eq!(needed_generations(&[3], &[1, 2], Some(2)), vec![3]);
        assert!(needed_generations(&[], &[1], Some(1)).is_empty());
    }

    #[test]
    fn test_signer_service_keys() {
        let entry = |generation: u64| ServiceKeyEntry {
            generation,
            key: [generation as u8; 32],
        };
        let outgoing = entry(2);
        // With a report: exactly the reported generations other than the new one.
        assert_eq!(
            signer_service_keys(Some(&[1, 3]), &[entry(1)], outgoing, &[], 3, None).unwrap(),
            vec![entry(1)]
        );
        assert_eq!(
            signer_service_keys(Some(&[]), &[entry(1)], outgoing, &[], 3, None).unwrap(),
            vec![]
        );
        // Without a report: nothing dropped, the outgoing key added.
        assert_eq!(
            signer_service_keys(None, &[entry(1)], outgoing, &[], 3, None).unwrap(),
            vec![entry(1), entry(2)]
        );
        // Lost generations are left out.
        assert_eq!(
            signer_service_keys(None, &[entry(1)], outgoing, &[], 3, Some(1)).unwrap(),
            vec![entry(2)]
        );
        // A reported key it doesn't hold, or too many, refuses the change.
        assert!(signer_service_keys(Some(&[5]), &[], outgoing, &[], 6, None).is_err());
        let many: Vec<u64> = (1..=257).collect();
        let keys: Vec<ServiceKeyEntry> = many.iter().map(|g| entry(*g)).collect();
        assert!(signer_service_keys(Some(&many), &[], outgoing, &keys, 300, None).is_err());
    }
}
