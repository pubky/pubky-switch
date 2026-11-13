//! The certificate check order and renewal (Switch wire 3.8, Switch spec 3.2 and 3.4): the
//! checks that need only what a caller presents, and the pure rules of renewals, reductions
//! and their closing.

use super::{AppCert, CLOCK_TOLERANCE_MS, IdentityDoc};
use crate::scopes;
use crate::sig::SignedDoc;

/// Why a presented certificate fails checks 1 to 3 of Switch wire 3.8.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckFailure {
    /// Check 1 or 2: it doesn't verify for the identity, names another identity or app, or
    /// another key than the one the request, message or record is checked with. The service
    /// answers `401 bad_signature`; a recipient drops the message, a sender skips the app.
    BadSignature(String),
    /// Check 3: it has expired at the checker's time. The service answers `403 cert_expired`.
    Expired,
}

/// Checks 1 to 3 of Switch wire 3.8, which need only what the caller presents and a clock:
/// the certificate verifies for `identity` (1); it names `app_id` when the caller names one,
/// and `signing_key` is the key the request, message or record is checked with (2); and it
/// hasn't expired at `at`, the service's time for a request, the entry's `accepted_at` for a
/// message, the reader's clock for sending or for acting on a record (3). With `at` `None`
/// check 3 is left to the caller, as the service does for an app of another identity, which
/// it checks after check 4 ([`AppCert::expired_at`]).
///
/// Check 4, the request's, message's or record's own signature, comes next and is the
/// caller's; check 5 is [`IdentityDoc::standing`] and check 6 [`super::AppRecord::carries`].
///
/// # Errors
///
/// The [`CheckFailure`] of the first check that fails.
pub fn check_presented(
    signed: &SignedDoc,
    identity: &[u8; 32],
    app_id: Option<&[u8; 16]>,
    signing_key: &[u8; 32],
    at: Option<u64>,
) -> Result<AppCert, CheckFailure> {
    let cert = AppCert::verify(signed, identity)
        .map_err(|error| CheckFailure::BadSignature(error.to_string()))?;
    if app_id.is_some_and(|id| id != &cert.app_id()) {
        return Err(CheckFailure::BadSignature(
            "Switch wire 3.8 check 2: the certificate names another app".into(),
        ));
    }
    if &cert.signing_key() != signing_key {
        return Err(CheckFailure::BadSignature(
            "Switch wire 3.8 check 2: another key than the certificate's".into(),
        ));
    }
    if at.is_some_and(|t| cert.expired_at(t)) {
        return Err(CheckFailure::Expired);
    }
    Ok(cert)
}

/// Whether `new` renews `old` (Switch wire 3.8, "Renewal"): the same App ID, signing key and
/// bundle key, and a later `issued_at`. Other keys make a new app.
pub fn is_renewal(old: &AppCert, new: &AppCert) -> bool {
    old.same_app_and_keys(new) && new.issued_at() > old.issued_at()
}

/// Whether a renewal from `old` to `new` is a reduction (Switch wire 3.8, "Reductions"): the
/// new certificate lacks a scope of the earlier one, by the scope hierarchy, or one of its
/// switch permissions, or it expires earlier. Its cutoff doesn't wait for the app.
pub fn is_reduction(old: &AppCert, new: &AppCert) -> bool {
    old.scopes().iter().any(|s| !scopes::holds(new.scopes(), s))
        || old.permissions().iter().any(|p| !new.has_permission(*p))
        || new.expires_at() < old.expires_at()
}

/// Whether a renewal rotates the data epoch (Switch wire 3.8, "A removed scope's keys
/// rotate"): the new certificate lacks, by the scope hierarchy, a scope of the earlier one
/// that has keys. Which scopes have keys is the protocol's choice, `has_keys`. Removing only
/// scopes without keys, a switch permission or expiry rotates nothing. Such a renewal is
/// always a reduction.
pub fn reduction_rotates(old: &AppCert, new: &AppCert, has_keys: impl Fn(&str) -> bool) -> bool {
    old.scopes()
        .iter()
        .any(|s| has_keys(s) && !scopes::holds(new.scopes(), s))
}

/// The epochs of a renewal at the current data epoch `epoch` (Switch wire 3.8 steps 1 and
/// 2): the last epoch of the full bundle made for the new certificate, and the `data_epoch`
/// the renewing `identity.json` carries. A renewal that rotates raises both to `epoch + 1`;
/// any other keeps `epoch`. `None` past the integer range.
pub fn renewal_epochs(rotates: bool, epoch: u64) -> Option<(u64, u64)> {
    let last = if rotates {
        epoch.checked_add(1)?
    } else {
        epoch
    };
    Some((last, last))
}

/// The `until` that closes a renewal (Switch wire 3.8). A reduction closes at once: the
/// service time of the renewing delivery, from its transition proof, plus the clock
/// tolerance. Any other renewal closes once the service holds the app's record carrying the
/// new certificate: its `record_at` plus the tolerance, `None` until then.
pub fn closing_until(reduction: bool, delivery_time: u64, record_at: Option<u64>) -> Option<u64> {
    if reduction {
        Some(delivery_time.saturating_add(CLOCK_TOLERANCE_MS))
    } else {
        record_at.map(|t| t.saturating_add(CLOCK_TOLERANCE_MS))
    }
}

/// The apps whose closing delivery a signer owes (Switch wire 3.8, "A closing delivery
/// owed"): every app with a `renewed` entry still open in `doc` whose renewal was a
/// reduction, judged from the certificates the signer issued, which `cert_of` finds by hash.
/// An entry whose certificates the signer doesn't hold is left out. Each App ID once, in the
/// order of `renewed`.
pub fn owed_closings<'a>(
    doc: &IdentityDoc,
    cert_of: impl Fn(&[u8; 32]) -> Option<&'a AppCert>,
) -> Vec<[u8; 16]> {
    let mut owed: Vec<[u8; 16]> = Vec::new();
    for entry in doc.body().renewed.iter().filter(|r| r.until.is_none()) {
        let Some(listed) = doc.listed_cert(&entry.app_id) else {
            continue;
        };
        let (Some(old), Some(new)) = (cert_of(&entry.cert), cert_of(&listed)) else {
            continue;
        };
        if is_reduction(old, new) && !owed.contains(&entry.app_id) {
            owed.push(entry.app_id);
        }
    }
    owed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKey;
    use crate::records::fixtures::{app, cert_body, identity, other_app};
    use crate::records::{
        DEFAULT_CERT_LIFETIME_MS, IdentityBody, IdentityPolicy, Inbox, ListedApp, RenewedCert,
    };
    use crate::scopes::Permission;

    fn issue(scopes: &[&str], permissions: &[Permission], issued: u64, expires: u64) -> AppCert {
        let mut body = cert_body(scopes);
        body.permissions = scopes::permission_names(permissions);
        body.issued_at = issued;
        body.expires_at = expires;
        AppCert::issue(&identity(), body).unwrap()
    }

    const BOTH: &[Permission] = &[Permission::ClaimsRead, Permission::ConversationAdd];

    #[test]
    fn test_check_presented_order() {
        let c = issue(&["scope-a"], BOTH, 1_000, 5_000);
        let (id, key) = (identity().public(), app().signing_public());
        check_presented(
            c.signed(),
            &id,
            Some(&app().app_id_bytes()),
            &key,
            Some(4_999),
        )
        .unwrap();
        assert_eq!(
            check_presented(c.signed(), &id, None, &key, Some(5_000)),
            Err(CheckFailure::Expired)
        );
        let other = IdentityKey::from_secret([9; 32]);
        assert!(matches!(
            check_presented(c.signed(), &other.public(), None, &key, Some(0)),
            Err(CheckFailure::BadSignature(_))
        ));
        assert!(matches!(
            check_presented(
                c.signed(),
                &id,
                Some(&other_app().app_id_bytes()),
                &key,
                Some(0)
            ),
            Err(CheckFailure::BadSignature(_))
        ));
        assert!(matches!(
            check_presented(
                c.signed(),
                &id,
                None,
                &other_app().signing_public(),
                Some(0)
            ),
            Err(CheckFailure::BadSignature(_))
        ));
        // Without a time, check 3 is the caller's.
        check_presented(c.signed(), &id, None, &key, None).unwrap();
        // An expired certificate that names another key fails check 2 first.
        assert!(matches!(
            check_presented(
                c.signed(),
                &id,
                None,
                &other_app().signing_public(),
                Some(9_000)
            ),
            Err(CheckFailure::BadSignature(_))
        ));
    }

    #[test]
    fn test_renewal_relations() {
        let e = 10_000;
        let base = |scopes: &[&str]| issue(scopes, BOTH, 1_000, e);
        let later = |scopes: &[&str], permissions: &[Permission], expires: u64| {
            issue(scopes, permissions, 2_000, expires)
        };
        let has_keys = |s: &str| !s.starts_with("nokeys");
        let fewer: &[Permission] = &[Permission::ClaimsRead];
        // Old scopes, new scopes, new permissions and expiry, reduction, rotates.
        type Case<'a> = (
            &'a [&'a str],
            &'a [&'a str],
            &'a [Permission],
            u64,
            bool,
            bool,
        );
        let cases: [Case; 9] = [
            (&["scope-a", "scope-b"], &["scope-a"], BOTH, e, true, true),
            (
                &["scope-a"],
                &["scope-a", "scope-b"],
                BOTH,
                e + 1,
                false,
                false,
            ),
            (&["scope-a"], &["scope-a"], BOTH, e - 1, true, false),
            (&["scope-a"], &["scope-a"], fewer, e, true, false),
            (&["scope-a", "nokeys:x"], &["scope-a"], BOTH, e, true, false),
            (&["name"], &["name:sub"], BOTH, e, true, true),
            (&["name:a", "name:b"], &["name:a"], BOTH, e, true, true),
            (&["name:a"], &["name"], BOTH, e, false, false),
            (&["name:a"], &["name:b"], BOTH, e, true, true),
        ];
        for (old, new, permissions, expires, reduction, rotates) in cases {
            let (o, n) = (base(old), later(new, permissions, expires));
            assert!(is_renewal(&o, &n), "{old:?} -> {new:?}");
            assert!(!is_renewal(&n, &o), "an earlier issued_at");
            assert_eq!(
                is_reduction(&o, &n),
                reduction,
                "{old:?} -> {new:?}: reduction"
            );
            assert_eq!(
                reduction_rotates(&o, &n, has_keys),
                rotates,
                "{old:?} -> {new:?}: rotates"
            );
            assert!(!rotates || reduction);
            assert_eq!(
                renewal_epochs(rotates, 7),
                Some(if rotates { (8, 8) } else { (7, 7) })
            );
        }
        let other = AppCert::issue(
            &identity(),
            crate::records::fixtures::cert_body_for(&other_app(), &["scope-a"]),
        )
        .unwrap();
        assert!(
            !is_renewal(&base(&["scope-a"]), &other),
            "other keys make a new app"
        );
        assert_eq!(renewal_epochs(true, u64::MAX), None);
    }

    #[test]
    fn test_closing_until() {
        assert_eq!(
            closing_until(true, 1_000, None),
            Some(1_000 + CLOCK_TOLERANCE_MS)
        );
        assert_eq!(
            closing_until(true, 1_000, Some(5_000)),
            Some(1_000 + CLOCK_TOLERANCE_MS)
        );
        assert_eq!(closing_until(false, 1_000, None), None);
        assert_eq!(
            closing_until(false, 1_000, Some(5_000)),
            Some(5_000 + CLOCK_TOLERANCE_MS)
        );
    }

    #[test]
    fn test_owed_closings() {
        let old = issue(
            &["scope-a", "scope-b"],
            BOTH,
            1_000,
            1_000 + DEFAULT_CERT_LIFETIME_MS,
        );
        let reduced = issue(&["scope-a"], BOTH, 2_000, 1_000 + DEFAULT_CERT_LIFETIME_MS);
        let grown = issue(
            &["scope-a", "scope-b", "scope-c"],
            BOTH,
            2_000,
            2_000 + DEFAULT_CERT_LIFETIME_MS,
        );
        let doc_with = |listed: &AppCert, until: Option<u64>| {
            let mut b = IdentityBody::first(
                identity().public(),
                [1; 16],
                Inbox::new("https://inbox.example", [2; 32]),
                IdentityPolicy::default(),
            );
            b.apps.push(ListedApp {
                app_id: app().app_id_bytes(),
                cert: listed.hash(),
            });
            b.renewed.push(RenewedCert {
                app_id: app().app_id_bytes(),
                cert: old.hash(),
                until,
            });
            IdentityDoc::sign(&identity(), b).unwrap()
        };
        let all = [old.clone(), reduced.clone(), grown.clone()];
        let find = |h: &[u8; 32]| all.iter().find(|c| &c.hash() == h);
        assert_eq!(
            owed_closings(&doc_with(&reduced, None), find),
            vec![app().app_id_bytes()]
        );
        assert!(
            owed_closings(&doc_with(&reduced, Some(9)), find).is_empty(),
            "closed"
        );
        assert!(
            owed_closings(&doc_with(&grown, None), find).is_empty(),
            "not a reduction"
        );
        assert!(owed_closings(&doc_with(&reduced, None), |_| None).is_empty());
    }
}
