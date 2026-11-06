//! Fixed keys and documents for the unit tests of the records.

use super::{AppCert, AppCertBody, DEFAULT_CERT_LIFETIME_MS};
use crate::keys::{AppKeys, IdentityKey};
use crate::scopes::Permission;

/// The test identity.
pub(crate) fn identity() -> IdentityKey {
    IdentityKey::from_secret([1; 32])
}

/// The test app.
pub(crate) fn app() -> AppKeys {
    AppKeys::from_secrets([2; 32], [3; 32])
}

/// A second test app of the same identity.
pub(crate) fn other_app() -> AppKeys {
    AppKeys::from_secrets([4; 32], [5; 32])
}

/// When the test certificates are issued.
pub(crate) const ISSUED: u64 = 1_767_225_600_000;

/// A certificate body for the test app with these scopes.
pub(crate) fn cert_body(scopes: &[&str]) -> AppCertBody {
    cert_body_for(&app(), scopes)
}

/// A certificate body for `app` with these scopes.
pub(crate) fn cert_body_for(app: &AppKeys, scopes: &[&str]) -> AppCertBody {
    AppCertBody::new(
        identity().public(),
        app.signing_public(),
        app.bundle_public(),
        scopes.iter().map(|s| (*s).to_owned()).collect(),
        &[Permission::ClaimsRead, Permission::ConversationAdd],
        ISSUED,
        ISSUED + DEFAULT_CERT_LIFETIME_MS,
    )
}

/// The test app's certificate with these scopes.
pub(crate) fn cert(scopes: &[&str]) -> AppCert {
    AppCert::issue(&identity(), cert_body(scopes)).unwrap()
}
