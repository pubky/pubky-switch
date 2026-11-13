//! The identity's apps as a management screen shows them (Switch spec 3.1, 3.2, 12.2).
//!
//! One summary per app the newest `identity.json` lists or names as removed, joined from that
//! document, the certificates the signer keeps, the revocations it is carrying out, the
//! automatic renewals no record took up, and the alerts the user hasn't cleared. It reads
//! only what the signer holds, signs nothing and sends nothing.

use pubky_switch_core::records::AppCert;

use super::Signer;
use crate::alert::Alert;
use crate::error::Result;

/// Where an app stands in the newest `identity.json` (Switch spec 12.2), as this install's
/// records show it. An app that left by itself is `Listed` until a version removes it: its
/// alerts tell it apart. During a recovery, `Revoking { at_switch: true }` is the lost
/// service's answer until the recovery's version is delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AppStanding {
    /// Listed as current.
    Listed,
    /// The user asked to revoke it, and no delivered version removes it yet. `at_switch` once
    /// the switch answered the revocation, so it serves the app no more.
    Revoking {
        /// Whether the switch answered the revocation.
        at_switch: bool,
    },
    /// Named in `removed`: revoked, or gone by itself, for good.
    Removed,
}

/// One app of the identity, for a management screen.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AppSummary {
    /// The App ID.
    pub app_id: [u8; 16],
    /// Where it stands.
    pub standing: AppStanding,
    /// The document hash of the certificate the newest version lists for it; `None` for a
    /// removed app.
    pub listed_cert: Option<[u8; 32]>,
    /// That certificate: its scopes, switch permissions, `issued_at` and `expires_at`. `None`
    /// for a removed app, and for a listed one whose certificate this install doesn't hold,
    /// as in a version it adopted from another install.
    pub cert: Option<AppCert>,
    /// Whether a renewal of it is open: an earlier certificate of it is in `renewed` without
    /// an `until` yet (Switch wire 3.8).
    pub renewal_open: bool,
    /// The registered protocols that own some of its scopes, in their registration order;
    /// `None` when `cert` is, since its scopes are then unknown here.
    pub protocols: Option<Vec<String>>,
    /// Its scopes that no registered protocol owns: the steps that need its keys wait for
    /// them (design note, decision 2). `None` when `cert` is.
    pub unowned_scopes: Option<Vec<String>>,
    /// From when its messages are distrusted: a removed app's `distrust_from`, or the earlier
    /// time the user picked for a revocation in progress (Switch spec 12.2).
    pub distrust_from: Option<u64>,
    /// How many of its automatic renewals in a row no record took up; at two the signer stops
    /// renewing it by itself (Switch spec 3.1, [`Alert::RenewalsStopped`]).
    pub untaken_renewals: usize,
    /// The alerts the user hasn't cleared that name it, oldest first.
    pub alerts: Vec<Alert>,
}

impl Signer {
    /// The identity's apps, as a management screen lists them: each app the newest
    /// `identity.json` lists, in its order, then each one it names as removed, in its order.
    /// Empty before the first version. What the user may do with each, and the confirmation
    /// each call needs first, are in the signer host guide (`docs/signer-host-guide.md`).
    ///
    /// # Errors
    ///
    /// [`crate::SignerError::InvalidData`] when the stored newest document or a stored
    /// certificate no longer verifies.
    pub fn apps(&self) -> Result<Vec<AppSummary>> {
        let Some(doc) = self.state.newest_doc()? else {
            return Ok(Vec::new());
        };
        let certs = self.certificates()?;
        let body = doc.body();
        let alerts_of = |app_id: &[u8; 16]| -> Vec<Alert> {
            self.state
                .alerts
                .iter()
                .filter(|alert| alert.names_app(app_id))
                .cloned()
                .collect()
        };
        let untaken_of = |app_id: &[u8; 16]| {
            self.state
                .untaken_renewals
                .iter()
                .filter(|(app, _)| app == app_id)
                .count()
        };
        let mut apps = Vec::with_capacity(body.apps.len() + body.removed.len());
        for listed in &body.apps {
            let app_id = listed.app_id;
            let cert = certs
                .iter()
                .find(|cert| cert.hash() == listed.cert)
                .cloned();
            let scopes = cert.as_ref().map(AppCert::scopes);
            let revoking = self.state.revoking.iter().find(|r| r.app_id == app_id);
            apps.push(AppSummary {
                app_id,
                standing: match revoking {
                    Some(r) => AppStanding::Revoking { at_switch: r.taken },
                    None => AppStanding::Listed,
                },
                renewal_open: body
                    .renewed
                    .iter()
                    .any(|renewed| renewed.app_id == app_id && renewed.until.is_none()),
                listed_cert: Some(listed.cert),
                protocols: scopes.map(|scopes| {
                    self.env
                        .protocols
                        .protocols_of(scopes)
                        .into_iter()
                        .map(str::to_owned)
                        .collect()
                }),
                unowned_scopes: scopes.map(|scopes| self.env.protocols.unowned(scopes)),
                distrust_from: revoking.and_then(|r| r.distrust_from),
                untaken_renewals: untaken_of(&app_id),
                alerts: alerts_of(&app_id),
                cert,
            });
        }
        for removed in &body.removed {
            apps.push(AppSummary {
                app_id: removed.app_id,
                standing: AppStanding::Removed,
                listed_cert: None,
                cert: None,
                renewal_open: false,
                protocols: None,
                unowned_scopes: None,
                distrust_from: Some(removed.distrust_from),
                untaken_renewals: 0,
                alerts: alerts_of(&removed.app_id),
            });
        }
        Ok(apps)
    }
}
