//! The certificates of the writers of the claim entries the app keeps (Switch wire 7.4.8,
//! 7.4.14).
//!
//! An upload after a provider loss carries each claim entry with its writer's certificate,
//! and the lost service's directory can't be read by then: the app gets each writer's
//! certificate while it can, as it does for a record write's writer (Switch wire 6.2
//! "Accepting a write" step 1).
//!
//! - **Marks** (`clcert/<app_id>`): a claim entry the app keeps, from the feed or a claim
//!   read, by another app it holds no certificate of in standing marks that writer, in the
//!   commit that keeps the entry. Only a writer the own `identity.json` lists in `apps` is
//!   marked, so the marks are bounded by the app limit (Switch wire 3.7), and a switch that
//!   names App IDs the document doesn't list marks nothing.
//! - **The directory read**: at the end of a read, when a mark is due, the app reads its own
//!   directory once (`GET /directory`, Switch wire 7.4.10) and keeps each certificate that
//!   verifies with the identity's key and has a standing in the own `identity.json` (listed,
//!   or an earlier certificate its `renewed` names). A switch can't make a certificate the
//!   document doesn't name count, and the identity's key signs every certificate, so it
//!   can't plant one either.
//! - **When a mark goes**: once the writer's certificate is kept, or once the own
//!   `identity.json` no longer lists the writer. A writer the directory didn't show is
//!   stamped with the document's version and not read for again until the app holds a newer
//!   own `identity.json`: one directory read per newly seen writer, and per document
//!   version, never one at every read. A read that fails for now keeps the marks due.
//! - **What stays a limit**: an entry whose writer's certificate the app never got, such as
//!   one by an app removed before the app first saw the entry, can't be uploaded; the
//!   upload counts it ([`super::SharedEvidence::claim_entries_left_out`]).

use pubky_switch_core::enc::{b64, unb64_array};
use pubky_switch_core::ops::SignedOp;
use pubky_switch_core::records::{AppCert, IdentityDoc, Standing};
use pubky_switch_core::sig::SignedDoc;

use super::state::Tx;
use super::{App, AppError};

/// A writer of kept claim entries whose certificate the app doesn't hold
/// (`clcert/<app_id>`), with the version of the own `identity.json` it was last looked for
/// at, 0 before the first look.
const WRITER_PREFIX: &str = "clcert/";

fn writer_key(app_id: &[u8; 16]) -> String {
    format!("{WRITER_PREFIX}{}", b64(app_id))
}

/// Whether the own `identity.json` gives the certificate a standing that dates writes: the
/// listed certificate or an earlier one its `renewed` names.
fn in_standing(doc: &IdentityDoc, cert: &AppCert) -> bool {
    matches!(
        doc.standing(&cert.app_id(), &cert.hash()),
        Standing::Listed | Standing::RenewedOpen | Standing::RenewedClosed { .. }
    )
}

impl App {
    /// After keeping the claim entry `op`: mark its writer when the own `identity.json`
    /// lists it and the app holds no certificate of it in standing, in `tx`.
    pub(crate) async fn note_entry_writer(
        &self,
        op: &SignedDoc,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let Some(writer) = SignedOp::peek(op).ok().and_then(|op| op.body().app_id) else {
            return Ok(());
        };
        let doc = &self.state.own_doc;
        if writer == self.state.meta.app_id || doc.listed_cert(&writer).is_none() {
            return Ok(());
        }
        let mark = writer_key(&writer);
        if self.reader().exists(&mark).await? {
            return Ok(());
        }
        let held = self.writer_certs_held(&writer).await?;
        if !held.iter().any(|cert| in_standing(doc, cert)) {
            tx.put(&mark, &0u64)?;
        }
        Ok(())
    }

    /// The certificates the app holds for its own app `writer`, verified with the
    /// identity's key.
    pub(crate) async fn writer_certs_held(
        &self,
        writer: &[u8; 16],
    ) -> Result<Vec<AppCert>, AppError> {
        if *writer == self.state.meta.app_id {
            let mut certs = vec![self.state.cert.clone()];
            certs.extend(self.state.renewal.iter().cloned());
            return Ok(certs);
        }
        let prefix = format!("ocert/{}/", pubky_switch_core::enc::zbase32_encode(writer));
        let identity = self.state.meta.identity;
        Ok(self
            .reader()
            .scan::<SignedDoc>(&prefix)
            .await?
            .into_iter()
            .filter_map(|(_, signed)| AppCert::verify(&signed, &identity).ok())
            .collect())
    }

    /// At the end of a read: when a marked writer is due, read the own directory once and
    /// keep the certificates in standing; drop the marks of writers now held or no longer
    /// listed, and stamp the rest with the document's version. A failed call or one the
    /// switch may answer later keeps the marks due, and the feed's read still succeeds; an
    /// alarm or a store failure fails it.
    pub(crate) async fn fetch_entry_writers(&mut self) -> Result<(), AppError> {
        let marks = self.reader().scan::<u64>(WRITER_PREFIX).await?;
        if marks.is_empty() {
            return Ok(());
        }
        let doc = self.state.own_doc.clone();
        let version = doc.version();
        let mut tx = self.tx()?;
        // The writers still owed a look, with their marks; the others' marks go.
        let mut owed = Vec::new();
        for (rest, looked_at) in marks {
            let key = format!("{WRITER_PREFIX}{rest}");
            let listed = unb64_array::<16>(&rest)
                .ok()
                .filter(|app_id| doc.listed_cert(app_id).is_some());
            let Some(app_id) = listed else {
                tx.delete(&key)?;
                continue;
            };
            let held = self.writer_certs_held(&app_id).await?;
            if held.iter().any(|cert| in_standing(&doc, cert)) {
                tx.delete(&key)?;
            } else if looked_at < version {
                owed.push((app_id, key));
            }
        }
        if !owed.is_empty() {
            let result = self.client.directory(None).await;
            match self.take(result).await {
                Ok(directory) => {
                    let identity = self.state.meta.identity;
                    let mut found = std::collections::BTreeSet::new();
                    for app in &directory.apps {
                        let Ok(cert) = AppCert::verify(app.record.cert().signed(), &identity)
                        else {
                            continue;
                        };
                        if cert.app_id() == app.app_id && in_standing(&doc, &cert) {
                            self.keep_cert(&cert, &mut tx)?;
                            found.insert(cert.app_id());
                        }
                    }
                    for (app_id, key) in owed {
                        if found.contains(&app_id) {
                            tx.delete(&key)?;
                        } else {
                            tx.put(&key, &version)?;
                        }
                    }
                }
                Err(AppError::Transport(_) | AppError::Switch(_)) => {}
                Err(error) => return Err(error),
            }
        }
        if !tx.is_empty() {
            self.commit(tx).await?;
        }
        Ok(())
    }
}
