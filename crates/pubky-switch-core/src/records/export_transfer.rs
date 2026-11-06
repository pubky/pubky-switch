//! The export transfer (Switch wire 3.11, Switch spec 12.5).

use serde::{Deserialize, Serialize};

use super::{Freeze, Inbox, check_tag, decode, encode, fmt, open_value};
use crate::enc::serde_b64;
use crate::error::{Result, invalid};
use crate::json::reject_unknown_members;
use crate::keys::IdentityKey;
use crate::labels;
use crate::sig::SignedDoc;

/// The export transfer's `kind`.
pub const EXPORT_TRANSFER_KIND: &str = "pubky-switch.export_transfer";

/// The members of an export transfer, which refuses any other (Switch wire 1.1, 3.11).
const EXPORT_TRANSFER_MEMBERS: [&str; 8] = [
    "v",
    "kind",
    "identity",
    "freeze_hash",
    "manifest_hash",
    "from",
    "to",
    "issued_at",
];

/// The members of `from` and `to`, which refuse any other (Switch wire 1.1).
const INBOX_MEMBERS: [&str; 2] = ["url", "service_key"];

/// The members of an export transfer (Switch wire 3.11), as the signer writes them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportTransferBody {
    /// The account's identity.
    #[serde(with = "fmt::pubky")]
    pub identity: [u8; 32],
    /// The document hash of the signed freeze.
    #[serde(with = "serde_b64")]
    pub freeze_hash: [u8; 32],
    /// The document hash of the old service's signed manifest.
    #[serde(with = "serde_b64")]
    pub manifest_hash: [u8; 32],
    /// The old service: its origin and the account's key there.
    pub from: Inbox,
    /// The next service, as the freeze names it.
    pub to: Inbox,
    /// When the transfer was issued; informational.
    #[serde(with = "fmt::time_ms")]
    pub issued_at: u64,
}

impl ExportTransferBody {
    /// Check the transfer for the identity the reader expects: the identity, and `from` and
    /// `to` origins (Switch wire 3.11).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] naming the rule that fails.
    pub fn check(&self, identity: &[u8; 32]) -> Result<()> {
        if &self.identity != identity {
            return invalid("Switch wire 3.11: identity isn't the account's identity");
        }
        self.from.check()?;
        self.to.check()
    }

    /// The body's exact JSON bytes, as the signer writes them.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        encode(EXPORT_TRANSFER_KIND, self)
    }
}

/// A verified export transfer (Switch wire 3.11): the signer's authorization for the next
/// service to fetch one export's chunks from the old service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportTransfer {
    body: ExportTransferBody,
    signed: SignedDoc,
}

impl ExportTransfer {
    /// Sign a transfer with the identity key; the signer signs it once per manifest and keeps
    /// it.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if the body breaks a rule of Switch wire 3.11.
    pub fn sign(key: &IdentityKey, body: ExportTransferBody) -> Result<Self> {
        body.check(&key.public())?;
        let signed = key.sign_doc(labels::sig::EXPORT_TRANSFER, &[], body.to_json()?);
        Ok(Self { body, signed })
    }

    /// Verify a transfer for the account's identity, then its body strictly, its unknown
    /// members refused, `from` and `to` included.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Signature`] if the identity key didn't sign it (`401 bad_signature`),
    /// and [`crate::Error::Invalid`] for any rule it breaks.
    pub fn verify(signed: &SignedDoc, identity: &[u8; 32]) -> Result<Self> {
        let value = open_value(signed, identity, labels::sig::EXPORT_TRANSFER)?;
        reject_unknown_members(&value, &EXPORT_TRANSFER_MEMBERS, "an export transfer")?;
        for member in ["from", "to"] {
            if let Some(inner) = value.get(member) {
                reject_unknown_members(inner, &INBOX_MEMBERS, "an export transfer's service")?;
            }
        }
        check_tag(&value, EXPORT_TRANSFER_KIND, "Switch wire 3.11")?;
        let body: ExportTransferBody = decode(value)?;
        body.check(identity)?;
        Ok(Self {
            body,
            signed: signed.clone(),
        })
    }

    /// The members as read.
    pub fn body(&self) -> &ExportTransferBody {
        &self.body
    }

    /// The signed document, in its exact bytes.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// The old service's check that the transfer names this export (Switch wire 3.11): the
    /// freeze the account is frozen with, the old service's own origin and the account's key,
    /// the next service that freeze names, and the manifest built for it.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it names another export (`403 not_admitted`).
    pub fn check_names(
        &self,
        freeze: &Freeze,
        origin: &str,
        service_key: &[u8; 32],
        manifest_hash: &[u8; 32],
    ) -> Result<()> {
        let b = &self.body;
        let names = b.identity == freeze.body().identity
            && b.freeze_hash == freeze.hash()
            && b.from.url == origin
            && &b.from.service_key == service_key
            && &b.to == freeze.next()
            && &b.manifest_hash == manifest_hash;
        if names {
            Ok(())
        } else {
            invalid("Switch wire 3.11: the transfer doesn't name this export")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::FreezeBody;
    use crate::records::fixtures::identity;

    const OLD: &str = "https://inbox.example";

    fn freeze() -> Freeze {
        let body = FreezeBody {
            identity: identity().public(),
            inbox: Inbox::new("https://next.example", [6; 32]),
            next_generation: 2,
            issued_at: 1_000,
            nonce: [4; 16],
        };
        Freeze::sign(&identity(), body).unwrap()
    }

    fn transfer() -> ExportTransfer {
        let f = freeze();
        let body = ExportTransferBody {
            identity: identity().public(),
            freeze_hash: f.hash(),
            manifest_hash: [7; 32],
            from: Inbox::new(OLD, [8; 32]),
            to: f.next().clone(),
            issued_at: 2_000,
        };
        ExportTransfer::sign(&identity(), body).unwrap()
    }

    fn resign(f: impl Fn(&mut serde_json::Value)) -> SignedDoc {
        let mut v: serde_json::Value =
            serde_json::from_slice(&transfer().signed().body_bytes().unwrap()).unwrap();
        f(&mut v);
        identity().sign_doc(
            labels::sig::EXPORT_TRANSFER,
            &[],
            serde_json::to_vec(&v).unwrap(),
        )
    }

    #[test]
    fn test_export_transfer_round_trip_and_names() {
        let t = transfer();
        assert_eq!(
            ExportTransfer::verify(t.signed(), &identity().public()).unwrap(),
            t
        );
        let f = freeze();
        t.check_names(&f, OLD, &[8; 32], &[7; 32]).unwrap();
        assert!(
            t.check_names(&f, OLD, &[8; 32], &[1; 32]).is_err(),
            "another manifest"
        );
        assert!(
            t.check_names(&f, "https://o.example", &[8; 32], &[7; 32])
                .is_err()
        );
        assert!(
            t.check_names(&f, OLD, &[1; 32], &[7; 32]).is_err(),
            "another key"
        );
    }

    #[test]
    fn test_export_transfer_refuses_unknown_members() {
        let id = identity().public();
        ExportTransfer::verify(&resign(|_| {}), &id).unwrap();
        assert!(
            ExportTransfer::verify(&resign(|v| v["future"] = serde_json::json!(1)), &id).is_err()
        );
        assert!(
            ExportTransfer::verify(&resign(|v| v["from"]["future"] = serde_json::json!(1)), &id)
                .is_err()
        );
        assert!(
            ExportTransfer::verify(&resign(|v| v["kind"] = serde_json::json!("other")), &id)
                .is_err()
        );
        let other = IdentityKey::from_secret([9; 32]);
        assert!(matches!(
            ExportTransfer::verify(transfer().signed(), &other.public()),
            Err(crate::Error::Signature(_))
        ));
    }
}
