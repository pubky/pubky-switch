//! Freeze, unfreeze and the discard answer (Switch wire 3.6, Switch spec 12.5).

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use super::{IdentityDoc, Inbox, check_tag, decode, encode, fmt, open_value};
use crate::enc::serde_b64;
use crate::error::{Result, invalid};
use crate::keys::IdentityKey;
use crate::labels;
use crate::sig::{self, SignedDoc};

/// The freeze's `kind`.
pub const FREEZE_KIND: &str = "pubky-switch.freeze";

/// The members of a freeze (Switch wire 3.6), as the signer writes them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreezeBody {
    /// The account's identity.
    #[serde(with = "fmt::pubky")]
    pub identity: [u8; 32],
    /// The next service and the account's key there.
    pub inbox: Inbox,
    /// The current generation plus one.
    pub next_generation: u64,
    /// When the freeze was issued.
    #[serde(with = "fmt::time_ms")]
    pub issued_at: u64,
    /// A random nonce, new for every move.
    #[serde(with = "serde_b64")]
    pub nonce: [u8; 16],
}

impl FreezeBody {
    /// Check the freeze for the identity the reader expects (Switch wire 3.6).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for another identity, an inbox that isn't an origin, or a
    /// `next_generation` below 2.
    pub fn check(&self, identity: &[u8; 32]) -> Result<()> {
        if &self.identity != identity {
            return invalid("Switch wire 3.6: identity isn't the account's identity");
        }
        self.inbox.check()?;
        if self.next_generation < 2 {
            return invalid("Switch wire 3.6: next_generation follows a generation of at least 1");
        }
        Ok(())
    }

    /// The body's exact JSON bytes, as the signer writes them.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it can't be written.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        encode(FREEZE_KIND, self)
    }
}

/// A verified freeze (Switch wire 3.6). Its freeze hash is its document hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Freeze {
    body: FreezeBody,
    signed: SignedDoc,
    hash: [u8; 32],
}

impl Freeze {
    /// Sign a freeze with the identity key. The signer keeps it before sending it, and sends
    /// those bytes again until it has an answer.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if the body breaks a rule of Switch wire 3.6.
    pub fn sign(key: &IdentityKey, body: FreezeBody) -> Result<Self> {
        body.check(&key.public())?;
        let signed = key.sign_doc(labels::sig::FREEZE, &[], body.to_json()?);
        let hash = signed.doc_hash()?;
        Ok(Self { body, signed, hash })
    }

    /// Verify a freeze for the identity the reader expects.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Signature`] if the identity key didn't sign it, and
    /// [`crate::Error::Invalid`] for any rule it breaks.
    pub fn verify(signed: &SignedDoc, identity: &[u8; 32]) -> Result<Self> {
        let value = open_value(signed, identity, labels::sig::FREEZE)?;
        check_tag(&value, FREEZE_KIND, "Switch wire 3.6")?;
        let body: FreezeBody = decode(value)?;
        body.check(identity)?;
        Ok(Self {
            body,
            signed: signed.clone(),
            hash: signed.doc_hash()?,
        })
    }

    /// The members as read.
    pub fn body(&self) -> &FreezeBody {
        &self.body
    }

    /// The signed document, in its exact bytes.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }

    /// The freeze hash.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The next service the freeze names.
    pub fn next(&self) -> &Inbox {
        &self.body.inbox
    }

    /// Whether the freeze moves the account from the generation of `current`: its
    /// `next_generation` is that generation plus one.
    pub fn follows(&self, current: &IdentityDoc) -> bool {
        current.generation().checked_add(1) == Some(self.body.next_generation)
    }
}

/// The next service's discard answer (Switch wire 3.6): the freeze hash, signed with the
/// service key the freeze names, over `lp(label, identity, freeze hash)`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DiscardAnswer {
    /// The freeze hash.
    #[serde(with = "serde_b64")]
    pub discarded: [u8; 32],
    /// The signature.
    #[serde(with = "serde_b64")]
    pub sig: [u8; 64],
}

impl DiscardAnswer {
    /// The answer the next service signs once it has discarded the import bound to the freeze.
    pub fn sign(service_key: &SigningKey, identity: &[u8; 32], freeze_hash: &[u8; 32]) -> Self {
        Self {
            discarded: *freeze_hash,
            sig: sig::sign(
                service_key,
                labels::sig::DISCARDED,
                &[identity, freeze_hash],
            ),
        }
    }

    /// Verify the answer for the freeze with hash `freeze_hash`, with the next service's key
    /// that freeze names.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it names another freeze, [`crate::Error::Signature`] if
    /// the key didn't sign it.
    pub fn verify(
        &self,
        identity: &[u8; 32],
        freeze_hash: &[u8; 32],
        next_service_key: &[u8; 32],
    ) -> Result<()> {
        if &self.discarded != freeze_hash {
            return invalid("Switch wire 3.6: the discard answer names another freeze");
        }
        sig::verify(
            next_service_key,
            labels::sig::DISCARDED,
            &[identity, freeze_hash],
            &self.sig,
        )
    }
}

/// Where an unfreeze is checked (Switch wire 3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnfreezeAt {
    /// The next service N, which gets it first, without a discard answer.
    Next,
    /// The old service O, which needs N's discard answer.
    Old,
}

/// The unfreeze (Switch wire 3.6): the freeze it cancels, signed by the identity key over
/// `lp(label, identity, freeze hash)`, and at the old service N's discard answer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Unfreeze {
    /// The hash of the freeze it cancels.
    #[serde(with = "serde_b64")]
    pub freeze_hash: [u8; 32],
    /// The identity key's signature.
    #[serde(with = "serde_b64")]
    pub sig: [u8; 64],
    /// N's discard answer: required at the old service, absent in the unfreeze sent to N.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discarded: Option<DiscardAnswer>,
}

impl Unfreeze {
    /// The unfreeze of the freeze with hash `freeze_hash`, as the signer sends it to N.
    pub fn sign(key: &IdentityKey, freeze_hash: &[u8; 32]) -> Self {
        Self {
            freeze_hash: *freeze_hash,
            sig: key.sign(labels::sig::UNFREEZE, &[&key.public(), freeze_hash]),
            discarded: None,
        }
    }

    /// The same unfreeze carrying N's answer, as the signer then sends it to O.
    pub fn with_discarded(mut self, answer: DiscardAnswer) -> Self {
        self.discarded = Some(answer);
        self
    }

    /// Check the unfreeze of `freeze` where it is sent (Switch wire 3.6). At O the discard
    /// answer must verify with the service key the freeze names, so that O and N never both
    /// accept writes.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if it names another freeze, if at O it carries no discard
    /// answer (`409 conflict`), or if at N it carries one; [`crate::Error::Signature`] if a
    /// signature fails.
    pub fn verify(&self, identity: &[u8; 32], freeze: &Freeze, at: UnfreezeAt) -> Result<()> {
        if self.freeze_hash != freeze.hash() {
            return invalid("Switch wire 3.6: the unfreeze names another freeze");
        }
        sig::verify(
            identity,
            labels::sig::UNFREEZE,
            &[identity, &self.freeze_hash],
            &self.sig,
        )?;
        match (at, &self.discarded) {
            (UnfreezeAt::Next, None) => Ok(()),
            (UnfreezeAt::Next, Some(_)) => {
                invalid("Switch wire 3.6: the unfreeze sent to the next service carries an answer")
            }
            (UnfreezeAt::Old, None) => {
                invalid("Switch wire 3.6: the unfreeze at the old service needs the discard answer")
            }
            (UnfreezeAt::Old, Some(answer)) => {
                answer.verify(identity, &self.freeze_hash, &freeze.next().service_key)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::fixtures::identity;

    fn next_key() -> SigningKey {
        SigningKey::from_bytes(&[6; 32])
    }

    fn freeze() -> Freeze {
        let body = FreezeBody {
            identity: identity().public(),
            inbox: Inbox::new(
                "https://next.example",
                next_key().verifying_key().to_bytes(),
            ),
            next_generation: 2,
            issued_at: 1_000,
            nonce: [4; 16],
        };
        Freeze::sign(&identity(), body).unwrap()
    }

    #[test]
    fn test_freeze_round_trip_and_rules() {
        let f = freeze();
        assert_eq!(Freeze::verify(f.signed(), &identity().public()).unwrap(), f);
        let other = IdentityKey::from_secret([9; 32]);
        assert!(Freeze::verify(f.signed(), &other.public()).is_err());
        let mut low = f.body().clone();
        low.next_generation = 1;
        assert!(low.check(&identity().public()).is_err());
        let mut no_origin = f.body().clone();
        no_origin.inbox.url = "next.example".into();
        assert!(no_origin.check(&identity().public()).is_err());
    }

    #[test]
    fn test_unfreeze_at_the_next_and_the_old_service() {
        let (f, id) = (freeze(), identity().public());
        let to_next = Unfreeze::sign(&identity(), &f.hash());
        to_next.verify(&id, &f, UnfreezeAt::Next).unwrap();
        assert!(
            to_next.verify(&id, &f, UnfreezeAt::Old).is_err(),
            "O needs the answer"
        );
        let answer = DiscardAnswer::sign(&next_key(), &id, &f.hash());
        answer
            .verify(&id, &f.hash(), &f.next().service_key)
            .unwrap();
        let to_old = to_next.clone().with_discarded(answer.clone());
        to_old.verify(&id, &f, UnfreezeAt::Old).unwrap();
        assert!(to_old.verify(&id, &f, UnfreezeAt::Next).is_err());
        // Only the key the freeze names signs the answer.
        let forged = DiscardAnswer::sign(&SigningKey::from_bytes(&[7; 32]), &id, &f.hash());
        assert!(
            to_next
                .clone()
                .with_discarded(forged)
                .verify(&id, &f, UnfreezeAt::Old)
                .is_err()
        );
        let mut elsewhere = answer;
        elsewhere.discarded = [0; 32];
        assert!(
            elsewhere
                .verify(&id, &f.hash(), &f.next().service_key)
                .is_err()
        );
        let mut other_freeze = to_next;
        other_freeze.freeze_hash = [1; 32];
        assert!(other_freeze.verify(&id, &f, UnfreezeAt::Next).is_err());
    }
}
