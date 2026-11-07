//! A recipient's checks of an inbox entry (Switch wire 5.1, Switch spec 11), in their order,
//! on top of [`MessagePlaintext::check`].
//!
//! | # | Check | Here |
//! |---|---|---|
//! | 1 | open the envelope and parse the plaintext | [`receive`] |
//! | 2 | the entry's certificate verifies for the entry's `sender` | [`receive`] |
//! | 3 | it hadn't expired at the entry's `accepted_at` | [`receive`] |
//! | 4 to 6 | the signature, the strict JSON and the parties | [`MessagePlaintext::check`] |
//! | 6 | a message from an own app is of a kind its protocol sends between own apps | the protocol's [`KindRules::sent_between_own_apps`] |
//! | 7 | the certificate's standing in the sender's newest `identity.json` at `accepted_at`, with the 5-minute tolerance | [`receive`] |
//! | 8 | the scopes that send and receive the kind | the protocol's [`KindRules::check_scopes`] |
//! | 9 | deduplication by (sender identity, `msg_id`) with the message hash | [`receive`], with the app's record of processed messages |
//! | 10 | the body, as its kind's protocol defines it | the caller |
//!
//! A failed check drops the entry. After check 10 the app keeps the (sender identity,
//! `msg_id`) pair with the message hash as processed, so the same message isn't checked
//! again. A sender whose `identity.json` can't be read holds the entry instead (Switch spec
//! 8.2): [`Refusal::SenderUnverifiable`].

use crate::error::Error;
use crate::json::OpaqueMember;
use crate::message::{Message, MessagePlaintext, VerifiedSender};
use crate::records::{AppCert, IdentityDoc, Standing};
use crate::sig::SignedDoc;

/// The rules a message's protocol gives the recipient checks: its opaque body members, the
/// kinds it sends between own apps (check 6) and the scopes of each kind (check 8). The
/// Switch gives no kind a meaning of its own (Switch spec 1).
pub trait KindRules {
    /// The opaque members of the protocol's bodies (Switch wire 1.1). None by default.
    fn opaque_members(&self) -> &[OpaqueMember<'_>] {
        &[]
    }

    /// Whether the protocol sends `kind` between apps of one identity (Switch wire 5.1 check
    /// 6, Switch spec 7).
    fn sent_between_own_apps(&self, kind: &str) -> bool;

    /// Check 8 (Switch wire 5.1): the sender's certificate holds a scope that sends the
    /// kind, and the own certificate one that receives it, with the protocol's narrower
    /// rules.
    ///
    /// # Errors
    ///
    /// The rule the message breaks; the entry is dropped.
    fn check_scopes(&self, message: &Message, sender: &AppCert) -> crate::Result<()>;
}

/// One inbox entry as a feed item carries it (Switch wire 7.5).
#[derive(Clone, Copy)]
pub struct InboxEntry<'a> {
    /// The entry's `sender` identity.
    pub sender: [u8; 32],
    /// The certificate the entry carries, the feed's `cert`.
    pub cert: &'a SignedDoc,
    /// When the inbox accepted the entry, a time on the recipient's service.
    pub accepted_at_ms: u64,
    /// The envelope.
    pub envelope: &'a [u8],
}

impl std::fmt::Debug for InboxEntry<'_> {
    // The envelope is message content, which stays out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "InboxEntry({}, {} bytes)",
            self.accepted_at_ms,
            self.envelope.len()
        )
    }
}

/// The sender identity's newest `identity.json` the recipient holds, if any (check 7).
#[derive(Clone, Copy, Debug)]
pub enum SenderIdentity<'a> {
    /// The newest version held, verified for the sender.
    Held(&'a IdentityDoc),
    /// None can be read now: the entry is held, with later entries processed past it.
    Unavailable,
}

/// A message that passed checks 1 to 9: the caller parses its body (check 10), then keeps
/// (sender identity, `msg_id`) with [`Received::hash`] as processed.
#[derive(Clone, Debug)]
pub struct Received {
    /// The message's common fields.
    pub message: Message,
    /// The signed plaintext, kept for re-sends and evidence.
    pub plaintext: MessagePlaintext,
    /// The sender's certificate, verified for the entry's sender.
    pub cert: AppCert,
    /// The sender app's standing at `accepted_at`.
    pub standing: Standing,
}

impl Received {
    /// The message hash, the deduplication record's value (Switch wire 5.1 check 9).
    pub fn hash(&self) -> [u8; 32] {
        self.plaintext.hash()
    }
}

/// Why an entry isn't processed now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A check failed: the entry is dropped and the cursor moves past it.
    Dropped {
        /// The check of Switch wire 5.1 that failed, 1 to 9.
        check: u8,
        /// The rule, without message content.
        reason: String,
    },
    /// Checks 1 to 6 passed, but the sender's `identity.json` can't be read: the entry is
    /// held (Switch spec 8.2). After a bounded wait the app stores it locally, moves its
    /// cursor past it, and checks it later.
    SenderUnverifiable,
    /// Already processed: the same (sender identity, `msg_id`). With another message hash,
    /// the sender sent two messages under one `msg_id`.
    Duplicate {
        /// Whether the stored hash differs from this message's.
        conflicting: bool,
    },
}

/// The app's record of processed messages (Switch wire 5.1 check 9, Switch spec 11): the
/// message hash kept for a (sender identity, `msg_id`) pair already processed, if any.
pub type Processed<'a> = dyn Fn(&[u8; 32], &str) -> Option<[u8; 32]> + 'a;

fn dropped(check: u8, reason: impl Into<String>) -> Refusal {
    Refusal::Dropped {
        check,
        reason: reason.into(),
    }
}

fn dropped_by(check: u8, error: Error) -> Refusal {
    dropped(check, error.to_string())
}

/// Run checks 1 to 9 of Switch wire 5.1 on an inbox entry, in their order, stopping at the
/// first that fails.
///
/// `own_identity` and `receive_secret` open the envelope; `sender_identity` is the sender's
/// newest `identity.json` held (check 7); `rules` are the protocol's checks 6 and 8; and
/// `processed` finds the message hash kept for a (sender identity, `msg_id`) already
/// processed (check 9). The body, check 10, is the caller's.
///
/// The standing is checked once, when the message is recorded: a stored message isn't
/// checked again against later versions (Switch spec 8.2).
///
/// # Errors
///
/// The [`Refusal`]: a dropped entry with its check, a held one, or a duplicate.
pub fn receive(
    entry: &InboxEntry<'_>,
    own_identity: &[u8; 32],
    receive_secret: &[u8; 32],
    sender_identity: SenderIdentity<'_>,
    rules: &dyn KindRules,
    processed: &Processed<'_>,
) -> Result<Received, Refusal> {
    // Check 1: open the envelope and read its plaintext.
    let plaintext = MessagePlaintext::open(entry.envelope, own_identity, receive_secret)
        .map_err(|e| dropped_by(1, e))?;
    // Check 2: the entry's certificate, as a certificate of the entry's sender, for the app
    // the plaintext names (Switch wire 3.8 checks 1 and 2).
    let cert = AppCert::verify(entry.cert, &entry.sender).map_err(|e| dropped_by(2, e))?;
    if cert.app_id() != plaintext.sender_app_id() {
        return Err(dropped(
            2,
            "Switch wire 5.1 check 2: the certificate is of another app than the plaintext's",
        ));
    }
    // Check 3: not expired when the inbox accepted the entry.
    if cert.expired_at(entry.accepted_at_ms) {
        return Err(dropped(
            3,
            "Switch wire 5.1 check 3: the certificate had expired at accepted_at",
        ));
    }
    // Checks 4 to 6.
    let sender = VerifiedSender::from_cert(&cert);
    let message = plaintext
        .check(own_identity, &entry.sender, &sender, rules.opaque_members())
        .map_err(|e| {
            let check = match e {
                Error::Signature(_) => 4,
                _ if e.to_string().contains("check 6") => 6,
                _ => 5,
            };
            dropped_by(check, e)
        })?;
    if message.is_from_own_app() && !rules.sent_between_own_apps(&message.kind) {
        return Err(dropped(
            6,
            "Switch wire 5.1 check 6: a kind its protocol doesn't send between own apps",
        ));
    }
    // Check 7: the standing at `accepted_at` in the sender's newest `identity.json`.
    let doc = match sender_identity {
        SenderIdentity::Held(doc) => doc,
        SenderIdentity::Unavailable => return Err(Refusal::SenderUnverifiable),
    };
    if doc.identity() != entry.sender {
        return Err(dropped(
            7,
            "Switch wire 5.1 check 7: the identity.json isn't the sender's",
        ));
    }
    let standing = doc.standing(&cert.app_id(), &cert.hash());
    if !standing.counts_at(entry.accepted_at_ms) {
        return Err(dropped(7, standing_reason(standing)));
    }
    // Check 8: the protocol's scopes.
    rules
        .check_scopes(&message, &cert)
        .map_err(|e| dropped_by(8, e))?;
    // Check 9: deduplication.
    if let Some(seen) = processed(&entry.sender, &message.msg_id) {
        return Err(Refusal::Duplicate {
            conflicting: seen != plaintext.hash(),
        });
    }
    Ok(Received {
        message,
        plaintext,
        cert,
        standing,
    })
}

/// Why a standing doesn't count at `accepted_at` (Switch wire 3.8, 5.1 check 7).
fn standing_reason(standing: Standing) -> &'static str {
    match standing {
        Standing::Removed { .. } => {
            "Switch wire 5.1 check 7: the sender app was removed before the message, within the tolerance"
        }
        Standing::RenewedClosed { .. } => {
            "Switch wire 5.1 check 7: the certificate's renewal closed before the message, within the tolerance"
        }
        Standing::Listed | Standing::RenewedOpen | Standing::None => {
            "Switch wire 5.1 check 7: the sender's identity.json doesn't list the certificate"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Recipient;
    use crate::keys::{AppKeys, IdentityKey, ReceiveKey};
    use crate::message::Sender;
    use crate::records::{
        AppCertBody, CLOCK_TOLERANCE_MS, DAY_MS, IdentityBody, IdentityPolicy, Inbox, ListedApp,
        RemovedApp, RenewedCert,
    };
    use crate::scopes::Permission;
    use serde_json::{Map, Value};

    const START: u64 = 1_767_225_600_000;

    struct Rules;

    impl KindRules for Rules {
        fn sent_between_own_apps(&self, kind: &str) -> bool {
            kind == "sample.notice"
        }

        fn check_scopes(&self, message: &Message, sender: &AppCert) -> crate::Result<()> {
            if message.kind == "sample.kind" && !sender.holds_scope("send") {
                return Err(Error::Invalid("the sender lacks send".into()));
            }
            Ok(())
        }
    }

    struct World {
        alice: IdentityKey,
        bob: IdentityKey,
        bob_app: AppKeys,
        cert: AppCert,
        receive: ReceiveKey,
    }

    fn world() -> World {
        let bob = IdentityKey::from_secret([2; 32]);
        let bob_app = AppKeys::from_secrets([3; 32], [4; 32]);
        let cert = cert_for(&bob, &bob_app, &["send"], START - DAY_MS);
        World {
            alice: IdentityKey::from_secret([1; 32]),
            bob,
            bob_app,
            cert,
            receive: ReceiveKey::from_secret(0, [5; 32]),
        }
    }

    fn cert_for(identity: &IdentityKey, app: &AppKeys, scopes: &[&str], issued: u64) -> AppCert {
        AppCert::issue(
            identity,
            AppCertBody::new(
                identity.public(),
                app.signing_public(),
                app.bundle_public(),
                scopes.iter().map(|s| (*s).to_owned()).collect(),
                &[Permission::ConversationAdd],
                issued,
                issued + 30 * DAY_MS,
            ),
        )
        .unwrap()
    }

    fn doc_of(identity: &IdentityKey, change: impl Fn(&mut IdentityBody)) -> IdentityDoc {
        let mut body = IdentityBody::first(
            identity.public(),
            [0; 16],
            Inbox::new("https://inbox.example", [9; 32]),
            IdentityPolicy::default(),
        );
        change(&mut body);
        IdentityDoc::sign(identity, body).unwrap()
    }

    fn listing(w: &World, cert: &AppCert) -> IdentityDoc {
        doc_of(&w.bob, |b| {
            b.apps.push(ListedApp {
                app_id: cert.app_id(),
                cert: cert.hash(),
            })
        })
    }

    fn envelope(w: &World, from: &IdentityKey, app: &AppKeys, kind: &str, to: [u8; 32]) -> Vec<u8> {
        envelope_from(w, from.public(), app, kind, to)
    }

    fn envelope_from(
        w: &World,
        from: [u8; 32],
        app: &AppKeys,
        kind: &str,
        to: [u8; 32],
    ) -> Vec<u8> {
        let mut message = Message::new(
            kind,
            Sender::of_app(from, app),
            to,
            START,
            vec![],
            Map::<String, Value>::new(),
        )
        .unwrap();
        message.msg_id = "11111111-2222-4333-8444-555555555555".into();
        message
            .sign(app)
            .unwrap()
            .seal(
                &w.alice.public(),
                &[Recipient::new(w.receive.public)],
                false,
            )
            .unwrap()
    }

    fn run(
        w: &World,
        entry: &InboxEntry<'_>,
        doc: SenderIdentity<'_>,
        seen: Option<[u8; 32]>,
    ) -> Result<Received, Refusal> {
        receive(
            entry,
            &w.alice.public(),
            &w.receive.secret(),
            doc,
            &Rules,
            &|_, _| seen,
        )
    }

    fn check_of(refusal: Refusal) -> u8 {
        match refusal {
            Refusal::Dropped { check, .. } => check,
            other => panic!("not dropped: {other:?}"),
        }
    }

    #[test]
    fn test_receive_accepts_a_listed_sender() {
        let w = world();
        let env = envelope(&w, &w.bob, &w.bob_app, "sample.kind", w.alice.public());
        let doc = listing(&w, &w.cert);
        let entry = InboxEntry {
            sender: w.bob.public(),
            cert: w.cert.signed(),
            accepted_at_ms: START,
            envelope: &env,
        };
        let got = run(&w, &entry, SenderIdentity::Held(&doc), None).unwrap();
        assert_eq!(got.message.kind, "sample.kind");
        assert_eq!(got.standing, Standing::Listed);
        assert_eq!(got.hash(), got.plaintext.hash());
        assert!(!format!("{entry:?}").contains("sample"));
    }

    #[test]
    fn test_receive_refuses_each_check_in_order() {
        let w = world();
        let env = envelope(&w, &w.bob, &w.bob_app, "sample.kind", w.alice.public());
        let doc = listing(&w, &w.cert);
        let base = InboxEntry {
            sender: w.bob.public(),
            cert: w.cert.signed(),
            accepted_at_ms: START,
            envelope: &env,
        };
        let held = SenderIdentity::Held(&doc);
        // 1: another receive key.
        let other_key = ReceiveKey::from_secret(0, [6; 32]);
        let error = receive(
            &base,
            &w.alice.public(),
            &other_key.secret(),
            held,
            &Rules,
            &|_, _| None,
        )
        .unwrap_err();
        assert_eq!(check_of(error), 1);
        // 2: the certificate of another identity's sender, or of another app.
        let carol = IdentityKey::from_secret([7; 32]);
        let entry = InboxEntry {
            sender: carol.public(),
            ..base
        };
        assert_eq!(check_of(run(&w, &entry, held, None).unwrap_err()), 2);
        let other_app = AppKeys::from_secrets([8; 32], [9; 32]);
        let other_cert = cert_for(&w.bob, &other_app, &["send"], START - DAY_MS);
        let entry = InboxEntry {
            cert: other_cert.signed(),
            ..base
        };
        assert_eq!(check_of(run(&w, &entry, held, None).unwrap_err()), 2);
        // 3: expired at accepted_at, though not when sent.
        let entry = InboxEntry {
            accepted_at_ms: w.cert.expires_at(),
            ..base
        };
        assert_eq!(check_of(run(&w, &entry, held, None).unwrap_err()), 3);
        // 4: a signature the certificate's signing key didn't make.
        let forged = {
            let mut plaintext =
                MessagePlaintext::open(&env, &w.alice.public(), &w.receive.secret()).unwrap();
            plaintext = MessagePlaintext::from_parts(
                plaintext.sender_app_id(),
                [1; 64],
                plaintext.json().to_vec(),
            )
            .unwrap();
            plaintext
                .seal(
                    &w.alice.public(),
                    &[Recipient::new(w.receive.public)],
                    false,
                )
                .unwrap()
        };
        let entry = InboxEntry {
            envelope: &forged,
            ..base
        };
        assert_eq!(check_of(run(&w, &entry, held, None).unwrap_err()), 4);
        // A message signed for another recipient fails the signature over the own identity.
        let misaddressed = envelope(&w, &w.bob, &w.bob_app, "sample.kind", carol.public());
        let entry = InboxEntry {
            envelope: &misaddressed,
            ..base
        };
        assert_eq!(check_of(run(&w, &entry, held, None).unwrap_err()), 4);
        // 6: from another identity than the certificate's; and an own-app kind its protocol
        // doesn't send.
        let other_from = envelope_from(
            &w,
            carol.public(),
            &w.bob_app,
            "sample.kind",
            w.alice.public(),
        );
        let entry = InboxEntry {
            envelope: &other_from,
            ..base
        };
        assert_eq!(check_of(run(&w, &entry, held, None).unwrap_err()), 6);
        let own_app = AppKeys::from_secrets([10; 32], [11; 32]);
        let own_cert = cert_for(&w.alice, &own_app, &["send"], START - DAY_MS);
        let own_doc = doc_of(&w.alice, |b| {
            b.apps.push(ListedApp {
                app_id: own_cert.app_id(),
                cert: own_cert.hash(),
            })
        });
        for (kind, outcome) in [("sample.kind", Some(6)), ("sample.notice", None)] {
            let own = envelope(&w, &w.alice, &own_app, kind, w.alice.public());
            let entry = InboxEntry {
                sender: w.alice.public(),
                cert: own_cert.signed(),
                envelope: &own,
                ..base
            };
            let got = run(&w, &entry, SenderIdentity::Held(&own_doc), None);
            assert_eq!(got.err().map(check_of), outcome, "{kind}");
        }
        // 7: unavailable holds; another identity's document, or one not listing the app, drops.
        assert_eq!(
            run(&w, &base, SenderIdentity::Unavailable, None).unwrap_err(),
            Refusal::SenderUnverifiable
        );
        assert_eq!(
            check_of(run(&w, &base, SenderIdentity::Held(&own_doc), None).unwrap_err()),
            7
        );
        let unlisting = doc_of(&w.bob, |_| {});
        assert_eq!(
            check_of(run(&w, &base, SenderIdentity::Held(&unlisting), None).unwrap_err()),
            7
        );
        // 8: the protocol's scopes.
        let no_send = cert_for(&w.bob, &w.bob_app, &["other"], START - DAY_MS - 1);
        let doc8 = listing(&w, &no_send);
        let entry = InboxEntry {
            cert: no_send.signed(),
            ..base
        };
        assert_eq!(
            check_of(run(&w, &entry, SenderIdentity::Held(&doc8), None).unwrap_err()),
            8
        );
        // 9: processed already, with the same hash or another.
        let hash = run(&w, &base, held, None).unwrap().hash();
        assert_eq!(
            run(&w, &base, held, Some(hash)).unwrap_err(),
            Refusal::Duplicate { conflicting: false }
        );
        assert_eq!(
            run(&w, &base, held, Some([0; 32])).unwrap_err(),
            Refusal::Duplicate { conflicting: true }
        );
    }

    #[test]
    fn test_receive_standing_applies_the_tolerance_and_renewals() {
        let w = world();
        let env = envelope(&w, &w.bob, &w.bob_app, "sample.kind", w.alice.public());
        let renewed_to = cert_for(&w.bob, &w.bob_app, &["send"], START);
        let at = |doc: &IdentityDoc, accepted: u64| {
            let entry = InboxEntry {
                sender: w.bob.public(),
                cert: w.cert.signed(),
                accepted_at_ms: accepted,
                envelope: &env,
            };
            run(&w, &entry, SenderIdentity::Held(doc), None).map(|r| r.standing)
        };
        let with_renewal = |until: Option<u64>| {
            doc_of(&w.bob, |b| {
                b.apps.push(ListedApp {
                    app_id: renewed_to.app_id(),
                    cert: renewed_to.hash(),
                });
                b.renewed.push(RenewedCert {
                    app_id: w.cert.app_id(),
                    cert: w.cert.hash(),
                    until,
                });
            })
        };
        // Renewed and open: counts.
        assert_eq!(
            at(&with_renewal(None), START).unwrap(),
            Standing::RenewedOpen
        );
        // Renewed and closed: counts only more than the tolerance before `until`.
        let until = START + 10 * CLOCK_TOLERANCE_MS;
        let closed = with_renewal(Some(until));
        assert!(at(&closed, until - CLOCK_TOLERANCE_MS - 1).is_ok());
        assert_eq!(
            check_of(at(&closed, until - CLOCK_TOLERANCE_MS).unwrap_err()),
            7
        );
        // Removed: counts up to the tolerance before `distrust_from`, inclusive.
        let removed = doc_of(&w.bob, |b| {
            b.removed.push(RemovedApp {
                app_id: w.cert.app_id(),
                distrust_from: until,
            })
        });
        assert!(at(&removed, until - CLOCK_TOLERANCE_MS).is_ok());
        assert_eq!(
            check_of(at(&removed, until - CLOCK_TOLERANCE_MS + 1).unwrap_err()),
            7
        );
    }
}
