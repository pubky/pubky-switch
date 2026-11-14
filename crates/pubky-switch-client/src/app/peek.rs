//! A push extension's peek (Switch spec 9 step 5).
//!
//! The extension fetches the feed after the cursor and runs the receive checks on each entry
//! without their side effects: the envelope opens with a held receive key; the signature
//! and certificate; the sender app current in a copy of the sender identity's
//! `identity.json` at most 10 minutes old and not marked as equivocating; the kind's
//! scopes; the message not processed already, which it only looks up; the protocol's body
//! check, without the effect (Switch wire 5.1 check 10); and the page's chain, checked on a
//! copy of the app's chain view. A message that passes is shown; one already
//! processed shows nothing; anything else, or every message after the app found itself
//! compromised, shows a generic notification.
//!
//! A peek commits nothing and changes nothing in memory: it doesn't move the cursor, write
//! records, change the chain view or count towards the receive key's rotation (Switch spec
//! 3.6). The app processes the messages when it next reads.

use std::sync::Arc;

use pubky_switch_core::envelope::parse_header;
use pubky_switch_core::message::{Message, MessagePlaintext};
use pubky_switch_core::ops::Position;
use pubky_switch_core::receive::{
    OpenedEntry, Refusal as CheckRefusal, SenderIdentity, check_opened,
};
use pubky_switch_core::records::IdentityDoc;

use super::App;
use super::error::{AppError, Refusal};
use super::identity::{self, DOC_CACHE_MS};
use super::protocol::{ReceivedMessage, Rules};
use super::state::{Processed, key};
use crate::client::answers::{EntryItem, FeedItem, FeedQuery};

/// The most feed pages one peek reads ([`PeekReport::more`]).
pub const PEEK_PAGES: usize = 2;

/// What the extension shows for one entry.
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub enum Peeked {
    /// The message passed the checks: shown.
    Show {
        /// The entry's `seq`.
        seq: u64,
        /// The sender identity.
        sender: [u8; 32],
        /// The message, checked.
        message: Box<Message>,
    },
    /// A generic notification: the message failed a check, its sender couldn't be checked
    /// from a fresh copy, the chain didn't verify, or the app found itself compromised.
    Generic {
        /// The entry's `seq`.
        seq: u64,
    },
}

impl std::fmt::Debug for Peeked {
    // The message's content is the host's to show; `Debug` names the kind only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Peeked::Show { seq, message, .. } => {
                write!(f, "Show(seq {seq}, kind {})", message.kind)
            }
            Peeked::Generic { seq } => write!(f, "Generic(seq {seq})"),
        }
    }
}

/// What a peek found.
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct PeekReport {
    /// One item per entry to notify about, in feed order; a message already processed has
    /// none.
    pub items: Vec<Peeked>,
    /// Whether the pages read verified against a copy of the chain view.
    pub chain_verified: bool,
    /// The peek stopped on its budget, [`PEEK_PAGES`] pages or the call's time
    /// ([`super::AppConfig::call_budget_ms`]), with entries after the last one it checked:
    /// the extension shows one generic notification for them. A peek keeps nothing, so the
    /// next one starts at the cursor again; the app checks them when it next reads.
    pub more: bool,
}

impl App {
    /// Peek at the feed for a push (Switch spec 9 step 5): the receive checks on each entry
    /// after the cursor, read-only. Nothing is committed or changed, and nothing but the
    /// feed is fetched.
    ///
    /// The call is bounded: it reads at most [`PEEK_PAGES`] pages, and no page after the
    /// first past the call's time budget ([`super::AppConfig::call_budget_ms`]); what it
    /// left is [`PeekReport::more`]. Its worst case at the defaults is two feed requests.
    ///
    /// # Errors
    ///
    /// [`Refusal::Left`] for an app that left; [`Refusal::Gone`] for one that isn't current
    /// any more, or whose account is gone; a failed feed read.
    pub async fn peek(&self) -> Result<PeekReport, AppError> {
        Box::pin(async move {
            if self.state.leave.is_some() {
                return Err(Refusal::Left.into());
            }
            if self.state.gone.is_some() {
                return Err(Refusal::Gone.into());
            }
            let Some(mut chain) = self.state.chain.clone() else {
                return Err(Refusal::NotNow("the app isn't registered".into()).into());
            };
            let compromised = self.state.alarm.is_some();
            let cursor = self.state.cursor;
            let now = self.now();
            let multi = self.state.device.multi_device;
            let budget = self.begin_budget();
            let mut report = PeekReport {
                items: Vec::new(),
                chain_verified: true,
                more: false,
            };
            let mut after = cursor.seq;
            for page_n in 0..PEEK_PAGES {
                if page_n > 0 && self.spent(&budget) {
                    report.more = true;
                    break;
                }
                let query = FeedQuery {
                    after: Some(Position {
                        generation: cursor.generation,
                        seq: after,
                    }),
                    limit: Some(self.config.page()),
                    wait: None,
                };
                let page = self.client.feed(query).await?;
                if report.chain_verified && chain.feed_page(&page, now, multi).is_err() {
                    report.chain_verified = false;
                }
                let trusted = report.chain_verified && !compromised && page.freeze.is_none();
                for item in &page.items {
                    if let FeedItem::Entry(entry) = item
                        && entry.seq > cursor.seq
                        && let Some(peeked) = self.peek_entry(entry, trusted).await?
                    {
                        report.items.push(peeked);
                    }
                }
                if !page.more || page.scanned_through <= after {
                    break;
                }
                after = page.scanned_through;
                report.more = page_n + 1 == PEEK_PAGES;
            }
            Ok(report)
        })
        .await
    }

    /// The checks on one entry; `None` for a message already processed.
    async fn peek_entry(
        &self,
        entry: &EntryItem,
        trusted: bool,
    ) -> Result<Option<Peeked>, AppError> {
        let generic = Ok(Some(Peeked::Generic { seq: entry.seq }));
        if !trusted {
            return generic;
        }
        let Ok(header) = parse_header(&entry.envelope) else {
            return generic;
        };
        let secret = header.kids().find_map(|kid| {
            self.state
                .receive_keys
                .values()
                .find(|held| held.key.kid == kid)
                .map(|held| held.key.secret())
        });
        let Some(secret) = secret else {
            return generic;
        };
        let identity = self.state.meta.identity;
        let Ok(plaintext) = MessagePlaintext::open(&entry.envelope, &identity, &secret) else {
            return generic;
        };
        let Some(doc) = self.fresh_sender_doc(&entry.sender).await? else {
            return generic;
        };
        let opened = OpenedEntry {
            sender: entry.sender,
            cert: &entry.cert,
            accepted_at_ms: entry.accepted_at,
        };
        let protocol = Arc::clone(&self.protocol);
        let opaque = protocol.opaque_members();
        let rules = Rules::new(protocol.as_ref(), &self.state.cert, &opaque);
        let received = match check_opened(
            plaintext,
            &opened,
            &identity,
            SenderIdentity::Held(&doc),
            &rules,
            &|_, _| None,
        ) {
            Ok(received) => received,
            Err(CheckRefusal::Duplicate { .. }) => return Ok(None),
            Err(_) => return generic,
        };
        let processed: Option<Processed> = self
            .reader()
            .get(&key::processed(&entry.sender, &received.message.msg_id))
            .await?;
        if processed.is_some() {
            return Ok(None);
        }
        let message = ReceivedMessage {
            seq: entry.seq,
            generation: self.state.cursor.generation,
            sender: entry.sender,
            accepted_at_ms: entry.accepted_at,
            message: received.message,
            plaintext: received.plaintext,
            cert: received.cert,
            standing: received.standing,
            context: entry.context.clone(),
            parked: false,
            released: false,
            conflict: None,
        };
        if protocol.check_body(&message).is_err() {
            return generic;
        }
        Ok(Some(Peeked::Show {
            seq: entry.seq,
            sender: entry.sender,
            message: Box::new(message.message),
        }))
    }

    /// The sender's `identity.json` for the peek: the own one, or a held copy at most 10
    /// minutes old of an identity not marked as equivocating. Nothing is fetched.
    async fn fresh_sender_doc(&self, sender: &[u8; 32]) -> Result<Option<IdentityDoc>, AppError> {
        if *sender == self.state.meta.identity {
            return Ok(Some(self.state.own_doc.clone()));
        }
        let reader = self.reader();
        if reader.exists(&key::ident_equivocated(sender)).await? {
            return Ok(None);
        }
        let now = self.now();
        Ok(identity::held_copy(&reader, sender)
            .await?
            .filter(|(_, fetched)| now.saturating_sub(*fetched) < DOC_CACHE_MS)
            .map(|(doc, _)| doc))
    }
}
