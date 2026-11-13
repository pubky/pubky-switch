//! The cursor the service holds for the app (Switch spec 8.3, 12.4; Switch wire 7.4.4).
//!
//! Every feed page carries `cursor`, the `seq` of the cursor the service holds for the
//! app, 0 before its first move. The page's response signature covers it. The app compares
//! it with its own position:
//!
//! - **At every page** with the furthest position it committed or sent: its committed
//!   cursor, or a move in a batch it keeps to send again, whose answer it may not have had.
//!   Every move is recorded with its batch before it is sent: a cursor-only move sends the
//!   cursor a page already committed, and a batch with operations is kept, its move inside
//!   it, before its first send. So the furthest position sent survives a crash.
//! - **At a restore**, once, at the first page read after it, with the backup's committed
//!   position: the restore is [`HeldCursor::Clean`] only when every condition of Switch spec
//!   12.4 "The held cursor" that the client can check holds (`App::restore_held_cursor`).
//!
//! Only a position of the current sequence compares: one whose generation is above the
//! newest own `identity.json`'s `recovery_from`, or any while that is null. A page without
//! `cursor`, from a service of an earlier version, is no report.
//!
//! - **`hcur`**: the restore's check, the backup's position and, once the first page was
//!   read, its verdict, kept until the next restore. An app whose devices don't share its
//!   cursor ends a clean verdict when a later page reports a cursor ahead of the furthest
//!   position it committed or sent.
//!
//! What the app does with ahead is the host's and the protocol's: the client reports it
//! ([`super::AppEvent::HeldCursorAhead`]) and never leaves on the service's word.

use serde::{Deserialize, Serialize};

use super::state::{Tx, key};
use super::{App, AppError, AppEvent};
use crate::client::Batch;

/// What the cursor the service holds says beside the app's own position (Switch spec 8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HeldCursor {
    /// At or behind the app's position: no device of the app passed an entry after it, so
    /// every entry after it is still at the service, but for those a `missed` item shows
    /// deleted and those sealed to a receive key the app doesn't hold. At a restore: every
    /// condition the client checks held as well ([`App::restore_held_cursor`]).
    Clean,
    /// Ahead of the app's position: an instance of the app passed entries after it that
    /// the app's state doesn't hold, and the service may have deleted them since. It is the
    /// service's word only: the app asks its user, and leaves on its own only on evidence
    /// the service can't make up (Switch spec 8.3).
    Ahead {
        /// The `seq` the service reports.
        held: u64,
        /// The `seq` of the app's position it was compared with.
        position: u64,
    },
    /// Nothing to tell: no report, a position a provider loss ended, an app whose devices
    /// share its cursor reported ahead, or, at a restore, a condition the client checks
    /// that didn't hold.
    Unknown,
}

impl HeldCursor {
    /// The worse of two: ahead over unknown over clean.
    pub(crate) fn worse(self, other: Self) -> Self {
        match (self, other) {
            (Self::Ahead { .. }, _) => self,
            (_, Self::Ahead { .. }) => other,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Clean,
        }
    }
}

/// `hcur`: a restore's check of the held cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RestoreCursor {
    /// The backup's committed position.
    pub(crate) generation: u64,
    pub(crate) seq: u64,
    /// `None` until the first page after the restore was read.
    pub(crate) verdict: Option<HeldCursor>,
}

impl App {
    /// The held cursor's verdict on the last restore (Switch spec 12.4 "The held cursor"):
    /// `None` without a restore, or before the first feed page after it was read.
    ///
    /// [`HeldCursor::Clean`] needs, of the eight conditions, the ones the client checks: the
    /// first page from the current service carried `cursor` under a verified response
    /// signature, read before any cursor move of the app was sent (1); the backup's
    /// position is of the current sequence (2); the position compared is the backup's
    /// committed one (3, by construction); the report is at or behind it (4); the restored
    /// receive key was the current one (6). A `missed` item after the position (5) goes to
    /// the protocol as always, and the verdict holds outside what it covers. That no other
    /// copy of the restored state runs again (7) is the host's to know; an app whose devices
    /// don't share its cursor ends a clean verdict at a later report ahead of it. Every
    /// other step of the restore runs whatever the verdict (8).
    ///
    /// A protocol may resume after a clean restore without asking its user about messages
    /// that may be lost; whether it does is the protocol's.
    pub fn restore_held_cursor(&self) -> Option<HeldCursor> {
        self.state.restore_cursor.and_then(|check| check.verdict)
    }

    /// The furthest position of the current generation the app committed or sent a move to:
    /// its committed cursor, or a move in a batch it keeps.
    async fn furthest_sent(&self) -> Result<u64, AppError> {
        let cursor = self.state.cursor;
        let mut furthest = cursor.seq.max(cursor.at_service);
        for (_, pending) in self.kept_batches().await? {
            if let Some(position) = Batch::from_body(pending.body.clone())?.cursor()
                && position.generation == cursor.generation
            {
                furthest = furthest.max(position.seq);
            }
        }
        Ok(furthest)
    }

    /// Whether a position of `generation` is of the current sequence (Switch spec 8.3).
    fn current_sequence(&self, generation: u64) -> bool {
        self.state
            .own_doc
            .body()
            .recovery_from
            .is_none_or(|lost| generation > lost)
    }

    /// Compare a page's `cursor` with the app's position, in `tx`: the page's verdict,
    /// folded into the read's ([`super::ReceiveReport::held_cursor`]). The first page after
    /// a restore settles the restore's verdict too.
    pub(crate) async fn compare_held_cursor(
        &mut self,
        reported: Option<u64>,
        tx: &mut Tx,
    ) -> Result<(), AppError> {
        let shared = self.state.device.multi_device;
        let judge = |held: Option<u64>, position: u64, current: bool| match held {
            _ if !current => HeldCursor::Unknown,
            None => HeldCursor::Unknown,
            Some(held) if held <= position => HeldCursor::Clean,
            // Another device's move is ordinary for an app whose devices share its cursor.
            Some(_) if shared => HeldCursor::Unknown,
            Some(held) => HeldCursor::Ahead { held, position },
        };
        let position = self.furthest_sent().await?;
        let current = self.current_sequence(self.state.cursor.generation);
        let verdict = judge(reported, position, current);
        if let HeldCursor::Ahead { held, position } = verdict
            && self.held_ahead_told.is_none_or(|told| held > told)
        {
            self.held_ahead_told = Some(held);
            self.events
                .push(AppEvent::HeldCursorAhead { held, position });
        }
        self.held_cursor_read = Some(
            self.held_cursor_read
                .map_or(verdict, |earlier| earlier.worse(verdict)),
        );
        let Some(mut check) = self.state.restore_cursor else {
            return Ok(());
        };
        match check.verdict {
            None => {
                let key_current = self
                    .state
                    .restore
                    .as_ref()
                    .is_some_and(|restore| restore.key_current == Some(true));
                let restored = judge(reported, check.seq, self.current_sequence(check.generation));
                check.verdict = Some(match restored {
                    HeldCursor::Clean if !key_current => HeldCursor::Unknown,
                    other => other,
                });
            }
            // A later report ahead of the furthest position ends a clean verdict.
            Some(HeldCursor::Clean) if matches!(verdict, HeldCursor::Ahead { .. }) => {
                check.verdict = Some(verdict);
            }
            Some(_) => return Ok(()),
        }
        self.state.restore_cursor = Some(check);
        tx.put(key::RESTORE_CURSOR, &check)
    }

    /// A batch carrying a cursor move is about to be sent: a restore whose first page
    /// isn't read yet can't tell its own move from an earlier instance's, so its verdict is
    /// unknown (Switch spec 12.4 "The held cursor" condition 1).
    pub(crate) async fn note_cursor_sent(&mut self, batch: &Batch) -> Result<(), AppError> {
        let Some(mut check) = self.state.restore_cursor else {
            return Ok(());
        };
        if check.verdict.is_some() || batch.cursor().is_none() {
            return Ok(());
        }
        check.verdict = Some(HeldCursor::Unknown);
        let mut tx = self.tx()?;
        tx.put(key::RESTORE_CURSOR, &check)?;
        self.commit(tx).await?;
        self.state.restore_cursor = Some(check);
        Ok(())
    }
}
