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
    /// When the restore ran, app clock: only a page read once the own `identity.json` was
    /// confirmed after it settles the verdict.
    pub(crate) restored_at_ms: u64,
    /// `None` until a page settled it.
    pub(crate) verdict: Option<HeldCursor>,
}

/// `hgap`: the gap ahead last handed to the protocol as a `missed` item, by generation
/// and held `seq`, so each occurrence is handed once, across loads.
const GAP_HANDED: &str = "hgap";

/// What comparing a page's `cursor` came to ([`App::compare_held_cursor`]).
pub(crate) struct Compared {
    /// A gap ahead to hand to the protocol as a `missed` item, not handed before: the
    /// `seq` reported and the position compared, which the event names. Handing it, in the page's transaction,
    /// owes a listing before the page's items (Switch spec 8.3 "Ahead").
    pub(crate) gap: Option<(u64, u64)>,
    /// The restore's check, settled or changed by this page: the app takes it once the
    /// page's commit is done.
    pub(crate) restore: Option<RestoreCursor>,
}

impl App {
    /// The held cursor's verdict on the last restore (Switch spec 12.4 "The held cursor"):
    /// `None` without a restore in reconcile mode, or before a page settled it.
    ///
    /// The verdict settles at the first feed page read once the app confirmed its newest
    /// own `identity.json` after the restore ([`App::refresh_identity`]): the host refreshes
    /// it after a restore, as before any attempt. Before that the app may be reading an
    /// old service that still answers, so a page settles nothing, and the verdict is
    /// `None`, never [`HeldCursor::Clean`].
    ///
    /// [`HeldCursor::Clean`] needs, of the eight conditions, the ones the client checks: the
    /// first page from the current service, read once the newest `identity.json` was
    /// confirmed and the app followed it, not a frozen service's, carried `cursor` under a
    /// verified response signature, before any cursor move of the app was sent (1); the
    /// backup's position is of the current sequence, judged again at every call, so a loss
    /// followed later reads [`HeldCursor::Unknown`] (2); the position compared is the
    /// backup's committed one (3, by construction); the report is at or behind it (4); the
    /// restored receive key was the current one (6). A `missed` item after the position (5)
    /// goes to the protocol as always, and the verdict holds outside what it covers. That
    /// no other copy of the restored state runs again (7) is the host's to know; an app whose
    /// devices don't share its cursor ends a clean verdict at a later report ahead of it.
    /// Every other step of the restore runs whatever the verdict (8).
    ///
    /// A protocol may resume after a clean restore without asking its user about messages
    /// that may be lost; whether it does is the protocol's. The verdict goes when the
    /// restore's reconcile mode ends with its key check done.
    pub fn restore_held_cursor(&self) -> Option<HeldCursor> {
        let check = self.state.restore_cursor?;
        let verdict = check.verdict?;
        Some(if self.current_sequence(check.generation) {
            verdict
        } else {
            HeldCursor::Unknown
        })
    }

    /// The furthest position of the current generation the app committed or sent a move
    /// to. No move goes past the committed cursor: a cursor-only move sends the cursor a
    /// page committed, and a batch with operations carries that same cursor, kept with it
    /// before its first send. So it is the committed cursor.
    fn furthest_sent(&self) -> u64 {
        let cursor = self.state.cursor;
        cursor.seq.max(cursor.at_service)
    }

    /// Whether a position of `generation` is of the current sequence (Switch spec 8.3).
    fn current_sequence(&self, generation: u64) -> bool {
        self.state
            .own_doc
            .body()
            .recovery_from
            .is_none_or(|lost| generation > lost)
    }

    /// Compare a page's `cursor` with the app's position: the page's verdict, folded into
    /// the read's ([`super::ReceiveReport::held_cursor`]), a gap ahead to hand over, and
    /// the restore's check as the page settles it.
    pub(crate) async fn compare_held_cursor(
        &mut self,
        reported: Option<u64>,
    ) -> Result<Compared, AppError> {
        let shared = self.state.device.multi_device;
        let judge = |held: Option<u64>, position: u64, current: bool| match held {
            _ if !current => HeldCursor::Unknown,
            None => HeldCursor::Unknown,
            Some(held) if held <= position => HeldCursor::Clean,
            // Another device's move is ordinary for an app whose devices share its cursor.
            Some(_) if shared => HeldCursor::Unknown,
            Some(held) => HeldCursor::Ahead { held, position },
        };
        let generation = self.state.cursor.generation;
        let current = self.current_sequence(generation);
        // A restore whose verdict isn't settled: the host knows of it, so ahead isn't told.
        let restoring = self
            .state
            .restore_cursor
            .is_some_and(|check| check.verdict.is_none());
        let verdict = judge(reported, self.furthest_sent(), current);
        self.held_cursor_read = Some(
            self.held_cursor_read
                .map_or(verdict, |earlier| earlier.worse(verdict)),
        );
        // The restore's check: settled at the first page read once the newest own
        // `identity.json` was confirmed after the restore; a later ahead ends a clean one.
        let mut restore = None;
        let mut settles = false;
        if let Some(mut check) = self.state.restore_cursor {
            let confirmed = self
                .identity_confirmed
                .is_some_and(|c| c.at_ms >= check.restored_at_ms);
            match check.verdict {
                None if confirmed => {
                    let key_current = self
                        .state
                        .restore
                        .as_ref()
                        .is_some_and(|restore| restore.key_current == Some(true));
                    let current = self.current_sequence(check.generation);
                    check.verdict = Some(match judge(reported, check.seq, current) {
                        HeldCursor::Clean if !key_current => HeldCursor::Unknown,
                        other => other,
                    });
                    settles = true;
                    restore = Some(check);
                }
                Some(HeldCursor::Clean) if matches!(verdict, HeldCursor::Ahead { .. }) => {
                    check.verdict = Some(verdict);
                    restore = Some(check);
                }
                _ => {}
            }
        }
        let HeldCursor::Ahead { held, position } = verdict else {
            self.held_ahead_told = None;
            return Ok(Compared { gap: None, restore });
        };
        // Told once for each higher report in a generation while the app runs, and not while
        // a restore's verdict is open or at the page that settles it: the host knows of the
        // restore (Switch spec 8.3, "at a read other than a restore's").
        let told = self
            .held_ahead_told
            .is_some_and(|(g, told)| g == generation && told >= held);
        if !told {
            self.held_ahead_told = Some((generation, held));
            if !settles && !restoring {
                self.events
                    .push(AppEvent::HeldCursorAhead { held, position });
            }
        }
        let handed: Option<(u64, u64)> = self.reader().get(GAP_HANDED).await?;
        let gap = handed
            .is_none_or(|(g, last)| g != generation || held > last)
            .then_some((held, position));
        Ok(Compared { gap, restore })
    }

    /// Note a gap ahead handed to the protocol, in `tx`.
    pub(crate) fn gap_handed(&self, held: u64, tx: &mut Tx) -> Result<(), AppError> {
        tx.put(GAP_HANDED, &(self.state.cursor.generation, held))
    }

    /// A batch carrying a cursor move is about to be sent: a restore whose verdict isn't
    /// settled yet can't tell its own move from an earlier instance's, so its verdict is
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
