//! Account change notifications, for the feed's long-poll (Switch wire 7.4.4).
//!
//! A feed request with `wait` answers at once when there is something to read, and
//! otherwise waits until its account changes or `wait` seconds pass. A request that changes
//! an account sends a PostgreSQL notification naming it as part of its transaction, so the
//! notification goes out only if the change commits. Every instance of the service listens,
//! and wakes the requests waiting on that account, wherever the change was made. A waiting
//! request is woken by its own account's changes only.

use std::{collections::HashMap, sync::Arc, time::Duration};

use parking_lot::Mutex;
use tokio::sync::watch;

use crate::store::{Store, StoreError};

/// The PostgreSQL notification channel.
pub const CHANNEL: &str = "pubky_switch_changes";

/// Wakes the requests waiting on an account.
#[derive(Debug, Default)]
pub struct ChangeHub {
    channels: Mutex<HashMap<String, watch::Sender<u64>>>,
}

impl ChangeHub {
    /// A hub with no waiters.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Wait for changes of `account`: the receiver sees a new value at each one. Subscribe
    /// before reading the account, so no change between the read and the wait is missed.
    pub fn subscribe(&self, account: &str) -> watch::Receiver<u64> {
        let mut channels = self.channels.lock();
        channels.retain(|_, sender| sender.receiver_count() > 0);
        channels
            .entry(account.to_string())
            .or_insert_with(|| watch::channel(0).0)
            .subscribe()
    }

    /// Wake the requests waiting on `account`.
    pub fn notify(&self, account: &str) {
        let mut channels = self.channels.lock();
        if let Some(sender) = channels.get(account) {
            if sender.receiver_count() == 0 {
                channels.remove(account);
            } else {
                sender.send_modify(|version| *version = version.wrapping_add(1));
            }
        }
    }

    /// Wake every waiting request, as after a lost notification connection, when changes
    /// may have been missed. They read again and find what changed.
    pub fn notify_all(&self) {
        let mut channels = self.channels.lock();
        channels.retain(|_, sender| sender.receiver_count() > 0);
        for sender in channels.values() {
            sender.send_modify(|version| *version = version.wrapping_add(1));
        }
    }

    /// Accounts with waiting requests.
    pub fn waiting(&self) -> usize {
        self.channels
            .lock()
            .values()
            .filter(|sender| sender.receiver_count() > 0)
            .count()
    }
}

/// The database's change notifications, forwarded to a [`ChangeHub`].
pub struct ChangeListener {
    listener: sqlx::postgres::PgListener,
    /// The listener's own one-connection pool, apart from the request pool, so it holds
    /// none of the requests' connections at any pool size.
    _pool: sqlx::PgPool,
}

impl std::fmt::Debug for ChangeListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangeListener").finish_non_exhaustive()
    }
}

impl ChangeListener {
    /// Connect and listen. Once this returns, every later change is seen.
    pub async fn connect(store: &Store) -> Result<Self, StoreError> {
        let options = (*store.pool().connect_options()).clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(options);
        let mut listener = sqlx::postgres::PgListener::connect_with(&pool).await?;
        listener.listen(CHANNEL).await?;
        Ok(Self {
            listener,
            _pool: pool,
        })
    }

    /// Forward notifications to `hub` until `shutdown` resolves. A lost connection is
    /// opened again, and wakes every waiting request, since notifications sent meanwhile
    /// are lost.
    pub async fn run(
        mut self,
        hub: Arc<ChangeHub>,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => return,
                received = self.listener.try_recv() => match received {
                    Ok(Some(notification)) => hub.notify(notification.payload()),
                    Ok(None) => {
                        tracing::warn!("change notifications: connection lost, reconnecting");
                        hub.notify_all();
                    }
                    Err(error) => {
                        tracing::warn!(%error, "change notifications");
                        hub.notify_all();
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_change_hub_wakes_only_its_account() {
        let hub = ChangeHub::new();
        let mut a = hub.subscribe("a");
        let b = hub.subscribe("b");
        hub.notify("a");
        assert!(a.has_changed().expect("open"));
        assert!(!b.has_changed().expect("open"));
        a.mark_unchanged();
        hub.notify_all();
        assert!(a.has_changed().expect("open"));
        assert!(b.has_changed().expect("open"));
    }

    #[tokio::test]
    async fn test_change_hub_forgets_accounts_without_waiters() {
        let hub = ChangeHub::new();
        let a = hub.subscribe("a");
        let b = hub.subscribe("b");
        assert_eq!(hub.waiting(), 2);
        drop(a);
        hub.notify("a");
        assert_eq!(hub.waiting(), 1);
        drop(b);
        let _c = hub.subscribe("c");
        assert_eq!(hub.waiting(), 1);
        // Notifying an account nobody waits on is a no-op.
        hub.notify("nobody");
    }

    #[tokio::test]
    async fn test_change_hub_wait_is_woken() {
        let hub = ChangeHub::new();
        let mut waiting = hub.subscribe("a");
        let notifier = hub.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            notifier.notify("a");
        });
        tokio::time::timeout(Duration::from_secs(2), waiting.changed())
            .await
            .expect("woken")
            .expect("open");
    }
}
