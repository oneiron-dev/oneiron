//! Chat turns in flight. Shutdown gives each a grace to reach its terminal,
//! then tells the rest to stop, so every turn ends with its message either
//! saved or cancelled, never left open.
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, watch};

#[derive(Clone)]
pub(crate) struct TurnTracker(Arc<Inner>);

struct Inner {
    active: AtomicUsize,
    drained: Notify,
    stop: watch::Sender<bool>,
}

/// Held by one running turn; dropping it marks the turn finished.
pub(crate) struct TurnGuard {
    tracker: TurnTracker,
    stop: watch::Receiver<bool>,
}

impl TurnTracker {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Inner {
            active: AtomicUsize::new(0),
            drained: Notify::new(),
            stop: watch::channel(false).0,
        }))
    }

    pub(crate) fn enter(&self) -> TurnGuard {
        self.0.active.fetch_add(1, Ordering::SeqCst);
        TurnGuard {
            tracker: self.clone(),
            stop: self.0.stop.subscribe(),
        }
    }

    /// Waits up to `grace` for running turns, stops the rest, and waits up
    /// to `grace` again for them to cancel.
    pub(crate) async fn shutdown(&self, grace: Duration) {
        if tokio::time::timeout(grace, self.drained()).await.is_ok() {
            return;
        }
        self.stop_now();
        let _ = tokio::time::timeout(grace, self.drained()).await;
    }

    /// Tells running turns to stop, without waiting.
    pub(crate) fn stop_now(&self) {
        self.0.stop.send_replace(true);
    }

    async fn drained(&self) {
        loop {
            // Created before the check, so a finish in between still wakes it.
            let finished = self.0.drained.notified();
            if self.0.active.load(Ordering::SeqCst) == 0 {
                return;
            }
            finished.await;
        }
    }
}

impl TurnGuard {
    /// Resolves once shutdown asks running turns to stop.
    pub(crate) async fn stopping(&mut self) {
        let _ = self.stop.wait_for(|stop| *stop).await;
    }
}

impl Drop for TurnGuard {
    fn drop(&mut self) {
        if self.tracker.0.active.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.tracker.0.drained.notify_waiters();
        }
    }
}
