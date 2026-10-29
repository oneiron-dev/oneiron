//! The hub's refresh loop: one task per hub, driving every kept session's
//! refresh on a short tick and, at once, on the vault's committed
//! notification signal (FIX 3084).
use super::Hub;
use std::sync::Arc;
use std::time::Duration;

/// Drives `hub`'s refresh every 25 ms, and as soon as `notifications` says a
/// put or mark committed. Signals that arrive during one refresh coalesce
/// into the next. The loop ends with the hub's server.
pub(super) fn spawn(hub: Arc<Hub>, mut notifications: tokio::sync::watch::Receiver<u64>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        // A closed vault sends no more signals; the tick goes on alone.
        let mut signalled = true;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                changed = notifications.changed(), if signalled => signalled = changed.is_ok(),
            }
            if hub.server.strong_count() == 0 {
                break;
            }
            hub.refresh();
            // Refolding live authority can exceed one period. Do not replay
            // overdue checks in a continuously-ready catch-up loop that
            // starves socket I/O; inspect current state again after a pause.
            tick.reset();
        }
    });
}
