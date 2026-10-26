//! The claim fence a seat run holds, watched while its CLI runs (FIX 9320).
//!
//! The host claims an attempt by id under the queue's lease, and its run's
//! process and T1 destinations live only as long as that claim does. A
//! [`HostSeatLease`] reads the claimed row again on every attempt-queue
//! signal while the run goes on. When the claim actually ends under it (the
//! row is cancelled or settled by another hand, erased, or leased again to
//! another owner or generation), it runs the run's own retirement once and
//! raises the run's stop flag, which the CLI executor reads. A still-held
//! claim needs no renewal: the queue's lease names no expiry. Nothing here
//! times a run out or stops one because a read failed: a read that fails is
//! read again at the next signal, and the run goes on.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::Vault;
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord};
use oneiron::dispatch_byoa::ByoaExecutionFence;
use tokio::sync::broadcast;

/// One claimed run's fence, watched on the host's runtime until the run
/// ends. Dropping it stops the watch.
pub(super) struct HostSeatLease {
    /// Raised once the claim is lost: the run's process is to stop.
    lost: Arc<AtomicBool>,
    watcher: Option<tokio::task::JoinHandle<()>>,
}

impl HostSeatLease {
    /// Watches `fence` on `vault` from the runtime this host runs on, and
    /// calls `on_lost` once, from the watch, if the claim is actually lost
    /// before [`Self::end`]. Off a runtime nothing is watched, as before.
    pub(super) fn watch(
        vault: Arc<Vault>,
        fence: ByoaExecutionFence,
        on_lost: impl FnOnce() + Send + 'static,
    ) -> Self {
        let lost = Arc::new(AtomicBool::new(false));
        let watcher = tokio::runtime::Handle::try_current().ok().map(|runtime| {
            let lost = Arc::clone(&lost);
            runtime.spawn(watch(vault, fence, lost, on_lost))
        });
        Self { lost, watcher }
    }

    /// The flag the run's process stops on: raised when its claim is lost.
    pub(super) fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.lost)
    }

    /// Stops the watch: the run has ended. Whether its claim was lost while
    /// it ran.
    pub(super) fn end(mut self) -> bool {
        if let Some(watcher) = self.watcher.take() {
            watcher.abort();
        }
        self.lost.load(Ordering::SeqCst)
    }
}

impl Drop for HostSeatLease {
    fn drop(&mut self) {
        if let Some(watcher) = self.watcher.take() {
            watcher.abort();
        }
    }
}

/// Reads the claimed row now and after each attempt-queue signal until it
/// no longer holds `fence`; then raises `lost` and runs `on_lost`.
async fn watch(
    vault: Arc<Vault>,
    fence: ByoaExecutionFence,
    lost: Arc<AtomicBool>,
    on_lost: impl FnOnce() + Send + 'static,
) {
    // Subscribed before the first read, so a change between them still wakes
    // the watch.
    let mut wake = AttemptQueue::new(&vault).subscribe();
    loop {
        let read = {
            let vault = Arc::clone(&vault);
            let id = fence.attempt_id;
            tokio::task::spawn_blocking(move || AttemptQueue::new(&vault).get(id)).await
        };
        if let Ok(Ok(row)) = read
            && !holds(row.as_ref(), &fence)
        {
            lost.store(true, Ordering::SeqCst);
            on_lost();
            return;
        }
        match wake.recv().await {
            Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

/// Whether `row` still holds the claim `fence` names: it exists, has not
/// ended, and is leased to the same owner in the same generation.
fn holds(row: Option<&AttemptRecord>, fence: &ByoaExecutionFence) -> bool {
    row.is_some_and(|row| {
        !row.state.is_terminal()
            && row.lease_owner.as_deref() == Some(fence.lease_owner.as_str())
            && row.attempt_count == fence.attempt_count
    })
}
