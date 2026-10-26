//! The mesh listener's stop for the work its routes admitted (FIX 4755,
//! 4756), under one deadline: the host's drain grace from the stop's start,
//! taken once. In its order:
//!
//! 1. no new work: no tick starts, a redrive or a pack rescan starts no next
//!    unit, and neither the organ service nor the model service admits a
//!    new call;
//! 2. the sync streams end, as they did;
//! 3. the ticks, their blocking work and the routes' connections are
//!    awaited until the deadline, never aborted;
//! 4. then the organ work still running is cancelled (each organ call with
//!    the protocol's shutdown reason) and the ticks' blocking work reaped,
//!    while the model service cancels its own at the same deadline;
//! 5. a held call the stop cut short or never tried stays held, as it was,
//!    for the next start, and the log says how many;
//! 6. then the endpoint closes, and the connections still open are awaited.

use std::time::{Duration, Instant};

use oneiron_organ_host::{MeshCancel, Redrive, Redriven};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::host::MeshTick;

/// The stop of the work the mesh's routes admitted, beside its sync
/// streams' own.
pub(super) struct MeshShutdown {
    /// The organ work's stop and cancel: the held-call redrive, the pack
    /// organ rescan, and the organ calls the listener serves.
    pub(super) organs: MeshCancel,
    /// `None` while the listener serves; then the one deadline, which the
    /// model service's calls drain by.
    pub(super) deadline: watch::Sender<Option<Instant>>,
}

impl MeshShutdown {
    pub(super) fn new() -> Self {
        Self {
            organs: MeshCancel::new(),
            deadline: watch::Sender::new(None),
        }
    }

    /// Begins the stop (step 1), and returns its one deadline.
    pub(super) fn begin(&self) -> Instant {
        let deadline = Instant::now() + crate::commands::DRAIN_GRACE;
        self.organs.stop();
        self.deadline.send_replace(Some(deadline));
        deadline
    }

    /// Steps 3 to 5: awaits `ticks` and `accepts` until `deadline`, then
    /// cancels the organ work still running and reaps the ticks. Returns
    /// `accepts` while connections still run, for the endpoint's close.
    pub(super) async fn drain(
        &self,
        ticks: Option<JoinHandle<()>>,
        accepts: JoinHandle<()>,
        deadline: Instant,
    ) -> Option<JoinHandle<()>> {
        let (ticks, accepts) = tokio::join!(until(ticks, deadline), until(Some(accepts), deadline));
        if ticks.is_some() || accepts.is_some() {
            tracing::info!("mesh work still runs at the stop's deadline; cancelling it");
        }
        self.organs.cancel();
        if let Some(ticks) = ticks {
            let _ = ticks.await;
        }
        accepts
    }
}

/// `task`, awaited until `deadline`: `None` once it has ended, else the
/// task still running.
async fn until(task: Option<JoinHandle<()>>, deadline: Instant) -> Option<JoinHandle<()>> {
    let mut task = task?;
    match tokio::time::timeout_at(deadline.into(), &mut task).await {
        Ok(_) => None,
        Err(_) => Some(task),
    }
}

/// The routes' ticks, one round each `every`, until the stop begins: no
/// tick starts after it, and the one running ends its unit, its blocking
/// work awaited here, never aborted.
pub(super) async fn tick(ticks: Vec<MeshTick>, organs: MeshCancel, every: Duration) {
    let mut every = tokio::time::interval(every);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = organs.stopped() => return,
            _ = every.tick() => {}
        }
        for tick in &ticks {
            if organs.is_stopping() {
                return;
            }
            tick().await;
        }
    }
}

/// Logs what a redrive left held under the stop (step 5).
pub(super) fn held(redriven: &[Redriven]) {
    let interrupted = redriven
        .iter()
        .filter(|call| matches!(call.state, Redrive::Interrupted))
        .count();
    let deferred = redriven
        .iter()
        .filter(|call| matches!(call.state, Redrive::Deferred))
        .count();
    if interrupted + deferred > 0 {
        tracing::info!(
            interrupted,
            deferred,
            "the mesh stop left held organ calls held for the next start"
        );
    }
}
