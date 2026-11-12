//! The model-seat watcher: releases Dreamer parks whose spent seat is back.
//!
//! A seat park names the model seat (a login or subscription) and the reset
//! its refusal reported. The watcher sweeps the durable due index and releases
//! every due seat through the engine's own writer in one write, which wakes
//! those seats' parks in that write. It runs beside the resident
//! pump and stops with it; on restart it simply reads the durable index
//! again. It never resumes a park itself.

use std::sync::Arc;
use std::time::Duration;

use oneiron::attempt_queue::AttemptQueue;
use tokio::sync::broadcast;

use super::{HousekeepingAdmission, SyncServer, admit_every_pass};

/// How long the watcher sleeps with no due reset known, and the longest it
/// ever sleeps: a due reset waits at most this past its time.
const IDLE_SLEEP: Duration = Duration::from_secs(60);
/// The shortest wait between two sweeps, so a burst of commits costs one.
const PASS_SPACING: Duration = Duration::from_secs(1);

impl SyncServer {
    /// Starts the model-seat watcher beside the resident pump.
    pub(crate) fn spawn_model_seat_watcher(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        self.spawn_model_seat_watcher_admitted(admit_every_pass())
    }

    /// Starts the watcher on a host with a write freeze: each sweep is
    /// admitted through `admit` and holds that admission on its blocking
    /// thread until its write commits. Nothing is admitted while it sleeps.
    pub(crate) fn spawn_model_seat_watcher_admitted(
        self: &Arc<Self>,
        admit: HousekeepingAdmission,
    ) -> tokio::task::JoinHandle<()> {
        let server = Arc::clone(self);
        tokio::spawn(async move { server.watch_model_seats_forever(admit).await })
    }

    async fn watch_model_seats_forever(self: Arc<Self>, admit: HousekeepingAdmission) {
        // Subscribed before the first sweep, so a park committed between
        // that sweep and the first wait still wakes the loop early.
        let mut wake = AttemptQueue::new(self.vault()).subscribe();
        loop {
            // A refused sweep (a vault frozen for reap) writes nothing
            // and asks again.
            let Some(admission) = admit() else {
                tokio::time::sleep(PASS_SPACING).await;
                continue;
            };
            let server = Arc::clone(&self);
            let next_due = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                server.seat_sweep_once()
            })
            .await
            .unwrap_or(None);
            let sleep = next_due
                .map(|due| due.saturating_sub(unix_now()))
                .map(Duration::from_secs)
                .unwrap_or(IDLE_SLEEP)
                .clamp(PASS_SPACING, IDLE_SLEEP);
            let commit_woke = tokio::select! {
                signal = wake.recv() => {
                    if matches!(signal, Err(broadcast::error::RecvError::Closed)) {
                        return;
                    }
                    true
                }
                () = tokio::time::sleep(sleep) => false,
            };
            if commit_woke {
                // A commit woke the loop: space the next sweep, as the resident pump does.
                tokio::time::sleep(PASS_SPACING).await;
            }
            // One sweep serves the burst of commits that woke it.
            while let Ok(()) | Err(broadcast::error::TryRecvError::Lagged(_)) = wake.try_recv() {}
        }
    }

    /// One sweep: releases every due seat, then reads the next due reset.
    /// Blocking. A sweep that cannot read or write logs and reads nothing:
    /// the loop sleeps the idle interval and tries again.
    fn seat_sweep_once(&self) -> Option<u64> {
        let released = match self.vault().release_due_model_seats() {
            Ok(seats) => seats.len(),
            Err(error) => {
                tracing::warn!(%error, "the model seat watcher cannot release due seats; it retries");
                return None;
            }
        };
        tracing::debug!(released, "the model seat watcher swept due model seats");
        if released > 0 {
            tracing::info!(released, "the model seat watcher released due model seats");
        }
        match self.vault().next_model_seat_reset_due() {
            Ok(next_due) => next_due,
            Err(error) => {
                tracing::warn!(%error, "the model seat watcher cannot read the next seat reset; it retries");
                None
            }
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
