//! A peer's sync apply wakes the Dreamer (ARCH-0026 #wake): a turn another
//! host wrote gets the turn producer's read, the wake policy counts what
//! arrived, and a step waiting on a peer's TASK result resumes in the pass
//! the hint takes. The runner's own rows never sync; only the work does.
use std::sync::Arc;

use oneiron::Vault;
use oneiron::dreamer_wake::WakeTurnSubject;
use oneiron::sync::WindowManager;
use oneiron::sync::bridge::{LiveQueryTee, MaterializedDiffSummary, OriginMark};
use tokio::sync::Notify;

use super::AiHandle;

/// Observer B's tee for peer batches. It only posts the wake: it writes
/// nothing and never re-enters the document it was called from.
struct PeerApplyTee {
    applied: Arc<Notify>,
}

impl LiveQueryTee for PeerApplyTee {
    fn on_materialized(&self, _path: &str, diff: &MaterializedDiffSummary, by: &OriginMark) {
        // A local write wakes the Dreamer through its own door; only bytes a
        // peer's connection carried in come this way.
        if by.conn_id.is_some() && !diff.containers.is_empty() {
            self.applied.notify_one();
        }
    }
}

/// The running wake: the tee (held, since the materializer keeps it weakly)
/// and the task that turns a burst of peer batches into one wake.
pub(super) struct SyncWake {
    _tee: Arc<dyn LiveQueryTee>,
    task: tokio::task::JoinHandle<()>,
}

impl SyncWake {
    pub(super) fn spawn(handle: AiHandle, vault: Arc<Vault>, manager: &WindowManager) -> Self {
        let applied = Arc::new(Notify::new());
        let tee: Arc<dyn LiveQueryTee> = Arc::new(PeerApplyTee {
            applied: Arc::clone(&applied),
        });
        manager.materializer().attach_live_query_tee(&tee);
        let task = tokio::spawn(async move {
            loop {
                applied.notified().await;
                // Batches that land while this wake runs leave one permit:
                // they share the next wake.
                if let Some(wake) = handle.wake_on_turn(&vault, WakeTurnSubject::Vault)
                    && let Err(error) = wake.await
                {
                    tracing::warn!(panicked = error.is_panic(), "sync-apply wake did not finish");
                }
            }
        });
        Self { _tee: tee, task }
    }

    /// Stops waking. A wake in flight finishes its own transaction.
    pub(super) fn stop(&self) {
        self.task.abort();
    }
}
