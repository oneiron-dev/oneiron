//! Post-commit invalidations for local run-tree observers.

use super::AttemptQueue;

impl crate::store::Store {
    /// Called only after a successful commit. Co-committing facade paths can
    /// notify coarsely; the observer suppresses unchanged, run-scoped trees.
    pub(crate) fn notify_attempt_observers(&self) {
        #[cfg(feature = "sync")]
        let _ = self.attempt_updates.send(());
    }

    /// Called only after a successful commit, with the TASKs it wrote.
    pub(crate) fn notify_task_updates(&self, ids: impl IntoIterator<Item = crate::EntityId>) {
        // A committed attendee entry moves its container's output mark
        // before any wake goes out (OF-365 P5).
        let ids = ids
            .into_iter()
            .inspect(|id| self.container_output.committed(*id));
        #[cfg(feature = "sync")]
        for id in ids {
            let _ = self.task_updates.send(id);
        }
        #[cfg(not(feature = "sync"))]
        ids.for_each(drop);
    }
}

impl AttemptQueue<'_> {
    /// Subscribe before taking a snapshot to avoid losing a concurrent commit.
    /// A lagged receiver must read a fresh snapshot, not retry a lost delta.
    #[cfg(feature = "sync")]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.store.attempt_updates.subscribe()
    }
}
