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
        #[cfg(feature = "sync")]
        for id in ids {
            let _ = self.task_updates.send(id);
        }
        #[cfg(not(feature = "sync"))]
        let _ = ids;
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
