//! A replacement's startup follows the retirement of every pending predecessor.
use std::sync::{Arc, PoisonError};

use super::{InferenceWorker, Inner, Phase};

impl InferenceWorker {
    /// Binds a new, unpublished supervisor to the worker it replaces. Pending
    /// ancestors survive even when the immediate predecessor never starts.
    #[must_use]
    pub fn with_predecessor(self, previous: &Self) -> Self {
        let mut predecessors = previous
            .inner
            .predecessors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|previous| previous.strong_count() > 0)
            .cloned()
            .collect::<Vec<_>>();
        predecessors.push(Arc::downgrade(&previous.inner));
        *self
            .inner
            .predecessors
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = predecessors;
        self
    }
}

impl Inner {
    pub(super) async fn wait_for_predecessors(&self) -> bool {
        let predecessors = self
            .predecessors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if !predecessors.is_empty() {
            {
                let mut state = self.lock();
                if state.retiring {
                    return false;
                }
                state.phase = Phase::Starting;
            }
            self.notify();
        }
        for previous in predecessors {
            let Some(inner) = previous.upgrade() else {
                continue;
            };
            let previous = InferenceWorker { inner };
            let retired = previous.retire();
            tokio::pin!(retired);
            loop {
                let mut changes = self.changed.subscribe();
                if self.lock().retiring {
                    return false;
                }
                tokio::select! {
                    () = retired.as_mut() => break,
                    _ = changes.changed() => {}
                }
            }
        }
        // An interrupted wait keeps its ancestors for the next replacement.
        self.predecessors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        true
    }
}
