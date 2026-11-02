//! The txn ids of recent commits that wrote only request-replay rows (a
//! slip's nonce and proof clock) or the clock floor (FIX 11568). A Dreamer
//! read phase that pinned the commit generation reads those commits as
//! leaving its inputs as they were, so an agent's recalls do not stale it.

use std::collections::BTreeSet;
use std::sync::{Mutex, PoisonError};

/// How many recent ids the ring keeps; an id that fell out reads as a
/// change.
const REPLAY_ONLY_COMMITS_KEPT: usize = 4096;

/// Recent replay-only commits, noted by their txn id.
#[derive(Default)]
pub(crate) struct ReplayOnlyCommits {
    ids: Mutex<BTreeSet<usize>>,
}

impl ReplayOnlyCommits {
    /// Notes `id`, the txn id of a commit that returned Ok, ran alone in its
    /// own write txn and wrote only replay rows or the clock floor. A writer
    /// reads it as `env.info().last_txn_id + 1` inside its txn and notes it
    /// only after the commit, never before: an id noted before a commit that
    /// failed would be the next commit's.
    pub(crate) fn note(&self, id: usize) {
        let mut ids = self.ids.lock().unwrap_or_else(PoisonError::into_inner);
        ids.insert(id);
        if ids.len() > REPLAY_ONLY_COMMITS_KEPT {
            ids.pop_first();
        }
    }

    /// Whether every commit after `pinned` through `last` is a noted one. A
    /// commit not noted yet reads as a change.
    pub(crate) fn only_noted_between(&self, pinned: usize, last: usize) -> bool {
        if last <= pinned {
            return last == pinned;
        }
        let ids = self.ids.lock().unwrap_or_else(PoisonError::into_inner);
        last - pinned <= ids.len() && (pinned + 1..=last).all(|id| ids.contains(&id))
    }
}
