//! Per-container output invalidation marks.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::entity_id::EntityId;

/// The vault's entry order, and the last entry mark of each container an
/// attendee entered.
#[derive(Debug, Default)]
pub(crate) struct ContainerOutputGuard {
    marks: Mutex<EntryMarks>,
}

#[derive(Debug, Default)]
struct EntryMarks {
    /// The latest mark moved; an output marked now stands here.
    order: u64,
    entered: HashMap<EntityId, u64>,
    /// Entry facts written and not yet announced, by their container.
    entering: HashMap<EntityId, EntityId>,
}

/// Where one output's assembly stands in the vault's entry order. Take it
/// with [`Vault::container_output_mark`] before the first read the output
/// is assembled from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputMark(u64);

impl ContainerOutputGuard {
    fn lock(&self) -> MutexGuard<'_, EntryMarks> {
        self.marks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The invalidation arm, in the write of `entry`, a first entry into
    /// `container`: nothing marked before now goes out into it.
    pub(crate) fn entering(&self, entry: EntityId, container: EntityId) {
        let mut marks = self.lock();
        marks.entering.insert(entry, container);
        marks.move_mark(container);
    }

    /// The committed arm, as the commit of TASK `task` is announced: when
    /// it is an entry, nothing marked before now goes out into its
    /// container.
    pub(crate) fn committed(&self, task: EntityId) {
        let mut marks = self.lock();
        if let Some(container) = marks.entering.remove(&task) {
            marks.move_mark(container);
        }
    }

    /// The live-call arm: a voice call went live in `container` (FIX 1388
    /// C1), so nothing marked before now goes out into it. Its speakers'
    /// entries may already stand, and then no new TASK announces them.
    pub(crate) fn changed(&self, container: EntityId) {
        self.lock().move_mark(container);
    }

    pub(crate) fn mark(&self) -> OutputMark {
        OutputMark(self.lock().order)
    }

    pub(crate) fn admits(&self, mark: OutputMark, container: EntityId) -> bool {
        self.lock()
            .entered
            .get(&container)
            .is_none_or(|at| *at <= mark.0)
    }
}

impl EntryMarks {
    fn move_mark(&mut self, container: EntityId) {
        self.order = self.order.saturating_add(1);
        self.entered.insert(container, self.order);
    }
}
