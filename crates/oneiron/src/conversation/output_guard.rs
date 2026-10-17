//! The container output guard (OF-365 P5, FIX 1389): the fence between an
//! attendee's first entry into a container and output assembled before it.
//!
//! A committed entry wakes each live host through the committed TASK
//! broadcast ([`Vault::subscribe_task_updates`]). That wake can lag, so it is
//! no fence on its own. This is the fence. Every first entry moves its
//! container's entry mark twice. The first move happens in its write, before
//! the commit, so a rolled-back entry only over-cancels. The second happens
//! as the commit is announced, before any wake goes out, whichever door
//! wrote the entry. Output marked before either move refuses to go out into
//! that container. A host takes its mark before the first read its output
//! is assembled from. So an assembly that could have missed the entry never
//! publishes, and one marked after the committed move has read the entry.
//! Marks are per vault and in memory only: no output outlives the process
//! that assembled it.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::*;

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

    fn mark(&self) -> OutputMark {
        OutputMark(self.lock().order)
    }

    fn admits(&self, mark: OutputMark, container: EntityId) -> bool {
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

impl Vault {
    /// The mark an output takes before the first read it is assembled from.
    #[must_use]
    pub fn container_output_mark(&self) -> OutputMark {
        self.store.container_output.mark()
    }

    /// The publish arm: whether output marked at `mark` may still go out
    /// into `container`, because no attendee has entered it since. Check
    /// it before each text delta or audio batch is published.
    #[must_use]
    pub fn container_output_admits(&self, mark: OutputMark, container: EntityId) -> bool {
        self.store.container_output.admits(mark, container)
    }

    /// The conversation `record` lies in, if it lies in one: a TURN's, or
    /// a MESSAGE's through its TURN.
    pub fn record_container(&self, record: EntityId) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        room_for_record_in(self, &txn, record)
    }
}
