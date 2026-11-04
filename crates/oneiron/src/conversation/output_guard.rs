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

use super::*;

pub(crate) use crate::store::container_output::ContainerOutputGuard;
pub use crate::store::container_output::OutputMark;

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
