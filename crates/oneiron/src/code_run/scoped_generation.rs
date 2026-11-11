//! A host-profiled child's original generation accounting, lent to compaction.

use crate::llm::WorkContext;
use crate::llm::manifest::ModelRole;

/// Admission and scheduling from the host that supplied a scoped child's
/// generation. A compaction call uses the same count and work identity as
/// that generation, without borrowing its extraction backend.
pub trait ScopedChildGeneration: Send + Sync {
    /// Admits one call while the original generation is open and not stopped.
    /// The returned ticket must settle once, including when dropped.
    fn admit(&self) -> Option<Box<dyn ScopedChildGenerationCall>>;

    /// The original child's deadline, cancellation identity and parent ticket.
    fn work_context(&self) -> WorkContext;

    /// The role the child's live generation is admitted on. A self-written
    /// live compaction fork must use that role, not the host's chat role.
    fn live_role(&self) -> ModelRole;
}

/// One admitted call on the original generation count. An implementation
/// settles zero on drop unless `settle` already consumed it.
pub trait ScopedChildGenerationCall: Send {
    /// Settles the response's input plus output units, or zero for an error
    /// or a call that was not sent. Closing the parent is the host's job.
    fn settle(self: Box<Self>, units: u64);
}
