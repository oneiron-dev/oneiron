//! Prepared vector-index neighbor choices bound to a read snapshot.

use crate::entity_id::EntityId;

/// A fresh node's neighbour search, run under a read snapshot before the
/// write transaction opens (RESEARCH-1115 Bend 2), so the writer only writes
/// edges. It stands only while the transaction's graph is the graph it
/// searched: same node count, entry point and vector version, no earlier graph
/// write in the batch, and every chosen neighbour still present.
pub(crate) struct InsertPlan {
    pub(crate) vector_version: u64,
    pub(crate) count: u64,
    pub(crate) entry_point: EntityId,
    pub(crate) vector: Vec<f32>,
    /// Every neighbour list the search expanded: the beam is a function of
    /// these lists, the entry point and the vectors it scored.
    pub(crate) expanded: Vec<(EntityId, u64)>,
    pub(crate) selected: Vec<EntityId>,
}

impl std::fmt::Debug for InsertPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InsertPlan")
            .field("count", &self.count)
            .field("expanded", &self.expanded.len())
            .field("selected", &self.selected.len())
            .finish_non_exhaustive()
    }
}
