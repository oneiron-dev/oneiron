//! Prepared vector-index neighbor choices bound to a read snapshot.

use oneiron_contracts::entity_id::EntityId;

/// A fresh node's neighbour search, run under a read snapshot before the
/// write transaction opens (RESEARCH-1115 Bend 2), so the writer only writes
/// edges. It stands only while the transaction's graph is the graph it
/// searched: same node count, entry point and vector version, no earlier graph
/// write in the batch, and every chosen neighbour still present.
pub struct InsertPlan {
    /// The vector version the search read.
    pub vector_version: u64,
    /// The node count the search read.
    pub count: u64,
    /// The entry point the search started from.
    pub entry_point: EntityId,
    /// The new node's vector.
    pub vector: Vec<f32>,
    /// Every neighbour list the search expanded: the beam is a function of
    /// these lists, the entry point and the vectors it scored.
    pub expanded: Vec<(EntityId, u64)>,
    /// The neighbours the search chose.
    pub selected: Vec<EntityId>,
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
