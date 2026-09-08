//! Shared graph, heap, and beam option types.

use std::collections::HashMap;

use crate::entity_id::EntityId;

#[derive(Debug)]
pub(crate) struct RebuiltHnswGraph {
    pub entry_point: Option<EntityId>,
    pub count: u64,
    pub neighbors: Vec<(EntityId, Vec<EntityId>)>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct HeapEntry {
    pub(super) id: EntityId,
    pub(super) distance: f32,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.distance.total_cmp(&other.distance).is_eq()
    }
}

impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.distance
            .total_cmp(&other.distance)
            .then_with(|| self.id.as_bytes().cmp(other.id.as_bytes()))
    }
}

/// Outcome of [`hnsw_insert_inner`]: either the graph mutation was applied
/// in place, or the op is a refresh on a legacy (pre-migration) graph whose
/// contract is a full snapshot rebuild — which the caller schedules so that
/// batched vector updates coalesce into at most one rebuild per transaction.
pub(super) enum InsertOutcome {
    Applied,
    NeedsLegacyRebuild,
}

/// Where [`beam_search`] reads neighbor lists from.
///
/// The persisted rows are the only production source; `Rebuilt` serves the
/// SLIM lazy-search route (ONE-1933 / OF-447), where the graph shape was
/// dropped and re-derived in memory for the current read snapshot. Both
/// variants share one traversal so neighbor ordering, tie-breaks, `fast_dims`
/// prefix scoring, beam width and the full-dimension rescore are identical.
#[derive(Clone, Copy, Debug)]
pub(super) enum GraphSource<'a> {
    Persisted,
    Rebuilt(&'a HashMap<EntityId, Vec<EntityId>>),
}

/// Beam-search knobs, bundled so probed call sites stay within argument
/// limits.
#[derive(Clone, Copy, Debug)]
pub(super) struct BeamOptions {
    pub(super) ef: usize,
    pub(super) lenient_neighbors: bool,
    pub(super) check_existence: bool,
    /// EMB-2 MRL funnel: number of leading vector components every distance
    /// computation scores over. Equal to `config.dimensions` when the
    /// funnel is off.
    pub(super) score_dims: usize,
}
