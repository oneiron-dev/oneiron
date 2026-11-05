//! Core half of `serialize::pack_accounting`: its store-layer items live in `oneiron_store::serialize::pack_accounting` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::serialize::pack_accounting::*;

use crate::entity_id::EntityId;
use std::collections::BTreeSet;

/// The critical claims a pack run found among its admitted candidates, and
/// those its budgets left out (FIX 9760). Engine-internal: the ids never
/// leave the engine. Only [`PackStats::critical_count`] and
/// [`PackStats::critical_over_budget`] do, counted over the ids the reading
/// caller is admitted to.
#[derive(Debug, Clone, Default)]
pub(crate) struct PackCriticalAccounting {
    /// Critical claims among the admitted candidates before any cut.
    pub(crate) eligible_ids: BTreeSet<EntityId>,
    /// Those of `eligible_ids` that a per-kind, diversity, result, neighbor
    /// or world-share cut left out of the pack.
    pub(crate) budget_omitted_ids: BTreeSet<EntityId>,
}
