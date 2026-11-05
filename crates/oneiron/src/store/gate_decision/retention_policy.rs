//! Core half of `store::gate_decision::retention_policy`: its store-layer items live in `oneiron_store::gate_decision::retention_policy` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::gate_decision::retention_policy::*;

/// Trusted append-time ancestry for a decision's retention evaluation.
/// Missing levels cannot be asserted later by a caller-selected sweep scope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct GateRetentionContext {
    pub(crate) world: Option<crate::EntityId>,
    pub(crate) project: Option<crate::EntityId>,
    pub(crate) sub_project: Option<crate::EntityId>,
    pub(crate) thread: Option<crate::EntityId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateRetentionScope {
    Vault,
    World(crate::EntityId),
    Project(crate::EntityId),
    SubProject(crate::EntityId),
    Thread(crate::EntityId),
}

impl GateRetentionScope {
    fn rank(self, context: GateRetentionContext) -> Option<u8> {
        match self {
            Self::Vault => Some(0),
            Self::World(id) if context.world == Some(id) => Some(1),
            Self::Project(id) if context.project == Some(id) => Some(2),
            Self::SubProject(id)
                if context.sub_project == Some(id) && context.project.is_some() =>
            {
                Some(3)
            }
            Self::Thread(id) if context.thread == Some(id) && context.project.is_some() => Some(4),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateRetentionRow {
    pub(crate) row_ref: String,
    pub(crate) scope: GateRetentionScope,
    pub(crate) horizon_secs: Option<u64>,
    pub(crate) override_parent: bool,
}

/// Owner-authored age sweep settings. `None` never authorizes pruning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateDecisionRetentionPolicy {
    pub(crate) horizon_secs: Option<u64>,
    pub(crate) max_sweep_rows: usize,
    pub(crate) precedence: GateRetentionPrecedence,
    /// Only the vault is a legal ceiling for an authenticated holder override.
    pub(crate) holder_override_ceiling: GateRetentionOverrideCeiling,
    pub(crate) rows: Vec<GateRetentionRow>,
}

impl GateDecisionRetentionPolicy {
    /// Evaluate the decision's append-time ancestry. `None` is unbounded
    /// retention; a child cannot make an absent vault opt-in prune anything.
    pub(crate) fn horizon_for(&self, context: GateRetentionContext) -> Option<u64> {
        let vault = self.horizon_secs?;
        let mut horizon = Some(vault);
        let mut rows: Vec<(u8, &GateRetentionRow)> = self
            .rows
            .iter()
            .filter_map(|row| {
                row.scope
                    .rank(context)
                    .filter(|rank| *rank > 0)
                    .map(|rank| (rank, row))
            })
            .collect();
        rows.sort_by_key(|(rank, _)| *rank);
        for (_, row) in rows {
            horizon = match self.precedence {
                GateRetentionPrecedence::NestedNarrowing
                    if !row.override_parent
                        || self.holder_override_ceiling == GateRetentionOverrideCeiling::Parent =>
                {
                    match (horizon, row.horizon_secs) {
                        (Some(parent), Some(child)) => Some(parent.max(child)),
                        _ => None, // unbounded parent or child cannot narrow
                    }
                }
                // Holder may release the direct parent, but never undercut
                // the authored vault floor. Most-specific is a separate
                // manifest-selected rule: a deeper row replaces its parent.
                GateRetentionPrecedence::NestedNarrowing
                | GateRetentionPrecedence::MostSpecific => {
                    row.horizon_secs.map(|child| vault.max(child))
                }
            };
        }
        horizon
    }
}
