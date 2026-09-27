//! Resolved-view types plus the `PolicyManifestResolution` struct definition.

use crate::llm::{BudgetExhaustionPolicy, BudgetPolicyTable};

use crate::gate::ceiling::{
    ActorCeiling, DelegationFoldCache, PolicyOwnerPatternRow, PolicyOwnerPolicyRow, PolicyPack,
    PolicySignature, SourceTrustCeiling,
};
use crate::gate::grants::PolicyScopedGrant;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PolicyManifestDiagnostics {
    pub(crate) manifest_count: usize,
    pub(crate) malformed_manifest_seen: bool,
    pub(crate) unsupported_schema_seen: bool,
    pub(crate) engine_version_floor_seen: bool,
    pub(crate) unknown_axis_seen: bool,
}

impl PolicyManifestDiagnostics {
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_fail_closed(self) -> bool {
        self.manifest_count == 0
            || self.malformed_manifest_seen
            || self.unsupported_schema_seen
            || self.engine_version_floor_seen
            || self.unknown_axis_seen
    }

    pub(crate) fn loaded_manifest_forces_fail_closed(self) -> bool {
        self.malformed_manifest_seen
            || self.unsupported_schema_seen
            || self.engine_version_floor_seen
            || self.unknown_axis_seen
    }
}

/// DEC-0005 posture for a send to an opted-out counterparty that carries no
/// matching `comm.send_override` (ARCH-0057 §3.1).
///
/// `Escalate` is the DEFAULT and the restrictive pole: an absent key anywhere,
/// and any single matching pack that names it, resolve here. It is the posture
/// that asks the owner rather than deciding for them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::gate) enum CommOptOutPosture {
    /// Hold the send as a pending owner decision.
    #[default]
    Escalate,
    /// Send immediately, keeping the opt-out receipt trail.
    AllowWithReceipt,
}

impl CommOptOutPosture {
    /// Restrictive composition: any `Escalate` wins.
    #[must_use]
    pub(crate) fn restrict(self, other: Self) -> Self {
        match (self, other) {
            (Self::AllowWithReceipt, Self::AllowWithReceipt) => Self::AllowWithReceipt,
            _ => Self::Escalate,
        }
    }

    /// Manifest token for this posture. The parse direction is
    /// `decode::parse_comm_opt_out_posture`; the two stay exact inverses.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Escalate => "escalate",
            Self::AllowWithReceipt => "allow_with_receipt",
        }
    }
}

/// Trusted append-time ancestry for a decision's retention evaluation.
/// Missing levels cannot be asserted later by a caller-selected sweep scope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct GateRetentionContext {
    pub(crate) world: Option<crate::EntityId>,
    pub(crate) project: Option<crate::EntityId>,
    pub(crate) sub_project: Option<crate::EntityId>,
    pub(crate) thread: Option<crate::EntityId>,
}

/// The manifest chooses how child scope rows compose with their ancestors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateRetentionPrecedence {
    NestedNarrowing,
    MostSpecific,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateRetentionOverrideCeiling {
    Vault,
    Parent,
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

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PolicyManifestResolution {
    pub(crate) diagnostics: PolicyManifestDiagnostics,
    pub(crate) diagnostic_bounds: Option<crate::self_heal::tripwires::TripwireBounds>,
    pub(crate) proposal_check_threshold: Option<u64>,
    pub(super) packs: Vec<PolicyPack>,
    pub(super) actor_ceilings: Vec<ActorCeiling>,
    pub(crate) delegation_fold: DelegationFoldCache,
    pub(super) source_trust: SourceTrustCeiling,
    pub(super) single_valued_predicates: std::collections::BTreeSet<String>,
    pub(super) scoped_grants: Vec<PolicyScopedGrant>,
    pub(super) owner_policy_rows: Vec<PolicyOwnerPolicyRow>,
    pub(super) owner_policy_rows_dropped: bool,
    pub(super) owner_policy_enabled: bool,
    pub(super) owner_policy_document: Option<String>,
    pub(super) owner_policy_output_contract: Option<String>,
    pub(super) owner_policy_patterns: Vec<PolicyOwnerPatternRow>,
    pub(super) owner_policy_patterns_dropped: bool,
    pub(super) signatures: Vec<PolicySignature>,
    pub(super) on_budget_exhausted: Option<BudgetExhaustionPolicy>,
    pub(super) comm_opt_out_posture: Option<CommOptOutPosture>,
    /// The opaque host auto-checker ref (ONE-1296). The CHECKER itself is
    /// never stored here — only the manifest's selector for it. Injection
    /// rides the write door's own options, so no host object is ever reachable
    /// from a resolved manifest.
    pub(super) auto_checker: Option<String>,
    pub(super) budget_policy: BudgetPolicyTable,
    pub(super) gate_decision_retention: Option<GateDecisionRetentionPolicy>,
}
