//! Resolved-view types plus the `PolicyManifestResolution` struct definition.

use crate::llm::{BudgetExhaustionPolicy, BudgetPolicyTable};

use crate::gate::breaker::GateBreakerThresholds;
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
pub(crate) enum CommOptOutPosture {
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

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PolicyManifestResolution {
    pub(crate) diagnostics: PolicyManifestDiagnostics,
    pub(super) packs: Vec<PolicyPack>,
    pub(super) actor_ceilings: Vec<ActorCeiling>,
    pub(crate) delegation_fold: DelegationFoldCache,
    pub(super) source_trust: SourceTrustCeiling,
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
    /// ONE-1453: the ONE resolved burst-breaker dial, or `None` for engine
    /// defaults. Zero valid overrides and two-or-more distinct valid overrides
    /// both resolve here as `None`.
    pub(super) actor_burst_breaker: Option<GateBreakerThresholds>,
}
