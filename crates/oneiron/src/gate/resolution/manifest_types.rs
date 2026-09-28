//! Resolved-view types plus the `PolicyManifestResolution` struct definition.

use crate::autoreason_campaign::selection::SelectionPolicyRow;
use crate::llm::{BudgetExhaustionPolicy, BudgetPolicyTable};
use std::collections::BTreeMap;

use crate::gate::class_policy::{ActPolicyTable, WaitPolicyTable};

use crate::gate::ceiling::{
    ActorCeiling, DelegationFoldCache, PolicyOwnerPatternRow, PolicyOwnerPolicyRow, PolicyPack,
    PolicySignature, SourceTrustCeiling,
};
use crate::gate::grants::PolicyScopedGrant;
use crate::gate::hosted_tts_policy::HostedTtsPolicy;

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

/// Policy-authored fold order for holder class-carry rows. Every holder is
/// still capped by the trusted vault relation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ConnectorClassPrecedence {
    #[default]
    Nested,
    HolderOverride,
}
impl ConnectorClassPrecedence {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "nested" => Some(Self::Nested),
            "holder_override" => Some(Self::HolderOverride),
            _ => None,
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Nested => "nested",
            Self::HolderOverride => "holder_override",
        }
    }
}

/// The shipped vault-level policy row, composed by nested narrowing.
/// The attempt manifest's 4,096-entry cap is structural; this work budget
/// limits receipt pages, not the number of facts one valid receipt may carry.
pub(crate) const DEFAULT_ATTRIBUTION_REASON_MAX_BYTES: u64 = 4096;
pub(crate) const DEFAULT_ATTRIBUTION_RECEIPTS_PER_PASS: u64 = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttributionLimits {
    pub(crate) reason_max_bytes: u64,
    pub(crate) receipts_per_pass: u64,
    pub(crate) holder_reason_bytes: std::collections::BTreeMap<crate::EntityId, u64>,
}

impl Default for AttributionLimits {
    fn default() -> Self {
        Self {
            reason_max_bytes: DEFAULT_ATTRIBUTION_REASON_MAX_BYTES,
            receipts_per_pass: DEFAULT_ATTRIBUTION_RECEIPTS_PER_PASS,
            holder_reason_bytes: Default::default(),
        }
    }
}

impl AttributionLimits {
    pub(crate) fn restrict(&mut self, other: Self) {
        self.reason_max_bytes = self.reason_max_bytes.min(other.reason_max_bytes);
        self.receipts_per_pass = self.receipts_per_pass.min(other.receipts_per_pass);
        for (holder, limit) in other.holder_reason_bytes {
            self.holder_reason_bytes
                .entry(holder)
                .and_modify(|current| *current = (*current).min(limit))
                .or_insert(limit);
        }
    }

    pub(crate) fn reason_bytes_for(&self, holder: &crate::EntityId) -> u64 {
        self.holder_reason_bytes
            .get(holder)
            .copied()
            .map_or(self.reason_max_bytes, |override_| {
                override_.min(self.reason_max_bytes)
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::gate) struct TeacherProbeRow {
    pub(in crate::gate) min_f1_millionths: u32,
    pub(in crate::gate) holders: BTreeMap<String, u32>,
}

/// Restrict-only typed sheet answer count for a vault, artifact, or sheet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SheetAnswerLimitRow {
    pub(crate) artifact_ref: Option<String>,
    pub(crate) sheet: Option<String>,
    pub(crate) max_count: u64,
}

/// The manifest's explicit scope-composition rule. Other tokens fail decode
/// until their admission semantics are specified and tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SheetAnswerPrecedence {
    NestedNarrowingHolderCappedAtVault,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PolicyManifestResolution {
    pub(crate) diagnostics: PolicyManifestDiagnostics,
    pub(crate) room_thread: Option<crate::gate::RoomThreadManifest>,
    pub(crate) diagnostic_bounds: Option<crate::self_heal::tripwires::TripwireBounds>,
    pub(crate) livequery_tracker_limits: Option<crate::gate::tracker_limits::PolicyTrackerLimits>,
    pub(in crate::gate) teacher_probe_trusted: bool,
    pub(in crate::gate) teacher_probe_vault_min: Option<u32>,
    pub(in crate::gate) teacher_probe_holders: BTreeMap<String, u32>,
    pub(crate) proposal_check_threshold: Option<u64>,
    pub(crate) retrieval_retention: crate::gate::retrieval_retention::RetrievalRetentionPolicy,
    pub(crate) goal_limits: Option<crate::workspace_roster::GoalLimits>,
    pub(crate) voice_ref_defaults: Option<crate::voice_identity::ref_limits::VoiceRefLimitPolicy>,
    pub(crate) voice_ref_limits: crate::voice_identity::ref_limits::VoiceRefLimitPolicy,
    pub(crate) sheet_answer_limits: Vec<SheetAnswerLimitRow>,
    pub(crate) untrusted_sheet_answer_limits: Vec<SheetAnswerLimitRow>,
    pub(crate) sheet_answer_default_max_count: Option<u64>,
    pub(crate) sheet_answer_precedence: Option<SheetAnswerPrecedence>,
    pub(crate) weave_correction_policy: Option<crate::gate::WeaveCorrectionPolicy>,
    pub(crate) attribution_limits: AttributionLimits,
    /// The shipped defaults apply only until a trusted policy row supplies
    /// a vault limit; later packs narrow that authored limit.
    pub(crate) attribution_limits_set: bool,
    pub(crate) ask_policy: Option<crate::gate::ask_policy::AskOperationalPolicy>,
    pub(crate) retry_source_policy: Vec<crate::gate::retry_source_policy::RetrySourcePolicyRow>,
    pub(crate) compilation_policies: Vec<crate::edit_distance::miner::CompilationPolicy>,
    pub(crate) experiment_selection: Vec<SelectionPolicyRow>,
    pub(crate) carry_forward_confidence: crate::gate::carry_forward_policy::CarryForwardPolicy,
    pub(super) carry_forward_authored: bool,
    pub(crate) judge_calibration: Option<crate::skill_optimize::policy::JudgeCalibrationPolicy>,
    pub(super) packs: Vec<PolicyPack>,
    pub(super) actor_ceilings: Vec<ActorCeiling>,
    pub(crate) delegation_fold: DelegationFoldCache,
    pub(super) source_trust: SourceTrustCeiling,
    pub(super) single_valued_predicates: std::collections::BTreeSet<String>,
    pub(super) scoped_grants: Vec<PolicyScopedGrant>,
    pub(crate) federation_grant_rows: Vec<crate::federation::grant_policy::GrantPolicyRow>,
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
    pub(super) voice_serving: Vec<crate::gate::voice_serving::VoiceServingRows>,
    pub(super) gate_decision_retention: Option<GateDecisionRetentionPolicy>,
    pub(crate) pack_install_policy: Option<crate::gate::PackInstallPolicy>,
    pub(super) pptx_comment_limits: Option<crate::edit_roundtrip::pptx::PptxOperationalLimits>,
    pub(super) docx_archive_limits: Vec<crate::gate::docx_budget::DocxArchivePolicy>,
    pub(super) booking_conversion_rows: Vec<crate::booking::BookingConversionPolicyRow>,
    /// Vault-resident wait windows keyed by class.
    pub(super) wait_policy: WaitPolicyTable,
    /// Vault-resident act postures keyed by act and subject class.
    pub(super) act_policy: ActPolicyTable,
    pub(super) hosted_tts: HostedTtsPolicy,
    pub(crate) connector_class_carry: Option<std::collections::BTreeSet<(String, String)>>,
    pub(crate) connector_class_precedence: ConnectorClassPrecedence,
    pub(super) slide_review_policy: crate::llm::decision::SlideReviewPolicy,
    pub(in crate::gate) docedit_resource_policy:
        Option<crate::gate::docedit_resource::DoceditResourcePolicy>,
}
