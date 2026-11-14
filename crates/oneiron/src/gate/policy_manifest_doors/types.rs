//! Typed DEC-0005 policy axes. Other manifest tables stay at their own doors.
use std::collections::BTreeMap;

use super::PolicyScopedGrantRow;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCeiling {
    Auto,
    Proposed,
}

impl PolicyCeiling {
    /// The public name of the Gate's approval ceiling `ceiling`.
    pub(crate) const fn of_approval(ceiling: crate::gate::PolicyApprovalCeiling) -> Self {
        match ceiling {
            crate::gate::PolicyApprovalCeiling::Auto => Self::Auto,
            crate::gate::PolicyApprovalCeiling::Proposed => Self::Proposed,
        }
    }
}

#[doc(hidden)]
pub use oneiron_verb_wire::gate::policy_manifest_doors::types::{
    GateCheckerReceipt, GateCheckerSet, GateCheckerView, PolicyAxes, PolicyCriticality,
    PolicyManifestRead, PolicyRule, PolicySensitivity, PolicySignature, PolicySource,
    SensitivityBand, SensitivityName, SheetAnswerLimit, SourceTrust, SourceTrustRow,
    TeacherProbeHolderFloor, TeacherProbePolicy,
};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActorCeiling {
    pub actor_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_ref: Option<String>,
    pub ceiling: PolicyCeiling,
}

/// The Gate policy envelope and write axes. Editing an existing manifest
/// replaces these fields only; unrelated policy tables are preserved.
/// Signature text is data, never a substitute for the owner's credential.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyManifest {
    pub schema_version: String,
    pub pack_id: String,
    pub pack_version: String,
    pub min_engine_version: String,
    pub defaults: PolicyAxes,
    pub rules: Vec<PolicyRule>,
    pub actor_ceilings: Vec<ActorCeiling>,
    #[serde(default)]
    pub source_trust: BTreeMap<PolicySource, SourceTrust>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<PolicySignature>,
    #[serde(default)]
    pub signatures: Vec<PolicySignature>,
    /// The host checker reference, as the existing manifest decoder stores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_checker: Option<String>,
    /// The slide review's pacing and route rows (FIX 9336); absent, the
    /// shipped rows hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slide_review_policy: Option<Vec<crate::llm::decision::SlideReviewPolicyRow>>,
    /// Who may settle a held code effect; each named person still needs its power.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_consent_settlement:
        Option<crate::gate::code_consent_settlement::CodeConsentSettlementRow>,
    /// Omit to preserve the stored table; an explicit list replaces it and
    /// an empty list clears it. No other manifest table is changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped_grants: Option<Vec<PolicyScopedGrantRow>>,
    /// The teacher-probe floor row: a holder authors a proposal's floor here
    /// to apply it (FIX 8780).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teacher_probe: Option<TeacherProbePolicy>,
    /// The sheet-answer limit rows: a holder authors a proposal's limits here
    /// to apply them (FIX 8780); absent, the shipped vault cap holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sheet_answer_limits: Option<Vec<SheetAnswerLimit>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyManifestPut {
    /// Omit for a new contribution. Use the returned default ref to edit defaults.
    #[serde(default)]
    pub manifest_ref: Option<String>,
    /// Required when editing: the exact body hash returned by the read door.
    #[serde(default)]
    pub expected_body_hash: Option<String>,
    pub manifest: PolicyManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyManifestPropose {
    pub manifest: PolicyManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyManifestView {
    pub manifest_ref: String,
    pub body_hash: String,
    pub trusted: bool,
    pub quarantined: bool,
    pub manifest: PolicyManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyManifestsView {
    pub default_manifest_ref: String,
    pub read_frontier_hash: String,
    pub manifests: Vec<PolicyManifestView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyManifestReceipt {
    pub manifest: PolicyManifestView,
    pub approval: PolicyCeiling,
    pub receipt_ref: String,
    pub read_frontier_hash: String,
}
