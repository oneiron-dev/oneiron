//! Moved from `crates/oneiron/src/verbs/skill_attribution.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_skill_attribution::types::SkillEditProposal;
use serde::Deserialize;
use serde::Serialize;

pub fn invalid(message: &'static str) -> MemoryError {
    MemoryError::bad_request(message)
}

/// Why the decider amended, spelled as the engine's pinned token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProposalAmendmentCause {
    ProposalWrong,
    ExternalChange,
    DeciderPreference,
}

/// One exact replacement the owner made: `before` must occur exactly once in
/// the text as it stands when this operation applies.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposalReplacement {
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AmendmentDeltaView {
    pub proposed_ref: String,
    pub final_ref: String,
    pub source: String,
    pub d_norm: f32,
    pub ops_summary: OpsSummaryView,
    pub engine_ver: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OpsSummaryView {
    pub ins: u32,
    pub del: u32,
    pub kept: u32,
    pub moved: u32,
    pub approx: bool,
}

/// One changed hunk as settled: the recorded replacement, its measured edit
/// mass, and the actor the recorded op attributes to when a span lines up.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettledHunkView {
    pub before: String,
    pub after: String,
    pub edit_mass: f64,
    pub actor: Option<EntityId>,
    pub trust: Option<String>,
}

/// Read one settlement by its receipt, with its artifact when the receipt
/// names one (or `artifact_ref` names it directly).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposalDeltaReadRequest {
    pub receipt_id: String,
    #[serde(default)]
    pub artifact_ref: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProposalOpSpanView {
    pub actor: Option<EntityId>,
    pub trust: String,
    /// `None` when the retained document no longer holds that version.
    pub before_text: Option<String>,
    pub after_text: Option<String>,
    pub lamport: u32,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProposalArtifactView {
    pub artifact_ref: EntityId,
    /// `None` when the retained document no longer holds that end.
    pub proposed_text: Option<String>,
    pub final_text: Option<String>,
    pub source_turn_ref: Option<EntityId>,
    pub spans: Vec<ProposalOpSpanView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AmendmentEvidenceView {
    pub receipt_id: String,
    pub actor: EntityId,
    pub skill: Option<EntityId>,
    pub attempt_receipt: Option<String>,
    pub scope: String,
    pub cause: Option<ProposalAmendmentCause>,
    pub followed_skill: Option<bool>,
    pub skill_covered_step: Option<bool>,
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PreferenceProposalView {
    pub receipt_id: String,
    pub scope: String,
    pub evidence_receipts: Vec<String>,
    pub share: f32,
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttributionEvidenceReceipt {
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillEditProposalView {
    pub judgment_sequence: u64,
    pub skill: EntityId,
    pub evidence_receipts: Vec<String>,
    pub at: u64,
}

impl From<SkillEditProposal> for SkillEditProposalView {
    fn from(proposal: SkillEditProposal) -> Self {
        Self {
            judgment_sequence: proposal.judgment_sequence,
            skill: proposal.skill,
            evidence_receipts: proposal.evidence_receipts,
            at: proposal.at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PositiveProposalView {
    pub evidence_sequence: u64,
    pub skill: EntityId,
    pub actor: EntityId,
    pub finding: String,
    pub reason: Option<String>,
    pub evidence_receipts: Vec<String>,
    pub at: u64,
}

/// Run one attribution pass. Absent `since_cursor`, the persisted cursor
/// admits only what is new.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttributionProjectRequest {
    #[serde(default)]
    pub since_cursor: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttributionListRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttributionProposalsView {
    pub edit_proposals: Vec<SkillEditProposalView>,
    pub preference_proposals: Vec<PreferenceProposalView>,
    pub positive_proposals: Vec<PositiveProposalView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PositiveRetireRequest {
    pub evidence_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PositiveRetireReceipt {
    pub retired: bool,
}
