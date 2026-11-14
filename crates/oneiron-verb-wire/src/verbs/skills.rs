//! Moved from `crates/oneiron/src/verbs/skills.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_hub::admission::HubAdmissionReceipt;
use crate::verbs::hub::HubSkillReceipts;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::skill_record::lifecycle::SkillLifecycle;
use oneiron_store::write_envelope::skill_source::hub_record::HubRef;
use serde::Deserialize;
use serde::Serialize;

/// Conversion accepts references, never caller-authored trusted skill bytes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillConvertRequest {
    pub message_refs: Vec<EntityId>,
    #[serde(default)]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SkillConvertReceipt {
    Created {
        entity: EntityId,
    },
    DupPointer {
        entity: EntityId,
    },
    MergeProposed {
        existing: EntityId,
        proposal: EntityId,
    },
}

impl SkillConvertReceipt {
    pub fn rows(&self) -> Vec<EntityId> {
        match self {
            Self::Created { entity } | Self::DupPointer { entity } => vec![*entity],
            Self::MergeProposed { existing, proposal } => vec![*existing, *proposal],
        }
    }
}

/// Public archive spelling of the engine's existing soft-retired Quarantined state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SkillLibraryLifecycle {
    Candidate,
    Active,
    Stale,
    Archived,
    Superseded,
}

impl From<SkillLifecycle> for SkillLibraryLifecycle {
    fn from(state: SkillLifecycle) -> Self {
        match state {
            SkillLifecycle::Candidate => Self::Candidate,
            SkillLifecycle::Active => Self::Active,
            SkillLifecycle::Stale => Self::Stale,
            SkillLifecycle::Quarantined => Self::Archived,
            SkillLifecycle::Superseded => Self::Superseded,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillLibraryListRequest {
    #[serde(default)]
    pub after: Option<EntityId>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillLibraryPage {
    pub skills: Vec<SkillLibraryView>,
    pub next_after: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillSourceEvidence {
    pub message_ref: EntityId,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillStaleView {
    pub reason: String,
    pub deleted_refs: Vec<EntityId>,
}

/// A birth pin, not today's head of the parent. None means the engine retained no pin.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillForkLineage {
    pub parent: EntityId,
    pub parent_version: Option<String>,
    pub parent_document: Option<EntityId>,
    pub parent_frontier: Option<Vec<u8>>,
    pub parent_available: bool,
    pub hub_sources: Vec<HubRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillLibraryDependency {
    pub skill_id: String,
    pub min_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillLibraryCall {
    pub reference: String,
    pub arguments: serde_json::Value,
    pub returns: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillCapabilityView {
    pub bins: Vec<String>,
    pub env: Vec<String>,
    pub mcp: Vec<String>,
    pub allowed_tools: Vec<String>,
}

/// Exact source bytes; source absence is distinct from an empty file tree.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillLibraryFile {
    pub path: String,
    pub content: Vec<u8>,
}

/// Scanner evidence remains separate from consent and owner rules.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SkillLibraryScan {
    pub content_hash: String,
    pub provider: String,
    pub scanned_at: u64,
    pub verdict: String,
    pub risk_level: String,
    pub completeness: String,
    pub governance: String,
    pub scanned_at_declared: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillLibraryView {
    pub entity: EntityId,
    pub skill_id: String,
    pub desc: String,
    pub version: String,
    pub content_hash: Option<String>,
    pub lifecycle: SkillLibraryLifecycle,
    pub approval: ClaimApprovalStatus,
    pub loadable: bool,
    pub source: String,
    pub role: String,
    pub call: Option<SkillLibraryCall>,
    pub governance_tier: Option<String>,
    pub generated: bool,
    pub human_authored: bool,
    pub dependencies: Vec<SkillLibraryDependency>,
    pub provenance: serde_json::Value,
    pub source_messages: Vec<SkillSourceEvidence>,
    pub stale: Option<SkillStaleView>,
    pub lineage: Vec<SkillForkLineage>,
    pub files: Option<Vec<SkillLibraryFile>>,
    pub capabilities: Option<SkillCapabilityView>,
    pub scans: Vec<SkillLibraryScan>,
    pub receipts: HubSkillReceipts,
}

/// Rows used by a library read, including ancestry and its hub aliases.
impl SkillLibraryView {
    pub fn rows(&self) -> Vec<EntityId> {
        std::iter::once(self.entity)
            .chain(self.source_messages.iter().map(|source| source.message_ref))
            .chain(self.receipts.sources.iter().map(|source| source.hub_id))
            .chain(self.lineage.iter().flat_map(|hop| {
                std::iter::once(hop.parent)
                    .chain(hop.hub_sources.iter().map(|source| source.hub_id))
            }))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillLibraryForkRequest {
    pub parent: EntityId,
    #[serde(default)]
    pub entity: Option<EntityId>,
    pub skill_id: String,
}

/// A hub restore repeats its existing exact-consent and held-out admission, not a bare flip.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillRestoreAdmission {
    pub source: HubRef,
    pub publisher: String,
    pub evidence_skill: EntityId,
    #[serde(default)]
    pub effect_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillLibraryRestoreRequest {
    pub entity: EntityId,
    #[serde(default)]
    pub admission: Option<SkillRestoreAdmission>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SkillLibraryRestoreReceipt {
    Restored {
        skill: Box<SkillLibraryView>,
        admission: Option<HubAdmissionReceipt>,
    },
    PendingAdmission {
        entity: EntityId,
        content_hash: String,
        effect_digest: String,
    },
    Refused {
        entity: EntityId,
        admission: HubAdmissionReceipt,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillHashRuleRequest {
    pub content_hash: String,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillCodeAutoInstallRequest {
    pub enabled: bool,
}

/// The owner's existing dependency-advisory ask setting.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillAdvisoryAskRequest {
    pub enabled: bool,
}

/// The governance axis of one stored skill, resolved fail-closed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillGovernanceView {
    pub entity: EntityId,
    pub skill_id: String,
    pub version: String,
    pub lifecycle: SkillLibraryLifecycle,
    /// `marked` | `legacy_standard` | `ambiguous`.
    pub verdict: String,
    /// Resolved tier (`identity` | `alignment` | `standard`); absent when ambiguous.
    pub tier: Option<String>,
    pub protected: bool,
    pub optimizable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillGovernanceSetRequest {
    pub entity: EntityId,
    /// `identity` | `alignment` | `standard`; absent clears the mark.
    #[serde(default)]
    pub tier: Option<String>,
}

/// `vault.skills.optimize.start`'s input: one Coach skill_optimize attempt.
/// `skill` restricts drafting and pending-proposal resume to that exact skill;
/// without it, the attempt ranks the engine's tier-filtered candidates.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeStartRequest {
    #[serde(default)]
    pub skill: Option<EntityId>,
    #[serde(default)]
    pub resident: Option<EntityId>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub dedupe_key: Option<String>,
    #[serde(default)]
    pub now: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeStartReceipt {
    /// `enqueued` | `existing` | `excluded`.
    pub outcome: String,
    /// 32-hex attempt id; absent when excluded before enqueue.
    pub job_ref: Option<String>,
    /// Queue state at enqueue time; absent when excluded.
    pub state: Option<String>,
    pub skill: Option<EntityId>,
    pub governance: Option<SkillGovernanceView>,
}

impl SkillOptimizeStartReceipt {
    pub fn rows(&self) -> Vec<EntityId> {
        self.skill.into_iter().collect()
    }
}

/// `vault.skills.optimize.result`'s input: a started job, a proposal, or both.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeResultRequest {
    #[serde(default)]
    pub job_ref: Option<String>,
    #[serde(default)]
    pub proposal: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeAxisView {
    pub axis: String,
    pub before: f32,
    pub after: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeVerdictView {
    pub id: EntityId,
    pub proposal: EntityId,
    pub skill: EntityId,
    pub disposition: String,
    pub accepted: bool,
    pub before: f32,
    pub after: f32,
    pub goal_axes: Vec<SkillOptimizeAxisView>,
    pub goal_revision: String,
    pub judge_revision: Option<String>,
    pub cycle: String,
    pub held_out_receipts: Vec<String>,
    pub held_out_count: u64,
    pub held_out_digest: String,
    pub held_out_truncated: bool,
    pub proposal_digest: String,
    pub target_digest: String,
    pub proposal_tier: Option<String>,
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeResultView {
    pub job_ref: Option<String>,
    pub state: Option<String>,
    pub kind: Option<String>,
    pub last_error: Option<String>,
    pub skill: Option<EntityId>,
    pub proposal: Option<EntityId>,
    pub proposal_lifecycle: Option<SkillLibraryLifecycle>,
    pub incumbent_lifecycle: Option<SkillLibraryLifecycle>,
    pub governance: Option<SkillGovernanceView>,
    pub verdict: Option<SkillOptimizeVerdictView>,
    pub verdicts: Vec<SkillOptimizeVerdictView>,
}

impl SkillOptimizeResultView {
    pub fn rows(&self) -> Vec<EntityId> {
        self.skill
            .into_iter()
            .chain(self.proposal)
            .chain(self.verdicts.iter().map(|verdict| verdict.id))
            .collect()
    }
}
