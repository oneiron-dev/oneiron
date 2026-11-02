//! Typed campaign enrollment, earned evidence and immediate unsubscribe.

use crate::campaign::claims::{EvidenceBasis, StageEvidenceClass, StageKey};
use crate::campaign::stage::{PromotionMode, StageLadderDefinition};
use serde::{Deserialize, Serialize};

/// One evidence-backed channel with its sticky sending identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignMemberChannelSpec {
    pub channel: String,
    pub basis_evidence: String,
    pub sender_ref: String,
}

/// Manual enrollment is an own-vault claim, not a send or an earned stage.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignEnrollRequest {
    pub campaign_ref: String,
    pub person_ref: String,
    pub channels: Vec<CampaignMemberChannelSpec>,
    pub evidence_refs: Vec<String>,
}

/// Host-stamped authorship and the evidence the operation actually used.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CampaignActionProvenance {
    pub actor_ref: String,
    pub evidence_refs: Vec<String>,
    pub recorded_at: u64,
}

/// The membership claim lives on PERSON, not in a campaign-owned member array.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CampaignEnrollmentReceipt {
    pub membership_claim_ref: String,
    pub person_ref: String,
    pub campaign_ref: String,
    pub state: CampaignEnrollmentState,
    pub channels: Vec<CampaignMemberChannelSpec>,
    pub approval: String,
    pub provenance: CampaignActionProvenance,
    pub receipt_ref: String,
}

/// The membership's effective state after an enrollment (FIX 9664, 10221): a
/// manual intake reconciles with the person's one membership and keeps a
/// pause, an exit or a suppression it finds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CampaignEnrollmentState {
    Enrolled,
    Paused,
    Exited,
    Suppressed,
}

/// Evidence carries a class and a basis; elapsed time is never an evidence class.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignStageEvidence {
    pub class: StageEvidenceClass,
    pub basis: EvidenceBasis,
    pub evidence_refs: Vec<String>,
    pub recorded_at: u64,
}

/// An authored ladder and one named transition, scoped to a person and campaign.
/// Owner attestation additionally requires the vault owner's verified proof.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignStageEvidenceRequest {
    pub campaign_ref: String,
    pub person_ref: String,
    pub ladder: StageLadderDefinition,
    pub target_stage: StageKey,
    pub evidence: CampaignStageEvidence,
    #[serde(default = "automatic")]
    pub mode: PromotionMode,
}

fn automatic() -> PromotionMode {
    PromotionMode::Auto
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStageEvidenceOutcome {
    Advanced,
    Proposed,
    NoChange,
}

/// The earned or proposed claim and its exact evidence. NoChange creates no claim.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CampaignStageEvidenceReceipt {
    pub person_ref: String,
    pub campaign_ref: String,
    pub outcome: CampaignStageEvidenceOutcome,
    pub stage_claim_ref: Option<String>,
    pub stage: Option<StageKey>,
    pub evidence: Option<CampaignStageEvidence>,
    pub provenance: Option<CampaignActionProvenance>,
    pub receipt_ref: Option<String>,
}

/// Suppression is immediate and channel-scoped, never a deferred projector job.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignUnsubscribeRequest {
    pub campaign_ref: String,
    pub person_ref: String,
    pub channel: String,
    pub evidence_ref: String,
}

/// All replacement member heads and the enforcement claim commit together.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CampaignUnsubscribeReceipt {
    pub campaign_ref: String,
    pub person_ref: String,
    pub channel: String,
    pub evidence_ref: String,
    pub suppression_claim_ref: String,
    pub member_claim_refs: Vec<String>,
    pub receipt_ref: String,
}
