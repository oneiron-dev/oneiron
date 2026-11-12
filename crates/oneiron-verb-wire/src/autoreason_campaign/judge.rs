//! Moved from `crates/oneiron/src/autoreason_campaign/judge.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::model_decision::AnswerContract;
use oneiron_store::model_decision::DecisionAnswer;
use oneiron_store::model_decision::DecisionBand;
use oneiron_store::model_decision::DecisionBandPolicy;
use oneiron_store::model_decision::DecisionDial;
use oneiron_store::model_decision::DecisionRung;
use oneiron_store::model_decision::Reversibility;
use oneiron_store::model_decision::catalogue::CAMPAIGN_TASTE;
use oneiron_store::retrieval_deadline::RetrievalDeadline;
use oneiron_wake_contract::llm::decision::types::DecisionReceipt;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;
use std::time::Instant;

/// External gold anchor a taste judgment was scored against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignGoldAnchor {
    /// Dataset id of the anchor.
    pub dataset_id: String,
    /// Dataset revision of the anchor.
    pub revision: String,
    /// Digest of the anchored gold content.
    pub gold_digest: String,
}

/// The only payload a campaign judge is shown.
///
/// It carries no arm, strategy, round, run id, candidate ref, model tier or
/// campaign ref, and `deny_unknown_fields` keeps a caller from smuggling one
/// back in through a decoded payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct BlindCampaignJudgeInput {
    /// Claim text under judgment.
    pub claim: String,
    /// Evidence references backing the claim.
    pub evidence_refs: Vec<String>,
    /// Held-out gold anchor the judge scores against.
    pub held_out_gold: CampaignGoldAnchor,
}
