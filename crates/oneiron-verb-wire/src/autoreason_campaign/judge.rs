//! Moved from `crates/oneiron/src/autoreason_campaign/judge.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

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
