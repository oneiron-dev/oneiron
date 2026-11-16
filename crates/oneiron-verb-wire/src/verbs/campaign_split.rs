//! Moved from `crates/oneiron/src/verbs/campaign_split.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::autoreason_campaign::config::CampaignExecutableArm;
use crate::autoreason_campaign::judge::BlindCampaignJudgeInput;
use crate::autoreason_campaign::report::CampaignCost;
use crate::autoreason_campaign::report::CampaignEvaluationSplit;
use crate::autoreason_campaign::report::CampaignSmokeOutcome;
use oneiron_base::extraction_eval::Of360ExtractionRun;
use oneiron_base::extraction_eval::Of360GoldDataset;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.research.evaluate_split`'s input: one arm's run on one split.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignSplitWire {
    /// The campaign's root attempt.
    pub root: EntityId,
    /// The arm that ran.
    #[schemars(with = "serde_json::Value")]
    pub arm: CampaignExecutableArm,
    /// The split it ran on: `search` or `held_out`.
    #[schemars(with = "serde_json::Value")]
    pub split: CampaignEvaluationSplit,
    /// The split's OF-360 gold, at the id and revision the config pins.
    #[schemars(with = "serde_json::Value")]
    pub dataset: Of360GoldDataset,
    /// The arm's parsed output on that gold.
    #[schemars(with = "serde_json::Value")]
    pub run: Of360ExtractionRun,
    /// What the run cost, as observed.
    #[schemars(with = "serde_json::Value")]
    pub cost: CampaignCost,
    /// The claim, its evidence and the external gold anchor, with no arm,
    /// run or campaign named: all a taste provider sees.
    #[schemars(with = "serde_json::Value")]
    pub blind: BlindCampaignJudgeInput,
    /// The run's smoke outcome; a killed run still reports, scored zero.
    #[schemars(with = "serde_json::Value")]
    pub smoke: CampaignSmokeOutcome,
}
