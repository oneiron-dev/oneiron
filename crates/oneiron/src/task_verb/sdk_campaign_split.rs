//! `vault.research.evaluate_split` (FIX 655): the vault owner scores one arm
//! of a bound claim-authoring campaign (OF-366) on one split. The config is
//! the one bound at the campaign's root; the caller brings the split's OF-360
//! gold, the arm's parsed run output, what the run cost, its smoke outcome and
//! the blind input the taste pack reads. [`build_campaign_split_report`]
//! checks them against the config and asks the taste questions through the
//! decisions the host lends. The report is returned, not stored.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::autoreason_campaign::authoring::authoring_campaign;
use crate::autoreason_campaign::{
    BlindCampaignJudgeInput, CampaignCost, CampaignError, CampaignEvaluationSplit,
    CampaignExecutableArm, CampaignSmokeOutcome, CampaignSplitReport, CampaignTasteDecisions,
    build_campaign_split_report,
};
use crate::entity_id::EntityId;
use crate::extraction_eval::{Of360ExtractionRun, Of360GoldDataset};
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};

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

/// Scores `input`'s arm on its split under the campaign bound at its root,
/// asking the taste questions through `taste`.
/// # Errors
/// No campaign is bound at the root, the inputs do not match its config or
/// each other, or the taste pack could not be asked.
pub fn evaluate_campaign_split(
    vault: &Vault,
    input: &CampaignSplitWire,
    taste: &CampaignTasteDecisions<'_>,
) -> MemoryResult<CampaignSplitReport> {
    let root = AttemptId::from_bytes(input.root.as_bytes())?;
    let campaign = authoring_campaign(vault, root)?.ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "no claim-authoring campaign is bound at this root",
            &["Bind the campaign first: a split is scored under its bound config."],
        )
    })?;
    build_campaign_split_report(
        &campaign.config,
        input.arm,
        input.split,
        &input.dataset,
        &input.run,
        input.cost,
        &input.blind,
        taste,
        input.smoke.clone(),
    )
    .map_err(|error| match error {
        CampaignError::Decision(error) => error.into(),
        error => MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            format!("vault.research.evaluate_split: {error}"),
            &["Bring the gold and the run at the dataset id and revision the campaign pins for that split."],
        ),
    })
}
