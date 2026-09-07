use serde::{Deserialize, Serialize};

use super::{CampaignError, CampaignResult};

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

/// One judge's scoring of an arm on a split.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignTasteJudgment {
    /// Quality score, finite in `[0, 1]`.
    pub score: f64,
    /// Judge's binary usefulness note; audit-only — never read by verdict or
    /// validation logic.
    pub useful: bool,
    /// Digest of the external gold anchor the judge scored against.
    pub external_anchor_digest: String,
}

pub(super) fn validate_taste(taste: &CampaignTasteJudgment) -> CampaignResult<()> {
    if !is_unit_interval_f64(taste.score) {
        return Err(CampaignError::ReportMismatch {
            reason: "taste score must be finite in [0, 1]",
        });
    }
    if taste.external_anchor_digest.is_empty() {
        return Err(CampaignError::ReportMismatch {
            reason: "taste judgment has no external anchor digest",
        });
    }
    Ok(())
}

fn is_unit_interval_f64(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}
