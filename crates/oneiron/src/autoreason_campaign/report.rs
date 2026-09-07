use serde::{Deserialize, Serialize};

use crate::extraction_eval::{
    Of360Ar3MetricTier, Of360ExtractionRun, Of360GoldDataset, of360_ar3_metric_tier,
};

use super::config::{campaign_split_dataset_ref, check_metric_pin};
use super::judge::validate_taste;
use super::{
    CampaignConfig, CampaignDatasetRef, CampaignError, CampaignExecutableArm, CampaignResult,
    CampaignTasteJudgment,
};

/// Splits an AR-3 report may be produced for.
///
/// There is deliberately no sealed variant: the sealed split is reserved by
/// the config and unreachable from every report constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignEvaluationSplit {
    /// Configuration-search split.
    Search,
    /// Verdict-deciding split.
    HeldOut,
}

/// Smoke-gate outcome for one arm on one split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignSmokeOutcome {
    /// The arm survived the smoke gate.
    Passed,
    /// The arm was killed by the smoke gate.
    Killed {
        /// Why the arm was killed.
        reason: String,
    },
}

/// Observed cost row for one arm on one split.
///
/// The module records what the run reported and never recalculates a provider
/// price table.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignCost {
    /// Input tokens observed.
    pub input_tokens: u64,
    /// Output tokens observed.
    pub output_tokens: u64,
    /// Cache-read tokens observed.
    pub cache_read_tokens: u64,
    /// Cache-write tokens observed.
    pub cache_write_tokens: u64,
    /// Observed cost in USD.
    pub cost_usd: f64,
    /// Observed wall-clock duration.
    pub elapsed_ms: u64,
}

/// One arm evaluated on one split.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignSplitReport {
    /// Arm this report belongs to.
    pub arm: CampaignExecutableArm,
    /// Split this report belongs to.
    pub split: CampaignEvaluationSplit,
    /// Dataset ref evaluated, copied from the config split.
    pub dataset: CampaignDatasetRef,
    /// Content hash of the evaluated metric definitions, carried verbatim.
    pub metric_definition_digest: String,
    /// Raw OF-360 AR-3 metric tier, retained unmodified.
    pub of360: Of360Ar3MetricTier,
    /// Raw observed cost row, retained unmodified.
    pub cost: CampaignCost,
    /// Raw taste judgment, retained unmodified.
    pub taste: CampaignTasteJudgment,
    /// Smoke-gate outcome.
    pub smoke: CampaignSmokeOutcome,
    /// Taste score after the smoke gate: zero when killed, raw when passed.
    pub effective_taste_score: f64,
}

impl CampaignSplitReport {
    /// Refuses inconsistent metric evidence or a score that does not follow its inputs.
    /// This checks internal consistency, not authenticity without the raw OF-360 inputs.
    pub fn validate(&self) -> CampaignResult<()> {
        self.of360.validate()?;
        if self.dataset.dataset_id.is_empty() || self.dataset.revision.is_empty() {
            return Err(CampaignError::ReportMismatch {
                reason: "split dataset ref is incomplete",
            });
        }
        if self.metric_definition_digest.is_empty() {
            return Err(CampaignError::ReportMismatch {
                reason: "metric definition digest is empty",
            });
        }
        if self.metric_definition_digest
            != self
                .of360
                .metric_definitions
                .derivation_envelope
                .content_hash
        {
            return Err(CampaignError::ReportMismatch {
                reason: "metric definition digest differs from the evaluated envelope",
            });
        }
        if self.of360.report.dataset_id != self.dataset.dataset_id
            || self.of360.report.dataset_revision != self.dataset.revision
        {
            return Err(CampaignError::ReportMismatch {
                reason: "evaluated dataset differs from the split dataset ref",
            });
        }
        validate_cost(&self.cost)?;
        validate_taste(&self.taste)?;
        validate_smoke(&self.smoke)?;
        if self.effective_taste_score != effective_taste_score(&self.smoke, &self.taste) {
            return Err(CampaignError::ReportMismatch {
                reason: "effective taste score does not follow the smoke outcome",
            });
        }
        Ok(())
    }
}

/// Evaluates one arm on one split through the landed OF-360 metric tier.
///
/// This is the module's only OF-360 call site.
#[expect(clippy::too_many_arguments)]
pub fn build_campaign_split_report(
    config: &CampaignConfig,
    arm: CampaignExecutableArm,
    split: CampaignEvaluationSplit,
    dataset: &Of360GoldDataset,
    run: &Of360ExtractionRun,
    cost: CampaignCost,
    taste: CampaignTasteJudgment,
    smoke: CampaignSmokeOutcome,
) -> CampaignResult<CampaignSplitReport> {
    config.validate()?;
    let dataset_ref = campaign_split_dataset_ref(config, split);
    if dataset.dataset_id != dataset_ref.dataset_id || dataset.revision != dataset_ref.revision {
        return Err(CampaignError::ReportMismatch {
            reason: "gold dataset is not the configured split",
        });
    }
    if run.dataset_id != dataset_ref.dataset_id || run.dataset_revision != dataset_ref.revision {
        return Err(CampaignError::ReportMismatch {
            reason: "extraction run is not the configured split",
        });
    }
    validate_cost(&cost)?;
    validate_taste(&taste)?;
    validate_smoke(&smoke)?;

    let of360 = of360_ar3_metric_tier(dataset, run)?;
    check_metric_pin(&config.metric_pin, &of360.metric_definitions)?;
    let metric_definition_digest = of360
        .metric_definitions
        .derivation_envelope
        .content_hash
        .clone();
    let effective = effective_taste_score(&smoke, &taste);
    let report = CampaignSplitReport {
        arm,
        split,
        dataset: dataset_ref.clone(),
        metric_definition_digest,
        of360,
        cost,
        taste,
        smoke,
        effective_taste_score: effective,
    };
    report.validate()?;
    Ok(report)
}

/// One arm evaluated on both reportable splits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignArmReport {
    /// Arm both split reports belong to.
    pub arm: CampaignExecutableArm,
    /// Search-split report.
    pub search: CampaignSplitReport,
    /// Held-out-split report.
    pub held_out: CampaignSplitReport,
}

/// Joins one arm's two split reports, revalidating both.
pub fn merge_campaign_arm_report(
    search: CampaignSplitReport,
    held_out: CampaignSplitReport,
) -> CampaignResult<CampaignArmReport> {
    search.validate()?;
    held_out.validate()?;
    if search.arm != held_out.arm {
        return Err(CampaignError::ReportMismatch {
            reason: "search and held-out reports belong to different arms",
        });
    }
    if search.split != CampaignEvaluationSplit::Search {
        return Err(CampaignError::ReportMismatch {
            reason: "search slot holds a non-search split report",
        });
    }
    if held_out.split != CampaignEvaluationSplit::HeldOut {
        return Err(CampaignError::ReportMismatch {
            reason: "held-out slot holds a non-held-out split report",
        });
    }
    if search.metric_definition_digest != held_out.metric_definition_digest {
        return Err(CampaignError::ReportMismatch {
            reason: "search and held-out reports have different metric definition digests",
        });
    }
    Ok(CampaignArmReport {
        arm: search.arm,
        search,
        held_out,
    })
}

pub(super) fn validate_arm_pairing(
    single_pass: &CampaignArmReport,
    tournament: &CampaignArmReport,
) -> CampaignResult<()> {
    validate_arm_report(single_pass, CampaignExecutableArm::SinglePass)?;
    validate_arm_report(tournament, CampaignExecutableArm::Tournament)?;
    if single_pass.held_out.metric_definition_digest != tournament.held_out.metric_definition_digest
    {
        return Err(CampaignError::ReportMismatch {
            reason: "arms have different metric definition digests",
        });
    }
    if single_pass.search.dataset != tournament.search.dataset
        || single_pass.held_out.dataset != tournament.held_out.dataset
    {
        return Err(CampaignError::ReportMismatch {
            reason: "corresponding arm splits use different dataset refs",
        });
    }
    Ok(())
}

fn validate_arm_report(
    report: &CampaignArmReport,
    expected: CampaignExecutableArm,
) -> CampaignResult<()> {
    if report.arm != expected {
        return Err(CampaignError::ReportMismatch {
            reason: "arm report is filed under the wrong arm",
        });
    }
    report.search.validate()?;
    report.held_out.validate()?;
    if report.search.arm != report.arm || report.held_out.arm != report.arm {
        return Err(CampaignError::ReportMismatch {
            reason: "split report arm differs from the arm report",
        });
    }
    if report.search.split != CampaignEvaluationSplit::Search
        || report.held_out.split != CampaignEvaluationSplit::HeldOut
    {
        return Err(CampaignError::ReportMismatch {
            reason: "arm report splits are not the search/held-out pair",
        });
    }
    if report.search.metric_definition_digest != report.held_out.metric_definition_digest {
        return Err(CampaignError::ReportMismatch {
            reason: "search and held-out reports have different metric definition digests",
        });
    }
    Ok(())
}

fn effective_taste_score(smoke: &CampaignSmokeOutcome, taste: &CampaignTasteJudgment) -> f64 {
    if smoke_is_killed(smoke) {
        0.0
    } else {
        taste.score
    }
}

pub(super) fn smoke_is_killed(smoke: &CampaignSmokeOutcome) -> bool {
    matches!(smoke, CampaignSmokeOutcome::Killed { .. })
}

fn validate_smoke(smoke: &CampaignSmokeOutcome) -> CampaignResult<()> {
    match smoke {
        CampaignSmokeOutcome::Passed => Ok(()),
        CampaignSmokeOutcome::Killed { reason } if !reason.trim().is_empty() => Ok(()),
        CampaignSmokeOutcome::Killed { .. } => Err(CampaignError::ReportMismatch {
            reason: "smoke kill requires a non-empty reason",
        }),
    }
}

fn validate_cost(cost: &CampaignCost) -> CampaignResult<()> {
    if !cost.cost_usd.is_finite() || cost.cost_usd < 0.0 {
        return Err(CampaignError::ReportMismatch {
            reason: "observed cost must be finite and non-negative",
        });
    }
    Ok(())
}
