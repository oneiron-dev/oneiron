use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;

use super::config::{campaign_split_dataset_ref, check_metric_pin};
use super::report::{smoke_is_killed, validate_arm_pairing};
use super::{
    CampaignArmReport, CampaignConfig, CampaignDatasetRef, CampaignError, CampaignGoldAnchor,
    CampaignResult, CampaignSmokeOutcome, CampaignSplitReport, EXPERIMENT_VERDICT_DISCARD,
    EXPERIMENT_VERDICT_KEEP,
};

/// Held-out comparison between the two executable arms.
///
/// Every report-derived field is recomputed from the two held-out reports and
/// never trusted on input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignHeldOutDecision {
    /// Whether the tournament arm scored above the incumbent on held-out.
    pub tournament_wins_held_out: bool,
    /// Whether the incumbent is at least as good and no more expensive.
    pub ab_dominated: bool,
    /// Tournament minus incumbent effective held-out score.
    pub quality_delta: f64,
    /// External cost penalty in quality units. Supplied, never converted here.
    pub cost_penalty: f64,
    /// External gold anchor both held-out judgments were scored against.
    pub external_anchor: CampaignGoldAnchor,
}

/// Builds the held-out decision from two validated arm reports.
///
/// `cost_penalty` is supplied external decision evidence: this module does not
/// convert USD into quality units. A self-generated anchor is caught
/// structurally — an anchor whose dataset ref is not the held-out split the
/// reports were built against fails.
pub fn build_campaign_held_out_decision(
    single_pass: &CampaignArmReport,
    tournament: &CampaignArmReport,
    cost_penalty: f64,
    external_anchor: CampaignGoldAnchor,
) -> CampaignResult<CampaignHeldOutDecision> {
    validate_arm_pairing(single_pass, tournament)?;
    if !cost_penalty.is_finite() || cost_penalty < 0.0 {
        return Err(CampaignError::InvalidDecision {
            field: "cost_penalty",
            reason: "must be finite and non-negative",
        });
    }
    check_held_out_anchor(
        &external_anchor,
        &single_pass.held_out,
        &tournament.held_out,
    )?;
    let derived = derive_held_out_fields(&single_pass.held_out, &tournament.held_out);
    Ok(CampaignHeldOutDecision {
        tournament_wins_held_out: derived.tournament_wins_held_out,
        ab_dominated: derived.ab_dominated,
        quality_delta: derived.quality_delta,
        cost_penalty,
        external_anchor,
    })
}

/// Outcome of the campaign experiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentVerdict {
    /// Keep the tournament arm.
    Keep,
    /// Discard the tournament arm.
    Discard,
}

impl ExperimentVerdict {
    /// Stable claim predicate for this verdict.
    #[must_use]
    pub const fn predicate(self) -> &'static str {
        match self {
            Self::Keep => EXPERIMENT_VERDICT_KEEP,
            Self::Discard => EXPERIMENT_VERDICT_DISCARD,
        }
    }
}

/// Why the campaign reached its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignVerdictReason {
    /// Held-out win survived the cost penalty.
    HeldOutWinNetOfCost,
    /// An arm's held-out row was killed by the smoke gate.
    SmokeKilled,
    /// The incumbent was at least as good and no more expensive.
    AbDominated,
    /// The tournament arm did not win held-out.
    NoHeldOutWin,
    /// The net held-out gain fell below the campaign epsilon.
    QualityDeltaBelowEpsilon,
}

/// The campaign verdict with the numerics it was derived from.
///
/// `quality_delta` and `cost_penalty` are the raw numbers the ladder was
/// applied to. `net_delta` is their difference, derived on construction and
/// preserved on decode so [`CampaignComparisonReport::validate`] can reject
/// numeric drift.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignVerdict {
    /// Keep or discard.
    pub verdict: ExperimentVerdict,
    /// Precedence rule that decided the verdict.
    pub reason: CampaignVerdictReason,
    /// Raw held-out quality delta, carried on every reason.
    pub quality_delta: f64,
    /// Raw cost penalty, carried on every reason.
    pub cost_penalty: f64,
    /// `quality_delta - cost_penalty`, carried on every reason. Derived on
    /// construction and checked by [`CampaignComparisonReport::validate`].
    pub net_delta: f64,
}

impl CampaignVerdict {
    /// Assembles a verdict whose `net_delta` follows its own numerics.
    fn new(
        verdict: ExperimentVerdict,
        reason: CampaignVerdictReason,
        quality_delta: f64,
        cost_penalty: f64,
    ) -> Self {
        Self {
            verdict,
            reason,
            quality_delta,
            cost_penalty,
            net_delta: net_delta(quality_delta, cost_penalty),
        }
    }
}

/// Full campaign comparison, re-derivable from its own contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignComparisonReport {
    /// Echoed from the validated config budget line for audit.
    pub campaign_ref: AttemptId,
    /// Echoed from the validated config so verdict precedence is re-derivable
    /// after serde.
    pub budget_id: String,
    /// Epsilon the verdict ladder was applied with.
    pub verdict_epsilon: f64,
    /// Metric definition digest shared by all four split reports.
    pub metric_definition_digest: String,
    /// Incumbent arm reports.
    pub single_pass: CampaignArmReport,
    /// Tournament arm reports.
    pub tournament: CampaignArmReport,
    /// Held-out decision.
    pub decision: CampaignHeldOutDecision,
    /// Verdict derived from the precedence ladder.
    pub verdict: CampaignVerdict,
}

impl CampaignComparisonReport {
    /// Re-derives everything derivable and refuses any drift.
    ///
    /// A decoded report carries its own epsilon and smoke outcomes, so the
    /// full precedence ladder is replayed here: a forged keep after a
    /// smoke-killed baseline cannot survive a round trip.
    pub fn validate(&self) -> CampaignResult<()> {
        validate_arm_pairing(&self.single_pass, &self.tournament)?;
        if self.budget_id.is_empty() {
            return Err(CampaignError::ReportMismatch {
                reason: "budget id is empty",
            });
        }
        if !self.verdict_epsilon.is_finite() || self.verdict_epsilon < 0.0 {
            return Err(CampaignError::ReportMismatch {
                reason: "verdict epsilon must be finite and non-negative",
            });
        }
        if self.metric_definition_digest.is_empty() {
            return Err(CampaignError::ReportMismatch {
                reason: "metric definition digest is empty",
            });
        }
        let splits = [
            &self.single_pass.search,
            &self.single_pass.held_out,
            &self.tournament.search,
            &self.tournament.held_out,
        ];
        for split in splits {
            if split.metric_definition_digest != self.metric_definition_digest {
                return Err(CampaignError::ReportMismatch {
                    reason: "split digest differs from the report metric definition digest",
                });
            }
        }
        check_held_out_anchor(
            &self.decision.external_anchor,
            &self.single_pass.held_out,
            &self.tournament.held_out,
        )?;
        cross_check_held_out_decision(&self.single_pass, &self.tournament, &self.decision)?;
        let verdict = campaign_verdict(
            &self.single_pass.held_out.smoke,
            &self.tournament.held_out.smoke,
            &self.decision,
            self.verdict_epsilon,
        );
        if verdict != self.verdict {
            return Err(CampaignError::InvalidDecision {
                field: "verdict",
                reason: "does not match the re-derived precedence ladder",
            });
        }
        Ok(())
    }
}

/// Assembles the campaign comparison for one run-tree root.
///
/// `campaign_ref` echoes the caller-supplied root attempt id exactly; no
/// second identity is minted here, and rootness stays a caller obligation this
/// module cannot verify.
pub fn compare_campaign(
    campaign_ref: AttemptId,
    config: &CampaignConfig,
    single_pass: CampaignArmReport,
    tournament: CampaignArmReport,
    decision: CampaignHeldOutDecision,
) -> CampaignResult<CampaignComparisonReport> {
    config.validate()?;
    let budget = config.budget.as_ref().ok_or(CampaignError::InvalidConfig {
        field: "budget",
        reason: "absent",
    })?;
    validate_arm_pairing(&single_pass, &tournament)?;
    for split in [
        &single_pass.search,
        &single_pass.held_out,
        &tournament.search,
        &tournament.held_out,
    ] {
        check_metric_pin(&config.metric_pin, &split.of360.metric_definitions)?;
        if &split.dataset != campaign_split_dataset_ref(config, split.split) {
            return Err(CampaignError::ReportMismatch {
                reason: "split dataset ref differs from the configured split",
            });
        }
    }
    check_config_held_out_anchor(&decision.external_anchor, &config.splits.held_out)?;
    check_held_out_anchor(
        &decision.external_anchor,
        &single_pass.held_out,
        &tournament.held_out,
    )?;
    cross_check_held_out_decision(&single_pass, &tournament, &decision)?;

    let verdict = campaign_verdict(
        &single_pass.held_out.smoke,
        &tournament.held_out.smoke,
        &decision,
        config.verdict_epsilon,
    );
    let metric_definition_digest = single_pass.held_out.metric_definition_digest.clone();
    let report = CampaignComparisonReport {
        campaign_ref,
        budget_id: budget.budget_id.clone(),
        verdict_epsilon: config.verdict_epsilon,
        metric_definition_digest,
        single_pass,
        tournament,
        decision,
        verdict,
    };
    report.validate()?;
    Ok(report)
}

/// Report-derived held-out scalars.
struct CampaignHeldOutDerivation {
    tournament_wins_held_out: bool,
    ab_dominated: bool,
    quality_delta: f64,
}

fn derive_held_out_fields(
    baseline: &CampaignSplitReport,
    contender: &CampaignSplitReport,
) -> CampaignHeldOutDerivation {
    let quality_delta = contender.effective_taste_score - baseline.effective_taste_score;
    CampaignHeldOutDerivation {
        tournament_wins_held_out: quality_delta > 0.0,
        ab_dominated: baseline.effective_taste_score >= contender.effective_taste_score
            && baseline.cost.cost_usd <= contender.cost.cost_usd,
        quality_delta,
    }
}

/// The single verdict-precedence implementation.
///
/// 1. either held-out row smoke-killed — a killed baseline invalidates the
///    experiment, so keep is unreachable even when the tournament row is live;
/// 2. incumbent dominates;
/// 3. no held-out win — search-split performance never yields keep;
/// 4. net gain below epsilon;
/// 5. otherwise keep.
///
/// Raw numerics ride along on every reason: no early branch zeroes them.
fn campaign_verdict(
    single_pass_smoke: &CampaignSmokeOutcome,
    tournament_smoke: &CampaignSmokeOutcome,
    decision: &CampaignHeldOutDecision,
    verdict_epsilon: f64,
) -> CampaignVerdict {
    let quality_delta = decision.quality_delta;
    let cost_penalty = decision.cost_penalty;
    let net_gain = net_delta(quality_delta, cost_penalty);
    let reason = if smoke_is_killed(single_pass_smoke) || smoke_is_killed(tournament_smoke) {
        CampaignVerdictReason::SmokeKilled
    } else if decision.ab_dominated {
        CampaignVerdictReason::AbDominated
    } else if !decision.tournament_wins_held_out {
        CampaignVerdictReason::NoHeldOutWin
    } else if net_gain < verdict_epsilon {
        CampaignVerdictReason::QualityDeltaBelowEpsilon
    } else {
        CampaignVerdictReason::HeldOutWinNetOfCost
    };
    let verdict = match reason {
        CampaignVerdictReason::HeldOutWinNetOfCost => ExperimentVerdict::Keep,
        CampaignVerdictReason::SmokeKilled
        | CampaignVerdictReason::AbDominated
        | CampaignVerdictReason::NoHeldOutWin
        | CampaignVerdictReason::QualityDeltaBelowEpsilon => ExperimentVerdict::Discard,
    };
    CampaignVerdict::new(verdict, reason, quality_delta, cost_penalty)
}

fn cross_check_held_out_decision(
    single_pass: &CampaignArmReport,
    tournament: &CampaignArmReport,
    decision: &CampaignHeldOutDecision,
) -> CampaignResult<()> {
    if !decision.cost_penalty.is_finite() || decision.cost_penalty < 0.0 {
        return Err(CampaignError::InvalidDecision {
            field: "cost_penalty",
            reason: "must be finite and non-negative",
        });
    }
    let derived = derive_held_out_fields(&single_pass.held_out, &tournament.held_out);
    if decision.quality_delta != derived.quality_delta {
        return Err(CampaignError::InvalidDecision {
            field: "quality_delta",
            reason: "does not match the held-out effective scores",
        });
    }
    if decision.tournament_wins_held_out != derived.tournament_wins_held_out {
        return Err(CampaignError::InvalidDecision {
            field: "tournament_wins_held_out",
            reason: "does not match the held-out effective scores",
        });
    }
    if decision.ab_dominated != derived.ab_dominated {
        return Err(CampaignError::InvalidDecision {
            field: "ab_dominated",
            reason: "does not match the held-out effective scores and costs",
        });
    }
    Ok(())
}

fn check_held_out_anchor(
    anchor: &CampaignGoldAnchor,
    baseline: &CampaignSplitReport,
    contender: &CampaignSplitReport,
) -> CampaignResult<()> {
    if anchor.gold_digest.is_empty()
        || anchor.dataset_id != baseline.dataset.dataset_id
        || anchor.revision != baseline.dataset.revision
        || anchor.dataset_id != contender.dataset.dataset_id
        || anchor.revision != contender.dataset.revision
        || anchor.gold_digest != baseline.taste.external_anchor_digest
        || anchor.gold_digest != contender.taste.external_anchor_digest
    {
        return Err(CampaignError::HeldOutAnchorMismatch);
    }
    Ok(())
}

fn check_config_held_out_anchor(
    anchor: &CampaignGoldAnchor,
    held_out: &CampaignDatasetRef,
) -> CampaignResult<()> {
    if anchor.dataset_id != held_out.dataset_id || anchor.revision != held_out.revision {
        return Err(CampaignError::HeldOutAnchorMismatch);
    }
    Ok(())
}

/// The one definition of the net held-out gain the ladder is applied to.
fn net_delta(quality_delta: f64, cost_penalty: f64) -> f64 {
    quality_delta - cost_penalty
}
