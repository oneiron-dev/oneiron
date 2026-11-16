//! Moved from `crates/oneiron/src/autoreason_campaign/verdict.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::autoreason_campaign::EXPERIMENT_VERDICT_DISCARD;
use crate::autoreason_campaign::EXPERIMENT_VERDICT_KEEP;
use crate::autoreason_campaign::report::smoke_is_killed;
use oneiron_verb_wire::autoreason_campaign::judge::CampaignGoldAnchor;
use oneiron_verb_wire::autoreason_campaign::report::CampaignSmokeOutcome;
use serde::Deserialize;
use serde::Serialize;

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
pub fn campaign_verdict(
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

/// The one definition of the net held-out gain the ladder is applied to.
pub fn net_delta(quality_delta: f64, cost_penalty: f64) -> f64 {
    quality_delta - cost_penalty
}
