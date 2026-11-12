//! Config-only contract for skill-driven campaigns. Execution, authority and
//! budget spending remain at their existing gates, outside this schema.
//! This `CampaignConfig` is the general schema; the fixed OF-366
//! configuration lives in `super::config`.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{CampaignDatasetRef, CampaignError, CampaignResult, CampaignSplits};

#[doc(hidden)]
pub use oneiron_verb_wire::autoreason_campaign::general::{
    BudgetLease, CampaignKnobs, DecideRules, Measurement, MergeCrossover, MetricAxis,
    MetricDirection, MetricRole, MetricSet, SearchAxis, Verdict,
};

/// One general, skill-driven campaign run. The OF-366 config is one adapter
/// to this schema; it retains its own admission and report-specific gates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignConfig {
    pub campaign_id: String,
    pub search_axes: Vec<SearchAxis>,
    pub metric_set: MetricSet,
    pub splits: CampaignSplits,
    pub budget: BudgetLease,
    pub decide: DecideRules,
    #[serde(default)]
    pub knobs: CampaignKnobs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    verdict: Verdict,
    merge_crossover_enabled: bool,
}

impl Decision {
    #[must_use]
    pub const fn verdict(self) -> Verdict {
        self.verdict
    }

    /// True only after a held-out promotion and an explicit knob request.
    #[must_use]
    pub const fn merge_crossover_enabled(self) -> bool {
        self.merge_crossover_enabled
    }
}

impl CampaignConfig {
    pub fn validate(&self) -> CampaignResult<()> {
        nonblank(&self.campaign_id, "campaign_id")?;
        if self.search_axes.is_empty() {
            return invalid("search_axes", "at least one search axis is required");
        }
        let mut names = BTreeSet::new();
        for axis in &self.search_axes {
            nonblank(&axis.name, "search_axes")?;
            if !names.insert(&axis.name) || axis.values.is_empty() {
                return invalid("search_axes", "duplicate or empty search axis");
            }
            let mut choices = BTreeSet::new();
            for choice in &axis.values {
                if choice.trim().is_empty() || !choices.insert(choice) {
                    return invalid("search_axes", "blank or duplicate choice");
                }
            }
        }
        nonblank(&self.metric_set.set_id, "metric_set.set_id")?;
        nonblank(&self.metric_set.revision, "metric_set.revision")?;
        if self.metric_set.axes.is_empty() {
            return invalid("metric_set.axes", "at least one metric is required");
        }
        names.clear();
        let mut primary = false;
        for axis in &self.metric_set.axes {
            nonblank(&axis.name, "metric_set.axes")?;
            if !names.insert(&axis.name) {
                return invalid("metric_set.axes", "duplicate metric axis");
            }
            primary |= axis.role == MetricRole::Primary;
        }
        if !primary {
            return invalid("metric_set.axes", "a primary metric is required");
        }
        let refs = [
            &self.splits.search,
            &self.splits.held_out,
            &self.splits.sealed,
        ];
        for dataset in refs {
            nonblank(&dataset.dataset_id, "splits")?;
            nonblank(&dataset.revision, "splits")?;
        }
        if refs[0] == refs[1] || refs[0] == refs[2] || refs[1] == refs[2] {
            return invalid("splits", "dataset revisions must be pairwise distinct");
        }
        nonblank(&self.budget.budget_id, "budget.budget_id")?;
        if self.budget.max_units == 0 || self.budget.exploration_units > self.budget.max_units {
            return invalid("budget", "invalid lease ceiling or exploration share");
        }
        if let DecideRules::Of366 { verdict_epsilon } = self.decide
            && (!verdict_epsilon.is_finite() || verdict_epsilon < 0.0)
        {
            return invalid("decide.verdict_epsilon", "must be finite and non-negative");
        }
        let overlap = self.knobs.merge_crossover.min_validation_overlap;
        if !overlap.is_finite() || !(0.0..=1.0).contains(&overlap) || overlap == 0.0 {
            return invalid("knobs.merge_crossover", "overlap floor must be in (0, 1]");
        }
        Ok(())
    }

    /// Replay OF-366's held-out verdict through its original report door.
    /// Its effective taste, externally supplied cost penalty, and both smoke
    /// outcomes live in the validated comparison report, not in OF-360 scores.
    /// The specialized config must match this row except for the opt-in knobs.
    pub fn decide_of366_held_out(
        &self,
        fixed: &super::CampaignConfig,
        report: &super::CampaignComparisonReport,
    ) -> CampaignResult<Decision> {
        self.validate()?;
        let mut expected = fixed.as_general()?;
        expected.knobs = self.knobs;
        if *self != expected {
            return invalid("decide", "OF-366 row differs from its validated source");
        }
        report.validate()?;
        let recomputed = super::compare_campaign(
            report.campaign_ref,
            fixed,
            report.single_pass.clone(),
            report.tournament.clone(),
            report.decision.clone(),
        )?;
        if recomputed != *report {
            return Err(CampaignError::ReportMismatch {
                reason: "OF-366 report differs from the configured comparison",
            });
        }
        let promoted = recomputed.verdict.verdict == super::ExperimentVerdict::Keep;
        Ok(Decision {
            verdict: if promoted {
                Verdict::Promote
            } else {
                Verdict::Reject
            },
            merge_crossover_enabled: promoted && self.knobs.merge_crossover.requested,
        })
    }

    /// Decide only from both arms' held-out values. This scores dominance:
    /// ties reject, improvements without regressions promote, and mixed
    /// improvements/regressions escalate rather than silently crossing floors.
    pub fn decide_held_out(
        &self,
        incumbent: &Measurement,
        candidate: &Measurement,
    ) -> CampaignResult<Decision> {
        self.validate()?;
        let DecideRules::Dominance = self.decide else {
            return invalid("decide", "OF-366 requires a validated comparison report");
        };
        for row in [incumbent, candidate] {
            if row.dataset != self.splits.held_out
                || row.metric_set_id != self.metric_set.set_id
                || row.metric_set_revision != self.metric_set.revision
                || row.scores.len() != self.metric_set.axes.len()
                || self.metric_set.axes.iter().any(|axis| {
                    !row.scores
                        .get(&axis.name)
                        .is_some_and(|value| value.is_finite())
                })
            {
                return invalid(
                    "measurement",
                    "held-out dataset or metric set does not match",
                );
            }
        }
        let mut better = false;
        let mut worse = false;
        for axis in &self.metric_set.axes {
            // The exact-key and finite checks above ensure these lookups exist.
            let before = incumbent.scores[&axis.name];
            let after = candidate.scores[&axis.name];
            let delta = match axis.direction {
                MetricDirection::Higher => after - before,
                MetricDirection::Lower => before - after,
            };
            if !delta.is_finite() {
                return invalid("measurement", "metric delta overflowed");
            }
            better |= delta > 0.0;
            worse |= delta < 0.0;
            if axis.role == MetricRole::Floor && delta < 0.0 {
                // A floor cannot be traded away even by escalation.
                return Ok(Decision {
                    verdict: Verdict::Reject,
                    merge_crossover_enabled: false,
                });
            }
        }
        let verdict = if better && worse {
            Verdict::EscalateTradeoff
        } else if better && !worse {
            Verdict::Promote
        } else {
            Verdict::Reject
        };
        Ok(Decision {
            verdict,
            merge_crossover_enabled: self.knobs.merge_crossover.requested
                && verdict == Verdict::Promote,
        })
    }
}

fn nonblank(value: &str, field: &'static str) -> CampaignResult<()> {
    if value.trim().is_empty() {
        invalid(field, "must not be blank")
    } else {
        Ok(())
    }
}

fn invalid<T>(field: &'static str, reason: &'static str) -> CampaignResult<T> {
    Err(CampaignError::InvalidConfig { field, reason })
}
