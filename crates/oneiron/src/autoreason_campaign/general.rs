//! Config-only contract for skill-driven campaigns. Execution, authority and
//! budget spending remain at their existing gates, outside this schema.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{CampaignDatasetRef, CampaignError, CampaignResult, CampaignSplits};

/// A bounded, tunable search dimension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct SearchAxis {
    pub name: String,
    pub values: Vec<String>,
}

/// Which way a measured axis improves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricDirection {
    Higher,
    Lower,
}

/// Primary axes seek improvement; floors cannot regress; costs count as tradeoffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricRole {
    Primary,
    Floor,
    Cost,
}

/// One named axis in a pinned metric set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct MetricAxis {
    pub name: String,
    pub direction: MetricDirection,
    pub role: MetricRole,
}

/// Evaluator-owned metric set identity and the axes used by the decision rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct MetricSet {
    pub set_id: String,
    pub revision: String,
    pub axes: Vec<MetricAxis>,
}

/// A bounded share of an externally enforced, reserve-then-spend lease.
/// This row cannot mint authority or spend the vault's lease by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct BudgetLease {
    pub budget_id: String,
    pub max_units: u64,
    pub exploration_units: u64,
}

/// How a held-out measurement is decided. OF-366 uses its own validated
/// comparison report: its net taste gain, external cost penalty and smoke
/// precedence cannot be reduced to OF-360 metric deltas.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecideRules {
    /// Require a minimum primary gain unless an independent cost/floor axis wins.
    Dominance { min_primary_gain: f64 },
    /// Delegate the fixed claim-authoring verdict to its validated report.
    Of366 { verdict_epsilon: f64 },
}

/// Requested merge crossover. It is never effective merely because this is true.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct MergeCrossover {
    #[serde(default)]
    pub requested: bool,
    /// Minimum overlap required by the executor's common-ancestor validation.
    pub min_validation_overlap: f64,
}

impl Default for MergeCrossover {
    fn default() -> Self {
        Self {
            requested: false,
            min_validation_overlap: 0.5,
        }
    }
}

/// Optional search policy; crossover stays disabled by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CampaignKnobs {
    #[serde(default)]
    pub merge_crossover: MergeCrossover,
}

/// One general, skill-driven campaign run. The OF-366 config is one adapter
/// to this schema; it retains its own admission and report-specific gates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Scores must come from a pinned dataset revision; a search split is never
/// eligible to supply decision evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct Measurement {
    pub dataset: CampaignDatasetRef,
    pub metric_set_id: String,
    pub metric_set_revision: String,
    pub scores: BTreeMap<String, f64>,
}

/// Decisions do not deserialize or expose mutable evidence. Consumers must
/// request a new decision from the config's held-out measurement door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Promote,
    Reject,
    EscalateTradeoff,
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
        let (field, threshold) = match self.decide {
            DecideRules::Dominance { min_primary_gain } => {
                ("decide.min_primary_gain", min_primary_gain)
            }
            DecideRules::Of366 { verdict_epsilon } => ("decide.verdict_epsilon", verdict_epsilon),
        };
        if !threshold.is_finite() || threshold < 0.0 {
            return invalid(field, "must be finite and non-negative");
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
        let DecideRules::Dominance { min_primary_gain } = self.decide else {
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
        let mut primary_win = false;
        let mut independent_win = false;
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
            if delta > 0.0 {
                if axis.role == MetricRole::Primary {
                    primary_win |= delta >= min_primary_gain;
                } else {
                    independent_win = true;
                }
            }
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
        } else if better && !worse && (independent_win || primary_win) {
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

#[cfg(test)]
mod tests;
