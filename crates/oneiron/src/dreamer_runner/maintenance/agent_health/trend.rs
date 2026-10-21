//! The daily trend review (OF-568 L3): pure, deterministic comparisons over
//! the rollups, per actor and per direct project, each within one task type
//! and executor model (and one unit, for spend). The latest N complete UTC
//! days are compared with the N before them; today's partial day is never
//! read. Each comparison records its direction and signed magnitude between
//! the two sides' rates or means, with improvement, flat and unknown recorded
//! too.
//!
//! It holds no threshold: a worsening is any adverse change, an observation
//! about the work and never a score of the agent. A signal comparison whose
//! detection cannot be compared is unknown: a detection dial row set inside
//! its span, a detector that changed, or a side no review covered. So is a
//! comparison whose source failed, and one with nothing known on a side.

use std::collections::{BTreeMap, BTreeSet};

use super::rollups::{
    HealthTrendRollup, HealthTrendRollups, TrendMargin, TrendRatio, TrendSource, TrendStratum,
};
use super::trend_policy::{DetectionDialChanges, SECONDS_PER_DAY, TrendWindow};
use crate::EntityId;
use crate::llm::run_admission::LeaseUnit;
use crate::self_heal::AgentHealthSignal;

/// The trend pass's facet. It rides the Coach's nightly timer jobs
/// (`MAINTENANCE_FACETS`), deduped per wake, apart from the health review.
pub const COACH_HEALTH_TRENDS_FACET: &str = "coach.health_trends";

/// What one trend review compares.
#[derive(Debug, Clone, PartialEq)]
pub struct HealthTrendInput {
    /// Today's UTC day number (days since the epoch): its partial day is
    /// never compared.
    pub today: u64,
    /// The rollups, with the period in force for each margin.
    pub rollups: HealthTrendRollups,
    /// The owner rows over the detection dials; `None` when they could not
    /// be read.
    pub dial_changes: Option<DetectionDialChanges>,
}

/// What a comparison measures.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrendMetric {
    /// Distinct affected attempts over checked attempts, for one T1 signal.
    Signal(AgentHealthSignal),
    /// Settled attempts per day: volume, with no adverse direction.
    Attempts,
    /// Witnessed calls per attempt whose calls are known: no adverse
    /// direction.
    Calls,
    /// Retries over attempts.
    Retries,
    /// Own-scope spend per closed launch scope, in one unit.
    Spend(LeaseUnit),
    /// Observed wait seconds, not on a person, over attempt life seconds.
    Wait,
}

impl TrendMetric {
    /// The T1 signal a worsening of this metric is filed under: spend as
    /// `cost_spike`, wait as `long_wait`. Attempts, calls and retries name
    /// none, so they stay in the review.
    #[must_use]
    pub const fn signal(&self) -> Option<AgentHealthSignal> {
        match self {
            Self::Signal(signal) => Some(*signal),
            Self::Spend(_) => Some(AgentHealthSignal::CostSpike),
            Self::Wait => Some(AgentHealthSignal::LongWait),
            Self::Attempts | Self::Calls | Self::Retries => None,
        }
    }

    /// Whether a rise is adverse. Volume and call intensity have no adverse
    /// direction.
    const fn adverse_rise(&self) -> bool {
        !matches!(self, Self::Attempts | Self::Calls)
    }

    /// The metric's stable token, as the replay hash binds it.
    pub(super) fn token(&self) -> String {
        match self {
            Self::Signal(signal) => format!("signal.{}", signal.as_str()),
            Self::Attempts => "attempts".to_owned(),
            Self::Calls => "calls".to_owned(),
            Self::Retries => "retries".to_owned(),
            Self::Spend(unit) => format!("spend.{}", unit.as_str()),
            Self::Wait => "wait".to_owned(),
        }
    }

    /// The sources a comparison of this metric reads beyond the ledger.
    fn sources(&self) -> &'static [TrendSource] {
        match self {
            Self::Signal(_) => &[
                TrendSource::Diagnostics,
                TrendSource::Dials,
                TrendSource::DialRows,
            ],
            Self::Calls => &[TrendSource::Calls],
            Self::Spend(_) => &[TrendSource::Spend],
            Self::Attempts | Self::Retries | Self::Wait => &[],
        }
    }
}

/// Why a comparison is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrendUnknown {
    /// A side has nothing known to divide by.
    NoEvidence,
    /// A source the metric reads failed.
    SourceFailed,
    /// A detection dial row reaching this work was set inside the span.
    DialChanged,
    /// The signal's detector changed inside the span.
    DetectorChanged,
}

/// Which way a comparison moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrendDirection {
    /// An adverse rise.
    Worsening,
    /// An adverse metric fell.
    Improving,
    /// A metric with no adverse direction rose.
    Rose,
    /// A metric with no adverse direction fell.
    Fell,
    /// No change.
    Flat,
    /// Not comparable.
    Unknown(TrendUnknown),
}

/// One side of a comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrendSide {
    /// Its UTC day numbers, half-open.
    pub days: (u64, u64),
    /// The summed ratio and its coverage.
    pub ratio: TrendRatio,
    /// The numerator's typed refs: the affected attempts and their
    /// DIAGNOSTICs, the counted attempts or the call receipts.
    pub refs: BTreeSet<EntityId>,
    /// Every attempt on this side.
    pub attempts: BTreeSet<EntityId>,
    /// The launch spend scopes counted, for spend.
    pub scopes: BTreeSet<String>,
}

/// One comparison of one metric for one margin and stratum.
#[derive(Debug, Clone, PartialEq)]
pub struct HealthTrendComparison {
    /// The actor or the direct project.
    pub margin: TrendMargin,
    /// The task type and executor model.
    pub stratum: TrendStratum,
    /// What is compared.
    pub metric: TrendMetric,
    /// The N days before the latest.
    pub prior: TrendSide,
    /// The latest N complete days.
    pub latest: TrendSide,
    /// The latest value less the prior; `None` when unknown.
    pub delta: Option<f64>,
    /// Which way it moved.
    pub direction: TrendDirection,
}

/// One trend review: every comparison, and what it could not read.
#[derive(Debug, Clone, PartialEq)]
pub struct HealthTrendReview {
    /// The UTC day number it ran on.
    pub today: u64,
    /// Every comparison, improvement, flat and unknown included.
    pub comparisons: Vec<HealthTrendComparison>,
    /// Sources whose read failed. With the ledger or the policy among
    /// them, no comparison could be made.
    pub failed: BTreeSet<TrendSource>,
    /// Ledger rows that reach no margin.
    pub unreadable_attempts: u64,
    /// DIAGNOSTIC rows deleted or undecodable.
    pub withheld_diagnostics: u64,
    /// Agent-health findings that name no attempt.
    pub unjoined_diagnostics: u64,
}

/// Compares each margin and stratum's latest period with its prior one, for
/// every metric. Pure: the same input gives the same review.
#[must_use]
pub fn review_health_trends(input: &HealthTrendInput) -> HealthTrendReview {
    let rollups = &input.rollups;
    let mut failed = rollups.failed.clone();
    if input.dial_changes.is_none() {
        failed.insert(TrendSource::DialRows);
    }
    let mut comparisons = Vec::new();
    if let Some(periods) = &rollups.periods {
        let mut groups: BTreeMap<(&TrendMargin, &TrendStratum), Vec<&HealthTrendRollup>> =
            BTreeMap::new();
        for bucket in &rollups.buckets {
            groups
                .entry((&bucket.margin, &bucket.stratum))
                .or_default()
                .push(bucket);
        }
        for ((margin, stratum), buckets) in groups {
            let window = TrendWindow::ending(input.today, periods.of(margin));
            let group = Group {
                margin,
                stratum,
                window,
                prior: side_buckets(&buckets, window.prior),
                latest: side_buckets(&buckets, window.latest),
            };
            comparisons.extend(group.compare(&failed, input.dial_changes.as_ref()));
        }
    }
    HealthTrendReview {
        today: input.today,
        comparisons,
        failed,
        unreadable_attempts: rollups.unreadable_attempts,
        withheld_diagnostics: rollups.withheld_diagnostics,
        unjoined_diagnostics: rollups.unjoined_diagnostics,
    }
}

/// The buckets whose day falls in `days`.
fn side_buckets<'a>(
    buckets: &[&'a HealthTrendRollup],
    days: (u64, u64),
) -> Vec<&'a HealthTrendRollup> {
    buckets
        .iter()
        .copied()
        .filter(|bucket| (days.0..days.1).contains(&bucket.day))
        .collect()
}

/// One margin and stratum, split into its two sides.
struct Group<'a> {
    margin: &'a TrendMargin,
    stratum: &'a TrendStratum,
    window: TrendWindow,
    prior: Vec<&'a HealthTrendRollup>,
    latest: Vec<&'a HealthTrendRollup>,
}

impl Group<'_> {
    /// Every metric's comparison: the ledger's own, each T1 signal's, and
    /// spend in each unit either side holds.
    fn compare(
        &self,
        failed: &BTreeSet<TrendSource>,
        dials: Option<&DetectionDialChanges>,
    ) -> Vec<HealthTrendComparison> {
        let mut metrics = vec![
            TrendMetric::Attempts,
            TrendMetric::Calls,
            TrendMetric::Retries,
            TrendMetric::Wait,
        ];
        metrics.extend(
            AgentHealthSignal::all()
                .into_iter()
                .map(TrendMetric::Signal),
        );
        let units: BTreeSet<&LeaseUnit> = self
            .prior
            .iter()
            .chain(&self.latest)
            .flat_map(|bucket| bucket.spend.keys())
            .collect();
        metrics.extend(units.into_iter().cloned().map(TrendMetric::Spend));
        metrics
            .into_iter()
            .map(|metric| {
                let prior = measure(&metric, &self.prior, self.window.prior);
                let latest = measure(&metric, &self.latest, self.window.latest);
                let (delta, direction) = match self.unknown(&metric, failed, dials) {
                    Some(reason) => (None, TrendDirection::Unknown(reason)),
                    None => judge(&metric, &prior.ratio, &latest.ratio),
                };
                HealthTrendComparison {
                    margin: self.margin.clone(),
                    stratum: self.stratum.clone(),
                    metric,
                    prior,
                    latest,
                    delta,
                    direction,
                }
            })
            .collect()
    }

    /// Why `metric` cannot be compared here beyond a side with nothing
    /// known: a failed source, or, for a signal, a detection dial row set
    /// inside the span or a detector that changed in it.
    fn unknown(
        &self,
        metric: &TrendMetric,
        failed: &BTreeSet<TrendSource>,
        dials: Option<&DetectionDialChanges>,
    ) -> Option<TrendUnknown> {
        if metric
            .sources()
            .iter()
            .any(|source| failed.contains(source))
        {
            return Some(TrendUnknown::SourceFailed);
        }
        let TrendMetric::Signal(signal) = metric else {
            return None;
        };
        let buckets = || self.prior.iter().chain(&self.latest);
        let projects: BTreeSet<Option<EntityId>> = buckets()
            .flat_map(|bucket| bucket.projects.iter().copied())
            .collect();
        let since = self.window.prior.0.saturating_mul(SECONDS_PER_DAY);
        if dials.is_some_and(|dials| dials.changed_since(&projects, &self.stratum.type_node, since))
        {
            return Some(TrendUnknown::DialChanged);
        }
        let detectors: BTreeSet<&str> = buckets()
            .filter_map(|bucket| bucket.signals.get(signal))
            .flat_map(|tally| tally.detectors.iter().map(String::as_str))
            .collect();
        (detectors.len() > 1).then_some(TrendUnknown::DetectorChanged)
    }
}

/// One side of `metric`, summed over its buckets.
fn measure(metric: &TrendMetric, buckets: &[&HealthTrendRollup], days: (u64, u64)) -> TrendSide {
    let mut side = TrendSide {
        days,
        ratio: TrendRatio::default(),
        refs: BTreeSet::new(),
        attempts: BTreeSet::new(),
        scopes: BTreeSet::new(),
    };
    for bucket in buckets {
        side.attempts.extend(bucket.attempts.iter().copied());
        let attempts = bucket.attempts.len() as u64;
        match metric {
            TrendMetric::Attempts => {
                side.ratio.add(&TrendRatio {
                    numerator: attempts,
                    denominator: 0,
                    known: attempts,
                    eligible: attempts,
                });
                side.refs.extend(bucket.attempts.iter().copied());
            }
            TrendMetric::Calls => {
                side.ratio.add(&bucket.calls);
                side.refs.extend(bucket.call_refs.iter().copied());
            }
            TrendMetric::Retries => {
                side.ratio.add(&TrendRatio {
                    numerator: bucket.retries.len() as u64,
                    denominator: attempts,
                    known: attempts,
                    eligible: attempts,
                });
                side.refs.extend(bucket.retries.iter().copied());
            }
            TrendMetric::Wait => {
                side.ratio.add(&bucket.wait);
                side.refs.extend(bucket.attempts.iter().copied());
            }
            TrendMetric::Signal(signal) => {
                let tally = bucket.signals.get(signal);
                let checked = bucket.checked.len() as u64;
                side.ratio.add(&TrendRatio {
                    numerator: tally.map_or(0, |tally| tally.attempts.len() as u64),
                    denominator: checked,
                    known: checked,
                    eligible: attempts,
                });
                if let Some(tally) = tally {
                    side.refs.extend(tally.attempts.iter().copied());
                    side.refs.extend(tally.diagnostics.iter().copied());
                }
            }
            TrendMetric::Spend(unit) => {
                if let Some(tally) = bucket.spend.get(unit) {
                    side.ratio.add(&tally.ratio);
                    side.refs.extend(tally.attempts.iter().copied());
                    side.scopes.extend(tally.scopes.iter().cloned());
                }
            }
        }
    }
    // Volume is a per-day mean over the side's whole period, each day of
    // the ledger read.
    if *metric == TrendMetric::Attempts {
        side.ratio.denominator = days.1.saturating_sub(days.0);
    }
    side
}

/// The signed change from `prior` to `latest`, and its direction. A side
/// with nothing known makes it unknown.
fn judge(
    metric: &TrendMetric,
    prior: &TrendRatio,
    latest: &TrendRatio,
) -> (Option<f64>, TrendDirection) {
    let (Some(before), Some(after)) = (prior.value(), latest.value()) else {
        return (None, TrendDirection::Unknown(TrendUnknown::NoEvidence));
    };
    let delta = after - before;
    let direction = match (delta > 0.0, delta < 0.0, metric.adverse_rise()) {
        (true, _, true) => TrendDirection::Worsening,
        (true, _, false) => TrendDirection::Rose,
        (_, true, true) => TrendDirection::Improving,
        (_, true, false) => TrendDirection::Fell,
        (false, false, _) => TrendDirection::Flat,
    };
    (Some(delta), direction)
}
