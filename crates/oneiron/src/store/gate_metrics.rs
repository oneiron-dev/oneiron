//! One vault's gate outcome x reason-class counters. The gate's
//! `GateMetrics::record_decision` counts each decision into them.

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::store::gate_reason::{
    GATE_METRIC_OUTCOME_COUNT, GATE_METRIC_REASON_CLASS_COUNT, GateMetricReasonClass, GateOutcome,
};

/// One vault's gate outcome x reason-class counters.
///
/// Owned by that vault's store handle (`StoreCore::diagnostics`), so a reader
/// sees only what its own vault's doors decided.
pub(crate) struct GateMetrics {
    pub(crate) counters: [[AtomicU64; GATE_METRIC_REASON_CLASS_COUNT]; GATE_METRIC_OUTCOME_COUNT],
}

impl Default for GateMetrics {
    fn default() -> Self {
        Self {
            counters: [const { [const { AtomicU64::new(0) }; GATE_METRIC_REASON_CLASS_COUNT] };
                GATE_METRIC_OUTCOME_COUNT],
        }
    }
}

impl GateMetrics {
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn snapshot(&self) -> GateMetricsSnapshot {
        let mut counters =
            Vec::with_capacity(GATE_METRIC_OUTCOME_COUNT * GATE_METRIC_REASON_CLASS_COUNT);
        for outcome in GateOutcome::metric_values() {
            for reason_class in GateMetricReasonClass::metric_values() {
                counters.push(GateMetricCounter {
                    outcome,
                    reason_class,
                    count: self.counters[outcome.metric_index()][reason_class.metric_index()]
                        .load(AtomicOrdering::Relaxed),
                });
            }
        }
        GateMetricsSnapshot { counters }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateMetricCounter {
    outcome: GateOutcome,
    reason_class: GateMetricReasonClass,
    count: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateMetricsSnapshot {
    counters: Vec<GateMetricCounter>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateMetricsSnapshot {
    #[must_use]
    pub(crate) fn count(&self, outcome: GateOutcome, reason_class: GateMetricReasonClass) -> u64 {
        self.counters
            .iter()
            .find(|counter| counter.outcome == outcome && counter.reason_class == reason_class)
            .map_or(0, |counter| counter.count)
    }
}
