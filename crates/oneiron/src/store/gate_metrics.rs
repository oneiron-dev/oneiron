//! Core half of `store::gate_metrics`: its store-layer items live in `oneiron_store::gate_metrics` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::gate_metrics::*;

use crate::store::gate_reason::{
    GATE_METRIC_OUTCOME_COUNT, GATE_METRIC_REASON_CLASS_COUNT, GateMetricReasonClass, GateOutcome,
};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

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
