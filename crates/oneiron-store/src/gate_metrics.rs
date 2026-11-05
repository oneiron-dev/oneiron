//! One vault's gate outcome x reason-class counters. The gate's
//! `GateMetrics::record_decision` counts each decision into them.

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::gate_reason::GATE_METRIC_OUTCOME_COUNT;
use crate::gate_reason::GATE_METRIC_REASON_CLASS_COUNT;
use crate::gate_reason::GateMetricReasonClass;
use crate::gate_reason::GateOutcome;

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateMetricCounter {
    pub outcome: GateOutcome,
    pub reason_class: GateMetricReasonClass,
    pub count: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateMetricsSnapshot {
    pub counters: Vec<GateMetricCounter>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateMetricsSnapshot {
    #[must_use]
    pub fn count(&self, outcome: GateOutcome, reason_class: GateMetricReasonClass) -> u64 {
        self.counters
            .iter()
            .find(|counter| counter.outcome == outcome && counter.reason_class == reason_class)
            .map_or(0, |counter| counter.count)
    }
}
