//! Doors for `tests/dreamer_stage_line.rs` (FIX 21929): a partition's stage
//! clock closed at set instants, and the one stage line it logs.

use std::time::Instant;

use crate::dreamer_consolidation::stage_log::PartitionStages;

/// The marks and inner stage ms of one closed model run, in the order a
/// window slot reaches them.
pub struct ClosedModelRun {
    pub run_started: Instant,
    pub prefix_ended: Instant,
    pub window_prefixes_ended: Instant,
    pub finish_started: Instant,
    pub corrections_ms: u64,
    pub resolve_ms: u64,
    pub gap_ms: u64,
    pub ended: Instant,
}

/// Closes a stage clock over `run` and logs its stage line for `attempt`
/// (hex) in `scope`, as a window slot's finish does.
pub fn log_closed_stage_line(run: &ClosedModelRun, attempt: &str, scope: &str) {
    let mut stages = PartitionStages::start(0);
    stages.mark_prefix_ended(run.prefix_ended);
    stages.mark_window_prefixes_ended(run.window_prefixes_ended);
    stages.mark_finish_started(run.finish_started);
    stages.set_inner_stage_ms(run.corrections_ms, run.resolve_ms, run.gap_ms);
    stages.close_model_run_at(run.run_started, run.ended);
    stages.log_line(attempt, scope, 0, "landed");
}
