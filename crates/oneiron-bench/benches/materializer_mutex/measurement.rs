//! Admit only fully materialized cases to the timing report.

use super::configuration::MaterializerCase;
use super::observers::{Implementation, ImplementationRuntime};
use super::reporting::{MaterializerBenchReport, MaterializerRowDiagnostics, summarize};
use super::worker::Fleet;

/// Everything one measured contention point produced.
#[derive(Debug)]
pub(super) struct CaseOutcome {
    pub(super) report: MaterializerBenchReport,
    pub(super) diagnostics: MaterializerRowDiagnostics,
}

/// Runs one (implementation, workers) point: warm up, record the deterministic
/// measured phase, then hand the live fleet to `sample` for Criterion.
///
/// Criterion sampling runs AFTER the recorded phase so the blueprint's exact
/// 100-warmup / 1,000-measured shape is what the JSON report carries.
pub(super) fn run_measured_case(
    case: &MaterializerCase,
    implementation: Implementation,
    sample: &mut dyn FnMut(&Fleet),
) -> Result<CaseOutcome, String> {
    run_case_with_runtime(case, implementation, implementation.runtime(), sample).map_err(|error| {
        format!(
            "{} / {} workers: {error}",
            implementation.label(),
            case.workers
        )
    })
}

pub(super) fn run_case_with_runtime(
    case: &MaterializerCase,
    implementation: Implementation,
    runtime: ImplementationRuntime,
    sample: &mut dyn FnMut(&Fleet),
) -> Result<CaseOutcome, String> {
    let ImplementationRuntime { factory, counters } = runtime;
    let mut fleet = Fleet::start(case, &factory, counters.clone());
    fleet.run_phase(u64::try_from(case.warmup_bursts).unwrap_or(0), false)?;
    let elapsed = fleet.run_phase(u64::try_from(case.measured_bursts).unwrap_or(0), true)?;
    let samples = fleet.take_samples();
    let report = summarize(implementation.label(), case, &samples, elapsed)?;
    sample(&fleet);
    fleet.shutdown();
    let materialized_rows = fleet.validate_materialization()?;
    let (shadow_committed_ops, shadow_errors) = match &counters {
        Some(counters) => counters.snapshot(),
        None => (0, 0),
    };
    Ok(CaseOutcome {
        report,
        diagnostics: MaterializerRowDiagnostics {
            implementation: implementation.label(),
            workers: case.workers,
            materialized_rows,
            shadow_committed_ops,
            shadow_errors,
            measured_samples: samples.len(),
        },
    })
}
