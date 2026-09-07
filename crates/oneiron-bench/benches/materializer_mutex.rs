//! ONE-331 — bench-only comparison of `std::sync::Mutex` against
//! `parking_lot::Mutex` on the Observer B materialization path.
//!
//! This target answers ONE measured question and changes NOTHING in
//! production: does the `Mutex<()>` that serializes Observer B
//! (`crates/oneiron/src/sync/bridge.rs`, `Materializer::lock`) give at least
//! a 10% p99 win under realistic contention if it becomes a
//! `parking_lot::Mutex`? Production `bridge.rs` and `crates/oneiron/Cargo.toml`
//! are untouched: `parking_lot` and `loro` are dev/bench dependencies of
//! `oneiron-bench` only, so no production build ever sees them.
//!
//! Three rows are measured with identical work and identical data:
//!
//! * `real_std` — the REAL current path: `oneiron::sync::bridge::Materializer`
//!   plus `register_observer_b`. This is the calibration row. It exists so the
//!   shadow workload cannot be tuned into an unrealistic microbenchmark.
//! * `shadow_std` — a bench-only adapter running the same delta decode and
//!   `Vault::batch()` materialization body behind a `std::sync::Mutex<()>`
//!   (with the same poison recovery production uses).
//! * `shadow_parking_lot` — the same adapter body behind a
//!   `parking_lot::Mutex<()>`.
//!
//! Workload (blueprint shape): one temporary vault; 1 / 4 / 16 workers, each
//! owning its own `LoroDoc` and its own logical window, all sharing ONE
//! materializer/lock; every worker commits bursts of 32 valid entity-map
//! updates and every measured burst starts through a shared barrier;
//! 100 warmup bursts then 1,000 measured bursts per contention point.
//!
//! Criterion does the stable sampling; a small deterministic recorder emits
//! commits/s and per-burst p50/p99 as JSON alongside Criterion's normal
//! output (see `report_path`).
//!
//! Calibration rule (blueprint): the 4-worker `shadow_std` p99 must land
//! within 15% of the real Observer B p99 on each machine, otherwise the
//! comparison is INCONCLUSIVE and production keeps `std::sync::Mutex`. The
//! verdict is recorded, never tuned away.
//!
//! Known, deliberate asymmetry between the real and shadow rows: the real
//! path materializes through the crate-private replicated door
//! (`batch_in().put_replicated(..)`) plus its tombstone / `dt:` marker /
//! quarantine gates, while a bench-only crate can only reach the PUBLIC
//! `Vault::batch().put(..)` door. That asymmetry is exactly what the
//! calibration row measures — it is not something to hide.

// The same source file is wired as both a `harness = false` Criterion bench
// target and a libtest target (see `crates/oneiron-bench/Cargo.toml`): a
// `harness = false` bench is never run by `cargo test`, and the
// load-bearing ONE-331 contract tests have to run there. Under the libtest
// build the Criterion driver and the JSON recorder are compiled but unused.
#![cfg_attr(test, allow(dead_code))]

use std::collections::BTreeMap;
use std::process::ExitCode;

use criterion::{BenchmarkId, Criterion, Throughput};

#[path = "materializer_mutex/configuration.rs"]
mod configuration;
#[path = "materializer_mutex/measurement.rs"]
mod measurement;
#[path = "materializer_mutex/observers.rs"]
mod observers;
#[path = "materializer_mutex/reporting.rs"]
mod reporting;
#[path = "materializer_mutex/worker.rs"]
mod worker;

#[cfg(test)]
#[path = "materializer_mutex/contract_tests.rs"]
mod tests;

use configuration::{MaterializerCase, WorkloadPlan, resolve_workload_plan};
use measurement::run_measured_case;
use observers::{IMPL_REAL_STD, IMPL_SHADOW_STD, Implementation};
use reporting::{
    CALIBRATION_TOLERANCE, CalibrationRecord, MaterializerBenchRun, calibration_relative_delta,
    calibration_verdict, write_report,
};
use worker::Fleet;

fn run_matrix(
    criterion: &mut Criterion,
    plan: &WorkloadPlan,
) -> Result<MaterializerBenchRun, String> {
    let implementations = [
        Implementation::RealStd,
        Implementation::ShadowStd,
        Implementation::ShadowParkingLot,
    ];
    let mut rows = Vec::new();
    let mut diagnostics = Vec::new();
    let mut calibration = Vec::new();
    let mut group = criterion.benchmark_group("materializer_mutex");
    // The authoritative p50/p99 comes from the deterministic recorder above;
    // Criterion is here for stable sampling, so the sample count stays at its
    // floor to keep the 1/4/16 matrix inside a sane wall-clock budget.
    group.sample_size(10);

    let mut first_case: Option<MaterializerCase> = None;
    for &workers in &plan.worker_matrix {
        let case = MaterializerCase::new(workers, plan.dimensions);
        if first_case.is_none() {
            first_case = Some(case);
        }
        let elements = u64::try_from(case.workers * case.updates_per_burst).unwrap_or(0);
        let mut p99_by_impl: BTreeMap<&'static str, f64> = BTreeMap::new();
        for implementation in implementations {
            let mut sample = |fleet: &Fleet| {
                group.throughput(Throughput::Elements(elements));
                group.bench_function(BenchmarkId::new(implementation.label(), workers), |b| {
                    b.iter_custom(|iters| {
                        // Criterion cannot return a Result. Abort before it
                        // records a timing if any sampled phase is invalid.
                        fleet.run_phase(iters, false).unwrap_or_else(|error| {
                            panic!("one-331: {error}; this run is not usable")
                        })
                    });
                });
            };
            let outcome = run_measured_case(&case, implementation, &mut sample)?;
            p99_by_impl.insert(implementation.label(), outcome.report.p99_us);
            rows.push(outcome.report);
            diagnostics.push(outcome.diagnostics);
        }
        if let (Some(real), Some(shadow)) = (
            p99_by_impl.get(IMPL_REAL_STD).copied(),
            p99_by_impl.get(IMPL_SHADOW_STD).copied(),
        ) {
            calibration.push(CalibrationRecord {
                workers,
                real_p99_us: real,
                shadow_std_p99_us: shadow,
                relative_delta: calibration_relative_delta(shadow, real),
                tolerance: CALIBRATION_TOLERANCE,
                verdict: calibration_verdict(shadow, real).as_str(),
            });
        }
    }
    group.finish();

    let shape = first_case.unwrap_or_else(|| MaterializerCase::new(1, plan.dimensions));
    Ok(MaterializerBenchRun {
        ticket: "ONE-331",
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        updates_per_burst: shape.updates_per_burst,
        warmup_bursts: shape.warmup_bursts,
        measured_bursts: shape.measured_bursts,
        rows,
        diagnostics,
        calibration,
    })
}

fn main() -> ExitCode {
    // Dimensions are resolved and range-checked FIRST: an unusable override has
    // to fail the process before any vault, worker thread or barrier exists.
    let plan = match resolve_workload_plan() {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("one-331: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut criterion = Criterion::default().configure_from_args();
    let run = match run_matrix(&mut criterion, &plan) {
        Ok(run) => run,
        Err(error) => {
            eprintln!("one-331: {error}; this run is not usable");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = write_report(&run) {
        eprintln!("one-331: {error}");
        // Fail-closed: the deterministic report IS the deliverable, so a run
        // that lost it does not get to print Criterion's completion summary on
        // top of the failure. Criterion's own per-benchmark data is already
        // persisted by `bench_function`; only the console banner is skipped.
        eprintln!("one-331: no report was written; this run is not usable");
        return ExitCode::FAILURE;
    }
    criterion.final_summary();
    ExitCode::SUCCESS
}
