//! Stable JSON rows, percentiles, calibration, and fail-closed report output.

use std::time::Duration;

use serde::Serialize;

use super::configuration::MaterializerCase;

/// Blueprint calibration tolerance: shadow-std p99 must be within 15% of the
/// real Observer B p99 at four workers, otherwise the run is inconclusive.
pub(super) const CALIBRATION_TOLERANCE: f64 = 0.15;

const ENV_REPORT: &str = "ONEIRON_MATERIALIZER_MUTEX_REPORT";

/// One measured row. Field set is pinned by the ONE-331 blueprint skeleton.
#[derive(Debug, Clone, Serialize)]
pub(super) struct MaterializerBenchReport {
    /// `real_std` | `shadow_std` | `shadow_parking_lot`.
    pub(super) implementation: &'static str,
    pub(super) workers: usize,
    pub(super) commits_per_second: f64,
    pub(super) p50_us: f64,
    pub(super) p99_us: f64,
}

/// Per-row integrity evidence: proof the row actually materialized to LMDB
/// rather than measuring an empty callback.
#[derive(Debug, Clone, Serialize)]
pub(super) struct MaterializerRowDiagnostics {
    pub(super) implementation: &'static str,
    pub(super) workers: usize,
    /// Entity rows found in LMDB after the run over the deterministic id space.
    pub(super) materialized_rows: usize,
    /// Shadow-adapter ops committed through `Vault::batch()` (0 for `real_std`).
    pub(super) shadow_committed_ops: u64,
    /// Shadow-adapter rejected/failed ops (0 for `real_std`).
    pub(super) shadow_errors: u64,
    pub(super) measured_samples: usize,
}

/// Calibration verdict for one contention point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CalibrationVerdict {
    /// Shadow-std p99 is within [`CALIBRATION_TOLERANCE`] of the real p99.
    Comparable,
    /// Outside tolerance: the comparison is invalid, production keeps std.
    InconclusiveKeepStd,
}

impl CalibrationVerdict {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Comparable => "comparable",
            Self::InconclusiveKeepStd => "inconclusive_keep_std",
        }
    }
}

/// Records the blueprint's calibration comparison at one worker count.
#[derive(Debug, Clone, Serialize)]
pub(super) struct CalibrationRecord {
    pub(super) workers: usize,
    pub(super) real_p99_us: f64,
    pub(super) shadow_std_p99_us: f64,
    /// `|shadow - real| / real`.
    pub(super) relative_delta: f64,
    pub(super) tolerance: f64,
    pub(super) verdict: &'static str,
}

/// Whole-run JSON envelope written alongside Criterion's output.
#[derive(Debug, Clone, Serialize)]
pub(super) struct MaterializerBenchRun {
    pub(super) ticket: &'static str,
    pub(super) os: &'static str,
    pub(super) arch: &'static str,
    pub(super) updates_per_burst: usize,
    pub(super) warmup_bursts: usize,
    pub(super) measured_bursts: usize,
    pub(super) rows: Vec<MaterializerBenchReport>,
    pub(super) diagnostics: Vec<MaterializerRowDiagnostics>,
    pub(super) calibration: Vec<CalibrationRecord>,
}

/// Applies the blueprint calibration rule.
///
/// A non-positive or non-finite real p99 cannot be calibrated against, so it
/// fails closed to "inconclusive, keep std" rather than silently passing.
pub(super) fn calibration_verdict(shadow_std_p99_us: f64, real_p99_us: f64) -> CalibrationVerdict {
    if !real_p99_us.is_finite() || !shadow_std_p99_us.is_finite() || real_p99_us <= 0.0 {
        return CalibrationVerdict::InconclusiveKeepStd;
    }
    if calibration_relative_delta(shadow_std_p99_us, real_p99_us) <= CALIBRATION_TOLERANCE {
        CalibrationVerdict::Comparable
    } else {
        CalibrationVerdict::InconclusiveKeepStd
    }
}

/// `|shadow - real| / real`, or `f64::INFINITY` when there is no usable real p99.
pub(super) fn calibration_relative_delta(shadow_std_p99_us: f64, real_p99_us: f64) -> f64 {
    if !real_p99_us.is_finite() || real_p99_us <= 0.0 {
        return f64::INFINITY;
    }
    (shadow_std_p99_us - real_p99_us).abs() / real_p99_us
}

pub(super) fn summarize(
    implementation: &'static str,
    case: &MaterializerCase,
    samples: &[u64],
    elapsed: Duration,
) -> Result<MaterializerBenchReport, String> {
    let expected_samples = case
        .workers
        .checked_mul(case.measured_bursts)
        .ok_or_else(|| "measured sample count overflow".to_owned())?;
    if samples.is_empty() || samples.len() != expected_samples {
        return Err(format!(
            "recorded {} samples; expected {expected_samples}",
            samples.len()
        ));
    }
    if elapsed.is_zero() {
        return Err("measured phase has no elapsed time".to_owned());
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let commits_per_second = sorted.len() as f64 / elapsed.as_secs_f64();
    Ok(MaterializerBenchReport {
        implementation,
        workers: case.workers,
        commits_per_second,
        p50_us: percentile_us(&sorted, 0.50),
        p99_us: percentile_us(&sorted, 0.99),
    })
}

/// Nearest-rank percentile over ascending nanosecond samples, in microseconds.
fn percentile_us(sorted_nanos: &[u64], quantile: f64) -> f64 {
    if sorted_nanos.is_empty() {
        return 0.0;
    }
    let rank = (quantile * sorted_nanos.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted_nanos.len() - 1);
    sorted_nanos[index] as f64 / 1_000.0
}

/// Where the deterministic p50/p99 JSON lands, next to Criterion's output.
fn report_path() -> std::path::PathBuf {
    if let Ok(raw) = std::env::var(ENV_REPORT) {
        return std::path::PathBuf::from(raw);
    }
    let target = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_owned());
    std::path::PathBuf::from(target)
        .join("criterion")
        .join("materializer_mutex")
        .join("materializer_mutex_report.json")
}

/// Writes the deterministic p50/p99 JSON report.
///
/// Fail-closed: every directory, serialization and write failure comes back as
/// an `Err` message for `main` to print before it exits non-zero. This report
/// is the authoritative record of the run, so one that never reached disk must
/// never leave a successful process behind.
pub(super) fn write_report(run: &MaterializerBenchRun) -> Result<(), String> {
    let path = report_path();
    if let Some(parent) = path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return Err(format!("could not create report directory: {error}"));
    }
    let bytes = serde_json::to_vec_pretty(run)
        .map_err(|error| format!("could not serialize report: {error}"))?;
    std::fs::write(&path, bytes).map_err(|error| format!("could not write report: {error}"))?;
    let written = path.display();
    eprintln!("one-331: materializer mutex report written to {written}");
    Ok(())
}
