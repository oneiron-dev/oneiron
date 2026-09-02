//! ONE-1579 fail-closed reporting cells.
//!
//! Two shapes carry the whole fail-closed contract of the perf report:
//!
//! * [`Cell`] — every numeric slot is `measured` / `not_applicable` /
//!   `not_ready`. A missing measurement is never rendered as `0`.
//! * [`Ratio`] — a speedup is only ever emitted when BOTH sides were measured
//!   wall-clock in this run. When a baseline was not measured the field is
//!   absent from the JSON entirely (`Option` + `skip_serializing_if`), so no
//!   simulated, injected or authored denominator can reach a reader.
//!
//! [`RunMode`] and [`EvidenceKind`] live here too: they say what a cell rests
//! on, and every axis carries one so a reader never has to infer it.

use serde::Serialize;

/// Label pinned on every ratio: the denominator was measured wall-clock in
/// this same run. No other baseline kind is representable.
pub(crate) const MEASURED_WALL_CLOCK_BASELINE: &str = "measured_wall_clock";

/// How a run was produced. A smoke is ALWAYS non-publishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunMode {
    /// Full run: floors apply, the exact session curve applies, cache events
    /// must come from real traffic.
    Full,
    /// Synthetic smoke over the bundled fixtures. Never publishable.
    SyntheticSmoke,
}

impl RunMode {
    pub(crate) const fn is_full(self) -> bool {
        matches!(self, Self::Full)
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::SyntheticSmoke => "synthetic_smoke",
        }
    }
}

/// What kind of evidence a cell or axis rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EvidenceKind {
    /// Timed in this process against real engine calls.
    MeasuredWallClock,
    /// Timed in this process, but over deliberately under-floor synthetic
    /// fixtures. Never publishable as a performance claim.
    SyntheticSmoke,
    /// Read from bench-owned event rows produced by real traffic.
    IngestedRealTrafficEvents,
    /// Environment description, not an engine benchmark row.
    DescriptiveExternal,
}

/// A single reportable slot. There is no fourth state, and no state carries a
/// silent zero: an absent measurement is `not_ready`, an inapplicable one is
/// `not_applicable`, and both carry a reason string.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum Cell<T> {
    Measured { value: T },
    NotApplicable { reason: String },
    NotReady { reason: String },
}

impl<T> Cell<T> {
    pub(crate) fn measured(value: T) -> Self {
        Self::Measured { value }
    }

    pub(crate) fn not_applicable(reason: impl Into<String>) -> Self {
        Self::NotApplicable {
            reason: reason.into(),
        }
    }

    pub(crate) fn not_ready(reason: impl Into<String>) -> Self {
        Self::NotReady {
            reason: reason.into(),
        }
    }

    /// `Some` becomes a measured cell; `None` becomes an explicit `not_ready`
    /// with the caller's reason. This is the ONLY conversion from an optional
    /// measurement, so a missing value can never fall through to `0`.
    pub(crate) fn from_option(value: Option<T>, reason: impl Into<String>) -> Self {
        match value {
            Some(value) => Self::measured(value),
            None => Self::not_ready(reason),
        }
    }

    pub(crate) fn value(&self) -> Option<&T> {
        match self {
            Self::Measured { value } => Some(value),
            Self::NotApplicable { .. } | Self::NotReady { .. } => None,
        }
    }

    pub(crate) fn is_measured(&self) -> bool {
        matches!(self, Self::Measured { .. })
    }
}

impl Cell<f64> {
    /// The measured number, or `None` for either fail-closed state. Used by
    /// the acceptance and publication readers, which must never treat an
    /// unmeasured cell as a zero.
    pub(crate) fn measured_f64(&self) -> Option<f64> {
        self.value().copied()
    }
}

/// Nearest-rank percentile summary over one sample set. `p95` is carried
/// explicitly because the contract rows are p50/p95, not a mean.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Percentiles {
    pub(crate) count: usize,
    pub(crate) p50: f64,
    pub(crate) p95: f64,
    pub(crate) p99: f64,
    pub(crate) min: f64,
    pub(crate) max: f64,
    pub(crate) mean: f64,
}

impl Percentiles {
    /// `None` for an empty sample set — the caller turns that into an explicit
    /// `not_ready` cell rather than a zero row.
    pub(crate) fn from_samples(samples: &[f64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_by(f64::total_cmp);
        let sum: f64 = sorted.iter().sum();
        Some(Self {
            count: sorted.len(),
            p50: percentile(&sorted, 50.0),
            p95: percentile(&sorted, 95.0),
            p99: percentile(&sorted, 99.0),
            min: sorted[0],
            max: sorted[sorted.len() - 1],
            mean: sum / sorted.len() as f64,
        })
    }
}

/// Nearest-rank percentile over an ascending-sorted, non-empty slice.
fn percentile(sorted: &[f64], pct: f64) -> f64 {
    let rank = ((pct / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// A ratio between two values BOTH measured wall-clock in this run.
///
/// There is no constructor that accepts a simulated, injected or authored
/// denominator, and the only producer is [`measured_speedup`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Ratio {
    pub(crate) value: f64,
    pub(crate) numerator: String,
    pub(crate) numerator_ms: f64,
    pub(crate) denominator: String,
    pub(crate) denominator_ms: f64,
    pub(crate) baseline_kind: &'static str,
}

/// Builds a speedup ONLY from two measured wall-clock values. When the
/// baseline was not measured (or is degenerate) the result is `None` and the
/// caller's field is omitted from the JSON entirely.
pub(crate) fn measured_speedup(
    numerator: &str,
    numerator_ms: Option<f64>,
    denominator: &str,
    denominator_ms: Option<f64>,
) -> Option<Ratio> {
    let numerator_ms = numerator_ms?;
    let denominator_ms = denominator_ms?;
    if !numerator_ms.is_finite() || !denominator_ms.is_finite() || denominator_ms <= 0.0 {
        return None;
    }
    Some(Ratio {
        value: numerator_ms / denominator_ms,
        numerator: numerator.to_owned(),
        numerator_ms,
        denominator: denominator.to_owned(),
        denominator_ms,
        baseline_kind: MEASURED_WALL_CLOCK_BASELINE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cell_without_a_measurement_is_never_zero() {
        let cell: Cell<f64> = Cell::from_option(None, "probe unavailable");
        assert!(!cell.is_measured());
        assert!(cell.value().is_none());
        assert!(cell.measured_f64().is_none());
        let rendered = serde_json::to_string(&cell).expect("cell renders");
        assert!(rendered.contains("not_ready"), "{rendered}");
        assert!(!rendered.contains(": 0"), "{rendered}");
    }

    #[test]
    fn a_speedup_without_a_measured_baseline_is_omitted() {
        assert!(measured_speedup("candidate", Some(4.0), "baseline", None).is_none());
        assert!(measured_speedup("candidate", None, "baseline", Some(4.0)).is_none());
        assert!(measured_speedup("candidate", Some(4.0), "baseline", Some(0.0)).is_none());
        let ratio = measured_speedup("candidate", Some(4.0), "baseline", Some(2.0))
            .expect("both sides measured");
        assert!((ratio.value - 2.0).abs() < f64::EPSILON);
        assert_eq!(ratio.baseline_kind, MEASURED_WALL_CLOCK_BASELINE);
    }

    #[test]
    fn percentiles_are_nearest_rank_over_a_non_empty_set() {
        assert!(Percentiles::from_samples(&[]).is_none());
        let percentiles = Percentiles::from_samples(&[4.0, 1.0, 3.0, 2.0]).expect("samples");
        assert_eq!(percentiles.count, 4);
        assert!((percentiles.p50 - 2.0).abs() < f64::EPSILON);
        assert!((percentiles.p95 - 4.0).abs() < f64::EPSILON);
        assert!((percentiles.min - 1.0).abs() < f64::EPSILON);
        assert!((percentiles.max - 4.0).abs() < f64::EPSILON);
    }
}
