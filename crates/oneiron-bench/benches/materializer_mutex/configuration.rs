//! Workload defaults and parse-time dimension bounds.

/// Blueprint workload constants.
pub(super) const DEFAULT_UPDATES_PER_BURST: usize = 32;
const DEFAULT_WARMUP_BURSTS: usize = 100;
const DEFAULT_MEASURED_BURSTS: usize = 1_000;
pub(super) const DEFAULT_WORKER_MATRIX: [usize; 3] = [1, 4, 16];

/// Environment overrides (all optional; defaults are the blueprint matrix).
///
/// The two dimensions that feed the entity id space (`ENV_WORKERS`,
/// `ENV_UPDATES`) are range-checked at parse time against
/// `1..=MAX_WORKLOAD_DIMENSION`; see `resolve_workload_plan`.
pub(super) const ENV_WORKERS: &str = "ONEIRON_MATERIALIZER_MUTEX_WORKERS";
pub(super) const ENV_UPDATES: &str = "ONEIRON_MATERIALIZER_MUTEX_UPDATES";
const ENV_WARMUP: &str = "ONEIRON_MATERIALIZER_MUTEX_WARMUP";
const ENV_MEASURED: &str = "ONEIRON_MATERIALIZER_MUTEX_MEASURED";

/// One contention point of the blueprint matrix.
#[derive(Debug, Clone, Copy)]
pub(super) struct MaterializerCase {
    /// 1 | 4 | 16 (blueprint default matrix).
    pub(super) workers: usize,
    /// 32 entity-map updates per burst.
    pub(super) updates_per_burst: usize,
    /// 100 unrecorded bursts.
    pub(super) warmup_bursts: usize,
    /// 1,000 recorded bursts.
    pub(super) measured_bursts: usize,
}

impl MaterializerCase {
    /// Blueprint defaults, with the ALREADY VALIDATED environment overrides so
    /// the matrix can be shortened for a smoke run without editing this file.
    ///
    /// Taking the dimensions as an argument is what makes the bound
    /// unconditional: they are resolved once, before any fleet exists, so no
    /// case can be built from an override this file never checked.
    pub(super) fn new(workers: usize, dimensions: WorkloadDimensions) -> Self {
        Self {
            workers,
            updates_per_burst: dimensions.updates_per_burst,
            warmup_bursts: dimensions.warmup_bursts,
            measured_bursts: dimensions.measured_bursts,
        }
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

/// Inclusive bound every id-space dimension must satisfy.
///
/// `bench_entity_id` packs the worker and update indices into `u16` fields, so
/// a count of `N` is usable exactly while its widest index (`N - 1`) still fits
/// a `u16`. Anything larger used to reach `narrow_u16` INSIDE a worker thread,
/// where the panic stranded the rest of the fleet on a barrier forever, so the
/// bound is enforced at parse time instead of discovered mid-phase.
pub(super) const MAX_WORKLOAD_DIMENSION: usize = u16::MAX as usize + 1;

/// The operator-facing refusal: which variable, which value, which range.
///
/// Every dimension rejection is built here so the sites cannot drift apart.
fn dimension_error(name: &str, value: &str, problem: &str) -> String {
    format!("{name}={value} {problem}; allowed range is 1..={MAX_WORKLOAD_DIMENSION}")
}

/// Parses one id-space dimension and enforces `1..=MAX_WORKLOAD_DIMENSION`.
///
/// Pure on purpose: the whole bound is testable without touching the process
/// environment.
pub(super) fn parse_dimension(name: &str, raw: &str) -> Result<usize, String> {
    let Ok(value) = raw.parse::<usize>() else {
        return Err(dimension_error(
            name,
            &format!("{raw:?}"),
            "is not a whole number",
        ));
    };
    if !(1..=MAX_WORKLOAD_DIMENSION).contains(&value) {
        return Err(dimension_error(name, &value.to_string(), "is out of range"));
    }
    Ok(value)
}

/// The blueprint contention points, or a validated `ENV_WORKERS` override.
///
/// An unset variable keeps the default matrix. A variable that IS set has to
/// name usable worker counts: an unparseable, zero, oversized or empty list is
/// a named error, never a silent fallback to the matrix the operator overrode.
fn resolve_worker_matrix() -> Result<Vec<usize>, String> {
    let Ok(raw) = std::env::var(ENV_WORKERS) else {
        return Ok(DEFAULT_WORKER_MATRIX.to_vec());
    };
    let mut parsed = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        parsed.push(parse_dimension(ENV_WORKERS, part)?);
    }
    if parsed.is_empty() {
        return Err(dimension_error(
            ENV_WORKERS,
            &format!("{raw:?}"),
            "lists no worker count",
        ));
    }
    Ok(parsed)
}

/// The per-burst shape every case in one run shares.
#[derive(Debug, Clone, Copy)]
pub(super) struct WorkloadDimensions {
    pub(super) updates_per_burst: usize,
    pub(super) warmup_bursts: usize,
    pub(super) measured_bursts: usize,
}

/// The contention points to run plus the dimensions each of them uses.
pub(super) struct WorkloadPlan {
    pub(super) worker_matrix: Vec<usize>,
    pub(super) dimensions: WorkloadDimensions,
}

/// Resolves every environment override ONCE, before any vault, worker thread
/// or barrier exists, so an unusable dimension fails the process instead of
/// stranding a fleet mid-phase.
///
/// Only the two dimensions that feed the `bench_entity_id` u16 id space carry
/// the `1..=MAX_WORKLOAD_DIMENSION` bound. Burst COUNTS (`ENV_WARMUP`,
/// `ENV_MEASURED`) only make a run longer, never unencodable, so they keep the
/// lenient parsing they already had.
pub(super) fn resolve_workload_plan() -> Result<WorkloadPlan, String> {
    let updates_per_burst = match std::env::var(ENV_UPDATES) {
        Ok(raw) => parse_dimension(ENV_UPDATES, raw.trim())?,
        Err(_) => DEFAULT_UPDATES_PER_BURST,
    };
    Ok(WorkloadPlan {
        worker_matrix: resolve_worker_matrix()?,
        dimensions: WorkloadDimensions {
            updates_per_burst,
            warmup_bursts: env_usize(ENV_WARMUP, DEFAULT_WARMUP_BURSTS),
            measured_bursts: env_usize(ENV_MEASURED, DEFAULT_MEASURED_BURSTS),
        },
    })
}
