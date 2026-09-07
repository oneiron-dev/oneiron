//! Deterministic workload, report, bounds, and rejection contracts.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use loro::LoroDoc;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{TimeRange, Vault, VaultConfig};

use super::configuration::*;
use super::measurement::{run_case_with_runtime, run_measured_case};
use super::observers::*;
use super::reporting::*;
use super::worker::*;

/// Deliberately tiny: the 1/4/16 x 32 x 100 x 1,000 matrix is a BENCH run,
/// not a unit test. These fixtures assert contracts, not timings.
fn fixture_case(workers: usize) -> MaterializerCase {
    MaterializerCase {
        workers,
        updates_per_burst: 4,
        warmup_bursts: 2,
        measured_bursts: 8,
    }
}

/// Drives one shadow adapter over a fixed delta containing four valid
/// entity ops, one op under a non-hex key, and one op whose blob is too
/// short to carry a header. Returns the committed rows plus the adapter's
/// (committed_ops, errors) counters.
fn shadow_fixture<L: BenchLock>() -> (BTreeMap<String, Vec<u8>>, u64, u64) {
    let dir = tempfile::tempdir().expect("fixture temp vault directory");
    let vault =
        Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("fixture temp vault opens"));
    let lock = Arc::new(L::new());
    let counters = Arc::new(ShadowCounters::default());
    let doc = LoroDoc::new();
    let _subscriptions = register_shadow_observer(&doc, &vault, &lock, &counters);
    let entities = doc.get_map("entities");

    let occurred = TimeRange {
        start: BASE_LEARNED_AT,
        end: BASE_LEARNED_AT,
    };
    let mut valid_ids = Vec::new();
    for update in 0..4 {
        let id = bench_entity_id(0, 0, update);
        let blob = encode_entity_blob(ENTITY_TYPE_PERSON, occurred, BASE_LEARNED_AT, ENTITY_BODY);
        entities
            .insert(&id.to_hex(), blob.as_slice())
            .expect("fixture entity insert succeeds");
        valid_ids.push(id);
    }
    // Rejected op 1: key is not 32-char hex.
    entities
        .insert("not-a-hex-entity-key", b"rejected".as_slice())
        .expect("fixture entity insert succeeds");
    // Rejected op 2: canonical key, but the blob is shorter than a header.
    entities
        .insert(&bench_entity_id(0, 0, 9).to_hex(), b"short".as_slice())
        .expect("fixture entity insert succeeds");
    doc.commit();

    let mut rows = BTreeMap::new();
    for id in &valid_ids {
        if let Some(raw) = vault.get_raw(id).expect("fixture entity read succeeds") {
            rows.insert(id.to_hex(), raw);
        }
    }
    let (committed_ops, errors) = counters.snapshot();
    (rows, committed_ops, errors)
}

/// Both adapters commit the same entity rows and the same error counts:
/// the only difference between them is the mutex.
#[test]
fn materializer_mutex_workload_equivalence() {
    let (std_rows, std_ops, std_errors) = shadow_fixture::<StdBenchLock>();
    let (parking_rows, parking_ops, parking_errors) = shadow_fixture::<ParkingLotBenchLock>();

    assert_eq!(
        std_rows.len(),
        4,
        "std adapter must materialize every valid entity op"
    );
    assert_eq!(
        std_rows, parking_rows,
        "std and parking_lot adapters must commit identical entity rows"
    );
    assert_eq!(
        std_ops, parking_ops,
        "std and parking_lot adapters must commit the same op count"
    );
    assert_eq!(
        std_errors, parking_errors,
        "std and parking_lot adapters must reject the same ops"
    );
    assert_eq!(std_ops, 4, "four valid ops are staged and committed");
    assert_eq!(
        std_errors, 2,
        "the non-hex key and the header-less blob are both rejected"
    );
}

/// The recorded row carries BOTH percentiles, and they survive
/// serialization into the JSON the run writes alongside Criterion.
#[test]
fn materializer_mutex_report_has_p50_and_p99() {
    let case = fixture_case(2);
    let outcome = run_measured_case(&case, Implementation::ShadowStd, &mut |_fleet: &Fleet| {})
        .expect("valid shadow workload produces a report");
    let report = &outcome.report;

    assert_eq!(report.implementation, IMPL_SHADOW_STD);
    assert_eq!(report.workers, 2);
    assert!(report.p50_us > 0.0, "p50 must be recorded, got {report:?}");
    assert!(report.p99_us > 0.0, "p99 must be recorded, got {report:?}");
    assert!(
        report.p99_us >= report.p50_us,
        "p99 must not sit below p50, got {report:?}"
    );
    assert!(
        report.commits_per_second > 0.0,
        "commits/s must be recorded, got {report:?}"
    );
    assert_eq!(
        outcome.diagnostics.measured_samples,
        case.workers * case.measured_bursts,
        "every measured burst contributes one latency sample"
    );

    let json = serde_json::to_value(report).expect("report serializes to JSON");
    assert!(json.get("p50_us").is_some(), "report JSON carries p50_us");
    assert!(json.get("p99_us").is_some(), "report JSON carries p99_us");
    assert!(
        json.get("commits_per_second").is_some(),
        "report JSON carries commits_per_second"
    );
}

/// The four-worker calibration contract.
///
/// Two halves, both deterministic:
///
/// 1. the gate itself — shadow-std p99 within 15% of the real Observer B
///    p99 is `Comparable`, anything outside is `InconclusiveKeepStd`
///    (blueprint: "otherwise the comparison is invalid and the production
///    lock stays unchanged");
/// 2. the two rows the gate compares actually exist at four workers and
///    both do REAL LMDB materialization over the identical id space — the
///    property that stops the shadow workload from degenerating into an
///    unrealistic microbenchmark.
///
/// The 15% bound itself is asserted against the recorded matrix on each
/// machine (a bench run), never against a handful of micro-bursts here:
/// a timing assertion at this size would be noise, not a contract.
#[test]
fn materializer_shadow_std_tracks_real_observer_b() {
    assert_eq!(
        calibration_verdict(100.0, 100.0),
        CalibrationVerdict::Comparable
    );
    assert_eq!(
        calibration_verdict(114.9, 100.0),
        CalibrationVerdict::Comparable
    );
    assert_eq!(
        calibration_verdict(85.1, 100.0),
        CalibrationVerdict::Comparable
    );
    assert_eq!(
        calibration_verdict(115.1, 100.0),
        CalibrationVerdict::InconclusiveKeepStd
    );
    assert_eq!(
        calibration_verdict(84.9, 100.0),
        CalibrationVerdict::InconclusiveKeepStd
    );
    assert_eq!(
        calibration_verdict(10.0, 0.0),
        CalibrationVerdict::InconclusiveKeepStd,
        "an unusable real p99 fails closed to keep-std"
    );

    let case = fixture_case(4);
    let real = run_measured_case(&case, Implementation::RealStd, &mut |_fleet: &Fleet| {})
        .expect("valid real workload produces a report");
    let shadow = run_measured_case(&case, Implementation::ShadowStd, &mut |_fleet: &Fleet| {})
        .expect("valid shadow workload produces a report");

    assert_eq!(real.report.implementation, IMPL_REAL_STD);
    assert_eq!(shadow.report.implementation, IMPL_SHADOW_STD);
    assert_eq!(real.report.workers, 4);
    assert_eq!(shadow.report.workers, 4);
    assert!(real.report.p99_us > 0.0, "real row must record a p99");
    assert!(shadow.report.p99_us > 0.0, "shadow row must record a p99");

    let expected_rows = case.workers * KEY_SLOTS * case.updates_per_burst;
    assert_eq!(
        real.diagnostics.materialized_rows, expected_rows,
        "real Observer B must materialize the whole id space"
    );
    assert_eq!(
        shadow.diagnostics.materialized_rows, expected_rows,
        "the shadow adapter must materialize the same rows Observer B does"
    );
    assert_eq!(
        real.diagnostics.shadow_committed_ops, 0,
        "the real row carries no shadow-adapter counters"
    );
    assert_eq!(
        shadow.diagnostics.shadow_errors, 0,
        "a valid burst workload must produce no shadow rejections"
    );
    assert!(
        shadow.diagnostics.shadow_committed_ops > 0,
        "the shadow adapter must actually commit through Vault::batch()"
    );

    // The verdict the run records for these two rows must be exactly the
    // 15% rule applied to the measured p99s — the tolerance itself is
    // judged on the full matrix, never on a handful of micro-bursts.
    let delta = calibration_relative_delta(shadow.report.p99_us, real.report.p99_us);
    let verdict = calibration_verdict(shadow.report.p99_us, real.report.p99_us);
    assert_eq!(
        verdict == CalibrationVerdict::Comparable,
        delta <= CALIBRATION_TOLERANCE,
        "the recorded verdict must be the calibration rule applied to the measured p99s"
    );
}

/// The parse-time dimension gate.
///
/// The blueprint defaults and the exact `u16` boundary are accepted; a
/// count the entity id space cannot encode, and a zero-sized workload, are
/// refused with a message naming the variable, the value and the range.
/// Refusing here is what keeps the old failure mode — `narrow_u16`
/// panicking inside a worker and parking the fleet on a barrier forever —
/// unreachable.
#[test]
fn materializer_mutex_dimension_bounds_are_enforced() {
    for workers in DEFAULT_WORKER_MATRIX {
        let raw = workers.to_string();
        assert_eq!(parse_dimension(ENV_WORKERS, &raw), Ok(workers));
    }
    let updates = DEFAULT_UPDATES_PER_BURST.to_string();
    let default_updates = parse_dimension(ENV_UPDATES, &updates);
    assert_eq!(default_updates, Ok(DEFAULT_UPDATES_PER_BURST));
    assert_eq!(
        parse_dimension(ENV_UPDATES, "65536"),
        Ok(MAX_WORKLOAD_DIMENSION),
        "the widest index of a 65536-count dimension is still a u16"
    );

    // Every refusal has to name the variable, the value and the range.
    let over = parse_dimension(ENV_UPDATES, "65537").expect_err("65537 is refused");
    for expected in [ENV_UPDATES, "65537", "1..=65536"] {
        assert!(over.contains(expected), "{over} must name {expected}");
    }
    let zero = parse_dimension(ENV_WORKERS, "0").expect_err("0 is refused");
    for expected in [ENV_WORKERS, "=0 ", "1..=65536"] {
        assert!(zero.contains(expected), "{zero} must name {expected}");
    }

    // A set-but-unparseable override is a named error too, never a silent
    // fallback to the default it was meant to replace.
    assert!(parse_dimension(ENV_WORKERS, "four").is_err());
}

/// Independent expected final state for a short run or a wrapped slot space.
/// Build it by replaying rounds, rather than duplicating the validator's
/// last-round arithmetic.
fn workload_rows(case: &MaterializerCase, rounds: u64) -> BTreeMap<String, Vec<u8>> {
    let mut rows = BTreeMap::new();
    for round in 0..rounds {
        let slot = (round % KEY_SLOTS as u64) as usize;
        let learned_at = BASE_LEARNED_AT + round;
        let occurred = TimeRange {
            start: learned_at,
            end: learned_at,
        };
        let blob = encode_entity_blob(ENTITY_TYPE_PERSON, occurred, learned_at, ENTITY_BODY);
        for worker in 0..case.workers {
            for update in 0..case.updates_per_burst {
                rows.insert(bench_entity_id(worker, slot, update).to_hex(), blob.clone());
            }
        }
    }
    rows
}

#[test]
fn materializer_mutex_requires_complete_current_materialization() {
    let case = fixture_case(2);
    for rounds in [2, KEY_SLOTS as u64, KEY_SLOTS as u64 + 2] {
        let rows = workload_rows(&case, rounds);
        let found = validate_workload_rows(&case, rounds, |id| Ok(rows.get(&id.to_hex()).cloned()))
            .expect("every visited slot has its latest blob");
        assert_eq!(found, rows.len());

        let missing_id = bench_entity_id(1, 1, 3).to_hex();
        let mut incomplete = rows;
        incomplete.remove(&missing_id);
        let error = validate_workload_rows(&case, rounds, |id| {
            Ok(incomplete.get(&id.to_hex()).cloned())
        })
        .expect_err("one missing row must invalidate the whole workload");
        assert!(error.contains("missing materialized entity"), "{error}");
        assert!(error.contains(&missing_id), "{error}");
    }

    // All slots still exist after warmup, but they cannot stand in for the
    // newer measured writes. This defeated a presence-only row census.
    let stale = workload_rows(&case, KEY_SLOTS as u64);
    let error = validate_workload_rows(&case, KEY_SLOTS as u64 + 2, |id| {
        Ok(stale.get(&id.to_hex()).cloned())
    })
    .expect_err("warmup rows must not mask failed measured writes");
    assert!(error.contains("does not match round"), "{error}");
}

#[test]
fn materializer_mutex_propagates_materialization_read_errors() {
    let case = fixture_case(1);
    let cause = oneiron::Error::InvalidKey;
    let expected_cause = cause.to_string();
    let error = validate_workload_rows(&case, 1, |_id| Err(oneiron::Error::InvalidKey))
        .expect_err("a storage error cannot become a miss or a usable row");
    assert!(
        error.contains("could not read materialized entity"),
        "{error}"
    );
    assert!(error.contains(&expected_cause), "{error}");
}

#[test]
fn materializer_mutex_rejects_failed_or_skipped_shadow_operations() {
    let case = fixture_case(2);
    let rounds = (case.warmup_bursts + case.measured_bursts) as u64;
    let expected = rounds * case.workers as u64 * case.updates_per_burst as u64;
    assert_eq!(validate_shadow_counts(&case, rounds, (expected, 0)), Ok(()));
    let error = validate_shadow_counts(&case, rounds, (expected, 1))
        .expect_err("even complete final rows cannot excuse an earlier shadow error");
    assert!(error.contains("1 errors"), "{error}");
    assert!(validate_shadow_counts(&case, rounds, (expected - 1, 0)).is_err());
    assert!(validate_shadow_counts(&case, rounds, (expected + 1, 0)).is_err());
}

struct EmptyObserverFactory;

impl ObserverFactory for EmptyObserverFactory {
    fn register(
        &self,
        _doc: &LoroDoc,
        _vault: &Arc<Vault>,
        _window_key: &str,
    ) -> Vec<loro::Subscription> {
        Vec::new()
    }
}

#[test]
fn materializer_mutex_rejects_empty_callbacks_before_sampling_or_reporting() {
    let mut case = fixture_case(1);
    case.warmup_bursts = 0;
    let runtime = ImplementationRuntime {
        factory: Arc::new(EmptyObserverFactory),
        counters: None,
    };
    let mut sampled = false;
    let error = run_case_with_runtime(&case, Implementation::RealStd, runtime, &mut |_fleet| {
        sampled = true;
    })
    .expect_err("missing measured writes must not produce an outcome");
    assert!(error.contains("missing materialized entity"), "{error}");
    assert!(
        !sampled,
        "Criterion must not sample an invalid recorded workload"
    );
}

#[test]
fn materializer_mutex_rejects_errors_from_later_sampling() {
    let case = fixture_case(1);
    let runtime = Implementation::ShadowStd.runtime();
    let counters = runtime
        .counters
        .as_ref()
        .expect("shadow has counters")
        .clone();
    let error = run_case_with_runtime(&case, Implementation::ShadowStd, runtime, &mut |_fleet| {
        counters
            .errors
            .store(1, std::sync::atomic::Ordering::Relaxed);
    })
    .expect_err("a valid measured phase cannot excuse later sampling errors");
    assert!(
        error.contains("shadow materialization reported 1 errors"),
        "{error}"
    );
}

#[test]
fn materializer_mutex_report_requires_all_samples_and_positive_elapsed() {
    let case = MaterializerCase {
        workers: 2,
        updates_per_burst: 4,
        warmup_bursts: 0,
        measured_bursts: 2,
    };
    let samples = [1_000, 2_000, 3_000, 4_000];
    let elapsed = Duration::from_secs(2);
    let report = summarize(IMPL_REAL_STD, &case, &samples, elapsed)
        .expect("four commits over a complete two-second interval");
    assert_eq!(report.commits_per_second, 2.0);
    assert_eq!(report.p50_us, 2.0);
    assert_eq!(report.p99_us, 4.0);
    assert!(summarize(IMPL_REAL_STD, &case, &samples[..3], elapsed).is_err());
    assert!(summarize(IMPL_REAL_STD, &case, &[], elapsed).is_err());
    assert!(summarize(IMPL_REAL_STD, &case, &samples, Duration::ZERO).is_err());
}
