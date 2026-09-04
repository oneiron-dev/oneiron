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
// `harness = false` bench is never run by `cargo test`, and the three
// load-bearing ONE-331 contract tests have to run there. Under the libtest
// build the Criterion driver and the JSON recorder are compiled but unused.
#![cfg_attr(test, allow(dead_code))]

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput};
use loro::event::MapDelta;
use loro::{ContainerTrait, LoroDoc, LoroMap, LoroValue, Subscription, ValueOrContainer};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::sync::bridge::{BRIDGE_ORIGIN, Materializer, register_observer_b};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde::Serialize;
use tempfile::TempDir;

/// Row label for the real `register_observer_b` + `Materializer` path.
const IMPL_REAL_STD: &str = "real_std";
/// Row label for the bench-only `std::sync::Mutex` adapter.
const IMPL_SHADOW_STD: &str = "shadow_std";
/// Row label for the bench-only `parking_lot::Mutex` adapter.
const IMPL_SHADOW_PARKING_LOT: &str = "shadow_parking_lot";

/// Entity metadata header: type byte + BE occurred start/end + BE learned_at.
/// Mirrors `crate::batch::ENTITY_METADATA_HEADER_LEN`, which is `pub(crate)`
/// and therefore not nameable from a bench crate.
const ENTITY_HEADER_LEN: usize = 25;

/// Blueprint workload constants.
const DEFAULT_UPDATES_PER_BURST: usize = 32;
const DEFAULT_WARMUP_BURSTS: usize = 100;
const DEFAULT_MEASURED_BURSTS: usize = 1_000;
const DEFAULT_WORKER_MATRIX: [usize; 3] = [1, 4, 16];

/// Number of distinct entity-key slots each worker rotates through. Bursts
/// re-write the same bounded key space with a strictly increasing
/// `learned_at`, which keeps the vault small while guaranteeing every burst
/// produces a real CRDT delta (an identical re-insert emits no event).
const KEY_SLOTS: usize = 8;

/// Fixed epoch for `learned_at` / `occurred` stamps (2026-01-01T00:00:00Z).
const BASE_LEARNED_AT: u64 = 1_767_225_600;

/// Entity body every burst writes. Plain ASCII: no secret-scan trigger, no
/// typed-body decode requirement (PERSON bodies are opaque to the engine).
const ENTITY_BODY: &[u8] = b"one-331 materializer mutex bench body";

/// Blueprint calibration tolerance: shadow-std p99 must be within 15% of the
/// real Observer B p99 at four workers, otherwise the run is inconclusive.
const CALIBRATION_TOLERANCE: f64 = 0.15;

/// Environment overrides (all optional; defaults are the blueprint matrix).
///
/// The two dimensions that feed the entity id space (`ENV_WORKERS`,
/// `ENV_UPDATES`) are range-checked at parse time against
/// `1..=MAX_WORKLOAD_DIMENSION`; see `resolve_workload_plan`.
const ENV_WORKERS: &str = "ONEIRON_MATERIALIZER_MUTEX_WORKERS";
const ENV_UPDATES: &str = "ONEIRON_MATERIALIZER_MUTEX_UPDATES";
const ENV_WARMUP: &str = "ONEIRON_MATERIALIZER_MUTEX_WARMUP";
const ENV_MEASURED: &str = "ONEIRON_MATERIALIZER_MUTEX_MEASURED";
const ENV_REPORT: &str = "ONEIRON_MATERIALIZER_MUTEX_REPORT";

// ---------------------------------------------------------------------------
// Lock abstraction
// ---------------------------------------------------------------------------

/// The one primitive under test.
///
/// Both implementations are wrapped identically so the ONLY difference
/// between the `shadow_std` and `shadow_parking_lot` rows is the mutex.
trait BenchLock: Send + Sync + 'static {
    /// Guard handed back by [`BenchLock::lock`].
    type Guard<'a>: 'a
    where
        Self: 'a;

    /// Builds a fresh, uncontended lock.
    fn new() -> Self;

    /// Row label this lock produces.
    fn label() -> &'static str;

    /// Acquires the lock, mirroring the production call shape exactly.
    fn lock(&self) -> Self::Guard<'_>;
}

/// `std::sync::Mutex<()>` — byte-for-byte the production `Materializer` shape,
/// including poison recovery (`bridge.rs` `Materializer::lock`).
struct StdBenchLock {
    mutex: Mutex<()>,
}

impl BenchLock for StdBenchLock {
    type Guard<'a>
        = std::sync::MutexGuard<'a, ()>
    where
        Self: 'a;

    fn new() -> Self {
        Self {
            mutex: Mutex::new(()),
        }
    }

    fn label() -> &'static str {
        IMPL_SHADOW_STD
    }

    fn lock(&self) -> Self::Guard<'_> {
        self.mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// `parking_lot::Mutex<()>` — the candidate. No poisoning, so no recovery arm.
struct ParkingLotBenchLock {
    mutex: parking_lot::Mutex<()>,
}

impl BenchLock for ParkingLotBenchLock {
    type Guard<'a>
        = parking_lot::MutexGuard<'a, ()>
    where
        Self: 'a;

    fn new() -> Self {
        Self {
            mutex: parking_lot::Mutex::new(()),
        }
    }

    fn label() -> &'static str {
        IMPL_SHADOW_PARKING_LOT
    }

    fn lock(&self) -> Self::Guard<'_> {
        self.mutex.lock()
    }
}

// ---------------------------------------------------------------------------
// Case / report shapes
// ---------------------------------------------------------------------------

/// One contention point of the blueprint matrix.
#[derive(Debug, Clone, Copy)]
struct MaterializerCase {
    /// 1 | 4 | 16 (blueprint default matrix).
    workers: usize,
    /// 32 entity-map updates per burst.
    updates_per_burst: usize,
    /// 100 unrecorded bursts.
    warmup_bursts: usize,
    /// 1,000 recorded bursts.
    measured_bursts: usize,
}

impl MaterializerCase {
    /// Blueprint defaults, with the ALREADY VALIDATED environment overrides so
    /// the matrix can be shortened for a smoke run without editing this file.
    ///
    /// Taking the dimensions as an argument is what makes the bound
    /// unconditional: they are resolved once, before any fleet exists, so no
    /// case can be built from an override this file never checked.
    fn new(workers: usize, dimensions: WorkloadDimensions) -> Self {
        Self {
            workers,
            updates_per_burst: dimensions.updates_per_burst,
            warmup_bursts: dimensions.warmup_bursts,
            measured_bursts: dimensions.measured_bursts,
        }
    }
}

/// One measured row. Field set is pinned by the ONE-331 blueprint skeleton.
#[derive(Debug, Clone, Serialize)]
struct MaterializerBenchReport {
    /// `real_std` | `shadow_std` | `shadow_parking_lot`.
    implementation: &'static str,
    workers: usize,
    commits_per_second: f64,
    p50_us: f64,
    p99_us: f64,
}

/// Per-row integrity evidence: proof the row actually materialized to LMDB
/// rather than measuring an empty callback.
#[derive(Debug, Clone, Serialize)]
struct MaterializerRowDiagnostics {
    implementation: &'static str,
    workers: usize,
    /// Entity rows found in LMDB after the run over the deterministic id space.
    materialized_rows: usize,
    /// Shadow-adapter ops committed through `Vault::batch()` (0 for `real_std`).
    shadow_committed_ops: u64,
    /// Shadow-adapter rejected/failed ops (0 for `real_std`).
    shadow_errors: u64,
    measured_samples: usize,
}

/// Calibration verdict for one contention point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CalibrationVerdict {
    /// Shadow-std p99 is within [`CALIBRATION_TOLERANCE`] of the real p99.
    Comparable,
    /// Outside tolerance: the comparison is invalid, production keeps std.
    InconclusiveKeepStd,
}

impl CalibrationVerdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Comparable => "comparable",
            Self::InconclusiveKeepStd => "inconclusive_keep_std",
        }
    }
}

/// Records the blueprint's calibration comparison at one worker count.
#[derive(Debug, Clone, Serialize)]
struct CalibrationRecord {
    workers: usize,
    real_p99_us: f64,
    shadow_std_p99_us: f64,
    /// `|shadow - real| / real`.
    relative_delta: f64,
    tolerance: f64,
    verdict: &'static str,
}

/// Whole-run JSON envelope written alongside Criterion's output.
#[derive(Debug, Clone, Serialize)]
struct MaterializerBenchRun {
    ticket: &'static str,
    os: &'static str,
    arch: &'static str,
    updates_per_burst: usize,
    warmup_bursts: usize,
    measured_bursts: usize,
    rows: Vec<MaterializerBenchReport>,
    diagnostics: Vec<MaterializerRowDiagnostics>,
    calibration: Vec<CalibrationRecord>,
}

/// Applies the blueprint calibration rule.
///
/// A non-positive or non-finite real p99 cannot be calibrated against, so it
/// fails closed to "inconclusive, keep std" rather than silently passing.
fn calibration_verdict(shadow_std_p99_us: f64, real_p99_us: f64) -> CalibrationVerdict {
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
fn calibration_relative_delta(shadow_std_p99_us: f64, real_p99_us: f64) -> f64 {
    if !real_p99_us.is_finite() || real_p99_us <= 0.0 {
        return f64::INFINITY;
    }
    (shadow_std_p99_us - real_p99_us).abs() / real_p99_us
}

// ---------------------------------------------------------------------------
// Entity blob encode / decode (bench-local mirror of the pub(crate) header)
// ---------------------------------------------------------------------------

/// Decoded entity metadata header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BenchEntityHeader {
    entity_type: u8,
    occurred_start: u64,
    occurred_end: u64,
    learned_at: u64,
}

fn parse_entity_header(raw: &[u8]) -> Option<BenchEntityHeader> {
    if raw.len() < ENTITY_HEADER_LEN {
        return None;
    }
    // Offsets mirror `crate::batch::types`: type byte at 0, occurred start at
    // 1..9, occurred end at 9..17, learned_at at 17..25, body from 25.
    Some(BenchEntityHeader {
        entity_type: raw[0],
        occurred_start: u64::from_be_bytes(raw[1..9].try_into().ok()?),
        occurred_end: u64::from_be_bytes(raw[9..17].try_into().ok()?),
        learned_at: u64::from_be_bytes(raw[17..25].try_into().ok()?),
    })
}

fn encode_entity_blob(
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut blob = Vec::with_capacity(ENTITY_HEADER_LEN + body.len());
    blob.push(entity_type);
    blob.extend_from_slice(&occurred.start.to_be_bytes());
    blob.extend_from_slice(&occurred.end.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(body);
    blob
}

/// Deterministic, collision-free entity id for `(worker, slot, update)`.
///
/// Never a reserved sentinel: the first byte is `0x31` and the tail is not
/// all-`0xFF`, so `EntityId::from_bytes` always accepts it.
fn bench_entity_id(worker: usize, slot: usize, update: usize) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x31;
    bytes[1..3].copy_from_slice(&narrow_u16(worker).to_be_bytes());
    bytes[3..5].copy_from_slice(&narrow_u16(slot).to_be_bytes());
    bytes[5..7].copy_from_slice(&narrow_u16(update).to_be_bytes());
    EntityId::from_bytes(bytes).expect("bench entity id is never a reserved sentinel")
}

/// Narrows one index of the id space above.
///
/// Unreachable from a worker: every dimension that reaches this is checked
/// against `MAX_WORKLOAD_DIMENSION` in `resolve_workload_plan`, before any
/// thread or barrier exists. That ordering is load-bearing — a panic here used
/// to strand the whole fleet on a barrier the dead worker never reached again.
fn narrow_u16(value: usize) -> u16 {
    u16::try_from(value).expect("workload dimensions are bounded before any worker starts")
}

// ---------------------------------------------------------------------------
// Shadow adapter: identical delta decode + Vault::batch() materialization
// ---------------------------------------------------------------------------

/// Work evidence for the shadow adapters, shared by both lock flavours.
#[derive(Debug, Default)]
struct ShadowCounters {
    committed_ops: AtomicU64,
    errors: AtomicU64,
}

impl ShadowCounters {
    fn snapshot(&self) -> (u64, u64) {
        (
            self.committed_ops.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
        )
    }
}

/// The bench-only materialization body.
///
/// Byte-for-byte identical under both locks: decode the map delta, reject
/// undecodable / non-canonical ops (counted, never panicking, exactly like
/// Observer B's quarantine-and-continue posture), stage every accepted op into
/// ONE `Vault::batch()` and commit it once — the same "accumulate the whole
/// delta into a single write transaction" shape `materialize_entities_from_delta`
/// uses.
fn shadow_materialize_entities(delta: &MapDelta<'_>, vault: &Vault, counters: &ShadowCounters) {
    let mut batch = vault.batch();
    let mut staged: u64 = 0;
    for (key, new_value) in &delta.updated {
        match new_value {
            Some(ValueOrContainer::Value(LoroValue::Binary(blob))) => {
                let Some(header) = parse_entity_header(blob) else {
                    counters.errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let Ok(id) = EntityId::from_hex(key.as_ref()) else {
                    counters.errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                // Non-canonical (case-shifted) hex alias key: a protocol
                // violation the production path refuses at the door.
                if key.as_ref() != id.to_hex() {
                    counters.errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                batch = batch.put(
                    &id,
                    header.entity_type,
                    TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    header.learned_at,
                    &blob[ENTITY_HEADER_LEN..],
                );
                staged += 1;
            }
            // Deleted key — entities use tombstones, no action (production parity).
            None => {}
            // Non-binary value where an entity blob belongs: undecodable op.
            _ => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    if staged == 0 {
        return;
    }
    match batch.commit() {
        Ok(()) => {
            counters.committed_ops.fetch_add(staged, Ordering::Relaxed);
        }
        Err(_) => {
            counters.errors.fetch_add(staged, Ordering::Relaxed);
        }
    }
}

/// Registers the bench-only observers on the same three map containers
/// production subscribes to (`entities`, `edges`, `tombstones`), with the same
/// bridge-origin filter and the same "lock, then walk the map deltas" callback
/// shape as `subscribe_map_observer`.
///
/// This workload only writes the `entities` map, so only that subscription
/// ever fires; the other two are registered so per-commit subscription
/// bookkeeping matches the real row.
fn register_shadow_observer<L: BenchLock>(
    doc: &LoroDoc,
    vault: &Arc<Vault>,
    lock: &Arc<L>,
    counters: &Arc<ShadowCounters>,
) -> Vec<Subscription> {
    let mut subscriptions = Vec::with_capacity(3);
    for container in ["entities", "edges", "tombstones"] {
        let map = doc.get_map(container);
        let container_id = map.id();
        let vault = vault.clone();
        let lock = lock.clone();
        let counters = counters.clone();
        subscriptions.push(doc.subscribe(
            &container_id,
            Arc::new(move |event| {
                if event.origin == BRIDGE_ORIGIN {
                    return;
                }
                let _guard = lock.lock();
                for container_diff in &event.events {
                    if let Some(map_delta) = container_diff.diff.as_map() {
                        shadow_materialize_entities(map_delta, &vault, &counters);
                    }
                }
            }),
        ));
    }
    subscriptions
}

// ---------------------------------------------------------------------------
// Observer wiring per implementation
// ---------------------------------------------------------------------------

/// Registers one implementation's observers on a worker-owned document.
///
/// Registration happens INSIDE the worker thread so no `Subscription` ever
/// crosses a thread boundary; the returned handles are held for the worker's
/// whole lifetime (dropping a `Subscription` unsubscribes).
trait ObserverFactory: Send + Sync + 'static {
    fn register(&self, doc: &LoroDoc, vault: &Arc<Vault>, window_key: &str) -> Vec<Subscription>;
}

/// The REAL production path: `Materializer` + `register_observer_b`.
struct RealObserverFactory {
    materializer: Arc<Materializer>,
}

impl ObserverFactory for RealObserverFactory {
    fn register(&self, doc: &LoroDoc, vault: &Arc<Vault>, window_key: &str) -> Vec<Subscription> {
        let (entities, edges, tombstones) =
            register_observer_b(doc, vault, &self.materializer, window_key);
        vec![entities, edges, tombstones]
    }
}

/// The bench-only adapter, generic over the primitive under test.
struct ShadowObserverFactory<L: BenchLock> {
    lock: Arc<L>,
    counters: Arc<ShadowCounters>,
}

impl<L: BenchLock> ObserverFactory for ShadowObserverFactory<L> {
    fn register(&self, doc: &LoroDoc, vault: &Arc<Vault>, _window_key: &str) -> Vec<Subscription> {
        // The shadow adapter is window-agnostic: it has no quarantine family
        // to key, which is one of the asymmetries the calibration row prices.
        register_shadow_observer(doc, vault, &self.lock, &self.counters)
    }
}

/// The three measured rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Implementation {
    RealStd,
    ShadowStd,
    ShadowParkingLot,
}

impl Implementation {
    fn label(self) -> &'static str {
        match self {
            Self::RealStd => IMPL_REAL_STD,
            Self::ShadowStd => StdBenchLock::label(),
            Self::ShadowParkingLot => ParkingLotBenchLock::label(),
        }
    }

    /// Builds a FRESH factory (fresh materializer / fresh lock) for one case.
    fn runtime(self) -> ImplementationRuntime {
        match self {
            Self::RealStd => ImplementationRuntime {
                factory: Arc::new(RealObserverFactory {
                    materializer: Arc::new(Materializer::new()),
                }),
                counters: None,
            },
            Self::ShadowStd => shadow_runtime::<StdBenchLock>(),
            Self::ShadowParkingLot => shadow_runtime::<ParkingLotBenchLock>(),
        }
    }
}

struct ImplementationRuntime {
    factory: Arc<dyn ObserverFactory>,
    counters: Option<Arc<ShadowCounters>>,
}

fn shadow_runtime<L: BenchLock>() -> ImplementationRuntime {
    let counters = Arc::new(ShadowCounters::default());
    ImplementationRuntime {
        factory: Arc::new(ShadowObserverFactory {
            lock: Arc::new(L::new()),
            counters: counters.clone(),
        }),
        counters: Some(counters),
    }
}

// ---------------------------------------------------------------------------
// Worker fleet
// ---------------------------------------------------------------------------

/// Shared driver/worker rendezvous state.
struct FleetControl {
    /// Driver + all workers meet here to open a phase.
    phase_start: Barrier,
    /// Driver + all workers meet here to close a phase.
    phase_end: Barrier,
    /// Workers only: every measured burst starts through this barrier.
    burst_gate: Barrier,
    rounds: AtomicU64,
    record: AtomicBool,
    stop: AtomicBool,
    /// Per-burst latencies in nanoseconds, pooled across workers.
    samples: Mutex<Vec<u64>>,
}

impl FleetControl {
    fn new(workers: usize) -> Self {
        Self {
            phase_start: Barrier::new(workers + 1),
            phase_end: Barrier::new(workers + 1),
            burst_gate: Barrier::new(workers.max(1)),
            rounds: AtomicU64::new(0),
            record: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            samples: Mutex::new(Vec::new()),
        }
    }
}

/// A running set of workers bound to one temporary vault.
struct Fleet {
    control: Arc<FleetControl>,
    handles: Vec<JoinHandle<()>>,
    vault: Arc<Vault>,
    /// Held so the vault directory outlives the fleet.
    _dir: TempDir,
}

impl Fleet {
    /// Opens the temp vault and spawns `case.workers` workers, each owning its
    /// own `LoroDoc` and window while sharing the vault and the one lock.
    fn start(case: &MaterializerCase, factory: &Arc<dyn ObserverFactory>) -> Self {
        let dir = tempfile::tempdir().expect("bench temp vault directory");
        let vault = Arc::new(
            Vault::open(dir.path(), VaultConfig::device()).expect("bench temp vault opens"),
        );
        let control = Arc::new(FleetControl::new(case.workers));
        let mut handles = Vec::with_capacity(case.workers);
        for worker in 0..case.workers {
            let control = control.clone();
            let vault = vault.clone();
            let factory = factory.clone();
            let case = *case;
            let handle = std::thread::Builder::new()
                .name(format!("one331-w{worker}"))
                .spawn(move || worker_main(worker, &case, &control, &vault, factory.as_ref()))
                .expect("bench worker thread spawns");
            handles.push(handle);
        }
        Self {
            control,
            handles,
            vault,
            _dir: dir,
        }
    }

    /// Runs one phase of `rounds` barrier-synchronized bursts per worker and
    /// returns the wall time the whole fleet needed.
    fn run_phase(&self, rounds: u64, record: bool) -> Duration {
        self.control.rounds.store(rounds, Ordering::SeqCst);
        self.control.record.store(record, Ordering::SeqCst);
        self.control.phase_start.wait();
        let started = Instant::now();
        self.control.phase_end.wait();
        started.elapsed()
    }

    /// Drains the pooled per-burst latencies recorded so far.
    fn take_samples(&self) -> Vec<u64> {
        let mut guard = self
            .control
            .samples
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }

    /// Counts how many of the deterministic ids actually landed in LMDB.
    ///
    /// This is the anti-"unrealistic microbenchmark" check: a row that
    /// measured an empty callback would report zero here.
    fn count_materialized_rows(&self, case: &MaterializerCase) -> usize {
        let mut found = 0usize;
        for worker in 0..case.workers {
            for slot in 0..KEY_SLOTS {
                for update in 0..case.updates_per_burst {
                    let id = bench_entity_id(worker, slot, update);
                    if matches!(self.vault.get_raw(&id), Ok(Some(_))) {
                        found += 1;
                    }
                }
            }
        }
        found
    }

    /// Stops every worker and joins it. Idempotent.
    fn shutdown(&mut self) {
        if self.handles.is_empty() {
            return;
        }
        self.control.stop.store(true, Ordering::SeqCst);
        self.control.phase_start.wait();
        for handle in std::mem::take(&mut self.handles) {
            if handle.join().is_err() && !std::thread::panicking() {
                panic!("bench worker thread panicked");
            }
        }
    }
}

impl Drop for Fleet {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// One worker: owns a document + window, then serves phases until stopped.
fn worker_main(
    worker: usize,
    case: &MaterializerCase,
    control: &FleetControl,
    vault: &Arc<Vault>,
    factory: &dyn ObserverFactory,
) {
    let doc = LoroDoc::new();
    let window_key = format!("one331-w{worker}");
    let _subscriptions = factory.register(&doc, vault, &window_key);
    let entities = doc.get_map("entities");
    let mut round: u64 = 0;
    loop {
        control.phase_start.wait();
        if control.stop.load(Ordering::SeqCst) {
            break;
        }
        let rounds = control.rounds.load(Ordering::SeqCst);
        let record = control.record.load(Ordering::SeqCst);
        let mut local = Vec::new();
        if record {
            local.reserve(usize::try_from(rounds).unwrap_or(0));
        }
        for _ in 0..rounds {
            control.burst_gate.wait();
            let started = Instant::now();
            run_burst(&doc, &entities, worker, round, case);
            let elapsed = started.elapsed();
            round += 1;
            if record {
                local.push(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
            }
        }
        if record && !local.is_empty() {
            control
                .samples
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(local);
        }
        control.phase_end.wait();
    }
}

/// One burst: `updates_per_burst` valid entity-map updates, then ONE commit.
///
/// The commit is where the observer fires and the lock is taken, so the timed
/// region covers exactly the CRDT work plus the serialized materialization.
fn run_burst(
    doc: &LoroDoc,
    entities: &LoroMap,
    worker: usize,
    round: u64,
    case: &MaterializerCase,
) {
    let slot = usize::try_from(round % (KEY_SLOTS as u64)).unwrap_or(0);
    let learned_at = BASE_LEARNED_AT + round;
    let occurred = TimeRange {
        start: learned_at,
        end: learned_at,
    };
    // One blob per burst: every update in a burst carries the same valid
    // envelope under a distinct entity key, so encoding stays out of the
    // timed inner loop and every row pays exactly the same cost.
    let blob = encode_entity_blob(ENTITY_TYPE_PERSON, occurred, learned_at, ENTITY_BODY);
    for update in 0..case.updates_per_burst {
        let id = bench_entity_id(worker, slot, update);
        entities
            .insert(&id.to_hex(), blob.as_slice())
            .expect("bench entity map insert succeeds");
    }
    doc.commit();
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// Everything one measured contention point produced.
struct CaseOutcome {
    report: MaterializerBenchReport,
    diagnostics: MaterializerRowDiagnostics,
}

/// Runs one (implementation, workers) point: warm up, record the deterministic
/// measured phase, then hand the live fleet to `sample` for Criterion.
///
/// Criterion sampling runs AFTER the recorded phase so the blueprint's exact
/// 100-warmup / 1,000-measured shape is what the JSON report carries.
fn run_measured_case(
    case: &MaterializerCase,
    implementation: Implementation,
    sample: &mut dyn FnMut(&Fleet),
) -> CaseOutcome {
    let ImplementationRuntime { factory, counters } = implementation.runtime();
    let mut fleet = Fleet::start(case, &factory);
    fleet.run_phase(u64::try_from(case.warmup_bursts).unwrap_or(0), false);
    let elapsed = fleet.run_phase(u64::try_from(case.measured_bursts).unwrap_or(0), true);
    let samples = fleet.take_samples();
    sample(&fleet);
    fleet.shutdown();
    let materialized_rows = fleet.count_materialized_rows(case);
    let (shadow_committed_ops, shadow_errors) = match &counters {
        Some(counters) => counters.snapshot(),
        None => (0, 0),
    };
    CaseOutcome {
        report: summarize(implementation.label(), case, &samples, elapsed),
        diagnostics: MaterializerRowDiagnostics {
            implementation: implementation.label(),
            workers: case.workers,
            materialized_rows,
            shadow_committed_ops,
            shadow_errors,
            measured_samples: samples.len(),
        },
    }
}

fn summarize(
    implementation: &'static str,
    case: &MaterializerCase,
    samples: &[u64],
    elapsed: Duration,
) -> MaterializerBenchReport {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let seconds = elapsed.as_secs_f64();
    let commits_per_second = if seconds > 0.0 {
        sorted.len() as f64 / seconds
    } else {
        0.0
    };
    MaterializerBenchReport {
        implementation,
        workers: case.workers,
        commits_per_second,
        p50_us: percentile_us(&sorted, 0.50),
        p99_us: percentile_us(&sorted, 0.99),
    }
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

// ---------------------------------------------------------------------------
// Configuration helpers
// ---------------------------------------------------------------------------

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
const MAX_WORKLOAD_DIMENSION: usize = u16::MAX as usize + 1;

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
fn parse_dimension(name: &str, raw: &str) -> Result<usize, String> {
    let Ok(value) = raw.parse::<usize>() else {
        return Err(dimension_error(name, &format!("{raw:?}"), "is not a whole number"));
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
        return Err(dimension_error(ENV_WORKERS, &format!("{raw:?}"), "lists no worker count"));
    }
    Ok(parsed)
}

/// The per-burst shape every case in one run shares.
#[derive(Debug, Clone, Copy)]
struct WorkloadDimensions {
    updates_per_burst: usize,
    warmup_bursts: usize,
    measured_bursts: usize,
}

/// The contention points to run plus the dimensions each of them uses.
struct WorkloadPlan {
    worker_matrix: Vec<usize>,
    dimensions: WorkloadDimensions,
}

/// Resolves every environment override ONCE, before any vault, worker thread
/// or barrier exists, so an unusable dimension fails the process instead of
/// stranding a fleet mid-phase.
///
/// Only the two dimensions that feed the `bench_entity_id` u16 id space carry
/// the `1..=MAX_WORKLOAD_DIMENSION` bound. Burst COUNTS (`ENV_WARMUP`,
/// `ENV_MEASURED`) only make a run longer, never unencodable, so they keep the
/// lenient parsing they already had.
fn resolve_workload_plan() -> Result<WorkloadPlan, String> {
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
fn write_report(run: &MaterializerBenchRun) -> Result<(), String> {
    let path = report_path();
    if let Some(parent) = path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return Err(format!("could not create report directory: {error}"));
    }
    let bytes = serde_json::to_vec_pretty(run)
        .map_err(|error| format!("could not serialize report: {error}"))?;
    std::fs::write(&path, bytes)
        .map_err(|error| format!("could not write report: {error}"))?;
    let written = path.display();
    eprintln!("one-331: materializer mutex report written to {written}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Criterion driver
// ---------------------------------------------------------------------------

fn run_matrix(criterion: &mut Criterion, plan: &WorkloadPlan) -> MaterializerBenchRun {
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
                    b.iter_custom(|iters| fleet.run_phase(iters, false));
                });
            };
            let outcome = run_measured_case(&case, implementation, &mut sample);
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
    MaterializerBenchRun {
        ticket: "ONE-331",
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        updates_per_burst: shape.updates_per_burst,
        warmup_bursts: shape.warmup_bursts,
        measured_bursts: shape.measured_bursts,
        rows,
        diagnostics,
        calibration,
    }
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
    let run = run_matrix(&mut criterion, &plan);
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

// ---------------------------------------------------------------------------
// Load-bearing contract tests (ONE-331 done-means)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        let vault = Arc::new(
            Vault::open(dir.path(), VaultConfig::device()).expect("fixture temp vault opens"),
        );
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
            let blob =
                encode_entity_blob(ENTITY_TYPE_PERSON, occurred, BASE_LEARNED_AT, ENTITY_BODY);
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
        let outcome = run_measured_case(&case, Implementation::ShadowStd, &mut |_fleet: &Fleet| {});
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
        let real = run_measured_case(&case, Implementation::RealStd, &mut |_fleet: &Fleet| {});
        let shadow = run_measured_case(&case, Implementation::ShadowStd, &mut |_fleet: &Fleet| {});

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
}
