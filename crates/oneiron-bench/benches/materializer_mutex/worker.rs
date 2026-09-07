//! Worker phases, entity encoding, and complete materialization evidence.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use loro::{LoroDoc, LoroMap};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::sync::quarantine::sync_doctor;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use tempfile::TempDir;

use super::configuration::MaterializerCase;
use super::observers::{ObserverFactory, ShadowCounters};

/// Entity metadata header: type byte + BE occurred start/end + BE learned_at.
/// Mirrors `crate::batch::ENTITY_METADATA_HEADER_LEN`, which is `pub(crate)`
/// and therefore not nameable from a bench crate.
pub(super) const ENTITY_HEADER_LEN: usize = 25;

/// Number of distinct entity-key slots each worker rotates through. Bursts
/// re-write the same bounded key space with a strictly increasing
/// `learned_at`, which keeps the vault small while guaranteeing every burst
/// produces a real CRDT delta (an identical re-insert emits no event).
pub(super) const KEY_SLOTS: usize = 8;

/// Fixed epoch for `learned_at` / `occurred` stamps (2026-01-01T00:00:00Z).
pub(super) const BASE_LEARNED_AT: u64 = 1_767_225_600;

/// Entity body every burst writes. Plain ASCII: no secret-scan trigger, no
/// typed-body decode requirement (PERSON bodies are opaque to the engine).
pub(super) const ENTITY_BODY: &[u8] = b"one-331 materializer mutex bench body";

/// Decoded entity metadata header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BenchEntityHeader {
    pub(super) entity_type: u8,
    pub(super) occurred_start: u64,
    pub(super) occurred_end: u64,
    pub(super) learned_at: u64,
}

pub(super) fn parse_entity_header(raw: &[u8]) -> Option<BenchEntityHeader> {
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

pub(super) fn encode_entity_blob(
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
pub(super) fn bench_entity_id(worker: usize, slot: usize, update: usize) -> EntityId {
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

/// Validate reads explicitly: a storage error is not an absent row, and an
/// existing but stale row is not evidence that the latest callback succeeded.
/// The reader parameter lets contracts exercise each failure without an LMDB
/// fault injector. Short runs cover only the slots they have actually visited.
pub(super) fn validate_workload_rows(
    case: &MaterializerCase,
    completed_rounds: u64,
    mut get_raw: impl FnMut(&EntityId) -> oneiron::Result<Option<Vec<u8>>>,
) -> Result<usize, String> {
    let slots = completed_rounds.min(KEY_SLOTS as u64) as usize;
    let mut found = 0;
    for slot in 0..slots {
        let last_round = completed_rounds - 1;
        let round = last_round - (last_round - slot as u64) % KEY_SLOTS as u64;
        let learned_at = BASE_LEARNED_AT
            .checked_add(round)
            .ok_or_else(|| "workload round timestamp overflow".to_owned())?;
        let occurred = TimeRange {
            start: learned_at,
            end: learned_at,
        };
        let expected = encode_entity_blob(ENTITY_TYPE_PERSON, occurred, learned_at, ENTITY_BODY);
        for worker in 0..case.workers {
            for update in 0..case.updates_per_burst {
                let id = bench_entity_id(worker, slot, update);
                let key = id.to_hex();
                let raw = get_raw(&id)
                    .map_err(|error| format!("could not read materialized entity {key}: {error}"))?
                    .ok_or_else(|| format!("missing materialized entity {key}"))?;
                if raw != expected {
                    return Err(format!(
                        "materialized entity {key} does not match round {round}"
                    ));
                }
                found += 1;
            }
        }
    }
    Ok(found)
}

/// Reject failed or skipped shadow operations, including failures whose slots
/// were subsequently overwritten. Both phases and both mutexes use this gate.
pub(super) fn validate_shadow_counts(
    case: &MaterializerCase,
    completed_rounds: u64,
    (committed_ops, errors): (u64, u64),
) -> Result<(), String> {
    if errors != 0 {
        return Err(format!("shadow materialization reported {errors} errors"));
    }
    let expected = u128::from(completed_rounds)
        .checked_mul(case.workers as u128)
        .and_then(|ops| ops.checked_mul(case.updates_per_burst as u128))
        .ok_or_else(|| "shadow operation count overflow".to_owned())?;
    if u128::from(committed_ops) != expected {
        return Err(format!(
            "shadow committed {committed_ops} operations; expected {expected}"
        ));
    }
    Ok(())
}

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
pub(super) struct Fleet {
    control: Arc<FleetControl>,
    handles: Vec<JoinHandle<()>>,
    vault: Arc<Vault>,
    case: MaterializerCase,
    completed_rounds: Cell<u64>,
    counters: Option<Arc<ShadowCounters>>,
    /// Held so the vault directory outlives the fleet.
    _dir: TempDir,
}

impl Fleet {
    /// Opens the temp vault and spawns `case.workers` workers, each owning its
    /// own `LoroDoc` and window while sharing the vault and the one lock.
    pub(super) fn start(
        case: &MaterializerCase,
        factory: &Arc<dyn ObserverFactory>,
        counters: Option<Arc<ShadowCounters>>,
    ) -> Self {
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
            case: *case,
            completed_rounds: Cell::new(0),
            counters,
            _dir: dir,
        }
    }

    /// Runs one phase of barrier-synchronized bursts and returns its wall time.
    /// Validation runs after the timer stops, before any later phase can hide a
    /// missing write by reusing its slot. Invalid phases return no usable time.
    pub(super) fn run_phase(&self, rounds: u64, record: bool) -> Result<Duration, String> {
        let completed = self
            .completed_rounds
            .get()
            .checked_add(rounds)
            .filter(|total| {
                BASE_LEARNED_AT
                    .checked_add(total.saturating_sub(1))
                    .is_some()
            })
            .ok_or_else(|| "workload round timestamp overflow".to_owned())?;
        self.control.rounds.store(rounds, Ordering::SeqCst);
        self.control.record.store(record, Ordering::SeqCst);
        // Capture BEFORE release: every worker commit belongs to this interval,
        // even if the driver is descheduled as the start barrier opens.
        let started = Instant::now();
        self.control.phase_start.wait();
        self.control.phase_end.wait();
        let elapsed = started.elapsed();
        self.completed_rounds.set(completed);
        self.validate_materialization()?;
        Ok(elapsed)
    }

    /// Drains the pooled per-burst latencies recorded so far.
    pub(super) fn take_samples(&self) -> Vec<u64> {
        let mut guard = self
            .control
            .samples
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }

    /// Requires the entire visited id space at its latest expected version.
    /// Counts alone would accept warmup rows after failed measured callbacks.
    pub(super) fn validate_materialization(&self) -> Result<usize, String> {
        let rows = validate_workload_rows(&self.case, self.completed_rounds.get(), |id| {
            self.vault.get_raw(id)
        })?;
        if let Some(counters) = &self.counters {
            validate_shadow_counts(&self.case, self.completed_rounds.get(), counters.snapshot())?;
        }
        // Observer B has no callback Result. Its durable rejection/retry
        // evidence must also be empty, even if a later burst repaired a row.
        let evidence = sync_doctor(&self.vault)
            .map_err(|error| format!("could not read Observer B failure evidence: {error}"))?;
        if evidence.quarantine_count != 0
            || evidence.eviction_count != 0
            || evidence.batch_drop_count != 0
            || !evidence.rm_pending_windows.is_empty()
        {
            return Err(format!(
                "Observer B materialization failure evidence: {evidence:?}"
            ));
        }
        Ok(rows)
    }

    /// Stops every worker and joins it. Idempotent.
    pub(super) fn shutdown(&mut self) {
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
