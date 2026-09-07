//! The real Observer B and identical shadow bodies under the two mutexes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use loro::event::MapDelta;
use loro::{ContainerTrait, LoroDoc, LoroValue, Subscription, ValueOrContainer};
use oneiron::sync::bridge::{BRIDGE_ORIGIN, Materializer, register_observer_b};
use oneiron::{EntityId, TimeRange, Vault};

use super::worker::{ENTITY_HEADER_LEN, parse_entity_header};

/// Row label for the real `register_observer_b` + `Materializer` path.
pub(super) const IMPL_REAL_STD: &str = "real_std";
/// Row label for the bench-only `std::sync::Mutex` adapter.
pub(super) const IMPL_SHADOW_STD: &str = "shadow_std";
/// Row label for the bench-only `parking_lot::Mutex` adapter.
pub(super) const IMPL_SHADOW_PARKING_LOT: &str = "shadow_parking_lot";

/// The one primitive under test.
///
/// Both implementations are wrapped identically so the ONLY difference
/// between the `shadow_std` and `shadow_parking_lot` rows is the mutex.
pub(super) trait BenchLock: Send + Sync + 'static {
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
pub(super) struct StdBenchLock {
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
pub(super) struct ParkingLotBenchLock {
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

/// Work evidence for the shadow adapters, shared by both lock flavours.
#[derive(Debug, Default)]
pub(super) struct ShadowCounters {
    pub(super) committed_ops: AtomicU64,
    pub(super) errors: AtomicU64,
}

impl ShadowCounters {
    pub(super) fn snapshot(&self) -> (u64, u64) {
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
pub(super) fn register_shadow_observer<L: BenchLock>(
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

/// Registers one implementation's observers on a worker-owned document.
///
/// Registration happens INSIDE the worker thread so no `Subscription` ever
/// crosses a thread boundary; the returned handles are held for the worker's
/// whole lifetime (dropping a `Subscription` unsubscribes).
pub(super) trait ObserverFactory: Send + Sync + 'static {
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
pub(super) enum Implementation {
    RealStd,
    ShadowStd,
    ShadowParkingLot,
}

impl Implementation {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::RealStd => IMPL_REAL_STD,
            Self::ShadowStd => StdBenchLock::label(),
            Self::ShadowParkingLot => ParkingLotBenchLock::label(),
        }
    }

    /// Builds a FRESH factory (fresh materializer / fresh lock) for one case.
    pub(super) fn runtime(self) -> ImplementationRuntime {
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

pub(super) struct ImplementationRuntime {
    pub(super) factory: Arc<dyn ObserverFactory>,
    pub(super) counters: Option<Arc<ShadowCounters>>,
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
