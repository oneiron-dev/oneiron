//! In-flight sealed-snapshot reservations and lease pins.

use crate::store::snapshot_catalog::SnapshotId;
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The in-flight half of each vault's disk line, in memory beside its
/// catalog: reservations and staged bodies, and the eviction counters.
#[derive(Debug, Default)]
pub(crate) struct Ledger(Mutex<LedgerState>);

#[derive(Debug, Default)]
pub(crate) struct LedgerState {
    pub(crate) next: u64,
    /// Each reservation's bytes, and whether a body's length charged it.
    pub(crate) held: BTreeMap<u64, (u64, bool)>,
    /// The rows a live lease holds, each with its count of holders.
    pub(crate) pins: BTreeMap<SnapshotId, u64>,
    pub(crate) evicted: u64,
    pub(crate) skipped: u64,
}

impl LedgerState {
    pub(crate) fn in_flight(&self) -> u64 {
        self.held
            .values()
            .fold(0_u64, |total, (bytes, _)| total.saturating_add(*bytes))
    }
}

impl Ledger {
    pub(crate) fn lock(&self) -> MutexGuard<'_, LedgerState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Drops every reservation: a lock ends every park in flight.
    pub(crate) fn clear(&self) {
        self.lock().held.clear();
    }
}
