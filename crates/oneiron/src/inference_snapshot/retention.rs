//! Each vault's sealed-snapshot budget (DESIGN-V2 §7 quotas, V2-R3): the
//! bytes its sealed bodies hold on disk, the bytes reserved for bodies about
//! to be written and those being staged, against the owner's per-vault disk
//! budget; and which snapshot goes first when a new one would not fit.
//!
//! Retention is housekeeping, never a refusal: a snapshot that would cross
//! the budget evicts others in [`choose_victim`]'s order, or is not parked,
//! and its turn recomputes from source. One larger than the whole budget is
//! never kept. A size nobody measured is never free: it reserves nothing and
//! is not kept. A snapshot an active lease holds is pinned until its
//! release is acknowledged, and never chosen.
//!
//! Host memory, device memory and transfer buffers are charged on their own
//! lines, by the device and host owners that already account for them, with
//! at least [`SNAPSHOT_HEADROOM_BYTES`] left free: this ledger is the disk
//! line alone.
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::catalog::{self, SnapshotClass, SnapshotId};
use crate::Vault;
use crate::error::Result;

/// The memory a snapshot's host or device copy, transfer or restore leaves
/// free at least, on its device and in host memory: a charge that would cut
/// into it evicts, skips the park, or recomputes. 2 GiB.
pub const SNAPSHOT_HEADROOM_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The owner's sealed-snapshot policy for one vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotBudget {
    /// Whether sealed parking is on: off keeps nothing, and purges what is
    /// kept.
    pub enabled: bool,
    /// The sealed bytes this vault may hold on disk; zero keeps none.
    pub disk_bytes: u64,
}

impl SnapshotBudget {
    /// The bytes this budget lets the vault keep: none when it is off.
    #[must_use]
    pub fn limit(&self) -> u64 {
        if self.enabled { self.disk_bytes } else { 0 }
    }
}

/// One eviction candidate: a catalog row, or a host copy, as the facts
/// [`choose_victim`] orders by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotCandidate {
    pub id: SnapshotId,
    pub bytes: u64,
    /// Whether it may serve a restore at all: one that may not (expired,
    /// revoked, missing a required field) goes first.
    pub reusable: bool,
    pub class: SnapshotClass,
    pub reuse_count: u64,
    pub last_used_ms: u64,
    /// An active lease holds it, through its release acknowledgement.
    pub pinned: bool,
}

/// The order candidates leave in (DESIGN-V2 §7): what may serve no restore
/// first, then background state before interactive, then the least reused,
/// then the oldest last use.
fn eviction_order(a: &SnapshotCandidate, b: &SnapshotCandidate) -> Ordering {
    a.reusable
        .cmp(&b.reusable)
        .then(a.class.cmp(&b.class))
        .then(a.reuse_count.cmp(&b.reuse_count))
        .then(a.last_used_ms.cmp(&b.last_used_ms))
        .then(a.id.cmp(&b.id))
}

/// The index of the candidate to evict next, `None` when every one is
/// pinned.
#[must_use]
pub fn choose_victim(candidates: &[SnapshotCandidate]) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| !candidate.pinned)
        .min_by(|(_, a), (_, b)| eviction_order(a, b))
        .map(|(index, _)| index)
}

/// A hold on disk bytes for one body about to be written. Charge it with
/// the body's sealed length once it is known; release it once the catalog
/// row counts the body, or the park is abandoned.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct SnapshotReservation {
    id: u64,
    bytes: u64,
}

impl SnapshotReservation {
    /// The bytes it holds.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// One vault's disk line as it stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SnapshotUsage {
    /// Catalog rows, and the sealed bytes those that decode name.
    pub snapshots: u64,
    pub sealed_bytes: u64,
    /// Rows that do not decode: their size is unknown, and the next
    /// enforcement retires them.
    pub unknown: u64,
    /// Reserved for bodies not yet written.
    pub reserved_bytes: u64,
    /// Charged with a body's sealed length, not yet in the catalog.
    pub staged_bytes: u64,
    /// Rows retired to stay inside the budget, and parks skipped because
    /// nothing could make room, since this vault opened.
    pub evicted: u64,
    pub skipped: u64,
}

/// The in-flight half of each vault's disk line, in memory beside its
/// catalog: reservations and staged bodies, and the eviction counters.
#[derive(Debug, Default)]
pub(crate) struct Ledger(Mutex<LedgerState>);

#[derive(Debug, Default)]
struct LedgerState {
    next: u64,
    /// Each reservation's bytes, and whether a body's length charged it.
    held: BTreeMap<u64, (u64, bool)>,
    evicted: u64,
    skipped: u64,
}

impl LedgerState {
    fn in_flight(&self) -> u64 {
        self.held
            .values()
            .fold(0_u64, |total, (bytes, _)| total.saturating_add(*bytes))
    }
}

impl Ledger {
    fn lock(&self) -> MutexGuard<'_, LedgerState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Drops every reservation: a lock ends every park in flight.
    pub(super) fn clear(&self) {
        self.lock().held.clear();
    }
}

/// One vault's sealed-snapshot disk line ([`Vault::snapshot_ledger`]).
pub struct SnapshotLedger<'a> {
    vault: &'a Vault,
}

impl Vault {
    /// This vault's sealed-snapshot disk line.
    #[must_use]
    pub fn snapshot_ledger(&self) -> SnapshotLedger<'_> {
        SnapshotLedger { vault: self }
    }
}

impl SnapshotLedger<'_> {
    fn ledger(&self) -> &Ledger {
        self.vault.store.inference_snapshots.ledger()
    }

    /// The disk line as it stands.
    ///
    /// # Errors
    /// Storage errors.
    pub fn usage(&self) -> Result<SnapshotUsage> {
        let rows = {
            let txn = self.vault.store.env.read_txn()?;
            catalog::rows(&self.vault.store, &txn)?
        };
        let state = self.ledger().lock();
        let mut usage = SnapshotUsage {
            evicted: state.evicted,
            skipped: state.skipped,
            ..SnapshotUsage::default()
        };
        for (bytes, charged) in state.held.values() {
            if *charged {
                usage.staged_bytes = usage.staged_bytes.saturating_add(*bytes);
            } else {
                usage.reserved_bytes = usage.reserved_bytes.saturating_add(*bytes);
            }
        }
        for (_, record) in &rows {
            usage.snapshots += 1;
            match record {
                Some(record) => {
                    usage.sealed_bytes = usage.sealed_bytes.saturating_add(record.sealed_bytes);
                }
                None => usage.unknown += 1,
            }
        }
        Ok(usage)
    }

    /// Reserves `bytes` of disk for one body about to be written, evicting
    /// kept snapshots outside `pinned` in [`choose_victim`]'s order until
    /// it fits. `None`, and nothing reserved, when the budget is off, the
    /// size is unknown, the body alone is larger than the budget, or
    /// nothing evictable makes room: the park is skipped, never refused.
    ///
    /// # Errors
    /// Storage errors.
    pub fn reserve(
        &self,
        budget: SnapshotBudget,
        bytes: Option<u64>,
        pinned: &[SnapshotId],
    ) -> Result<Option<SnapshotReservation>> {
        let Some(bytes) = bytes.filter(|bytes| *bytes <= budget.limit() && budget.limit() > 0)
        else {
            self.ledger().lock().skipped += 1;
            return Ok(None);
        };
        if !self.enforce_budget(budget, bytes, pinned)? {
            self.ledger().lock().skipped += 1;
            return Ok(None);
        }
        let mut state = self.ledger().lock();
        let id = state.next;
        state.next = state.next.wrapping_add(1);
        state.held.insert(id, (bytes, false));
        Ok(Some(SnapshotReservation { id, bytes }))
    }

    /// Charges `reservation` with the body's sealed length, `sealed`. A
    /// body longer than what was reserved is not kept: `false`, and the
    /// caller releases the reservation and drops the body.
    pub fn charge(&self, reservation: &mut SnapshotReservation, sealed: u64) -> bool {
        if sealed > reservation.bytes {
            return false;
        }
        let mut state = self.ledger().lock();
        match state.held.get_mut(&reservation.id) {
            Some(held) => {
                *held = (sealed, true);
                reservation.bytes = sealed;
                true
            }
            // A lock since dropped every reservation: nothing is kept.
            None => false,
        }
    }

    /// Releases `reservation`: its body is in the catalog, which counts it
    /// now, or the park was abandoned.
    pub fn release(&self, reservation: SnapshotReservation) {
        self.ledger().lock().held.remove(&reservation.id);
    }

    /// Retires kept snapshots outside `pinned`, in [`choose_victim`]'s
    /// order, until what is kept, what is in flight and `need` more bytes
    /// fit the budget; rows that do not decode go first, their size being
    /// unknown. A budget that is off purges every row not pinned. `false`
    /// when only pinned rows are left and it still does not fit.
    ///
    /// # Errors
    /// Storage errors.
    pub fn enforce_budget(
        &self,
        budget: SnapshotBudget,
        need: u64,
        pinned: &[SnapshotId],
    ) -> Result<bool> {
        let store = &self.vault.store;
        let mut wtxn = store.env.write_txn()?;
        let rows = catalog::rows(store, &wtxn)?;
        let mut kept = 0_u64;
        let mut candidates = Vec::new();
        let mut evicted = 0_u64;
        for (id, record) in rows {
            let Some(record) = record else {
                super::store::retire_in_txn(store, &mut wtxn, &id)?;
                evicted += 1;
                continue;
            };
            kept = kept.saturating_add(record.sealed_bytes);
            candidates.push(SnapshotCandidate {
                id,
                bytes: record.sealed_bytes,
                reusable: record.reusable(),
                class: record.class,
                reuse_count: record.reuse_count,
                last_used_ms: record.last_used_ms,
                pinned: pinned.contains(&id),
            });
        }
        let limit = budget.limit();
        let in_flight = self.ledger().lock().in_flight();
        let fits = |kept: u64| kept.saturating_add(in_flight).saturating_add(need) <= limit;
        while !fits(kept) {
            let Some(index) = choose_victim(&candidates) else {
                break;
            };
            let victim = candidates.swap_remove(index);
            super::store::retire_in_txn(store, &mut wtxn, &victim.id)?;
            kept = kept.saturating_sub(victim.bytes);
            evicted += 1;
        }
        wtxn.commit()?;
        if evicted > 0 {
            self.ledger().lock().evicted += evicted;
            self.vault
                .finish_inference_snapshot_retirements_after_commit();
        }
        Ok(fits(kept))
    }
}
