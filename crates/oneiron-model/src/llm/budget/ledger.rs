//! Lease and tally bookkeeping: reservations, charging, and metering math.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use super::dispatch::DispatchBinding;
use super::policy::BudgetPolicyRow;
use super::state::BudgetState;
use super::types::{BudgetLeaseState, BudgetThreshold};
use crate::llm::LlmUsage;
use crate::llm::backend::PhysicalAttempts;

/// Per-row bookkeeping inside the one meter. `used_units`/`reserved_units`
/// carry the full charge of every call matching the row — those are the cap
/// and ladder tallies. The `floor_*` pair is the allocation partition: how
/// much of that spend the row's own floor protects.
#[derive(Debug, Clone, Default)]
pub(super) struct BudgetRowTally {
    pub(super) used_units: u64,
    pub(super) reserved_units: u64,
    pub(super) floor_used_units: u64,
    pub(super) floor_reserved_units: u64,
    pub(super) fired_thresholds: BTreeSet<BudgetThreshold>,
}

/// How much of one lease is protected by one matched row's floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FloorAllocation {
    pub(super) row_index: usize,
    pub(super) units: u64,
}

/// The floor/shared split one admission would take, computed before any
/// mutation and then committed verbatim.
#[derive(Debug, Clone, Default)]
pub(super) struct ReserveAllocation {
    pub(super) matched_rows: Vec<usize>,
    pub(super) floor_allocations: Vec<FloorAllocation>,
    pub(super) shared_units: u64,
}

/// Outcome of the pure pre-mutation projection for one reserve request.
#[derive(Debug)]
pub(super) enum ReservePlan {
    Admit(ReserveAllocation),
    /// A matched row cap refuses the call. Deliberate policy, never capacity.
    /// Free local work never reaches it: its lease is unmetered.
    DeniedByCap,
    /// Global, shared-slice, or floor-headroom capacity refuses the call.
    DeniedByCapacity,
}

/// One open lease, as the meter's table holds it until the lease settles or
/// aborts. The record then leaves the table, and what the lease's handles
/// still read stays in their shared [`ClosedLeaseCell`].
#[derive(Debug, Clone)]
pub(super) struct LeaseRecord {
    pub(super) reserve_units: u64,
    pub(super) metered: bool,
    /// Resolved policy rows this lease's call matched; empty on the
    /// single-pool branch and on unmetered local leases.
    pub(super) matched_rows: Vec<usize>,
    pub(super) floor_allocations: Vec<FloorAllocation>,
    pub(super) shared_reserved_units: u64,
    /// What a bound admission granted this lease for; `None` on the plain
    /// admissions, which never dispatch through [`super::BudgetGuard::begin_dispatch`].
    pub(super) binding: Option<DispatchBinding>,
    /// Set once by `begin_dispatch`: bytes may have left under this lease, so
    /// it can no longer be released untouched.
    pub(super) dispatched: bool,
    /// The physical attempts the lease's transports began, the same counter
    /// every handle of the lease shares. Once it is above zero, bytes left,
    /// and the lease can never be marked unsent (FIX BUDGET-LEASE).
    pub(super) physical_attempts: PhysicalAttempts,
    /// The cell every handle of this lease shares, filled as the lease closes.
    pub(super) closed: ClosedLeaseCell,
}

impl LeaseRecord {
    /// Closes this lease as `outcome`, which its caller took out of the
    /// meter's table: what the lease's handles still read moves into their
    /// cell. The caller releases and charges the record in the same critical
    /// section.
    pub(super) fn close(&self, outcome: LeaseOutcome) {
        let closed = ClosedLease {
            outcome,
            reserve_units: self.reserve_units,
            dispatched: self.dispatched,
            request_digest: self
                .binding
                .as_ref()
                .and_then(|binding| binding.request_digest.clone()),
        };
        // Each issuance has its own cell and one record, which leaves the
        // table as it closes, so the cell is still empty here.
        let filled = self.closed.0.set(closed).is_ok();
        debug_assert!(filled, "a lease closes once");
    }
}

/// How a lease closed. A lease the meter's table still holds is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LeaseOutcome {
    Settled { charged_units: u64 },
    Aborted,
}

/// What a lease keeps once it settled or aborted: the facts its handles still
/// read (FIX BUDGET-LINE-LEASE-TABLE-UNBOUNDED). Its matched rows and
/// reservation split were released and charged at the close, and nothing keeps
/// them.
#[derive(Debug)]
pub(super) struct ClosedLease {
    pub(super) outcome: LeaseOutcome,
    /// What the lease reserved at admission; the close released all of it.
    pub(super) reserve_units: u64,
    pub(super) dispatched: bool,
    pub(super) request_digest: Option<String>,
}

/// The closed state of one lease, shared by every clone of its handle and by
/// the open record its meter holds until the close. The meter's table keeps
/// only open leases, so a closed lease answers through its handle, and the
/// cell goes when the last handle drops.
#[derive(Debug, Clone, Default)]
pub(crate) struct ClosedLeaseCell(Arc<OnceLock<ClosedLease>>);

impl ClosedLeaseCell {
    pub(super) fn get(&self) -> Option<&ClosedLease> {
        self.0.get()
    }

    pub(super) fn outcome(&self) -> Option<LeaseOutcome> {
        self.get().map(|closed| closed.outcome)
    }
}

/// One lease as its issuing meter answers for it: its open record, or what
/// its handles keep once it closed.
#[derive(Clone, Copy)]
pub(super) enum LeaseEntry<'a> {
    Open(&'a LeaseRecord),
    Closed(&'a ClosedLease),
}

impl<'a> LeaseEntry<'a> {
    pub(super) fn is_open(self) -> bool {
        matches!(self, Self::Open(_))
    }

    pub(super) fn reserve_units(self) -> u64 {
        match self {
            Self::Open(record) => record.reserve_units,
            Self::Closed(closed) => closed.reserve_units,
        }
    }

    pub(super) fn dispatched(self) -> bool {
        match self {
            Self::Open(record) => record.dispatched,
            Self::Closed(closed) => closed.dispatched,
        }
    }

    pub(super) fn request_digest(self) -> Option<&'a str> {
        match self {
            Self::Open(record) => record.binding.as_ref()?.request_digest.as_deref(),
            Self::Closed(closed) => closed.request_digest.as_deref(),
        }
    }

    pub(super) fn observation(self) -> BudgetLeaseState {
        match self {
            Self::Open(record) => BudgetLeaseState::Open {
                reserve_units: record.reserve_units,
                dispatched: record.dispatched,
            },
            Self::Closed(closed) => match closed.outcome {
                LeaseOutcome::Settled { charged_units } => BudgetLeaseState::Settled {
                    used_units: charged_units,
                },
                LeaseOutcome::Aborted => BudgetLeaseState::Aborted,
            },
        }
    }
}

/// Releases every reservation one lease holds, in the one critical section:
/// the global reserve, the full-charge reserve on every matched row, every
/// floor allocation, and the shared-slice share. Settlement calls this before
/// applying usage; abort calls it alone and records no spend.
pub(super) fn release_reservations_for_lease(state: &mut BudgetState, record: &LeaseRecord) {
    state.reserved_units = state.reserved_units.saturating_sub(record.reserve_units);
    for &row_index in &record.matched_rows {
        if let Some(tally) = state.row_tallies.get_mut(row_index) {
            tally.reserved_units = tally.reserved_units.saturating_sub(record.reserve_units);
        }
    }
    for floor in &record.floor_allocations {
        if let Some(tally) = state.row_tallies.get_mut(floor.row_index) {
            tally.floor_reserved_units = tally.floor_reserved_units.saturating_sub(floor.units);
        }
    }
    state.shared_reserved_units = state
        .shared_reserved_units
        .saturating_sub(record.shared_reserved_units);
}

/// Adds one metered lease's new spend to every matched row and partition.
///
/// `used_units` is what the global meter gained from this settlement: a
/// call's own usage, or a cumulative reading's rise over the watermark
/// (FIX 8624), never the full reading. Each matched row takes the whole of
/// it, since rows are the cap/ladder authority for matched traffic (caps are
/// conjunctive), so rows sum above the global total only when one call
/// matches several. The amount partitions once, floor-first — matched floor
/// headroom in resolved manifest order — and any remainder lands in the
/// shared partition, so overshoot beyond the slice is recorded as shared
/// spend and later admissions saturate-deny rather than any admitted call
/// being killed.
pub(super) fn apply_usage_for_lease(
    state: &mut BudgetState,
    record: &LeaseRecord,
    used_units: u64,
) {
    for &row_index in &record.matched_rows {
        if let Some(tally) = state.row_tallies.get_mut(row_index) {
            tally.used_units = tally.used_units.saturating_add(used_units);
        }
    }
    let mut remaining = used_units;
    for &row_index in &record.matched_rows {
        if remaining == 0 {
            break;
        }
        let Some(floor_units) = state
            .policy_row(row_index)
            .and_then(BudgetPolicyRow::floor_units)
        else {
            continue;
        };
        let committed = state.row_tally(row_index).map_or(0, |tally| {
            tally
                .floor_used_units
                .saturating_add(tally.floor_reserved_units)
        });
        let units = remaining.min(floor_units.saturating_sub(committed));
        if units == 0 {
            continue;
        }
        if let Some(tally) = state.row_tallies.get_mut(row_index) {
            tally.floor_used_units = tally.floor_used_units.saturating_add(units);
        }
        remaining = remaining.saturating_sub(units);
    }
    state.shared_used_units = state.shared_used_units.saturating_add(remaining);
}

pub(super) fn llm_usage_units(usage: &LlmUsage) -> u64 {
    usage.input.total.saturating_add(usage.output.total)
}

pub(super) fn percent_used(used_units: u64, limit_units: u64) -> u64 {
    if limit_units == 0 {
        return 100;
    }
    let numerator = u128::from(used_units).saturating_mul(100);
    (numerator / u128::from(limit_units)).min(100) as u64
}
