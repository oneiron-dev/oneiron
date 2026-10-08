//! Lease and tally bookkeeping: reservations, charging, and metering math.

use std::collections::BTreeSet;

use super::policy::BudgetPolicyRow;
use super::state::BudgetState;
use super::types::BudgetThreshold;
use crate::llm::LlmUsage;

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
    pub(super) row_index: u16,
    pub(super) units: u64,
}

/// The floor/shared split one admission would take, computed before any
/// mutation and then committed verbatim.
#[derive(Debug, Clone, Default)]
pub(super) struct ReserveAllocation {
    pub(super) matched_rows: Vec<u16>,
    pub(super) floor_allocations: Vec<FloorAllocation>,
    pub(super) shared_units: u64,
}

/// Outcome of the pure pre-mutation projection for one reserve request.
#[derive(Debug)]
pub(super) enum ReservePlan {
    Admit(ReserveAllocation),
    /// A matched row cap refuses the call. Deliberate policy, never capacity:
    /// this denial is final and never yields a local-continuation lease.
    DeniedByCap,
    /// Global, shared-slice, or floor-headroom capacity refuses the call.
    DeniedByCapacity,
}

#[derive(Debug, Clone)]
pub(super) struct LeaseRecord {
    pub(super) reserve_units: u64,
    pub(super) metered: bool,
    pub(super) state: LeaseState,
    /// Resolved policy rows this lease's call matched; empty on the
    /// single-pool branch and on unmetered local leases.
    pub(super) matched_rows: Vec<u16>,
    pub(super) floor_allocations: Vec<FloorAllocation>,
    pub(super) shared_reserved_units: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LeaseState {
    Open,
    Settled { absolute_used_units: u64 },
    Aborted,
}

/// Releases every reservation one lease holds, in the one critical section:
/// the global reserve, the full-charge reserve on every matched row, every
/// floor allocation, and the shared-slice share. Settlement calls this before
/// applying usage; abort calls it alone and records no spend.
pub(super) fn release_reservations_for_lease(state: &mut BudgetState, record: &LeaseRecord) {
    state.reserved_units = state.reserved_units.saturating_sub(record.reserve_units);
    for &row_index in &record.matched_rows {
        if let Some(tally) = state.row_tallies.get_mut(usize::from(row_index)) {
            tally.reserved_units = tally.reserved_units.saturating_sub(record.reserve_units);
        }
    }
    for floor in &record.floor_allocations {
        if let Some(tally) = state.row_tallies.get_mut(usize::from(floor.row_index)) {
            tally.floor_reserved_units = tally.floor_reserved_units.saturating_sub(floor.units);
        }
    }
    state.shared_reserved_units = state
        .shared_reserved_units
        .saturating_sub(record.shared_reserved_units);
}

/// Adds one metered lease's supplied usage to every matched row and partition.
///
/// Rows meter per-lease matched spend, so they may sum above the global
/// watermark when producers report per-response absolutes: rows are the
/// cap/ladder authority for matched traffic while the global meter stays the
/// total authority. The per-lease amount partitions floor-first — matched
/// floor headroom in resolved manifest order — and any remainder lands in
/// the shared partition, so overshoot beyond the slice is recorded as shared
/// spend and later admissions saturate-deny rather than any admitted call
/// being killed.
pub(super) fn apply_usage_for_lease(
    state: &mut BudgetState,
    record: &LeaseRecord,
    used_units: u64,
) {
    for &row_index in &record.matched_rows {
        if let Some(tally) = state.row_tallies.get_mut(usize::from(row_index)) {
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
        if let Some(tally) = state.row_tallies.get_mut(usize::from(row_index)) {
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
