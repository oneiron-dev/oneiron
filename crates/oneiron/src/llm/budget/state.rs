//! Budget meter core: reserve planning and admission.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use super::ledger::{
    BudgetRowTally, FloorAllocation, LeaseRecord, LeaseState, ReserveAllocation, ReservePlan,
};
use super::policy::{BudgetPolicyRow, BudgetPolicyTable};
use super::types::{BudgetAdmission, BudgetExhaustionPolicy, BudgetRead, BudgetThreshold};
use crate::entity_id::EntityId;
use crate::llm::{BudgetDenied, BudgetLease, CallPurpose};

#[derive(Debug)]
pub(super) struct BudgetState {
    pub(super) guard_identity: Arc<()>,
    pub(super) attempt_id: String,
    pub(super) limit_units: u64,
    pub(super) reserve_units: u64,
    pub(super) on_budget_exhausted: BudgetExhaustionPolicy,
    pub(super) used_units: u64,
    pub(super) reserved_units: u64,
    pub(super) next_lease_seq: u64,
    pub(super) fired_thresholds: BTreeSet<BudgetThreshold>,
    pub(super) leases: BTreeMap<String, LeaseRecord>,
    /// Engine-stamped actor this meter is bound to, for actor selectors.
    pub(super) actor: Option<EntityId>,
    pub(super) policy: BudgetPolicyTable,
    pub(super) row_tallies: Vec<BudgetRowTally>,
    pub(super) total_floor_units: u64,
    pub(super) row_horizons: Vec<u64>,
    pub(super) shared_used_units: u64,
    pub(super) shared_reserved_units: u64,
}

impl BudgetState {
    pub(super) fn new(
        attempt_id: String,
        limit_units: u64,
        reserve_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
        actor: Option<EntityId>,
        policy: BudgetPolicyTable,
    ) -> Self {
        let row_tallies = vec![BudgetRowTally::default(); policy.rows().len()];
        let total_floor_units = policy
            .rows()
            .iter()
            .filter_map(BudgetPolicyRow::floor_units)
            .fold(0, u64::saturating_add);
        let mut selector_floor_units = HashMap::new();
        for row in policy.rows() {
            let Some(floor_units) = row.floor_units() else {
                continue;
            };
            selector_floor_units
                .entry(row.selector().clone())
                .and_modify(|sum: &mut u64| *sum = sum.saturating_add(floor_units))
                .or_insert(floor_units);
        }
        let row_horizons = policy
            .rows()
            .iter()
            .map(|row| {
                let leaseable_floor_units = selector_floor_units
                    .get(row.selector())
                    .copied()
                    .unwrap_or(0);
                let inaccessible_floor_units =
                    total_floor_units.saturating_sub(leaseable_floor_units);
                row.cap_units()
                    .unwrap_or(u64::MAX)
                    .min(limit_units.saturating_sub(inaccessible_floor_units))
            })
            .collect();
        Self {
            guard_identity: Arc::new(()),
            attempt_id,
            limit_units,
            reserve_units,
            on_budget_exhausted,
            used_units: 0,
            reserved_units: 0,
            next_lease_seq: 0,
            fired_thresholds: BTreeSet::new(),
            leases: BTreeMap::new(),
            actor,
            policy,
            row_tallies,
            total_floor_units,
            row_horizons,
            shared_used_units: 0,
            shared_reserved_units: 0,
        }
    }

    pub(super) fn check_lease_provenance(&self, lease: &BudgetLease) -> Result<(), BudgetDenied> {
        if Arc::ptr_eq(&self.guard_identity, &lease.guard_identity) {
            Ok(())
        } else {
            Err(BudgetDenied::LeaseInvalid)
        }
    }

    pub(super) fn reserve(&mut self, reserve_units: u64) -> Result<BudgetLease, BudgetDenied> {
        self.reserve_for(reserve_units, None)
    }

    /// `purpose` is `None` for the generic admissions: it suppresses
    /// purpose-row matching only, the construction-bound actor still binds.
    pub(super) fn reserve_for(
        &mut self,
        reserve_units: u64,
        purpose: Option<&CallPurpose>,
    ) -> Result<BudgetLease, BudgetDenied> {
        if reserve_units == 0 {
            return Err(BudgetDenied::AdmissionDenied);
        }

        let allocation = match self.plan_reserve(reserve_units, purpose) {
            ReservePlan::Admit(allocation) => allocation,
            ReservePlan::DeniedByCap | ReservePlan::DeniedByCapacity => {
                return Err(BudgetDenied::Exhausted);
            }
        };

        self.commit_reservation(reserve_units, &allocation);
        Ok(self.issue_lease_with(reserve_units, true, "metered", allocation))
    }

    /// Projects one admission without mutating any global, shared, row, floor,
    /// threshold, or lease state.
    pub(super) fn plan_reserve(
        &self,
        reserve_units: u64,
        purpose: Option<&CallPurpose>,
    ) -> ReservePlan {
        if self.policy.is_empty() {
            // Empty/absent table: the single-pool branch, taken before any row
            // allocation, so lease ids, denials, reads, and ladders stay
            // byte-identical to the plain meter.
            return self.plan_single_pool(reserve_units);
        }

        let matched_rows = self.matched_rows(purpose);
        if self.matched_cap_denies(&matched_rows, reserve_units) {
            return ReservePlan::DeniedByCap;
        }

        let (floor_allocations, shared_units) = self.allocate_floors(&matched_rows, reserve_units);
        let shared_projected = self.shared_committed().saturating_add(shared_units);
        if shared_units > 0 && shared_projected > self.shared_admission_ceiling() {
            return ReservePlan::DeniedByCapacity;
        }
        if self.global_denies(reserve_units) {
            // Floors partition the base total; they never create budget.
            return ReservePlan::DeniedByCapacity;
        }

        ReservePlan::Admit(ReserveAllocation {
            matched_rows,
            floor_allocations,
            shared_units,
        })
    }

    pub(super) fn plan_single_pool(&self, reserve_units: u64) -> ReservePlan {
        if self.global_denies(reserve_units) {
            return ReservePlan::DeniedByCapacity;
        }
        ReservePlan::Admit(ReserveAllocation::default())
    }

    pub(super) fn global_denies(&self, reserve_units: u64) -> bool {
        self.global_committed().saturating_add(reserve_units) > self.cap_units()
    }

    /// Row indices whose selector matches this call, in resolved order.
    pub(super) fn matched_rows(&self, purpose: Option<&CallPurpose>) -> Vec<u16> {
        self.policy
            .rows()
            .iter()
            .enumerate()
            .filter(|(_, row)| row.selector().matches(purpose, self.actor))
            .filter_map(|(index, _)| u16::try_from(index).ok())
            .collect()
    }

    /// Caps are conjunctive: a matching call must fit every matched cap.
    pub(super) fn matched_cap_denies(&self, matched_rows: &[u16], reserve_units: u64) -> bool {
        matched_rows.iter().any(|&row_index| {
            let Some(cap_units) = self
                .policy_row(row_index)
                .and_then(BudgetPolicyRow::cap_units)
            else {
                return false;
            };
            let Some(tally) = self.row_tally(row_index) else {
                return false;
            };
            tally
                .used_units
                .saturating_add(tally.reserved_units)
                .saturating_add(reserve_units)
                > cap_units
        })
    }

    /// Draws matched floor headroom in resolved manifest order, then hands the
    /// remainder to the shared slice. An unmatched floor is never touched.
    pub(super) fn allocate_floors(
        &self,
        matched_rows: &[u16],
        reserve_units: u64,
    ) -> (Vec<FloorAllocation>, u64) {
        let mut allocations = Vec::new();
        let mut remaining = reserve_units;
        for &row_index in matched_rows {
            if remaining == 0 {
                break;
            }
            let Some(floor_units) = self
                .policy_row(row_index)
                .and_then(BudgetPolicyRow::floor_units)
            else {
                continue;
            };
            let Some(tally) = self.row_tally(row_index) else {
                continue;
            };
            let committed = tally
                .floor_used_units
                .saturating_add(tally.floor_reserved_units);
            let units = remaining.min(floor_units.saturating_sub(committed));
            if units == 0 {
                continue;
            }
            allocations.push(FloorAllocation { row_index, units });
            remaining -= units;
        }
        (allocations, remaining)
    }

    pub(super) fn commit_reservation(
        &mut self,
        reserve_units: u64,
        allocation: &ReserveAllocation,
    ) {
        self.reserved_units = self.reserved_units.saturating_add(reserve_units);
        for &row_index in &allocation.matched_rows {
            if let Some(tally) = self.row_tallies.get_mut(usize::from(row_index)) {
                tally.reserved_units = tally.reserved_units.saturating_add(reserve_units);
            }
        }
        for floor in &allocation.floor_allocations {
            if let Some(tally) = self.row_tallies.get_mut(usize::from(floor.row_index)) {
                tally.floor_reserved_units = tally.floor_reserved_units.saturating_add(floor.units);
            }
        }
        self.shared_reserved_units = self
            .shared_reserved_units
            .saturating_add(allocation.shared_units);
    }

    /// Global exhaustion, or a policy capacity block (shared slice or floor
    /// headroom) the metered branch would deny. A matched cap denial is
    /// deliberate policy, so it never reaches here.
    pub(super) fn local_continuation_available(
        &self,
        reserve_units: u64,
        purpose: Option<&CallPurpose>,
    ) -> bool {
        if self.policy.is_empty() {
            return self.is_exhausted();
        }
        match self.plan_reserve(reserve_units, purpose) {
            ReservePlan::DeniedByCap => false,
            ReservePlan::DeniedByCapacity => true,
            ReservePlan::Admit(_) => self.is_exhausted(),
        }
    }

    /// `T - sum(all floors)`, saturating: oversubscribed floors leave no
    /// shared slice at all rather than wrapping.
    pub(super) fn shared_slice_units(&self) -> u64 {
        self.limit_units.saturating_sub(self.total_floor_units)
    }

    pub(super) fn shared_admission_ceiling(&self) -> u64 {
        let overdraft = self.cap_units().saturating_sub(self.limit_units);
        self.shared_slice_units().saturating_add(overdraft)
    }

    pub(super) fn shared_committed(&self) -> u64 {
        self.shared_used_units
            .saturating_add(self.shared_reserved_units)
    }

    pub(super) fn global_committed(&self) -> u64 {
        self.used_units.saturating_add(self.reserved_units)
    }

    pub(super) fn policy_row(&self, row_index: u16) -> Option<&BudgetPolicyRow> {
        self.policy.rows().get(usize::from(row_index))
    }

    pub(super) fn row_tally(&self, row_index: u16) -> Option<&BudgetRowTally> {
        self.row_tallies.get(usize::from(row_index))
    }

    pub(super) fn metered_admission(&mut self, lease: BudgetLease) -> BudgetAdmission {
        let ladder_events = self.fire_ladder_events();
        let read = self.read();
        BudgetAdmission {
            lease,
            read,
            ladder_events,
        }
    }

    pub(super) fn cap_units(&self) -> u64 {
        self.on_budget_exhausted.admission_cap(self.limit_units)
    }

    pub(super) fn is_exhausted(&self) -> bool {
        self.used_units.saturating_add(self.reserved_units) >= self.cap_units()
    }

    pub(super) fn issue_lease(
        &mut self,
        reserve_units: u64,
        metered: bool,
        kind: &str,
    ) -> BudgetLease {
        self.issue_lease_with(reserve_units, metered, kind, ReserveAllocation::default())
    }

    /// The lease id stays `<attempt>:<kind>:<seq>`: row indices, actor refs,
    /// and selector names never enter the public token.
    pub(super) fn issue_lease_with(
        &mut self,
        reserve_units: u64,
        metered: bool,
        kind: &str,
        allocation: ReserveAllocation,
    ) -> BudgetLease {
        self.next_lease_seq = self.next_lease_seq.saturating_add(1);
        let lease_id = format!("{}:{kind}:{}", self.attempt_id, self.next_lease_seq);
        let lease = BudgetLease::issued(lease_id.clone(), Arc::clone(&self.guard_identity));
        self.leases.insert(
            lease_id,
            LeaseRecord {
                reserve_units,
                metered,
                state: LeaseState::Open,
                matched_rows: allocation.matched_rows,
                floor_allocations: allocation.floor_allocations,
                shared_reserved_units: allocation.shared_units,
            },
        );
        lease
    }

    pub(super) fn read(&self) -> BudgetRead {
        let cap_units = self.cap_units();
        let committed = self.used_units.saturating_add(self.reserved_units);
        BudgetRead {
            attempt_id: self.attempt_id.clone(),
            limit_units: self.limit_units,
            cap_units,
            used_units: self.used_units,
            reserved_units: self.reserved_units,
            remaining_units: cap_units.saturating_sub(committed),
            on_budget_exhausted: self.on_budget_exhausted,
            fired_thresholds: self.fired_thresholds.iter().copied().collect(),
        }
    }
}
