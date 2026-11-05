//! Provider token reports on the exact leases this meter started. These are
//! observations, not the mixed units that admission and settlement charge.

use serde::{Deserialize, Serialize};

use super::guard::BudgetGuard;
use super::ledger::LeaseState;
use super::state::BudgetState;
use crate::llm::{BudgetDenied, BudgetLease, ProviderTokenMeasurement};
use oneiron_contracts::entity_id::EntityId;

/// A snapshot of this guard's started calls, not a final spend-scope total.
/// A component is absent if any call is unsettled, did not report that
/// component, or the sum overflowed. No started calls is also unknown, not
/// a provider-reported zero. Other guards and later calls are not covered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderTokenObservation {
    pub dispatched_calls: usize,
    pub unsettled_calls: usize,
    pub input: Option<u64>,
    pub output: Option<u64>,
}

/// One guard generation's current provider reports. Clones of the guard
/// keep the same generation; a fresh guard, including a restarted one,
/// has a new generation even when its attempt and lease strings repeat.
/// The generation is opaque observation data, not an entity reference,
/// authority or proof that every guard on a spend scope was covered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderTokenSnapshot {
    pub generation: [u8; 16],
    /// Capture order within this generation, not a call or charge count.
    pub observation_id: [u8; 16],
    pub observation: ProviderTokenObservation,
    /// Native receipts retained by failed leases, including partial reports.
    /// Missing requests remain uncovered; an empty list is not a known zero.
    pub failed_call_reports: Vec<ProviderTokenMeasurement>,
}

impl BudgetGuard {
    /// Reads the current reports with their immutable guard generation.
    /// The capture id orders snapshots of this same generation, including
    /// calls whose paid charge stays zero. It confers no authority and
    /// proves neither persistence nor coverage of a whole spend scope.
    #[must_use]
    pub fn provider_token_snapshot(&self) -> ProviderTokenSnapshot {
        let state = self.lock_state();
        ProviderTokenSnapshot {
            generation: state.provider_token_generation,
            observation_id: *EntityId::now().as_bytes(),
            observation: observation_in_state(&state),
            failed_call_reports: state
                .leases
                .values()
                .filter(|record| record.dispatched)
                .flat_map(|record| record.provider_failed_call_reports.iter().copied())
                .collect(),
        }
    }

    /// Records the final provider report on its actual started lease. This
    /// changes no budget charge, reservation, policy or lease state. Replacing
    /// one lease's report cannot charge or count that call a second time.
    pub fn observe_provider_tokens(
        &self,
        lease: &BudgetLease,
        measurement: Option<ProviderTokenMeasurement>,
    ) -> Result<(), BudgetDenied> {
        let mut state = self.lock_state();
        state.check_lease_provenance(lease)?;
        let record = state
            .leases
            .get_mut(lease.id())
            .ok_or(BudgetDenied::LeaseInvalid)?;
        if !record.dispatched {
            return Err(BudgetDenied::LeaseInvalid);
        }
        record.provider_tokens = measurement;
        Ok(())
    }

    /// Retains native reports on a failed started lease without treating
    /// those partial reports as its complete usage or changing any charge.
    pub fn observe_provider_failed_call_reports(
        &self,
        lease: &BudgetLease,
        reports: Vec<ProviderTokenMeasurement>,
    ) -> Result<(), BudgetDenied> {
        let mut state = self.lock_state();
        state.check_lease_provenance(lease)?;
        let record = state
            .leases
            .get_mut(lease.id())
            .ok_or(BudgetDenied::LeaseInvalid)?;
        if !record.dispatched {
            return Err(BudgetDenied::LeaseInvalid);
        }
        record.provider_failed_call_reports = reports;
        Ok(())
    }

    /// Reads provider reports independently of the charged units. Free local
    /// calls remain visible: their zero charge never supplies a token count.
    /// Missing reports (failed, cancelled or unsupported calls included)
    /// stay unknown. This read does not finalize a run or persist a scope.
    #[must_use]
    pub fn provider_token_observation(&self) -> ProviderTokenObservation {
        let state = self.lock_state();
        observation_in_state(&state)
    }
}

fn observation_in_state(state: &BudgetState) -> ProviderTokenObservation {
    let mut result = ProviderTokenObservation {
        input: Some(0),
        output: Some(0),
        ..ProviderTokenObservation::default()
    };
    for record in state.leases.values().filter(|record| record.dispatched) {
        result.dispatched_calls += 1;
        if record.state == LeaseState::Open {
            result.unsettled_calls += 1;
            result.input = None;
            result.output = None;
            continue;
        }
        result.input = result
            .input
            .and_then(|sum| sum.checked_add(record.provider_tokens?.input?));
        result.output = result
            .output
            .and_then(|sum| sum.checked_add(record.provider_tokens?.output?));
    }
    if result.dispatched_calls == 0 {
        result.input = None;
        result.output = None;
    }
    result
}
