//! Bound admissions and the one-use dispatch check: a lease that records what
//! it was granted for, and is started once, where bytes leave.

use serde::{Deserialize, Serialize};

use super::guard::BudgetGuard;
use super::ledger::LeaseState;
use super::types::{BudgetAdmission, BudgetRead};
use crate::llm::{BudgetDenied, BudgetLease, LlmUsage, ModelLocality};

/// What one bound admission grants its lease for. The guard records it and
/// compares it at dispatch; it holds no rule about which subjects or routes a
/// caller may name. That policy belongs to whoever admits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchBinding {
    /// The model id, or the paid connector, the call is for.
    pub subject: String,
    /// The host's name for where the call goes: the adapter and its origin.
    pub route: String,
    /// Where that route runs, as the host attests it. Never the request's own
    /// label.
    pub locality: ModelLocality,
}

/// Why [`BudgetGuard::begin_dispatch`] refused to start a lease. Every
/// refusal comes before any byte leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum DispatchRefused {
    /// Another guard issued the lease, whatever its textual id.
    #[error("lease was issued by another meter")]
    ForeignLease,
    /// The lease is settled or aborted.
    #[error("lease is closed")]
    Closed,
    /// The lease was admitted without a binding, so it names no call.
    #[error("lease is not bound to a call")]
    Unbound,
    /// The lease already started a call; a lease is good for one call only.
    #[error("lease already dispatched")]
    AlreadyDispatched,
    /// The call names another model or connector than the lease was granted for.
    #[error("call names another subject than its lease")]
    SubjectMismatch,
    /// The call goes out on another route than the lease was granted for.
    #[error("call takes another route than its lease")]
    RouteMismatch,
}

impl From<DispatchRefused> for BudgetDenied {
    fn from(_: DispatchRefused) -> Self {
        Self::LeaseInvalid
    }
}

impl BudgetGuard {
    /// An unmetered lease for a call the host attests runs on-device: a real
    /// local call spends nothing on this meter.
    pub fn admit_unmetered(
        &self,
        binding: DispatchBinding,
    ) -> Result<BudgetAdmission, BudgetDenied> {
        if binding.locality != ModelLocality::OnDevice {
            return Err(BudgetDenied::AdmissionDenied);
        }
        let mut state = self.lock_state();
        let lease = state.issue_lease(0, false, "local", Some(binding));
        let read = state.read();
        Ok(BudgetAdmission {
            lease,
            read,
            ladder_events: Vec::new(),
        })
    }

    /// Reserves `reserve_units` for one paid call that is not a model call
    /// (a search, a GPU job), bound like a model admission.
    pub fn admit_reserve_bound(
        &self,
        reserve_units: u64,
        binding: DispatchBinding,
    ) -> Result<BudgetAdmission, BudgetDenied> {
        let mut state = self.lock_state();
        let lease = state.reserve_bound(reserve_units, None, Some(binding))?;
        Ok(state.metered_admission(lease))
    }

    /// Starts the one call a bound lease was granted for, before any byte
    /// leaves. It checks the issuer, that the lease is open and not yet
    /// started, and that the call names the bound subject and route; then
    /// marks the lease started in the same critical section. From then on an
    /// abort charges the reservation.
    pub fn begin_dispatch(
        &self,
        lease: &BudgetLease,
        subject: &str,
        route: &str,
    ) -> Result<(), DispatchRefused> {
        let mut state = self.lock_state();
        state
            .check_lease_provenance(lease)
            .map_err(|_| DispatchRefused::ForeignLease)?;
        let record = state
            .leases
            .get_mut(lease.id())
            .ok_or(DispatchRefused::ForeignLease)?;
        if record.state != LeaseState::Open {
            return Err(DispatchRefused::Closed);
        }
        let binding = record.binding.as_ref().ok_or(DispatchRefused::Unbound)?;
        if record.dispatched {
            return Err(DispatchRefused::AlreadyDispatched);
        }
        if binding.subject != subject {
            return Err(DispatchRefused::SubjectMismatch);
        }
        if binding.route != route {
            return Err(DispatchRefused::RouteMismatch);
        }
        record.dispatched = true;
        Ok(())
    }

    /// Whether [`Self::begin_dispatch`] started this lease; `None` for a
    /// lease another meter issued or this one never did.
    #[must_use]
    pub fn dispatched(&self, lease: &BudgetLease) -> Option<bool> {
        let state = self.lock_state();
        state.check_lease_provenance(lease).ok()?;
        state.leases.get(lease.id()).map(|record| record.dispatched)
    }

    /// Moves this meter's limit and per-call reservation: an owner's or a
    /// host's revision of the line. Spend, open reservations and fired
    /// thresholds stay; a lower limit only refuses later admissions.
    pub fn revise_line(&self, limit_units: u64, reserve_units: u64) -> BudgetRead {
        let mut state = self.lock_state();
        state.revise_line(limit_units, reserve_units);
        state.read()
    }

    /// Units this lease reserved at admission; `None` for a lease another
    /// meter issued or this one never did.
    #[must_use]
    pub fn reserved_for(&self, lease: &BudgetLease) -> Option<u64> {
        let state = self.lock_state();
        state.check_lease_provenance(lease).ok()?;
        state
            .leases
            .get(lease.id())
            .map(|record| record.reserve_units)
    }
}

/// Key in [`LlmUsage::raw_provider`] counting the provider calls a fallback
/// chain made and lost before the one that answered: its failed rungs.
pub const FAILED_RUNGS_KEY: &str = "failed_rungs";

/// One answered call's charge: its tokens, or `floor` when it reports none,
/// plus `floor` for each rung that failed before it. A reply that reports no
/// usage is charged a bounded estimate, never zero, and a rung that failed
/// before a later one answered is still charged.
#[must_use]
pub fn answered_units(usage: &LlmUsage, floor: u64) -> u64 {
    u64::try_from(answered_units_wide(usage, floor)).unwrap_or(u64::MAX)
}

/// [`answered_units`] before it is narrowed to `u64`, for a caller that
/// converts the amount into another unit before it meters it.
#[must_use]
pub fn answered_units_wide(usage: &LlmUsage, floor: u64) -> u128 {
    let tokens = u128::from(usage.input.total) + u128::from(usage.output.total);
    let floor = u128::from(floor);
    let answer = if tokens == 0 { floor } else { tokens };
    answer + u128::from(failed_rungs(usage)) * floor
}

/// How many rungs a fallback chain tried and lost before the one that
/// answered, as its receipt counts them under [`FAILED_RUNGS_KEY`].
fn failed_rungs(usage: &LlmUsage) -> u64 {
    usage
        .raw_provider
        .get(FAILED_RUNGS_KEY)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}
