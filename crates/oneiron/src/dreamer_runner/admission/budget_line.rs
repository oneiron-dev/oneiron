//! The original line established by a successful native admission.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use oneiron_model::llm::{
    BudgetAccountingSnapshot, BudgetGuard, BudgetLease, BudgetLeaseState, BudgetMeterRange,
};

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::error::{Error, Result};

/// Accounting provenance, not an execution grant or a paid receipt.
#[derive(Debug, Clone)]
pub(crate) struct AdmittedBudgetLine {
    attempt_id: AttemptId,
    generation: u32,
    budget_id: String,
    next_invocation: Arc<AtomicU64>,
    native_leases: Arc<Mutex<Vec<NativeCallLease>>>,
}

/// One invocation of the original admission, and one of its corrective calls.
/// Transport retries keep the same coordinate. It certifies no payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdmittedCallId {
    pub(crate) attempt_id: AttemptId,
    pub(crate) generation: u32,
    pub(crate) invocation: u64,
    pub(crate) ordinal: u32,
}

#[derive(Debug, Clone)]
struct NativeCallLease {
    origin: AdmittedCallId,
    lease: BudgetLease,
}

/// Selected native tokens and their producer's meter, read together.
/// This is aggregate-inclusion evidence, not a native NET payment.
#[derive(Debug, Clone)]
pub(crate) struct NativeMeterSnapshot {
    original_line: AdmittedBudgetLine,
    start_used_units: u64,
    accounting: BudgetAccountingSnapshot,
    calls: Vec<NativeCallLease>,
}

impl NativeMeterSnapshot {
    pub(crate) fn matches_settlement(&self, line: &str, attempt: AttemptId) -> bool {
        self.original_line.for_attempt(attempt) == Some(line)
    }

    pub(crate) fn interval(&self) -> BudgetMeterRange {
        BudgetMeterRange {
            start_used_units: self.start_used_units,
            end_used_units: self.accounting.read.used_units,
        }
    }

    /// Each retained call and its token-derived state and first-settlement range
    /// from this snapshot. Missing observations remain unknown; empty ranges
    /// and calls outside the interval are retained, not classified as excluded.
    pub(crate) fn observed_calls(
        &self,
    ) -> impl Iterator<
        Item = (
            AdmittedCallId,
            &str,
            Option<BudgetLeaseState>,
            Option<BudgetMeterRange>,
        ),
    > {
        self.calls
            .iter()
            .zip(&self.accounting.leases)
            .zip(&self.accounting.meter_ranges)
            .map(|((call, state), range)| (call.origin, call.lease.id(), *state, *range))
    }

    pub(crate) fn included_calls(
        &self,
    ) -> impl Iterator<Item = (AdmittedCallId, &str, BudgetMeterRange)> {
        self.calls
            .iter()
            .zip(&self.accounting.meter_ranges)
            .filter_map(|(call, range)| {
                let range = (*range)?;
                (range.start_used_units >= self.start_used_units
                    && range.end_used_units >= range.start_used_units
                    && range.end_used_units <= self.accounting.read.used_units)
                    .then_some((call.origin, call.lease.id(), range))
            })
    }
}

impl PartialEq for AdmittedBudgetLine {
    fn eq(&self, other: &Self) -> bool {
        self.attempt_id == other.attempt_id
            && self.generation == other.generation
            && self.budget_id == other.budget_id
    }
}

impl Eq for AdmittedBudgetLine {}

impl AdmittedBudgetLine {
    pub(super) fn new(attempt_id: AttemptId, generation: u32, budget_id: String) -> Self {
        Self {
            attempt_id,
            generation,
            budget_id,
            next_invocation: Arc::new(AtomicU64::new(0)),
            native_leases: Arc::default(),
        }
    }

    pub(crate) fn for_attempt(&self, attempt_id: AttemptId) -> Option<&str> {
        (self.attempt_id == attempt_id).then_some(self.budget_id.as_str())
    }

    /// Retain the actual opaque token once, without allocating another call id.
    pub(crate) fn retain_native_lease(&self, origin: AdmittedCallId, lease: &BudgetLease) {
        if origin.attempt_id != self.attempt_id || origin.generation != self.generation {
            return;
        }
        let mut calls = self
            .native_leases
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !calls.iter().any(|call| call.lease == *lease) {
            calls.push(NativeCallLease {
                origin,
                lease: lease.clone(),
            });
        }
    }

    pub(crate) fn meter_snapshot(
        &self,
        guard: &BudgetGuard,
        start_used_units: u64,
    ) -> NativeMeterSnapshot {
        let calls = self
            .native_leases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        // Release the original-line registry before taking the guard's lock.
        let leases: Vec<_> = calls.iter().map(|call| &call.lease).collect();
        let accounting = guard.accounting_snapshot(&leases);
        NativeMeterSnapshot {
            original_line: self.clone(),
            start_used_units,
            accounting,
            calls,
        }
    }

    pub(crate) fn next_call(&self, attempt_id: AttemptId) -> Result<Option<AdmittedCallId>> {
        if self.attempt_id != attempt_id {
            return Ok(None);
        }
        let invocation = self
            .next_invocation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| Error::ArithmeticOverflow("dreamer admitted invocation sequence"))?;
        Ok(Some(AdmittedCallId {
            attempt_id: self.attempt_id,
            generation: self.generation,
            invocation,
            ordinal: 0,
        }))
    }
}

impl DreamerAdmittedAttempt {
    pub(crate) fn admitted_budget_line(&self) -> &AdmittedBudgetLine {
        &self.admitted_budget_line
    }
}
