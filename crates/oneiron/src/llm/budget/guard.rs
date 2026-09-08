//! Guard handle: admission, abort, reads, and settlement entry points.

use std::sync::{Arc, Mutex, MutexGuard};

use super::ledger::{LeaseState, llm_usage_units, release_reservations_for_lease};
use super::policy::BudgetPolicyTable;
use super::state::BudgetState;
use super::types::{
    BudgetAdmission, BudgetExhaustionPolicy, BudgetRead, BudgetSettlement,
    DEFAULT_BUDGET_RESERVE_UNITS,
};
use crate::llm::{BudgetDenied, BudgetLease, LlmRequest, LlmUsage, ModelLocality};
use crate::write_envelope::WriteActor;

#[derive(Debug, Clone)]
pub struct BudgetGuard {
    pub(super) state: Arc<Mutex<BudgetState>>,
}

impl BudgetGuard {
    #[must_use]
    pub fn new(
        attempt_id: impl Into<String>,
        limit_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
    ) -> Self {
        Self::with_reserve_units(
            attempt_id,
            limit_units,
            DEFAULT_BUDGET_RESERVE_UNITS,
            on_budget_exhausted,
        )
    }

    #[must_use]
    pub fn with_reserve_units(
        attempt_id: impl Into<String>,
        limit_units: u64,
        reserve_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(BudgetState::new(
                attempt_id.into(),
                limit_units,
                reserve_units,
                on_budget_exhausted,
                None,
                BudgetPolicyTable::default(),
            ))),
        }
    }

    /// The policy-aware primitive: the same single meter, plus the resolved
    /// [`BudgetPolicyTable`] and the engine-stamped actor this guard is bound
    /// to. The actor comes from durable write provenance at construction and
    /// is never read from request JSON, so one policy-aware guard belongs to
    /// one actor and must not be reused for another's calls.
    ///
    /// The table must already have passed `resolve_policy_manifest`: this
    /// constructor performs no fallible row validation.
    #[must_use]
    pub(crate) fn with_policy_table(
        attempt_id: impl Into<String>,
        limit_units: u64,
        reserve_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
        actor: WriteActor,
        policy: &BudgetPolicyTable,
    ) -> Self {
        debug_assert!(
            policy.rows().len() <= usize::from(u16::MAX) + 1,
            "resolved budget policy rows must stay addressable by a u16 row index"
        );
        let state = BudgetState::new(
            attempt_id.into(),
            limit_units,
            reserve_units,
            on_budget_exhausted,
            Some(actor.entity_ref()),
            policy.clone(),
        );
        debug_assert_eq!(state.row_tallies.len(), state.policy.rows().len());
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn admit(&self) -> Result<BudgetAdmission, BudgetDenied> {
        let mut state = self.lock_state();
        let reserve_units = state.reserve_units;
        let lease = state.reserve(reserve_units)?;
        Ok(state.metered_admission(lease))
    }

    pub fn admit_for_request(&self, request: &LlmRequest) -> Result<BudgetAdmission, BudgetDenied> {
        let mut state = self.lock_state();
        let purpose = &request.envelope.purpose;
        let reserve_units = state.reserve_units;
        let continue_local = matches!(request.envelope.locality, ModelLocality::OnDevice)
            && matches!(
                state.on_budget_exhausted,
                BudgetExhaustionPolicy::ContinueOnLocal
            )
            && state.local_continuation_available(reserve_units, Some(purpose));
        if continue_local {
            let lease = state.issue_lease(0, false, "local");
            let read = state.read();
            return Ok(BudgetAdmission {
                lease,
                read,
                ladder_events: Vec::new(),
            });
        }

        let lease = state.reserve_for(reserve_units, Some(purpose))?;
        Ok(state.metered_admission(lease))
    }

    pub fn admit_local(&self) -> Result<BudgetAdmission, BudgetDenied> {
        let mut state = self.lock_state();
        let reserve_units = state.reserve_units;
        if !matches!(
            state.on_budget_exhausted,
            BudgetExhaustionPolicy::ContinueOnLocal
        ) || !state.local_continuation_available(reserve_units, None)
        {
            return Err(BudgetDenied::AdmissionDenied);
        }

        let lease = state.issue_lease(0, false, "local");
        let read = state.read();
        Ok(BudgetAdmission {
            lease,
            read,
            ladder_events: Vec::new(),
        })
    }

    pub fn admit_reserve(&self, reserve_units: u64) -> Result<BudgetAdmission, BudgetDenied> {
        let mut state = self.lock_state();
        let lease = state.reserve(reserve_units)?;
        Ok(state.metered_admission(lease))
    }

    pub fn settle_terminal(
        &self,
        lease: &BudgetLease,
        usage: &LlmUsage,
    ) -> Result<BudgetSettlement, BudgetDenied> {
        self.settle_absolute(lease, llm_usage_units(usage))
    }

    /// Settles one call's usage exactly once, adding it to this meter's total.
    /// Unlike `settle_terminal` / `settle_absolute`, `usage` is not a cumulative
    /// counter. Lease validation, reservation release, and all global/row/floor/
    /// shared charges happen under the same mutex. Unmetered local leases stay
    /// uncharged; already-settled leases are no-ops even across settlement APIs.
    pub fn settle_per_call(
        &self,
        lease: &BudgetLease,
        usage: &LlmUsage,
    ) -> Result<BudgetSettlement, BudgetDenied> {
        self.settle_usage(lease, llm_usage_units(usage))
    }

    pub fn abort(&self, lease: &BudgetLease) -> Result<BudgetSettlement, BudgetDenied> {
        let mut state = self.lock_state();
        state.check_lease_provenance(lease)?;
        let mut aborted = None;
        {
            let Some(record) = state.leases.get_mut(lease.id()) else {
                return Err(BudgetDenied::LeaseInvalid);
            };
            match record.state {
                LeaseState::Open => {
                    record.state = LeaseState::Aborted;
                    aborted = Some(record.clone());
                }
                LeaseState::Aborted => {}
                LeaseState::Settled { .. } => return Err(BudgetDenied::LeaseInvalid),
            }
        }
        if let Some(record) = aborted {
            release_reservations_for_lease(&mut state, &record);
        }
        let ladder_events = state.fire_ladder_events();
        let read = state.read();
        Ok(BudgetSettlement {
            read,
            ladder_events,
        })
    }

    #[must_use]
    pub fn read(&self) -> BudgetRead {
        self.lock_state().read()
    }

    #[must_use]
    pub fn self_budget(&self) -> BudgetRead {
        self.read()
    }

    pub(super) fn lock_state(&self) -> MutexGuard<'_, BudgetState> {
        self.state.lock().expect("budget guard mutex poisoned")
    }
}
