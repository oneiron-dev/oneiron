use super::{
    BudgetDenied, BudgetGuard, BudgetLease, BudgetSettlement, LeaseState, apply_usage_for_lease,
    release_reservations_for_lease,
};

impl BudgetGuard {
    pub fn settle_absolute(
        &self,
        lease: &BudgetLease,
        absolute_used_units: u64,
    ) -> Result<BudgetSettlement, BudgetDenied> {
        let mut state = self.lock_state();
        state.check_lease_provenance(lease)?;
        let mut settled = None;
        {
            let Some(record) = state.leases.get_mut(lease.id()) else {
                return Err(BudgetDenied::LeaseInvalid);
            };
            match record.state {
                LeaseState::Open => {
                    record.state = LeaseState::Settled {
                        absolute_used_units,
                    };
                    settled = Some(record.clone());
                }
                LeaseState::Settled { .. } => {}
                LeaseState::Aborted => return Err(BudgetDenied::LeaseInvalid),
            }
        }
        if let Some(record) = settled {
            release_reservations_for_lease(&mut state, &record);
            if record.metered {
                state.used_units = state.used_units.max(absolute_used_units);
                apply_usage_for_lease(&mut state, &record, absolute_used_units);
            }
        }
        let ladder_events = state.fire_ladder_events();
        let read = state.read();
        Ok(BudgetSettlement {
            read,
            ladder_events,
        })
    }

    /// Settles one lease's actual spend, adding it to this meter exactly once.
    /// Use this for per-request usage, not an absolute meter reading.
    pub fn settle_usage(
        &self,
        lease: &BudgetLease,
        call_used_units: u64,
    ) -> Result<BudgetSettlement, BudgetDenied> {
        let mut state = self.lock_state();
        state.check_lease_provenance(lease)?;
        let absolute_used_units = state.used_units.saturating_add(call_used_units);
        let mut settled = None;
        {
            let Some(record) = state.leases.get_mut(lease.id()) else {
                return Err(BudgetDenied::LeaseInvalid);
            };
            match record.state {
                LeaseState::Open => {
                    record.state = LeaseState::Settled {
                        absolute_used_units,
                    };
                    settled = Some(record.clone());
                }
                LeaseState::Settled { .. } => {}
                LeaseState::Aborted => return Err(BudgetDenied::LeaseInvalid),
            }
        }
        if let Some(record) = settled {
            release_reservations_for_lease(&mut state, &record);
            if record.metered {
                state.used_units = absolute_used_units;
                apply_usage_for_lease(&mut state, &record, call_used_units);
            }
        }
        let ladder_events = state.fire_ladder_events();
        let read = state.read();
        Ok(BudgetSettlement {
            read,
            ladder_events,
        })
    }
}
