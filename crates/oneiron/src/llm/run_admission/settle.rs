//! Settling a run's permits: an answer pays its usage or its reservation, a
//! started call that failed pays its reservation, and every settlement the
//! meter refuses goes on the receipt.
use super::super::{BudgetSettlement, LlmUsage, answered_units};
use super::admission::{RunDenied, RunInner};
use super::host::convert;
use super::permit::RunPermit;
use super::receipt::RunEvent;

/// How a permitted call ended, for its settlement.
#[derive(Debug, Clone, Copy)]
pub enum CallOutcome<'a> {
    /// The model answered with this usage.
    Answered(&'a LlmUsage),
    /// The paid service reports this many units of its service used.
    Used(u64),
    /// No answer arrived: the call failed, or its response was lost.
    Failed,
}

impl RunInner {
    /// Settles `permit` on this run, its issuer. Only [`RunPermit::settle`]
    /// and the permit's drop call this, once.
    pub(super) fn settle(
        &self,
        permit: &RunPermit,
        outcome: CallOutcome<'_>,
    ) -> Result<BudgetSettlement, RunDenied> {
        let native = match outcome {
            CallOutcome::Answered(usage) => {
                let floor = u64::try_from(permit.reserve_native).unwrap_or(u64::MAX);
                Some(u128::from(answered_units(usage, floor)))
            }
            CallOutcome::Used(quantity) => {
                Some(u128::from(quantity) * u128::from(permit.unit_cost))
            }
            CallOutcome::Failed => None,
        };
        let line_unit = &permit.facts.unit;
        let line_units = native.map(|native| {
            convert(native, &permit.native, line_unit, &permit.rates)
                .unwrap_or(permit.facts.reserved_units)
        });
        let settled = match line_units {
            Some(units) => self.guard.settle_usage(&permit.lease, units),
            // A started call's abort charges its reservation; an unstarted
            // one's releases it.
            None => self.guard.abort(&permit.lease),
        };
        // Read after the abort: a lease it closed unstarted can never start.
        let started = self.guard.dispatched(&permit.lease) == Some(true);
        let units = match line_units {
            Some(units) => units,
            None if started => permit.facts.reserved_units,
            None => 0,
        };
        let allocation = permit.allocation.as_ref().map(|hold| {
            let reserved = hold.meter.reserved_for(&hold.lease).unwrap_or(0);
            match native {
                Some(native) => {
                    let units = convert(native, &permit.native, &hold.unit, &permit.rates)
                        .unwrap_or(reserved);
                    (units, hold.meter.settle_usage(&hold.lease, units))
                }
                None if started => (reserved, hold.meter.settle_reserved(&hold.lease)),
                None => (0, hold.meter.abort(&hold.lease)),
            }
        });
        let charged = if permit.metered { units } else { 0 };
        if settled.is_ok()
            && let Some(facts) = self.lock_calls().get_mut(permit.lease.id())
        {
            facts.settled_units = Some(charged);
        }
        let allocation_error = allocation
            .as_ref()
            .and_then(|(_, settled)| settled.as_ref().err().cloned());
        self.record(
            permit.revision,
            RunEvent::Settled {
                lease: permit.lease.id().to_owned(),
                units: charged,
                unit: line_unit.clone(),
                allocation_units: allocation.as_ref().map(|(units, _)| *units),
                error: settled.as_ref().err().cloned(),
                allocation_error: allocation_error.clone(),
            },
        );
        match (settled, allocation_error) {
            (Err(denied), _) | (Ok(_), Some(denied)) => Err(RunDenied::Budget { denied }),
            (Ok(settlement), None) => Ok(settlement),
        }
    }
}
