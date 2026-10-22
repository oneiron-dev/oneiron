//! Settling a run's permits: an answer pays its usage or its reservation, a
//! started call that failed pays its reservation, and every settlement the
//! meter refuses goes on the receipt, with the inference receipts the call
//! reported or its lease observed (FIX 9065).
use super::super::{
    BudgetSettlement, InferenceCallObservation, InferenceCallReceipt, LlmUsage, answered_units_wide,
};
use super::admission::{RunDenied, RunInner};
use super::declaration::LeaseUnit;
use super::host::{UnitRate, Unpriced, convert};
use super::permit::RunPermit;
use super::receipt::{RunEvent, RunStreamUsage, RunTokenUsage};

/// How a permitted call ended, for its settlement.
#[derive(Debug, Clone, Copy)]
pub enum CallOutcome<'a> {
    /// The model answered with this usage.
    Answered(&'a LlmUsage),
    /// The paid service reports this many units of its service used.
    Used(u64),
    /// No answer arrived: the call failed, or its response was lost.
    Failed,
    /// The call goes on past this process: a kept job a restart takes up
    /// again, whose new permit pays its end. It is charged nothing here.
    Kept,
}

impl RunInner {
    /// Settles `permit` on this run, its issuer. Only
    /// [`RunPermit::settle_with`], [`RunPermit::settle_stream`] and the
    /// permit's drop call this, once. `stream` is a metered stream's audio,
    /// for the receipt. `provided` is the inference receipts a call reported
    /// beside its quantity (a media call's), listed after those an answer's
    /// usage holds, and then what the lease observed of requests that never
    /// reported ([`settled_inference_calls`]); none changes what the call is
    /// charged.
    pub(super) fn settle(
        &self,
        permit: &RunPermit,
        outcome: CallOutcome<'_>,
        stream: Option<RunStreamUsage>,
        provided: Vec<InferenceCallReceipt>,
    ) -> Result<BudgetSettlement, RunDenied> {
        // A settled permit never starts, so its run stops holding it.
        self.lock_paid().remove(permit.lease.id());
        let native = match outcome {
            CallOutcome::Answered(usage) => {
                let floor = u64::try_from(permit.reserve_native).unwrap_or(u64::MAX);
                Some(answered_units_wide(usage, floor))
            }
            CallOutcome::Used(quantity) => {
                Some(u128::from(quantity) * u128::from(permit.unit_cost))
            }
            CallOutcome::Failed => None,
            CallOutcome::Kept => Some(0),
        };
        let kept = matches!(outcome, CallOutcome::Kept);
        let line_unit = &permit.facts.unit;
        let line_units = native.map(|native| {
            if kept {
                return 0;
            }
            charge(
                native,
                &permit.native,
                line_unit,
                &permit.rates,
                permit.facts.reserved_units,
            )
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
                Some(_) if kept => (0, hold.meter.settle_usage(&hold.lease, 0)),
                Some(native) => {
                    let units = charge(native, &permit.native, &hold.unit, &permit.rates, reserved);
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
        let mut reported = match outcome {
            CallOutcome::Answered(usage) => usage.inference_calls(),
            _ => Vec::new(),
        };
        reported.extend(provided);
        let inference_calls =
            settled_inference_calls(reported, permit.lease.inference_observations());
        self.record(
            permit.revision,
            RunEvent::Settled {
                lease: permit.lease.id().to_owned(),
                dispatched: started,
                usage: match outcome {
                    CallOutcome::Answered(usage) => Some(RunTokenUsage {
                        input: usage.input,
                        output: usage.output,
                    }),
                    _ => None,
                },
                service_quantity: match outcome {
                    CallOutcome::Used(quantity) => Some(quantity),
                    _ => None,
                },
                stream,
                inference_calls,
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

/// The inference receipts a settled call records (FIX 9065): those it
/// reported (an answer's usage, then any provided beside it), then each
/// request its lease observed that never reached a final receipt, in the order
/// they began. A request's final receipt is the one its answer reports, so it
/// is not counted again. A call that reported none (a failed, cancelled or
/// dropped one) records everything its lease observed, final or partial. What
/// no native source measured stays absent.
fn settled_inference_calls(
    reported: Vec<InferenceCallReceipt>,
    observed: Vec<InferenceCallObservation>,
) -> Vec<InferenceCallReceipt> {
    if reported.is_empty() {
        return observed
            .into_iter()
            .map(InferenceCallObservation::into_receipt)
            .collect();
    }
    let mut calls = reported;
    calls.extend(
        observed
            .into_iter()
            .filter(|observation| !observation.is_final())
            .map(InferenceCallObservation::into_receipt),
    );
    calls
}

/// What a finished call charges a meter. Admission priced the same units
/// through the same rates, so a missing rate falls back to the reservation; a
/// call that ran past what a meter holds charges all it holds.
fn charge(
    native: u128,
    from: &LeaseUnit,
    to: &LeaseUnit,
    rates: &[UnitRate],
    reserved: u64,
) -> u64 {
    match convert(native, from, to, rates) {
        Ok(units) => units,
        Err(Unpriced::TooLarge) => u64::MAX,
        Err(Unpriced::NoRate) => reserved,
    }
}
