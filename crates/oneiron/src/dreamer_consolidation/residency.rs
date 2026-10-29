//! A read refused only because a TURN's tagged MESSAGE is away from this
//! replica (a window demoted back to thin, OF-534) is owed work, not a fault
//! (FIX 3861). The attempt that meets it waits, queued, for the promotion
//! that brings the row back, and runs whole then: it is never failed, parked
//! or applied for it. Every other refusal stays what it was.

use super::step_charge::StepChargeTally;
use super::turn_text::residency_deferred;
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::error::{Error, Result};

/// Whether `error` is that wait, [`super::turn_text`]'s exact
/// not-resident refusal, and nothing else.
pub(crate) fn waits_on_residency(error: &Error) -> bool {
    matches!(error, Error::InvalidClaimBody(reason) if residency_deferred(reason))
}

/// The deferral an attempt that met the wait takes: queued again after
/// [`super::RESIDENCY_RETRY_SECS`], settling what it already spent.
pub(super) fn residency_deferral(
    now_ms: u64,
    completed_units: u64,
    step_hashes: Vec<[u8; 32]>,
) -> DreamerAttemptExecution {
    DreamerAttemptExecution::Deferred {
        completed_units,
        retry_at: now_ms
            .div_ceil(1_000)
            .saturating_add(super::RESIDENCY_RETRY_SECS),
        step_hashes,
    }
}

/// An error an attempt met after its model spend (FIX 6060): the wait
/// defers, settling what `charges` already spent, never failing the
/// attempt. Every other error stays what it was, and what `charges` spent
/// goes with it to the driver's settlement of that error (FIX 7432).
pub(super) fn spent_or_deferred(
    error: Error,
    ctx: &WakeAttemptContext<'_>,
    charges: &StepChargeTally,
) -> Result<DreamerAttemptExecution> {
    if waits_on_residency(&error) {
        Ok(residency_deferral(
            ctx.now_ms,
            charges.units,
            charges.step_hashes.clone(),
        ))
    } else {
        ctx.note_spend_before_error(charges.units, &charges.step_hashes);
        Err(error)
    }
}
