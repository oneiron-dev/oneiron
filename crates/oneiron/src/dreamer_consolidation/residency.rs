//! A read refused only because a TURN's tagged MESSAGE is away from this
//! replica (a window demoted back to thin, OF-534) is owed work, not a fault
//! (FIX 3861). The attempt that meets it waits, queued, for the promotion
//! that brings the row back, and runs whole then: it is never failed, parked
//! or applied for it. Every other refusal stays what it was.

use super::turn_text::residency_deferred;
use crate::dreamer_wake::DreamerAttemptExecution;
use crate::error::{Error, Result};

/// Whether `error` is that wait, [`super::turn_text`]'s exact
/// not-resident refusal, and nothing else.
pub(crate) fn waits_on_residency(error: &Error) -> bool {
    matches!(error, Error::InvalidClaimBody(reason) if residency_deferred(reason))
}

/// The deferral an attempt that met the wait takes: queued again after
/// [`super::RESIDENCY_RETRY_SECS`], settling what it already spent.
pub(super) fn residency_deferral(now_ms: u64, completed_units: u64) -> DreamerAttemptExecution {
    DreamerAttemptExecution::Deferred {
        completed_units,
        retry_at: now_ms
            .div_ceil(1_000)
            .saturating_add(super::RESIDENCY_RETRY_SECS),
    }
}

/// An error an attempt met after its model spend (FIX 6060): the wait
/// defers, settling the `completed_units` already spent, never failing the
/// attempt; every other error stays what it was.
pub(super) fn spent_or_deferred(
    error: Error,
    now_ms: u64,
    completed_units: u64,
) -> Result<DreamerAttemptExecution> {
    if waits_on_residency(&error) {
        Ok(residency_deferral(now_ms, completed_units))
    } else {
        Err(error)
    }
}
