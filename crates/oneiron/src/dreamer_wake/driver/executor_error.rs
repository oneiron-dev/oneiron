//! The executor-error arm (H-S5/R2, ONE-1683; FIX 7272): what a non-deadline
//! error settles and parks before it leaves the pass, and whether the pass
//! ends on it.

use super::park_cause::executor_error_park_cause;
use super::*;
use crate::dreamer_runner::DreamerAdmittedAttempt;

impl DreamerWakeDriver<'_> {
    /// Releases what admission acquired for `admitted` after a non-deadline
    /// `error` from `stage`: what its run line charged stays spent and the
    /// rest of the reservation is refunded (SCAN C012), then the attempt
    /// parks. Returning the error first used to leak the admitted attempt
    /// (stuck leased) AND its reservation.
    ///
    /// `true` when the pass ends on `error` now, as before: an error only an
    /// owner act clears parks as ExecutorError, and an attempt the step
    /// layer already parked keeps its park. `false` when it parked as a
    /// Checkpoint the next pass resumes, and the pass goes on.
    pub(super) fn park_executor_error(
        &mut self,
        admitted: &DreamerAdmittedAttempt,
        line: &str,
        meter: &WakeAttemptMeter,
        error: &crate::Error,
        stage: &'static str,
        input: &RunWakePass,
    ) -> Result<bool> {
        let attempt_id = admitted.status.attempt.id;
        let kind = error.kind();
        let cause = executor_error_park_cause(kind);
        let settled = match self.settle_charged_or_abort(line, attempt_id, meter, input.now) {
            Ok(settled) => settled,
            Err(settle_error) => {
                let cause = Some(cause);
                self.log_attempt_outcome(
                    admitted,
                    stage,
                    Some(kind),
                    cause,
                    "settle_failed",
                    "none",
                );
                return Err(settle_error);
            }
        };
        // The durable reason keeps the whole error Display; the error itself
        // leaves the pass untouched.
        let reason = format!("{DREAMER_EXECUTOR_ERROR_PARK_REASON}: {error}");
        if let Some(row) = self.store.parked_attempt(attempt_id)? {
            // One park-owner: the step layer already parked this attempt
            // (under a non-hard-cut reason) inside its own wtxn — publish
            // only, never re-park. A publish failure must not mask the
            // executor error: the attempt is parked either way.
            if let Err(publish_error) =
                self.publish(attempt_id, ProgressKind::Parked, Some(reason), input.now)
            {
                tracing::warn!(
                    kind = ?publish_error.kind(),
                    "parked-progress publish failed after executor error"
                );
            }
            let parked = Some(row.cause);
            self.log_attempt_outcome(
                admitted,
                stage,
                Some(kind),
                parked,
                settled,
                "step_layer_parked",
            );
            return Ok(true);
        }
        let parked = self.park_attempt(admitted, reason, cause, &input.lease_owner, input.now);
        let park = if parked.is_ok() {
            "committed"
        } else {
            "park_failed"
        };
        self.log_attempt_outcome(admitted, stage, Some(kind), Some(cause), settled, park);
        parked?;
        Ok(cause == DreamerParkCause::ExecutorError)
    }
}
