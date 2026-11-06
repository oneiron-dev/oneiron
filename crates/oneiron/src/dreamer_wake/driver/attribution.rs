//! One structured line per admitted attempt the pass did not complete (FIX
//! 7271): who it was, where it ended and how its reservation settled. Ids,
//! kinds and static codes only; never an error's text or a park's reason.
//! A completed attempt has its own debug line, and every line carries the
//! pass's elapsed ms, so a pass's wall time splits by attempt type.

use super::*;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::error::ErrorKind;

impl DreamerWakeDriver<'_> {
    /// Logs `admitted`'s outcome: `stage` names where it ended, `error` the
    /// kind of the error that ended it, `cause` the park it holds,
    /// `settlement` how its reservation settled and `park` whether this
    /// pass committed the park. Errors warn, parks inform, the rest is
    /// debug.
    pub(super) fn log_attempt_outcome(
        &self,
        admitted: &DreamerAdmittedAttempt,
        stage: &'static str,
        error: Option<ErrorKind>,
        cause: Option<DreamerParkCause>,
        settlement: &'static str,
        park: &'static str,
    ) {
        let attempt = &admitted.status.attempt;
        let attempt_id = bytes_to_hex_lower(attempt.id.as_bytes());
        let attempt_type = admitted.status.payload.attempt_type.as_str();
        let wake = self
            .deadline
            .wake_ref()
            .map_or_else(|| "none".to_owned(), |wake| wake.entity_id().to_hex());
        let parked = cause.is_some();
        let cause = cause.map_or("none", DreamerParkCause::as_str);
        let pass_elapsed_ms = self.deadline.elapsed_ms();
        match error {
            Some(kind) => tracing::warn!(
                attempt_id = %attempt_id,
                generation = attempt.attempt_count,
                queue_kind = %attempt.kind,
                attempt_type,
                wake = %wake,
                stage,
                pass_elapsed_ms,
                error_kind = ?kind,
                park_cause = cause,
                settlement,
                park,
                "dreamer attempt ended on an error"
            ),
            None if parked => tracing::info!(
                attempt_id = %attempt_id,
                generation = attempt.attempt_count,
                queue_kind = %attempt.kind,
                attempt_type,
                wake = %wake,
                stage,
                pass_elapsed_ms,
                park_cause = cause,
                settlement,
                park,
                "dreamer attempt parked"
            ),
            None => tracing::debug!(
                attempt_id = %attempt_id,
                generation = attempt.attempt_count,
                queue_kind = %attempt.kind,
                attempt_type,
                wake = %wake,
                stage,
                pass_elapsed_ms,
                settlement,
                "dreamer attempt did not complete this pass"
            ),
        }
    }

    /// Logs at debug that `admitted` completed this pass, with the same
    /// identity fields and the pass's elapsed ms, so the completions the
    /// incomplete-only lines leave out are counted by type too.
    pub(super) fn log_attempt_completed(&self, admitted: &DreamerAdmittedAttempt) {
        let attempt = &admitted.status.attempt;
        let wake = self
            .deadline
            .wake_ref()
            .map_or_else(|| "none".to_owned(), |wake| wake.entity_id().to_hex());
        tracing::debug!(
            attempt_id = %bytes_to_hex_lower(attempt.id.as_bytes()),
            generation = attempt.attempt_count,
            queue_kind = %attempt.kind,
            attempt_type = admitted.status.payload.attempt_type.as_str(),
            wake = %wake,
            pass_elapsed_ms = self.deadline.elapsed_ms(),
            "dreamer attempt completed"
        );
    }
}
