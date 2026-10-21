//! The outcome line of an attempt the server's Dreamer executor ended
//! without completing it (FIX 7271): who it was, the kind of the error it
//! returned or the cause of the park. Ids, kinds and static codes only;
//! never an error's text or a park's reason.

use oneiron::{DreamerAdmittedAttempt, DreamerAttemptExecution, EntityId, WakeAttemptContext};

/// Logs what the executor returned for `attempt` in `ctx`'s pass: an error
/// warns with its kind, a park informs with its cause. Any other outcome is
/// the driver's to log.
pub(super) fn executed(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    outcome: &oneiron::Result<DreamerAttemptExecution>,
) {
    let record = &attempt.status.attempt;
    let attempt_id = EntityId::from_bytes(*record.id.as_bytes())
        .map_or_else(|_| "unnamed".to_owned(), |id| id.to_hex());
    let attempt_type = attempt.status.payload.attempt_type.as_str();
    let wake = ctx
        .deadline
        .wake_ref()
        .map_or_else(|| "none".to_owned(), |wake| wake.entity_id().to_hex());
    let (stage, cause) = match outcome {
        Err(error) => {
            tracing::warn!(
                attempt_id = %attempt_id,
                generation = record.attempt_count,
                queue_kind = %record.kind,
                attempt_type,
                wake = %wake,
                stage = "executor_err",
                error_kind = ?error.kind(),
                "the dreamer executor returned an error"
            );
            return;
        }
        Ok(DreamerAttemptExecution::Park { cause, .. }) => ("park", cause.as_str()),
        Ok(DreamerAttemptExecution::ParkWithSpend { cause, .. }) => {
            ("park_with_spend", cause.as_str())
        }
        Ok(_) => return,
    };
    tracing::info!(
        attempt_id = %attempt_id,
        generation = record.attempt_count,
        queue_kind = %record.kind,
        attempt_type,
        wake = %wake,
        stage,
        park_cause = cause,
        "the dreamer executor parked an attempt"
    );
}
