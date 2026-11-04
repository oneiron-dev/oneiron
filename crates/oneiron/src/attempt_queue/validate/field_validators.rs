//! Length caps, error literals, and per-field validators plus lease/manifest mutators.

use crate::attempt_queue::cancel::{CancelStanding, MAX_LANDING_RESERVE_PERCENT};
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::types::{AttemptRecord, AttemptState, CleanupAttemptLeases};
use crate::error::{ArtifactError, Error, Result};
pub(in crate::attempt_queue) use crate::store::attempt_record_codec::field_validators::{
    ERR_ABANDONED_WITHOUT_REASON, ERR_ABANDONED_WITHOUT_RESULT, ERR_CANCEL_ACTOR_IS_RUNTIME,
    ERR_CANCEL_NO_STANDING, ERR_CANCEL_RECEIPT_FIELD_FORBIDDEN, ERR_CANCEL_RECEIPT_MISSING_GROUNDS,
    ERR_CANCEL_RECEIPT_MISSING_REASON, ERR_CANCEL_RECEIPT_MISSING_REQUEST_REF,
    ERR_CANCEL_RECEIPT_MISSING_RESUME_POINT, ERR_CANCEL_RECEIPT_MISSING_TRIGGER,
    ERR_CANCEL_RECEIPT_RESERVE_UNITS, ERR_CANCELLATION_MISPLACED, ERR_DEDUPE_ACTOR_WITHOUT_KEY,
    ERR_FAILURE_REASON_EMPTY, ERR_HANDOFF_WITHOUT_RESUME_POINT, ERR_LANDING_RECORD_MISPLACED,
    ERR_LANDING_WITH_BACKOFF, ERR_LANDING_WITHOUT_LEASE, ERR_LANDING_WITHOUT_RECORD,
    ERR_LEASE_TIMEOUT_ZERO, ERR_MANIFEST_REFERENCE_EMPTY, ERR_MANIFEST_REFERENCE_HAS_AT,
    ERR_MANIFEST_REFERENCE_TOO_LONG, ERR_MANIFEST_VERSION_EMPTY, ERR_MANIFEST_VERSION_TOO_LONG,
    ERR_RESERVE_SPEND_ZERO, ERR_RESULT_REF_REBOUND, ERR_RUN_ID_TOO_LONG, MAX_FAILURE_REASON_LEN,
    MAX_MANIFEST_REFERENCE_LEN, MAX_MANIFEST_VERSION_LEN, MAX_RUN_ID_LEN, validate_attempt_events,
    validate_attempt_manifest, validate_cancel_actor, validate_failure_reason,
    validate_intervention_actor, validate_kind, validate_manifest_entry,
    validate_optional_cancel_status, validate_optional_dedupe, validate_optional_dedupe_actor_ref,
    validate_optional_failure_reason, validate_optional_intervention_note,
    validate_optional_result_ref, validate_optional_resume_point, validate_optional_run_id,
    validate_planned_binding, validate_resume_point,
};
pub(super) use crate::store::attempt_record_codec::field_validators::{
    ERR_CANCEL_RECEIPT_FIELD_MISSING, ERR_CANCEL_RECEIPT_REQUEST_REF, ERR_CANCEL_RECEIPT_SEQUENCE,
    ERR_CANCEL_RECEIPT_TERMINAL_ORDER, ERR_CANCEL_STATUS_EMPTY, ERR_CANCEL_STATUS_TOO_LONG,
    ERR_CANCELLATION_MALFORMED, ERR_RESERVE_OVERSPENT, ERR_RESERVE_PERCENT_RANGE,
    ERR_RESUME_ARTIFACT_REF_EMPTY, ERR_RESUME_ARTIFACT_REF_TOO_LONG, ERR_RESUME_MARKER_EMPTY,
    ERR_RESUME_MARKER_TOO_LONG, MAX_CANCEL_STATUS_LEN, MAX_RESUME_MARKER_LEN,
};

/// Same bound as a resume point's artifact reference: both name one durable
/// artifact, so one over-long reference must not be admissible on one door and
/// refused on the other.
pub(in crate::attempt_queue) use crate::store::attempt_result::MAX_RESULT_REF_LEN;

pub(super) use crate::store::attempt_result::MAX_RESUME_ARTIFACT_REF_LEN;

pub(super) use crate::store::attempt_result::ERR_RESULT_REF_EMPTY;

pub(super) use crate::store::attempt_result::ERR_RESULT_REF_TOO_LONG;

pub(super) use crate::store::attempt_result::ERR_RESULT_REF_CONTROL;

pub(in crate::attempt_queue) use crate::store::attempt_result::validate_result_ref;

/// Guards the write-once discipline on a result reference.
///
/// Re-attaching the SAME reference is idempotent, so a retried capture
/// converges. Attaching a DIFFERENT one is refused: the row already published
/// which artifact carries this try's output, and silently repointing it would
/// orphan evidence a reader has already resolved.
pub(in crate::attempt_queue) fn validate_result_rebind(
    record: &AttemptRecord,
    result_ref: &super::types::AttemptResultRef,
) -> Result<()> {
    match record.result_ref.as_ref() {
        Some(existing) if existing != result_ref => Err(Error::Artifact(
            ArtifactError::InvalidAttemptQueueRecord(ERR_RESULT_REF_REBOUND),
        )),
        _ => Ok(()),
    }
}

pub(crate) use crate::store::attempt_lease::validate_lease_owner;

pub(in crate::attempt_queue) fn validate_cleanup_leases_input(
    input: &CleanupAttemptLeases,
) -> Result<()> {
    if input.lease_timeout_secs == 0 {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_LEASE_TIMEOUT_ZERO,
        )));
    }
    Ok(())
}

/// Leases an admitted ready row in place. The readiness instant is consumed by
/// the lease, so both spellings clear; `attempt_count` advances as this row's
/// lease-generation fence.
pub(in crate::attempt_queue) fn lease_claimed_record(
    record: &mut AttemptRecord,
    lease_owner: &str,
    now: u64,
) -> Result<()> {
    record.state = AttemptState::Leased;
    record.lease_owner = Some(lease_owner.to_owned());
    record.attempt_count = record
        .attempt_count
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("attempt lease count"))?;
    if record.claimed_at.is_none() {
        record.claimed_at = Some(now);
    }
    record.scheduled_at = None;
    record.backoff_until = None;
    record.updated_at = now;
    Ok(())
}

pub(in crate::attempt_queue) fn validate_transition_lease(
    record: &AttemptRecord,
    lease_owner: &str,
    attempt_count: u32,
    action: &'static str,
) -> Result<()> {
    if record.lease_owner.as_deref() != Some(lease_owner) {
        return Err(invalid_transition(action, "leased_by_other"));
    }
    if record.attempt_count != attempt_count {
        return Err(invalid_transition(action, "stale_attempt"));
    }
    Ok(())
}

pub(in crate::attempt_queue) fn validate_cancel_standing(standing: CancelStanding) -> Result<()> {
    if standing.may_request() {
        Ok(())
    } else {
        Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_CANCEL_NO_STANDING,
        )))
    }
}

pub(in crate::attempt_queue) fn validate_reserve_percent(reserve_percent: u64) -> Result<()> {
    if reserve_percent == 0 || reserve_percent > MAX_LANDING_RESERVE_PERCENT {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RESERVE_PERCENT_RANGE,
        )));
    }
    Ok(())
}
