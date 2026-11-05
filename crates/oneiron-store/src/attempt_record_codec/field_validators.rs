//! The attempt record's field validators and their length caps and error
//! literals: every check the strict reader runs on a stored row's fields.
//! Run identifiers have no byte cap. The attempt
//! queue (`attempt_queue::validate`) runs the same checks on its doors and
//! keeps the lease and reserve validators and the record mutators.
use crate::attempt_inputs::AttemptEvent;
use crate::attempt_result::AttemptResultRef;
use crate::attempt_result::MAX_RESUME_ARTIFACT_REF_LEN;
use crate::attempt_result::validate_result_ref;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// Upper bound on a cycle label.
pub const SKILL_EDIT_CYCLE_MAX_BYTES: usize = 128;

/// The label prefix [`proven_cycle`] names a RUN-proven cycle with.
///
/// Shared with the cycle resolver: a run id that fits after this prefix
/// keeps its literal label; a longer one gets a fixed-size hash label.
pub const SKILL_EDIT_CYCLE_RUN_PREFIX: &str = "run:";

const MAX_KIND_LEN: usize = 128;

const MAX_DEDUPE_KEY_LEN: usize = 512;

pub const MAX_FAILURE_REASON_LEN: usize = 2048;

pub const MAX_MANIFEST_REFERENCE_LEN: usize = 512;

pub const MAX_MANIFEST_VERSION_LEN: usize = 128;

const ERR_EMPTY_KIND: &str = "kind must not be empty";

const ERR_KIND_TOO_LONG: &str = "kind exceeds 128 bytes";

const ERR_DEDUPE_KEY_EMPTY: &str = "dedupe key must not be empty";

const ERR_DEDUPE_KEY_TOO_LONG: &str = "dedupe key exceeds 512 bytes";

pub const ERR_DEDUPE_ACTOR_REF_EMPTY: &str = "dedupe actor ref must not be empty";

pub const ERR_DEDUPE_ACTOR_REF_TOO_LONG: &str = "dedupe actor ref exceeds 128 bytes";

pub const ERR_DEDUPE_ACTOR_WITHOUT_KEY: &str = "attempt with actor scope must carry a dedupe key";

pub const ERR_FAILURE_REASON_EMPTY: &str = "failure reason must not be empty";

const ERR_FAILURE_REASON_TOO_LONG: &str = "failure reason exceeds 2048 bytes";

const ERR_RUN_ID_EMPTY: &str = "run id must not be empty";

const ERR_INTERVENTION_ACTOR_EMPTY: &str = "intervention actor must not be empty";

const ERR_INTERVENTION_NOTE_EMPTY: &str = "intervention note must not be empty";

pub const ERR_MANIFEST_REFERENCE_EMPTY: &str = "manifest reference must not be empty";

pub const ERR_MANIFEST_REFERENCE_TOO_LONG: &str = "manifest reference exceeds 512 bytes";

pub const ERR_MANIFEST_REFERENCE_HAS_AT: &str = "manifest reference must not contain '@'";

pub const ERR_MANIFEST_VERSION_EMPTY: &str = "manifest version must not be empty";

pub const ERR_MANIFEST_VERSION_TOO_LONG: &str = "manifest version exceeds 128 bytes";

pub const ERR_LEASE_TIMEOUT_ZERO: &str = "lease timeout must be > 0";

pub const MAX_CANCEL_STATUS_LEN: usize = 2048;

pub const MAX_RESUME_MARKER_LEN: usize = 2048;

pub const ERR_CANCEL_ACTOR_IS_RUNTIME: &str =
    "cancel actor must not claim the reserved runtime identity";

pub const ERR_CANCEL_NO_STANDING: &str = "cancel request requires standing";

pub const ERR_CANCEL_STATUS_EMPTY: &str = "cancel status must not be empty";

pub const ERR_CANCEL_STATUS_TOO_LONG: &str = "cancel status exceeds 2048 bytes";

pub const ERR_RESUME_MARKER_EMPTY: &str = "resume marker must not be empty";

pub const ERR_RESUME_MARKER_TOO_LONG: &str = "resume marker exceeds 2048 bytes";

pub const ERR_RESUME_ARTIFACT_REF_EMPTY: &str = "resume artifact ref must not be empty";

pub const ERR_RESUME_ARTIFACT_REF_TOO_LONG: &str = "resume artifact ref exceeds 512 bytes";

pub const ERR_CANCEL_RECEIPT_SEQUENCE: &str =
    "attempt cancel receipt sequence must be strictly increasing";

pub const ERR_CANCEL_RECEIPT_TERMINAL_ORDER: &str =
    "a terminal cancel receipt must be the last row, and there may be only one";

pub const ERR_CANCEL_RECEIPT_REQUEST_REF: &str =
    "a cancel receipt may only answer an earlier request receipt";

pub const ERR_RESERVE_PERCENT_RANGE: &str = "landing reserve percent must be in 1..=50";

pub const ERR_RESERVE_SPEND_ZERO: &str = "landing reserve spend must be > 0";

pub const ERR_RESERVE_OVERSPENT: &str = "landing reserve spent exceeds the dialed reserve";

pub const ERR_LANDING_WITHOUT_RECORD: &str = "landing attempt must have a landing record";

pub const ERR_LANDING_WITHOUT_LEASE: &str = "landing attempt must have a lease owner";

pub const ERR_LANDING_WITH_BACKOFF: &str = "landing attempt must not have backoff state";

pub const ERR_LANDING_RECORD_MISPLACED: &str =
    "only a landing or cancelled attempt may carry a landing record";

pub const ERR_CANCELLATION_MISPLACED: &str =
    "only a cancelled attempt may carry a cancellation receipt";

pub const ERR_CANCELLATION_MALFORMED: &str =
    "cancellation grounds must be set exactly for a forced stop";

pub const ERR_HANDOFF_WITHOUT_RESUME_POINT: &str =
    "landing handoff requires a recorded resume point";

pub const ERR_CANCEL_RECEIPT_FIELD_MISSING: &str =
    "cancel receipt is missing a field its kind requires";

pub const ERR_CANCEL_RECEIPT_FIELD_FORBIDDEN: &str =
    "cancel receipt carries a field its kind forbids";

pub const ERR_CANCEL_RECEIPT_MISSING_TRIGGER: &str =
    "a cancel request or landing receipt must name its trigger";

pub const ERR_CANCEL_RECEIPT_MISSING_REASON: &str =
    "a refusal receipt must carry the worker's reason";

pub const ERR_CANCEL_RECEIPT_MISSING_REQUEST_REF: &str =
    "a refusal receipt must name the request it answered";

pub const ERR_CANCEL_RECEIPT_MISSING_RESUME_POINT: &str =
    "a resume-point receipt must carry the resume point it recorded";

pub const ERR_CANCEL_RECEIPT_MISSING_GROUNDS: &str =
    "a force-cancel receipt must carry its authorized grounds";

pub const ERR_CANCEL_RECEIPT_RESERVE_UNITS: &str =
    "cancel receipt reserve units contradict its kind";

pub const ERR_ABANDONED_WITHOUT_RESULT: &str =
    "abandoned attempt must name its last durable result";

pub const ERR_ABANDONED_WITHOUT_REASON: &str = "abandoned attempt must record why it stopped";

pub const ERR_RESULT_REF_REBOUND: &str =
    "attempt result reference is write-once and already names a different artifact";

pub const ERR_PLANNED_BINDING_UNSTAMPED: &str = "a planned binding requires its executor model";

pub const ERR_PLANNED_EXACT_OFF_PICK: &str = "an exact planned binding must run its pick";

pub fn validate_kind(kind: &str) -> Result<()> {
    if kind.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_EMPTY_KIND,
        )));
    }
    if kind.len() > MAX_KIND_LEN {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_KIND_TOO_LONG,
        )));
    }
    Ok(())
}

pub fn validate_optional_dedupe(dedupe_key: Option<&str>) -> Result<()> {
    if let Some(dedupe_key) = dedupe_key {
        if dedupe_key.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_DEDUPE_KEY_EMPTY,
            )));
        }
        if dedupe_key.len() > MAX_DEDUPE_KEY_LEN {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_DEDUPE_KEY_TOO_LONG,
            )));
        }
    }
    Ok(())
}

pub fn validate_failure_reason(reason: &str) -> Result<()> {
    validate_optional_failure_reason(Some(reason))
}

pub fn validate_optional_failure_reason(reason: Option<&str>) -> Result<()> {
    if let Some(reason) = reason {
        if reason.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_FAILURE_REASON_EMPTY,
            )));
        }
        if reason.len() > MAX_FAILURE_REASON_LEN {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_FAILURE_REASON_TOO_LONG,
            )));
        }
    }
    Ok(())
}

/// Re-validates a result reference read back off a row.
///
/// [`AttemptResultRef`] validates at construction, but its
/// `Deserialize` is transparent, so a hand-written or corrupted row could
/// still carry a reference the constructor would have refused.
pub fn validate_optional_result_ref(result_ref: Option<&AttemptResultRef>) -> Result<()> {
    match result_ref {
        Some(result_ref) => validate_result_ref(result_ref.as_str()),
        None => Ok(()),
    }
}

pub fn validate_optional_run_id(run_id: Option<&str>) -> Result<()> {
    if let Some(run_id) = run_id {
        if run_id.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_RUN_ID_EMPTY,
            )));
        }
    }
    Ok(())
}

/// Structural only, at the door and at decode alike (FIX 9580): an actor
/// names someone, so it is not empty. Its length is no refusal; the queue's
/// encode observes it on the `attempt_event_actor_bytes` scan row, so an
/// admitted actor always decodes.
pub fn validate_intervention_actor(actor: &str) -> Result<()> {
    if actor.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_INTERVENTION_ACTOR_EMPTY,
        )));
    }
    Ok(())
}

/// Structural only, at the door and at decode alike (FIX 9580): a note that
/// is present says something. Its length is no refusal; the queue's encode
/// observes it on the `attempt_event_note_bytes` scan row, so an admitted
/// note always decodes.
pub fn validate_optional_intervention_note(note: Option<&str>) -> Result<()> {
    if note.is_some_and(str::is_empty) {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_INTERVENTION_NOTE_EMPTY,
        )));
    }
    Ok(())
}

pub fn validate_attempt_events(events: &[AttemptEvent]) -> Result<()> {
    let mut previous_sequence = 0;
    for event in events {
        if event.sequence == 0 || event.sequence <= previous_sequence {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "attempt event sequence must be strictly increasing",
            )));
        }
        validate_intervention_actor(&event.actor)?;
        validate_optional_intervention_note(event.note.as_deref())?;
        previous_sequence = event.sequence;
    }
    Ok(())
}

pub fn validate_optional_cancel_status(status: Option<&str>) -> Result<()> {
    if let Some(status) = status {
        if status.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_CANCEL_STATUS_EMPTY,
            )));
        }
        if status.len() > MAX_CANCEL_STATUS_LEN {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_CANCEL_STATUS_TOO_LONG,
            )));
        }
    }
    Ok(())
}
