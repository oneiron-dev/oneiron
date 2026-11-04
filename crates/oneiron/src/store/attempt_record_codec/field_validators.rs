//! The attempt record's field validators and their length caps and error
//! literals: every check the strict reader runs on a stored row's fields,
//! and the run-id bound derived from the skill edit cycle label. The attempt
//! queue (`attempt_queue::validate`) runs the same checks on its doors and
//! keeps the lease and reserve validators and the record mutators.
use crate::error::{ArtifactError, Error, Result};
use crate::store::attempt_cancel::{ATTEMPT_RUNTIME_ACTOR, AttemptResumePoint};
use crate::store::attempt_inputs::AttemptEvent;
use crate::store::attempt_manifest::ManifestEntry;
use crate::store::attempt_record::{AttemptRecord, PlannedExactness};
use crate::store::attempt_result::{
    AttemptResultRef, MAX_RESUME_ARTIFACT_REF_LEN, validate_result_ref,
};

use super::MAX_DEDUPE_ACTOR_REF_LEN;

/// Upper bound on a cycle label.
pub const SKILL_EDIT_CYCLE_MAX_BYTES: usize = 128;

/// The label prefix [`proven_cycle`] names a RUN-proven cycle with.
///
/// Pinned here because two modules have to agree on it: this one BUILDS the
/// label, and the attempt queue's run-id validator
/// (`crate::attempt_queue::validate`) sizes its own bound by subtracting this
/// prefix from [`SKILL_EDIT_CYCLE_MAX_BYTES`]. Spelling it twice is how a run
/// id the queue accepted became a cycle label nobody could name.
pub(crate) const SKILL_EDIT_CYCLE_RUN_PREFIX: &str = "run:";

const MAX_KIND_LEN: usize = 128;

const MAX_DEDUPE_KEY_LEN: usize = 512;

pub(crate) const MAX_FAILURE_REASON_LEN: usize = 2048;

/// Longest run id the queue admits, and deliberately not a round number.
///
/// A run id is not only a queue key: `skill_optimize::proven_cycle` turns it
/// into the Dreamer CYCLE label the per-cycle skill-edit accept cap is counted
/// against, by writing `skill_optimize::SKILL_EDIT_CYCLE_RUN_PREFIX` in front
/// of it. So the budget is the cycle bound MINUS that prefix, DERIVED from both
/// rather than restated — a run id this door accepted but no cycle could name
/// was a run whose every drafted proposal died at the gate, after the author
/// had already been paid for it.
pub(crate) const MAX_RUN_ID_LEN: usize =
    SKILL_EDIT_CYCLE_MAX_BYTES - SKILL_EDIT_CYCLE_RUN_PREFIX.len();

pub(crate) const MAX_MANIFEST_REFERENCE_LEN: usize = 512;

pub(crate) const MAX_MANIFEST_VERSION_LEN: usize = 128;

const ERR_EMPTY_KIND: &str = "kind must not be empty";

const ERR_KIND_TOO_LONG: &str = "kind exceeds 128 bytes";

const ERR_DEDUPE_KEY_EMPTY: &str = "dedupe key must not be empty";

const ERR_DEDUPE_KEY_TOO_LONG: &str = "dedupe key exceeds 512 bytes";

const ERR_DEDUPE_ACTOR_REF_EMPTY: &str = "dedupe actor ref must not be empty";

const ERR_DEDUPE_ACTOR_REF_TOO_LONG: &str = "dedupe actor ref exceeds 128 bytes";

pub(crate) const ERR_DEDUPE_ACTOR_WITHOUT_KEY: &str =
    "attempt with actor scope must carry a dedupe key";

pub(crate) const ERR_FAILURE_REASON_EMPTY: &str = "failure reason must not be empty";

const ERR_FAILURE_REASON_TOO_LONG: &str = "failure reason exceeds 2048 bytes";

const ERR_RUN_ID_EMPTY: &str = "run id must not be empty";

pub(crate) const ERR_RUN_ID_TOO_LONG: &str =
    "run id exceeds 124 bytes; the cycle label needs the rest";

const ERR_INTERVENTION_ACTOR_EMPTY: &str = "intervention actor must not be empty";

const ERR_INTERVENTION_NOTE_EMPTY: &str = "intervention note must not be empty";

pub(crate) const ERR_MANIFEST_REFERENCE_EMPTY: &str = "manifest reference must not be empty";

pub(crate) const ERR_MANIFEST_REFERENCE_TOO_LONG: &str = "manifest reference exceeds 512 bytes";

pub(crate) const ERR_MANIFEST_REFERENCE_HAS_AT: &str = "manifest reference must not contain '@'";

pub(crate) const ERR_MANIFEST_VERSION_EMPTY: &str = "manifest version must not be empty";

pub(crate) const ERR_MANIFEST_VERSION_TOO_LONG: &str = "manifest version exceeds 128 bytes";

pub(crate) const ERR_LEASE_TIMEOUT_ZERO: &str = "lease timeout must be > 0";

pub(crate) const MAX_CANCEL_STATUS_LEN: usize = 2048;

pub(crate) const MAX_RESUME_MARKER_LEN: usize = 2048;

pub(crate) const ERR_CANCEL_ACTOR_IS_RUNTIME: &str =
    "cancel actor must not claim the reserved runtime identity";

pub(crate) const ERR_CANCEL_NO_STANDING: &str = "cancel request requires standing";

pub(crate) const ERR_CANCEL_STATUS_EMPTY: &str = "cancel status must not be empty";

pub(crate) const ERR_CANCEL_STATUS_TOO_LONG: &str = "cancel status exceeds 2048 bytes";

pub(crate) const ERR_RESUME_MARKER_EMPTY: &str = "resume marker must not be empty";

pub(crate) const ERR_RESUME_MARKER_TOO_LONG: &str = "resume marker exceeds 2048 bytes";

pub(crate) const ERR_RESUME_ARTIFACT_REF_EMPTY: &str = "resume artifact ref must not be empty";

pub(crate) const ERR_RESUME_ARTIFACT_REF_TOO_LONG: &str = "resume artifact ref exceeds 512 bytes";

pub(crate) const ERR_CANCEL_RECEIPT_SEQUENCE: &str =
    "attempt cancel receipt sequence must be strictly increasing";

pub(crate) const ERR_CANCEL_RECEIPT_TERMINAL_ORDER: &str =
    "a terminal cancel receipt must be the last row, and there may be only one";

pub(crate) const ERR_CANCEL_RECEIPT_REQUEST_REF: &str =
    "a cancel receipt may only answer an earlier request receipt";

pub(crate) const ERR_RESERVE_PERCENT_RANGE: &str = "landing reserve percent must be in 1..=50";

pub(crate) const ERR_RESERVE_SPEND_ZERO: &str = "landing reserve spend must be > 0";

pub(crate) const ERR_RESERVE_OVERSPENT: &str = "landing reserve spent exceeds the dialed reserve";

pub(crate) const ERR_LANDING_WITHOUT_RECORD: &str = "landing attempt must have a landing record";

pub(crate) const ERR_LANDING_WITHOUT_LEASE: &str = "landing attempt must have a lease owner";

pub(crate) const ERR_LANDING_WITH_BACKOFF: &str = "landing attempt must not have backoff state";

pub(crate) const ERR_LANDING_RECORD_MISPLACED: &str =
    "only a landing or cancelled attempt may carry a landing record";

pub(crate) const ERR_CANCELLATION_MISPLACED: &str =
    "only a cancelled attempt may carry a cancellation receipt";

pub(crate) const ERR_CANCELLATION_MALFORMED: &str =
    "cancellation grounds must be set exactly for a forced stop";

pub(crate) const ERR_HANDOFF_WITHOUT_RESUME_POINT: &str =
    "landing handoff requires a recorded resume point";

pub(crate) const ERR_CANCEL_RECEIPT_FIELD_MISSING: &str =
    "cancel receipt is missing a field its kind requires";

pub(crate) const ERR_CANCEL_RECEIPT_FIELD_FORBIDDEN: &str =
    "cancel receipt carries a field its kind forbids";

pub(crate) const ERR_CANCEL_RECEIPT_MISSING_TRIGGER: &str =
    "a cancel request or landing receipt must name its trigger";

pub(crate) const ERR_CANCEL_RECEIPT_MISSING_REASON: &str =
    "a refusal receipt must carry the worker's reason";

pub(crate) const ERR_CANCEL_RECEIPT_MISSING_REQUEST_REF: &str =
    "a refusal receipt must name the request it answered";

pub(crate) const ERR_CANCEL_RECEIPT_MISSING_RESUME_POINT: &str =
    "a resume-point receipt must carry the resume point it recorded";

pub(crate) const ERR_CANCEL_RECEIPT_MISSING_GROUNDS: &str =
    "a force-cancel receipt must carry its authorized grounds";

pub(crate) const ERR_CANCEL_RECEIPT_RESERVE_UNITS: &str =
    "cancel receipt reserve units contradict its kind";

pub(crate) const ERR_ABANDONED_WITHOUT_RESULT: &str =
    "abandoned attempt must name its last durable result";

pub(crate) const ERR_ABANDONED_WITHOUT_REASON: &str =
    "abandoned attempt must record why it stopped";

pub(crate) const ERR_RESULT_REF_REBOUND: &str =
    "attempt result reference is write-once and already names a different artifact";

const ERR_PLANNED_BINDING_UNSTAMPED: &str = "a planned binding requires its executor model";

const ERR_PLANNED_EXACT_OFF_PICK: &str = "an exact planned binding must run its pick";

pub(crate) fn validate_kind(kind: &str) -> Result<()> {
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

pub(crate) fn validate_optional_dedupe(dedupe_key: Option<&str>) -> Result<()> {
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

/// Guards the optional actor scope of a dedupe key, at the same doors the kind
/// and the key itself are guarded.
///
/// The bound matters twice: it keeps a scope out of the index that the v2
/// length prefix could not describe, and it keeps one caller from spending
/// another's key space on an unbounded segment.
pub(crate) fn validate_optional_dedupe_actor_ref(actor_ref: Option<&str>) -> Result<()> {
    if let Some(actor_ref) = actor_ref {
        if actor_ref.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_DEDUPE_ACTOR_REF_EMPTY,
            )));
        }
        if actor_ref.len() > MAX_DEDUPE_ACTOR_REF_LEN {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_DEDUPE_ACTOR_REF_TOO_LONG,
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_failure_reason(reason: &str) -> Result<()> {
    validate_optional_failure_reason(Some(reason))
}

pub(crate) fn validate_optional_failure_reason(reason: Option<&str>) -> Result<()> {
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
pub(crate) fn validate_optional_result_ref(result_ref: Option<&AttemptResultRef>) -> Result<()> {
    match result_ref {
        Some(result_ref) => validate_result_ref(result_ref.as_str()),
        None => Ok(()),
    }
}

/// A planned binding is written in one write with its executor model (FIX
/// 7720), so one without that model, or an exact one whose model is not its
/// pick, is a row no door wrote. Shape only, never a model's availability.
pub(crate) fn validate_planned_binding(record: &AttemptRecord) -> Result<()> {
    let Some(binding) = &record.planned_binding else {
        return Ok(());
    };
    let reason = match record.executor_model.as_deref() {
        None => ERR_PLANNED_BINDING_UNSTAMPED,
        Some(model)
            if binding.exactness == PlannedExactness::Exact && model != binding.pick.as_str() =>
        {
            ERR_PLANNED_EXACT_OFF_PICK
        }
        Some(_) => return Ok(()),
    };
    Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
        reason,
    )))
}

pub(crate) fn validate_optional_run_id(run_id: Option<&str>) -> Result<()> {
    if let Some(run_id) = run_id {
        if run_id.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_RUN_ID_EMPTY,
            )));
        }
        if run_id.len() > MAX_RUN_ID_LEN {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_RUN_ID_TOO_LONG,
            )));
        }
    }
    Ok(())
}

/// Structural only, at the door and at decode alike (FIX 9580): an actor
/// names someone, so it is not empty. Its length is no refusal; the queue's
/// encode observes it on the `attempt_event_actor_bytes` scan row, so an
/// admitted actor always decodes.
pub(crate) fn validate_intervention_actor(actor: &str) -> Result<()> {
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
pub(crate) fn validate_optional_intervention_note(note: Option<&str>) -> Result<()> {
    if note.is_some_and(str::is_empty) {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_INTERVENTION_NOTE_EMPTY,
        )));
    }
    Ok(())
}

pub(crate) fn validate_attempt_events(events: &[AttemptEvent]) -> Result<()> {
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

/// Refuses a row the `reference@version` wire form could not carry back.
///
/// `@` in a REFERENCE is rejected here (owner ruling R-20260807-04): it is the
/// delimiter, so a reference holding one makes [`ManifestEntry::parse_wire_form`]
/// ambiguous and lets a row name a skill the pack never loaded. A VERSION may
/// hold `@` freely — everything after the first delimiter is the version.
pub(crate) fn validate_manifest_entry(entry: &ManifestEntry) -> Result<()> {
    if entry.reference.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_MANIFEST_REFERENCE_EMPTY,
        )));
    }
    if entry.reference.contains('@') {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_MANIFEST_REFERENCE_HAS_AT,
        )));
    }
    if entry.reference.len() > MAX_MANIFEST_REFERENCE_LEN {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_MANIFEST_REFERENCE_TOO_LONG,
        )));
    }
    if entry.version.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_MANIFEST_VERSION_EMPTY,
        )));
    }
    if entry.version.len() > MAX_MANIFEST_VERSION_LEN {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_MANIFEST_VERSION_TOO_LONG,
        )));
    }
    Ok(())
}

pub(crate) fn validate_attempt_manifest(manifest: &[ManifestEntry]) -> Result<()> {
    for entry in manifest {
        validate_manifest_entry(entry)?;
    }
    Ok(())
}

/// Refuses an actor that claims the runtime's own identity.
///
/// Structural forgery is already impossible — a hard receipt can only be
/// written by the [`ForceCancelAuthority`](crate::attempt_queue::ForceCancelAuthority) path — but a soft row
/// whose actor reads `runtime` would still MISLEAD every reviewer, so the door
/// refuses it outright.
pub(crate) fn validate_cancel_actor(actor: &str) -> Result<()> {
    validate_intervention_actor(actor)?;
    if actor == ATTEMPT_RUNTIME_ACTOR {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_CANCEL_ACTOR_IS_RUNTIME,
        )));
    }
    Ok(())
}

pub(crate) fn validate_optional_cancel_status(status: Option<&str>) -> Result<()> {
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

pub(crate) fn validate_resume_point(resume_point: &AttemptResumePoint) -> Result<()> {
    if resume_point.marker.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RESUME_MARKER_EMPTY,
        )));
    }
    if resume_point.marker.len() > MAX_RESUME_MARKER_LEN {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RESUME_MARKER_TOO_LONG,
        )));
    }
    if let Some(artifact_ref) = resume_point.artifact_ref.as_deref() {
        if artifact_ref.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_RESUME_ARTIFACT_REF_EMPTY,
            )));
        }
        if artifact_ref.len() > MAX_RESUME_ARTIFACT_REF_LEN {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_RESUME_ARTIFACT_REF_TOO_LONG,
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_optional_resume_point(
    resume_point: Option<&AttemptResumePoint>,
) -> Result<()> {
    match resume_point {
        Some(resume_point) => validate_resume_point(resume_point),
        None => Ok(()),
    }
}
