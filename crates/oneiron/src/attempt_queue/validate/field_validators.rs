//! Length caps, error literals, and per-field validators plus lease/manifest mutators.

use crate::attempt_queue::cancel::{
    ATTEMPT_RUNTIME_ACTOR, AttemptResumePoint, CancelStanding, MAX_LANDING_RESERVE_PERCENT,
};
use crate::attempt_queue::encoding::MAX_DEDUPE_ACTOR_REF_LEN;
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::types::{
    AttemptEvent, AttemptRecord, AttemptState, CleanupAttemptLeases, MAX_ATTEMPT_MANIFEST_ENTRIES,
    ManifestEntry,
};
use crate::error::{ArtifactError, Error, Result};

const MAX_KIND_LEN: usize = 128;

const MAX_DEDUPE_KEY_LEN: usize = 512;

pub(in crate::attempt_queue) const MAX_FAILURE_REASON_LEN: usize = 2048;

const MAX_LEASE_OWNER_LEN: usize = 128;

/// Longest run id the queue admits, and deliberately not a round number.
///
/// A run id is not only a queue key: `skill_optimize::proven_cycle` turns it
/// into the Dreamer CYCLE label the per-cycle skill-edit accept cap is counted
/// against, by writing `skill_optimize::SKILL_EDIT_CYCLE_RUN_PREFIX` in front
/// of it. So the budget is the cycle bound MINUS that prefix, DERIVED from both
/// rather than restated — a run id this door accepted but no cycle could name
/// was a run whose every drafted proposal died at the gate, after the author
/// had already been paid for it.
pub(in crate::attempt_queue) const MAX_RUN_ID_LEN: usize =
    crate::skill_optimize::SKILL_EDIT_CYCLE_MAX_BYTES
        - crate::skill_optimize::SKILL_EDIT_CYCLE_RUN_PREFIX.len();

const MAX_INTERVENTION_ACTOR_LEN: usize = 128;

const MAX_INTERVENTION_NOTE_LEN: usize = 2048;

/// Same bound as a resume point's artifact reference: both name one durable
/// artifact, so one over-long reference must not be admissible on one door and
/// refused on the other.
pub(in crate::attempt_queue) const MAX_RESULT_REF_LEN: usize = MAX_RESUME_ARTIFACT_REF_LEN;

pub(in crate::attempt_queue) const MAX_MANIFEST_REFERENCE_LEN: usize = 512;

pub(in crate::attempt_queue) const MAX_MANIFEST_VERSION_LEN: usize = 128;

const ERR_EMPTY_KIND: &str = "kind must not be empty";

const ERR_KIND_TOO_LONG: &str = "kind exceeds 128 bytes";

const ERR_DEDUPE_KEY_EMPTY: &str = "dedupe key must not be empty";

const ERR_DEDUPE_KEY_TOO_LONG: &str = "dedupe key exceeds 512 bytes";

const ERR_DEDUPE_ACTOR_REF_EMPTY: &str = "dedupe actor ref must not be empty";

const ERR_DEDUPE_ACTOR_REF_TOO_LONG: &str = "dedupe actor ref exceeds 128 bytes";

pub(in crate::attempt_queue) const ERR_DEDUPE_ACTOR_WITHOUT_KEY: &str =
    "attempt with actor scope must carry a dedupe key";

pub(in crate::attempt_queue) const ERR_FAILURE_REASON_EMPTY: &str =
    "failure reason must not be empty";

const ERR_FAILURE_REASON_TOO_LONG: &str = "failure reason exceeds 2048 bytes";

const ERR_LEASE_OWNER_EMPTY: &str = "lease owner must not be empty";

const ERR_LEASE_OWNER_TOO_LONG: &str = "lease owner exceeds 128 bytes";

const ERR_RUN_ID_EMPTY: &str = "run id must not be empty";

pub(in crate::attempt_queue) const ERR_RUN_ID_TOO_LONG: &str =
    "run id exceeds 124 bytes; the cycle label needs the rest";

const ERR_INTERVENTION_ACTOR_EMPTY: &str = "intervention actor must not be empty";

const ERR_INTERVENTION_ACTOR_TOO_LONG: &str = "intervention actor exceeds 128 bytes";

const ERR_INTERVENTION_NOTE_EMPTY: &str = "intervention note must not be empty";

const ERR_INTERVENTION_NOTE_TOO_LONG: &str = "intervention note exceeds 2048 bytes";

pub(in crate::attempt_queue) const ERR_MANIFEST_REFERENCE_EMPTY: &str =
    "manifest reference must not be empty";

pub(in crate::attempt_queue) const ERR_MANIFEST_REFERENCE_TOO_LONG: &str =
    "manifest reference exceeds 512 bytes";

pub(in crate::attempt_queue) const ERR_MANIFEST_REFERENCE_HAS_AT: &str =
    "manifest reference must not contain '@'";

pub(in crate::attempt_queue) const ERR_MANIFEST_VERSION_EMPTY: &str =
    "manifest version must not be empty";

pub(in crate::attempt_queue) const ERR_MANIFEST_VERSION_TOO_LONG: &str =
    "manifest version exceeds 128 bytes";

pub(in crate::attempt_queue) const ERR_MANIFEST_FULL: &str =
    "attempt manifest is full; entries are never dropped";

pub(in crate::attempt_queue) const ERR_LEASE_TIMEOUT_ZERO: &str = "lease timeout must be > 0";

pub(super) const MAX_CANCEL_STATUS_LEN: usize = 2048;

pub(super) const MAX_RESUME_MARKER_LEN: usize = 2048;

pub(super) const MAX_RESUME_ARTIFACT_REF_LEN: usize = 512;

pub(in crate::attempt_queue) const ERR_CANCEL_ACTOR_IS_RUNTIME: &str =
    "cancel actor must not claim the reserved runtime identity";

pub(in crate::attempt_queue) const ERR_CANCEL_NO_STANDING: &str =
    "cancel request requires standing";

pub(super) const ERR_CANCEL_STATUS_EMPTY: &str = "cancel status must not be empty";

pub(super) const ERR_CANCEL_STATUS_TOO_LONG: &str = "cancel status exceeds 2048 bytes";

pub(super) const ERR_RESUME_MARKER_EMPTY: &str = "resume marker must not be empty";

pub(super) const ERR_RESUME_MARKER_TOO_LONG: &str = "resume marker exceeds 2048 bytes";

pub(super) const ERR_RESUME_ARTIFACT_REF_EMPTY: &str = "resume artifact ref must not be empty";

pub(super) const ERR_RESUME_ARTIFACT_REF_TOO_LONG: &str = "resume artifact ref exceeds 512 bytes";

pub(in crate::attempt_queue) const ERR_CANCEL_RECEIPTS_FULL: &str =
    "attempt cancel receipts are full; refusal evidence is never dropped";

pub(super) const ERR_CANCEL_RECEIPT_SEQUENCE: &str =
    "attempt cancel receipt sequence must be strictly increasing";

pub(super) const ERR_CANCEL_RECEIPT_TERMINAL_ORDER: &str =
    "a terminal cancel receipt must be the last row, and there may be only one";

pub(super) const ERR_CANCEL_RECEIPT_REQUEST_REF: &str =
    "a cancel receipt may only answer an earlier request receipt";

pub(super) const ERR_RESERVE_PERCENT_RANGE: &str = "landing reserve percent must be in 1..=50";

pub(in crate::attempt_queue) const ERR_RESERVE_SPEND_ZERO: &str =
    "landing reserve spend must be > 0";

pub(super) const ERR_RESERVE_OVERSPENT: &str = "landing reserve spent exceeds the dialed reserve";

pub(in crate::attempt_queue) const ERR_LANDING_WITHOUT_RECORD: &str =
    "landing attempt must have a landing record";

pub(in crate::attempt_queue) const ERR_LANDING_WITHOUT_LEASE: &str =
    "landing attempt must have a lease owner";

pub(in crate::attempt_queue) const ERR_LANDING_WITH_BACKOFF: &str =
    "landing attempt must not have backoff state";

pub(in crate::attempt_queue) const ERR_LANDING_RECORD_MISPLACED: &str =
    "only a landing or cancelled attempt may carry a landing record";

pub(in crate::attempt_queue) const ERR_CANCELLATION_MISPLACED: &str =
    "only a cancelled attempt may carry a cancellation receipt";

pub(super) const ERR_CANCELLATION_MALFORMED: &str =
    "cancellation grounds must be set exactly for a forced stop";

pub(in crate::attempt_queue) const ERR_HANDOFF_WITHOUT_RESUME_POINT: &str =
    "landing handoff requires a recorded resume point";

pub(super) const ERR_CANCEL_RECEIPT_FIELD_MISSING: &str =
    "cancel receipt is missing a field its kind requires";

pub(in crate::attempt_queue) const ERR_CANCEL_RECEIPT_FIELD_FORBIDDEN: &str =
    "cancel receipt carries a field its kind forbids";

pub(in crate::attempt_queue) const ERR_CANCEL_RECEIPT_MISSING_TRIGGER: &str =
    "a cancel request or landing receipt must name its trigger";

pub(in crate::attempt_queue) const ERR_CANCEL_RECEIPT_MISSING_REASON: &str =
    "a refusal receipt must carry the worker's reason";

pub(in crate::attempt_queue) const ERR_CANCEL_RECEIPT_MISSING_REQUEST_REF: &str =
    "a refusal receipt must name the request it answered";

pub(in crate::attempt_queue) const ERR_CANCEL_RECEIPT_MISSING_RESUME_POINT: &str =
    "a resume-point receipt must carry the resume point it recorded";

pub(in crate::attempt_queue) const ERR_CANCEL_RECEIPT_MISSING_GROUNDS: &str =
    "a force-cancel receipt must carry its authorized grounds";

pub(in crate::attempt_queue) const ERR_CANCEL_RECEIPT_RESERVE_UNITS: &str =
    "cancel receipt reserve units contradict its kind";

pub(super) const ERR_RESULT_REF_EMPTY: &str = "attempt result reference must not be empty";

pub(super) const ERR_RESULT_REF_TOO_LONG: &str = "attempt result reference exceeds 512 bytes";

pub(super) const ERR_RESULT_REF_CONTROL: &str =
    "attempt result reference contains a control character";

pub(in crate::attempt_queue) const ERR_ABANDONED_WITHOUT_RESULT: &str =
    "abandoned attempt must name its last durable result";

pub(in crate::attempt_queue) const ERR_ABANDONED_WITHOUT_REASON: &str =
    "abandoned attempt must record why it stopped";

pub(in crate::attempt_queue) const ERR_RESULT_REF_REBOUND: &str =
    "attempt result reference is write-once and already names a different artifact";

pub(in crate::attempt_queue) fn validate_kind(kind: &str) -> Result<()> {
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

pub(in crate::attempt_queue) fn validate_optional_dedupe(dedupe_key: Option<&str>) -> Result<()> {
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
pub(in crate::attempt_queue) fn validate_optional_dedupe_actor_ref(
    actor_ref: Option<&str>,
) -> Result<()> {
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

pub(in crate::attempt_queue) fn validate_failure_reason(reason: &str) -> Result<()> {
    validate_optional_failure_reason(Some(reason))
}

pub(in crate::attempt_queue) fn validate_optional_failure_reason(
    reason: Option<&str>,
) -> Result<()> {
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

/// Refuses a result reference no reader could resolve.
///
/// Control characters are rejected in addition to the length/emptiness bounds
/// the other reference doors use: a result reference is projected onto read
/// surfaces verbatim (the run tree renders it under its own wire key), so an
/// embedded newline or terminal escape would be a rendering hazard carried on
/// a durable row.
pub(in crate::attempt_queue) fn validate_result_ref(result_ref: &str) -> Result<()> {
    if result_ref.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RESULT_REF_EMPTY,
        )));
    }
    if result_ref.len() > MAX_RESULT_REF_LEN {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RESULT_REF_TOO_LONG,
        )));
    }
    if result_ref.chars().any(char::is_control) {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RESULT_REF_CONTROL,
        )));
    }
    Ok(())
}

/// Re-validates a result reference read back off a row.
///
/// [`super::types::AttemptResultRef`] validates at construction, but its
/// `Deserialize` is transparent, so a hand-written or corrupted row could
/// still carry a reference the constructor would have refused.
pub(in crate::attempt_queue) fn validate_optional_result_ref(
    result_ref: Option<&super::types::AttemptResultRef>,
) -> Result<()> {
    match result_ref {
        Some(result_ref) => validate_result_ref(result_ref.as_str()),
        None => Ok(()),
    }
}

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

pub(in crate::attempt_queue) fn validate_optional_run_id(run_id: Option<&str>) -> Result<()> {
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

pub(in crate::attempt_queue) fn validate_intervention_actor(actor: &str) -> Result<()> {
    if actor.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_INTERVENTION_ACTOR_EMPTY,
        )));
    }
    if actor.len() > MAX_INTERVENTION_ACTOR_LEN {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_INTERVENTION_ACTOR_TOO_LONG,
        )));
    }
    Ok(())
}

pub(in crate::attempt_queue) fn validate_optional_intervention_note(
    note: Option<&str>,
) -> Result<()> {
    if let Some(note) = note {
        if note.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_INTERVENTION_NOTE_EMPTY,
            )));
        }
        if note.len() > MAX_INTERVENTION_NOTE_LEN {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_INTERVENTION_NOTE_TOO_LONG,
            )));
        }
    }
    Ok(())
}

pub(in crate::attempt_queue) fn validate_lease_owner(lease_owner: &str) -> Result<()> {
    if lease_owner.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_LEASE_OWNER_EMPTY,
        )));
    }
    if lease_owner.len() > MAX_LEASE_OWNER_LEN {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_LEASE_OWNER_TOO_LONG,
        )));
    }
    Ok(())
}

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

pub(in crate::attempt_queue) fn validate_attempt_events(events: &[AttemptEvent]) -> Result<()> {
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
pub(in crate::attempt_queue) fn validate_manifest_entry(entry: &ManifestEntry) -> Result<()> {
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

pub(in crate::attempt_queue) fn validate_attempt_manifest(
    manifest: &[ManifestEntry],
) -> Result<()> {
    if manifest.len() > MAX_ATTEMPT_MANIFEST_ENTRIES {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_MANIFEST_FULL,
        )));
    }
    for entry in manifest {
        validate_manifest_entry(entry)?;
    }
    Ok(())
}

/// Refuses an actor that claims the runtime's own identity.
///
/// Structural forgery is already impossible — a hard receipt can only be
/// written by the [`super::types::ForceCancelAuthority`] path — but a soft row
/// whose actor reads `runtime` would still MISLEAD every reviewer, so the door
/// refuses it outright.
pub(in crate::attempt_queue) fn validate_cancel_actor(actor: &str) -> Result<()> {
    validate_intervention_actor(actor)?;
    if actor == ATTEMPT_RUNTIME_ACTOR {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_CANCEL_ACTOR_IS_RUNTIME,
        )));
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

pub(in crate::attempt_queue) fn validate_optional_cancel_status(
    status: Option<&str>,
) -> Result<()> {
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

pub(in crate::attempt_queue) fn validate_resume_point(
    resume_point: &AttemptResumePoint,
) -> Result<()> {
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

pub(in crate::attempt_queue) fn validate_optional_resume_point(
    resume_point: Option<&AttemptResumePoint>,
) -> Result<()> {
    match resume_point {
        Some(resume_point) => validate_resume_point(resume_point),
        None => Ok(()),
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
