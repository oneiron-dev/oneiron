//! Core half of `store::attempt_record_codec::field_validators`: its store-layer items live in `oneiron_store::attempt_record_codec::field_validators` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::attempt_record_codec::field_validators::*;

use super::MAX_DEDUPE_ACTOR_REF_LEN;
use crate::error::{ArtifactError, Error, Result};
use crate::store::attempt_cancel::{ATTEMPT_RUNTIME_ACTOR, AttemptResumePoint};
use crate::store::attempt_inputs::AttemptEvent;
use crate::store::attempt_manifest::ManifestEntry;
use crate::store::attempt_record::{AttemptRecord, PlannedExactness};
use crate::store::attempt_result::{
    AttemptResultRef, MAX_RESUME_ARTIFACT_REF_LEN, validate_result_ref,
};

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
