//! Register wire-format converters and validators.

use super::super::hex_bytes;
use super::register::CompanionRegisterProvenancePayload;
use super::register::CompanionRegisterRecordPayload;
use super::register::CompanionRegisterRelationshipRefPayload;
use super::register::CompanionRegisterScopePayload;
use super::register::CompanionRegisterSubjectPayload;
use crate::error::ApiError;
use serde::Serialize;
use utoipa::ToSchema;

/// Goodbye-artifact hook status returned by relationship teardown.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionGoodbyeArtifactHookPayload {
    /// Hook state: `enqueued`, `existing`, `skipped_bad_end`, or `skipped`.
    #[schema(example = "enqueued")]
    status: String,
    /// Companion task kind for the goodbye-artifact hook.
    #[schema(example = "goodbye_artifact")]
    task: String,
    /// Durable attempt id when the hook enqueued or found an existing task.
    #[schema(example = "018f0000000000000000000000000000")]
    #[serde(rename = "job_id")] // wire key pinned pre-rename (ONE-1714)
    attempt_id: Option<String>,
    /// Optional run id stamped onto the durable attempt row.
    #[schema(example = "eiri-goodbye-artifact-1700000600")]
    run_id: Option<String>,
}

/// End companion relationship response envelope.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionEndRelationshipResponse {
    /// Companion register entity id.
    #[schema(example = "33333333333333333333333333333333")]
    pub(super) id: String,
    /// Scrubbed and retired companion relationship record.
    pub(super) record: CompanionRegisterRecordPayload,
    /// Goodbye-artifact hook status.
    pub(super) goodbye_artifact: CompanionGoodbyeArtifactHookPayload,
}

/// Companion register response envelope.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CompanionRegisterRecordResponse {
    /// Companion register entity id.
    #[schema(example = "33333333333333333333333333333333")]
    id: String,
    /// Typed companion register record.
    record: CompanionRegisterRecordPayload,
}

pub(crate) fn companion_register_record_response(
    id: &oneiron::EntityId,
    record: &oneiron::CompanionRecord,
) -> CompanionRegisterRecordResponse {
    CompanionRegisterRecordResponse {
        id: id.to_hex(),
        record: companion_register_record_payload(record),
    }
}

pub(crate) fn companion_goodbye_artifact_hook_payload(
    outcome: Option<oneiron::EnqueueCompanionTaskOutcome>,
    ended_badly: bool,
    already_ended: bool,
) -> CompanionGoodbyeArtifactHookPayload {
    let skipped = |status: &'static str| CompanionGoodbyeArtifactHookPayload {
        status: status.to_owned(),
        task: oneiron::CompanionTaskKind::GoodbyeArtifact
            .as_str()
            .to_owned(),
        attempt_id: None,
        run_id: None,
    };

    let Some(outcome) = outcome else {
        return if already_ended {
            skipped("already_ended")
        } else if ended_badly {
            skipped("skipped_bad_end")
        } else {
            skipped("skipped")
        };
    };

    let (status, task_status) = match outcome {
        oneiron::EnqueueCompanionTaskOutcome::Enqueued(status) => ("enqueued", status),
        oneiron::EnqueueCompanionTaskOutcome::Existing(status) => ("existing", status),
        _ => return skipped("unknown"),
    };
    CompanionGoodbyeArtifactHookPayload {
        status: status.to_owned(),
        task: task_status.task.kind.as_str().to_owned(),
        attempt_id: Some(hex_bytes(task_status.attempt.id.as_bytes())),
        run_id: task_status.attempt.run_id,
    }
}

pub(crate) fn companion_register_record_payload(
    record: &oneiron::CompanionRecord,
) -> CompanionRegisterRecordPayload {
    CompanionRegisterRecordPayload {
        kind: record.kind().as_str().to_owned(),
        scope: companion_register_scope_payload(&record.scope),
        subject: companion_register_subject_payload(&record.subject),
        value: oneiron::companion_value_to_json(&record.value),
        provenance: CompanionRegisterProvenancePayload {
            actor_ref: record.provenance.actor_ref.to_hex(),
            actor_class: record.provenance.actor_class as u8,
            source: record.provenance.source.as_str().to_owned(),
            approval: record.provenance.approval.as_str().to_owned(),
            value: oneiron::companion_value_to_json(&record.provenance.value),
        },
        lifecycle: Some(record.lifecycle.as_str().to_owned()),
        export_classification: record.export_classification.as_str().to_owned(),
    }
}

pub(crate) fn companion_register_scope_payload(
    scope: &oneiron::CompanionScope,
) -> CompanionRegisterScopePayload {
    match scope {
        oneiron::CompanionScope::Neutral => CompanionRegisterScopePayload {
            kind: "neutral".to_owned(),
            person_ref: None,
            vault_id: None,
        },
        oneiron::CompanionScope::Personal { person_ref } => CompanionRegisterScopePayload {
            kind: "personal".to_owned(),
            person_ref: Some(person_ref.to_hex()),
            vault_id: None,
        },
        oneiron::CompanionScope::SharedVault { vault_id } => CompanionRegisterScopePayload {
            kind: "shared_vault".to_owned(),
            person_ref: None,
            vault_id: Some(*vault_id),
        },
        _ => {
            tracing::warn!("unknown companion register scope variant in API response");
            CompanionRegisterScopePayload {
                kind: "unknown".to_owned(),
                person_ref: None,
                vault_id: None,
            }
        }
    }
}

pub(crate) fn companion_register_subject_payload(
    subject: &oneiron::CompanionSubject,
) -> CompanionRegisterSubjectPayload {
    match subject {
        oneiron::CompanionSubject::Persona { persona_ref } => CompanionRegisterSubjectPayload {
            kind: "persona".to_owned(),
            persona_ref: Some(persona_ref.to_hex()),
            relationship_ref: None,
        },
        oneiron::CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => CompanionRegisterSubjectPayload {
            kind: "relationship".to_owned(),
            persona_ref: None,
            relationship_ref: Some(CompanionRegisterRelationshipRefPayload {
                source_ref: source_ref.to_hex(),
                target_ref: target_ref.to_hex(),
            }),
        },
        _ => {
            tracing::warn!("unknown companion register subject variant in API response");
            CompanionRegisterSubjectPayload {
                kind: "unknown".to_owned(),
                persona_ref: None,
                relationship_ref: None,
            }
        }
    }
}

pub(crate) fn companion_register_kind_from_wire(
    value: &str,
    field: &'static str,
) -> Result<oneiron::CompanionRecordKind, ApiError> {
    match value {
        "persona" => Ok(oneiron::CompanionRecordKind::Persona),
        "relationship" => Ok(oneiron::CompanionRecordKind::Relationship),
        _ => Err(ApiError::bad_request(
            "kind must be persona or relationship",
            Some(field),
        )),
    }
}

pub(crate) fn companion_register_lifecycle_from_wire(
    value: &str,
) -> Result<oneiron::ClaimLifecycleStatus, ApiError> {
    match value {
        "active" => Ok(oneiron::ClaimLifecycleStatus::Active),
        "superseded" => Ok(oneiron::ClaimLifecycleStatus::Superseded),
        "retracted" => Ok(oneiron::ClaimLifecycleStatus::Retracted),
        _ => Err(ApiError::bad_request(
            "lifecycle must be active, superseded, or retracted",
            Some("record.lifecycle"),
        )),
    }
}

pub(crate) fn companion_register_export_from_wire(
    value: &str,
) -> Result<oneiron::CompanionExportClassification, ApiError> {
    match value {
        "local_only" => Ok(oneiron::CompanionExportClassification::LocalOnly),
        "portable" => Ok(oneiron::CompanionExportClassification::Portable),
        "shared_vault" => Ok(oneiron::CompanionExportClassification::SharedVault),
        _ => Err(ApiError::bad_request(
            "export must be local_only, portable, or shared_vault",
            Some("record.export"),
        )),
    }
}

pub(crate) fn companion_register_actor_class(
    value: u8,
) -> Result<oneiron::EdgeActorClass, ApiError> {
    match value {
        0 => Ok(oneiron::EdgeActorClass::Human),
        1 => Ok(oneiron::EdgeActorClass::Agent),
        2 => Ok(oneiron::EdgeActorClass::System),
        _ => Err(ApiError::bad_request(
            "actor_class must be 0, 1, or 2",
            Some("record.provenance.actor_class"),
        )),
    }
}

pub(crate) fn companion_register_source_from_wire(
    value: &str,
) -> Result<oneiron::ClaimSource, ApiError> {
    match value {
        "user_stated" => Ok(oneiron::ClaimSource::UserStated),
        "observed" => Ok(oneiron::ClaimSource::Observed),
        "inferred" => Ok(oneiron::ClaimSource::Inferred),
        "imported" => Ok(oneiron::ClaimSource::Imported),
        "tool_output" => Ok(oneiron::ClaimSource::ToolOutput),
        "generated" => Ok(oneiron::ClaimSource::Generated),
        _ => Err(ApiError::bad_request(
            "source is not recognized",
            Some("record.provenance.source"),
        )),
    }
}

pub(crate) fn companion_register_approval_from_wire(
    value: &str,
) -> Result<oneiron::ClaimApprovalStatus, ApiError> {
    match value {
        "auto" => Ok(oneiron::ClaimApprovalStatus::Auto),
        "proposed" => Ok(oneiron::ClaimApprovalStatus::Proposed),
        "approved" => Ok(oneiron::ClaimApprovalStatus::Approved),
        "rejected" => Ok(oneiron::ClaimApprovalStatus::Rejected),
        _ => Err(ApiError::bad_request(
            "approval is not recognized",
            Some("record.provenance.approval"),
        )),
    }
}
