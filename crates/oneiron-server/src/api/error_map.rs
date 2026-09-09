//! Engine-to-ApiError mapping plus query/JSON rejection translators.

use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use oneiron::ErrorKind;

pub(super) fn core_engine_error(message: &'static str, error: oneiron::Error) -> ApiError {
    match error.kind() {
        ErrorKind::DimensionMismatch
        | ErrorKind::InvalidVector
        | ErrorKind::InvalidKey
        | ErrorKind::InvalidConfig
        | ErrorKind::InvalidTemporalExpression
        | ErrorKind::InvalidEntityType
        | ErrorKind::InvalidTimeRange
        | ErrorKind::InvalidClaimBody
        | ErrorKind::InvalidAccessGrantBody
        | ErrorKind::InvalidCounterpartyContactBody
        | ErrorKind::InvalidCommRecordBody
        | ErrorKind::InvalidTaskBody
        | ErrorKind::InvalidCodeArtifactBody
        | ErrorKind::InvalidBlobArtifactBody
        | ErrorKind::InvalidWitnessMessageBody
        | ErrorKind::InvalidEditManifest
        | ErrorKind::InvalidSkillBody
        | ErrorKind::InvalidCodebaseSnapshotBody
        | ErrorKind::InvalidCodeSymbolManifestBody
        | ErrorKind::InvalidAttemptQueueRecord
        | ErrorKind::InvalidAttemptQueueTransition
        | ErrorKind::SurfaceEventCorrelationKindCollision
        | ErrorKind::MaintenanceKindNotWritable
        | ErrorKind::EntityTypeImmutable
        | ErrorKind::StructuralKindZoneViolation
        | ErrorKind::StructuralKindCollision
        | ErrorKind::InvalidStructuralKindRegistration
        | ErrorKind::PolicyManifestInvalid
        | ErrorKind::ClaimSelfSupersession
        | ErrorKind::ProvenanceClaimLifecycle
        | ErrorKind::AgentNotDispatchable
        | ErrorKind::InvalidAgentDispatchInput
        | ErrorKind::AgentDefinitionNotFound
        | ErrorKind::AgentDefinitionDisabled => ApiError::bad_request(error.to_string(), None),
        ErrorKind::EntityNotFound | ErrorKind::EdgeNotFound => ApiError::not_found("entity", None),
        ErrorKind::CycleDetected | ErrorKind::ChildOfCardinality => {
            ApiError::invalid_state(Some("child_of_constraint"))
        }
        ErrorKind::ClaimAlreadyClosed | ErrorKind::ProvenanceClaimAlreadyClosed => {
            ApiError::invalid_state(Some("memory_lifecycle_closed"))
        }
        ErrorKind::HostedMediaHashMatchKnownMatch => ApiError::new(
            error.to_string(),
            ApiErrorDetails::InvalidState {
                state: Some("hosted_media_hash_match_known_match".to_owned()),
            },
            [
                "Remove public access, preserve evidence, and follow the known-CSAM hosted media runbook.",
            ],
        ),
        ErrorKind::GateWriteRejected => ApiError::new(
            error.to_string(),
            ApiErrorDetails::InvalidState {
                state: Some("gate_write_rejected".to_owned()),
            },
            ["Route the write through policy review before retrying."],
        ),
        ErrorKind::GateConsentStale => ApiError::new(
            error.to_string(),
            ApiErrorDetails::InvalidState {
                state: Some("gate_consent_stale".to_owned()),
            },
            ["Restart policy review from the current diff and read frontier."],
        ),
        _ => ApiError::internal_server_error(message),
    }
}

pub(super) fn query_rejection_error(rejection: QueryRejection) -> ApiError {
    if rejection.body_text().contains("invalid_view") {
        ApiError::bad_request("view must be one of summary, standard, full", Some("view"))
    } else {
        ApiError::bad_request("invalid query parameters", None)
    }
}

pub(super) fn json_rejection_error(_rejection: JsonRejection) -> ApiError {
    ApiError::bad_request("invalid JSON request body", None)
}
