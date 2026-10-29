//! Engine-to-ApiError mapping plus query/JSON rejection translators.

use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use oneiron::ErrorKind;

pub(super) fn core_engine_error(message: &'static str, error: oneiron::Error) -> ApiError {
    // FIX 2222: the owner refusal a read key or a host action carries (a
    // self-hosted root that binds no live owner under its key, a broken
    // owner check) answers as the facade's `From<MemoryError>` does: a 403
    // or a 409 with the engine's own words, never this plane's 500.
    if let oneiron::Error::Claim(oneiron::error::ClaimError::ScopedReadOwnerNotLive(refusal)) =
        &error
        && let Some(answer) = owner_refusal(refusal)
    {
        return answer;
    }
    // A held first write names the consents it waits on and the join that
    // files them; the generic conversation-state answer would drop both.
    if matches!(
        error,
        oneiron::Error::Record(oneiron::error::RecordError::RoomJoinHeld(_))
    ) {
        return ApiError::new(
            error.to_string(),
            ApiErrorDetails::InvalidState {
                state: Some("room_join_held".to_owned()),
            },
            [
                "File the join with vault.rooms.join and the intent_key named here; the write goes through once those parties consent.",
            ],
        );
    }
    // A room's assembly held on a live voice call names the room and the
    // call; the generic conversation-state answer would drop both.
    if matches!(
        error,
        oneiron::Error::Record(oneiron::error::RecordError::RoomLiveSpeakersIncomplete(_))
    ) {
        return ApiError::new(
            error.to_string(),
            ApiErrorDetails::InvalidState {
                state: Some("room_live_speakers_incomplete".to_owned()),
            },
            [
                "A voice call live in this room has no stored roster, or a speaker it must place is not entered yet; its host records them on its next roster refresh. Assemble again after that.",
            ],
        );
    }
    // A room refusal names the speaker, or the join, it refused; the
    // generic scope answer would drop them.
    if let oneiron::Error::Record(oneiron::error::RecordError::RoomJoinRefused { .. }) = error {
        return ApiError::new(
            error.to_string(),
            ApiErrorDetails::Forbidden {
                required_scope: Some("conversation_actor".to_owned()),
            },
            [
                "A party refused this room join, or it cannot stand; nothing was written. The refusal names which part and who.",
            ],
        );
    }
    if matches!(
        error,
        oneiron::Error::Record(oneiron::error::RecordError::RoomSpeakerIneligible { .. })
    ) {
        return ApiError::new(
            error.to_string(),
            ApiErrorDetails::Forbidden {
                required_scope: Some("conversation_actor".to_owned()),
            },
            [
                "Speak as an actor with a speaking role in this room; a person, the Dreamer or an upkeep actor may not host it.",
            ],
        );
    }
    match error.kind() {
        ErrorKind::ConversationDenied => ApiError::forbidden_scope("conversation_actor"),
        ErrorKind::ConversationState => ApiError::invalid_state(Some("conversation_state")),
        ErrorKind::InvalidConversationBody
        | ErrorKind::DimensionMismatch
        | ErrorKind::InvalidVector
        | ErrorKind::InvalidKey
        | ErrorKind::InvalidConfig
        | ErrorKind::InvalidTemporalExpression
        | ErrorKind::InvalidEntityType
        | ErrorKind::InvalidTimeRange
        | ErrorKind::InvalidConversationDag
        | ErrorKind::InvalidScopeSummary
        | ErrorKind::ActorClassMismatch
        | ErrorKind::ReservedEdgeKind
        | ErrorKind::InvalidClaimBody
        | ErrorKind::InvalidAccessGrantBody
        | ErrorKind::InvalidCounterpartyContactBody
        | ErrorKind::InvalidCommRecordBody
        | ErrorKind::InvalidTaskBody
        | ErrorKind::InvalidCodeArtifactBody
        | ErrorKind::InvalidBlobArtifactBody
        | ErrorKind::InvalidWitnessMessageBody
        | ErrorKind::InvalidEditManifest
        | ErrorKind::LiveDeckRefused
        | ErrorKind::InvalidSkillBody
        | ErrorKind::InvalidCodebaseSnapshotBody
        | ErrorKind::InvalidCodeSymbolManifestBody
        | ErrorKind::InvalidAttemptQueueRecord
        | ErrorKind::InvalidAttemptQueueTransition
        | ErrorKind::SurfaceEventCorrelationKindCollision
        | ErrorKind::MaintenanceKindNotWritable
        | ErrorKind::EntityTypeImmutable
        | ErrorKind::DreamerActorImmutable
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
        ErrorKind::ConsentOwnerNotAuthenticated => ApiError::forbidden_scope("owner"),
        // FIX 2222: a host credential where no host acts as a person.
        ErrorKind::HostActionRequiresSupportGrant => ApiError::new(
            error.to_string(),
            ApiErrorDetails::Forbidden {
                required_scope: Some("support_grant".to_owned()),
            },
            [
                "Ask the customer for a support grant; the operator's own admin commands (status, backup, restore, repair, move) need none.",
            ],
        ),
        ErrorKind::WorkCompanionRequired => ApiError::new(
            error.to_string(),
            ApiErrorDetails::Forbidden {
                required_scope: None,
            },
            ["Start a work companion in this workspace; its policy refuses a brought one."],
        ),
        ErrorKind::HeadAdvanceOffTrunk => ApiError::invalid_state(Some("head_advance_off_trunk")),
        ErrorKind::DagParentOutsideConversation => {
            ApiError::invalid_state(Some("dag_parent_outside_conversation"))
        }
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
        // A refusal that names its bound answers as the facade does (FIX
        // 4618): the message is the whole answer.
        ErrorKind::Refused => ApiError::new(
            error.to_string(),
            ApiErrorDetails::InvalidState { state: None },
            ["Do what the message names (fund, bind or configure it), then ask again."],
        ),
        // A legal order binding the host keeps the record (WILL-PLAN L01
        // rows 01 and 03): its state, and the message naming its bound.
        ErrorKind::LegalHold => {
            let state = match &error {
                oneiron::Error::LegalHold(notice) => notice.state.as_str(),
                _ => "legal_hold",
            };
            ApiError::new(
                error.to_string(),
                ApiErrorDetails::InvalidState {
                    state: Some(state.to_owned()),
                },
                [oneiron::error::LEGAL_HOLD_SUGGESTION],
            )
        }
        // KS-6: a credential's custody key does not open, or custody could
        // not take a new one: the vault's state, as the facade answers it;
        // the message names the credential and its way out, never a byte.
        ErrorKind::CredentialLeafUnreadable | ErrorKind::CredentialCustodyUnavailable => {
            let state = match error.kind() {
                ErrorKind::CredentialCustodyUnavailable => "credential_custody_unavailable",
                _ => "credential_leaf_unreadable",
            };
            ApiError::new(
                error.to_string(),
                ApiErrorDetails::InvalidState {
                    state: Some(state.to_owned()),
                },
                ["Do what the message names: retry, or re-enter or reissue that credential."],
            )
        }
        // A hold named a gate-decision partition an erase or a key
        // retirement took (FIX 2923): its typed state, as the facade answers
        // it, never a bad request.
        ErrorKind::HoldTargetErased => {
            let state = match &error {
                oneiron::Error::Record(oneiron::error::RecordError::HoldTargetErased(target)) => {
                    target.as_str()
                }
                _ => oneiron::error::ErasedHoldTarget::Erased.as_str(),
            };
            ApiError::new(
                error.to_string(),
                ApiErrorDetails::InvalidState {
                    state: Some(state.to_owned()),
                },
                [oneiron::error::HOLD_TARGET_ERASED_SUGGESTION],
            )
        }
        // An erase took the reply this read names (FIX 5718): the record's
        // state, as the facade answers it, never this plane's 500.
        ErrorKind::ResponseErased => ApiError::new(
            error.to_string(),
            ApiErrorDetails::InvalidState {
                state: Some("response_erased".to_owned()),
            },
            ["An erase took this reply: what the call did stands, and no call sends it again."],
        ),
        _ => ApiError::internal_server_error(message),
    }
}

/// The carried owner refusal's answer: `OWNER_BINDING_REQUIRED` and
/// `FORBIDDEN` are the 403 refusal shape the support-grant refusal uses,
/// naming the owner as what the act requires; `INVALID_STATE` is a 409. Any
/// other code stays the caller's 500.
fn owner_refusal(refusal: &oneiron::MemoryError) -> Option<ApiError> {
    let details = match refusal.code.as_str() {
        oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED | oneiron::MEMORY_CODE_FORBIDDEN => {
            ApiErrorDetails::Forbidden {
                required_scope: Some("owner".to_owned()),
            }
        }
        oneiron::MEMORY_CODE_INVALID_STATE => ApiErrorDetails::InvalidState {
            state: Some("owner_check".to_owned()),
        },
        _ => return None,
    };
    Some(ApiError::new(
        refusal.message.clone(),
        details,
        refusal.suggestions.clone(),
    ))
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
