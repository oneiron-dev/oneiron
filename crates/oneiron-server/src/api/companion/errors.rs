//! Companion error constructors.

use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use crate::error::EnvelopedApiError;
use oneiron::ErrorKind;

pub(crate) fn companion_access_denied() -> EnvelopedApiError {
    ApiError::new(
        "companion profile access is not granted",
        ApiErrorDetails::Forbidden {
            required_scope: Some("companion_profile.read".to_owned()),
        },
        ["Create an active AccessGrant for this principal and profile before retrying."],
    )
    .into()
}

pub(crate) fn companion_create_error(error: oneiron::Error) -> EnvelopedApiError {
    match error.kind() {
        ErrorKind::AccessGrantAlreadyExists => {
            ApiError::invalid_state(Some("access_grant_exists")).into()
        }
        _ => companion_engine_error("companion access grant create failed", error),
    }
}

pub(crate) fn companion_register_engine_error(
    message: &'static str,
    error: oneiron::Error,
) -> EnvelopedApiError {
    match error.kind() {
        ErrorKind::CompanionRecordAlreadyExists => {
            ApiError::invalid_state(Some("companion_record_exists")).into()
        }
        ErrorKind::EntityNotFound => ApiError::not_found("companion_record", None).into(),
        ErrorKind::InvalidClaimBody
        | ErrorKind::InvalidEntityType
        | ErrorKind::InvalidTimeRange
        | ErrorKind::StructuralKindZoneViolation
        | ErrorKind::StructuralKindCollision
        | ErrorKind::InvalidStructuralKindRegistration => {
            ApiError::bad_request(error.to_string(), None).into()
        }
        _ => ApiError::internal_server_error(message).into(),
    }
}

pub(crate) fn companion_engine_error(
    message: &'static str,
    error: oneiron::Error,
) -> EnvelopedApiError {
    match error.kind() {
        ErrorKind::InvalidKey
        | ErrorKind::InvalidAccessGrantBody
        | ErrorKind::InvalidEntityType
        | ErrorKind::InvalidTimeRange => ApiError::bad_request(error.to_string(), None).into(),
        ErrorKind::EntityNotFound => ApiError::not_found("access_grant", None).into(),
        _ => ApiError::internal_server_error(message).into(),
    }
}
