use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::TimeRange;
use oneiron::booking::BookingError;
use oneiron::booking::agent_api::SelectedSlot;

use super::validate::validate_selected_slot;
use crate::error::ApiError;

// -------------------------------------------------------------------------
// Shared helpers
// -------------------------------------------------------------------------

pub(super) fn slot_range(slot: SelectedSlot) -> Result<TimeRange, ApiError> {
    validate_selected_slot(slot)?;
    Ok(TimeRange {
        start: slot.start_utc,
        end: slot.end_utc,
    })
}

pub(super) fn domain_digest(domain: &[u8], material: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(material);
    *hasher.finalize().as_bytes()
}

pub(super) fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    out
}

pub(super) fn now_secs() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ApiError::internal_server_error("booking clock unavailable"))
}

pub(super) fn engine_read_error(error: oneiron::Error) -> ApiError {
    tracing::error!(error = %error, "booking agent api vault read failed");
    ApiError::internal_server_error("booking storage read failed")
}

/// Projects a typed engine booking error onto the API vocabulary.
///
/// Configuration and storage defects are the server's; constraint, parse, and
/// oracle refusals are the caller's request being unusable, and a spent
/// session dial is a retry-class state.
pub(super) fn booking_error(error: BookingError) -> ApiError {
    match error {
        BookingError::InvalidConfig(detail) => {
            tracing::error!(detail = %detail, "booking configuration defect");
            ApiError::internal_server_error("booking page configuration is unusable")
        }
        BookingError::InvalidConstraint(detail) => ApiError::bad_request(detail, None),
        BookingError::ConstraintParse(detail) => ApiError::bad_request(detail, Some("constraint")),
        BookingError::SessionCapExhausted => {
            ApiError::invalid_state(Some("booking_session_cap_exhausted"))
        }
        BookingError::SlotOracle(detail) => {
            tracing::warn!(detail = %detail, "booking oracle refused");
            ApiError::invalid_state(Some("booking_slot_unavailable"))
        }
        BookingError::Surface(detail) => {
            tracing::error!(detail = %detail, "booking surface assembly failed");
            ApiError::internal_server_error("booking surface assembly failed")
        }
        BookingError::Boundary(error) => {
            use crate::error::ApiErrorDetails;
            let details = match error.code.as_str() {
                oneiron::MEMORY_CODE_FORBIDDEN => ApiErrorDetails::Forbidden {
                    required_scope: None,
                },
                oneiron::MEMORY_CODE_INVALID_STATE => ApiErrorDetails::InvalidState {
                    state: Some("booking_state".to_owned()),
                },
                oneiron::MEMORY_CODE_BAD_REQUEST => ApiErrorDetails::BadRequest { field: None },
                oneiron::MEMORY_CODE_NOT_FOUND => return ApiError::not_found("booking", None),
                _ => return ApiError::internal_server_error("booking boundary failed"),
            };
            ApiError::new(error.message, details, error.suggestions)
        }
    }
}

impl From<BookingError> for ApiError {
    fn from(error: BookingError) -> Self {
        booking_error(error)
    }
}
