use oneiron::TimeRange;
use oneiron::booking::EventTypeKey;
use oneiron::booking::agent_api::{
    BookingBookInput, BookingIntakeAnswer, BookingOperationRequest, SelectedSlot,
};

use super::constants::{
    MAX_BOOKER_EMAIL_BYTES, MAX_IDEMPOTENCY_KEY_BYTES, MAX_INTAKE_ANSWERS,
    MAX_INTAKE_FIELD_KEY_BYTES, MAX_INTAKE_VALUE_BYTES, MAX_SESSION_REF_BYTES,
};
use crate::error::ApiError;

// -------------------------------------------------------------------------
// Shape validation
// -------------------------------------------------------------------------

/// Validates the caller-controlled shape of one request before any storage
/// read, any admission call, and any solve.
pub(super) fn validate_operation_shape(request: &BookingOperationRequest) -> Result<(), ApiError> {
    match request {
        BookingOperationRequest::Availability(input) => {
            validate_event_type(&input.event_type)?;
            validate_session_ref(&input.session_ref)?;
            validate_window(input.window)
        }
        BookingOperationRequest::Book(BookingBookInput::Hold(input)) => {
            validate_event_type(&input.event_type)?;
            validate_session_ref(&input.session_ref)?;
            validate_idempotency_key(&input.idempotency_key)?;
            validate_selected_slot(input.selected_slot)?;
            validate_optional_token(
                input.checkout_lease_token.as_deref(),
                "checkout_lease_token",
            )
        }
        BookingOperationRequest::Book(BookingBookInput::Confirm(input)) => {
            validate_session_ref(&input.session_ref)?;
            validate_idempotency_key(&input.idempotency_key)?;
            validate_token(&input.hold_token, "hold_token")?;
            validate_booker_email(&input.booker_email)?;
            validate_intake(&input.intake)
        }
        BookingOperationRequest::Reschedule(input) => {
            validate_idempotency_key(&input.idempotency_key)?;
            validate_token(&input.reschedule_token, "reschedule_token")?;
            validate_selected_slot(input.selected_slot)
        }
        BookingOperationRequest::Cancel(input) => {
            validate_idempotency_key(&input.idempotency_key)?;
            validate_token(&input.cancel_token, "cancel_token")
        }
    }
}

fn validate_event_type(event_type: &EventTypeKey) -> Result<(), ApiError> {
    if event_type.0.trim().is_empty() || event_type.0.len() > 64 {
        return Err(ApiError::bad_request(
            "event_type must be 1..=64 non-blank bytes",
            Some("event_type"),
        ));
    }
    Ok(())
}

fn validate_session_ref(session_ref: &str) -> Result<(), ApiError> {
    if session_ref.is_empty() || session_ref.len() > MAX_SESSION_REF_BYTES {
        return Err(ApiError::bad_request(
            format!("session_ref must be 1..={MAX_SESSION_REF_BYTES} bytes"),
            Some("session_ref"),
        ));
    }
    if !session_ref
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ApiError::bad_request(
            "session_ref must use only ASCII alphanumerics, '.', '_', or '-'",
            Some("session_ref"),
        ));
    }
    Ok(())
}

fn validate_window(window: TimeRange) -> Result<(), ApiError> {
    if window.start >= window.end {
        return Err(ApiError::bad_request(
            "window must satisfy start < end",
            Some("window"),
        ));
    }
    Ok(())
}

pub(super) fn validate_selected_slot(slot: SelectedSlot) -> Result<(), ApiError> {
    if slot.start_utc >= slot.end_utc {
        return Err(ApiError::bad_request(
            "selected_slot must satisfy start_utc < end_utc",
            Some("selected_slot"),
        ));
    }
    Ok(())
}

fn validate_idempotency_key(key: &str) -> Result<(), ApiError> {
    if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(ApiError::bad_request(
            format!("idempotency_key must be 1..={MAX_IDEMPOTENCY_KEY_BYTES} bytes"),
            Some("idempotency_key"),
        ));
    }
    Ok(())
}

/// Bearer credentials this surface accepts are exactly the lowercase hex the
/// lifecycle mints. A malformed value is refused before it can reach a digest
/// lookup, and an internal identifier never has this shape.
fn validate_token(token: &str, field: &'static str) -> Result<(), ApiError> {
    let well_formed = token.len() == 64
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if well_formed {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            format!("{field} must be a 64-character lowercase hex booking token"),
            Some(field),
        ))
    }
}

fn validate_optional_token(token: Option<&str>, field: &'static str) -> Result<(), ApiError> {
    token.map_or(Ok(()), |token| validate_token(token, field))
}

fn validate_booker_email(email: &str) -> Result<(), ApiError> {
    if email.trim().is_empty() || email.len() > MAX_BOOKER_EMAIL_BYTES {
        return Err(ApiError::bad_request(
            format!("booker_email must be 1..={MAX_BOOKER_EMAIL_BYTES} non-blank bytes"),
            Some("booker_email"),
        ));
    }
    Ok(())
}

fn validate_intake(intake: &[BookingIntakeAnswer]) -> Result<(), ApiError> {
    if intake.len() > MAX_INTAKE_ANSWERS {
        return Err(ApiError::bad_request(
            format!("intake carries at most {MAX_INTAKE_ANSWERS} answers"),
            Some("intake"),
        ));
    }
    for answer in intake {
        if answer.field_key.trim().is_empty() || answer.field_key.len() > MAX_INTAKE_FIELD_KEY_BYTES
        {
            return Err(ApiError::bad_request(
                format!(
                    "intake field_key must be 1..={MAX_INTAKE_FIELD_KEY_BYTES} non-blank bytes"
                ),
                Some("intake.field_key"),
            ));
        }
        if answer.value.len() > MAX_INTAKE_VALUE_BYTES {
            return Err(ApiError::bad_request(
                format!("intake value must be at most {MAX_INTAKE_VALUE_BYTES} bytes"),
                Some("intake.value"),
            ));
        }
    }
    Ok(())
}
