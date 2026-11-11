use oneiron::TimeRange;
use oneiron::booking::EventTypeKey;
use oneiron::booking::agent_api::{
    BookingBookInput, BookingIntakeAnswer, BookingOperationRequest, SelectedSlot,
};

use super::constants::{
    MAX_BOOKER_EMAIL_BYTES, MAX_INTAKE_ANSWERS, MAX_INTAKE_FIELD_KEY_BYTES, MAX_INTAKE_VALUE_BYTES,
};
use crate::error::ApiError;

// -------------------------------------------------------------------------
// Shape validation
// -------------------------------------------------------------------------

/// Validates the caller-controlled shape of one request before any storage
/// read, any admission call, and any solve. An `anonymous` visitor's email and
/// intake keep their pre-auth bounds, so its work stays sheddable; an
/// authenticated caller's are measured instead ([`measure_authenticated`]).
pub(super) fn validate_operation_shape(
    request: &BookingOperationRequest,
    anonymous: bool,
) -> Result<(), ApiError> {
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
            validate_booker_email(&input.booker_email, anonymous)?;
            validate_intake(&input.intake, anonymous)
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

/// An event type key of any length, non-blank (ABC row 67).
fn validate_event_type(event_type: &EventTypeKey) -> Result<(), ApiError> {
    if event_type.0.trim().is_empty() {
        return Err(ApiError::bad_request(
            "event_type must be non-blank",
            Some("event_type"),
        ));
    }
    Ok(())
}

/// A session ref of any length (ABC row 68): a long one names its card by a
/// digest in the front.
fn validate_session_ref(session_ref: &str) -> Result<(), ApiError> {
    if session_ref.is_empty() {
        return Err(ApiError::bad_request(
            "session_ref must not be empty",
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

/// An idempotency key of any length (ABC row 73); the lifecycle queue keys on
/// its digest.
fn validate_idempotency_key(key: &str) -> Result<(), ApiError> {
    if key.is_empty() {
        return Err(ApiError::bad_request(
            "idempotency_key must not be empty",
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

fn validate_booker_email(email: &str, anonymous: bool) -> Result<(), ApiError> {
    if email.trim().is_empty() {
        return Err(ApiError::bad_request(
            "booker_email must be non-blank",
            Some("booker_email"),
        ));
    }
    if anonymous && email.len() > MAX_BOOKER_EMAIL_BYTES {
        return Err(ApiError::bad_request(
            format!("booker_email must be at most {MAX_BOOKER_EMAIL_BYTES} bytes"),
            Some("booker_email"),
        ));
    }
    Ok(())
}

/// An anonymous visitor's confirm carries at most [`MAX_INTAKE_ANSWERS`]
/// answers: pre-auth work stays sheddable. An authenticated caller's intake
/// is served whatever its count (FIX 9633).
pub(super) fn validate_anonymous_intake_count(
    request: &BookingOperationRequest,
) -> Result<(), ApiError> {
    if let BookingOperationRequest::Book(BookingBookInput::Confirm(input)) = request
        && input.intake.len() > MAX_INTAKE_ANSWERS
    {
        return Err(ApiError::bad_request(
            format!("intake carries at most {MAX_INTAKE_ANSWERS} answers"),
            Some("intake"),
        ));
    }
    Ok(())
}

fn validate_intake(intake: &[BookingIntakeAnswer], anonymous: bool) -> Result<(), ApiError> {
    for answer in intake {
        if answer.field_key.trim().is_empty() {
            return Err(ApiError::bad_request(
                "intake field_key must be non-blank",
                Some("intake.field_key"),
            ));
        }
        if anonymous && answer.field_key.len() > MAX_INTAKE_FIELD_KEY_BYTES {
            return Err(ApiError::bad_request(
                format!("intake field_key must be at most {MAX_INTAKE_FIELD_KEY_BYTES} bytes"),
                Some("intake.field_key"),
            ));
        }
        if anonymous && answer.value.len() > MAX_INTAKE_VALUE_BYTES {
            return Err(ApiError::bad_request(
                format!("intake value must be at most {MAX_INTAKE_VALUE_BYTES} bytes"),
                Some("intake.value"),
            ));
        }
    }
    Ok(())
}

/// An authenticated caller's confirm, measured against its `[limits]` rows
/// once the shape is valid (ABC rows 69, 70, 72): past a row it asks whether
/// everything is okay, and the confirm is served whole.
pub(super) fn measure_authenticated(vault: &oneiron::Vault, request: &BookingOperationRequest) {
    use oneiron::limit_ask::EngineLimit;
    match request {
        BookingOperationRequest::Book(BookingBookInput::Confirm(input)) => {
            let _ = vault.measure_limit(
                EngineLimit::BookingEmailBytes,
                input.booker_email.len() as u64,
            );
            let _ =
                vault.measure_limit(EngineLimit::BookingIntakeAnswers, input.intake.len() as u64);
            let largest = input
                .intake
                .iter()
                .map(|answer| answer.value.len())
                .max()
                .unwrap_or(0);
            let _ = vault.measure_limit(EngineLimit::BookingIntakeValueBytes, largest as u64);
        }
        _ => {}
    }
}
