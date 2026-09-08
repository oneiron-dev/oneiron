//! Query-bound slot cache. Cached bodies are never publication authority.
use super::super::booking_anti_abuse::{cached_slot_list_body, remember_slot_list_body};
use super::*;
use oneiron::booking::BookingPagePublication;
use oneiron::booking::publication::PublicBookingAuthority;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct CachedAvailability {
    query: serde_json::Value,
    response: BookingOperationResponse,
}

fn query(
    input: &BookingAvailabilityInput,
    authority: &PublicBookingAuthority,
) -> serde_json::Value {
    // Session identity does not change availability. Window, timezone,
    // constraint, event, and exact owner snapshot do.
    serde_json::json!({
        "event_type": input.event_type, "window": {"start": input.window.start, "end": input.window.end},
        "visitor_tz": input.visitor_tz, "constraint": input.constraint, "authority": authority,
    })
}

pub(super) fn validate_public_request(
    publication: &BookingPagePublication,
    request: &BookingOperationRequest,
) -> Result<(), ApiError> {
    let (event, has_constraint) = match request {
        BookingOperationRequest::Availability(input) => {
            (&input.event_type, input.constraint.is_some())
        }
        BookingOperationRequest::Book(BookingBookInput::Hold(input)) => {
            (&input.event_type, input.constraint.is_some())
        }
        _ => return Ok(()),
    };
    if !publication
        .event_types
        .iter()
        .any(|card| card.key == *event)
        || (has_constraint && !publication.constraint_field.enabled)
    {
        return Err(public::public_booking_not_found());
    }
    Ok(())
}

pub(super) fn recheck(
    server: &SyncServer,
    authority: Option<&PublicBookingAuthority>,
) -> Result<(), ApiError> {
    if let Some(authority) = authority {
        let current = oneiron::booking::load_public_booking_page(
            &server.vault,
            authority.page_ref,
            now_secs()?,
        )
        .map_err(|_| public::public_booking_not_found())?;
        if current.as_ref() != Some(&authority.publication) {
            return Err(public::public_booking_not_found());
        }
    }
    Ok(())
}

pub(super) fn cached_response(
    server: &SyncServer,
    page: EntityId,
    request: &BookingOperationRequest,
    authority: Option<&PublicBookingAuthority>,
) -> Result<Option<BookingOperationResponse>, ApiError> {
    let (BookingOperationRequest::Availability(input), Some(authority)) = (request, authority)
    else {
        return Ok(None);
    };
    let Some(bytes) = cached_slot_list_body(server, &page, Some(&input.event_type))? else {
        return Ok(None);
    };
    let Ok(cached) = serde_json::from_slice::<CachedAvailability>(&bytes) else {
        return Ok(None);
    };
    if cached.query != query(input, authority) {
        return Ok(None);
    }
    if !matches!(
        &cached.response,
        BookingOperationResponse::Availability { .. }
    ) {
        return Ok(None);
    }
    Ok(Some(cached.response))
}

pub(super) fn remember_response(
    server: &SyncServer,
    page: EntityId,
    input: &BookingAvailabilityInput,
    authority: Option<&PublicBookingAuthority>,
    response: &BookingOperationResponse,
) -> Result<(), ApiError> {
    let Some(authority) = authority else {
        return Ok(());
    };
    let bytes = serde_json::to_vec(&CachedAvailability {
        query: query(input, authority),
        response: response.clone(),
    })
    .map_err(|_| ApiError::internal_server_error("booking slot cache encoding failed"))?;
    remember_slot_list_body(server, &page, Some(&input.event_type), &bytes)?;
    Ok(())
}

pub(super) fn solve(
    server: &Arc<SyncServer>,
    page_ref: EntityId,
    input: BookingAvailabilityInput,
    now: u64,
    public_authority: Option<&PublicBookingAuthority>,
) -> Result<BookingOperationResponse, ApiError> {
    let constraint = normalize_constraint(input.constraint.clone(), now)?;
    let solve_request = SolveRequest {
        event_type: input.event_type.clone(),
        window: input.window,
        constraint,
        visitor_tz: input.visitor_tz.clone(),
    };
    let mut solved = booking_oracle(server, page_ref, None, now)?.solve(&solve_request)?;
    if public_authority.is_some() {
        let oneiron::booking::RungProjection::Slots(mask) = oneiron::booking::bounded_public_slots(
            oneiron::booking::slot_mask(&solve_request, solved),
        )
        .map_err(booking_error)?
        else {
            return Err(public::public_booking_not_found());
        };
        solved = SolveResult {
            slots: mask.slots,
            flex_used: mask.flex_used,
            host_bindings: Vec::new(),
        };
    }
    recheck(server, public_authority)?;
    let SolveResult {
        slots, flex_used, ..
    } = solved;
    let response = BookingOperationResponse::Availability { slots, flex_used };
    remember_response(server, page_ref, &input, public_authority, &response)?;
    Ok(response)
}

/// Replaces caller-supplied constraint input with a canonical object.
///
/// A prebuilt object bypasses parsing but still validates and canonicalizes,
/// so two semantically identical constraints reach the oracle as the same
/// bytes. Free text goes to ONE-1816's bounded parser and NEVER reaches the
/// oracle: [`SolveRequest`] has no text field, and this function returns the
/// parsed object or an error — never the sentence.
fn normalize_constraint(
    input: Option<BookingConstraintInput>,
    _now: u64,
) -> Result<Option<ConstraintObject>, ApiError> {
    match input {
        None => Ok(None),
        Some(BookingConstraintInput::Object(object)) => {
            Ok(Some(object.canonicalize().map_err(booking_error)?))
        }
        // ONE-1816's parser is one bounded model call over a host-configured
        // cheap tier. This daemon binds no LLM backend and no budget lease, so
        // there is nothing to parse WITH — and the fail-closed answer is the
        // only correct one: forwarding the sentence to the oracle is exactly
        // what the seam exists to prevent, and inventing a local parser would
        // be the second parser ONE-1816 forbids.
        Some(BookingConstraintInput::FreeText(_)) => Err(ApiError::not_implemented(
            "booking free-text constraint parsing requires a configured constraint parse tier",
        )),
    }
}
