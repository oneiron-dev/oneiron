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
    /// The rows the cached solve was derived from, by hex id (FIX 4781):
    /// its calendar binding's claims and every row its oracle listed. An
    /// entry that kept none lists unknown.
    #[serde(default)]
    sources: Option<Vec<String>>,
}

/// A cached answer and the rows its solve listed, `None` when unknown.
pub(super) type CachedListing = (BookingOperationResponse, Option<Vec<EntityId>>);

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
) -> Result<Option<CachedListing>, ApiError> {
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
    let sources = cached.sources.and_then(|ids| {
        ids.iter()
            .map(|id| EntityId::from_hex(id).ok())
            .collect::<Option<Vec<_>>>()
    });
    Ok(Some((cached.response, sources)))
}

pub(super) fn remember_response(
    server: &SyncServer,
    page: EntityId,
    input: &BookingAvailabilityInput,
    authority: Option<&PublicBookingAuthority>,
    response: &BookingOperationResponse,
    sources: &[EntityId],
) -> Result<(), ApiError> {
    let Some(authority) = authority else {
        return Ok(());
    };
    let entry = |sources: Option<Vec<String>>| {
        serde_json::to_vec(&CachedAvailability {
            query: query(input, authority),
            response: response.clone(),
            sources,
        })
        .map_err(|_| ApiError::internal_server_error("booking slot cache encoding failed"))
    };
    // The rows ride beside the answer when the entry still fits the cache's
    // bound; otherwise the answer is cached exactly as before, and a hit on
    // it lists unknown.
    let listed = entry(Some(sources.iter().map(EntityId::to_hex).collect()))?;
    if remember_slot_list_body(server, &page, Some(&input.event_type), &listed).is_err() {
        remember_slot_list_body(server, &page, Some(&input.event_type), &entry(None)?)?;
    }
    Ok(())
}

/// Solves one availability request, beside the rows the solve was derived
/// from (FIX 4781): the calendar binding's claims and every row the listing
/// oracle read. They go into the cache beside the answer.
pub(super) fn solve(
    server: &Arc<SyncServer>,
    page_ref: EntityId,
    input: BookingAvailabilityInput,
    now: u64,
    public_authority: Option<&PublicBookingAuthority>,
) -> Result<(BookingOperationResponse, Vec<EntityId>), ApiError> {
    let constraint = normalize_constraint(input.constraint.clone(), now)?;
    let solve_request = SolveRequest {
        event_type: input.event_type.clone(),
        window: input.window,
        constraint,
        visitor_tz: input.visitor_tz.clone(),
    };
    let producers = oneiron::memory::ProducerRows::default();
    let (oracle, mut sources) =
        lifecycle::booking_oracle_listing(server, page_ref, None, now, &producers)?;
    let mut solved = oracle.solve(&solve_request)?;
    sources.extend(producers.take());
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
    remember_response(
        server,
        page_ref,
        &input,
        public_authority,
        &response,
        &sources,
    )?;
    Ok((response, sources))
}

/// Replaces caller-supplied constraint input with a canonical object.
///
/// A prebuilt object bypasses parsing but still validates and canonicalizes,
/// so two semantically identical constraints reach the oracle as the same
/// bytes. Free text goes to ONE-1816's bounded parser before the solve
/// (`free_text`) and NEVER reaches the oracle: [`SolveRequest`] has no text
/// field, and this function returns the object or an error — never the
/// sentence.
fn normalize_constraint(
    input: Option<BookingConstraintInput>,
    _now: u64,
) -> Result<Option<ConstraintObject>, ApiError> {
    match input {
        None => Ok(None),
        Some(BookingConstraintInput::Object(object)) => {
            Ok(Some(object.canonicalize().map_err(booking_error)?))
        }
        // The parse ran before the solve; text here would be a bypass.
        Some(BookingConstraintInput::FreeText(_)) => Err(ApiError::internal_server_error(
            "booking free text reached the solve unparsed",
        )),
    }
}
