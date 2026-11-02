//! Typed booking-page discovery, published lifecycle and constraint front.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::booking::agent_api::{BookingOperationRequest, BookingOperationResponse};
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    BookingAvailabilityRequest, BookingBookRequest, BookingCancelRequest,
    BookingConstraintTurnRequest, BookingConstraintTurnResponse, BookingPageTokenRequest,
    BookingPageTokenResponse, BookingRescheduleRequest,
};

use super::FacadeApiError;
use super::host_doors::support::{Listed, MaybeListed, internal, refused};
use crate::api::booking::{
    booking_page_token, credential_transport_context, execute_booking_operation_listing,
    resolve_booking_page_listing, resolve_public_booking_page_listing,
    run_public_constraint_turn_listing,
};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The same owner proof as every owner door; a token grants no new authority.
/// It lists the rows the token was resolved from (`host_door_lists`): the
/// page and each live `booking.event_type` claim that makes it bookable,
/// kept from the resolver's own reads ([`resolve_booking_page_listing`]).
pub(crate) async fn vault_booking_page_token(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: BookingPageTokenRequest,
) -> Listed<BookingPageTokenResponse> {
    const VERB: &str = "vault.booking.page_token";
    if let Err(refusal) = super::owner_binding::facade_owner(server, auth, VERB) {
        return refused(refusal);
    }
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        let Ok(page_ref) = EntityId::from_hex(input.page_ref.trim()) else {
            return refused(MemoryError::bad_request("invalid booking page_ref"));
        };
        let page_token = booking_page_token(page_ref);
        // Discovery addresses only pages the existing booking executor resolves.
        match resolve_booking_page_listing(&server, &page_token) {
            Ok((_, rows)) => (Ok(BookingPageTokenResponse { page_token }), rows),
            Err(error) => refused(FacadeApiError::from(error).into_memory_error()),
        }
    })
    .await
    .unwrap_or_else(|_| refused(internal(VERB)))
}

/// The same live publication, admission, parser and oracle as the public front.
/// The caller's own credential keys the wait and pays for its model call.
/// It lists (`host_door_lists`) the rows its answer was derived from, from
/// the same reads (FIX 4777): the page, its publication claim and the
/// event-type claims it validated, whose text and configuration the card
/// copies, and every row its solves read (the calendar binding's claims,
/// the configuration claim, each busy EVENT and charged booking with the
/// claims on it). The visitor's sentence, the parse, live holds (side-table
/// rows) and the session counters list none, and no busy detail leaves
/// through the answer. A refusal carries nothing and lists none (FIX 6080).
pub(crate) async fn vault_booking_constraint_turn(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: BookingConstraintTurnRequest,
) -> Listed<BookingConstraintTurnResponse> {
    let answer: MemoryResult<(BookingConstraintTurnResponse, Vec<EntityId>)> = async {
        let transport = credential_transport_context(server, auth)
            .map_err(|error| FacadeApiError::from(error).into_memory_error())?;
        let (page_ref, publication, mut rows) =
            resolve_public_booking_page_listing(server, &input.page_token)
                .map_err(|error| FacadeApiError::from(error).into_memory_error())?;
        let authority = oneiron::booking::publication::PublicBookingAuthority {
            page_ref,
            publication,
        };
        let (response, solved) =
            run_public_constraint_turn_listing(server, authority, input.turn, &transport)
                .await
                .map_err(|error| FacadeApiError::from(error).into_memory_error())?;
        rows.extend(solved);
        Ok((response, rows))
    }
    .await;
    match answer {
        Ok((response, rows)) => (Ok(response), rows),
        Err(error) => (Err(error), Vec::new()),
    }
}

/// All lifecycle calls use the caller's own credential and the existing
/// executor. It binds the live public page, admits once, checks action-token
/// scope and runs the home-node writer; no transport invents a peer address.
/// Each lists (`host_door_lists`) what the executor lists from the same
/// execution (FIX 4781): an availability answer its publication's and its
/// solve's rows, as the constraint turn does; a hold, confirm, reschedule or
/// cancel unknown (`None`), since its writer and replay keep no set of the
/// rows they read.
async fn booking_operation(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    page_token: String,
    operation: BookingOperationRequest,
) -> MaybeListed<BookingOperationResponse> {
    let answer: MemoryResult<(BookingOperationResponse, Option<Vec<EntityId>>)> = async {
        let transport = credential_transport_context(server, auth)
            .map_err(|error| FacadeApiError::from(error).into_memory_error())?;
        execute_booking_operation_listing(server, &page_token, operation, &transport)
            .await
            .map_err(|error| FacadeApiError::from(error).into_memory_error())
    }
    .await;
    match answer {
        Ok((response, rows)) => (Ok(response), rows),
        Err(error) => (Err(error), None),
    }
}

/// `vault.booking.availability` (FIX 6080): its credential transport always
/// binds the live publication, and a cached answer that kept no rows beside
/// it is solved again for it, so the executor lists every availability
/// answer it gives ([`execute_booking_operation_listing`]). A refusal
/// carries nothing and lists none.
pub(crate) async fn vault_booking_availability(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: BookingAvailabilityRequest,
) -> MaybeListed<BookingOperationResponse> {
    let BookingAvailabilityRequest::Availability { page_token, input } = request;
    let (answer, rows) = booking_operation(
        server,
        auth,
        page_token,
        BookingOperationRequest::Availability(input),
    )
    .await;
    let rows = if answer.is_err() {
        Some(Vec::new())
    } else {
        rows
    };
    (answer, rows)
}

pub(crate) async fn vault_booking_book(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: BookingBookRequest,
) -> MaybeListed<BookingOperationResponse> {
    let BookingBookRequest::Book { page_token, input } = request;
    booking_operation(
        server,
        auth,
        page_token,
        BookingOperationRequest::Book(input),
    )
    .await
}

pub(crate) async fn vault_booking_reschedule(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: BookingRescheduleRequest,
) -> MaybeListed<BookingOperationResponse> {
    let BookingRescheduleRequest::Reschedule { page_token, input } = request;
    booking_operation(
        server,
        auth,
        page_token,
        BookingOperationRequest::Reschedule(input),
    )
    .await
}

pub(crate) async fn vault_booking_cancel(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: BookingCancelRequest,
) -> MaybeListed<BookingOperationResponse> {
    let BookingCancelRequest::Cancel { page_token, input } = request;
    booking_operation(
        server,
        auth,
        page_token,
        BookingOperationRequest::Cancel(input),
    )
    .await
}
