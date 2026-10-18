//! Typed booking-page discovery, published lifecycle and constraint front.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::booking::agent_api::{BookingOperationRequest, BookingOperationResponse};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    BookingAvailabilityRequest, BookingBookRequest, BookingCancelRequest,
    BookingConstraintTurnRequest, BookingConstraintTurnResponse, BookingPageTokenRequest,
    BookingPageTokenResponse, BookingRescheduleRequest,
};

use super::FacadeApiError;
use super::host_doors::{Listed, internal, refused};
use crate::api::booking::{
    booking_page_token, credential_transport_context, execute_booking_operation,
    resolve_booking_page_listing, resolve_public_booking_page, run_public_constraint_turn,
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
    if crate::api::owner_routes::owner(auth, server).is_err() {
        return refused(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{VERB} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        ));
    }
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
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
pub(crate) async fn vault_booking_constraint_turn(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: BookingConstraintTurnRequest,
) -> MemoryResult<BookingConstraintTurnResponse> {
    let transport = credential_transport_context(server, auth)
        .map_err(|error| FacadeApiError::from(error).into_memory_error())?;
    let (page_ref, publication) = resolve_public_booking_page(server, &input.page_token)
        .map_err(|error| FacadeApiError::from(error).into_memory_error())?;
    let authority = oneiron::booking::publication::PublicBookingAuthority {
        page_ref,
        publication,
    };
    run_public_constraint_turn(server, authority, input.turn, &transport)
        .await
        .map_err(|error| FacadeApiError::from(error).into_memory_error())
}

/// All lifecycle calls use the caller's own credential and the existing
/// executor. It binds the live public page, admits once, checks action-token
/// scope and runs the home-node writer; no transport invents a peer address.
async fn booking_operation(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    page_token: String,
    operation: BookingOperationRequest,
) -> MemoryResult<BookingOperationResponse> {
    let transport = credential_transport_context(server, auth)
        .map_err(|error| FacadeApiError::from(error).into_memory_error())?;
    execute_booking_operation(server, &page_token, operation, &transport)
        .await
        .map_err(|error| FacadeApiError::from(error).into_memory_error())
}

pub(crate) async fn vault_booking_availability(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: BookingAvailabilityRequest,
) -> MemoryResult<BookingOperationResponse> {
    let BookingAvailabilityRequest::Availability { page_token, input } = request;
    booking_operation(
        server,
        auth,
        page_token,
        BookingOperationRequest::Availability(input),
    )
    .await
}

pub(crate) async fn vault_booking_book(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: BookingBookRequest,
) -> MemoryResult<BookingOperationResponse> {
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
) -> MemoryResult<BookingOperationResponse> {
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
) -> MemoryResult<BookingOperationResponse> {
    let BookingCancelRequest::Cancel { page_token, input } = request;
    booking_operation(
        server,
        auth,
        page_token,
        BookingOperationRequest::Cancel(input),
    )
    .await
}
